package controllers

import (
	"context"
	"os"

	natsjwt "github.com/nats-io/jwt/v2"
	nkeys "github.com/nats-io/nkeys"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Default secret name; can override with env OPERATOR_SECRET_NAME
	operatorSecretDefault = "nats-operator-jwt"
	sysSecretName         = "nats-sys-account-jwt"
)

// GetOrCreateOperatorKP ensures a Secret with operator seed & jwt exists and
// returns a loaded nkeys.KeyPair plus JWT string.
func GetOrCreateOperatorKP(ctx context.Context, c client.Client, ns string) (nkeys.KeyPair, string, error) {
	secretName := os.Getenv("OPERATOR_SECRET_NAME")
	if secretName == "" {
		secretName = operatorSecretDefault
	}

	var sec corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: ns}, &sec)
	if err != nil && !errors.IsNotFound(err) {
		return nil, "", err
	}

	// If secret exists and has seed&jwt, reuse
	if err == nil {
		seed, okSeed := sec.Data["seed"]
		jwtB, okJwt := sec.Data["jwt"]
		if okSeed && okJwt {
			kp, err := nkeys.FromSeed(seed)
			if err == nil {
				return kp, string(jwtB), nil
			}
		}
	}

	// Need to (re)generate
	kp, _ := nkeys.CreateOperator()
	pub, _ := kp.PublicKey()

	oc := natsjwt.NewOperatorClaims(pub)
	// Optionally embed resolver URL etc.
	jwtStr, _ := oc.Encode(kp)
	seed, _ := kp.Seed()

	// Build / create secret
	newSec := &corev1.Secret{}
	newSec.Name = secretName
	newSec.Namespace = ns
	newSec.Type = corev1.SecretTypeOpaque
	newSec.StringData = map[string]string{
		"seed": string(seed),
		"jwt":  jwtStr,
		"pub":  pub,
	}
	if newSec.Labels == nil {
		newSec.Labels = map[string]string{}
	}
	newSec.Labels["app.kubernetes.io/component"] = "nats-operator"

	if errors.IsNotFound(err) {
		if err := c.Create(ctx, newSec); err != nil {
			return nil, "", err
		}
	} else {
		if err := c.Update(ctx, newSec); err != nil {
			return nil, "", err
		}
	}

	return kp, jwtStr, nil
}

// EnsureSysAccount returns (sysKP, sysJWT string, sysPub string).
// If rotate==true it generates a *new* account keypair & JWT, replacing
// whatever is stored in the Secret.
func EnsureSysAccount(ctx context.Context, c client.Client, ns string, opKp nkeys.KeyPair, rotate bool) (nkeys.KeyPair, string, string, error) {
	var sec corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Name: sysSecretName, Namespace: ns}, &sec)

	// (A) reuse existing if present & no rotation requested
	if err == nil && !rotate {
		seedB, okSeed := sec.Data["seed"]
		jwtB, okJwt := sec.Data["jwt"]
		pubB, okPub := sec.Data["pub"]
		if okSeed && okJwt && okPub {
			kp, err := nkeys.FromSeed(seedB)
			if err == nil {
				return kp, string(jwtB), string(pubB), nil
			}
		}
	}
	if err != nil && !errors.IsNotFound(err) {
		return nil, "", "", err
	}

	// (B) generate fresh keypair / JWT (first boot or rotation requested)
	sysKP, _ := nkeys.CreateAccount()
	sysPub, _ := sysKP.PublicKey()

	ac := natsjwt.NewAccountClaims(sysPub)
	ac.Name = "$SYS"
	ac.Limits = natsjwt.OperatorLimits{} // minimal limits – adjust as desired
	sysJWT, _ := ac.Encode(opKp)         // signed by Operator
	sysSeed, _ := sysKP.Seed()

	// build / update Secret data map
	data := map[string][]byte{
		"seed": []byte(sysSeed),
		"jwt":  []byte(sysJWT),
		"pub":  []byte(sysPub),
	}

	if errors.IsNotFound(err) {
		// create Secret first time
		newSec := &corev1.Secret{}
		newSec.Name = sysSecretName
		newSec.Namespace = ns
		newSec.Type = corev1.SecretTypeOpaque
		newSec.Data = data
		if err := c.Create(ctx, newSec); err != nil {
			return nil, "", "", err
		}
	} else {
		// patch existing if any bytes differ
		changed := false
		for k, v := range data {
			if existing, ok := sec.Data[k]; !ok || string(existing) != string(v) {
				sec.Data[k] = v
				changed = true
			}
		}
		if changed {
			if err := c.Update(ctx, &sec); err != nil {
				return nil, "", "", err
			}
		}
	}

	// Optionally push updated JWT to NATS immediately (best effort)
	_ = pushJWT(sysJWT) // ignore error at bootstrap

	return sysKP, sysJWT, sysPub, nil
}
