package controllers

import (
	"context"
	"fmt"
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
func GetOrCreateOperatorKP(ctx context.Context, c client.Client, operatorNs string) (nkeys.KeyPair, string, error) {
	secretName := os.Getenv("OPERATOR_SECRET_NAME")
	if secretName == "" {
		secretName = operatorSecretDefault
	}

	var sec corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: operatorNs}, &sec)
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
	newSec.Namespace = operatorNs
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
func EnsureSysAccount(ctx context.Context, nURL string, c client.Client, operatorNs string, opKp nkeys.KeyPair, rotate bool) (nkeys.KeyPair, string, string, string, error) {
	var sec corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Name: sysSecretName, Namespace: operatorNs}, &sec)

	// (A) reuse existing if present & no rotation requested
	if err == nil && !rotate {
		seedB, okSeed := sec.Data["seed"]
		jwtB, okJwt := sec.Data["jwt"]
		pubB, okPub := sec.Data["pub"]
		if okSeed && okJwt && okPub {
			sysKP, err := nkeys.FromSeed(seedB)
			if err == nil {
				sysSeed, _ := sysKP.Seed()
				sysCreds, err := ensureSysResolverUserCreds(ctx, c, operatorNs, sysSeed)
				if err != nil {
					return nil, "", "", "", fmt.Errorf("ensure sys resolver user creds: %w", err)
				}

				if _, err := ensureSysResolverUserCredsFile(sysCreds); err != nil {
					return nil, "", "", "", fmt.Errorf("ensure sys resolver user creds file: %w", err)
				}

				return sysKP, string(jwtB), string(pubB), sysCreds, nil
			}
		}
	}
	if err != nil && !errors.IsNotFound(err) {
		return nil, "", "", "", err
	}

	// (B) generate fresh keypair / JWT (first boot or rotation requested)
	sysKP, _ := nkeys.CreateAccount()
	sysPub, _ := sysKP.PublicKey()

	ac := natsjwt.NewAccountClaims(sysPub)
	ac.Name = "$SYS"
	ac.Limits = natsjwt.OperatorLimits{
		AccountLimits: natsjwt.AccountLimits{
			Conn:            -1,
			LeafNodeConn:    -1,
			Imports:         -1,
			Exports:         -1,
			WildcardExports: true,
			DisallowBearer:  false,
		},
		NatsLimits: natsjwt.NatsLimits{
			Subs:    -1,
			Data:    -1,
			Payload: -1,
		},
	}
	sysJWT, _ := ac.Encode(opKp) // signed by Operator
	sysSeed, _ := sysKP.Seed()

	// build / update Secret data map
	data := map[string][]byte{
		"seed": sysSeed,
		"jwt":  []byte(sysJWT),
		"pub":  []byte(sysPub),
	}

	if errors.IsNotFound(err) {
		// create Secret first time
		newSec := &corev1.Secret{}
		newSec.Name = sysSecretName
		newSec.Namespace = operatorNs
		newSec.Type = corev1.SecretTypeOpaque
		newSec.Data = data
		if err := c.Create(ctx, newSec); err != nil {
			return nil, "", "", "", err
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
				return nil, "", "", "", err
			}
		}
	}

	// Store sys resolver user creds in file
	sysCreds, err := ensureSysResolverUserCreds(ctx, c, operatorNs, sysSeed)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("ensure sys resolver user creds: %w", err)
	}

	if _, err := ensureSysResolverUserCredsFile(sysCreds); err != nil {
		return nil, "", "", "", fmt.Errorf("ensure sys resolver user creds file: %w", err)
	}

	// Push updated JWT to NATS immediately (best effort)
	_ = pushJWT(sysJWT) // ignore error at bootstrap

	return sysKP, sysJWT, sysPub, sysCreds, nil
}

func ensureSysResolverUserCreds(ctx context.Context, c client.Client, operatorNs string, sysSeed []byte) (string, error) {
	sysCreds, err := EnsureSysResolverUser(ctx, c, operatorNs, sysSeed, false)
	if err != nil {
		return "", fmt.Errorf("bootstrap sys resolver user: %w", err)
	}

	return sysCreds, nil
}

func ensureSysResolverUserCredsFile(sysCreds string) (string, error) {
	// If no nats creds file is specified, write the secret to a temporary file
	if natsCreds == "" {
		// If no NATS_CREDS env var, fallback to the default system creds file path
		f, err := os.CreateTemp("", "nats-sys-creds-*")
		if err != nil {
			return "", fmt.Errorf("failed to create temp file for nats creds: %w", err)
		}
		if _, err := f.Write([]byte(sysCreds)); err != nil {
			return "", fmt.Errorf("write sys creds to temp file: %w", err)
		}
		SetNatsCreds(f.Name())
	}

	return natsCreds, nil
}
