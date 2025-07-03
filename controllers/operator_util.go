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
)

// getOrCreateOperatorKP ensures a Secret with operator seed & jwt exists and
// returns a loaded nkeys.KeyPair plus JWT string.
func getOrCreateOperatorKP(ctx context.Context, c client.Client, ns string) (nkeys.KeyPair, string, error) {
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
	newSec.StringData = map[string]string{"seed": string(seed), "jwt": jwtStr}
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
