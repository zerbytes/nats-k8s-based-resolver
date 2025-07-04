package controllers

import (
	"context"
	"fmt"

	natsjwt "github.com/nats-io/jwt/v2"
	nkeys "github.com/nats-io/nkeys"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	natsv1alpha1 "github.com/zerbytes/nats-based-resolver/api/v1alpha1"
)

// NatsAccountReconciler reconciles a NatsAccount object
// +kubebuilder:rbac:groups=natsresolver.zerbytes.net,resources=natsaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=natsresolver.zerbytes.net,resources=natsaccounts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

type NatsAccountReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *NatsAccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	var account natsv1alpha1.NatsAccount
	if err := r.Get(ctx, req.NamespacedName, &account); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// 1. Ensure operator secret exists (bootstrap elsewhere).

	// 2. Generate / fetch account keypair
	secretName := fmt.Sprintf("nats-account-%s-seed", account.Name)

	pub, jwtStr, seed, err := r.ensureAccountJWT(ctx, &account, secretName)
	if err != nil {
		log.Error(err, "unable to ensure account JWT")
		return ctrl.Result{}, err
	}

	// track whether we changed the JWT
	jwtChanged := false

	// 3. Create / patch secret with JWT and seed
	sec := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: req.Namespace}, sec); err != nil {
		if errors.IsNotFound(err) {
			jwtChanged = true
			sec.Type = corev1.SecretTypeOpaque
			sec.Name = secretName
			sec.Namespace = req.Namespace
			sec.StringData = map[string]string{
				"jwt":  jwtStr,
				"seed": seed,
				"pub":  pub,
			}
			// Add labels
			if sec.Labels == nil {
				sec.Labels = map[string]string{}
			}
			sec.Labels["app.kubernetes.io/managed-by"] = "nats-account-operator"
			sec.Labels["zerbytes.net/account"] = account.Name
			if err := ctrl.SetControllerReference(&account, sec, r.Scheme); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.Create(ctx, sec); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			return ctrl.Result{}, err
		}
	} else {
		if string(sec.Data["jwt"]) != jwtStr {
			jwtChanged = true
		}
		if string(sec.Data["jwt"]) != jwtStr || string(sec.Data["seed"]) != seed {
			sec.StringData = map[string]string{
				"jwt":  jwtStr,
				"seed": seed,
				"pub":  pub,
			}
			if err := r.Update(ctx, sec); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// 4. Update status
	if !account.Status.Ready {
		account.Status.Ready = true
		account.Status.AccountPublicKey = pub
		account.Status.SecretName = secretName
		if err := r.Status().Update(ctx, &account); err != nil {
			return ctrl.Result{}, err
		}
	}

	// -----------------------------------------------------------------
	// Push update to NATS if JWT changed
	// -----------------------------------------------------------------
	if jwtChanged {
		if err := pushJWT(jwtStr); err != nil {
			log.Error(err, "failed to push account JWT to NATS, will retry next reconcile")
			// don't fail reconcile; best effort
		} else {
			log.Info("pushed account JWT to NATS", "account", account.Name)
		}
	}

	return ctrl.Result{}, nil
}

func (r *NatsAccountReconciler) ensureAccountJWT(ctx context.Context, a *natsv1alpha1.NatsAccount, secretName string) (string, string, string, error) {
	// 1. Try to load existing keypair from the account secret
	var existing corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: a.Namespace}, &existing); err == nil {
		if seedB, ok := existing.Data["seed"]; ok && len(seedB) > 0 {
			kp, err := nkeys.FromSeed(seedB)
			if err == nil {
				pub, _ := kp.PublicKey()
				if jwtB, ok := existing.Data["jwt"]; ok {
					return pub, string(jwtB), string(seedB), nil // reuse existing
				}
			}
		}
	}

	// 2. Generate new account keypair (first creation path)
	kp, _ := nkeys.CreateAccount()
	pub, _ := kp.PublicKey()
	seed, _ := kp.Seed()

	// Build AccountClaims from spec
	ac := natsjwt.NewAccountClaims(pub)
	if a.Spec.JetStreamEnabled {
		ac.Limits.DiskStorage = -1
		ac.Limits.MemoryStorage = -1
		// TODO: map full limits from spec
	}
	if a.Spec.Expiration != nil {
		ac.Expires = a.Spec.Expiration.Unix()
	}

	// 3. **LOAD OR CREATE OPERATOR KEY** and sign the Account JWT
	opKp, _, err := GetOrCreateOperatorKP(ctx, r.Client, a.Namespace)
	if err != nil {
		return "", "", "", err
	}

	jwtStr, err := ac.Encode(opKp)
	if err != nil {
		return "", "", "", err
	}

	return pub, jwtStr, string(seed), nil
}

func (r *NatsAccountReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&natsv1alpha1.NatsAccount{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
