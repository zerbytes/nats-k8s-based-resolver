package controllers

import (
	"context"
	"fmt"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	nkeys "github.com/nats-io/nkeys"
	natsv1 "github.com/zerbytes/nats-based-resolver/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NatsUserReconciler reconciles a NatsUser object
// +kubebuilder:rbac:groups=natsresolver.zerbytes.net,resources=natsusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=natsresolver.zerbytes.net,resources=natsusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

type NatsUserReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *NatsUserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	// 1. Load NatsUser CR
	var user natsv1.NatsUser
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// 2. Fetch parent account secret for seed.
	var acct natsv1.NatsAccount
	if err := r.Get(ctx, types.NamespacedName{Name: user.Spec.AccountRef.Name, Namespace: user.Spec.AccountRef.Namespace}, &acct); err != nil {
		log.Error(err, "parent account not ready")
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	if !acct.Status.Ready {
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// 3. Load account seed from the secret
	var acctSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: acct.Status.SecretName, Namespace: acct.Namespace}, &acctSecret); err != nil {
		log.Error(err, "unable to load account secret")
		return ctrl.Result{RequeueAfter: time.Minute * 1}, nil
	}
	seedBytes, ok := acctSecret.Data["seed"]
	if !ok || len(seedBytes) == 0 {
		log.Info("account seed missing – requeue")
		return ctrl.Result{RequeueAfter: time.Minute * 1}, nil
	}
	accKp, err := nkeys.FromSeed(seedBytes)
	if err != nil {
		log.Error(err, "invalid account seed")
		return ctrl.Result{}, err
	}

	// 4. Create user key & JWT
	userKp, _ := nkeys.CreateUser()
	pub, _ := userKp.PublicKey()

	uc := natsjwt.NewUserClaims(pub)
	if user.Spec.Expiration != nil {
		uc.Expires = user.Spec.Expiration.Unix()
	}
	jwtStr, err := uc.Encode(accKp)
	if err != nil {
		return ctrl.Result{}, err
	}

	seed, _ := userKp.Seed()
	creds := fmt.Sprintf(`---- BEGIN NATS USER JWT ----
%s
------ END NATS USER JWT ------

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
%s
------END USER NKEY SEED------

*************************************************************
`, jwtStr, seed)

	secretName := fmt.Sprintf("nats-user-%s-jwt", user.Name)
	sec := &corev1.Secret{}
	jwtChanged := false

	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: req.Namespace}, sec); err != nil {
		if errors.IsNotFound(err) {
			jwtChanged = true
			sec.Type = corev1.SecretTypeOpaque
			sec.ObjectMeta.Name = secretName
			sec.ObjectMeta.Namespace = req.Namespace
			sec.StringData = map[string]string{
				"user.creds": creds,
			}
			if sec.Labels == nil {
				sec.Labels = map[string]string{}
			}
			sec.Labels["app.kubernetes.io/managed-by"] = "nats-account-operator"
			sec.Labels["zerbytes.net/account"] = acct.Name
			if err := ctrl.SetControllerReference(&user, sec, r.Scheme); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.Create(ctx, sec); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			return ctrl.Result{}, err
		}
	} else {
		if string(sec.Data["user.creds"]) != creds {
			jwtChanged = true
			sec.StringData = map[string]string{
				"user.creds": creds,
			}
			if err := r.Update(ctx, sec); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// 4. Update status
	if !user.Status.Ready {
		user.Status.Ready = true
		user.Status.UserPublicKey = pub
		user.Status.SecretName = secretName
		if err := r.Status().Update(ctx, &user); err != nil {
			return ctrl.Result{}, err
		}
	}

	// 5. Push User JWT to NATS so servers refresh cache
	if jwtChanged {
		if err := pushJWT(jwtStr); err != nil {
			log.Error(err, "failed to push user JWT to NATS, will retry later")
		} else {
			log.Info("pushed user JWT to NATS", "user", user.Name, "account", acct.Name)
		}
	}

	return ctrl.Result{}, nil
}

func (r *NatsUserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&natsv1.NatsUser{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
