package controllers

import (
	"bytes"
	"context"
	"fmt"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	nkeys "github.com/nats-io/nkeys"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	natsv1alpha1 "github.com/zerbytes/nats-k8s-based-resolver/api/v1alpha1"
)

// +kubebuilder:rbac:groups=natsresolver.zerbytes.net,resources=natsaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=natsresolver.zerbytes.net,resources=natsaccounts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// NatsAccountReconciler reconciles a NatsAccount object
type NatsAccountReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *NatsAccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	// 1. Fetch NatsAccount CR
	var acct natsv1alpha1.NatsAccount
	if err := r.Get(ctx, req.NamespacedName, &acct); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	desired := accDesiredFromSpec(&acct)

	// 2. Determine if we need new creds or can reuse existing
	secretName := fmt.Sprintf("nats-account-%s-jwt", acct.Name)
	var sec corev1.Secret
	first := errors.IsNotFound(r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: req.Namespace}, &sec))

	var (
		kp      nkeys.KeyPair
		pubKey  string
		seedStr string
		jwtStr  string
		changed bool
	)

	if !first {
		// Try to parse existing secret
		if b := sec.Data["seed"]; len(b) > 0 {
			if k, e := nkeys.FromSeed(b); e == nil {
				kp = k
				pubKey, _ = kp.PublicKey()
				seedStr = string(b)
			}
		}
		jwtStr = string(sec.Data["jwt"])
	}

	if kp == nil { // no keypair found
		changed = true
		kp, _ = nkeys.CreateAccount()
		pubKey, _ = kp.PublicKey()
		s, _ := kp.Seed()
		seedStr = string(s)
	}

	// Decide if we need to create/update the JWT
	if first {
		changed = true
	} else {
		claim, _ := natsjwt.Decode(jwtStr)
		if ac, ok := claim.(*natsjwt.AccountClaims); ok {
			if !desired.equal(accDesiredFromClaims(ac)) {
				changed = true
			}
		} else {
			changed = true
		}
	}

	if changed {
		// build new JWT
		opKp, _, err := GetOrCreateOperatorKP(ctx, r.Client, acct.Namespace)
		if err != nil {
			return ctrl.Result{}, err
		}
		ac := natsjwt.NewAccountClaims(pubKey)
		// copy limits
		ac.Limits.Conn = desired.limits.conns
		ac.Limits.Subs = desired.limits.subs
		ac.Limits.Data = desired.limits.data
		ac.Limits.Payload = desired.limits.payload
		ac.Limits.DiskStorage = desired.limits.diskStorage
		ac.Limits.MemoryStorage = desired.limits.memoryStorage
		if desired.exp != 0 {
			ac.Expires = desired.exp
		}
		jwtStr, err = ac.Encode(opKp)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	if first {
		sec.Type = corev1.SecretTypeOpaque
		sec.Name = secretName
		sec.Namespace = req.Namespace
		sec.Data = map[string][]byte{"jwt": []byte(jwtStr), "seed": []byte(seedStr)}
		if sec.Labels == nil {
			sec.Labels = map[string]string{}
		}
		sec.Labels["app.kubernetes.io/managed-by"] = "nats-account-operator"
		sec.Labels["zerbytes.net/account"] = acct.Name
		_ = ctrl.SetControllerReference(&acct, &sec, r.Scheme)
		if err := r.Create(ctx, &sec); err != nil {
			return ctrl.Result{}, err
		}
	} else if changed {
		dirty := false
		if !bytes.Equal(sec.Data["jwt"], []byte(jwtStr)) {
			sec.Data["jwt"] = []byte(jwtStr)
			dirty = true
		}
		if !bytes.Equal(sec.Data["seed"], []byte(seedStr)) {
			sec.Data["seed"] = []byte(seedStr)
			dirty = true
		}
		if dirty {
			if err := r.Update(ctx, &sec); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// 4. Status update with error handling
	if !acct.Status.Ready || acct.Status.AccountPublicKey != pubKey {
		acct.Status.Ready = true
		acct.Status.AccountPublicKey = pubKey
		acct.Status.SecretName = secretName
		if err := r.Status().Update(ctx, &acct); err != nil {
			return ctrl.Result{}, err
		}
	}

	// 5. Push JWT to NATS if changed
	if changed {
		if err := pushJWT(jwtStr); err != nil {
			log.Error(err, "failed to push account JWT to NATS, will retry later", "account", acct.Name)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{RequeueAfter: 12 * time.Hour}, nil
}

type accDesired struct {
	limits accLimits
	exp    int64
}

func (a accDesired) equal(b accDesired) bool {
	return a == b
}

func accDesiredFromSpec(a *natsv1alpha1.NatsAccount) accDesired {
	d := accDesired{limits: accLimitsFromSpec(a)}
	if a.Spec.Expiration != nil {
		d.exp = a.Spec.Expiration.Unix()
	}
	return d
}

func accDesiredFromClaims(ac *natsjwt.AccountClaims) accDesired {
	return accDesired{limits: accLimitsFromClaims(ac), exp: ac.Expires}
}

type accLimits struct {
	conns, subs, data, payload, diskStorage, memoryStorage int64
	jetstream                                              bool
}

func accLimitsFromSpec(a *natsv1alpha1.NatsAccount) accLimits {
	var l accLimits
	if a.Spec.Limits != nil {
		if a.Spec.Limits.MaxConnections != nil {
			l.conns = int64(*a.Spec.Limits.MaxConnections)
		} else {
			l.conns = -1 // default to unlimited if not set
		}
		if a.Spec.Limits.MaxSubs != nil {
			l.subs = int64(*a.Spec.Limits.MaxSubs)
		} else {
			l.subs = -1 // default to unlimited if not set
		}
		if a.Spec.Limits.MaxData != nil {
			l.data = int64(*a.Spec.Limits.MaxData)
		} else {
			l.data = -1 // default to unlimited if not set
		}
		if a.Spec.Limits.MaxPayload != nil {
			l.payload = int64(*a.Spec.Limits.MaxPayload)
		} else {
			l.payload = -1 // default to unlimited if not set
		}
		if a.Spec.Limits.MaxDiskStorage != nil {
			l.diskStorage = int64(*a.Spec.Limits.MaxDiskStorage)
		} else {
			l.diskStorage = -1 // default to unlimited if not set
		}
		if a.Spec.Limits.MaxMemoryStorage != nil {
			l.memoryStorage = int64(*a.Spec.Limits.MaxMemoryStorage)
		} else {
			l.memoryStorage = -1 // default to unlimited if not set
		}
	} else {
		// default to unlimited if not set
		l.conns = -1
		l.subs = -1
		l.data = -1
		l.payload = -1
		l.diskStorage = -1
		l.memoryStorage = -1
	}
	l.jetstream = a.Spec.JetStreamEnabled
	return l
}

func accLimitsFromClaims(ac *natsjwt.AccountClaims) accLimits {
	var l accLimits
	l.conns = ac.Limits.Conn
	l.subs = ac.Limits.Subs
	l.data = ac.Limits.Data
	l.payload = ac.Limits.Payload
	l.diskStorage = ac.Limits.DiskStorage
	l.memoryStorage = ac.Limits.MemoryStorage
	l.jetstream = ac.Limits.DiskStorage != 0 || ac.Limits.MemoryStorage != 0
	return l
}

func (r *NatsAccountReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&natsv1alpha1.NatsAccount{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
