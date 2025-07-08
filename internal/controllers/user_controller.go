package controllers

import (
	"bytes"
	"context"
	"fmt"
	"strings"
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

// +kubebuilder:rbac:groups=natsresolver.zerbytes.net,resources=natsusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=natsresolver.zerbytes.net,resources=natsusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// NatsUserReconciler reconciles a NatsUser object
type NatsUserReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	NS     string
}

func (r *NatsUserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	// 1. Load NatsUser CR
	var user natsv1alpha1.NatsUser
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	log.Info("reconciling NatsUser", "name", user.Name, "namespace", user.Namespace, "acct_ref", user.Spec.AccountRef.Name, "acc_ref_namespace", user.Spec.AccountRef.Namespace)

	desired := userDesiredFromSpec(&user)

	// 2. Fetch parent account
	var acct natsv1alpha1.NatsAccount
	if err := r.Get(ctx, types.NamespacedName{Name: user.Spec.AccountRef.Name, Namespace: user.Spec.AccountRef.Namespace}, &acct); err != nil {
		log.Error(err, "parent account not ready")
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
	if !acct.Status.Ready || acct.Status.SecretName == "" {
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}

	// 3. Load account seed
	var acctSec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: acct.Status.SecretName, Namespace: acct.Namespace}, &acctSec); err != nil {
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}
	accSeed := acctSec.Data["seed"]
	accKp, err := nkeys.FromSeed(accSeed)
	if err != nil {
		return ctrl.Result{}, err
	}
	accPubKey, _ := accKp.PublicKey() // Track account public key

	// 4. Determine if we need new creds or can reuse existing
	secretName := fmt.Sprintf("nats-user-%s-jwt", user.Name)
	var sec corev1.Secret
	first := errors.IsNotFound(r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: req.Namespace}, &sec))

	var (
		userKp  nkeys.KeyPair
		pubKey  string
		jwtStr  string
		seedStr string
		creds   string
		changed bool
	)

	if !first {
		// Try to parse existing creds
		creds = string(sec.Data["user.creds"])
		parts := strings.Split(creds, "\n")
		if len(parts) >= 2 {
			jwtStr, seedStr = extractJWTandSeed(creds)
			if jwtStr != "" && seedStr != "" {
				if kp, e := nkeys.FromSeed([]byte(seedStr)); e == nil {
					userKp = kp
					pubKey, _ = userKp.PublicKey()
				}
			}
		}
	}

	if userKp == nil { // no existing creds or parse failed
		changed = true
		userKp, _ = nkeys.CreateUser()
		pubKey, _ = userKp.PublicKey()
	}

	// Decide if we need to create/update the JWT
	if first {
		changed = true
	} else if user.Status.SigningKeyPublicKey != accPubKey {
		// If the signing key (account) changed, force regeneration
		changed = true
	} else {
		claim, _ := natsjwt.Decode(jwtStr)
		if uc, ok := claim.(*natsjwt.UserClaims); ok {
			if !desired.equal(desiredFromClaims(uc)) {
				changed = true
			}
		} else {
			changed = true
		}
	}

	if changed {
		uc := natsjwt.NewUserClaims(pubKey)
		if desired.exp != 0 {
			uc.Expires = desired.exp
		}
		// limits
		uc.Limits.Payload = desired.limits.payload
		uc.Subs = desired.limits.subs
		uc.Data = desired.limits.data
		// perms
		uc.Pub.Allow = desired.perms.pubAllow
		uc.Pub.Deny = desired.perms.pubDeny
		uc.Sub.Allow = desired.perms.subAllow
		uc.Sub.Deny = desired.perms.subDeny

		jwtStr, _ = uc.Encode(accKp)
		s, _ := userKp.Seed()
		seedStr = string(s)
		creds = fmt.Sprintf(credsTemplate, jwtStr, seedStr)
	}

	// 5. Create or update Secret
	if first {
		sec.Type = corev1.SecretTypeOpaque
		sec.Name = secretName
		sec.Namespace = req.Namespace
		sec.Data = map[string][]byte{
			"user.creds": []byte(creds),
		}
		if sec.Labels == nil {
			sec.Labels = map[string]string{}
		}
		sec.Labels["app.kubernetes.io/managed-by"] = "nats-account-operator"
		sec.Labels["zerbytes.net/account"] = acct.Name
		_ = ctrl.SetControllerReference(&user, &sec, r.Scheme)
		if err := r.Create(ctx, &sec); err != nil {
			return ctrl.Result{}, err
		}
	} else if changed {
		if !bytes.Equal(sec.Data["user.creds"], []byte(creds)) {
			sec.Data["user.creds"] = []byte(creds)
			if err := r.Update(ctx, &sec); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// 6. Update status
	if !user.Status.Ready || user.Status.UserPublicKey != pubKey || user.Status.SigningKeyPublicKey != accPubKey {
		user.Status.Ready = true
		user.Status.UserPublicKey = pubKey
		user.Status.SecretName = secretName
		user.Status.SigningKeyPublicKey = accPubKey
		if err := r.Status().Update(ctx, &user); err != nil {
			return ctrl.Result{}, err
		}
	}

	// No need to push user JWTs to the nats server/cluster.

	return ctrl.Result{RequeueAfter: 12 * time.Hour}, nil
}

type userLimits struct {
	payload int64
	subs    int64
	data    int64
}

type userPerms struct {
	pubAllow []string
	subAllow []string
	pubDeny  []string
	subDeny  []string
}

type userDesired struct {
	exp    int64
	limits userLimits
	perms  userPerms
}

func userDesiredFromSpec(u *natsv1alpha1.NatsUser) userDesired {
	d := userDesired{}
	if u.Spec.Expiration != nil {
		d.exp = u.Spec.Expiration.Unix()
	}
	if u.Spec.Limits != nil {
		if u.Spec.Limits.MaxPayload != nil {
			d.limits.payload = *u.Spec.Limits.MaxPayload
		} else {
			d.limits.payload = natsjwt.NoLimit
		}
		if u.Spec.Limits.MaxSubs != nil {
			d.limits.subs = *u.Spec.Limits.MaxSubs
		} else {
			d.limits.subs = natsjwt.NoLimit
		}
		if u.Spec.Limits.MaxData != nil {
			d.limits.data = *u.Spec.Limits.MaxData
		} else {
			d.limits.data = natsjwt.NoLimit
		}
	} else {
		d.limits.payload = natsjwt.NoLimit
		d.limits.subs = natsjwt.NoLimit
		d.limits.data = natsjwt.NoLimit
	}
	if u.Spec.Permissions != nil {
		d.perms = userPerms{
			pubAllow: u.Spec.Permissions.Publish.Allow,
			subAllow: u.Spec.Permissions.Subscribe.Allow,
			pubDeny:  u.Spec.Permissions.Publish.Deny,
			subDeny:  u.Spec.Permissions.Subscribe.Deny,
		}
	} else {
		d.perms = userPerms{
			pubAllow: []string{">"},
			subAllow: []string{">", "_INBOX.>"},
			pubDeny:  []string{},
			subDeny:  []string{},
		}
	}
	return d
}

func desiredFromClaims(uc *natsjwt.UserClaims) userDesired {
	d := userDesired{exp: uc.Expires}
	d.limits.payload = uc.Limits.Payload
	d.limits.subs = uc.Subs
	d.limits.data = uc.Data
	d.perms = userPerms{
		pubAllow: uc.Pub.Allow,
		pubDeny:  uc.Pub.Deny,
		subAllow: uc.Sub.Allow,
		subDeny:  uc.Sub.Deny,
	}
	return d
}

// equal compares all fields including unordered slices
func (d userDesired) equal(o userDesired) bool {
	if d.exp != o.exp || d.limits != o.limits {
		return false
	}
	return sliceEqual(d.perms.pubAllow, o.perms.pubAllow) &&
		sliceEqual(d.perms.pubDeny, o.perms.pubDeny) &&
		sliceEqual(d.perms.subAllow, o.perms.subAllow) &&
		sliceEqual(d.perms.subDeny, o.perms.subDeny)
}

// sliceEqual returns true if two string slices contain the same elements regardless of order/dupes
func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		if m[s] == 0 {
			return false
		}
		m[s]--
	}
	return true
}

func (r *NatsUserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&natsv1alpha1.NatsUser{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
