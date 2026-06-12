package controllers

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	nkeys "github.com/nats-io/nkeys"
	natsv1alpha1 "github.com/zerbytes/nats-k8s-based-resolver/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const NatsSYSAcc = "$SYS"

// Kubernetes label values cannot contain '$', so use a safe representation for
// the system account when storing it in secret metadata.
const NatsSYSAccountLabelValue = "SYS"

const credsTemplate = `---- BEGIN NATS USER JWT ----
%s
------ END NATS USER JWT ------

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
%s
------END USER NKEY SEED------

*************************************************************
`

var (
	connOnce  sync.Once
	natsURL   string
	natsCreds string

	nConn   *nats.Conn
	connErr error
)

func SetNatsURL(url string) {
	natsURL = url
}

func SetNatsCreds(creds string) {
	natsCreds = creds
}

func accountLabelValue(account string) string {
	if account == NatsSYSAcc {
		return NatsSYSAccountLabelValue
	}

	return account
}

// GetNATSConn returns a shared connection using env vars:
//
//	NATS_URL   – e.g. nats://nats:4222
//	NATS_CREDS – path to resolver creds (user in $SYS)
func GetNATSConn() (*nats.Conn, error) {
	connOnce.Do(func() {
		if natsURL == "" {
			natsURL = "nats://nats:4222" // sensible default
		}
		opts := []nats.Option{nats.Name(AccountOperatorName)}
		if natsCreds != "" {
			opts = append(opts, nats.UserCredentials(natsCreds))
		}
		nConn, connErr = nats.Connect(natsURL, opts...)
	})
	return nConn, connErr
}

// pushJWT publishes *any* NATS JWT (Account or User) on $SYS.REQ.CLAIMS.UPDATE.
// NATS servers will parse and cache based on the JWT type.
// Waits up to 2 s for an ACK but ignores the body.
// https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt#subjects-available-when-using-nats-based-resolver
func pushJWT(ctx context.Context, jwt string) error {
	nc, err := GetNATSConn()
	if err != nil {
		return err
	}
	if !nc.IsConnected() {
		return nc.LastError()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = nc.RequestWithContext(ctx, "$SYS.REQ.CLAIMS.UPDATE", []byte(jwt))
	return err
}

// deleteJWT publishes a JWT delete event on $SYS.REQ.CLAIMS.DELETE.
// NATS servers will only delete the JWT when `resolver` -> `allow_delete: true` is set.
// https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt#subjects-available-when-using-nats-based-resolver
func deleteJWT(ctx context.Context, c client.Client, operatorNS string, accountID string) error {
	if accountID == "" {
		return fmt.Errorf("account id is required")
	}

	_, opKp, _, err := GetOrCreateOperatorKP(ctx, c, operatorNS)
	if err != nil {
		return err
	}
	opPub, err := opKp.PublicKey()
	if err != nil {
		return err
	}

	claim := natsjwt.NewGenericClaims(opPub)
	claim.Data["accounts"] = []string{accountID}
	jwt, err := claim.Encode(opKp)
	if err != nil {
		return err
	}

	nc, err := GetNATSConn()
	if err != nil {
		return err
	}
	if !nc.IsConnected() {
		return nc.LastError()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = nc.RequestWithContext(ctx, "$SYS.REQ.CLAIMS.DELETE", []byte(jwt))
	return err
}

func extractJWTandSeed(creds string) (jwt, seed string) {
	lines := strings.Split(strings.TrimSpace(creds), "\n")
	for i, l := range lines {
		switch {
		case l == "---- BEGIN NATS USER JWT ----" && i+1 < len(lines):
			jwt = lines[i+1]
		case l == "-----BEGIN USER NKEY SEED-----" && i+1 < len(lines):
			seed = lines[i+1]
		}
	}
	return
}

func EnsureSysResolverUser(ctx context.Context, c client.Client, ns string,
	sysSeed []byte, owner client.Object, scheme *runtime.Scheme, rotate bool,
) (creds string, err error) {
	const secretName = "nats-sys-resolver-creds"

	// 1. Reuse existing secret unless rotate == true
	var sec corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: ns}, &sec); err == nil && !rotate {
		return string(sec.Data["resolver.creds"]), nil
	}

	// 2. Build an NKey & User JWT signed by the $SYS seed
	sysKP, _ := nkeys.FromSeed(sysSeed)
	sysPub, _ := sysKP.PublicKey()

	userKP, _ := nkeys.CreateUser()
	userPub, _ := userKP.PublicKey()

	uc := natsjwt.NewUserClaims(userPub) // no extra limits
	uc.IssuerAccount = sysPub
	jwtStr, _ := uc.Encode(sysKP)
	seed, _ := userKP.Seed()

	creds = fmt.Sprintf(credsTemplate, jwtStr, seed) // same template you already have

	// 3. Persist in Secret
	sec = corev1.Secret{}
	if err := prepareManagedSecret(&sec, owner, scheme, secretName, ns, map[string]string{
		natsv1alpha1.GroupName + "/account": accountLabelValue(NatsSYSAcc),
	}, map[string][]byte{
		"resolver.creds": []byte(creds),
	}); err != nil {
		return "", err
	}
	err = client.IgnoreAlreadyExists(c.Create(ctx, &sec))
	return creds, err
}
