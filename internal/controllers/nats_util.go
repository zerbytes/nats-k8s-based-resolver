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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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

// GetNATSConn returns a shared connection using env vars:
//
//	NATS_URL   – e.g. nats://nats:4222
//	NATS_CREDS – path to resolver creds (user in $SYS)
func GetNATSConn() (*nats.Conn, error) {
	connOnce.Do(func() {
		if natsURL == "" {
			natsURL = "nats://nats:4222" // sensible default
		}
		opts := []nats.Option{nats.Name("nats-account-operator")}
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
func pushJWT(jwt string) error {
	nc, err := GetNATSConn()
	if err != nil {
		return err
	}
	if !nc.IsConnected() {
		return nc.LastError()
	}
	subj := "$SYS.REQ.CLAIMS.UPDATE"
	_, err = nc.Request(subj, []byte(jwt), 2*time.Second)
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
	sysSeed []byte, rotate bool,
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
	sec = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "nats-account-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"resolver.creds": creds,
		},
	}
	_ = client.IgnoreAlreadyExists(c.Create(ctx, &sec))
	return creds, nil
}
