package controllers

import (
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

var (
	connOnce sync.Once
	nConn    *nats.Conn
	connErr  error
)

// getNATSConn returns a shared connection using env vars:
//
//	NATS_URL   – e.g. nats://nats:4222
//	NATS_CREDS – path to resolver creds (user in $SYS)
func getNATSConn() (*nats.Conn, error) {
	connOnce.Do(func() {
		url := os.Getenv("NATS_URL")
		creds := os.Getenv("NATS_CREDS")
		if url == "" {
			url = "nats://nats:4222" // sensible default
		}
		opts := []nats.Option{nats.Name("nats-account-operator")}
		if creds != "" {
			opts = append(opts, nats.UserCredentials(creds))
		}
		nConn, connErr = nats.Connect(url, opts...)
	})
	return nConn, connErr
}

// pushJWT publishes *any* NATS JWT (Account or User) on $SYS.REQ.CLAIMS.UPDATE.
// NATS servers will parse and cache based on the JWT type.
// Waits up to 2 s for an ACK but ignores the body.
func pushJWT(jwt string) error {
	nc, err := getNATSConn()
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
