package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/puzpuzpuz/xsync/v4"
	natsv1 "github.com/zerbytes/nats-based-resolver/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

type cacheEntry struct {
	jwt string
	ts  time.Time
}

var (
	lookupCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nats_resolver_jwt_lookups_total",
		Help: "Total JWT lookup requests served",
	})
	cacheHit = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nats_resolver_jwt_cache_hits_total",
		Help: "Cache hits for account JWT lookups",
	})
	cacheMiss = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nats_resolver_jwt_cache_misses_total",
		Help: "Cache misses for account JWT lookups",
	})
	pushCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nats_resolver_jwt_push_total",
		Help: "Total proactive JWT pushes to NATS",
	})
)

var jwtCache = xsync.NewMap[string, cacheEntry]()

type ResolverCmd struct{}

func (c *ResolverCmd) Run(cli *MainCommand) error {
	prometheus.MustRegister(lookupCounter, cacheHit, cacheMiss, pushCounter)

	// 1. Connect to Kubernetes
	cfg := config.GetConfigOrDie()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		}, // disable default metrics
		LeaderElection: false,
	})
	if err != nil {
		setupLog.Error(err, "manager")
		return err
	}

	// Shared client for secret fetches
	k8sClient := mgr.GetClient()

	// 2. In-memory cache populated via informer
	accInformer, err := mgr.GetCache().GetInformer(context.TODO(), &natsv1.NatsAccount{})
	if err != nil {
		setupLog.Error(err, "informer")
		return err
	}

	if _, err := accInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			account := obj.(*natsv1.NatsAccount)
			maybeUpdateCache(context.TODO(), k8sClient, account, jwtCache)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			account := newObj.(*natsv1.NatsAccount)
			maybeUpdateCache(context.TODO(), k8sClient, account, jwtCache)
		},
		DeleteFunc: func(obj interface{}) {
			account := obj.(*natsv1.NatsAccount)
			jwtCache.Delete(account.Status.AccountPublicKey)
		},
	}); err != nil {
		setupLog.Error(err, "add event handler")
		return err
	}

	// 3. Connect to NATS
	natsURL := os.Getenv("NATS_URL")
	credsPath := os.Getenv("NATS_CREDS")
	nc, err := nats.Connect(natsURL, nats.UserCredentials(credsPath))
	if err != nil {
		setupLog.Error(err, "nats connect")
		return err
	}
	//nolint:errcheck
	defer nc.Drain()

	// 4. Subscribe for account lookup requests
	_, err = nc.Subscribe("$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP", func(m *nats.Msg) {
		lookupCounter.Inc()
		parts := strings.Split(m.Subject, ".")
		if len(parts) < 6 {
			_ = m.Respond(nil)
			return
		}
		accountID := parts[4]
		if entry, ok := jwtCache.Load(accountID); ok {
			cacheHit.Inc()
			_ = m.Respond([]byte(entry.jwt))
			return
		}
		cacheMiss.Inc()
		// On miss, fetch from K8s - simplified example
		var list natsv1.NatsAccountList
		if err := k8sClient.List(context.TODO(), &list); err == nil {
			for _, a := range list.Items {
				if a.Status.AccountPublicKey == accountID && a.Status.SecretName != "" {
					var sec corev1.Secret
					if err := k8sClient.Get(context.TODO(), client.ObjectKey{
						Name:      a.Status.SecretName,
						Namespace: a.Namespace,
					}, &sec); err == nil {
						jwtStr := string(sec.Data["jwt"])
						jwtCache.Store(a.Status.AccountPublicKey, cacheEntry{jwt: jwtStr, ts: time.Now()})
						_ = m.Respond([]byte(jwtStr))
						return
					}
				}
			}
		}
		_ = m.Respond(nil) // not found
	})
	if err != nil {
		setupLog.Error(err, "subscribe")
		return err
	}

	// 5. Serve metrics
	http.Handle("/metrics", promhttp.Handler())
	log.Println("resolver service ready: metrics on :2112/metrics")
	if err := http.ListenAndServe(":2112", nil); err != nil {
		setupLog.Error(err, "metrics server")
		return err
	}

	select {}
}

// maybeUpdateCache loads the JWT from the referenced secret and updates map
func maybeUpdateCache(ctx context.Context, c client.Client,
	acc *natsv1.NatsAccount, store *xsync.Map[string, cacheEntry],
) {
	if !acc.Status.Ready || acc.Status.SecretName == "" || acc.Status.AccountPublicKey == "" {
		return
	}
	var sec corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: acc.Status.SecretName, Namespace: acc.Namespace}, &sec); err != nil {
		return
	}
	jwtBytes, ok := sec.Data["jwt"]
	if !ok {
		return
	}
	store.Store(acc.Status.AccountPublicKey, cacheEntry{jwt: string(jwtBytes), ts: time.Now()})
}
