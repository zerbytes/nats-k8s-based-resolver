//nolint:lll
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/puzpuzpuz/xsync/v4"
	natsv1alpha1 "github.com/zerbytes/nats-k8s-based-resolver/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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

type ResolverCmd struct {
	NatsURL   string `env:"NATS_URL" help:"NATS server URL, e.g. nats://localhost:4222"`
	NatsCreds string `env:"NATS_CREDS" help:"Path to NATS $SYS user credentials file (e.g., secret named \"nats-sys-resolver-creds\")"`
}

func (c *ResolverCmd) Run(cli *MainCommand) error {
	prometheus.MustRegister(lookupCounter, cacheHit, cacheMiss, pushCounter)

	setupLog, err := setupLogging()
	if err != nil {
		return err
	}

	mgr, k8sClient, err := initK8sManager()
	if err != nil {
		setupLog.Error(err, "manager")
		return err
	}

	if err := setupAccountInformer(mgr, k8sClient); err != nil {
		setupLog.Error(err, "informer")
		return err
	}

	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "default"
	}

	nc, err := connectNATS(cli.Resolver.NatsURL, cli.Resolver.NatsCreds, setupLog)
	if err != nil {
		return err
	}
	defer func() {
		if nc == nil {
			return
		}
		//nolint:errcheck
		nc.Drain()
	}()

	if err := preloadJWTs(mgr, k8sClient, ns); err != nil {
		return err
	}

	if err := setupNATSSubscriptions(nc, k8sClient, setupLog); err != nil {
		return err
	}

	if err := startMetricsServer(mgr); err != nil {
		return err
	}

	setupLog.Info("starting resolver")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running resolver")
		return err
	}

	return nil
}

// initK8sManager initializes the Kubernetes manager and client
func initK8sManager() (manager.Manager, client.Client, error) {
	cfg := config.GetConfigOrDie()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		LeaderElection: false,
	})
	if err != nil {
		return nil, nil, err
	}
	return mgr, mgr.GetClient(), nil
}

// setupAccountInformer sets up the informer and cache event handlers
func setupAccountInformer(mgr manager.Manager, k8sClient client.Client) error {
	accInformer, err := mgr.GetCache().GetInformer(context.TODO(), &natsv1alpha1.NatsAccount{})
	if err != nil {
		return err
	}
	if _, err := accInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			account := obj.(*natsv1alpha1.NatsAccount)
			maybeUpdateCache(context.TODO(), k8sClient, account, jwtCache)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			account := newObj.(*natsv1alpha1.NatsAccount)
			maybeUpdateCache(context.TODO(), k8sClient, account, jwtCache)
		},
		DeleteFunc: func(obj interface{}) {
			account := obj.(*natsv1alpha1.NatsAccount)
			jwtCache.Delete(account.Status.AccountPublicKey)
		},
	}); err != nil {
		return err
	}
	return nil
}

// connectNATS connects to the NATS server
func connectNATS(url, creds string, setupLog *zap.SugaredLogger) (*nats.Conn, error) {
	if url == "" {
		return nil, nil
	}

	nc, err := nats.Connect(url, nats.UserCredentials(creds))
	if err != nil {
		setupLog.Error(err, "nats connect")
		return nil, err
	}
	return nc, nil
}

// preloadJWTs preloads operator and $SYS JWTs into the cache
func preloadJWTs(mgr manager.Manager, k8sClient client.Client, ns string) error {
	return mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		// 1. wait until the informer cache is ready
		if ok := mgr.GetCache().WaitForCacheSync(ctx); !ok {
			return fmt.Errorf("cache never syncs")
		}

		// 2. now it's safe to use the cached client
		var list natsv1alpha1.NatsAccountList
		if err := k8sClient.List(ctx, &list); err != nil {
			return err
		}
		for i := range list.Items {
			maybeUpdateCache(ctx, k8sClient, &list.Items[i], jwtCache)
		}

		// 3. Pre-load operator and $SYS account JWT
		var opSec corev1.Secret
		if err := k8sClient.Get(ctx,
			types.NamespacedName{Name: "nats-operator-jwt", Namespace: ns}, &opSec); err == nil {

			opJWT := string(opSec.Data["jwt"])
			if subj, err := natsjwt.Decode(opJWT); err == nil {
				if oc, ok := subj.(*natsjwt.OperatorClaims); ok {
					jwtCache.Store(oc.Subject, cacheEntry{jwt: opJWT, ts: time.Now()})
				}
			}
		}

		var sysSec corev1.Secret
		if err := k8sClient.Get(ctx,
			types.NamespacedName{Name: "nats-sys-account-jwt", Namespace: ns}, &sysSec); err == nil {

			sysJWT := string(sysSec.Data["jwt"])
			if subj, err := natsjwt.Decode(sysJWT); err == nil {
				if ac, ok := subj.(*natsjwt.AccountClaims); ok {
					jwtCache.Store(ac.Subject, cacheEntry{jwt: sysJWT, ts: time.Now()})
				}
			}
		}

		return nil
	}))
}

// setupNATSSubscriptions sets up NATS subscriptions for account lookups
func setupNATSSubscriptions(nc *nats.Conn, k8sClient client.Client, setupLog *zap.SugaredLogger) error {
	_, err := nc.Subscribe("$SYS.REQ.OPERATOR.CLAIMS.LOOKUP", func(m *nats.Msg) {
		if entry, ok := jwtCache.Load("operator"); ok {
			_ = m.Respond([]byte(entry.jwt))
		} else {
			_ = m.Respond(nil)
		}
	})
	if err != nil {
		setupLog.Error(err, "subscribe operator lookup")
		return err
	}
	_, err = nc.Subscribe("$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP", func(m *nats.Msg) {
		lookupCounter.Inc()
		parts := strings.Split(m.Subject, ".")
		if len(parts) < 6 {
			_ = m.Respond(nil)
			return
		}
		accountID := parts[3]
		if entry, ok := jwtCache.Load(accountID); ok {
			cacheHit.Inc()
			_ = m.Respond([]byte(entry.jwt))
			return
		}
		cacheMiss.Inc()
		// On miss, fetch from K8s
		var list natsv1alpha1.NatsAccountList
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
						if err = m.Respond([]byte(jwtStr)); err != nil {
							setupLog.Error(err, "respond with JWT", "account", accountID)
						}
						return
					}
				}
			}
		} else {
			setupLog.Error(err, "list accounts")
		}

		if err = m.Respond(nil); err != nil { // not found
			setupLog.Error(err, "respond with nil", "account", accountID)
		}
	})
	if err != nil {
		setupLog.Error(err, "subscribe account lookup")
		return err
	}
	return nil
}

// startMetricsServer starts the Prometheus metrics server
func startMetricsServer(mgr manager.Manager) error {
	return mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		srv := &http.Server{
			Addr:    ":2112",
			Handler: mux,
		}

		// graceful shutdown when mgr stops
		go func() {
			<-ctx.Done()
			_ = srv.Shutdown(context.Background())
		}()

		log.Println("[resolver] metrics server listening on :2112/metrics")
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			return err
		}
		return nil
	}))
}

// maybeUpdateCache loads the JWT from the referenced secret and updates map
func maybeUpdateCache(ctx context.Context, c client.Client,
	acc *natsv1alpha1.NatsAccount, store *xsync.Map[string, cacheEntry],
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
