//nolint:lll
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/puzpuzpuz/xsync/v4"
	natsv1alpha1 "github.com/zerbytes/nats-k8s-based-resolver/api/v1alpha1"
	"github.com/zerbytes/nats-k8s-based-resolver/internal/controllers"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
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
	metrics.Registry.MustRegister(lookupCounter, cacheHit, cacheMiss, pushCounter)

	setupLog, err := setupLogging()
	if err != nil {
		return err
	}

	mgr, k8sClient, err := initK8sManager(setupLog, cli)
	if err != nil {
		setupLog.Error(err, "manager")
		return err
	}

	if err := setupAccountInformer(mgr, k8sClient); err != nil {
		setupLog.Error(err, "informer")
		return err
	}

	var nc *nats.Conn
	// Bootstrap: Operator key & $SYS account + user Secret
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		// 1. Wait for informer cache
		if ok := mgr.GetCache().WaitForCacheSync(ctx); !ok {
			return fmt.Errorf("cache never syncs")
		}

		client := mgr.GetClient()

		// Operator key
		opKP, _, err := controllers.GetOrCreateOperatorKP(ctx, client, cli.PodNamespace)
		if err != nil {
			return err
		}

		controllers.SetNatsURL(cli.NatsURL)
		controllers.SetNatsCreds(cli.NatsCreds)

		// $SYS account (no rotation on first boot)
		if _, _, _, _, err := controllers.EnsureSysAccount(ctx, cli.NatsURL, client, cli.PodNamespace, opKP, false); err != nil {
			return fmt.Errorf("bootstrap sys account: %w", err)
		}

		// Setup NATS connection
		nc, err = controllers.GetNATSConn()
		if err != nil {
			return err
		}
		if err := setupNATSSubscriptions(nc, k8sClient, setupLog); err != nil {
			return err
		}
		setupLog.Info("NATS connection established")

		return nil
	})); err != nil {
		setupLog.Error(err, "add bootstrap runnable")
		os.Exit(1)
	}

	if err := preloadJWTs(mgr, k8sClient, cli.PodNamespace); err != nil {
		return err
	}

	// Add liveness / readiness endpoints
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		return err
	}

	setupLog.Info("starting resolver")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running resolver")
		return err
	}

	if nc != nil {
		//nolint:errcheck
		nc.Drain() // wait for NATS to finish processing
	}

	return nil
}

// initK8sManager initializes the Kubernetes manager and client
func initK8sManager(logger *zap.SugaredLogger, cli *MainCommand) (manager.Manager, client.Client, error) {
	var tlsOpts []func(*tls.Config)

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		logger.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !cli.EnableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   cli.MetricsAddr,
		SecureServing: cli.SecureMetrics,
		TLSOpts:       tlsOpts,
	}

	cfg := config.GetConfigOrDie()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: cli.ProbeAddr,
		LeaderElection:         false,
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
		if err := k8sClient.List(context.TODO(), &list, &client.ListOptions{Namespace: ""}); err == nil {
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
