//nolint:lll
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-logr/zapr"
	natsv1alpha1 "github.com/zerbytes/nats-based-resolver/api/v1alpha1"
	"github.com/zerbytes/nats-based-resolver/internal/controllers"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(natsv1alpha1.AddToScheme(scheme))
}

type MainCommand struct {
	// Manager is the command to run the NATS-based resolver controller manager/operator.
	Manager ManagerCmd `cmd:"" default:"withargs" help:"Run the NATS-based resolver controller manager/operator."`

	// Resolver is the command to run the NATS-based resolver.
	Resolver ResolverCmd `cmd:"" help:"Run the NATS-based resolver resolver."`
}

type ManagerCmd struct {
	MetricsAddr          string `name:"metrics-bind-address" default:"0" help:"The address the metrics endpoint binds to. Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service."`
	ProbeAddr            string `name:"health-probe-bind-address" default:":8081" help:"The address the probe endpoint binds to."`
	EnableLeaderElection bool   `name:"leader-elect" default:"false" help:"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager."`
	SecureMetrics        bool   `name:"metrics-secure" default:"true" help:"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead."`
	WebhookCertPath      string `name:"webhook-cert-path" default:"" help:"The directory that contains the webhook certificate."`
	WebhookCertName      string `name:"webhook-cert-name" default:"tls.crt" help:"The name of the webhook certificate file."`
	WebhookCertKey       string `name:"webhook-cert-key" default:"tls.key" help:"The name of the webhook key file."`
	MetricsCertPath      string `name:"metrics-cert-path" default:"" help:"The directory that contains the metrics server certificate."`
	MetricsCertName      string `name:"metrics-cert-name" default:"tls.crt" help:"The name of the metrics server certificate file."`
	MetricsCertKey       string `name:"metrics-cert-key" default:"tls.key" help:"The name of the metrics server key file."`
	EnableHTTP2          bool   `name:"enable-http2" default:"false" help:"If set, HTTP/2 will be enabled for the metrics and webhook servers"`
}

func (c *ManagerCmd) Run(cli *MainCommand) error {
	zapLog, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("who watches the watchmen (%v)?", err))
	}
	ctrl.SetLogger(zapr.NewLogger(zapLog))

	var tlsOpts []func(*tls.Config)

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !cli.Manager.EnableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Create watchers for metrics and webhooks certificates
	var metricsCertWatcher, webhookCertWatcher *certwatcher.CertWatcher

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts

	if len(cli.Manager.WebhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", cli.Manager.WebhookCertPath, "webhook-cert-name", cli.Manager.WebhookCertName, "webhook-cert-key", cli.Manager.WebhookCertKey)

		var err error
		webhookCertWatcher, err = certwatcher.New(
			filepath.Join(cli.Manager.WebhookCertPath, cli.Manager.WebhookCertName),
			filepath.Join(cli.Manager.WebhookCertPath, cli.Manager.WebhookCertKey),
		)
		if err != nil {
			setupLog.Error(err, "Failed to initialize webhook certificate watcher")
			return err
		}

		webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
			config.GetCertificate = webhookCertWatcher.GetCertificate
		})
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: webhookTLSOpts,
	})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   cli.Manager.MetricsAddr,
		SecureServing: cli.Manager.SecureMetrics,
		TLSOpts:       tlsOpts,
	}

	if cli.Manager.SecureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(cli.Manager.MetricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", cli.Manager.MetricsCertPath, "metrics-cert-name", cli.Manager.MetricsCertName, "metrics-cert-key", cli.Manager.MetricsCertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(cli.Manager.MetricsCertPath, cli.Manager.MetricsCertName),
			filepath.Join(cli.Manager.MetricsCertPath, cli.Manager.MetricsCertKey),
		)
		if err != nil {
			setupLog.Error(err, "to initialize metrics certificate watcher", "error", err)
			return err
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: cli.Manager.ProbeAddr,
		LeaderElection:         cli.Manager.EnableLeaderElection,
		LeaderElectionID:       "nats-based-resolver-controller",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return err
	}

	// Bootstrap: Operator key & $SYS account Secret
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		// 1. Wait for informer cache
		if ok := mgr.GetCache().WaitForCacheSync(ctx); !ok {
			return fmt.Errorf("cache never syncs")
		}
		// Use POD_NAMESPACE (set by the Helm chart) or fallback "default"
		ns := os.Getenv("POD_NAMESPACE")
		if ns == "" {
			ns = "default"
		}
		client := mgr.GetClient()

		// Operator key
		opKP, _, err := controllers.GetOrCreateOperatorKP(ctx, client, ns)
		if err != nil {
			return err
		}

		// $SYS account (no rotation on first boot)
		if _, _, _, err := controllers.EnsureSysAccount(ctx, client, ns, opKP, false); err != nil {
			return fmt.Errorf("bootstrap sys account: %w", err)
		}

		return nil
	})); err != nil {
		setupLog.Error(err, "add bootstrap runnable")
		os.Exit(1)
	}

	if err = (&controllers.NatsAccountReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "NatsAccount")
		return err
	}
	if err = (&controllers.NatsUserReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "NatsUser")
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

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		return err
	}

	return nil
}
