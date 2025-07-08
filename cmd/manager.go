//nolint:lll
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zerbytes/nats-k8s-based-resolver/internal/controllers"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

type ManagerCmd struct {
	WebhookCertPath string `name:"webhook-cert-path" default:"" help:"The directory that contains the webhook certificate."`
	WebhookCertName string `name:"webhook-cert-name" default:"tls.crt" help:"The name of the webhook certificate file."`
	WebhookCertKey  string `name:"webhook-cert-key" default:"tls.key" help:"The name of the webhook key file."`
}

func (c *ManagerCmd) Run(cli *MainCommand) error {
	setupLog, err := setupLogging()
	if err != nil {
		return err
	}

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

	if !cli.EnableHTTP2 {
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
		BindAddress:   cli.MetricsAddr,
		SecureServing: cli.SecureMetrics,
		TLSOpts:       tlsOpts,
	}

	if cli.SecureMetrics {
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
	if len(cli.MetricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", cli.MetricsCertPath, "metrics-cert-name", cli.MetricsCertName, "metrics-cert-key", cli.MetricsCertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(cli.MetricsCertPath, cli.MetricsCertName),
			filepath.Join(cli.MetricsCertPath, cli.MetricsCertKey),
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
		HealthProbeBindAddress: cli.ProbeAddr,
		LeaderElection:         cli.EnableLeaderElection,
		LeaderElectionID:       "nats-k8s-based-resolver-controller",
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

	// Use POD_NAMESPACE (set by the Helm chart) or fallback "default"
	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		ns = "default"
	}

	// Bootstrap: Operator key & $SYS account Secret
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		// 1. Wait for informer cache
		if ok := mgr.GetCache().WaitForCacheSync(ctx); !ok {
			return fmt.Errorf("cache never syncs")
		}

		client := mgr.GetClient()

		// Operator key
		opKP, _, err := controllers.GetOrCreateOperatorKP(ctx, client, ns)
		if err != nil {
			return err
		}

		controllers.SetNatsURL(cli.NatsURL)
		controllers.SetNatsCreds(cli.NatsCreds)

		// $SYS account (no rotation on first boot)
		if _, _, _, _, err := controllers.EnsureSysAccount(ctx, cli.NatsURL, client, ns, opKP, false); err != nil {
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
		NS:     ns,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "NatsAccount")
		return err
	}
	if err = (&controllers.NatsUserReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		NS:     ns,
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
