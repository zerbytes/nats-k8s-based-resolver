package main

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/go-logr/zapr"
	natsv1alpha1 "github.com/zerbytes/nats-k8s-based-resolver/api/v1alpha1"
	"github.com/zerbytes/nats-k8s-based-resolver/pkg/version"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
)

var scheme = runtime.NewScheme()

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

	Version kong.VersionFlag `name:"version" short:"v" help:"Print the version of the NATS-based resolver."`

	NatsURL   string `required:"" env:"NATS_URL" help:"NATS server URL, e.g. nats://localhost:4222"`
	NatsCreds string `env:"NATS_CREDS" help:"Path to NATS $SYS user credentials file (e.g., secret named \"nats-sys-resolver-creds\"), will fallback to loading the secret from Kubernetes directly and storing in temporary file."`

	MetricsAddr          string `name:"metrics-bind-address" default:"0" help:"The address the metrics endpoint binds to. Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service."`
	ProbeAddr            string `name:"health-probe-bind-address" default:":8081" help:"The address the probe endpoint binds to."`
	EnableLeaderElection bool   `name:"leader-elect" default:"false" help:"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager."`
	SecureMetrics        bool   `name:"metrics-secure" default:"true" help:"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead."`
	MetricsCertPath      string `name:"metrics-cert-path" default:"" help:"The directory that contains the metrics server certificate."`
	MetricsCertName      string `name:"metrics-cert-name" default:"tls.crt" help:"The name of the metrics server certificate file."`
	MetricsCertKey       string `name:"metrics-cert-key" default:"tls.key" help:"The name of the metrics server key file."`
	EnableHTTP2          bool   `name:"enable-http2" default:"false" help:"If set, HTTP/2 will be enabled for the metrics and webhook servers"`
}

var cli MainCommand

func main() {
	ctx := kong.Parse(&cli,
		kong.Vars{
			"version": version.Version,
		},
	)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run(cli)
	ctx.FatalIfErrorf(err)
}

// setupLogging initializes logging
func setupLogging() (*zap.SugaredLogger, error) {
	zapLog, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("who watches the watchmen (%v)?", err)
	}
	ctrl.SetLogger(zapr.NewLogger(zapLog))
	return zapLog.Sugar(), nil
}
