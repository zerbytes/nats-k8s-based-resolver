package main

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/go-logr/zapr"
	natsv1alpha1 "github.com/zerbytes/nats-k8s-based-resolver/api/v1alpha1"
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

var cli MainCommand

func main() {
	ctx := kong.Parse(&cli)
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
