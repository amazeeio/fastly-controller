/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	"github.com/robfig/cron/v3"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	//+kubebuilder:scaffold:imports
	"github.com/amazeeio/fastly-controller/internal/controller"
	"github.com/amazeeio/fastly-controller/internal/handler"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	//+kubebuilder:scaffold:scheme
}

func main() {
	var fastlyAPIToken string
	var fastlyPlatformTLSConfiguration string
	var clusterName string
	var enablePausedStatusCron bool
	var pausedStatusCron string
	var maxRetryCount int
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&fastlyAPIToken, "api-token", "",
		"The default Fastly API Token to use if one is not supplied.")
	flag.StringVar(&fastlyPlatformTLSConfiguration, "platform-tls-id", "",
		"The default Fastly PlatformTLS ID to use.")
	flag.StringVar(&clusterName, "cluster-name", "",
		"The name of the cluster the controller is deployed in.")
	flag.BoolVar(&enablePausedStatusCron, "enable-paused-status-cron", false,
		"Enable the paused status cron check for ingresses.")
	flag.StringVar(&pausedStatusCron, "paused-status-cron", "*/5 * * * *",
		"The cron definition for checking paused ingresses.")
	flag.IntVar(&maxRetryCount, "max-retry-count", 5,
		"The number of times to retry checking paused ingresses.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// set a global API token for all requests, otherwise annotation will be used
	fastlyAPIToken = getEnv("FASTLY_API_TOKEN", fastlyAPIToken)
	fastlyPlatformTLSConfiguration = getEnv("FASTLY_PLATFORM_TLS_CONFIGURATION_ID", fastlyPlatformTLSConfiguration)
	clusterName = getEnv("CLUSTER_NAME", clusterName)
	enablePausedStatusCron = getEnvBool("ENABLE_PAUSED_STATUS_CRON", enablePausedStatusCron)
	pausedStatusCron = getEnv("PAUSED_STATUS_CRON", pausedStatusCron)

	if fastlyAPIToken == "" {
		setupLog.Error(fmt.Errorf("%s", "Environment variable FASTLY_API_TOKEN not set"), "unable to start manager")
		os.Exit(1)
	}
	if fastlyPlatformTLSConfiguration == "" {
		setupLog.Error(fmt.Errorf("%s", "Environment variable FASTLY_PLATFORM_TLS_CONFIGURATION_ID not set"), "unable to start manager")
		os.Exit(1)
	}
	if clusterName == "" {
		setupLog.Error(fmt.Errorf("%s", "Environment variable CLUSTER_NAME not set"), "unable to start manager")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "lahc7eig.amazee.io",
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
		os.Exit(1)
	}

	resourceCleanup := handler.NewCleanup(
		mgr.GetClient(),
		maxRetryCount,
		true,
	)
	c := cron.New()
	// this will check any `Ingress` resources for the paused status
	// and attempt to unpause them
	if enablePausedStatusCron {
		setupLog.Info("setting paused status check cron") // use cron to run a paused status check
		c.AddFunc(pausedStatusCron, func() {
			resourceCleanup.CheckPausedCertStatus()
		})
	}
	c.Start()

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// start the ingress monitor controller
	if err := (&controller.IngressReconciler{
		Token:                    fastlyAPIToken,
		PlatformTLSConfiguration: fastlyPlatformTLSConfiguration,
		ClusterName:              clusterName,
		Client:                   mgr.GetClient(),
		Log:                      ctrl.Log.WithName("controllers").WithName("Ingress"),
		Scheme:                   mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Ingress")
		os.Exit(1)
	}

	// start the secret monitor controller
	if err := (&controller.IngressSecretReconciler{
		Token:                    fastlyAPIToken,
		PlatformTLSConfiguration: fastlyPlatformTLSConfiguration,
		ClusterName:              clusterName,
		Client:                   mgr.GetClient(),
		Log:                      ctrl.Log.WithName("controllers").WithName("IngressSecret"),
		Scheme:                   mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "IngressSecret")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// accepts fallback values 1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False
// anything else is false.
func getEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		rVal, _ := strconv.ParseBool(value)
		return rVal
	}
	return fallback
}
