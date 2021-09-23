/*

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

	"github.com/amazeeio/fastly-controller/controllers"
	"github.com/amazeeio/fastly-controller/handlers"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"gopkg.in/robfig/cron.v2"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var fastlyAPIToken string
	var fastlyPlatformTLSConfiguration string
	var clusterName string
	var pausedStatusCron string

	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&fastlyAPIToken, "api-token", "",
		"The default Fastly API Token to use if one is not supplied.")
	flag.StringVar(&fastlyPlatformTLSConfiguration, "platform-tls-id", "",
		"The default Fastly PlatformTLS ID to use.")
	flag.StringVar(&clusterName, "cluster-name", "",
		"The name of the cluster the controller is deployed in.")
	flag.StringVar(&pausedStatusCron, "paused-status-cron", "*/5 * * * *",
		"The cron definition for checking paused ingresses.")
	flag.Parse()

	// set a global API token for all requests, otherwise annotation will be used
	fastlyAPIToken = getEnv("FASTLY_API_TOKEN", fastlyAPIToken)
	fastlyPlatformTLSConfiguration = getEnv("FASTLY_PLATFORM_TLS_CONFIGURATION_ID", fastlyPlatformTLSConfiguration)
	clusterName = getEnv("CLUSTER_NAME", clusterName)
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

	ctrl.SetLogger(zap.New(func(o *zap.Options) {
		o.Development = true
	}))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		LeaderElection:     enableLeaderElection,
		Port:               9443,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	resourceCleanup := handlers.NewCleanup(
		mgr.GetClient(),
		true,
	)
	c := cron.New()
	setupLog.Info("setting paused status check cron") // use cron to run a paused status check
	// this will check any `Ingress` resources for the paused status
	// and attempt to unpause them
	c.AddFunc(pausedStatusCron, func() {
		resourceCleanup.CheckPausedCertStatus()
	})

	// +kubebuilder:scaffold:builder

	// start the ingress monitor controller
	if err = (&controllers.IngressReconciler{
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
	if err = (&controllers.IngressSecretReconciler{
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
