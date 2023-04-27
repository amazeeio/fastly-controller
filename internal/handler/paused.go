package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Cleanup is used for cleaning up old pods or resources.
type Cleanup struct {
	Client      client.Client
	MaxRetries  int
	EnableDebug bool
}

// NewCleanup returns a cleanup with controller-runtime client.
func NewCleanup(client client.Client, maxRetries int, enableDebug bool) *Cleanup {
	return &Cleanup{
		Client:      client,
		MaxRetries:  maxRetries,
		EnableDebug: enableDebug,
	}
}

// CheckPausedCertStatus is a cronjob that will periodically check for paused status on ingresses that have failed to
// upload their certificate to fastly and will unpause them to allow them to retry
// after 5 attempts it will give up
func (h *Cleanup) CheckPausedCertStatus() {
	opLog := ctrl.Log.WithName("handlers").WithName("PausedCertStatusCheck")
	opLog.Info("Running paused status check job")
	namespaces := &corev1.NamespaceList{}
	if err := h.Client.List(context.Background(), namespaces); err != nil {
		opLog.Error(err, "Unable to list namespaces, there may be none or something went wrong")
		return
	}
	for _, ns := range namespaces.Items {
		ingresses := &networkv1.IngressList{}
		listOption := (&client.ListOptions{}).ApplyOptions([]client.ListOption{
			client.InNamespace(ns.ObjectMeta.Name),
			client.MatchingLabels(map[string]string{
				"fastly.amazee.io/paused": "true",
			}),
		})
		if err := h.Client.List(context.Background(), ingresses, listOption); err != nil {
			opLog.Error(err, "Unable to list Ingress resource in namespace, there may be none or something went wrong")
			return
		}
		if len(ingresses.Items) > 0 {
			// if there are any ingresses in the selector response, then print a debug message
			opLog.Info(fmt.Sprintf("Checking ingresses in namespace %s", ns.ObjectMeta.Name))
		}
		for _, ingress := range ingresses.Items {
			// check if a reason exists
			if reason, ok := ingress.ObjectMeta.Annotations["fastly.amazee.io/paused-reason"]; ok {
				// always set retryCount to 0
				retryCount := 0
				// then read the value in from the annotation if it is present and set the value to it
				if retryValue, ok := ingress.ObjectMeta.Annotations["fastly.amazee.io/paused-retry-count"]; ok {
					if i, err := strconv.Atoi(retryValue); err == nil {
						retryCount = i
					}
				}
				// and if the reason is unable to find a secret
				if strings.Contains(reason, "Unable to find secret of") {
					// then attempt the process to fix it, but give up after `h.MaxRetries` attempts
					if retryCount <= h.MaxRetries {
						//increment the retry count by 1
						retryCount = retryCount + 1

						// set the paused status to false, and upsert the retry-count into the annotations
						mergePatch, err := json.Marshal(map[string]interface{}{
							"metadata": map[string]interface{}{
								"annotations": map[string]interface{}{
									"fastly.amazee.io/paused":             nil,
									"fastly.amazee.io/paused-retry-count": fmt.Sprintf("%d", retryCount),
								},
								"labels": map[string]interface{}{
									"fastly.amazee.io/paused": "false",
								},
							},
						})
						if err != nil {
							opLog.Info(fmt.Sprintf("Unable to create mergepatch for %s, error was: %v", ingress.ObjectMeta.Name, err))
							continue
						}
						// patch the ingress so that the controller will attemp to run through its process
						if err := h.Client.Patch(context.Background(), &ingress, client.RawPatch(types.MergePatchType, mergePatch)); err != nil {
							opLog.Info(fmt.Sprintf("Unable to patch ingress %s, error was: %v", ingress.ObjectMeta.Name, err))
							continue
						}
						opLog.Info(fmt.Sprintf("Patched ingress %s", ingress.ObjectMeta.Name))
					}
				}
			}
		}
	}
}
