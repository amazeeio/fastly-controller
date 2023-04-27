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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/fastly/go-fastly/fastly"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IngressReconciler reconciles a Ingress object
type IngressReconciler struct {
	client.Client
	Log                      logr.Logger
	Scheme                   *runtime.Scheme
	Labels                   map[string]string
	FastlyClient             *fastly.Client
	ClusterName              string
	Token                    string
	PlatformTLSConfiguration string
}

// +kubebuilder:rbac:groups=*,resources=ingresses,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=*,resources=ingress/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=*,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=namespaces,verbs=get;list;watch

// Reconcile .
func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	opLog := r.Log.WithValues("ingress", req.NamespacedName)

	finalizerName := "finalizer.fastly.amazee.io/v1"

	// load the resource
	var ingress networkv1.Ingress
	if err := r.Get(ctx, req.NamespacedName, &ingress); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// labels := map[string]string{
	// 	LabelAppManaged: "fastly-controller",
	// }
	serviceID := ingress.ObjectMeta.Annotations["fastly.amazee.io/service-id"]
	paused := false
	if pausedVal, ok := ingress.ObjectMeta.Labels["fastly.amazee.io/paused"]; ok {
		result, _ := strconv.ParseBool(pausedVal)
		paused = result
	}
	// deleteexternal prevents the controller from deleting anything in fastly or in cluster
	deleteExternal := true
	if deleteExternalVal, ok := ingress.ObjectMeta.Annotations["fastly.amazee.io/delete-external-resources"]; ok {
		result, _ := strconv.ParseBool(deleteExternalVal)
		deleteExternal = result
	}
	// check if `tls-acme` is configured on the ingress, this is then passed through to the ingress secret
	// and is used by the secret to determine if it is to be uploaded into fastly or not
	// ingress domains will still be added to the fastly service, tls-acme is just used for the certificates only
	tlsAcme := false
	if tlsAcmeVal, ok := ingress.ObjectMeta.Annotations["kubernetes.io/tls-acme"]; ok {
		result, _ := strconv.ParseBool(tlsAcmeVal)
		tlsAcme = result
	}

	// setup the fastly client
	var err error
	// start with the global configuration
	fastlyConfig := fastlyAPI{
		Token:                    r.Token,
		PlatformTLSConfiguration: r.PlatformTLSConfiguration,
		ServiceID:                serviceID,
	}
	// check for `fastly.amazee.io/api-secret-name` and load the variables from it into the fastlyConfig
	// if the ingress has a `fastly.amazee.io/api-secret-name` annotation, then we also want to inject that
	// into the tls-secrets for the ingress, so that they know which secret to use too
	if apiSecretName, ok := ingress.ObjectMeta.Annotations["fastly.amazee.io/api-secret-name"]; ok {
		fastlyAPISecret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      apiSecretName,
			Namespace: req.Namespace,
		}, fastlyAPISecret); err != nil {
			opLog.Info(fmt.Sprintf("Unable to find secret %s, pausing ingress, error was: %v", apiSecretName, err))
			patchErr := r.patchPausedStatus(ctx,
				ingress,
				fastlyConfig.ServiceID,
				fmt.Sprintf("%v", err),
				true,
				tlsAcme,
			)
			if patchErr != nil {
				// if we can't patch the resource, just log it and return
				// next time it tries to reconcile, it will just exit here without doing anything else
				opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
			}
			return ctrl.Result{}, nil
		}
		if _, ok := fastlyAPISecret.StringData["api-token"]; ok {
			fastlyConfig.Token = fastlyAPISecret.StringData["api-token"]
			opLog.Info(fmt.Sprintf("Unable to find secret data for API_TOKEN, pausing ingress, error was: %v", err))
			patchErr := r.patchPausedStatus(ctx,
				ingress,
				fastlyConfig.ServiceID,
				fmt.Sprintf("%v", err),
				true,
				tlsAcme,
			)
			if patchErr != nil {
				// if we can't patch the resource, just log it and return
				// next time it tries to reconcile, it will just exit here without doing anything else
				opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
			}
			return ctrl.Result{}, nil
		}
		if _, ok := fastlyAPISecret.StringData["platform-tls-configuration"]; ok {
			fastlyConfig.PlatformTLSConfiguration = fastlyAPISecret.StringData["platform-tls-configuration"]
			opLog.Info(fmt.Sprintf("Unable to find secret data for platform-tls-configuration, pausing ingress, error was: %v", err))
			patchErr := r.patchPausedStatus(ctx,
				ingress,
				fastlyConfig.ServiceID,
				fmt.Sprintf("%v", err),
				true,
				tlsAcme,
			)
			if patchErr != nil {
				// if we can't patch the resource, just log it and return
				// next time it tries to reconcile, it will just exit here without doing anything else
				opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
			}
			return ctrl.Result{}, nil
		}
		fastlyConfig.SecretName = apiSecretName
	}
	// setup the fastly client
	r.FastlyClient, err = fastly.NewClient(fastlyConfig.Token)
	if err != nil {
		return ctrl.Result{}, err
	}

	// examine DeletionTimestamp to determine if object is under deletion
	if ingress.ObjectMeta.DeletionTimestamp.IsZero() && ingress.ObjectMeta.Name != "" {
		// check if the ingress is not paused
		if !paused {
			// check fastly for the list of domains currently in the service
			opLog.Info(fmt.Sprintf("Checking fastly service %s for current domains", fastlyConfig.ServiceID))
			latest, domains, err := r.getLatestServiceDomains(fastlyConfig)
			if err != nil {
				return ctrl.Result{}, err
			}
			var domainsToAdd []string
			for _, tls := range ingress.Spec.TLS {
				for _, host := range tls.Hosts {
					if !containsDomain(domains, host) {
						opLog.Info(fmt.Sprintf("Found domain %s to add to service %v", host, fastlyConfig.ServiceID))
						domainsToAdd = append(domainsToAdd, host)
					}
				}
			}
			// if we have any domains to add to the service, we do that here
			if len(domainsToAdd) > 0 {
				// if the latest version is active, then we should clone it
				clonedVersion, err := r.FastlyClient.CloneVersion(
					&fastly.CloneVersionInput{
						Service: fastlyConfig.ServiceID,
						Version: latest.Number,
					})
				if err != nil {
					// @TODO: log the error and drop out, maybe do something else to help prevent cloning it again and again?
					// check for existing non-activated versions?
					opLog.Info(fmt.Sprintf("Unable to clone service version in fastly, pausing ingress, error was: %v", err))
					patchErr := r.patchPausedStatus(ctx,
						ingress,
						fastlyConfig.ServiceID,
						fmt.Sprintf("%v", err),
						true,
						tlsAcme,
					)
					if patchErr != nil {
						// if we can't patch the resource, just log it and return
						// next time it tries to reconcile, it will just exit here without doing anything else
						opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, giving up, error was: %v", patchErr))
					}
					return ctrl.Result{}, nil
				}
				opLog.Info(fmt.Sprintf(
					"Cloned version %d of service %s",
					clonedVersion.Number,
					fastlyConfig.ServiceID,
				))
				// once we have the latest version, then we can update it
				comment := fmt.Sprintf(
					"Domains in ingress %s added by fastly-controller: cluster:%s:namespace:%s",
					ingress.ObjectMeta.Name,
					r.ClusterName,
					ingress.ObjectMeta.Namespace,
				)
				// update the version in fastly
				version, err := r.FastlyClient.UpdateVersion(
					&fastly.UpdateVersionInput{
						Service: fastlyConfig.ServiceID,
						Version: clonedVersion.Number,
						Comment: truncateString(comment, 512), // truncate the comment to 512 to not exceed comment limit
					})
				if err != nil {
					opLog.Info(fmt.Sprintf("Unable to update service version in fastly, pausing ingress, error was: %v", err))
					// unable to update the version in fastly, so we should just stop trying to do stuff with this ingress
					// add the paused annotations
					patchErr := r.patchPausedStatus(ctx,
						ingress,
						fastlyConfig.ServiceID,
						fmt.Sprintf("%v", err),
						true,
						tlsAcme,
					)
					if patchErr != nil {
						// if we can't patch the resource, just log it and return
						// next time it tries to reconcile, it will just exit here without doing anything else
						opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
					}
					return ctrl.Result{}, nil
				}
				for _, rule := range ingress.Spec.Rules {
					// check if the domain exists first
					// TODO(marco): check why the value of domain is never used... :)
					domain, err := r.FastlyClient.GetDomain(
						&fastly.GetDomainInput{
							Service: fastlyConfig.ServiceID,
							Version: version.Number,
							Name:    rule.Host,
						})
					if err != nil {
						// if the domain doesn't exist, then create it.
						domain, err = r.FastlyClient.CreateDomain(
							&fastly.CreateDomainInput{
								Service: fastlyConfig.ServiceID,
								Version: version.Number,
								Name:    rule.Host,
								Comment: fmt.Sprintf(
									"Domain added by fastly-controller - cluster:%s:namespace:%s",
									r.ClusterName,
									req.Namespace,
								),
							})
						if err != nil {
							// @TODO: could not create domain, should we care?
							opLog.Info(fmt.Sprintf("Unable to create domain in fastly, pausing ingress, error was: %v", err))
							// unable to update the version in fastly, so we should just stop trying to do stuff with this ingress
							// add the paused annotations
							patchErr := r.patchPausedStatus(ctx,
								ingress,
								fastlyConfig.ServiceID,
								fmt.Sprintf("%v", err),
								true,
								tlsAcme,
							)
							if patchErr != nil {
								// if we can't patch the resource, just log it and return
								// next time it tries to reconcile, it will just exit here without doing anything else
								opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
							}
							return ctrl.Result{}, nil
						}
						opLog.Info(fmt.Sprintf(
							"Added domain %s to service %s",
							domain.Name,
							fastlyConfig.ServiceID,
						))
					}
				}
				// Finally, activate this new version.
				activeVersion, err := r.validateActivateService(ingress, fastlyConfig, version.Number)
				if err != nil {
					// there was an error activating this service
					opLog.Info(fmt.Sprintf("Unable to validate or activate service version in fastly, pausing ingress, error was: %v", err))
					// unable to update the version in fastly, so we should just stop trying to do stuff with this ingress
					// add the paused annotations
					patchErr := r.patchPausedStatus(ctx,
						ingress,
						fastlyConfig.ServiceID,
						fmt.Sprintf("%v", err),
						true,
						tlsAcme,
					)
					if patchErr != nil {
						// if we can't patch the resource, just log it and return
						// next time it tries to reconcile, it will just exit here without doing anything else
						opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
					}
					return ctrl.Result{}, nil
				}
				opLog.Info(fmt.Sprintf(
					"Active version for service %s is now %v",
					fastlyConfig.ServiceID,
					activeVersion.Number,
				))
			} else {
				opLog.Info(fmt.Sprintf("No domains found to add to service %s", fastlyConfig.ServiceID))
			}
			// patch the ingress secrets after adding the domains
			// this also gives a bit of time for the ingress tls secrets to be created
			if tlsAcme {
				for _, tls := range ingress.Spec.TLS {
					opLog.Info(fmt.Sprintf("Patching secret %s with service ID and watch status", tls.SecretName))
					err := r.patchSecret(ctx,
						ingress,
						fastlyConfig,
						tls.SecretName,
						false,
						tlsAcme,
					)
					if err != nil {
						opLog.Info(fmt.Sprintf("Unable to patch secret, pausing ingress, error was: %v", err))
						patchErr := r.patchPausedStatus(ctx, ingress, fastlyConfig.ServiceID, fmt.Sprintf("%v", err), true, tlsAcme)
						if patchErr != nil {
							// if we can't patch the resource, just log it and return
							// next time it tries to reconcile, it will just exit here without doing anything else
							opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, giving up, error was: %v", patchErr))
						}
						return ctrl.Result{}, nil
					}
				}
			}
			opLog.Info(fmt.Sprintf("Finished checking fastly service %s", fastlyConfig.ServiceID))
		} else {
			// if the ingress has the paused status, then patch any secret with paused too so that we
			// dont continue to act on any changes to it
			if tlsAcme {
				for _, tls := range ingress.Spec.TLS {
					opLog.Info(fmt.Sprintf("Patching secret %s with service ID and paused status %v", tls.SecretName, true))
					err := r.patchSecret(ctx,
						ingress,
						fastlyConfig,
						tls.SecretName,
						true,
						tlsAcme,
					)
					if err != nil {
						opLog.Info(fmt.Sprintf("Unable to patch secret, giving up, error was: %v", err))
						return ctrl.Result{}, nil
					}
				}
			}
		}
	} else {
		// The object is being deleted
		if err := r.deleteExternalResources(ctx,
			ingress,
			fastlyConfig,
			opLog,
			deleteExternal,
			paused,
		); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to delete external resources, error was: %v", err)
		}
		// remove finalizer if one exists
		if containsString(ingress.ObjectMeta.Finalizers, finalizerName) {
			ingress.ObjectMeta.Finalizers = removeString(ingress.ObjectMeta.Finalizers, finalizerName)
			if err := r.Update(ctx, &ingress); err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the given manager and watch filters.
func (r *IngressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkv1.Ingress{}).
		WithEventFilter(IngressPredicates{}).
		Complete(r)
}

// delete any external resources
func (r *IngressReconciler) deleteExternalResources(ctx context.Context,
	ingress networkv1.Ingress,
	fastlyConfig fastlyAPI,
	opLog logr.Logger,
	deleteExternal,
	paused bool,
) error {
	// if we have the external flag, then we should remove from fastly
	if deleteExternal || !paused {
		// Get the latest active version
		latest, domains, err := r.getLatestServiceDomains(fastlyConfig)
		if err != nil {
			return err
		}
		// get the list of ingress rules/hosts and put them into a sliced
		opLog.Info(fmt.Sprintf(
			"There are %d domains in service %s",
			len(domains),
			fastlyConfig.ServiceID,
		))
		var delDomains []string
		for _, tls := range ingress.Spec.TLS {
			for _, host := range tls.Hosts {
				if containsDomain(domains, host) {
					opLog.Info(fmt.Sprintf(
						"Will delete domain %s from service %s",
						host,
						fastlyConfig.ServiceID,
					))
					delDomains = append(delDomains, host)
				}
			}
		}
		opLog.Info(fmt.Sprintf(
			"There are %d domains to remove from service %s",
			len(delDomains),
			fastlyConfig.ServiceID,
		))
		// if there are any domains in the slice, then we need to clone the service and remove the domains from it
		if len(delDomains) > 0 {
			// if the latest version is active, then we should clone it
			clonedVersion, err := r.FastlyClient.CloneVersion(
				&fastly.CloneVersionInput{
					Service: fastlyConfig.ServiceID,
					Version: latest.Number,
				})
			if err != nil {
				// @TODO: log the error and drop out, maybe do something else to help prevent cloning it again and again?
				// check for existing non-activated versions?
				opLog.Info(fmt.Sprintf("Unable to clone service version in fastly, error was: %v", err))
				return nil
			}
			opLog.Info(fmt.Sprintf(
				"Cloned version %d of service %s",
				clonedVersion.Number,
				fastlyConfig.ServiceID,
			))
			comment := fmt.Sprintf(
				"Domains in ingress %s removed by fastly-controller: cluster:%s:namespace:%s",
				ingress.ObjectMeta.Name,
				r.ClusterName,
				ingress.ObjectMeta.Namespace,
			)
			if clonedVersion.Comment != "" && !latest.Active {
				// if there is already a comment on the cloned version, then add our comment to the end
				comment = fmt.Sprintf(
					"%s\nDomains in ingress %s removed by fastly-controller: cluster:%s:namespace:%s",
					clonedVersion.Comment,
					ingress.ObjectMeta.Name,
					r.ClusterName,
					ingress.ObjectMeta.Namespace,
				)
			}
			// TODO(marco): check why the value of version is never used...
			version, err := r.FastlyClient.UpdateVersion(
				&fastly.UpdateVersionInput{
					Service: fastlyConfig.ServiceID,
					Version: clonedVersion.Number,
					Comment: comment,
				})
			// delete the domains from the service
			for _, host := range delDomains {
				err = r.FastlyClient.DeleteDomain(
					&fastly.DeleteDomainInput{
						Service: fastlyConfig.ServiceID,
						Version: version.Number,
						Name:    host,
					})
				if err != nil {
					// couldnt delete the domain @TODO maybe do something different here
					return err
				}
				opLog.Info(fmt.Sprintf(
					"Deleted domain %s from service %s",
					host,
					fastlyConfig.ServiceID,
				))
			}
			// Finally, activate this new version.
			activeVersion, err := r.validateActivateService(ingress,
				fastlyConfig,
				version.Number,
			)
			if err != nil {
				return err
			}
			opLog.Info(fmt.Sprintf(
				"Active version for service %s is now %v",
				fastlyConfig.ServiceID,
				activeVersion.Number,
			))
		}
	}
	// @TODO: this doesn't clean anything out of platform-tls, do we need to do this?
	// clean up any tls secrets this ingress has
	for _, tlsSecret := range ingress.Spec.TLS {
		opLog.Info(fmt.Sprintf("Attemping to delete tls secret %s", tlsSecret.SecretName))
		var ingressSecret corev1.Secret
		if err := r.Get(ctx,
			types.NamespacedName{
				Name:      tlsSecret.SecretName,
				Namespace: ingress.ObjectMeta.Namespace,
			}, &ingressSecret); err != nil {
			return fmt.Errorf("unable to get secret %s, error was: %v", tlsSecret.SecretName, err)
		}
		if err := r.Delete(ctx, &ingressSecret); err != nil {
			return fmt.Errorf("unable to delete secret %s, error was: %v", tlsSecret.SecretName, err)
		}
		opLog.Info(fmt.Sprintf("Deleted tls secret %s", tlsSecret.SecretName))
	}
	return nil
}

func (r *IngressReconciler) getLatestServiceDomains(fastlyConfig fastlyAPI) (*fastly.Version, []*fastly.Domain, error) {
	// get service information from fastly
	service, err := r.FastlyClient.GetService(&fastly.GetServiceInput{
		ID: fastlyConfig.ServiceID,
	})
	if err != nil {
		return nil, nil, err
	}

	// iterate over the services to get the latest active version
	latest := service.Versions[len(service.Versions)-1]
	for _, version := range service.Versions {
		if version.Active {
			latest = version
			break
		}
	}

	// get all the domains from the active service
	domains, err := r.FastlyClient.ListDomains(
		&fastly.ListDomainsInput{
			Service: fastlyConfig.ServiceID,
			Version: latest.Number,
		})
	if err != nil {
		return nil, nil, err
	}

	// return these
	return latest, domains, nil
}

func (r *IngressReconciler) validateActivateService(
	ingress networkv1.Ingress,
	fastlyConfig fastlyAPI,
	version int,
) (*fastly.Version, error) {
	valid, _, err := r.FastlyClient.ValidateVersion(
		&fastly.ValidateVersionInput{
			Service: fastlyConfig.ServiceID,
			Version: version,
		})
	if err != nil {
		return nil, err
	}
	// if a configuration is invalid we should check if it is because there are no more domains left
	if !valid {
		domains, err := r.FastlyClient.ListDomains(
			&fastly.ListDomainsInput{
				Service: fastlyConfig.ServiceID,
				Version: version,
			})
		if err != nil {
			return nil, err
		}
		// if we have domains, then the service is invalid for some other reason
		if len(domains) > 0 {
			return nil, fmt.Errorf("not valid version %d for service %s", version, fastlyConfig.ServiceID)
		}
		// it could still be invalid, but no domains left do we care? send back the current active version number
		r.Log.WithValues("ingress",
			types.NamespacedName{
				Name:      ingress.ObjectMeta.Name,
				Namespace: ingress.ObjectMeta.Namespace,
			},
		).Info(fmt.Sprintf("No domains left in version %d for service %s, skipping activation", version, fastlyConfig.ServiceID))
		return &fastly.Version{
			ServiceID: fastlyConfig.ServiceID,
			Number:    version,
		}, nil
	}
	// Finally, activate this new version.
	return r.FastlyClient.ActivateVersion(
		&fastly.ActivateVersionInput{
			Service: fastlyConfig.ServiceID,
			Version: version,
		})
}

// patch any tls secrets attached to this ingress with our fastly annotations
// this is so that the ingressecret_controller can watch for new certificates being added or updated by lets encrypt/other
func (r *IngressReconciler) patchSecret(
	ctx context.Context,
	ingress networkv1.Ingress,
	fastlyConfig fastlyAPI,
	secret string,
	paused, tlsAcme bool,
) error {
	var ingressSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Name:      secret,
		Namespace: ingress.ObjectMeta.Namespace,
	}, &ingressSecret); err != nil {
		return fmt.Errorf("unable to find secret of %s to add to service %s", secret, fastlyConfig.ServiceID)
	}
	// check for the service-id
	// if we dont have it, add it.
	// if its different, change it to match the new one
	// set the watch status to true so we can monitor for certificate changes in the ingresssecret_controller
	annotations := map[string]interface{}{
		"fastly.amazee.io/service-id":   fastlyConfig.ServiceID,
		"fastly.amazee.io/watch":        "true",
		"fastly.amazee.io/paused":       nil,
		"fastly.amazee.io/ingress-name": ingress.ObjectMeta.Name,
	}
	labels := map[string]interface{}{
		"fastly.amazee.io/paused":   fmt.Sprintf("%v", paused),
		"fastly.amazee.io/tls-acme": fmt.Sprintf("%v", tlsAcme),
	}
	// add the custom api secret to this ingress secret if one is provided by the ingress
	// this is so that actions on the ingress secret can be taken against the fastly api if not using the default
	// controller credentials
	if apiSecretName, ok := ingress.ObjectMeta.Annotations["fastly.amazee.io/api-secret-name"]; ok {
		annotations["fastly.amazee.io/api-secret-name"] = apiSecretName
	}
	mergePatch, err := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": annotations,
			"labels":      labels,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to create mergepatch for %s, error was: %v", ingress.ObjectMeta.Name, err)
	}
	if err := r.Patch(ctx, &ingressSecret, client.RawPatch(types.MergePatchType, mergePatch)); err != nil {
		return fmt.Errorf("unable to patch secret %s, error was: %v", ingressSecret.ObjectMeta.Name, err)
	}
	r.Log.WithValues("ingress", types.NamespacedName{
		Name:      ingressSecret.ObjectMeta.Name,
		Namespace: ingressSecret.ObjectMeta.Namespace,
	}).Info(fmt.Sprintf("Patched secret %s", secret))
	return nil
}

// patch any ingress (or secrets if possible) with the pause status to prevent anything from being done
// add the paused-reason to the annotations so user can see why it was paused and try to fix any issues it before unpausing
func (r *IngressReconciler) patchPausedStatus(
	ctx context.Context,
	ingress networkv1.Ingress,
	serviceID string,
	reason string,
	paused, tlsAcme bool,
) error {
	// set the paused annotations to nil if this is unpaused
	annotations := map[string]interface{}{
		"fastly.amazee.io/paused":             nil,
		"fastly.amazee.io/paused-reason":      nil,
		"fastly.amazee.io/paused-at":          nil,
		"fastly.amazee.io/paused-retry-count": nil,
		"fastly.amazee.io/tls-acme":           nil,
	}
	if paused {
		// if paused, set the annotations
		annotations = map[string]interface{}{
			"fastly.amazee.io/paused":        nil,
			"fastly.amazee.io/paused-reason": reason,
			"fastly.amazee.io/paused-at":     time.Now().UTC().Format("2006-01-02 15:04:05"),
			"fastly.amazee.io/tls-acme":      fmt.Sprintf("%v", tlsAcme),
		}
	}
	labels := map[string]interface{}{
		"fastly.amazee.io/paused": fmt.Sprintf("%v", paused),
	}
	mergePatch, err := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": annotations,
			"labels":      labels,
		},
	})
	if err != nil {
		r.Log.WithValues("ingress", types.NamespacedName{
			Name:      ingress.ObjectMeta.Name,
			Namespace: ingress.ObjectMeta.Namespace,
		}).Info(fmt.Sprintf("Unable to create mergepatch for %s, error was: %v", ingress.ObjectMeta.Name, err))
		return nil
	}
	if err := r.Patch(ctx, &ingress, client.RawPatch(types.MergePatchType, mergePatch)); err != nil {
		r.Log.WithValues("ingress", types.NamespacedName{
			Name:      ingress.ObjectMeta.Name,
			Namespace: ingress.ObjectMeta.Namespace,
		}).Info(fmt.Sprintf("Unable to patch ingress %s, error was: %v", ingress.ObjectMeta.Name, err))
		return nil
	}
	r.Log.WithValues("ingress", types.NamespacedName{
		Name:      ingress.ObjectMeta.Name,
		Namespace: ingress.ObjectMeta.Namespace,
	}).Info(fmt.Sprintf("Patched ingress %s", ingress.ObjectMeta.Name))

	// check any tls secrets attached to the ingress
	// and try to patch them as paused if possible
	for _, tlsSecret := range ingress.Spec.TLS {
		var ingressSecret corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{
			Name:      tlsSecret.SecretName,
			Namespace: ingress.ObjectMeta.Namespace,
		}, &ingressSecret); err != nil {
			// if the secret doesn't exist, then just log it and return
			r.Log.WithValues("ingress", types.NamespacedName{
				Name:      ingress.ObjectMeta.Name,
				Namespace: ingress.ObjectMeta.Namespace,
			}).Info(fmt.Sprintf("Unable to find secret of %s to add to service %s", tlsSecret.SecretName, serviceID))
			return nil
		}
		if err := r.Patch(ctx, &ingressSecret, client.RawPatch(types.MergePatchType, mergePatch)); err != nil {
			// if we can't patch the secret, then, then just log it and return
			// no point trying to keep patching it if we can't do it the first time
			r.Log.WithValues("ingress", types.NamespacedName{
				Name:      ingress.ObjectMeta.Name,
				Namespace: ingress.ObjectMeta.Namespace,
			}).Info(fmt.Sprintf("Unable to patch secret %s, error was: %v", ingressSecret.ObjectMeta.Name, err))
			return nil
		}
		// if we can patch it, log it
		r.Log.WithValues("ingress", types.NamespacedName{
			Name:      ingressSecret.ObjectMeta.Name,
			Namespace: ingressSecret.ObjectMeta.Namespace,
		}).Info(fmt.Sprintf("Patched secret %s", tlsSecret.SecretName))
	}
	return nil
}
