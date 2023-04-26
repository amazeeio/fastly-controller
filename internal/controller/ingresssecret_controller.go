package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
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

// IngressSecretReconciler reconciles a FastlyService object
type IngressSecretReconciler struct {
	client.Client
	Log                      logr.Logger
	Scheme                   *runtime.Scheme
	Labels                   map[string]string
	FastlyClient             *fastly.Client
	ClusterName              string
	Token                    string
	PlatformTLSConfiguration string
}

// +kubebuilder:rbac:groups=*,resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile .
func (r *IngressSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	opLog := r.Log.WithValues("ingress-secret", req.NamespacedName)
	// load the resource
	var ingressSecret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &ingressSecret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// get the serviceid and secret name from annotations
	// these should be added by the ingress controller side of the fastly-operator
	serviceID := ingressSecret.ObjectMeta.Annotations["fastly.amazee.io/service-id"]

	// pausing prevents the controller from acting on this object
	// it prevents anything happening in fastly
	paused := false
	if pausedVal, ok := ingressSecret.ObjectMeta.Labels["fastly.amazee.io/paused"]; ok {
		result, _ := strconv.ParseBool(pausedVal)
		paused = result
	}
	// deleteexternal prevents the controller from deleting anything in fastly or in cluster
	deleteExternal := true
	if deleteExternalVal, ok := ingressSecret.ObjectMeta.Annotations["fastly.amazee.io/delete-external-resources"]; ok {
		result, _ := strconv.ParseBool(deleteExternalVal)
		deleteExternal = result
	}
	// check if `tls-acme` is passed in from the ingress
	tlsAcme := true
	if tlsAcmeVal, ok := ingressSecret.ObjectMeta.Annotations["fastly.amazee.io/tls-acme"]; ok {
		result, _ := strconv.ParseBool(tlsAcmeVal)
		tlsAcme = result
	}

	// check if `ingress-acme` is configured on the ingress, this is then passed through to the ingress secret
	// and is used by the secret to determine if it is to be uploaded into fastly or not
	// ingress domains will still be added to the fastly service, tls-acme is just used for the certificates only
	ingressName := ""
	if ingressNameVal, ok := ingressSecret.ObjectMeta.Annotations["fastly.amazee.io/ingress-name"]; ok {
		ingressName = ingressNameVal
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
	if apiSecretName, ok := ingressSecret.ObjectMeta.Annotations["fastly.amazee.io/api-secret-name"]; ok {
		fastlyAPISecret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      apiSecretName,
			Namespace: req.Namespace,
		}, fastlyAPISecret); err != nil {
			opLog.Info(fmt.Sprintf("Unable to find secret %s, pausing ingress, error was: %v", apiSecretName, err))
			patchErr := r.patchPausedStatus(ctx, ingressSecret, nil, fastlyConfig.ServiceID, fmt.Sprintf("%v", err), true)
			if patchErr != nil {
				// if we can't patch the resource, just log it and return
				// next time it tries to reconcile, it will just exit here without doing anything else
				opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
			}
			return ctrl.Result{}, nil
		}
		if _, ok := fastlyAPISecret.StringData["api-token"]; ok {
			fastlyConfig.Token = fastlyAPISecret.StringData["api-token"]
			opLog.Info(fmt.Sprintf("Unable to find secret data for api-token, pausing ingress, error was: %v", err))
			patchErr := r.patchPausedStatus(ctx, ingressSecret, nil, fastlyConfig.ServiceID, fmt.Sprintf("%v", err), true)
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
			patchErr := r.patchPausedStatus(ctx, ingressSecret, nil, fastlyConfig.ServiceID, fmt.Sprintf("%v", err), true)
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
	if ingressSecret.ObjectMeta.DeletionTimestamp.IsZero() && ingressSecret.ObjectMeta.Name != "" {

		// when a patch operation is run, it triggers a reconciliation which causes the bulk certificate to be added/created twice
		// in fastly, first run through will create the private key in fastly and patch the secret, the code continues to then do the bulk certificate
		// but before that can be done the reconciler runs again after the first patch operation and does a bulk certificate check too
		// neither runs are aware of the other at this stage
		// now all the final annotation updates should happen at the end after everything has been created
		updateAnnotations := false
		annotations := make(map[string]string)

		// if the secret is not paused, and tls-acme is enabled on the ingress
		if !paused && tlsAcme {
			// check if the key is populated, if the size is 0 it means there is no key yet
			// store the original annotation values for later use
			publicKeySha1Annotation := ingressSecret.Annotations["fastly.amazee.io/public-key-sha1"]
			privateKeyIDAnnotation := ingressSecret.Annotations["fastly.amazee.io/private-key-id"]
			bulkCertificateIDAnnotation := ingressSecret.Annotations["fastly.amazee.io/bulk-certificate-id"]

			oldPublicKeySha1Annotation := ingressSecret.Annotations["fastly.amazee.io/old-public-key-sha1"]
			oldPrivateKeyIDAnnotation := ingressSecret.Annotations["fastly.amazee.io/old-private-key-id"]

			if len(ingressSecret.Data["tls.key"]) > 0 {
				// get the publickeysha1 from the privatekey so we can check if it is already in fastly at some point
				// we will also load this sha into the annotations
				publicKeySha1, err := decodePrivateKeyToPublicKeySHA1(ingressSecret.Data["tls.key"])
				if err != nil {
					opLog.Info(fmt.Sprintf("Pausing, error was: %v", err))
					patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, fmt.Sprintf("%v", err), true)
					if patchErr != nil {
						// if we can't patch the resource, just log it and return
						// next time it tries to reconcile, it will just exit here without doing anything else
						opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
					}
					return ctrl.Result{}, nil
				}

				// if the publickeysha1annotation is not empty (we already populated it once before)
				// and the annotation does not match the current publickeysha1 from the certificate (cert-manager renewal likely)
				// then we should add the new privatekey, update the annotations with the old values and clean up later
				if publicKeySha1Annotation != "" && publicKeySha1Annotation != publicKeySha1 {
					// load the privatekey into fastly
					opLog.Info("Privatekey is different to the one defined, check or load into Fastly")
					privateKeyID, err := r.addPrivateKey(ctx, ingressSecret, publicKeySha1)
					if err != nil {
						opLog.Info(fmt.Sprintf("Privatekey failed to load into Fastly, pausing, error was: %v", err))
						patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, fmt.Sprintf("%v", err), true)
						if patchErr != nil {
							// if we can't patch the resource, just log it and return
							// next time it tries to reconcile, it will just exit here without doing anything else
							opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
						}
						return ctrl.Result{}, nil
					}

					updateAnnotations = true
					// patch the ingress with what we discover from the api or from the one we created
					// add the original annotations to `old` annotations for clean up later
					annotations["fastly.amazee.io/private-key-id"] = privateKeyID
					annotations["fastly.amazee.io/public-key-sha1"] = publicKeySha1
					annotations["fastly.amazee.io/old-public-key-sha1"] = publicKeySha1Annotation
					annotations["fastly.amazee.io/old-private-key-id"] = privateKeyIDAnnotation
					privateKeyIDAnnotation = privateKeyID
					publicKeySha1Annotation = publicKeySha1
					oldPublicKeySha1Annotation = publicKeySha1Annotation
					oldPrivateKeyIDAnnotation = privateKeyIDAnnotation
				}
				// if the privatekeyID is empty, or the publickeysha1 is empty (we haven't got any value at all)
				// then we should add the privatekey and then update the annotations with the values
				if privateKeyIDAnnotation == "" || publicKeySha1Annotation == "" {
					// load the privatekey into fastly
					opLog.Info("Privatekey info not found, check or load it into Fastly")
					privateKeyID, err := r.addPrivateKey(ctx, ingressSecret, publicKeySha1)
					if err != nil {
						opLog.Info(fmt.Sprintf("Privatekey failed to load into Fastly, pausing, error was: %v", err))
						patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, fmt.Sprintf("%v", err), true)
						if patchErr != nil {
							// if we can't patch the resource, just log it and return
							// next time it tries to reconcile, it will just exit here without doing anything else
							opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
						}
						return ctrl.Result{}, nil
					}

					updateAnnotations = true
					// patch the ingress with what we discover from the api or from the one we created
					annotations["fastly.amazee.io/private-key-id"] = privateKeyID
					annotations["fastly.amazee.io/public-key-sha1"] = publicKeySha1
					privateKeyIDAnnotation = privateKeyID
					publicKeySha1Annotation = publicKeySha1
				}
			}

			// check if we have a tls.crt before trying to do anything with it
			if len(ingressSecret.Data["tls.crt"]) > 0 {
				if bulkCertificateIDAnnotation != "" && oldPublicKeySha1Annotation != "" && oldPrivateKeyIDAnnotation != "" {
					// if we do have a bulk certificate id, and there is an oldPublicKeySha1Annotation and oldPrivateKeyIDAnnotation set
					// @TODO: use `updateCertificate` instead, and not bother with the `old-bulk-certificate-id` annotation
					opLog.Info("Private key was updated, the certificate was probably renewed")
					/*
						err := r.updateCertificate(ctx, ingressSecret, bulkCertificateIDAnnotation)
						if err != nil {
							return ctrl.Result{}, fmt.Errorf("Certificate failed to update in Fastly, error was: %v", err)
						}
					*/
					// check the certificate expiration dates to see if the secret is newer than the one in fastly
					// we update the one in fastly if this one is newer.
					mainCert, _, err := getCertsFromChain(ingressSecret.Data["tls.crt"])
					if err != nil {
						errMsg := fmt.Sprintf("Unable to get certificate from chain, error was: %v", err)
						opLog.Info(errMsg)
						patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, errMsg, true)
						if patchErr != nil {
							// if we can't patch the resource, just log it and return
							// next time it tries to reconcile, it will just exit here without doing anything else
							opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
						}
						return ctrl.Result{}, nil
					}
					certDERBlock, _ := pem.Decode(mainCert)
					if certDERBlock != nil && certDERBlock.Type == "CERTIFICATE" {
						secretCert, err := x509.ParseCertificate(certDERBlock.Bytes)
						if err != nil {
							errMsg := fmt.Sprintf("Unable to parse certificate, error was: %v", err)
							opLog.Info(errMsg)
							patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, errMsg, true)
							if patchErr != nil {
								// if we can't patch the resource, just log it and return
								// next time it tries to reconcile, it will just exit here without doing anything else
								opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
							}
							return ctrl.Result{}, nil
						}
						bulkCertificate, err := r.FastlyClient.GetBulkCertificate(&fastly.GetBulkCertificateInput{
							ID: bulkCertificateIDAnnotation,
						})
						if err != nil {
							errMsg := fmt.Sprintf("Unable to get certificate information from Fastly, error was: %v", err)
							opLog.Info(errMsg)
							patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, errMsg, true)
							if patchErr != nil {
								// if we can't patch the resource, just log it and return
								// next time it tries to reconcile, it will just exit here without doing anything else
								opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
							}
							return ctrl.Result{}, nil
						}
						if secretCert.NotAfter.After(*bulkCertificate.NotAfter) {
							opLog.Info(fmt.Sprintf("Certificate has changed, old expiry is %v, new expiry is %v. Updating certificate in Fastly",
								bulkCertificate.NotAfter,
								secretCert.NotAfter,
							))
							err = r.updateCertificate(ctx, ingressSecret, bulkCertificateIDAnnotation)
							if err != nil {
								errMsg := fmt.Sprintf("Certificate failed to update in Fastly, error was: %v", err)
								opLog.Info(errMsg)
								patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, errMsg, true)
								if patchErr != nil {
									// if we can't patch the resource, just log it and return
									// next time it tries to reconcile, it will just exit here without doing anything else
									opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
								}
								return ctrl.Result{}, nil
							}
						} else {
							opLog.Info("Certificate already uploaded, possibly renewed")
						}
					}
				} else if bulkCertificateIDAnnotation == "" {
					// if we don't have the bulk certificate id, and this is not an update event
					// we assume this a new certificate and load it into fastly
					opLog.Info("Adding certificate into Fastly")
					certificateID, err := r.loadCertificate(ctx, ingressSecret, fastlyConfig)
					if err != nil {
						errMsg := fmt.Sprintf("Certificate failed to load into Fastly, error was: %v", err)
						opLog.Info(errMsg)
						patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, errMsg, true)
						if patchErr != nil {
							// if we can't patch the resource, just log it and return
							// next time it tries to reconcile, it will just exit here without doing anything else
							opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
						}
						return ctrl.Result{}, nil
					}
					updateAnnotations = true
					// patch the secret with the bulk-certificate annotation
					annotations["fastly.amazee.io/bulk-certificate-id"] = certificateID
					bulkCertificateIDAnnotation = certificateID
				} else if bulkCertificateIDAnnotation != "" {
					// check the certificate expiration dates to see if the secret is newer than the one in fastly
					// we update the one in fastly if this one is newer.
					mainCert, _, err := getCertsFromChain(ingressSecret.Data["tls.crt"])
					if err != nil {
						errMsg := fmt.Sprintf("Unable to get certificate from chain, error was: %v", err)
						opLog.Info(errMsg)
						patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, errMsg, true)
						if patchErr != nil {
							// if we can't patch the resource, just log it and return
							// next time it tries to reconcile, it will just exit here without doing anything else
							opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
						}
						return ctrl.Result{}, nil
					}
					certDERBlock, _ := pem.Decode(mainCert)
					if certDERBlock != nil && certDERBlock.Type == "CERTIFICATE" {
						secretCert, err := x509.ParseCertificate(certDERBlock.Bytes)
						if err != nil {
							errMsg := fmt.Sprintf("Unable to parse certificate, error was: %v", err)
							opLog.Info(errMsg)
							patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, errMsg, true)
							if patchErr != nil {
								// if we can't patch the resource, just log it and return
								// next time it tries to reconcile, it will just exit here without doing anything else
								opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
							}
							return ctrl.Result{}, nil
						}
						bulkCertificate, err := r.FastlyClient.GetBulkCertificate(&fastly.GetBulkCertificateInput{
							ID: bulkCertificateIDAnnotation,
						})
						if err != nil {
							errMsg := fmt.Sprintf("Unable to get certificate information from Fastly, error was: %v", err)
							opLog.Info(errMsg)
							patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, errMsg, true)
							if patchErr != nil {
								// if we can't patch the resource, just log it and return
								// next time it tries to reconcile, it will just exit here without doing anything else
								opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
							}
							return ctrl.Result{}, nil
						}
						if secretCert.NotAfter.After(*bulkCertificate.NotAfter) {
							opLog.Info(fmt.Sprintf("Certificate has changed, old expiry is %v, new expiry is %v. Updating certificate in Fastly",
								secretCert.NotAfter,
								bulkCertificate.NotAfter,
							))
							err = r.updateCertificate(ctx, ingressSecret, bulkCertificateIDAnnotation)
							if err != nil {
								errMsg := fmt.Sprintf("Certificate failed to update in Fastly, error was: %v", err)
								opLog.Info(errMsg)
								patchErr := r.patchPausedStatus(ctx, ingressSecret, annotations, fastlyConfig.ServiceID, errMsg, true)
								if patchErr != nil {
									// if we can't patch the resource, just log it and return
									// next time it tries to reconcile, it will just exit here without doing anything else
									opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
								}
								return ctrl.Result{}, nil
							}
						} else {
							opLog.Info("Certificate already uploaded")
						}
					}
				}
			} else {
				// don't do anything, reconciler will run when the certificate is ready
				opLog.Info("Certificate has not been populated yet")
			}

			// if we get this far and have old things to delete, we should do that here.
			if oldPublicKeySha1Annotation != "" && oldPrivateKeyIDAnnotation != "" {
				// TODO(marco): remove this once we're sure we don't need it anymore
				/*
					// @TODO: we don't actually store any `old-bulk-certificate-id` if that changes, we can delete it using this
					if _, ok := ingressSecret.Annotations["fastly.amazee.io/old-bulk-certificate-id"]; ok {
						opLog.Info(fmt.Sprintf("Clean up old bulk certificate id:%s", ingressSecret.Annotations["fastly.amazee.io/old-bulk-certificate-id"]))
						if err := r.deleteBulkCertificate(ingressSecret, ingressSecret.Annotations["fastly.amazee.io/old-bulk-certificate-id"]); err != nil {
							return ctrl.Result{}, err
						}
						// patch the secret to remove the old items
						r.patchSecretAnnotations(ctx, ingressSecret, map[string]string{
							"fastly.amazee.io/old-bulk-certificate-id": "",
						})
					}
				*/
				opLog.Info(fmt.Sprintf("Clean up old PubkeySha1:%s, PrivKeyID:%s", oldPublicKeySha1Annotation, oldPrivateKeyIDAnnotation))
				// TODO(marco): remove this once we're sure we don't need it anymore
				/*
					// @TODO: can't delete old private keys without deleting the certificate too
					if err := r.deletePrivateKey(ingressSecret, string(ingressSecret.Annotations["fastly.amazee.io/old-private-key-id"])); err != nil {
						return ctrl.Result{}, err
					}
				*/
				// patch the secret to remove the old items
				updateAnnotations = true
				annotations["fastly.amazee.io/private-key-id"] = ""
				annotations["fastly.amazee.io/public-key-sha1"] = ""
			}
			// if the secret has the ingress name attached, and the certificates have been uploaded
			// patch the associated ingress to unpause it
			if ingressName != "" {
				var ingress networkv1.Ingress
				if err := r.Get(ctx, types.NamespacedName{
					Name:      ingressName,
					Namespace: ingressSecret.ObjectMeta.Namespace,
				}, &ingress); err != nil {
					return ctrl.Result{}, client.IgnoreNotFound(err)
				}
				if pausedIngressVal, ok := ingress.ObjectMeta.Annotations["fastly.amazee.io/paused"]; ok {
					result, _ := strconv.ParseBool(pausedIngressVal)
					if result {
						opLog.Info(fmt.Sprintf("Unpausing ingress %s after adding certificate and key", ingressName))
						patchErr := r.patchIngressPausedStatus(ctx, ingress, fastlyConfig.ServiceID, "", false)
						if patchErr != nil {
							// if we can't patch the resource, just log it and return
							// next time it tries to reconcile, it will just exit here without doing anything else
							opLog.Info(fmt.Sprintf("Unable to patch the ingress with paused status, error was: %v", patchErr))
						}
					}
				}
			}
			// if any changes required, patch the secret
			if updateAnnotations {
				r.patchSecretAnnotations(ctx, ingressSecret, annotations)
			}
		}
	} else {
		// The object is being deleted
		if deleteExternal || !paused {
			if err := r.deleteExternalResources(ctx, ingressSecret); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to delete external resources, error was: %v", err)
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager will setup the controller to watch corev1.Secret resources and only act based on the SecretPredicates
func (r *IngressSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(SecretPredicates{}).
		Complete(r)
}

// patch the ingress secrets with the pause status to prevent anything from being done
// add the paused-reason to the annotations so user can see why it was paused and try to fix any issues it before unpausing
func (r *IngressSecretReconciler) patchPausedStatus(
	ctx context.Context,
	ingressSecret corev1.Secret,
	additionalAnnotations map[string]string,
	serviceID string,
	reason string,
	paused bool,
) error {
	annotations := map[string]interface{}{
		"fastly.amazee.io/paused":        nil,
		"fastly.amazee.io/paused-reason": reason,
		"fastly.amazee.io/paused-at":     time.Now().UTC().Format("2006-01-02 15:04:05"),
	}
	// add any additional annotations to the annotations
	for k, v := range additionalAnnotations {
		annotations[k] = v
	}
	mergePatch, err := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": annotations,
			"labels": map[string]interface{}{
				"fastly.amazee.io/paused": fmt.Sprintf("%v", paused),
			},
		},
	})
	if err != nil {
		r.Log.WithValues("ingressSecret", types.NamespacedName{
			Name:      ingressSecret.ObjectMeta.Name,
			Namespace: ingressSecret.ObjectMeta.Namespace,
		}).Info(fmt.Sprintf("Unable to create mergepatch for %s, error was: %v", ingressSecret.ObjectMeta.Name, err))
		return nil
	}
	if err := r.Patch(ctx, &ingressSecret, client.RawPatch(types.MergePatchType, mergePatch)); err != nil {
		r.Log.WithValues("ingressSecret", types.NamespacedName{
			Name:      ingressSecret.ObjectMeta.Name,
			Namespace: ingressSecret.ObjectMeta.Namespace,
		}).Info(fmt.Sprintf("Unable to patch ingress secret %s, error was: %v", ingressSecret.ObjectMeta.Name, err))
		return nil
	}
	r.Log.WithValues("ingressSecret", types.NamespacedName{
		Name:      ingressSecret.ObjectMeta.Name,
		Namespace: ingressSecret.ObjectMeta.Namespace,
	}).Info(fmt.Sprintf("Patched ingress secret %s", ingressSecret.ObjectMeta.Name))
	return nil
}

// patch the ingress with the pause status to prevent anything from being done
// add the paused-reason to the annotations so user can see why it was paused and try to fix any issues it before unpausing
func (r *IngressSecretReconciler) patchIngressPausedStatus(
	ctx context.Context,
	ingress networkv1.Ingress,
	serviceID string,
	reason string,
	paused bool,
) error {
	// set the paused annotations to nil if this is unpaused
	annotations := map[string]interface{}{
		"fastly.amazee.io/paused-reason":      nil,
		"fastly.amazee.io/paused-at":          nil,
		"fastly.amazee.io/paused-retry-count": nil,
	}
	if paused {
		// if paused, set the annotations
		annotations = map[string]interface{}{
			"fastly.amazee.io/paused-reason": reason,
			"fastly.amazee.io/paused-at":     time.Now().UTC().Format("2006-01-02 15:04:05"),
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
	return nil
}

// delete any external resources
func (r *IngressSecretReconciler) deleteExternalResources(
	ctx context.Context,
	ingressSecret corev1.Secret,
) error {
	// if we have a bulk-certificate-id, try and delete them from fastly
	if ingressSecret.Annotations["fastly.amazee.io/bulk-certificate-id"] != "" {
		r.Log.WithValues("ingress", types.NamespacedName{
			Name:      ingressSecret.ObjectMeta.Name,
			Namespace: ingressSecret.ObjectMeta.Namespace,
		}).Info("Attempting to delete bulk certificates")
		err := r.deleteBulkCertificate(ingressSecret, ingressSecret.Annotations["fastly.amazee.io/bulk-certificate-id"])
		if err != nil {
			// don't error on deletion, just log it and move on so we don't lock the finalizer up
			r.Log.WithValues("ingress", types.NamespacedName{
				Name:      ingressSecret.ObjectMeta.Name,
				Namespace: ingressSecret.ObjectMeta.Namespace,
			}).Info(fmt.Sprintf("Error trying to delete bulk certificates from platform-tls, error was: %v", err))
		}
		r.patchSecretAnnotations(ctx, ingressSecret, map[string]string{
			"fastly.amazee.io/bulk-certificate-id": "",
		})
	}
	// if we have a private-key-id, try delete from fastly
	if ingressSecret.Annotations["fastly.amazee.io/private-key-id"] != "" {
		r.Log.WithValues("ingress", types.NamespacedName{
			Name:      ingressSecret.ObjectMeta.Name,
			Namespace: ingressSecret.ObjectMeta.Namespace,
		}).Info("Attempting to delete privatekey")
		err := r.deletePrivateKey(ingressSecret, string(ingressSecret.Annotations["fastly.amazee.io/private-key-id"]))
		if err != nil {
			// don't error on deletion, just log it and move on so we don't lock the finalizer up
			r.Log.WithValues("ingress", types.NamespacedName{
				Name:      ingressSecret.ObjectMeta.Name,
				Namespace: ingressSecret.ObjectMeta.Namespace,
			}).Info(fmt.Sprintf("Error trying to delete privatekey from platform-tls, error was: %v", err))
		}
		r.patchSecretAnnotations(ctx, ingressSecret, map[string]string{
			"fastly.amazee.io/private-key-id": "",
		})
	}
	return nil
}

// load the privatekey into fastly
func (r *IngressSecretReconciler) addPrivateKey(ctx context.Context, ingressSecret corev1.Secret, publicKeySha1 string) (string, error) {
	// attempt to create the key in Fastly with the cluster name, namespace and name of the fastly api secret name
	var privateKeyID string
	privateKey, err := r.FastlyClient.CreatePrivateKey(&fastly.CreatePrivateKeyInput{
		Key:  string(ingressSecret.Data["tls.key"]),
		Name: fmt.Sprintf("cluster:%s:namespace:%s", r.ClusterName, ingressSecret.ObjectMeta.Namespace),
	})
	if err != nil {
		// if the key already exists we just continue on. Any other error then we fail
		if !strings.Contains(err.Error(), "key already exists") {
			return "", err
		}
		// if the key already exists, search fastly for it
		// @TODO filtering or searching by publickeysha1 would be nicer (not supported by API yet)
		privateKeys, err2 := r.FastlyClient.ListPrivateKeys(&fastly.ListPrivateKeysInput{
			PageSize: fastly.Uint(2000),
		})
		if err2 != nil {
			return "", err2
		}
		exists, privateKeyID := containsPrivateKey(privateKeys, publicKeySha1)
		if exists {
			r.Log.WithValues("ingress", types.NamespacedName{
				Name:      ingressSecret.ObjectMeta.Name,
				Namespace: ingressSecret.ObjectMeta.Namespace,
			}).Info(fmt.Sprintf("Privatekey with ID %s already exists", privateKeyID))
		} else {
			r.Log.WithValues("ingress", types.NamespacedName{
				Name:      ingressSecret.ObjectMeta.Name,
				Namespace: ingressSecret.ObjectMeta.Namespace,
			}).Info(fmt.Sprintf("Privatekey doesn't exist: %v", err))
		}
		return privateKeyID, nil
	}
	if privateKeyID == "" {
		// we created a private key that didnt exist, we patch the ingress secret with the ID
		privateKeyID = privateKey.ID
		r.Log.WithValues("ingress", types.NamespacedName{
			Name:      ingressSecret.ObjectMeta.Name,
			Namespace: ingressSecret.ObjectMeta.Namespace,
		}).Info(fmt.Sprintf("Privatekey with ID %s created", privateKeyID))
	}
	return privateKeyID, nil
}

// load the certificate into fastly
func (r *IngressSecretReconciler) loadCertificate(ctx context.Context, ingressSecret corev1.Secret, fastlyConfig fastlyAPI) (string, error) {
	mainCert, intermediateCert, err := getCertsFromChain(ingressSecret.Data["tls.crt"])
	if err != nil {
		return "", err
	}
	// create the certificate in fastly
	certificate, err := r.FastlyClient.CreateBulkCertificate(&fastly.CreateBulkCertificateInput{
		CertBlob:          string(mainCert),
		IntermediatesBlob: string(intermediateCert),
		TLSConfigurations: []*fastly.TLSConfiguration{
			{
				ID: fastlyConfig.PlatformTLSConfiguration,
			},
		},
	})
	if err != nil {
		return "", err
	}
	r.Log.WithValues("ingress", types.NamespacedName{
		Name:      ingressSecret.ObjectMeta.Name,
		Namespace: ingressSecret.ObjectMeta.Namespace,
	}).Info(fmt.Sprintf("Created bulkcertificate with ID %s", certificate.ID))
	return certificate.ID, nil
}

// load the certificate into fastly
func (r *IngressSecretReconciler) updateCertificate(ctx context.Context, ingressSecret corev1.Secret, certID string) error {
	mainCert, intermediateCert, err := getCertsFromChain(ingressSecret.Data["tls.crt"])
	if err != nil {
		return err
	}
	// create the certificate in fastly
	certificates, err := r.FastlyClient.UpdateBulkCertificate(&fastly.UpdateBulkCertificateInput{
		CertBlob:          string(mainCert),
		IntermediatesBlob: string(intermediateCert),
		ID:                certID,
	})
	if err != nil {
		return err
	}
	// patch with the bulk-certificate-id annotation
	r.patchSecretAnnotations(ctx, ingressSecret, map[string]string{
		"fastly.amazee.io/bulk-certificate-id": certificates.ID,
	})
	r.Log.WithValues("ingress", types.NamespacedName{
		Name:      ingressSecret.ObjectMeta.Name,
		Namespace: ingressSecret.ObjectMeta.Namespace,
	}).Info(fmt.Sprintf("Patched bulkcertificate with ID %s", certificates.ID))
	return nil
}

// helper function to patch the secret with any annotations
func (r *IngressSecretReconciler) patchSecretAnnotations(
	ctx context.Context,
	ingressSecret corev1.Secret,
	annotations map[string]string,
) error {
	if err := r.Get(ctx, types.NamespacedName{
		Name:      ingressSecret.ObjectMeta.Name,
		Namespace: ingressSecret.ObjectMeta.Namespace,
	}, &ingressSecret); err != nil {
		return fmt.Errorf("unable to find secret of %s", ingressSecret.ObjectMeta.Name)
	}
	mergePatch, err := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": annotations,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to create mergepatch for %s, error was: %v", ingressSecret.ObjectMeta.Name, err)
	}
	if err := r.Patch(ctx, &ingressSecret, client.RawPatch(types.StrategicMergePatchType, mergePatch)); err != nil {
		return fmt.Errorf("unable to patch secret %s, error was: %v", ingressSecret.ObjectMeta.Name, err)
	}
	r.Log.WithValues("ingress", types.NamespacedName{
		Name:      ingressSecret.ObjectMeta.Name,
		Namespace: ingressSecret.ObjectMeta.Namespace,
	}).Info(fmt.Sprintf("Patched secret %s", ingressSecret.ObjectMeta.Name))
	return nil
}

// helper to delete a bulk certificate
func (r *IngressSecretReconciler) deleteBulkCertificate(ingressSecret corev1.Secret, certID string) error {
	err := r.retry(5, 2*time.Second, func() (err error) {
		err = r.FastlyClient.DeleteBulkCertificate(
			&fastly.DeleteBulkCertificateInput{
				ID: certID,
			},
		)
		return
	})
	if err != nil {
		return fmt.Errorf("failed to delete bulk certificate from Fastly: %v", err)
	}
	r.Log.WithValues("ingress", types.NamespacedName{
		Name:      ingressSecret.ObjectMeta.Name,
		Namespace: ingressSecret.ObjectMeta.Namespace,
	}).Info(fmt.Sprintf("Deleted bulk certificate: %s", certID))
	return nil
}

// helper to delete privatekey
func (r *IngressSecretReconciler) deletePrivateKey(ingressSecret corev1.Secret, privateKeyID string) error {
	err := r.retry(5, 2*time.Second, func() (err error) {
		err = r.FastlyClient.DeletePrivateKey(
			&fastly.DeletePrivateKeyInput{
				ID: privateKeyID,
			},
		)
		return
	})
	if err != nil {
		return fmt.Errorf("failed to delete privatekey from Fastly: %v", err)
	}
	r.Log.WithValues("ingress", types.NamespacedName{
		Name:      ingressSecret.ObjectMeta.Name,
		Namespace: ingressSecret.ObjectMeta.Namespace,
	}).Info(fmt.Sprintf("Deleted privatekey: %s", privateKeyID))
	return nil
}

// helper to retry function
func (r *IngressSecretReconciler) retry(attempts int, sleep time.Duration, f func() error) (err error) {
	for i := 0; ; i++ {
		err = f()
		if err == nil {
			return
		}
		if i >= (attempts - 1) {
			break
		}
		time.Sleep(sleep)
	}
	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
}
