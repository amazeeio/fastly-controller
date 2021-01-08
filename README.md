# Fastly Controller

This set of controllers is for automatically loading Ingress/Routes and associated certificates into Fastly and PlatformTLS

It is comprised of the following controllers
* Ingress
	* Controls setting up the domains within a service in Fastly
* Secret (for TLS secrets associated with an Ingress)
	* Controls loading the private key and certificate into Fastly

## Ingress Controller

### Process (MVP)
When an ingress is annotated with the `watch` and `service-id`, the Ingress controller will:
* Check if `api-secret-name` annotation exists, and pull credentials from it if required
* Check the service in Fastly for all current domains in the latest version of that service
* Iterate through the `rules` in the ingress to check if the hosts are already in the service in Fastly
* Checks for the existence of a TLS `secretName` and patch it with:
	* ServiceID
	* `watch` annotation
	* `api-secret-name` if one is defined on the ingress
* If there are new domains to add
	* Clone the latest version (or use the existing cloned version if one is available)
	* Check the domain isn't already in the service and add it
	* Validate the service in Fastly
	* Activate the service in Fastly

Once the TLS `secretName` has been patched, the `ingressSecret` controller will do what it needs to do to get the certificates into Fastly PlatformTLS. 

This process is as follows
* Check for the existence of the `tls.key` value
	* Add it to Fastly PlatformTLS
	* Patch the secret with the returned PrivateKeyID and PublicKeySha1 values for the private key
* With the list of domains that were patched into the secret
	* Add the bulk certificate into PlatformTLS
	* Patch the secret with the returned bulk certificate ID

> If at any point a step in the process fails, the controller will try and patch the objects with a paused status to prevent it from trying again and again.

### Ingress
Any ingresses that should be in Fastly attached to the service defined, add the required annotations
```
kind: Ingress
apiVersion: extensions/v1beta1
metadata:
  name: example
  annotations:
    fastly.amazee.io/watch: 'true'
    fastly.amazee.io/service-id: 7i6HN3TK9wS159v2gPAZ8A
    fastly.amazee.io/api-secret-name: example-fastly-api #optional (leave unset to use credentials defined by the controllers)
spec:
  tls:
    - hosts:
        - www.example.com
      secretName: example-tls
  rules:
    - host: www.example.com
	  ...
```

### Ingress Secret
Any ingress secrets get automatically annotated when the ingress they are associated to is annotated.
```
kind: Secret
apiVersion: v1
metadata:
  name: example-tls
  annotations:
    fastly.amazee.io/watch: 'true'
    fastly.amazee.io/service-id: 7i6HN3TK9wS159v2gPAZ8A
    fastly.amazee.io/api-secret-name: example-fastly-api #optional (leave unset to use credentials defined by the controllers)
    fastly.amazee.io/bulk-certificate-id: 51iAgnMveTqoIQKw4wNddU
    fastly.amazee.io/private-key-id: 2NXhVxOV4oqeb39ONHjZv1
    fastly.amazee.io/public-key-sha1: 2bb0e43514a45c6717826a6b671b0187e7689871
data:
  tls.crt: >-
    ...
  tls.key: >-
    ...
type: kubernetes.io/tls
```

### API Secret
This is used if having different credentials to what the controller is started with are required.

## Route Controller
Not implemented

## Services Controller
Not implemented

## Snippet Controller
Not implemented

# Install

> WIP

```
helm repo add fastly-controller https://raw.githubusercontent.com/amazeeio/fastly-controller/master/charts
helm upgrade --install -n fastly-controller fastly-controller fastly-controller/fastly-controller \
	--set fastly.apiToken=${FASTLY_API_TOKEN} \
	--set fastly.tlsConfigID=${FASTLY_PLATFORM_TLS_CONFIGURATION_ID} \
	--set fastly.clusterName=${CLUSTER_NAME}

## or from file

helm upgrade --install -n fastly-controller charts/fastly-controller-0.1.0.tgz  \
	--set fastly.apiToken=${FASTLY_API_TOKEN} \
	--set fastly.tlsConfigID=${FASTLY_PLATFORM_TLS_CONFIGURATION_ID} \
	--set fastly.clusterName=${CLUSTER_NAME}
```

## Requirements
Some environment variables need to be configured initially to start the controllers
* `FASTLY_API_TOKEN` this is the default API token to use for all requests
* `FASTLY_PLATFORM_TLS_CONFIGURATION_ID` this is the default TLS configuration ID to use for all requests
* `CLUSTER_NAME` set this to the name of the cluster, this will be used in any comments or descriptions when interacting with Fastly API
Optional