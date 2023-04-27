# Fastly Controller

This set of controllers is for automatically loading Ingress/Routes and associated certificates into Fastly and PlatformTLS

It is comprised of the following controllers
* Ingress
	* Controls setting up the domains within a service in Fastly
* Secret (for TLS secrets associated with an Ingress)
	* Controls loading the private key and certificate into Fastly

# Installation

See [Amazee.io Charts](https://github.com/amazeeio/charts)

# Controllers

## Ingress Controller

The Ingress controller handles adding the domains from an ingress into the defined Fastly service.

### Process
When an ingress is annotated with the `watch` and `service-id`, the Ingress controller will:
* Check if `api-secret-name` annotation exists, and pull credentials the defined `Kind: Secret` that it references
* Check the `serivce-id` service in Fastly for all current domains in the latest version of that service
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
## Ingress Secret Controller

The Ingress Secret controller handled adding the TLS certificates, from the Secret that is defined in the Ingress, into Fastly PlatformTLS.
It will automatically upload new certificates and private keys if they are updated in the Secret. For example, LetsEncrypt renewals will automatically get updated in PlatformTLS.

### Ingress Secret
Any Ingress Secrets get automatically annotated when the Ingress they are associated to is annotated.
```
kind: Secret
apiVersion: v1
metadata:
  name: example-tls
  annotations:
    fastly.amazee.io/watch: 'true'
    fastly.amazee.io/service-id: 7i6HN3TK9wS159v2gPAZ8A
    fastly.amazee.io/api-secret-name: example-fastly-api #optional (leave unset to use credentials defined by the controllers)
    fastly.amazee.io/bulk-certificate-id: 51iAgnMveTqoIQKw4wNddU #added automatically by the controller once detected or updated
    fastly.amazee.io/private-key-id: 2NXhVxOV4oqeb39ONHjZv1 #added automatically by the controller once detected or updated
    fastly.amazee.io/public-key-sha1: 2bb0e43514a45c6717826a6b671b0187e7689871 #added automatically by the controller once detected or updated
data:
  tls.crt: >-
    ...
  tls.key: >-
    ...
type: kubernetes.io/tls
```

## API Secret (api-secret-name)
If a specific Ingress or Ingress Secret should be using a different API token and/or PlatformTLS ID, then creating a Secret is required. 

The required Ingress and Ingress Secret should be annotated then with the `fastly.amazee.io/api-secret-name: secret-name` annotation referencing the name of the secret that is created.

```
kind: Secret
apiVersion: v1
metadata:
  name: example-fastly-api
data:
  api-token: 'abc'
  platform-tls-configuration: 'abc'
type: Opaque
```

### Troubleshooting

If the controllers encounter any issues, then the following 2 annotations and a label will be added to the Ingress and/or Ingress Secret.

```
# labels
fastly.amazee.io/paused: 'true'
# annotations
fastly.amazee.io/paused-at: '2021-01-27 04:08:39'
fastly.amazee.io/paused-reason: >-
  Unable to do x due to reason x.
```

Typical issues will be:

* The certificate was unable to be created, this will appear as an error like `Unable to find secret of www.example.com-tls to add to service`.
  * To resolve this, check that the DNS is correctly pointing at either the cluster directly, or the Fastly CDN.
  * If the DNS is correct, it could be that the TLS secret creation took too long, check if enough time has passed that the secret `www.example.com-tls` exists now. If it does, set the `fastly.amazee.io/paused` annotations to false and the controller should attempt to upload the certificate again.
* The domain already exists in a service in Fastly.
  * This is tricky, without knowing who added it or where it was added. If it exists in a different service in Fastly, whoever added it may need to remove it from the existing service before it can be added to the one defined in the annotation.
* The private key is incorrect length
  * This will usually be because PlatformTLS doesn't currently support 4096 length private keys.

Once the issue(s) are corrected, you can set the `fastly.amazee.io/paused` annotation to false and remove the `fastly.amazee.io/paused-at` and `fastly.amazee.io/paused-reason` annotations

### Running on the cluster
1. Install Instances of Custom Resources:

```sh
kubectl apply -f config/samples/
```

2. Build and push your image to the location specified by `IMG`:

```sh
make docker-build docker-push IMG=<some-registry>/fastly-controller:tag
```

3. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/fastly-controller:tag
```

### Uninstall CRDs
To delete the CRDs from the cluster:

```sh
make uninstall
```

### Undeploy controller
UnDeploy the controller from the cluster:

```sh
make undeploy
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

### How it works
This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/).

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/),
which provide a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster.

### Test It Out
1. Install the CRDs into the cluster:

```sh
make install
```

2. Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

**NOTE:** You can also run this in one step by running: `make install run`

### Modifying the API definitions
If you are editing the API definitions, generate the manifests such as CRs or CRDs using:

```sh
make manifests
```

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

