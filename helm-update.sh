#!/bin/bash

index-fastly () {
    pushd charts
    helm package fastly-controller
    helm repo index .
    popd
}

case $1 in
  index)
    index-fastly
    ;;
  template)
    helm template charts/fastly-controller -f charts/fastly-controller/values.yaml \
      --set fastly.apiToken=${FASTLY_API_TOKEN} \
      --set fastly.tlsConfigID=${FASTLY_PLATFORM_TLS_CONFIGURATION_ID} \
      --set fastly.clusterName=${CLUSTER_NAME}
    ;;
  install)
    helm repo add fastly-controller https://raw.githubusercontent.com/amazeeio/fastly-controller/master/charts
    helm upgrade --install -n fastly-controller fastly-controller fastly-controller/fastly-controller \
      --set fastly.apiToken=${FASTLY_API_TOKEN} \
      --set fastly.tlsConfigID=${FASTLY_PLATFORM_TLS_CONFIGURATION_ID} \
      --set fastly.clusterName=${CLUSTER_NAME}
    ;;
  install-tgz)
    helm upgrade --install -n fastly-controller fastly-controller  charts/fastly-controller-0.0.3.tgz  \
      --set fastly.apiToken=${FASTLY_API_TOKEN} \
      --set fastly.tlsConfigID=${FASTLY_PLATFORM_TLS_CONFIGURATION_ID} \
      --set fastly.clusterName=${CLUSTER_NAME}
    ;;
  *)
    echo "nothing"
    ;;
esac