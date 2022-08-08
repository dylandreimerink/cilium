#!/bin/bash

# Make output verbose
set -v

# Write kind config file
cat <<EOT >> /tmp/kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
- role: worker
networking:
  disableDefaultCNI: true
EOT

export KUBECONFIG=/root/.kube/config

# Create kind cluster
kind create cluster --config=/tmp/kind-config.yaml

# Export kubeconfig
kind export kubeconfig

# Get cluster credentials
kubectl cluster-info --context kind-kind

# Install cilium-cli
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/master/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}

cilium install

cilium status --wait

cilium connectivity test --datapath

# Shutdown system once we are done
systemctl start systemd-poweroff
