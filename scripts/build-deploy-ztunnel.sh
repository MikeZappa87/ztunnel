#!/bin/bash
# Build ztunnel from this branch and deploy to kind cluster
# Usage: ./scripts/build-deploy-ztunnel.sh

set -e

CLUSTER_NAME="${CLUSTER_NAME:-ztunnel-test}"
IMAGE_TAG="${IMAGE_TAG:-local}"
IMAGE_NAME="ztunnel:${IMAGE_TAG}"

echo "=== Building ztunnel release binary ==="
cd /workspaces/ztunnel
cargo build --release --bin ztunnel

echo "=== Building Docker image ==="
# Create a minimal Dockerfile if needed
cat > /tmp/Dockerfile.ztunnel << 'EOF'
FROM gcr.io/distroless/cc-debian12:nonroot
COPY ztunnel /usr/local/bin/ztunnel
ENTRYPOINT ["/usr/local/bin/ztunnel"]
EOF

cp out/rust/release/ztunnel /tmp/ztunnel
docker build -t "${IMAGE_NAME}" -f /tmp/Dockerfile.ztunnel /tmp

echo "=== Loading image into kind cluster '${CLUSTER_NAME}' ==="
kind load docker-image "${IMAGE_NAME}" --name "${CLUSTER_NAME}"

echo "=== Updating ztunnel DaemonSet to use local image ==="
kubectl set image ds/ztunnel -n istio-system ztunnel="${IMAGE_NAME}"
kubectl patch ds/ztunnel -n istio-system -p '{"spec":{"template":{"spec":{"containers":[{"name":"ztunnel","imagePullPolicy":"Never"}]}}}}'

echo "=== Waiting for rollout ==="
kubectl rollout status ds/ztunnel -n istio-system --timeout=180s || {
    echo "Rollout timed out, checking pod status..."
    kubectl get pods -n istio-system -l app=ztunnel
    kubectl logs -n istio-system -l app=ztunnel --tail=20
}

echo "=== Done ==="
kubectl get pods -n istio-system -l app=ztunnel
