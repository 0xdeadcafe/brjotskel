#!/bin/sh
# gather/linux/enum-containers.sh — Docker/Podman/LXC/K8s enumeration
# Requires: docker/podman group membership or root
# Read-only: YES
# MITRE ATT&CK: T1610 — Deploy Container, T1613 — Container Discovery

echo "=== CONTAINER RUNTIME ==="
command -v docker >/dev/null 2>&1 && echo "docker: $(docker --version 2>/dev/null)"
command -v podman >/dev/null 2>&1 && echo "podman: $(podman --version 2>/dev/null)"
command -v lxc >/dev/null 2>&1 && echo "lxc: $(lxc --version 2>/dev/null)"
command -v kubectl >/dev/null 2>&1 && echo "kubectl: $(kubectl version --client --short 2>/dev/null)"
command -v crictl >/dev/null 2>&1 && echo "crictl: present"

echo ""
echo "=== AM I IN A CONTAINER? ==="
[ -f /.dockerenv ] && echo "YES: /.dockerenv exists"
grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null && echo "YES: container cgroup detected"
cat /proc/1/cgroup 2>/dev/null | head -5

echo ""
echo "=== DOCKER ==="
if command -v docker >/dev/null 2>&1; then
  echo "--- running containers ---"
  docker ps 2>/dev/null
  echo "--- all containers ---"
  docker ps -a 2>/dev/null
  echo "--- images ---"
  docker images 2>/dev/null
  echo "--- volumes ---"
  docker volume ls 2>/dev/null
  echo "--- networks ---"
  docker network ls 2>/dev/null
  echo "--- privileged/host-net containers ---"
  docker inspect $(docker ps -q 2>/dev/null) 2>/dev/null | grep -B5 '"Privileged": true\|"NetworkMode": "host"' | head -20
fi

echo ""
echo "=== PODMAN ==="
if command -v podman >/dev/null 2>&1; then
  echo "--- running containers ---"
  podman ps 2>/dev/null
  echo "--- all ---"
  podman ps -a 2>/dev/null
fi

echo ""
echo "=== KUBERNETES (if node) ==="
if command -v kubectl >/dev/null 2>&1; then
  echo "--- pods ---"
  kubectl get pods --all-namespaces 2>/dev/null | head -30
  echo "--- secrets ---"
  kubectl get secrets --all-namespaces 2>/dev/null | head -20
  echo "--- service accounts ---"
  kubectl get serviceaccounts --all-namespaces 2>/dev/null | head -20
fi
# Check for service account token
[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] && echo "K8S SA TOKEN: present" && cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null

echo ""
echo "=== DOCKER SOCKET ==="
ls -la /var/run/docker.sock 2>/dev/null
ls -la /run/containerd/containerd.sock 2>/dev/null
