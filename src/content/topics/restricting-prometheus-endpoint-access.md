---
title: Restricting Prometheus Endpoint Access
description: Preventing unauthenticated access to Prometheus metrics that expose cluster topology, pod identities, and internal service addresses
category: defensive
createdAt: 2026-04-12
impact: An open Prometheus endpoint gives an attacker inside the cluster a full map of namespaces, pod names, container images, service IPs, and node details without making a single Kubernetes API call. Enabling authentication and restricting network access removes that passive reconnaissance path.
mitigation:
  - Enable basic auth or TLS on the Prometheus HTTP endpoint using the --web.config.file flag
  - Apply a NetworkPolicy that restricts ingress to the Prometheus pod to only authorized namespaces or pods, blocking arbitrary workloads from querying the metrics API
  - Treat port-forward access to the Prometheus pod as a sensitive operation subject to the same RBAC controls as other privileged resources
references: |
  - [Cluster Reconnaissance via Prometheus](/topics/cluster-reconnaissance-via-prometheus)
  - [Prometheus Basic Auth Guide](https://prometheus.io/docs/guides/basic-auth/)
  - [Prometheus web.config reference](https://prometheus.io/docs/prometheus/latest/configuration/https/)
---

Prometheus ships with no authentication enabled by default. Any pod in the cluster that can reach the Prometheus service can query the full metrics database, retrieve container image inventories, map internal services, and read node details, all without touching the Kubernetes API. Two controls close this gap: enabling authentication on the Prometheus HTTP endpoint and restricting network access via NetworkPolicy.

## Enabling Basic Auth via web.config.file

Prometheus supports basic auth through a web configuration file passed via the `--web.config.file` flag. The file uses bcrypt-hashed passwords.

Generate a bcrypt hash for the password:

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt(rounds=10)).decode())"
```

```output
$2b$10$OFBLW.e.aIu5vio8uMN3TO4qXzs9BuIj970yGTmOezdwfVavwhLTW
```

Create the web configuration file:

```yaml
basic_auth_users:
  admin: $2b$10$OFBLW.e.aIu5vio8uMN3TO4qXzs9BuIj970yGTmOezdwfVavwhLTW
```

Store it as a ConfigMap and mount it into the Prometheus pod:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-web-config
  namespace: monitoring
data:
  web.yml: |
    basic_auth_users:
      admin: $2b$10$OFBLW.e.aIu5vio8uMN3TO4qXzs9BuIj970yGTmOezdwfVavwhLTW
```

Pass the flag and mount the volume in the Prometheus deployment:

```yaml
containers:
  - name: prometheus-server
    args:
      - --web.config.file=/etc/prometheus/web-config/web.yml
    volumeMounts:
      - name: web-config
        mountPath: /etc/prometheus/web-config
volumes:
  - name: web-config
    configMap:
      name: prometheus-web-config
```

Once the pod restarts, unauthenticated requests return `401 Unauthorized`:

```output
HTTP/1.1 401 Unauthorized
```

Requests with valid credentials return `200 OK`:

```output
HTTP/1.1 200 OK
```

If using the [prometheus-community Helm chart](https://github.com/prometheus-community/helm-charts), you may need to configure health probes to use basic auth credentials, as the default probes typically use plain HTTP. Consult the chart documentation for the specific configuration options available in your chart version.

## Restricting Access with NetworkPolicy

A NetworkPolicy limits which pods can initiate connections to the Prometheus pod. The following policy denies all ingress to the Prometheus pod except from pods carrying the label `role: monitoring-access`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: prometheus-restrict-ingress
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: prometheus
      app.kubernetes.io/component: server
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: monitoring-access
    ports:
    - protocol: TCP
      port: 9090
```

To also allow access from a specific namespace such as a dedicated Grafana namespace:

```yaml
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: grafana
    - podSelector:
        matchLabels:
          role: monitoring-access
    ports:
    - protocol: TCP
      port: 9090
```

NetworkPolicy enforcement depends on the CNI plugin. CNIs like Calico, Cilium, Weave Net, and others support NetworkPolicy enforcement.

## Limitations

- **Authentication weaknesses**: Basic auth credentials are transmitted as base64-encoded strings. Without TLS, credentials are readable on the network. Basic auth also lacks modern security features like multi-factor authentication or token expiration.

- **Credential management**: The bcrypt passwords must be stored in ConfigMaps or Secrets. Credential rotation requires updating the ConfigMap and restarting Prometheus pods.

- **Network bypass methods**: NetworkPolicy only restricts pod-to-pod traffic. It does not protect against `kubectl port-forward` (which bypasses the pod network), direct node access, or external service exposure via NodePort, LoadBalancer, or Ingress.

- **Administrative endpoints**: Basic auth protects the metrics API, but Prometheus exposes administrative endpoints like `/-/reload` and `/-/quit` that may require separate protection.

- **RBAC for port-forward**: Restricting the `pods/portforward` verb via RBAC covers kubectl access. A role that grants read access to pods without allowing port-forward:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: prometheus-read-only
  namespace: monitoring
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
```

Any attempt to port-forward without the `pods/portforward` verb is rejected at the API server:

```output
error: pods "prometheus-server-8545d4469-dq4td" is forbidden: User "system:serviceaccount:monitoring:restricted-user" cannot create resource "pods/portforward" in API group "" in the namespace "monitoring"
```

