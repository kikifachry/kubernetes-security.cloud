---
title: Detecting API Server Proxy Abuse
description: Identifying abuse of the services/proxy and pods/proxy subresources to bypass network segmentation or use the API server as an open HTTP proxy
category: defensive
createdAt: 2026-05-16
impact: An attacker with services/proxy access can bypass NetworkPolicies and reach internal services that should be isolated. Pod status manipulation can turn the API server into an open HTTP proxy to external endpoints. Detection relies on audit log analysis of proxy requests and pod status modifications.
mitigation:
  - Restrict create and get on services/proxy and pods/proxy to only users and service accounts that require debugging access
  - Alert on proxy requests from pod identities to services outside their own namespace
  - Alert on any pods/status patch event from non-kubelet identities
  - Export API server audit logs to centralized logging so proxy activity is visible alongside network flow data
references: |
  - [Abusing Kubernetes API Server Proxy](/topics/abusing-kubernetes-api-server-proxy)
  - [Kubernetes Audit Logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
---

The Kubernetes API server proxy subresource allows authenticated users to make HTTP requests to any service or pod through the API server. This feature is designed for debugging, but it bypasses NetworkPolicies because the request originates from the API server, not the user's pod. Additionally, pod status manipulation can redirect proxy traffic to external IPs, turning the API server into an open HTTP proxy.

Detection depends on two independent signals: proxy request patterns in the audit log, and unauthorized pod status modifications.

## Signal 1: Proxy Request Patterns

Every proxy request to a service or pod produces a `ResponseComplete` audit entry. The `requestURI` field contains the full proxy path, including the target namespace, service or pod name, port, and request path.

### Service proxy request

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "f86e87fe-52fb-4251-90ab-94df381ce2eb",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/monitoring/services/grafana:3000/proxy/",
  "verb": "get",
  "user": {
    "username": "system:serviceaccount:production:proxy-user",
    "groups": ["system:serviceaccounts", "system:serviceaccounts:production", "system:authenticated"]
  },
  "sourceIPs": ["10.244.0.27"],
  "userAgent": "curl/8.7.1",
  "objectRef": {
    "resource": "services",
    "subresource": "proxy",
    "namespace": "monitoring",
    "name": "grafana:3000",
    "apiVersion": "v1"
  },
  "responseStatus": { "metadata": {}, "code": 200 },
  "requestReceivedTimestamp": "2026-05-01T15:53:25.096525Z",
  "stageTimestamp": "2026-05-01T15:53:25.098859Z"
}
```

The key fields for detection:
- `objectRef.subresource: "proxy"` identifies this as a proxy request
- `objectRef.namespace: "monitoring"` is the target namespace, different from the requester's namespace (`production`)
- `user.username` reveals the service account that initiated the request
- `sourceIPs` shows the pod IP that made the API call

### Pod proxy request

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/production/pods/api-server:80/proxy/get",
  "verb": "get",
  "user": {
    "username": "system:serviceaccount:production:proxy-user",
    "groups": ["system:serviceaccounts", "system:serviceaccounts:production", "system:authenticated"]
  },
  "sourceIPs": ["10.244.0.27"],
  "userAgent": "curl/8.7.1",
  "objectRef": {
    "resource": "pods",
    "subresource": "proxy",
    "namespace": "production",
    "name": "api-server:80",
    "apiVersion": "v1"
  },
  "responseStatus": { "metadata": {}, "code": 200 },
  "requestReceivedTimestamp": "2026-05-01T15:53:30.011346Z",
  "stageTimestamp": "2026-05-01T15:53:30.018432Z"
}
```

## Signal 2: Pod Status Manipulation

Patching `status.podIP` to redirect proxy traffic to external IPs produces a distinct audit event:

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/production/pods/api-server/status",
  "verb": "patch",
  "user": {
    "username": "system:serviceaccount:production:proxy-user",
    "groups": ["system:serviceaccounts", "system:serviceaccounts:production", "system:authenticated"]
  },
  "sourceIPs": ["10.244.0.27"],
  "userAgent": "curl/8.7.1",
  "objectRef": {
    "resource": "pods",
    "subresource": "status",
    "namespace": "production",
    "name": "api-server",
    "apiVersion": "v1"
  },
  "responseStatus": { "metadata": {}, "code": 200 },
  "requestReceivedTimestamp": "2026-05-01T15:53:35.011346Z",
  "stageTimestamp": "2026-05-01T15:53:35.014521Z"
}
```

The `user.username` is a service account, not the kubelet. In normal operation, only the kubelet patches pod status. The `requestObject` field may contain the patched IP value if `Request` or `RequestResponse` level auditing is enabled.

## Detection Queries

Assuming API server audit logs are shipped to Loki with the label `{job="k8s-audit"}`.

### Detect service proxy requests

Filter for proxy requests to services where the requester is a pod identity:

```bash
logcli query '{job="k8s-audit"} |= "subresource":"proxy" |= "resource":"services" |= "username":"system:serviceaccount:"' \
  --output=jsonl \
  | jq -r '.line | fromjson | {user: .user.username, target: (.objectRef.namespace + "/" + .objectRef.name), uri: .requestURI, timestamp: .requestReceivedTimestamp}'
```

```output
{
  "user": "system:serviceaccount:production:proxy-user",
  "target": "monitoring/grafana:3000",
  "uri": "/api/v1/namespaces/monitoring/services/grafana:3000/proxy/",
  "timestamp": "2026-05-01T15:53:25.096525Z"
}
```

### Detect cross-namespace proxy access

The most reliable signal is a pod identity proxying to a service in a different namespace. This query extracts the requester's namespace from the username and compares it to the target namespace:

```bash
logcli query '{job="k8s-audit"} |= "subresource":"proxy" |= "resource":"services" |= "username":"system:serviceaccount:"' \
  --output=jsonl \
  | jq -r '
    .line | fromjson |
    .user.username as $user |
    .objectRef.namespace as $target_ns |
    ($user | split(":")[2]) as $source_ns |
    select($source_ns != $target_ns) |
    {user: $user, source: $source_ns, target: ($target_ns + "/" + .objectRef.name), uri: .requestURI, timestamp: .requestReceivedTimestamp}
  '
```

```output
{
  "user": "system:serviceaccount:production:proxy-user",
  "source": "production",
  "target": "monitoring/grafana:3000",
  "uri": "/api/v1/namespaces/monitoring/services/grafana:3000/proxy/",
  "timestamp": "2026-05-01T15:53:25.096525Z"
}
```

### Detect pod status manipulation

Monitor for `patch` events on `pods/status` from non-kubelet identities:

```bash
logcli query '{job="k8s-audit"} |= "subresource":"status" |= "verb":"patch" !~ "username":"system:node:"' \
  --output=jsonl \
  | jq -r '.line | fromjson | {user: .user.username, pod: (.objectRef.namespace + "/" + .objectRef.name), timestamp: .requestReceivedTimestamp}'
```

```output
{
  "user": "system:serviceaccount:production:proxy-user",
  "pod": "production/api-server",
  "timestamp": "2026-05-01T15:53:35.011346Z"
}
```

To see the patched IP value, require `Request` level audit logging and check the `requestObject` field:

```bash
logcli query '{job="k8s-audit"} |= "subresource":"status" |= "verb":"patch" !~ "username":"system:node:"' \
  --output=jsonl \
  | jq -r '.line | fromjson | {user: .user.username, pod: (.objectRef.namespace + "/" + .objectRef.name), patchedIP: .requestObject.status.podIP, timestamp: .requestReceivedTimestamp}'
```

```output
{
  "user": "system:serviceaccount:production:proxy-user",
  "pod": "production/api-server",
  "patchedIP": "203.0.113.50",
  "timestamp": "2026-05-01T15:53:35.011346Z"
}
```

### Detect repeated status patches

Maintaining a proxy redirect requires continuous patching because the kubelet reconciles pod status. A burst of status patches to the same pod from the same identity is a strong signal:

```bash
logcli query '{job="k8s-audit"} |= "subresource":"status" |= "verb":"patch" !~ "username":"system:node:"' \
  --output=jsonl \
  | jq -r '.line | fromjson | .objectRef.namespace + "/" + .objectRef.name + ":" + .user.username' \
  | sort | uniq -c | sort -rn | head -10
```

```output
     47 production/api-server:system:serviceaccount:production:proxy-user
      3 production/api-server:system:serviceaccount:production:deployer
```

A count of 47 patches to the same pod in a short window is anomalous. Normal status updates come from the kubelet at pod lifecycle events (startup, readiness changes, termination).

## Known Legitimate Proxy Users

Not every proxy request is hostile. The following are common authorized uses:

| Identity | Typical use |
| --- | --- |
| `kubectl proxy` from admin workstation | Debugging internal services during troubleshooting |
| CI/CD pipeline service accounts | Deployment verification against internal services |
| Monitoring tools (Prometheus, Grafana) | Health checks and metrics scraping |
| Cluster operators | Accessing control plane component endpoints |

The detection signal is proxy access **outside** these patterns. A pod identity proxying to a service in a different namespace, especially a sensitive namespace like `kube-system` or `monitoring`, should trigger investigation.

## Audit Policy Requirements

A minimal audit policy that captures both proxy requests and status modifications:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    resources:
      - group: ""
        resources: ["services/proxy", "pods/proxy"]
  - level: Request
    verbs: ["patch", "update"]
    resources:
      - group: ""
        resources: ["pods/status"]
```

`Metadata` level is sufficient for proxy requests because the `requestURI` field already contains the full proxy path. `Request` level is required for `pods/status` patches to capture the `requestObject` containing the patched IP value.
