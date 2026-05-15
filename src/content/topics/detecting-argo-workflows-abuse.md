---
title: Detecting Argo Workflows Abuse via Audit Logs
description: Identifying unauthorized workflow creation, CronWorkflow persistence, and WorkflowTemplate poisoning by auditing argoproj.io resource events
category: defensive
createdAt: 2026-05-15
impact: When audit logging records Argo Workflows resource creation, you can see who submitted workflows, created CronWorkflows, or modified WorkflowTemplates. Without it, malicious workflows blend into normal CI/CD traffic because the Argo controller executes them using its own credentials.
mitigation:
  - Enable Kubernetes audit logging with a policy that records argoproj.io resource creation events. The workflows, cronworkflows, and workflowtemplates resources are the primary signals.
  - Regularly audit Roles and RoleBindings that grant workflows create, cronworkflows create, or workflowtemplates patch verbs. Keep grants narrow and namespace-scoped.
  - Alert on workflow creation from identities that should never submit workflows, such as application ServiceAccounts or developer accounts outside CI/CD pipelines.
  - Treat CronWorkflow creation from non-operator identities as high-priority regardless of namespace.
references: |
  - [Weaponizing Argo Workflows](/topics/weaponizing-argo-workflows)
  - [Argo Workflows Security Documentation](https://argo-workflows.readthedocs.io/en/stable/security/)
  - [Audit logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
---

Kubernetes audit events record creation and modification of Argo Workflows custom resources. When an attacker submits a workflow via the Argo API, the Argo controller creates a Workflow object in the cluster. That creation event is recorded in the audit log with the identity of the Argo controller service account, not the attacker. The attacker identity is visible only if the Argo API server logs its own requests separately.

> [!NOTE]
> Kubernetes audit logging must be enabled on the API server. If auditing is off or the policy does not cover argoproj.io resources, workflow creation produces no distinguishable trail in the Kubernetes audit log.

## Signal 1: Workflow Creation Events

Every Workflow, CronWorkflow, and WorkflowTemplate creation generates an audit event. The verb is create, the objectRef.resource is workflows, cronworkflows, or workflowtemplates, and the objectRef.apiGroup is argoproj.io.

The Argo controller service account creates workflows on behalf of authenticated API users. In the Kubernetes audit log, the user field shows the Argo controller identity, typically system:serviceaccount:argo:argo-server. The actual user who triggered the workflow is recorded in the workflow metadata under the workflows.argoproj.io/creator label, but that label is not part of the audit event itself.

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Metadata",
  "auditID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "stage": "ResponseComplete",
  "requestURI": "/apis/argoproj.io/v1alpha1/namespaces/production/workflows",
  "verb": "create",
  "user": {
    "username": "system:serviceaccount:argo:argo-server",
    "groups": ["system:serviceaccounts", "system:serviceaccounts:argo", "system:authenticated"]
  },
  "sourceIPs": ["10.244.0.15"],
  "userAgent": "argo-server/v3.6.0",
  "objectRef": {
    "resource": "workflows",
    "apiGroup": "argoproj.io",
    "apiVersion": "v1alpha1",
    "namespace": "production"
  },
  "responseStatus": { "metadata": {}, "code": 201 },
  "requestReceivedTimestamp": "2026-05-14T10:23:45.011346Z",
  "stageTimestamp": "2026-05-14T10:23:45.015221Z"
}
```

The user.username is system:serviceaccount:argo:argo-server. This is the Argo API server identity. Every workflow creation appears to come from this account in the Kubernetes audit log, regardless of who authenticated to the Argo API.

## Signal 2: RBAC Grants for Workflow Permissions

Workflow creation requires the create verb on workflows, cronworkflows, or workflowtemplates in the argoproj.io API group. Proactively auditing these grants helps identify potential abuse paths before they are exploited.

### Check who can create workflows

List every Role that grants the workflows create verb:

```bash
kubectl get roles -A -o json \
  | jq -r '
    .items[] |
    select(.rules[]? | (.apiGroups[]? == "argoproj.io") and (.resources[]? == "workflows") and (.verbs[]? == "create")) |
    "\(.metadata.namespace)/\(.metadata.name)"
  '
```

```output
argo/submit-workflow-template
argo/workflow-manager
production/workflow-submitter
```

For each Role returned, list the subjects that hold it:

```bash
ROLE="<role-name>"
NAMESPACE="<namespace>"
kubectl get rolebindings -n "$NAMESPACE" -o json \
  | jq -r --arg role "$ROLE" '
    .items[]
    | select(.roleRef.name == $role)
    | .subjects[]??
    | "\(.kind)/\(.name)"
  '
```

```output
ServiceAccount/workflow-sa
```

Flag bindings where the subject is a ServiceAccount in an application namespace, or where resourceNames is absent from the role rules.

### Check who can create CronWorkflows

```bash
kubectl get roles -A -o json \
  | jq -r '
    .items[] |
    select(.rules[]? | (.apiGroups[]? == "argoproj.io") and (.resources[]? == "cronworkflows") and (.verbs[]? == "create")) |
    "\(.metadata.namespace)/\(.metadata.name)"
  '
```

CronWorkflow creation is more dangerous than one-time workflows because it persists in the cluster and executes on a recurring schedule. Any identity with this permission outside of a dedicated scheduler or operator should be reviewed.

### Check who can modify WorkflowTemplates

```bash
kubectl get roles -A -o json \
  | jq -r '
    .items[] |
    select(.rules[]? | (.apiGroups[]? == "argoproj.io") and (.resources[]? == "workflowtemplates") and (.verbs[]? == "patch" or .verbs[]? == "update")) |
    "\(.metadata.namespace)/\(.metadata.name)"
  '
```

WorkflowTemplate modification enables supply chain compromise. Any identity with patch or update on workflowtemplates can inject malicious steps into templates that CI/CD pipelines reference.

### Check workflow ServiceAccount permissions for secrets access

Workflow ServiceAccounts often hold broader permissions than the identity that submitted the workflow. Check which workflow SAs can read secrets:

```bash
kubectl get roles -A -o json \
  | jq -r '
    .items[] |
    select(.rules[]? | (.resources[]? == "secrets") and (.verbs[]? == "get") and ((.resourceNames // []) | length == 0)) |
    "\(.metadata.namespace)/\(.metadata.name)"
  '
```

```output
argo/argo-role
production/workflow-role
```

A workflow SA with secrets:get and no resourceNames can read every secret in the namespace. This is the most common misconfiguration that enables secret exfiltration via workflow identity.

## Signal 3: Suspicious Workflow Characteristics

Workflows created by attackers often exhibit patterns that differ from legitimate CI/CD pipelines.

### Workflows using unexpected ServiceAccounts

List all workflows and the ServiceAccount they run under:

```bash
kubectl get workflows -A -o json \
  | jq -r '
    .items[] |
    "\(.metadata.namespace)/\(.metadata.name) -> SA: \(.spec.serviceAccountName // "(default)")"
  '
```

Flag workflows running under ServiceAccounts that are not associated with approved CI/CD pipelines.

### Workflow pods with unexpected images

Check what container images workflow pods are using:

```bash
kubectl get pods -A -l workflows.argoproj.io/workflow -o json \
  | jq -r '
    .items[] |
    .metadata.name as $pod | .metadata.namespace as $ns |
    .spec.containers[] |
    select(.name != "wait") |
    "\($ns)/\($pod) -> image: \(.image)"
  '
```

Workflows using images outside the organization approved list, such as alpine:latest, busybox, or bitnami/kubectl, warrant investigation. Legitimate CI/CD pipelines typically use specific application images or approved base images with pinned tags.

### CronWorkflows with aggressive schedules

List all CronWorkflows and their schedules:

```bash
kubectl get cronworkflows -A -o json \
  | jq -r '
    .items[] |
    "\(.metadata.namespace)/\(.metadata.name) -> schedule: \(.spec.schedule), SA: \(.spec.serviceAccountName // "(default)")"
  '
```

CronWorkflows running every few minutes, such as */5 * * * * or more frequent, from non-operator identities are suspicious. Legitimate scheduled workflows typically run on hourly or daily intervals.

## Detection Queries

Assuming API server audit logs are shipped to Loki with the label {job="k8s-audit"}.

### Search for workflow creation

Filter for Workflow creation events:

```bash
logcli query '{job="k8s-audit"} |= "resource":"workflows" |= "verb":"create" |= "argoproj.io"' \
  --output=jsonl \
  | jq -r '.line | fromjson | {user: .user.username, namespace: .objectRef.namespace, timestamp: .requestReceivedTimestamp}'
```

### Search for CronWorkflow creation

```bash
logcli query '{job="k8s-audit"} |= "resource":"cronworkflows" |= "verb":"create" |= "argoproj.io"' \
  --output=jsonl \
  | jq -r '.line | fromjson | {user: .user.username, namespace: .objectRef.namespace, timestamp: .requestReceivedTimestamp}'
```

### Search for WorkflowTemplate modifications

```bash
logcli query '{job="k8s-audit"} |= "resource":"workflowtemplates" |= "verb":"patch" |= "argoproj.io"' \
  --output=jsonl \
  | jq -r '.line | fromjson | {user: .user.username, namespace: .objectRef.namespace, timestamp: .requestReceivedTimestamp}'
```

## Known Legitimate Workflow Patterns

Not every workflow creation is hostile. The following are common authorized uses:

| Source | Typical use |
| --- | --- |
| CI/CD pipelines | Triggering build and deployment workflows |
| Argo Events | Event-driven workflow execution |
| Platform operators | Testing workflow templates and configurations |
| Scheduled data processing | CronWorkflows for periodic ETL jobs |

The detection signal is workflow creation outside these patterns. A workflow submitted from a ServiceAccount that has never done it before, or a CronWorkflow created at an unusual hour from an unexpected namespace, should trigger investigation.

## Correlation with Other Signals

Workflow abuse rarely happens in isolation. After finding suspicious workflow activity, check for related activity from the same identity.

### Check for permission enumeration before workflow submission

An attacker often maps their capabilities before submitting workflows:

```bash
logcli query '{job="k8s-audit"} |= "resource":"selfsubjectrulesreviews" |= "verb":"create"' \
  --output=jsonl \
  | jq -r '.line | fromjson | {user: .user.username, timestamp: .requestReceivedTimestamp}'
```

A spike in SelfSubjectRulesReview requests followed by workflow creation suggests the attacker was mapping their capabilities first.

### Check what workflows accessed after execution

After identifying suspicious workflows, check what resources the workflow ServiceAccount accessed:

```bash
logcli query '{job="k8s-audit"} |= "verb":"get" |= "resource":"secrets"' \
  --output=jsonl \
  | jq -r '.line | fromjson | {user: .user.username, namespace: .objectRef.namespace, resource: .objectRef.name, timestamp: .requestReceivedTimestamp}'
```

Filter for events where user.username matches the workflow ServiceAccount. This reveals whether the workflow used its identity to read secrets or access other sensitive resources.

## Audit Policy Requirements

A minimal audit policy that captures Argo Workflows activity:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    verbs: ["create", "patch", "update"]
    resources:
      - group: "argoproj.io"
        resources: ["workflows", "cronworkflows", "workflowtemplates"]
```

Metadata level is enough to see the user, verb, resource, and namespace. Request and RequestResponse add the workflow spec in the request body, which reveals the serviceAccountName, container images, and commands defined in the workflow. This is valuable for investigation but generates significantly more log volume.

## Limitations

This detection depends on audit logging being enabled with at least Metadata level coverage for argoproj.io resources. A minimal audit policy that satisfies this requirement:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    verbs: ["create", "patch", "update"]
    resources:
      - group: "argoproj.io"
        resources: ["workflows", "cronworkflows", "workflowtemplates"]
```

The Kubernetes audit log records the Argo controller service account as the creator, not the actual user who authenticated to the Argo API. To identify the original submitter, you must inspect the workflows.argoproj.io/creator label on the Workflow object itself, or enable separate audit logging on the Argo API server. Clusters without audit logging configured produce no audit events and cannot surface this signal.
