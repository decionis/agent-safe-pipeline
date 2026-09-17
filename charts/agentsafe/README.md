# agentsafe

The AgentSafe gateway as a Deployment in front of one upstream Service. It is the same image and
the same runtime as every other distribution; the chart adds a Service, a ServiceAccount with no
token and no bindings, a ConfigMap with the runtime's configuration file, a NetworkPolicy, a
PodDisruptionBudget, an optional HorizontalPodAutoscaler and an optional read-only Role for
on-call. No policy lives here and no credential: the Decionis key is a Secret created out of band,
mounted as a file.

```bash
kubectl create namespace payments
kubectl -n payments create secret generic decionis --from-literal=api-key="$DECIONIS_API_KEY"

helm install agentsafe oci://ghcr.io/decionis/charts/agentsafe --version <chart version> \
  --namespace payments \
  --set decionis.tenantId=<your organization id> \
  --set upstream.service=payments --set upstream.port=8080 \
  --set image.digest=sha256:<the release's image digest>
```

Or with a values file:

```yaml
decionis:
  tenantId: 00000000-0000-4000-8000-000000000000
  apiKeySecretRef:
    name: decionis
    key: api-key

gateway:
  mode: shadow # then enforcement
  failurePolicy: FailClosed
  routes:
    - path: /payments/**
      action: payment.create
      methods: [POST]

upstream:
  service: payments
  port: 8080

image:
  digest: sha256:...
```

The full reference is [`values.yaml`](./values.yaml); every value is commented, and
[`values.schema.json`](./values.schema.json) refuses a value the runtime would refuse. The
[Kubernetes install page](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/install/kubernetes.md)
walks through it; [production](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/deployment/production.md),
[high availability](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/deployment/high-availability.md)
and [security](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/deployment/security.md)
say what the chart establishes and what the cluster still owns.

## What is deployed

| Object                  | Notes                                                                                                                                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Deployment              | `agentsafe run`; non-root 65532, read-only root, no capabilities, seccomp; startup, readiness and liveness probes on `/_agentsafe/*`; rolling update with no unavailable replica; anti-affinity across nodes |
| ConfigMap               | `agentsafe.yaml`, rendered from the values; a change rolls the pods                                                                                                                                          |
| Secret (referenced)     | the Decionis key, mounted at `/var/run/agent-safe/secrets/<key>`, mode `0440`, named by `DECIONIS_API_KEY_FILE`                                                                                              |
| Service                 | ClusterIP with ClientIP affinity, because a held escalation lives in one replica                                                                                                                             |
| ServiceAccount          | no token mounted, no bindings                                                                                                                                                                                |
| NetworkPolicy           | ingress on the listener from `networkPolicy.ingressFrom`; egress to DNS, the upstream, and the authority on 443                                                                                              |
| PodDisruptionBudget     | `minAvailable: 1`                                                                                                                                                                                            |
| HorizontalPodAutoscaler | optional, on CPU                                                                                                                                                                                             |
| Role, RoleBinding       | optional: on-call reads pods and logs, nothing on Secrets or ConfigMaps                                                                                                                                      |

## Verify the chart

The release attaches `agentsafe-<chart version>.tgz` and lists it in `SHA256SUMS`; the OCI
artifact is pushed to `ghcr.io/decionis/charts/agentsafe`. `helm template` with your values, then
`agentsafe config --json` against the rendered file, shows what the runtime will resolve.
