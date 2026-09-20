# Install on Kubernetes

The gateway runs as a Deployment in front of one upstream Service, from the Helm chart in
[`charts/agentsafe`](../../charts/agentsafe). It is the same image the release builds for Docker,
and the same runtime as the executable; the chart deploys it with a Service, a ServiceAccount, a
ConfigMap, a NetworkPolicy, a PodDisruptionBudget and, when asked, an autoscaler and an on-call
Role. The deployment pattern is the gateway: one Deployment per protected Service, in that
Service's namespace, the smallest production-grade shape. The trusted executor's own kit, with two
namespaces and a StatefulSet, stays in [`deploy/`](../../deploy/README.md) for the proposal
ingress.

> Availability: the chart is packaged and pushed to `oci://ghcr.io/decionis/charts/agentsafe` by
> the release workflow from `v0.2.0` on. Before that, install from the checkout:
> `helm install agentsafe ./charts/agentsafe ...`.

## Install

The Decionis key is a Secret you create; the chart references it by name and never holds a value.

```bash
kubectl create namespace payments
kubectl -n payments create secret generic decionis --from-literal=api-key="$DECIONIS_API_KEY"

helm install agentsafe oci://ghcr.io/decionis/charts/agentsafe --version <chart version> \
  --namespace payments \
  --set decionis.tenantId=<your organization id> \
  --set upstream.service=payments --set upstream.port=8080
```

A values file says the same, and is where the routes go:

```yaml
decionis:
  tenantId: 00000000-0000-4000-8000-000000000000
  apiKeySecretRef:
    name: decionis
    key: api-key

gateway:
  mode: shadow
  failurePolicy: FailClosed
  routes:
    - path: /payments/**
      action: payment.create
      methods: [POST]
    - path: /refunds/**
      action: refund.create
      methods: [POST]

upstream:
  service: payments
  port: 8080

image:
  digest: sha256:<the release's image digest>
```

`helm install agentsafe oci://ghcr.io/decionis/charts/agentsafe --version <chart version> -n
payments -f values.yaml`. The chart's [`values.yaml`](../../charts/agentsafe/values.yaml) documents
every value; its schema refuses a mode, a policy or a route the runtime would refuse.

## Point the callers at the gateway

Callers reach `http://agentsafe.payments.svc:8080` instead of the upstream. In shadow nothing
changes for them: every request goes through unchanged and the gateway's log records what
Decionis would have decided. The NetworkPolicy admits ingress from `networkPolicy.ingressFrom`
(every pod in the namespace when empty); tightening it, and denying the callers a direct route to
the upstream, is what makes the gateway a boundary rather than an option. The
[security](../deployment/security.md) page says how.

When the callers cannot be pointed anywhere, the same boundary is held from beside them: the
[transparent interceptor](../gateway/transparent-interception.md) is a kustomize Component
([`deploy/intercept/kubernetes`](../../deploy/intercept/kubernetes)) that redirects a labelled
Deployment's outbound 80 and 443 into an `agentsafe intercept` sidecar, reports every destination
the workload reaches, and governs the ones you name under an authority the workload trusts. It
needs a namespace under the `baseline` Pod Security profile, and it says what that authority costs.

## Watch it

```bash
kubectl -n payments rollout status deployment/agentsafe
kubectl -n payments logs deployment/agentsafe -f
kubectl -n payments port-forward svc/agentsafe 8080:8080
curl -s http://127.0.0.1:8080/_agentsafe/status
```

Readiness is `/_agentsafe/readyz`, liveness `/_agentsafe/healthz`, metrics `/_agentsafe/metrics`
(scrape annotations are on the pods; `metrics.tokenSecretRef` guards the route with a bearer
token). Every event, the chained evidence included, is one JSON line on standard output.

## Send your first governed action

From inside the cluster:

```bash
kubectl -n payments run curl --rm -it --image=curlimages/curl --restart=Never -- \
  curl -i -X POST http://agentsafe:8080/payments -H 'content-type: application/json' -d '{"amount": 500}'
```

In shadow the request reaches the upstream and the log line says `"state":"SHADOW"` with what
Decionis would have decided. `helm upgrade ... --set gateway.mode=enforcement` makes the
decisions binding: an `ALLOW` is forwarded once, an `ESCALATE` is held (`202`), a `BLOCK` is refused
(`403`), and an unreachable authority is `503` with `AUTHORITY_UNAVAILABLE`, never a `BLOCK`.

## Upgrade, roll back, remove

`helm upgrade` rolls the pods with no replica unavailable; a changed configuration rolls them
through the ConfigMap checksum. `helm rollback` returns to the previous values and image.
`helm uninstall` removes everything the chart created and leaves the Secret you created.

## Production

[Production](../deployment/production.md) is the checklist: pin the image by digest, enforcement
with fail-closed, evidence retention, the NetworkPolicy tightened, alerts on
`agentsafe_authority_errors_total`. [High availability](../deployment/high-availability.md) says
what replicas, the budget and the affinity give, and what a held escalation needs.
