import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { parseAllDocuments, parse } from "yaml";

const root = fileURLToPath(new URL("../../", import.meta.url));
const chart = `${root}charts/agentsafe`;
const helm = spawnSync("helm", ["version", "--short"], { encoding: "utf8" });
const available = helm.status === 0;
const TENANT_ID = "00000000-0000-4000-8000-000000000001";

function render(sets, extra = []) {
  const args = ["template", "agentsafe", chart, "--namespace", "payments", ...extra];
  for (const [key, value] of Object.entries(sets)) args.push("--set", `${key}=${value}`);
  const result = spawnSync("helm", args, { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return parseAllDocuments(result.stdout)
    .map((document) => document.toJS())
    .filter((object) => object !== null && typeof object === "object");
}

const byKind = (objects, kind) => objects.filter((object) => object.kind === kind);
const configOf = (objects) => parse(byKind(objects, "ConfigMap")[0].data["agentsafe.yaml"]);

/**
 * The chart is one more wrapper around the same runtime. These gates hold it
 * to that: the configuration it renders is one the runtime's own loader
 * accepts in production, the key is a mounted file and never a value, the
 * pod is hardened the way the image expects, and every object the values
 * promise is there.
 */
describe("the Helm chart", { skip: available ? false : "helm is not installed" }, () => {
  const base = { "decionis.tenantId": TENANT_ID, "upstream.service": "payments" };

  it("lints, and refuses to render without the organization id", () => {
    const lint = spawnSync(
      "helm",
      [
        "lint",
        chart,
        "--set",
        `decionis.tenantId=${TENANT_ID}`,
        "--set",
        "upstream.service=payments",
      ],
      { encoding: "utf8" },
    );
    assert.equal(lint.status, 0, lint.stderr + lint.stdout);
    const missing = spawnSync(
      "helm",
      ["template", "agentsafe", chart, "--set", "upstream.service=payments"],
      { encoding: "utf8" },
    );
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /decionis\.tenantId is required/);
  });

  it("renders a configuration the runtime's loader accepts in production, with no secret in it", async () => {
    const { GatewayConfigLoader } = await import(
      `${root}packages/agentsafe/dist/gateway/GatewayConfig.js`
    );
    const objects = render({
      ...base,
      "gateway.routes[0].path": "/payments/**",
      "gateway.routes[0].action": "payment.create",
      "gateway.routes[0].methods": "{POST}",
      "gateway.mode": "enforcement",
      "gateway.failurePolicy": "FailOpen",
      "presence.managed": "true",
      "presence.approverId": "synthetic-cro",
      "presence.approverRole": "CRO",
    });
    const file = configOf(objects);
    const config = GatewayConfigLoader.load({
      env: { NODE_ENV: "production", DECIONIS_API_KEY_FILE: "/var/run/agent-safe/secrets/api-key" },
      file,
      version: "0.0.0",
    });
    assert.equal(config.upstream.url, "http://payments.payments.svc:8080");
    assert.equal(config.upstream.insecure, true);
    assert.deepEqual(config.listen, { host: "0.0.0.0", port: 8080 });
    assert.equal(config.authority.kind, "DECIONIS");
    assert.equal(config.authority.mode, "ENFORCEMENT");
    assert.equal(config.authority.failurePolicy, "FAIL_OPEN");
    assert.equal(config.authority.tenantId, TENANT_ID);
    assert.deepEqual(config.interception.routes, [
      { path: "/payments/**", action: "payment.create", methods: ["POST"] },
    ]);
    assert.equal(config.interception.maxBodyBytes, 1048576);
    assert.equal(config.escalation.mode, "MANAGED");
    assert.equal(config.output.format, "JSON");
    const text = JSON.stringify(byKind(objects, "ConfigMap"));
    assert.doesNotMatch(text, /api-key|DECIONIS_API_KEY/);
    const shadow = GatewayConfigLoader.load({
      env: { NODE_ENV: "production", DECIONIS_API_KEY_FILE: "/k" },
      file: configOf(render(base)),
      version: "0",
    });
    assert.equal(shadow.authority.mode, "SHADOW");
    assert.equal(shadow.authority.failurePolicy, "FAIL_CLOSED");
    assert.deepEqual(shadow.interception.routes, []);
    const external = GatewayConfigLoader.load({
      env: { NODE_ENV: "production", DECIONIS_API_KEY_FILE: "/k" },
      file: configOf(
        render({ "decionis.tenantId": TENANT_ID, "upstream.url": "https://payments.example" }),
      ),
      version: "0",
    });
    assert.equal(external.upstream.url, "https://payments.example");
    assert.equal(external.upstream.insecure, false);
  });

  it("mounts the key as a file, hardens the pod, probes the gateway's own routes, and names the command", () => {
    const objects = render(base);
    const deployment = byKind(objects, "Deployment")[0];
    const pod = deployment.spec.template.spec;
    const container = pod.containers[0];
    assert.deepEqual(container.args, ["run"]);
    assert.equal(container.image, "ghcr.io/decionis/agentsafe:0.2.4");
    const env = Object.fromEntries(
      container.env.map((entry) => [entry.name, entry.value ?? entry.valueFrom]),
    );
    assert.equal(env.DECIONIS_API_KEY_FILE, "/var/run/agent-safe/secrets/api-key");
    assert.equal(env.AGENTSAFE_CONFIG, "/etc/agentsafe/agentsafe.yaml");
    assert.equal(env.AGENTSAFE_LOG_FORMAT, "json");
    assert.equal(env.AGENTSAFE_SURFACE, "kubernetes");
    assert.ok(!("DECIONIS_API_KEY" in env));
    const secret = pod.volumes.find((volume) => volume.name === "secrets").secret;
    assert.equal(secret.secretName, "decionis");
    assert.equal(secret.defaultMode, 0o440);
    assert.deepEqual(secret.items, [{ key: "api-key", path: "api-key" }]);
    assert.equal(pod.automountServiceAccountToken, false);
    assert.deepEqual(pod.securityContext, {
      runAsNonRoot: true,
      runAsUser: 65532,
      runAsGroup: 65532,
      fsGroup: 65532,
      seccompProfile: { type: "RuntimeDefault" },
    });
    assert.deepEqual(container.securityContext, {
      allowPrivilegeEscalation: false,
      readOnlyRootFilesystem: true,
      capabilities: { drop: ["ALL"] },
    });
    assert.equal(container.readinessProbe.httpGet.path, "/_agentsafe/readyz");
    assert.equal(container.livenessProbe.httpGet.path, "/_agentsafe/healthz");
    assert.equal(container.startupProbe.httpGet.path, "/_agentsafe/healthz");
    assert.equal(pod.terminationGracePeriodSeconds, 20);
    assert.ok(container.resources.requests.cpu);
    assert.ok(container.resources.limits.memory);
    assert.ok(deployment.spec.template.metadata.annotations["checksum/config"]);
    assert.equal(
      deployment.spec.template.metadata.annotations["prometheus.io/path"],
      "/_agentsafe/metrics",
    );
    assert.equal(deployment.spec.replicas, 2);
    assert.ok(pod.affinity.podAntiAffinity);
    const pinned = byKind(
      render({ ...base, "image.digest": `sha256:${"a".repeat(64)}` }),
      "Deployment",
    )[0];
    assert.equal(
      pinned.spec.template.spec.containers[0].image,
      `ghcr.io/decionis/agentsafe@sha256:${"a".repeat(64)}`,
    );
  });

  it("renders the objects the values promise, and only those", () => {
    const kinds = (objects) => objects.map((object) => object.kind).sort();
    assert.deepEqual(kinds(render(base)), [
      "ConfigMap",
      "Deployment",
      "NetworkPolicy",
      "PodDisruptionBudget",
      "Service",
      "ServiceAccount",
    ]);
    const everything = render({
      ...base,
      "rbac.create": "true",
      "autoscaling.enabled": "true",
      "metrics.tokenSecretRef.name": "metrics",
      "metrics.tokenSecretRef.key": "token",
    });
    assert.deepEqual(kinds(everything), [
      "ConfigMap",
      "Deployment",
      "HorizontalPodAutoscaler",
      "NetworkPolicy",
      "PodDisruptionBudget",
      "Role",
      "RoleBinding",
      "Service",
      "ServiceAccount",
    ]);
    const autoscaled = byKind(everything, "Deployment")[0];
    assert.equal(autoscaled.spec.replicas, undefined);
    const role = byKind(everything, "Role")[0];
    assert.ok(
      role.rules.every((rule) =>
        rule.verbs.every((verb) => ["get", "list", "watch"].includes(verb)),
      ),
    );
    assert.ok(
      role.rules.every(
        (rule) => !rule.resources.includes("secrets") && !rule.resources.includes("configmaps"),
      ),
    );
    const token = byKind(everything, "Deployment")[0].spec.template.spec.containers[0].env.find(
      (entry) => entry.name === "AGENTSAFE_METRICS_TOKEN",
    );
    assert.deepEqual(token.valueFrom, { secretKeyRef: { name: "metrics", key: "token" } });
    const minimal = render({
      ...base,
      "networkPolicy.enabled": "false",
      "podDisruptionBudget.enabled": "false",
      "serviceAccount.create": "false",
    });
    assert.deepEqual(kinds(minimal), ["ConfigMap", "Deployment", "Service"]);
    const policy = byKind(
      render({ ...base, "networkPolicy.authorityCidrs": "{203.0.113.0/24}" }),
      "NetworkPolicy",
    )[0];
    assert.deepEqual(policy.spec.policyTypes, ["Ingress", "Egress"]);
    assert.ok(
      policy.spec.egress.some((rule) =>
        rule.to?.some((to) => to.ipBlock?.cidr === "203.0.113.0/24"),
      ),
    );
    assert.ok(policy.spec.egress.every((rule) => rule.ports.length > 0));
    const service = byKind(render(base), "Service")[0];
    assert.equal(service.spec.sessionAffinity, "ClientIP");
  });
});
