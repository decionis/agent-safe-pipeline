import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, it } from "node:test";
import { parseAllDocuments } from "yaml";

const ROOT = new URL("../../deploy/", import.meta.url).pathname;
const KUBERNETES = join(ROOT, "kubernetes");

/** Every YAML file under `deploy/`, path relative to the repository's `deploy/`. */
function manifestFiles(directory = ROOT) {
  const found = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...manifestFiles(path));
    else if (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml")) found.push(path);
  }
  return found.sort();
}

/** Every Kubernetes object in every manifest, with the file it came from. */
function documents() {
  return manifestFiles().flatMap((path) => {
    const text = readFileSync(path, "utf8");
    const parsed = parseAllDocuments(text);
    for (const document of parsed) {
      assert.deepEqual(
        document.errors.map((error) => error.message),
        [],
        `${relative(ROOT, path)} does not parse`,
      );
    }
    return parsed
      .map((document) => document.toJS())
      .filter((value) => value !== null && typeof value === "object")
      .map((value) => ({ file: relative(ROOT, path), object: value }));
  });
}

const all = documents();
const byKind = (kind) => all.filter(({ object }) => object.kind === kind);
const kubernetes = all.filter(
  ({ file }) => file.startsWith("kubernetes/") && !file.startsWith("kubernetes/cilium/"),
);
const text = () => manifestFiles().map((path) => readFileSync(path, "utf8"));

const EXECUTOR_LABELS = { app: "agent-safe-executor" };
const PORT = 8443;

/** Every value in a nested object, for a whole-tree assertion. */
function* values(value) {
  if (Array.isArray(value)) {
    for (const item of value) yield* values(item);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      yield [key, entry];
      yield* values(entry);
    }
  }
}

describe("the deployment kit's manifests", () => {
  it("are all parseable, and there are the files the kit claims", () => {
    const files = manifestFiles().map((path) => relative(ROOT, path));
    assert.deepEqual(files, [
      "alerts/TrustedExecutor.yaml",
      "intercept/docker/compose.yaml",
      "intercept/kubernetes/GovernExample.yaml",
      "intercept/kubernetes/Sidecar.yaml",
      "intercept/kubernetes/kustomization.yaml",
      "kubernetes/AgentZone.yaml",
      "kubernetes/ContainmentProbe.yaml",
      "kubernetes/DefaultDeny.yaml",
      "kubernetes/ExecutorEgress.yaml",
      "kubernetes/Namespaces.yaml",
      "kubernetes/OperatorRbac.yaml",
      "kubernetes/TrustedExecutor.yaml",
      "kubernetes/cilium/FqdnEgress.yaml",
      "kubernetes/kustomization.yaml",
    ]);
    assert.ok(all.length > 12, "every file should hold at least one object");
  });

  it("are listed in the apply order, every one of them", () => {
    // The interceptor's component is applied to a workload of the operator's,
    // never by this kit's order; it is checked on its own below.
    const kustomization = byKind("Kustomization");
    assert.equal(kustomization.length, 1);
    const listed = kustomization[0].object.resources;
    // Everything under `kubernetes/` except the order itself and the Cilium
    // replacement; the alerting rules live outside it and apply to nothing.
    const applicable = manifestFiles()
      .filter((path) => relative(ROOT, path).startsWith("kubernetes/"))
      .map((path) => relative(KUBERNETES, path))
      .filter((path) => path !== "kustomization.yaml" && !path.startsWith("cilium/"));
    assert.deepEqual([...listed].sort(), applicable.sort());
    // The order is the control: namespaces, then the deny, then the rest.
    assert.equal(listed[0], "Namespaces.yaml");
    assert.equal(listed[1], "DefaultDeny.yaml");
  });

  it("never carry a Secret, so nothing here can leak a credential", () => {
    assert.deepEqual(byKind("Secret"), []);
    for (const line of text().join("\n").split("\n")) {
      assert.ok(!/^\s*kind:\s*Secret\s*$/.test(line), `a Secret appears: ${line}`);
    }
  });

  it("reach no real host: every address is a reserved example name", () => {
    for (const body of text()) {
      for (const match of body.matchAll(/https?:\/\/([^/"'\s)]+)/g)) {
        const host = match[1].replace(/:\d+$/, "");
        assert.ok(
          host.endsWith(".example") ||
            host.endsWith(".invalid") ||
            host === "localhost" ||
            host === "127.0.0.1",
          `not a reserved host: ${host}`,
        );
      }
    }
  });

  it("declare both namespaces with Pod Security's restricted profile enforced", () => {
    const namespaces = byKind("Namespace");
    assert.deepEqual(namespaces.map(({ object }) => object.metadata.name).sort(), [
      "agent-safe-agents",
      "agent-safe-executor",
    ]);
    for (const { object } of namespaces) {
      const labels = object.metadata.labels;
      for (const mode of ["enforce", "audit", "warn"]) {
        assert.equal(
          labels[`pod-security.kubernetes.io/${mode}`],
          "restricted",
          `${object.metadata.name} must ${mode} restricted`,
        );
      }
      assert.ok(labels["agent-safe-zone"], `${object.metadata.name} must name its zone`);
    }
  });

  it("deny everything in both namespaces before anything grants a path", () => {
    const deny = byKind("NetworkPolicy").filter(
      ({ object }) => object.metadata.name === "default-deny",
    );
    assert.equal(deny.length, 2);
    for (const { object } of deny) {
      assert.deepEqual(object.spec.podSelector, {}, "a default deny selects every pod");
      assert.deepEqual([...object.spec.policyTypes].sort(), ["Egress", "Ingress"]);
      assert.deepEqual(object.spec.ingress, []);
      assert.deepEqual(object.spec.egress, []);
    }
    assert.deepEqual(deny.map(({ object }) => object.metadata.namespace).sort(), [
      "agent-safe-agents",
      "agent-safe-executor",
    ]);
  });

  it("say what every other policy governs, and bound every path it opens", () => {
    for (const { file, object } of byKind("NetworkPolicy")) {
      assert.ok(Array.isArray(object.spec.policyTypes), `${file}: policyTypes must be explicit`);
      assert.ok(object.spec.policyTypes.length > 0, `${file}: policyTypes must not be empty`);
      for (const rule of [...(object.spec.egress ?? []), ...(object.spec.ingress ?? [])]) {
        if (Object.keys(rule).length === 0) continue;
        assert.ok(Array.isArray(rule.ports), `${file}: every rule names its ports`);
        assert.ok(rule.ports.length > 0, `${file}: a rule with no port is a rule with every port`);
      }
    }
  });

  it("open nothing to the whole internet", () => {
    for (const [key, value] of values(all.map(({ object }) => object))) {
      if (key !== "cidr") continue;
      assert.notEqual(value, "0.0.0.0/0");
      assert.notEqual(value, "::/0");
      assert.ok(!/\/0$/.test(String(value)), `a zero-length prefix is every address: ${value}`);
    }
  });

  it("give the agent zone no route off the cluster, and only the listener on it", () => {
    const zone = byKind("NetworkPolicy").find(
      ({ object }) =>
        object.metadata.namespace === "agent-safe-agents" &&
        object.metadata.name !== "default-deny",
    );
    assert.ok(zone, "the agent zone needs an egress policy");
    assert.deepEqual(zone.object.spec.policyTypes, ["Egress"]);
    // An ipBlock is a path off the cluster; the agent zone must have none.
    for (const [key] of values(zone.object)) {
      assert.notEqual(key, "ipBlock", "the agent zone must name no CIDR at all");
    }
    const destinations = zone.object.spec.egress.flatMap((rule) =>
      rule.ports.map((port) => port.port),
    );
    assert.deepEqual([...new Set(destinations)].sort(), [53, PORT]);
  });

  it("keep the containment probe inside the caller policy and empty of credentials", () => {
    const probe = byKind("CronJob").find(
      ({ object }) => object.metadata.name === "agent-safe-containment-probe",
    );
    assert.ok(probe, "the kit needs the containment probe");
    assert.equal(probe.object.metadata.namespace, "agent-safe-agents");
    const template = probe.object.spec.jobTemplate.spec.template;
    // The probe proves something about the callers only while the agent-zone
    // policy selects it too. Relabelled, it measures its own network.
    assert.equal(
      template.metadata.labels["agent-safe-caller"],
      "true",
      "the probe must sit in the caller policy's scope",
    );
    const [container] = template.spec.containers;
    // A probe that authenticated would have to hold the credential whose
    // absence it is checking, so it mounts nothing and reads no environment.
    assert.equal(template.spec.volumes, undefined, "the probe mounts nothing");
    assert.equal(container.volumeMounts, undefined, "the probe mounts nothing");
    assert.equal(container.env, undefined, "the probe reads no environment");
    assert.equal(container.envFrom, undefined, "the probe reads no environment");
    assert.equal(template.spec.automountServiceAccountToken, false);
    assert.equal(container.args[0], "probe-containment");
    for (const target of container.args.slice(1)) {
      const host = target.slice(target.indexOf("=") + 1).split(":")[0];
      assert.ok(host.endsWith(".example"), `${host} must be a .example host`);
    }
    // Exiting non-zero on a reachable target is the whole signal; a retry
    // would turn one finding into several.
    assert.equal(probe.object.spec.jobTemplate.spec.backoffLimit, 0);
    assert.equal(probe.object.spec.concurrencyPolicy, "Forbid");
  });

  it("let only a labelled caller in the agent zone reach the executor", () => {
    const policy = byKind("NetworkPolicy").find(
      ({ object }) =>
        object.metadata.namespace === "agent-safe-executor" &&
        object.metadata.name !== "default-deny",
    );
    assert.ok(policy, "the executor needs its own policy");
    const ingress = policy.object.spec.ingress;
    assert.equal(ingress.length, 1, "one way in");
    assert.deepEqual(ingress[0].from[0].namespaceSelector.matchLabels, {
      "agent-safe-zone": "agents",
    });
    assert.deepEqual(ingress[0].from[0].podSelector.matchLabels, { "agent-safe-caller": "true" });
    assert.deepEqual(
      ingress[0].ports.map((port) => port.port),
      [PORT],
    );
    // The executor never reaches back into the zone that calls it.
    const egress = JSON.stringify(policy.object.spec.egress);
    assert.ok(!egress.includes("agent-safe-agents"), "the executor must not egress to the agents");
    assert.ok(!egress.includes("agent-safe-caller"), "the executor must not egress to a caller");
  });

  it("agree on one port across the configuration, the container, the service and the probes", () => {
    const config = byKind("ConfigMap").find(
      ({ object }) => object.metadata.name === "agent-safe-executor-config",
    );
    assert.equal(config.object.data.PORT, String(PORT));
    const set = byKind("StatefulSet")[0].object;
    const container = set.spec.template.spec.containers[0];
    assert.deepEqual(
      container.ports.map((port) => port.containerPort),
      [PORT],
    );
    for (const probe of [container.readinessProbe, container.livenessProbe]) {
      assert.equal(probe.httpGet.port, PORT);
      assert.equal(probe.httpGet.scheme, "HTTPS", "the listener is TLS, so a probe speaks TLS");
    }
    const service = byKind("Service").find(
      ({ object }) => object.metadata.name === "agent-safe-executor",
    ).object;
    assert.deepEqual(
      service.spec.ports.map((port) => [port.port, port.targetPort]),
      [[PORT, PORT]],
    );
    assert.deepEqual(service.spec.selector, EXECUTOR_LABELS);
  });

  it("run the executor as the hardened shape its posture check requires", () => {
    const set = byKind("StatefulSet")[0].object;
    const pod = set.spec.template.spec;
    assert.equal(set.spec.replicas, 2, "a rolling restart must leave one replica taking work");
    assert.equal(pod.serviceAccountName, "agent-safe-executor");
    assert.equal(pod.automountServiceAccountToken, false);
    assert.equal(pod.terminationGracePeriodSeconds, 20);
    for (const key of ["hostNetwork", "hostPID", "hostIPC"]) {
      assert.notEqual(pod[key], true, `${key} must not be set`);
    }
    assert.equal(pod.securityContext.runAsNonRoot, true);
    assert.equal(pod.securityContext.runAsUser, 65532);
    assert.equal(pod.securityContext.runAsGroup, 65532);
    assert.equal(pod.securityContext.fsGroup, 65532);
    assert.equal(pod.securityContext.seccompProfile.type, "RuntimeDefault");
    const container = pod.containers[0];
    assert.equal(container.securityContext.allowPrivilegeEscalation, false);
    assert.equal(container.securityContext.readOnlyRootFilesystem, true);
    assert.equal(container.securityContext.runAsNonRoot, true);
    assert.deepEqual(container.securityContext.capabilities.drop, ["ALL"]);
    assert.equal(container.securityContext.seccompProfile.type, "RuntimeDefault");
    assert.ok(container.resources.limits.cpu, "a limit on cpu");
    assert.ok(container.resources.limits.memory, "a limit on memory");
    assert.ok(container.resources.requests.cpu && container.resources.requests.memory);
  });

  it("mount every credential read-only, at 0440, with no subPath", () => {
    const pod = byKind("StatefulSet")[0].object.spec.template.spec;
    const container = pod.containers[0];
    for (const volume of pod.volumes) {
      if (volume.secret === undefined && volume.configMap === undefined) continue;
      const source = volume.secret ?? volume.configMap;
      // 288 decimal is 0440: a YAML 1.2 reader takes `0440` as four hundred
      // and forty, so the mode is written as the number it means.
      assert.equal(source.defaultMode, 288, `${volume.name} must be mounted 0440`);
    }
    for (const mount of container.volumeMounts) {
      assert.equal(mount.subPath, undefined, `${mount.name}: a subPath does not follow a rotation`);
      if (mount.mountPath.startsWith("/var/run/agent-safe")) {
        assert.equal(mount.readOnly, true, `${mount.name} must be read-only`);
      }
    }
    // The journal is the one writable mount, and it is a per-replica claim.
    const claims = byKind("StatefulSet")[0].object.spec.volumeClaimTemplates;
    assert.equal(claims.length, 1);
    assert.deepEqual(claims[0].spec.accessModes, ["ReadWriteOnce"]);
    assert.equal(claims[0].metadata.name, "journal");
  });

  it("keep every secret file inside the directory the posture check verifies", () => {
    const data = byKind("ConfigMap").find(
      ({ object }) => object.metadata.name === "agent-safe-executor-config",
    ).object.data;
    for (const [key, value] of Object.entries(data)) {
      if (!key.endsWith("_FILE")) continue;
      assert.ok(
        String(value).startsWith("/var/run/agent-safe/") ||
          String(value).startsWith("/var/lib/agent-safe/"),
        `${key} must live under a mounted directory: ${value}`,
      );
    }
    assert.equal(data.EXECUTOR_SECRETS_DIR, "/var/run/agent-safe");
  });

  it("set no flag that only a developer's machine may have", () => {
    const data = byKind("ConfigMap").find(
      ({ object }) => object.metadata.name === "agent-safe-executor-config",
    ).object.data;
    for (const key of [
      "EXECUTOR_ALLOW_PLAINTEXT_LISTENER",
      "DECIONIS_ALLOW_INSECURE_LOOPBACK",
      "EXECUTOR_ALLOW_LEGACY_CALLER",
      "EXECUTOR_CALLER_TOKEN",
      "EXECUTOR_CALLER_TOKEN_FILE",
    ]) {
      assert.equal(data[key], undefined, `${key} must not be set in a deployment`);
    }
    assert.notEqual(data.EXECUTOR_POSTURE, "DEVELOPMENT");
    // The journal is required, which is the default; saying so is a claim the
    // manifest should not be able to walk back.
    assert.notEqual(data.EXECUTOR_JOURNAL_REQUIRED, "false");
  });

  it("resolve every service account a pod names", () => {
    const declared = new Set(
      byKind("ServiceAccount").map(
        ({ object }) => `${object.metadata.namespace}/${object.metadata.name}`,
      ),
    );
    for (const kind of ["StatefulSet", "Deployment", "DaemonSet", "Job"]) {
      for (const { file, object } of byKind(kind)) {
        const pod = object.spec.template.spec;
        if (pod.serviceAccountName === undefined) continue;
        assert.ok(
          declared.has(`${object.metadata.namespace}/${pod.serviceAccountName}`),
          `${file}: ${pod.serviceAccountName} is named but not declared`,
        );
      }
    }
  });

  it("keep an operator away from secrets and from the configuration", () => {
    const role = byKind("Role").find(
      ({ object }) => object.metadata.name === "agent-safe-executor-operator",
    ).object;
    for (const rule of role.rules) {
      assert.ok(!rule.resources.includes("secrets"), "an operator gets no verb on a Secret");
      if (!rule.resources.includes("configmaps")) continue;
      const writes = rule.verbs.filter((verb) => verb !== "create");
      if (writes.length === 0) continue;
      // Any verb beyond `create` has to be pinned to the halt flag by name.
      assert.deepEqual(rule.resourceNames, ["agent-safe-executor-halt"]);
    }
    const binding = byKind("RoleBinding")[0].object;
    assert.equal(binding.roleRef.name, role.metadata.name);
    assert.match(binding.subjects[0].name, /PLACEHOLDER/, "a real group belongs to the adopter");
  });

  it("keep the Cilium file to Cilium policies alone", () => {
    const cilium = all.filter(({ file }) => file.startsWith("kubernetes/cilium/"));
    assert.ok(cilium.length > 0);
    for (const { object } of cilium) {
      assert.equal(object.kind, "CiliumNetworkPolicy");
      assert.equal(object.apiVersion, "cilium.io/v2");
    }
    // It replaces the CIDR rules rather than joining them, so it must not be
    // in the apply order; the assertion above covers that from the other side.
    const listed = byKind("Kustomization")[0].object.resources.join(" ");
    assert.ok(!listed.includes("cilium"));
  });

  it("place every object in one of the kit's two namespaces", () => {
    for (const { file, object } of kubernetes) {
      if (["Namespace", "Kustomization"].includes(object.kind)) continue;
      assert.ok(
        ["agent-safe-agents", "agent-safe-executor"].includes(object.metadata.namespace),
        `${file}: ${object.kind}/${object.metadata.name} is in ${object.metadata.namespace}`,
      );
    }
  });

  it("alert on signals the executor's own registry declares, and on nothing invented", () => {
    const source = readFileSync(
      new URL("../../packages/agentsafe/src/incident/Metrics.ts", import.meta.url).pathname,
      "utf8",
    );
    const declared = new Set(
      [...source.matchAll(/registry\.(?:counter|gauge)\(\s*"([a-z_]+)"/g)].map((match) => match[1]),
    );
    assert.ok(declared.size > 10, "the registry should declare its families here");
    const rules = byKind("PrometheusRule");
    assert.equal(rules.length, 1, "one alerting file");
    const expressions = rules[0].object.spec.groups.flatMap((group) =>
      group.rules.map((rule) => rule.expr),
    );
    assert.ok(expressions.length > 8, "the file should carry the signals worth paging on");
    for (const expression of expressions) {
      // A counter is exposed with `_total`; a gauge is exposed as it is named.
      for (const metric of expression.match(/agentsafe_[a-z_]+/g) ?? []) {
        const base = metric.endsWith("_total") ? metric.slice(0, -"_total".length) : metric;
        assert.ok(
          declared.has(base) || declared.has(metric),
          `alerts on a metric the registry does not declare: ${metric}`,
        );
      }
    }
  });

  it("say what every alert is and how severe, and are applied by nothing", () => {
    const rules = byKind("PrometheusRule")[0].object;
    assert.equal(rules.metadata.namespace, "agent-safe-executor");
    for (const group of rules.spec.groups) {
      for (const rule of group.rules) {
        assert.ok(rule.alert, "every rule names itself");
        assert.ok(
          ["critical", "warning", "info"].includes(rule.labels?.severity),
          `${rule.alert}: a severity a rota can act on`,
        );
        assert.ok(rule.annotations?.summary, `${rule.alert}: a summary in words`);
      }
    }
    // Applied by nothing: it has never run against a live Prometheus, so it
    // must not be in the order `kubectl apply -k` walks.
    const listed = byKind("Kustomization")[0].object.resources.join(" ");
    assert.ok(!listed.includes("alerts"));
  });

  it("keep one replica available while a disruption runs", () => {
    const budget = byKind("PodDisruptionBudget")[0].object;
    assert.equal(budget.spec.minAvailable, 1);
    assert.deepEqual(budget.spec.selector.matchLabels, EXECUTOR_LABELS);
  });
});
