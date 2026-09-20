import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { parse } from "yaml";

const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

/**
 * Transparent interception is three pieces that must agree: the redirect the
 * init container writes, the interceptor the redirect points at, and the two
 * deployment shapes (a Kubernetes sidecar, a Docker namespace) that put them
 * beside a workload. These gates hold the pieces to each other: the same
 * ports, the same user id, the same version, the same hardening the rest of
 * the kit promises, and a redirect that refuses anything it does not
 * understand before it touches a rule.
 */
describe("the redirect", () => {
  it("is POSIX sh and refuses a setting that is not what it says before touching a rule", async () => {
    const script = await read("packaging/intercept/Redirect.sh");
    assert.equal(spawnSync("sh", ["-n", "-"], { input: script, encoding: "utf8" }).status, 0);
    // An empty search path: `command -v iptables` finds nothing, so a valid
    // configuration stops exactly where the tool would be needed.
    const run = (env) =>
      spawnSync("/bin/sh", ["-"], {
        input: script,
        encoding: "utf8",
        env: { PATH: "/nonexistent", ...env },
      });
    for (const [env, message] of [
      [{ AGENTSAFE_INTERCEPT_UID: "root" }, "AGENTSAFE_INTERCEPT_UID must be a user id"],
      [{ AGENTSAFE_INTERCEPT_HTTP_PORT: "0" }, "AGENTSAFE_INTERCEPT_HTTP_PORT must be a port"],
      [
        { AGENTSAFE_INTERCEPT_HTTPS_PORT: "65536" },
        "AGENTSAFE_INTERCEPT_HTTPS_PORT must be a port",
      ],
      [{ AGENTSAFE_INTERCEPT_HTTP_FROM: "http" }, "AGENTSAFE_INTERCEPT_HTTP_FROM must be a port"],
      [{ AGENTSAFE_INTERCEPT_HTTPS_FROM: "4a3" }, "AGENTSAFE_INTERCEPT_HTTPS_FROM must be a port"],
      [{ AGENTSAFE_INTERCEPT_HTTPS_PORT: "15001" }, "the two listener ports must differ"],
      [{ AGENTSAFE_INTERCEPT_IPV6: "yes" }, "AGENTSAFE_INTERCEPT_IPV6 must be auto, on or off"],
      [
        { AGENTSAFE_INTERCEPT_EXCLUDE_CIDRS: "10.0.0.0/8, 10.1.0.0/16" },
        "AGENTSAFE_INTERCEPT_EXCLUDE_CIDRS holds something that is not an address or a range",
      ],
      [
        { AGENTSAFE_INTERCEPT_EXCLUDE_CIDRS: "10.0.0.0/8;reboot" },
        "AGENTSAFE_INTERCEPT_EXCLUDE_CIDRS holds something that is not an address or a range",
      ],
      // Every setting valid, and no iptables on the path: the refusal names the tool.
      [{}, "iptables is not installed"],
    ]) {
      const result = run(env);
      assert.equal(result.status, 1, JSON.stringify(env));
      assert.match(
        result.stderr,
        new RegExp(`^agentsafe-redirect: ${message.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
      );
    }
    // The rules themselves: a chain of our own for the decision, one for the
    // redirect, one jump from OUTPUT checked before it is added, the
    // interceptor's user and loopback left alone, and IPv6 refused rather than
    // let by.
    for (const rule of [
      'iptables -t nat -A AGENTSAFE_REDIRECT -p tcp --dport "$http_from" -j REDIRECT --to-ports "$http_port"',
      'iptables -t nat -A AGENTSAFE_REDIRECT -p tcp --dport "$https_from" -j REDIRECT --to-ports "$https_port"',
      'iptables -t nat -A AGENTSAFE_OUTPUT -m owner --uid-owner "$uid" -j RETURN',
      "iptables -t nat -A AGENTSAFE_OUTPUT -o lo -j RETURN",
      "iptables -t nat -A AGENTSAFE_OUTPUT -j AGENTSAFE_REDIRECT",
      "iptables -t nat -C OUTPUT -p tcp -j AGENTSAFE_OUTPUT 2>/dev/null \\\n  || iptables -t nat -A OUTPUT -p tcp -j AGENTSAFE_OUTPUT",
      'ip6tables -A AGENTSAFE_OUTPUT6 -p tcp --dport "$https_from" -j REJECT --reject-with tcp-reset',
    ]) {
      assert.ok(script.includes(rule), rule);
    }
    assert.doesNotMatch(
      script,
      /--to-ports \$\{?http_port\}?[^"]/,
      "ports are quoted where they are used",
    );
    assert.doesNotMatch(script, /eval/);
    assert.match(script, /^set -eu$/m);
  });
});

describe("the interception images", () => {
  it("come from the one Dockerfile, the init stage pinned by digest and the runtime still the default", async () => {
    const dockerfile = await read("packages/agentsafe/Dockerfile");
    assert.match(
      dockerfile,
      /^ARG INIT_BASE_IMAGE=public\.ecr\.aws\/docker\/library\/alpine:3\.\d+@sha256:[0-9a-f]{64}$/m,
    );
    assert.match(dockerfile, /^FROM \$\{INIT_BASE_IMAGE\} AS init$/m);
    assert.match(dockerfile, /^RUN apk add --no-cache iptables ip6tables$/m);
    assert.match(
      dockerfile,
      /^COPY packaging\/intercept\/Redirect\.sh \/usr\/local\/bin\/agentsafe-redirect$/m,
    );
    assert.match(dockerfile, /^ENTRYPOINT \["\/usr\/local\/bin\/agentsafe-redirect"\]$/m);
    const stages = [...dockerfile.matchAll(/^FROM .* AS (\w+)$/gm)].map((match) => match[1]);
    assert.deepEqual(stages, ["base", "builder", "init", "runner"]);
  });
});

describe("the sidecar shapes", () => {
  it("put the same interceptor, at the runtime's version, beside a workload in Kubernetes", async () => {
    const version = JSON.parse(await read("packages/agentsafe/package.json")).version;
    const component = parse(await read("deploy/intercept/kubernetes/kustomization.yaml"));
    assert.equal(component.kind, "Component");
    assert.deepEqual(component.patches, [
      {
        path: "Sidecar.yaml",
        target: { kind: "Deployment", labelSelector: "agent-safe-intercept=true" },
      },
    ]);
    const patch = parse(await read("deploy/intercept/kubernetes/Sidecar.yaml"));
    const pod = patch.spec.template.spec;
    const [init] = pod.initContainers;
    const [sidecar] = pod.containers;
    assert.equal(init.name, "agentsafe-redirect");
    assert.equal(init.image, `ghcr.io/decionis/agentsafe:${version}-init`);
    assert.equal(sidecar.name, "agentsafe-intercept");
    assert.equal(sidecar.image, `ghcr.io/decionis/agentsafe:${version}`);
    assert.deepEqual(sidecar.args, ["intercept"]);
    const env = (container) =>
      Object.fromEntries(container.env.map(({ name, value }) => [name, value]));
    const initEnv = env(init);
    const sidecarEnv = env(sidecar);
    // The redirect leaves the interceptor's own user alone, and sends the
    // ports to where the interceptor listens.
    assert.equal(initEnv.AGENTSAFE_INTERCEPT_UID, String(sidecar.securityContext.runAsUser));
    assert.equal(sidecar.securityContext.runAsUser, 65532);
    assert.equal(initEnv.AGENTSAFE_INTERCEPT_HTTP_PORT, sidecarEnv.AGENTSAFE_INTERCEPT_HTTP_PORT);
    assert.equal(initEnv.AGENTSAFE_INTERCEPT_HTTPS_PORT, sidecarEnv.AGENTSAFE_INTERCEPT_HTTPS_PORT);
    assert.equal(sidecarEnv.AGENTSAFE_SURFACE, "kubernetes");
    assert.equal(sidecarEnv.AGENTSAFE_LOG_FORMAT, "json");
    // The init has the two capabilities iptables needs and nothing else; the
    // interceptor has none, and both are otherwise held as the kit holds
    // every container.
    assert.deepEqual(init.securityContext.capabilities, {
      drop: ["ALL"],
      add: ["NET_ADMIN", "NET_RAW"],
    });
    assert.deepEqual(sidecar.securityContext.capabilities, { drop: ["ALL"] });
    for (const container of [init, sidecar]) {
      assert.equal(container.securityContext.allowPrivilegeEscalation, false);
      assert.equal(container.securityContext.readOnlyRootFilesystem, true);
      assert.equal(container.securityContext.privileged, false);
      assert.deepEqual(container.securityContext.seccompProfile, { type: "RuntimeDefault" });
      assert.ok(container.resources.limits.memory, container.name);
    }
    assert.equal(sidecar.securityContext.runAsNonRoot, true);
    assert.equal(init.securityContext.runAsUser, 0);
  });

  it("put the same three containers in one namespace in Docker, the workload joining last", async () => {
    const compose = parse(await read("deploy/intercept/docker/compose.yaml"));
    const {
      "agentsafe-intercept": intercept,
      "agentsafe-redirect": redirect,
      agent,
    } = compose.services;
    assert.match(
      intercept.image,
      /^ghcr\.io\/decionis\/agentsafe:\$\{AGENTSAFE_VERSION:\?[^}]+\}$/,
    );
    assert.match(
      redirect.image,
      /^ghcr\.io\/decionis\/agentsafe:\$\{AGENTSAFE_VERSION:\?[^}]+\}-init$/,
    );
    assert.deepEqual(intercept.command, ["intercept"]);
    assert.equal(intercept.user, "65532:65532");
    assert.deepEqual(intercept.cap_drop, ["ALL"]);
    assert.equal(intercept.read_only, true);
    assert.equal(redirect.network_mode, "service:agentsafe-intercept");
    assert.equal(agent.network_mode, "service:agentsafe-intercept");
    assert.deepEqual(redirect.cap_add, ["NET_ADMIN", "NET_RAW"]);
    assert.equal(redirect.environment.AGENTSAFE_INTERCEPT_UID, "65532");
    assert.equal(redirect.restart, "no");
    assert.deepEqual(agent.depends_on, {
      "agentsafe-redirect": { condition: "service_completed_successfully" },
    });
    assert.match(agent.image, /^\$\{AGENT_IMAGE:\?/);
    assert.doesNotMatch(await read("deploy/intercept/docker/compose.yaml"), /privileged/);
  });

  it("govern the listed hosts from the same sidecar, the authority in the sidecar and its certificate in the workload", async () => {
    const sidecar = parse(await read("deploy/intercept/kubernetes/Sidecar.yaml"));
    const example = parse(await read("deploy/intercept/kubernetes/GovernExample.yaml"));
    const pod = example.spec.template.spec;
    const env = (container) =>
      Object.fromEntries(container.env.map(({ name, value }) => [name, value]));
    const interceptName = sidecar.spec.template.spec.containers[0].name;
    const intercept = pod.containers.find((container) => container.name === interceptName);
    const agent = pod.containers.find((container) => container.name === "agent");
    assert.ok(intercept, "the example patches the container the component adds, by its name");
    assert.ok(agent);
    // The example adds nothing the component already decided: no image, no
    // args, no security context, so the merge cannot loosen either.
    for (const container of pod.containers) {
      assert.equal(container.image, undefined, container.name);
      assert.equal(container.securityContext, undefined, container.name);
      assert.equal(container.args, undefined, container.name);
    }
    const interceptEnv = env(intercept);
    const mounts = (container) =>
      Object.fromEntries(container.volumeMounts.map(({ name, mountPath }) => [name, mountPath]));
    const volumes = Object.fromEntries(pod.volumes.map((volume) => [volume.name, volume]));
    // The authority's key reaches the sidecar as a Secret, read-only, owner
    // and group only; its certificate reaches the workload as a ConfigMap.
    const caMount = mounts(intercept)["agentsafe-intercept-ca"];
    assert.equal(interceptEnv.AGENTSAFE_INTERCEPT_CA_CERT_FILE, `${caMount}/ca.crt`);
    assert.equal(interceptEnv.AGENTSAFE_INTERCEPT_CA_KEY_FILE, `${caMount}/ca.key`);
    assert.equal(volumes["agentsafe-intercept-ca"].secret.defaultMode, 288);
    assert.ok(volumes["agentsafe-intercept-ca-cert"].configMap);
    const trustMount = mounts(agent)["agentsafe-intercept-ca-cert"];
    const agentEnv = env(agent);
    for (const variable of ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"]) {
      assert.equal(agentEnv[variable], `${trustMount}/ca.crt`, variable);
    }
    assert.equal(
      mounts(agent)["agentsafe-intercept-ca"],
      undefined,
      "the key never reaches the workload",
    );
    for (const container of pod.containers) {
      for (const mount of container.volumeMounts) assert.equal(mount.readOnly, true, mount.name);
    }
    // Governed hosts are names, and the example starts in shadow, in
    // production, with the key from a file.
    for (const host of interceptEnv.AGENTSAFE_INTERCEPT_GOVERN.split(",")) {
      assert.match(host, /^[a-z0-9.-]+\.example$/, host);
    }
    assert.equal(interceptEnv.AGENTSAFE_INTERCEPT_UNLISTED, "passthrough");
    assert.equal(interceptEnv.AGENTSAFE_MODE, "shadow");
    assert.equal(interceptEnv.NODE_ENV, "production");
    assert.equal(interceptEnv.DECIONIS_API_KEY, undefined);
    assert.equal(interceptEnv.DECIONIS_API_KEY_FILE, `${mounts(intercept).decionis}/api-key`);
    assert.equal(volumes.decionis.secret.defaultMode, 288);
    // The Docker recipe says the same in its own words.
    const compose = await read("deploy/intercept/docker/compose.yaml");
    for (const variable of [
      "AGENTSAFE_INTERCEPT_GOVERN",
      "AGENTSAFE_INTERCEPT_CA_CERT_FILE",
      "AGENTSAFE_INTERCEPT_CA_KEY_FILE",
      "DECIONIS_API_KEY_FILE",
      "NODE_EXTRA_CA_CERTS",
    ]) {
      assert.ok(compose.includes(variable), variable);
    }
  });
});
