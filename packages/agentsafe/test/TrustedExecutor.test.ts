import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TLSSocket } from "node:tls";
import { JsonObjectSchema } from "@decionis/agent-safe-pipeline";
import { LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EVIDENCE_STREAM } from "../src/audit/HashChainedAuditSink.js";
import { ExecutorConfigLoader } from "../src/config/ExecutorConfig.js";
import type { HandlerRegistration } from "../src/handlers/HandlerRegistration.js";
import { SECURITY_STREAM } from "../src/incident/SecurityEvents.js";
import { HostPosture } from "../src/posture/HostPosture.js";
import type { PostureFacts } from "../src/posture/PostureChecks.js";
import { createTrustedExecutor, type TrustedExecutor } from "../src/TrustedExecutor.js";
import { verifyAuditChain } from "../src/verify/VerifyAuditChain.js";
import {
  CALLER_TOKEN,
  collectedEvents,
  LOOPBACK_ORIGIN,
  loopbackEnvironment,
  offlineEnvironment,
  openSecrets,
  proposal,
} from "./support/Environment.js";
import { ProviderDouble } from "./support/ProviderDouble.js";
import { TestCertificateAuthority } from "./support/TestCertificateAuthority.js";

const authority = new LocalAuthority();
const provider = new ProviderDouble();
const directory = mkdtempSync(join(tmpdir(), "agentsafe-executor-"));

beforeAll(async () => {
  await authority.start();
  await provider.start();
});

afterAll(async () => {
  await provider.stop();
  await authority.stop();
  rmSync(directory, { recursive: true, force: true });
});

async function propose(baseUrl: string, amountMinor: number): Promise<Record<string, unknown>> {
  const response = await fetch(`${baseUrl}/v1/actions`, {
    method: "POST",
    headers: { authorization: `Bearer ${CALLER_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify(proposal(amountMinor).body),
  });
  return (await response.json()) as Record<string, unknown>;
}

describe("createTrustedExecutor", () => {
  it("seals the adopter's handlers behind the listener and reports them on /ready", async () => {
    const handlers: HandlerRegistration = ({ registry }) => {
      registry.register("custom_action", { parametersSchema: JsonObjectSchema, execute: () => 1 });
      return ["custom_action"];
    };
    const config = ExecutorConfigLoader.load(offlineEnvironment());
    const secrets = openSecrets(offlineEnvironment(), config);
    const executor = await createTrustedExecutor({
      config,
      secrets,
      handlers,
      dependencies: { emit: () => undefined, security: collectedEvents() },
    });
    expect(executor.service.actions).toEqual(["custom_action"]);
    expect(executor.posture.mode).toBe("DEVELOPMENT");
    expect(executor.posture.failed).toEqual([]);
    expect(executor.evidence.head.seq).toBe(0);
    const address = await executor.listen(0, "127.0.0.1");
    const ready = await fetch(`${LOOPBACK_ORIGIN}:${address.port}/ready`);
    expect(ready.status).toBe(200);
    expect(await ready.json()).toEqual({
      status: "ready",
      mode: "ENFORCEMENT",
      escalation: "NONE",
      actions: ["custom_action"],
      open_attempts: 0,
    });
    await executor.close();
    expect(secrets.get("EXECUTOR_CALLER_TOKEN").disposed).toBe(true);
  });

  it("defaults to the reference forwarding handler and the process streams", async () => {
    const config = ExecutorConfigLoader.load(offlineEnvironment());
    const executor = await createTrustedExecutor({
      config,
      secrets: openSecrets(offlineEnvironment(), config),
    });
    expect(executor.service.actions).toEqual(["forward_request"]);
    expect(executor.metrics.registry.render()).toContain("# TYPE agentsafe_proposals counter");
    await executor.close();
  });

  it("verifies an injected posture before anything else and refuses to assemble on a failure", async () => {
    const env = offlineEnvironment();
    delete env["EXECUTOR_POSTURE"];
    const config = ExecutorConfigLoader.load(env);
    const facts = (euid: number): PostureFacts => ({
      euid,
      egid: 65532,
      cwd: "/app",
      writable: () => false,
      fileStat: () => null,
      realpath: (path) => path,
      inspectorActive: () => false,
      permission: () => ({ active: true, has: () => false }),
      globalFetchLocked: () => true,
    });
    const settings = { ...config.posture, environment: { NODE_ENV: "production" } };
    const rooted = new HostPosture(
      { mode: "ENFORCED", intervalSeconds: 60, config: settings, facts: facts(0) },
      collectedEvents(),
    );
    await expect(
      createTrustedExecutor({
        config,
        secrets: openSecrets(env, config),
        dependencies: { posture: rooted, emit: () => undefined, security: collectedEvents() },
      }),
    ).rejects.toThrow("POSTURE_ROOT_UID");
    const hardened = new HostPosture(
      { mode: "ENFORCED", intervalSeconds: 60, config: settings, facts: facts(65532) },
      collectedEvents(),
    );
    const executor = await createTrustedExecutor({
      config,
      secrets: openSecrets(env, config),
      dependencies: { posture: hardened, emit: () => undefined, security: collectedEvents() },
    });
    expect(executor.posture.mode).toBe("ENFORCED");
    expect(executor.posture.waived).toEqual([]);
    await executor.close();
  });

  it("chains every line, counts what it does, persists the chain heads, and resumes from them", async () => {
    const journalDir = join(directory, "journal");
    const env = {
      ...loopbackEnvironment({ authority, providerBaseUrl: provider.baseUrl }, "ENFORCEMENT"),
      EXECUTOR_JOURNAL_DIR: journalDir,
      EXECUTOR_AUDIT_CHECKPOINT_LINES: "2",
    };
    const auditLines: string[] = [];
    const securityLines: string[] = [];
    const start = async (): Promise<{ executor: TrustedExecutor; baseUrl: string }> => {
      const config = ExecutorConfigLoader.load(env);
      const executor = await createTrustedExecutor({
        config,
        secrets: openSecrets(env, config),
        dependencies: {
          emit: (line) => auditLines.push(line),
          security: collectedEvents(securityLines),
        },
      });
      const address = await executor.listen(0, "127.0.0.1");
      return { executor, baseUrl: `${LOOPBACK_ORIGIN}:${address.port}` };
    };
    const first = await start();
    const allowed = await propose(first.baseUrl, 25_00);
    expect(allowed["outcome"]).toBe("COMPLETED");
    const blocked = await propose(first.baseUrl, 10_000_000_00);
    expect(blocked["verdict"]).toBe("BLOCK");
    const head = first.executor.evidence.head;
    expect(head.seq).toBeGreaterThanOrEqual(4);
    expect(first.executor.metrics.proposals.get({ verdict: "ALLOW" })).toBe(1);
    expect(first.executor.metrics.proposals.get({ verdict: "BLOCK" })).toBe(1);
    expect(first.executor.metrics.executions.get({ outcome: "COMPLETED" })).toBe(1);
    expect(first.executor.metrics.auditLines.get({ chain: EVIDENCE_STREAM })).toBe(head.seq);
    expect(first.executor.metrics.auditLines.get({ chain: SECURITY_STREAM })).toBeGreaterThan(0);
    await first.executor.close();
    const persisted = JSON.parse(
      readFileSync(join(journalDir, "chain", "agent-safe.executor-evidence_1.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(persisted).toEqual({ stream: EVIDENCE_STREAM, ...head });
    const events = (): string[] =>
      securityLines.map((line) => (JSON.parse(line) as { event: string }).event);
    expect(events().filter((event) => event === "CHAIN_CHECKPOINT").length).toBeGreaterThanOrEqual(
      3,
    );
    const second = await start();
    expect(second.executor.evidence.head).toEqual(head);
    const resumed = securityLines
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((event) => event["event"] === "CHAIN_RESUMED");
    expect(resumed).toEqual([expect.objectContaining({ chain: EVIDENCE_STREAM, head: head.seq })]);
    await propose(second.baseUrl, 30_00);
    expect(second.executor.evidence.head.seq).toBeGreaterThan(head.seq);
    await second.executor.close();
    const audit = verifyAuditChain(auditLines);
    expect(audit.ok).toBe(true);
    expect(audit.streams[EVIDENCE_STREAM]).toMatchObject({ starts: 1, lines: auditLines.length });
    expect(auditLines.every((line) => line.includes('"caller_principal":"legacy-caller"'))).toBe(
      true,
    );
  });

  it("listens over TLS with the configured material and follows the key's rotation", async () => {
    const ca = new TestCertificateAuthority("Synthetic Executor CA");
    const tlsDir = join(directory, "tls");
    mkdirSync(tlsDir, { recursive: true });
    const write = (): void => {
      const issued = ca.issueServer(["localhost"], ["127.0.0.1"]);
      writeFileSync(join(tlsDir, "tls.crt"), issued.cert);
      writeFileSync(join(tlsDir, "tls.key"), issued.key);
    };
    write();
    const env = offlineEnvironment();
    delete env["EXECUTOR_ALLOW_PLAINTEXT_LISTENER"];
    env["EXECUTOR_TLS_CERT_FILE"] = join(tlsDir, "tls.crt");
    env["EXECUTOR_TLS_KEY_FILE"] = join(tlsDir, "tls.key");
    const config = ExecutorConfigLoader.load(env);
    const secrets = openSecrets(env, config);
    const securityLines: string[] = [];
    const executor = await createTrustedExecutor({
      config,
      secrets,
      dependencies: { emit: () => undefined, security: collectedEvents(securityLines) },
    });
    const address = await executor.listen(0, "127.0.0.1");
    const plain = await fetch(`${LOOPBACK_ORIGIN}:${address.port}/health`).catch(
      (error: Error) => error,
    );
    expect(plain).toBeInstanceOf(Error);
    const before = await served(address.port, ca.certificate);
    expect(before.status).toBe(200);
    write();
    await secrets.reload("SIGHUP");
    const after = await served(address.port, ca.certificate);
    expect(after.status).toBe(200);
    expect(after.fingerprint).not.toBe(before.fingerprint);
    expect(securityLines.some((line) => line.includes('"TLS_CONTEXT_ROTATED"'))).toBe(true);
    await executor.close();
  });
});

function served(port: number, ca: string): Promise<{ status: number; fingerprint: string }> {
  return new Promise((resolve, reject) => {
    request(
      { host: "127.0.0.1", port, path: "/health", ca, servername: "localhost", agent: false },
      (response) => {
        const fingerprint = (response.socket as TLSSocket).getPeerCertificate().fingerprint256;
        response.resume();
        response.on("end", () => resolve({ status: response.statusCode ?? 0, fingerprint }));
      },
    )
      .on("error", reject)
      .end();
  });
}
