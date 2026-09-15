import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { forwardRequestHandlers } from "../../src/handlers/ForwardRequestHandler.js";
import { HaltSwitch } from "../../src/incident/HaltSwitch.js";
import { InMemoryExecutionJournal } from "../../src/journal/InMemoryExecutionJournal.js";
import type { Principal } from "../../src/identity/PrincipalRegistry.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { verifyEvidenceBundle } from "../../src/verify/VerifyEvidenceBundle.js";
import {
  CALLER_TOKEN,
  TENANT_ID,
  collectedEvents,
  loopbackEnvironment,
  openSecrets,
  proposal,
} from "../support/Environment.js";
import { sha256Hex } from "../support/Principals.js";
import { ProviderDouble } from "../support/ProviderDouble.js";

const authority = new LocalAuthority();
const provider = new ProviderDouble();
const root = mkdtempSync(join(tmpdir(), "agentsafe-incident-"));

beforeAll(async () => {
  await authority.start();
  await provider.start();
});

afterAll(async () => {
  await provider.stop();
  await authority.stop();
  rmSync(root, { recursive: true, force: true });
});

interface Built {
  readonly service: TrustedExecutorService;
  readonly operator: Principal;
  readonly proposer: Principal;
  readonly lines: string[];
  readonly securityLines: string[];
  readonly evidenceDir: string | null;
}

let sequence = 0;

function build(overrides: Record<string, string | undefined> = {}): Built {
  sequence += 1;
  const dir = overrides["EXECUTOR_EVIDENCE_DIR"] === null ? null : join(root, `run-${sequence}`);
  const env: Record<string, string> = {
    ...loopbackEnvironment({ authority, providerBaseUrl: provider.baseUrl }, "ENFORCEMENT"),
    ...(dir === null ? {} : { EXECUTOR_EVIDENCE_DIR: dir }),
  };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  const config = ExecutorConfigLoader.load(env);
  const lines: string[] = [];
  const securityLines: string[] = [];
  const events = collectedEvents(securityLines);
  const service = TrustedExecutorService.create(
    config,
    openSecrets(env, config, events),
    forwardRequestHandlers(),
    {
      emit: (line) => lines.push(line),
      security: events,
      journal: new InMemoryExecutionJournal(),
      halt: new HaltSwitch({ events }),
    },
  );
  const operator: Principal = {
    id: "synthetic-ops-oncall",
    role: "OPERATOR",
    tenantId: null,
    actor: null,
    scopes: new Set(["status", "metrics", "halt", "resume", "secrets.reload", "evidence"]),
    allowedActions: new Set(),
    credential: { kind: "BEARER", token_sha256: "0".repeat(64) },
    rateLimit: null,
  } as unknown as Principal;
  return {
    service,
    operator,
    proposer: service.principals.proposers[0] as Principal,
    lines,
    securityLines,
    evidenceDir: dir,
  };
}

async function refusal(work: Promise<unknown>): Promise<ServiceError> {
  try {
    await work;
  } catch (error) {
    if (error instanceof ServiceError) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

const events = (lines: string[]): Record<string, unknown>[] =>
  lines.map((line) => JSON.parse(line) as Record<string, unknown>);

describe("taking evidence out of a running executor", () => {
  it("writes a bundle an auditor can verify with no key and no service", async () => {
    const built = build();
    await built.service.propose(proposal(1_000).body, built.proposer);
    const bundle = await built.service.exportEvidence(
      { reason: "payment rail incident, on-call took a bundle" },
      built.operator,
    );
    expect(bundle.manifest.exported_by).toBe("synthetic-ops-oncall");
    expect(bundle.signature).toBeNull();
    const files = readdirSync(bundle.directory).sort();
    expect(files).toEqual([
      "audit.jsonl",
      "manifest.json",
      "open-attempts.json",
      "posture.json",
      "security-events.jsonl",
    ]);
    const report = await verifyEvidenceBundle({
      read: (name) => {
        try {
          return readFileSync(join(bundle.directory, name), "utf8");
        } catch {
          return null;
        }
      },
    });
    expect(report.findings).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.establishes).toBe("INTERNAL_CONSISTENCY");
    // The proposal that ran is in the bundle's own audit stream.
    expect(report.chains["agent-safe.executor-evidence/1"]?.lines).toBeGreaterThan(2);
    built.service.close();
  });

  it("reports the export on the security stream, with the count and whether it was signed", async () => {
    const built = build();
    await built.service.exportEvidence({ reason: "a drill" }, built.operator);
    const exported = events(built.securityLines).find(
      (event) => event["event"] === "EVIDENCE_EXPORTED",
    );
    expect(exported).toMatchObject({ principal: "synthetic-ops-oncall", files: 4, signed: false });
    expect(built.service.metrics.evidenceExports.get()).toBe(1);
    built.service.close();
  });

  it("carries no secret, no parameter, and no provider body", async () => {
    const built = build();
    await built.service.propose(proposal(2_500).body, built.proposer);
    const bundle = await built.service.exportEvidence({ reason: "a drill" }, built.operator);
    const everything = readdirSync(bundle.directory)
      .map((name) => readFileSync(join(bundle.directory, name), "utf8"))
      .join("\n");
    for (const forbidden of [
      "synthetic-authority-key",
      "synthetic-caller-token",
      "synthetic-downstream-credential",
      "Bearer ",
      "amountMinor",
      "2500",
    ]) {
      expect(everything, forbidden).not.toContain(forbidden);
    }
    built.service.close();
  });

  it("refuses a proposer, an operator without the scope, and a missing reason", async () => {
    const built = build();
    expect(
      (await refusal(built.service.exportEvidence({ reason: "no" }, built.proposer))).code,
    ).toBe("ROLE_FORBIDDEN");
    const narrow = { ...built.operator, scopes: new Set(["status"]) } as unknown as Principal;
    expect((await refusal(built.service.exportEvidence({ reason: "no" }, narrow))).code).toBe(
      "SCOPE_FORBIDDEN",
    );
    expect((await refusal(built.service.exportEvidence({}, built.operator))).code).toBe(
      "REQUEST_INVALID",
    );
    expect((await refusal(built.service.exportEvidence({ reason: "" }, built.operator))).code).toBe(
      "REQUEST_INVALID",
    );
    built.service.close();
  });

  it("refuses when no directory was configured, rather than writing somewhere", async () => {
    const built = build({ EXECUTOR_EVIDENCE_DIR: undefined });
    const refused = await refusal(
      built.service.exportEvidence({ reason: "a drill" }, built.operator),
    );
    expect([refused.status, refused.code]).toEqual([409, "EVIDENCE_DIR_NOT_CONFIGURED"]);
    built.service.close();
  });

  it("reports a flipped byte in a bundle it wrote itself", async () => {
    const built = build();
    const bundle = await built.service.exportEvidence({ reason: "a drill" }, built.operator);
    const files = new Map<string, string>();
    for (const name of readdirSync(bundle.directory)) {
      files.set(name, readFileSync(join(bundle.directory, name), "utf8"));
    }
    files.set("posture.json", `${files.get("posture.json") ?? ""}tampered`);
    const report = await verifyEvidenceBundle({ read: (name) => files.get(name) ?? null });
    expect(report.ok).toBe(false);
    expect(report.findings[0]?.code).toBe("BUNDLE_FILE_DIGEST_MISMATCH");
    built.service.close();
  });
});

describe("what an incident is detected by", () => {
  it("names a finalization the authority did not take, and counts every one it did", async () => {
    const built = build();
    await built.service.propose(proposal(1_000).body, built.proposer);
    expect(built.service.metrics.finalizations.get({ status: "RECORDED" })).toBe(1);
    expect(
      events(built.securityLines).some((event) => event["event"] === "FINALIZATION_PENDING"),
    ).toBe(false);
    built.service.close();
  });

  it("names a proposer that runs as an operator's identity, before the authority is asked", async () => {
    // A proposer equal to the *approver* is refused at start-up, so this is
    // the shape start-up cannot see: a workflow whose actor is the identity
    // that also holds `halt` and `resume`, which would let the party that
    // proposes also stop and start the boundary around itself.
    const path = join(root, "principals-sod.json");
    writeFileSync(
      path,
      JSON.stringify({
        version: "agent-safe.principals/1",
        principals: [
          {
            id: "synthetic-treasury-workflow",
            role: "PROPOSER",
            tenant_id: TENANT_ID,
            actor: { id: "synthetic-ops-oncall", type: "AI_AGENT" },
            allowed_actions: ["forward_request"],
            credential: { kind: "BEARER", token_sha256: sha256Hex(CALLER_TOKEN) },
          },
          {
            id: "synthetic-ops-oncall",
            role: "OPERATOR",
            scopes: ["halt", "resume", "status"],
            credential: { kind: "BEARER", token_sha256: sha256Hex("synthetic-operator-token") },
          },
        ],
      }),
    );
    const built = build({
      EXECUTOR_PRINCIPALS_FILE: path,
      EXECUTOR_TENANT_ID: undefined,
      EXECUTOR_ACTOR_ID: undefined,
      EXECUTOR_ACTOR_TYPE: undefined,
      EXECUTOR_ACTOR_RUNTIME: undefined,
      EXECUTOR_CALLER_TOKEN: undefined,
    });
    const requests = authority.requests.length;
    const refused = await refusal(built.service.propose(proposal(1_000).body, built.proposer));
    expect([refused.status, refused.code]).toEqual([422, "SEPARATION_OF_DUTIES_VIOLATED"]);
    expect(authority.requests.length).toBe(requests);
    expect(
      events(built.securityLines).some(
        (event) => event["event"] === "SEPARATION_OF_DUTIES_VIOLATED",
      ),
    ).toBe(true);
    built.service.close();
  });
});
