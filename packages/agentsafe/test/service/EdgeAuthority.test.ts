import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { EdgeModule } from "@decionis/agent-safe-pipeline";
import {
  LOCAL_AUTHORITY_API_KEY,
  LocalAuthority,
  LocalPresence,
} from "@decionis/agent-safe-pipeline/testing";
import { CompactSign } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { ENTITLEMENT_TYPE } from "../../src/edge/EntitlementEvaluation.js";
import { forwardRequestHandlers } from "../../src/handlers/ForwardRequestHandler.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import {
  APPROVER_ID,
  collectedEvents,
  loopbackEnvironment,
  openSecrets,
  proposal,
  type Escalation,
} from "../support/Environment.js";
import { edgeBundle, edgeModuleDouble } from "../support/EdgeModuleDouble.js";
import { ProviderDouble } from "../support/ProviderDouble.js";

const presence = new LocalPresence({ autoComplete: "MANUAL", roles: { [APPROVER_ID]: "CRO" } });
const authority = new LocalAuthority({ presence });
const provider = new ProviderDouble();

function bundleFile(contents = edgeBundle()): string {
  const path = join(mkdtempSync(join(tmpdir(), "edge-bundle-")), "bundle.jws");
  writeFileSync(path, contents);
  return path;
}

interface Built {
  readonly service: TrustedExecutorService;
  readonly lines: string[];
  readonly security: string[];
  readonly loadModule: ReturnType<typeof vi.fn>;
}

function build(
  options: {
    escalation?: Escalation;
    env?: Record<string, string | undefined>;
    module?: () => EdgeModule;
  } = {},
): Built {
  const env: Record<string, string> = {
    ...loopbackEnvironment(
      { authority, presence, providerBaseUrl: provider.baseUrl },
      "ENFORCEMENT",
      options.escalation ?? "NONE",
    ),
    EXECUTOR_DECISION_AUTHORITY: "edge",
    EXECUTOR_EDGE_WASM_PATH: "/opt/decionis/policy_core_edge.wasm",
    EXECUTOR_EDGE_ORG_ID: "org-synthetic",
    EXECUTOR_EDGE_BUNDLE_SOURCE: "file",
    EXECUTOR_EDGE_BUNDLE_FILE: bundleFile(),
    EXECUTOR_EDGE_SINGLE_REPLICA: "true",
  };
  for (const [key, value] of Object.entries(options.env ?? {})) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  const lines: string[] = [];
  const security: string[] = [];
  const config = ExecutorConfigLoader.load(env);
  const events = collectedEvents(security);
  const loadModule = vi.fn(options.module ?? (() => edgeModuleDouble()));
  const service = TrustedExecutorService.create(
    config,
    openSecrets(env, config, events),
    forwardRequestHandlers(),
    { emit: (line) => lines.push(line), security: events, loadEdgeModule: loadModule },
  );
  return { service, lines, security, loadModule };
}

const enforceAndBind = (): number =>
  authority.requests.filter((request) => request.path === "/v1/authority/enforce-and-bind").length;

const claimed = (): number =>
  authority.requests.filter((request) => request.path.startsWith("/v1/execution/")).length;

const edgeLines = (lines: readonly string[]): Record<string, unknown>[] =>
  lines
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => String(line["event"]).startsWith("EDGE_"));

beforeAll(async () => {
  await presence.start();
  await authority.start();
  await provider.start();
});

afterAll(async () => {
  await provider.stop();
  await authority.stop();
  await presence.stop();
});

describe("the executor with the edge authority", () => {
  it("decides an ALLOW locally and executes it once, with no call to Decionis", async () => {
    const { service, lines, security } = build();
    await service.startEdge();
    const asked = enforceAndBind();
    const claims = claimed();
    const dispatches = provider.dispatches;
    const { body } = proposal(5_000);
    const allowed = await service.propose(body);
    expect(allowed).toMatchObject({
      verdict: "ALLOW",
      outcome: "COMPLETED",
      executed: true,
      finalization: "RECORDED",
      reason_codes: expect.arrayContaining(["EDGE_POLICY_ALLOW"]),
    });
    expect(allowed.decision_id).toMatch(/^edge:/);
    expect(enforceAndBind()).toBe(asked);
    // No Decionis grant exists on this path, so nothing is claimed or finalized there.
    expect(claimed()).toBe(claims);
    expect(provider.dispatches).toBe(dispatches + 1);

    const evidence = edgeLines(lines);
    expect(evidence.map((line) => line["event"])).toEqual([
      "EDGE_DECISION",
      "EDGE_EXECUTION_FINALIZED",
    ]);
    expect(evidence[0]).toMatchObject({
      stream: EVIDENCE_STREAM,
      verdict: "ALLOW",
      bundle_id: "bundle-1",
      policy_version: "policy-2026.10",
      kid: "decionis-policy-bundle-test-v1",
      jti: "jti-1",
      evaluation_digest: `sha256:${"e".repeat(64)}`,
      intent_hash: allowed.intent_hash,
      intent_id: allowed.intent_id,
      delegated: false,
      caller_principal: expect.any(String),
    });
    expect(evidence[1]).toMatchObject({ outcome: "COMMITTED", decision_id: allowed.decision_id });
    // The evidence carries identifiers, never the proposal's parameters.
    const text = JSON.stringify(evidence);
    expect(text).not.toContain("amountMinor");
    expect(text).not.toContain("synthetic-payout-");
    expect(security.some((line) => line.includes('"EDGE_BUNDLE_LOADED"'))).toBe(true);
    service.close();
  });

  it("refuses a BLOCK locally", async () => {
    const { service } = build();
    await service.startEdge();
    const asked = enforceAndBind();
    const blocked = await service.propose(proposal(500_000).body);
    expect(blocked).toMatchObject({ verdict: "BLOCK", outcome: "BLOCKED", executed: false });
    expect(enforceAndBind()).toBe(asked);
    service.close();
  });

  it("hands an ESCALATE to Decionis, so the managed Presence flow runs unchanged", async () => {
    const { service, lines } = build({ escalation: "MANAGED" });
    await service.startEdge();
    const asked = enforceAndBind();
    const effects = provider.effects.size;
    const held = await service.propose(proposal(50_000).body);
    expect(enforceAndBind()).toBe(asked + 1);
    expect(held).toMatchObject({ verdict: "ESCALATE", outcome: "ESCALATE_PENDING" });
    expect(edgeLines(lines)[0]).toMatchObject({ verdict: "ESCALATE", delegated: true });
    const handoff = held.escalation;
    if (handoff?.mode !== "MANAGED") throw new Error("expected a managed handoff");
    presence.approve(
      authority.escalations.get(handoff.escalation.escalationId)?.presenceRequestId ?? "",
    );
    let resumed = await service.resume(handoff);
    for (let lookups = 1; lookups < 10 && resumed.outcome === "ESCALATE_PENDING"; lookups += 1) {
      resumed = await service.resume(resumed.escalation);
    }
    expect(resumed).toMatchObject({ outcome: "COMPLETED", executed: true });
    expect(provider.effects.size).toBe(effects + 1);
    service.close();
  });

  it("asks Decionis while no bundle is loaded, and claims the hosted grant once", async () => {
    const { service, lines } = build();
    const asked = enforceAndBind();
    const allowed = await service.propose(proposal(5_000).body);
    expect(enforceAndBind()).toBe(asked + 1);
    expect(allowed).toMatchObject({ verdict: "ALLOW", outcome: "COMPLETED", executed: true });
    expect(allowed.decision_id).not.toMatch(/^edge:/);
    expect(edgeLines(lines)[0]).toMatchObject({
      event: "EDGE_UNAVAILABLE",
      reason: "EDGE_BUNDLE_UNAVAILABLE",
      fallback: "HOSTED",
    });
    service.close();
  });

  it("fails closed while no bundle is loaded under onUnavailable=block", async () => {
    const { service } = build({ env: { EXECUTOR_EDGE_ON_UNAVAILABLE: "block" } });
    const asked = enforceAndBind();
    const refused = await service.propose(proposal(5_000).body);
    expect(refused).toMatchObject({
      verdict: "BLOCK",
      fail_closed: true,
      executed: false,
      reason_codes: expect.arrayContaining(["EDGE_BUNDLE_UNAVAILABLE"]),
    });
    expect(enforceAndBind()).toBe(asked);
    service.close();
  });

  it("logs a failed bundle fetch by code, never with the API key", async () => {
    // The loopback authority does not serve bundles, so the fetch fails.
    const { service, security } = build({
      env: { EXECUTOR_EDGE_BUNDLE_SOURCE: undefined, EXECUTOR_EDGE_BUNDLE_FILE: undefined },
    });
    await service.startEdge();
    const failed = security
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .find((line) => line["event"] === "EDGE_BUNDLE_REFRESH_FAILED");
    expect(failed).toMatchObject({ code: expect.stringMatching(/^BUNDLE_/), failures: 1 });
    expect(security.join("\n")).not.toContain(LOCAL_AUTHORITY_API_KEY);
    service.close();
  });

  it("refuses to start without a valid module", () => {
    expect(() =>
      build({
        module: () => {
          throw new Error("unexpected");
        },
      }),
    ).toThrow("CONFIG_INVALID: EXECUTOR_EDGE_WASM_PATH (EDGE_MODULE_INVALID)");
    expect(() => build({ module: () => edgeModuleDouble(2) })).toThrow(
      "CONFIG_INVALID: EXECUTOR_EDGE_WASM_PATH (EDGE_MODULE_ABI_UNSUPPORTED)",
    );
  });

  it("refuses to start on a module path that is missing", async () => {
    const { EdgeModule } = await import("@decionis/agent-safe-pipeline");
    expect(() =>
      build({ module: () => EdgeModule.fromFile("/nonexistent/policy_core_edge.wasm") }),
    ).toThrow("CONFIG_INVALID: EXECUTOR_EDGE_WASM_PATH (EDGE_MODULE_UNREADABLE)");
  });

  it("never blocks, delays or changes a decision whatever the licence says", async () => {
    // An entitlement that is expired, excludes the edge and includes no
    // actions, signed by the key the pinned JWKS names; and no usage key.
    const signer = generateKeyPairSync("ed25519");
    const now = Math.floor(Date.now() / 1000);
    const entitlement = await new CompactSign(
      new TextEncoder().encode(
        JSON.stringify({
          iss: "decionis-synthetic",
          aud: "org-synthetic",
          iat: now - 86_400 * 40,
          exp: now - 60,
          plan: "premium",
          tier: "hosted",
          included_actions_per_month: 0,
          volume_band: null,
          edge: false,
          usage_report_due_days: 35,
        }),
      ),
    )
      .setProtectedHeader({ alg: "EdDSA", typ: ENTITLEMENT_TYPE, kid: "synthetic-entitlement-1" })
      .sign(signer.privateKey);
    const directory = mkdtempSync(join(tmpdir(), "entitlement-"));
    writeFileSync(join(directory, "entitlement.jws"), entitlement);
    writeFileSync(
      join(directory, "jwks.json"),
      JSON.stringify({
        keys: [{ ...signer.publicKey.export({ format: "jwk" }), kid: "synthetic-entitlement-1" }],
      }),
    );
    const licensed = build({
      env: {
        EXECUTOR_EDGE_ENTITLEMENT_FILE: join(directory, "entitlement.jws"),
        EXECUTOR_EDGE_JWKS_FILE: join(directory, "jwks.json"),
      },
    });
    await licensed.service.startEdge();
    const asked = enforceAndBind();
    const allowed = await licensed.service.propose(proposal(5_000).body);
    expect(allowed).toMatchObject({ verdict: "ALLOW", outcome: "COMPLETED", executed: true });
    expect(allowed.decision_id).toMatch(/^edge:/);
    expect(enforceAndBind()).toBe(asked);
    const blocked = await licensed.service.propose(proposal(500_000).body);
    expect(blocked).toMatchObject({ verdict: "BLOCK", fail_closed: false });
    const warnings = licensed.security
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((line) => line["event"] === "EDGE_LICENCE_WARNING")
      .map((line) => line["code"]);
    // Raised at start; the next hourly check adds INCLUDED_ACTIONS_EXCEEDED for
    // the decision just made, which is a line and a metric too, and no more.
    expect(warnings).toEqual([
      "ENTITLEMENT_EXPIRED",
      "EDGE_NOT_ENTITLED",
      "USAGE_REPORT_KEY_MISSING",
    ]);
    const gauge = licensed.service.metrics.edgeLicenceWarnings;
    expect(gauge.get({ code: "EDGE_NOT_ENTITLED" })).toBe(1);
    expect(licensed.service.metrics.registry.render()).toContain(
      'agentsafe_edge_licence_warning{code="ENTITLEMENT_EXPIRED"} 1',
    );
    licensed.service.close();
  });

  it("never loads a module when the authority is hosted", async () => {
    const env = loopbackEnvironment(
      { authority, presence, providerBaseUrl: provider.baseUrl },
      "ENFORCEMENT",
    );
    const config = ExecutorConfigLoader.load(env);
    expect(config.decision.authority).toBe("hosted");
    expect(config.edge).toBeNull();
    const loadEdgeModule = vi.fn(() => edgeModuleDouble());
    const service = TrustedExecutorService.create(
      config,
      openSecrets(env, config),
      forwardRequestHandlers(),
      { emit: () => undefined, security: collectedEvents(), loadEdgeModule },
    );
    await service.startEdge();
    const allowed = await service.propose(proposal(5_000).body);
    expect(allowed).toMatchObject({ verdict: "ALLOW", executed: true });
    expect(loadEdgeModule).not.toHaveBeenCalled();
    service.close();
  });
});
