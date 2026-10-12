import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cardHandlers } from "../../src/adapters/cards/CardHandlers.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import type { LoadPg, PgPool } from "../../src/edge/EdgeReplay.js";
import type { Principal } from "../../src/identity/PrincipalRegistry.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { edgeBundle, edgeModuleDouble } from "../support/EdgeModuleDouble.js";
import { collectedEvents, loopbackEnvironment, openSecrets } from "../support/Environment.js";
import { FakeCardHoldsSql } from "../support/FakeCardHoldsSql.js";

const authority = new LocalAuthority();

beforeAll(async () => {
  await authority.start();
});

afterAll(async () => {
  await authority.stop();
});

const ISSUER: Principal = {
  id: "synthetic-issuer-hook",
  role: "OPERATOR",
  tenantId: null,
  actor: null,
  allowedActions: new Set(),
  scopes: new Set(["cards.authorize"]),
  credential: { kind: "BEARER", tokenDigest: Buffer.alloc(32) },
  rateLimit: null,
} as unknown as Principal;

function bundleFile(): string {
  const path = join(mkdtempSync(join(tmpdir(), "edge-card-bundle-")), "bundle.jws");
  writeFileSync(path, edgeBundle());
  return path;
}

function build(env: Record<string, string> = {}, loadPg?: LoadPg) {
  const environment: Record<string, string> = {
    ...loopbackEnvironment({ authority, providerBaseUrl: "http://127.0.0.1:9" }, "ENFORCEMENT"),
    DOWNSTREAM_SYSTEM: "synthetic-issuer",
    DOWNSTREAM_OPERATION: "card_purchase",
    EXECUTOR_ACTOR_ID: "synthetic-shopping-agent",
    EXECUTOR_DECISION_AUTHORITY: "edge",
    EXECUTOR_EDGE_WASM_PATH: "/opt/decionis/policy_core_edge.wasm",
    EXECUTOR_EDGE_ORG_ID: "org-synthetic",
    EXECUTOR_EDGE_BUNDLE_SOURCE: "file",
    EXECUTOR_EDGE_BUNDLE_FILE: bundleFile(),
    EXECUTOR_EDGE_SINGLE_REPLICA: "true",
    ...env,
  };
  const config = ExecutorConfigLoader.load(environment);
  const lines: string[] = [];
  const security: string[] = [];
  const events = collectedEvents(security);
  const service = TrustedExecutorService.create(
    config,
    openSecrets(environment, config, events),
    cardHandlers(),
    {
      emit: (line) => lines.push(line),
      security: events,
      loadEdgeModule: () => edgeModuleDouble(),
      ...(loadPg === undefined ? {} : { loadPg }),
    },
  );
  return { service, lines, security };
}

let sequence = 0;

function purchase(amountMinor = 4_250) {
  sequence += 1;
  const parameters = {
    cardTokenRef: `fixture_card_ref_${sequence}`,
    amountMinor,
    currency: "EUR",
    merchantId: "fixture_merchant_17",
  };
  return {
    parameters,
    body: {
      proposal: { action: "card.purchase", target: `card:${parameters.cardTokenRef}`, parameters },
      idempotency_key: `fixture-edge-card-${sequence}`,
    },
  };
}

const hosted = (): number =>
  authority.requests.filter(
    (request) =>
      request.path === "/v1/authority/enforce-and-bind" ||
      request.path.startsWith("/v1/execution/"),
  ).length;

const events = (lines: readonly string[]): string[] =>
  lines.map((line) => String((JSON.parse(line) as { event: string }).event));

describe("a card purchase decided at the edge", () => {
  it("holds a local decision, claims it in the process with no call to Decionis, and finalizes locally", async () => {
    const { service, lines } = build();
    await service.startEdge();
    const before = hosted();
    const { parameters, body } = purchase();
    const held = await service.propose(body);
    expect(held).toMatchObject({ verdict: "ALLOW", outcome: "HELD_FOR_AUTHORIZATION" });
    expect(held.dossier_id).toMatch(/^edge:sha256:/);
    const asked = {
      authorization_id: "fixture_edge_auth_1",
      card_token_ref: parameters.cardTokenRef,
      amount_minor: 4_000,
      currency: "EUR",
      merchant_id: "fixture_merchant_17",
    };
    const approved = await service.authorizeCard(asked, ISSUER);
    expect(approved).toMatchObject({
      decision: "APPROVE",
      intent_id: held.intent_id,
      grant_id: `edge:${held.intent_id}`,
    });
    const result = await service.settleCard(
      asked.authorization_id,
      { status: "APPROVED", approved_amount_minor: 4_000 },
      ISSUER,
    );
    expect(result).toMatchObject({
      outcome: "COMMITTED",
      executed: true,
      finalization: "RECORDED",
    });
    // The whole path, decision to finalization, stayed in the process.
    expect(hosted()).toBe(before);
    const seen = events(lines);
    expect(seen).toContain("EDGE_DECISION");
    expect(seen).toContain("EDGE_EXECUTION_FINALIZED");
    expect(seen.filter((event) => event === "GRANT_CONSUMED")).toHaveLength(1);
    // Spent once: the same grant cannot be claimed again.
    expect(
      await service.authorizeCard({ ...asked, authorization_id: "fixture_edge_auth_2" }, ISSUER),
    ).toEqual({ decision: "NO_MATCH", code: "GRANT_ALREADY_USED" });
    service.close();
  });

  it("settles a locally claimed hold on another replica, where the finalization is recorded", async () => {
    const sql = new FakeCardHoldsSql();
    const load: LoadPg = async () => ({
      Pool: class implements PgPool {
        public async query(text: string, values: unknown[]): Promise<{ rowCount: number | null }> {
          return await sql.query(text, values);
        }
        public on(): void {
          return undefined;
        }
        public async end(): Promise<void> {
          return undefined;
        }
      },
    });
    const env = {
      EXECUTOR_CARD_HOLDS_STORE: "postgres",
      EXECUTOR_CARD_HOLDS_NAMESPACE: "org-synthetic",
      EXECUTOR_CARD_HOLDS_DATABASE_URL: "postgres://executor@db.invalid/cards",
      EXECUTOR_CARD_HOLDS_KEY: randomBytes(32).toString("hex"),
    };
    const a = build(env, load);
    const b = build(env, load);
    await a.service.startEdge();
    await b.service.startEdge();
    const before = hosted();
    const { parameters, body } = purchase();
    const held = await a.service.propose(body);
    const asked = {
      authorization_id: "fixture_edge_auth_3",
      card_token_ref: parameters.cardTokenRef,
      amount_minor: 4_250,
      currency: "EUR",
      merchant_id: "fixture_merchant_17",
    };
    // Claimed on A: the local grant is A's, so the claim happens where the hold was decided.
    expect(await a.service.authorizeCard(asked, ISSUER)).toMatchObject({
      decision: "APPROVE",
      intent_id: held.intent_id,
    });
    // Settled on B, which adopts the claim as local and records the finalization itself.
    const result = await b.service.settleCard(
      asked.authorization_id,
      { status: "DECLINED" },
      ISSUER,
    );
    expect(result).toMatchObject({ outcome: "FAILED", executed: false, finalization: "RECORDED" });
    expect(events(b.lines)).toContain("EDGE_EXECUTION_FINALIZED");
    expect(events(a.lines)).not.toContain("EDGE_EXECUTION_FINALIZED");
    expect(hosted()).toBe(before);
    a.service.close();
    b.service.close();
  });
});
