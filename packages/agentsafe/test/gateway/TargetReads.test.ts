import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  LOCAL_AUTHORITY_API_KEY,
  LocalAuthority,
  type LocalAuthorityPolicyInput,
} from "@decionis/agent-safe-pipeline/testing";
import { Gateway } from "../../src/gateway/Gateway.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import {
  collectedIo,
  LOOPBACK_ORIGIN,
  testConfig,
  type CollectedIo,
} from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const COMPANY = "6f3c1a52-1d2e-4f5a-8b9c-0d1e2f3a4b5c";
const CUSTOMER = `/companies(${COMPANY})/customers(9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d)`;
const GATEWAY_TOKEN = "synthetic-gateway-token";
const SOURCE = "businesscentral/api/v2#customers.get";

interface Seen {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

/**
 * A system of record with one versioned customer, shaped as Business
 * Central answers it: a read states the record and its `@odata.etag`, and a
 * change applies the body and moves the version. It honours the version the
 * gateway sends on a write, as a provider that takes writes only through the
 * gateway's credential would, and refuses a write whose target has moved.
 * `misapply` stores another `blocked` than the one sent; `unversioned` reads
 * without an etag; `missing` answers every read with a 404.
 */
class VersionedTarget {
  public readonly seen: Seen[] = [];
  public version = 1;
  public record: Record<string, unknown> = {
    id: "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    number: "C-10000",
    displayName: "Synthetic Customer",
    blocked: " ",
  };
  public misapply = false;
  public unversioned = false;
  public missing = false;
  private server: Server | null = null;
  private port = 0;

  public get baseUrl(): string {
    return `${LOOPBACK_ORIGIN}:${this.port}`;
  }

  public get etag(): string {
    return `W/"${this.version}"`;
  }

  public reads(): number {
    return this.seen.filter((request) => request.method === "GET").length;
  }

  public writes(): number {
    return this.seen.filter((request) => request.method !== "GET").length;
  }

  /** Someone else's write, through no gateway: the version moves. */
  public bump(change: Record<string, unknown> = {}): void {
    this.record = { ...this.record, ...change };
    this.version += 1;
  }

  public async start(): Promise<void> {
    const server = createServer((request, response) => {
      void this.handle(request, response);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    this.port = typeof address === "object" && address !== null ? address.port : 0;
    this.server = server;
  }

  public async stop(): Promise<void> {
    this.server?.closeAllConnections();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const method = request.method ?? "";
    this.seen.push({ method, url: request.url ?? "/", headers: request.headers });
    const answer = (status: number, body: unknown): void => {
      response.writeHead(status, { "content-type": "application/json", connection: "close" });
      response.end(JSON.stringify(body));
    };
    if (method === "GET") {
      if (this.missing) return answer(404, { error: "NotFound" });
      return answer(
        200,
        this.unversioned ? this.record : { "@odata.etag": this.etag, ...this.record },
      );
    }
    const expected = request.headers["x-agent-safe-expected-state-version"];
    if (expected !== undefined && expected !== this.etag) {
      return answer(412, { error: "TARGET_STATE_CHANGED" });
    }
    const change = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<
      string,
      unknown
    >;
    this.bump(this.misapply ? { ...change, blocked: "Ship" } : change);
    return answer(200, { "@odata.etag": this.etag, ...this.record });
  }
}

const parsed = (io: CollectedIo): Record<string, unknown>[] =>
  io.out.map((line) => JSON.parse(line) as Record<string, unknown>);
const chained = (io: CollectedIo, event: string): Record<string, unknown>[] =>
  parsed(io).filter(
    (line) => line["stream"] === "agent-safe.gateway-events/1" && line["event"] === event,
  );
const intercepted = (io: CollectedIo): Record<string, unknown>[] =>
  parsed(io).filter((line) => line["event"] === "INTERCEPTED");

describe("a gateway that reads the target a profiled write names", () => {
  const target = new VersionedTarget();
  let verdict: "ALLOW" | "BLOCK" | "ESCALATE" = "ALLOW";
  let duringDecision: () => void = () => undefined;
  const decided: LocalAuthorityPolicyInput[] = [];
  const authority = new LocalAuthority({
    policy: (request) => {
      decided.push(request);
      duringDecision();
      return verdict;
    },
    trustedEffectObserverIds: [LOCAL_AUTHORITY_API_KEY],
  });
  let directory: string;
  let gateway: Gateway;
  let server: GatewayHttpServer;
  let origin: string;
  let io: CollectedIo;

  async function build(
    interception: Record<string, unknown> = {},
    options: { mode?: "enforcement" | "shadow"; authorityUrl?: string } = {},
  ): Promise<void> {
    io = collectedIo();
    const env = {
      DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
      DECIONIS_API_URL: options.authorityUrl ?? authority.baseUrl,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      DECIONIS_TENANT_ID: TENANT_ID,
      DECIONIS_TIMEOUT_MS: "500",
      AGENTSAFE_MODE: options.mode ?? "enforcement",
    };
    const file = {
      version: 1,
      gateway: { gatewayToken: { file: join(directory, "gateway-token") } },
      interception: {
        profile: "businesscentral/api/v2",
        refusalWindowMs: 150,
        ...interception,
      },
      evidence: { observer: LOCAL_AUTHORITY_API_KEY },
    };
    gateway = await Gateway.create(testConfig(target.baseUrl, { env, file }), {
      env,
      io,
      version: "9.9.9",
    });
    server = new GatewayHttpServer(gateway);
    origin = `${LOOPBACK_ORIGIN}:${(await server.listen(0, "127.0.0.1")).port}`;
  }

  /** Stops the gateway once its reads after a refusal have finished, so their lines are written. */
  async function teardown(): Promise<void> {
    await server.close(10);
    await gateway.close();
  }

  async function change(body: Record<string, unknown>): Promise<Response> {
    return await fetch(`${origin}${CUSTOMER}`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        "if-match": "*",
        authorization: "Bearer synthetic-agent-credential",
      },
      body: JSON.stringify(body),
    });
  }

  const finalizationRecords = () =>
    authority.requests.filter(
      (record) =>
        record.path.endsWith("/receipts") || record.path === "/v1/execution/finalize-token",
    );
  const finalizations = (): Record<string, unknown>[] =>
    finalizationRecords().map((record) => record.body as Record<string, unknown>);

  /** A loopback port nothing listens on: an authority that cannot be reached. */
  async function closedPort(): Promise<number> {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
    const address = probe.address();
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    return typeof address === "object" && address !== null ? address.port : 0;
  }

  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), "agentsafe-target-"));
    writeFileSync(join(directory, "gateway-token"), GATEWAY_TOKEN);
    await target.start();
    await authority.start();
  });
  afterAll(async () => {
    await target.stop();
    await authority.stop();
    rmSync(directory, { recursive: true, force: true });
  });

  it("binds the version it read, as itself, and the provider refuses a write whose target moved", async () => {
    await build();
    verdict = "ALLOW";
    // Someone else writes to the customer while the authority decides.
    duringDecision = () => target.bump({ displayName: "Changed Elsewhere" });
    const before = target.version;
    const seen = target.seen.length;
    const answer = await change({ blocked: "All" });
    duringDecision = () => undefined;
    await teardown();
    expect([answer.status, answer.headers.get("agentsafe-execution")]).toEqual([412, "FAILED"]);
    // The read was the gateway's own: its token, none of the caller's headers.
    const [read, write] = target.seen.slice(seen);
    expect(read).toMatchObject({ method: "GET", url: CUSTOMER });
    expect(read?.headers["agentsafe-gateway-token"]).toBe(GATEWAY_TOKEN);
    expect(read?.headers["authorization"]).toBeUndefined();
    expect(read?.headers["if-match"]).toBeUndefined();
    // The intent bound the version read before the decision, and the write said so.
    const context = decided.at(-1)?.context as Record<string, unknown>;
    expect(context["agent_safe"]).toEqual({
      precondition: {
        version: `W/"${before}"`,
        state: " ",
        source: SOURCE,
        read_at: expect.any(String) as unknown,
      },
    });
    expect(write).toMatchObject({ method: "PATCH" });
    expect(write?.headers["x-agent-safe-expected-state-version"]).toBe(`W/"${before}"`);
    expect(target.record["blocked"]).toBe(" ");
    expect(intercepted(io).at(-1)).toMatchObject({
      state: "EXECUTION_FAILED",
      upstream_status: 412,
    });
  });

  it("reads back an effect as authorised: CONFIRMED, and the authority records it so", async () => {
    await build();
    verdict = "ALLOW";
    const reads = target.reads();
    const answer = await change({ blocked: "All" });
    await teardown();
    expect([answer.status, answer.headers.get("agentsafe-execution")]).toEqual([200, "FORWARDED"]);
    expect(target.reads() - reads).toBe(2);
    const expected = decided.at(-1)?.expected_effect_digest;
    expect(expected).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(intercepted(io).at(-1)).toMatchObject({
      state: "ALLOW",
      effect: { confirmation: "CONFIRMED", reason_codes: [] },
    });
    expect(chained(io, "EFFECT_OBSERVED").at(-1)).toMatchObject({
      operation: "customers.update",
      confirmation: "CONFIRMED",
      mismatched: [],
      expected_effect_digest: expected,
      observed_effect_digest: expected,
    });
    expect(finalizations().at(-1)).toMatchObject({
      outcome: "COMMITTED",
      effect_evidence: {
        status: "CONFIRMED",
        observation_method: "READ_AFTER_WRITE",
        observer: { id: LOCAL_AUTHORITY_API_KEY, version: "9.9.9" },
        expected_effect_digest: expected,
        observed_effect_digest: expected,
      },
    });
    expect(finalizationRecords().at(-1)?.response?.body).toMatchObject({
      effect_evidence_recorded: true,
      effect_confirmation: "CONFIRMED",
    });
    expect(gateway.metricsText()).toContain('agentsafe_effects_total{effect="CONFIRMED"} 1');
  });

  it("reports an effect that differs, and the breach it opens holds the next write in its scope", async () => {
    await build();
    verdict = "ALLOW";
    target.misapply = true;
    const answer = await change({ blocked: "All" });
    target.misapply = false;
    expect(answer.status).toBe(200);
    expect(intercepted(io).at(-1)).toMatchObject({
      state: "ALLOW",
      effect: { confirmation: "UNKNOWN", reason_codes: ["EFFECT_MISMATCH"] },
    });
    const observed = chained(io, "EFFECT_OBSERVED").at(-1);
    expect(observed).toMatchObject({ confirmation: "UNKNOWN", mismatched: ["/body/blocked"] });
    expect(observed?.["observed_effect_digest"]).not.toBe(observed?.["expected_effect_digest"]);
    expect(finalizations().at(-1)).toMatchObject({
      effect_evidence: { status: "UNCONFIRMED", observation_method: "READ_AFTER_WRITE" },
    });
    expect(authority.assumptionBreaches.all.at(-1)).toMatchObject({
      trigger: "EFFECT_MISMATCH",
      status: "OPEN",
    });
    // The breach holds the action at that target: the next change escalates.
    const next = await change({ blocked: "Invoice" });
    await teardown();
    expect(next.status).toBe(202);
    expect(await next.json()).toMatchObject({
      verdict: "ESCALATE",
      reason_codes: ["ASSUMPTION_BREACH_OPEN"],
    });
    expect(gateway.metricsText()).toContain('agentsafe_effects_total{effect="UNKNOWN"} 1');
    // Only a governed release that cites the breach and its evidence clears it.
    const breach = authority.assumptionBreaches.all.at(-1)!;
    authority.assumptionBreaches.clear([
      { breachId: breach.breachId, evidenceIds: breach.evidenceIds },
    ]);
  });

  it("leaves an attempt PENDING, and says why, when nothing declares or states its effect", async () => {
    await build();
    verdict = "ALLOW";
    // The change states no value the effect names: the grant commits to none.
    const unstated = await change({ displayName: "Renamed" });
    expect(unstated.status).toBe(200);
    expect(decided.at(-1)?.expected_effect_digest).toBeUndefined();
    expect(decided.at(-1)?.context).toHaveProperty("agent_safe.precondition.source", SOURCE);
    expect(intercepted(io).at(-1)).toMatchObject({
      effect: { confirmation: "PENDING", reason_codes: ["EFFECT_UNSTATED"] },
    });
    // A write the profile names no read for holds only the acknowledgement.
    const reads = target.reads();
    const created = await fetch(`${origin}/companies(${COMPANY})/salesOrders`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ customerNumber: "C-10000" }),
    });
    await teardown();
    expect(created.status).toBe(200);
    expect(target.reads()).toBe(reads);
    expect(decided.at(-1)?.context).not.toHaveProperty("agent_safe");
    expect(intercepted(io).at(-1)).toMatchObject({
      effect: { confirmation: "PENDING", reason_codes: ["EFFECT_UNDECLARED"] },
    });
    expect(finalizations().at(-1)).not.toHaveProperty("effect_evidence");
    expect(chained(io, "EFFECT_OBSERVED")).toEqual([]);
  });

  it("binds the version and no effect digest in facts-only privacy", async () => {
    await build({ privacy: "facts" });
    verdict = "ALLOW";
    const answer = await change({ blocked: "All" });
    await teardown();
    expect(answer.status).toBe(200);
    expect(decided.at(-1)?.expected_effect_digest).toBeUndefined();
    expect(decided.at(-1)?.context).toHaveProperty("agent_safe.precondition.source", SOURCE);
    expect(intercepted(io).at(-1)).toMatchObject({
      effect: { confirmation: "PENDING", reason_codes: ["EFFECT_NOT_BOUND"] },
    });
  });

  it("observes a refused write's target unchanged, after a BLOCK, a held ESCALATE and a fail-closed refusal", async () => {
    for (const [refusal, status] of [
      ["BLOCK", 403],
      ["ESCALATE", 202],
      ["AUTHORITY_UNAVAILABLE", 503],
    ] as const) {
      await build(
        {},
        refusal === "AUTHORITY_UNAVAILABLE"
          ? { authorityUrl: `${LOOPBACK_ORIGIN}:${await closedPort()}` }
          : {},
      );
      verdict = refusal === "ESCALATE" ? "ESCALATE" : "BLOCK";
      const writes = target.writes();
      const version = target.etag;
      const answer = await change({ blocked: "All" });
      await teardown();
      expect([refusal, answer.status]).toEqual([refusal, status]);
      expect(target.writes()).toBe(writes);
      expect(chained(io, "REFUSAL_OBSERVATION")).toEqual([
        expect.objectContaining({
          refusal,
          operation: "customers.update",
          source: SOURCE,
          outcome: "UNCHANGED",
          version_before: version,
          version_after: version,
        }),
      ]);
      const [line] = chained(io, "REFUSAL_OBSERVATION");
      expect(Date.parse(String(line?.["read_after_at"]))).toBeGreaterThanOrEqual(
        Date.parse(String(line?.["read_before_at"])) + 140,
      );
      expect(gateway.metricsText()).toContain(
        'agentsafe_refusal_observations_total{outcome="UNCHANGED"} 1',
      );
    }
  });

  it("observes another writer that changed the target after the refusal", async () => {
    await build();
    verdict = "BLOCK";
    const version = target.etag;
    const answer = await change({ blocked: "All" });
    expect(answer.status).toBe(403);
    // A write by a route that is not the gateway's, inside the window.
    await fetch(`${target.baseUrl}${CUSTOMER}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ blocked: "All" }),
    });
    await teardown();
    expect(chained(io, "REFUSAL_OBSERVATION")).toEqual([
      expect.objectContaining({
        refusal: "BLOCK",
        outcome: "CHANGED",
        version_before: version,
        version_after: target.etag,
      }),
    ]);
    expect(target.etag).not.toBe(version);
  });

  it("reads nothing after a refusal when observeRefusals is false, or after a write it never read", async () => {
    await build({ observeRefusals: false });
    verdict = "BLOCK";
    const reads = target.reads();
    expect((await change({ blocked: "All" })).status).toBe(403);
    await teardown();
    expect(target.reads() - reads).toBe(1);
    expect(chained(io, "REFUSAL_OBSERVATION")).toEqual([]);
    await build();
    const created = await fetch(`${origin}/companies(${COMPANY})/salesOrders`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ customerNumber: "C-10000" }),
    });
    await teardown();
    expect(created.status).toBe(403);
    expect(target.reads() - reads).toBe(1);
    expect(chained(io, "REFUSAL_OBSERVATION")).toEqual([]);
  });

  it("records an after-read that states no version as UNREADABLE", async () => {
    await build();
    verdict = "BLOCK";
    const version = target.etag;
    duringDecision = () => {
      target.unversioned = true;
    };
    expect((await change({ blocked: "All" })).status).toBe(403);
    await teardown();
    duringDecision = () => undefined;
    target.unversioned = false;
    expect(chained(io, "REFUSAL_OBSERVATION")).toEqual([
      expect.objectContaining({
        outcome: "UNREADABLE",
        version_before: version,
        version_after: null,
      }),
    ]);
  });

  it("refuses a write whose target states no usable version, before the authority is asked", async () => {
    await build();
    verdict = "ALLOW";
    const asked = decided.length;
    const writes = target.writes();
    target.unversioned = true;
    const unstated = await change({ blocked: "All" });
    target.unversioned = false;
    target.missing = true;
    const missing = await change({ blocked: "All" });
    target.missing = false;
    await teardown();
    expect(unstated.status).toBe(502);
    expect(await unstated.json()).toMatchObject({
      state: "ERROR",
      reason_codes: ["TARGET_STATE_UNREADABLE", "TARGET_VERSION_UNSTATED"],
      execution: "NOT_FORWARDED",
    });
    expect(await missing.json()).toMatchObject({
      reason_codes: ["TARGET_STATE_UNREADABLE", "UPSTREAM_STATUS_404"],
    });
    expect(decided.length).toBe(asked);
    expect(target.writes()).toBe(writes);
    expect(chained(io, "TARGET_STATE_UNREADABLE").map((line) => line["reason_codes"])).toEqual([
      ["TARGET_STATE_UNREADABLE", "TARGET_VERSION_UNSTATED"],
      ["TARGET_STATE_UNREADABLE", "UPSTREAM_STATUS_404"],
    ]);
    expect(gateway.metricsText()).toContain(
      'agentsafe_requests_total{kind="target_state_unreadable"} 2',
    );
  });

  it("reads nothing in shadow, which changes nothing about a call", async () => {
    await build({}, { mode: "shadow" });
    verdict = "BLOCK";
    const reads = target.reads();
    const answer = await change({ displayName: "Shadowed" });
    await new Promise((resolve) => setTimeout(resolve, 50));
    await teardown();
    expect(answer.status).toBe(200);
    expect(target.reads()).toBe(reads);
    expect(chained(io, "REFUSAL_OBSERVATION")).toEqual([]);
  });
});
