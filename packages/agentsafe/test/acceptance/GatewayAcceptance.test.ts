import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { ACCEPTANCE_PLAN_VERSION } from "../../src/acceptance/AcceptancePlan.js";
import { readAcceptanceReport } from "../../src/acceptance/AcceptanceReport.js";
import { ACCEPTANCE_RUN_HEADER } from "../../src/acceptance/AcceptanceRun.js";
import type { ZoneFindings } from "../../src/acceptance/ZoneProbes.js";
import { Gateway, type GatewayStatus } from "../../src/gateway/Gateway.js";
import type { GatewayConfigError } from "../../src/gateway/GatewayConfig.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import { SecretError } from "../../src/secrets/SecretStore.js";
import { runAccept } from "../../src/cli/Accept.js";
import { runVerifyAcceptance } from "../../src/cli/VerifyAcceptance.js";
import { stringify as toYaml } from "yaml";
import {
  collectedIo,
  LOOPBACK_ORIGIN,
  testConfig,
  type CollectedIo,
  fakeProcess,
} from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const COMPANY = "6f3c1a52-1d2e-4f5a-8b9c-0d1e2f3a4b5c";
const CUSTOMER = `/companies(${COMPANY})/customers(9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d)`;
const CANARY = `/companies(${COMPANY})/customers(00000000-0000-4000-8000-0000000000ca)`;
const OPERATOR_TOKEN = "synthetic-operator-token";
const noZone: ZoneFindings = {
  origins: [],
  providers: [],
  mcp: [],
  credentials: [],
  metadata: null,
};

/** One versioned record per path, shaped as Business Central answers it; a write applies its body and moves the version. */
class VersionedTarget {
  public readonly seen: { method: string; url: string; headers: IncomingMessage["headers"] }[] = [];
  private readonly records = new Map<
    string,
    { version: number; record: Record<string, unknown> }
  >();
  private server: Server | null = null;
  private port = 0;

  public get baseUrl(): string {
    return `${LOOPBACK_ORIGIN}:${this.port}`;
  }

  public writes(): number {
    return this.seen.filter((request) => request.method !== "GET").length;
  }

  public version(path: string): number {
    return this.entry(path).version;
  }

  private entry(path: string): { version: number; record: Record<string, unknown> } {
    let entry = this.records.get(path);
    if (entry === undefined) {
      entry = { version: 1, record: { number: "C-1", blocked: " " } };
      this.records.set(path, entry);
    }
    return entry;
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
    const url = request.url ?? "/";
    this.seen.push({ method, url, headers: request.headers });
    const entry = this.entry(url);
    if (method !== "GET") {
      entry.record = {
        ...entry.record,
        ...(JSON.parse(Buffer.concat(chunks).toString() || "{}") as object),
      };
      entry.version += 1;
    }
    response.writeHead(200, { "content-type": "application/json", connection: "close" });
    response.end(JSON.stringify({ "@odata.etag": `W/"${entry.version}"`, ...entry.record }));
  }
}

const parsed = (io: CollectedIo): Record<string, unknown>[] =>
  io.out.map((line) => JSON.parse(line) as Record<string, unknown>);

describe("a gateway that serves acceptance runs", () => {
  const target = new VersionedTarget();
  const authority = new LocalAuthority({
    // The canary's change is the one the policy refuses.
    policy: (request) =>
      (request.action as { parameters?: { body?: { blocked?: string } } }).parameters?.body
        ?.blocked === "All"
        ? "BLOCK"
        : "ALLOW",
    trustedEffectObserverIds: [LOCAL_AUTHORITY_API_KEY],
  });
  let directory: string;
  let gateway: Gateway;
  let server: GatewayHttpServer;
  let origin: string;
  let io: CollectedIo;

  const env = (): Record<string, string> => ({
    DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
    DECIONIS_API_URL: authority.baseUrl,
    DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    DECIONIS_TENANT_ID: TENANT_ID,
    DECIONIS_TIMEOUT_MS: "500",
    AGENTSAFE_MODE: "enforcement",
  });

  const file = (acceptance: Record<string, unknown> | null): Record<string, unknown> => ({
    version: 1,
    interception: { profile: "businesscentral/api/v2", refusalWindowMs: 50 },
    evidence: { observer: LOCAL_AUTHORITY_API_KEY },
    ...(acceptance === null ? {} : { acceptance }),
  });

  const acceptance = (): Record<string, unknown> => ({
    key: { file: join(directory, "acceptance.pem") },
    operatorToken: { file: join(directory, "operator-token") },
  });

  async function build(section: Record<string, unknown> | null = acceptance()): Promise<void> {
    io = collectedIo();
    gateway = await Gateway.create(
      testConfig(target.baseUrl, { env: env(), file: file(section) }),
      {
        env: env(),
        io,
        version: "9.9.9",
      },
    );
    server = new GatewayHttpServer(gateway);
    origin = `${LOOPBACK_ORIGIN}:${(await server.listen(0, "127.0.0.1")).port}`;
  }

  async function teardown(): Promise<void> {
    await server.close(10);
    await gateway.close();
  }

  async function call(
    path: string,
    body: unknown,
    token: string | null = OPERATOR_TOKEN,
  ): Promise<Response> {
    return await fetch(`${origin}/_agentsafe/v1/acceptance/${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token === null ? {} : { authorization: `Bearer ${token}` }),
      },
      body: JSON.stringify(body),
    });
  }

  async function write(path: string, body: unknown, tag?: string): Promise<Response> {
    return await fetch(`${origin}${path}`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        "if-match": "*",
        ...(tag === undefined ? {} : { [ACCEPTANCE_RUN_HEADER]: tag }),
      },
      body: JSON.stringify(body),
    });
  }

  const plan = {
    version: ACCEPTANCE_PLAN_VERSION,
    gateway: "http://gateway.example",
    expires_at: "2099-01-01T00:00:00Z",
    permitted: [{ name: "update", method: "PATCH", path: CUSTOMER, body: { blocked: " " } }],
    prohibited: [
      {
        name: "block",
        method: "PATCH",
        path: CANARY,
        body: { blocked: "All" },
        canary: "the canary customer",
      },
    ],
  };

  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), "agentsafe-acceptance-"));
    const { privateKey } = generateKeyPairSync("ed25519");
    writeFileSync(
      join(directory, "acceptance.pem"),
      privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    );
    writeFileSync(join(directory, "operator-token"), OPERATOR_TOKEN);
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
    writeFileSync(
      join(directory, "rsa.pem"),
      rsa.export({ format: "pem", type: "pkcs8" }).toString(),
    );
    await target.start();
    await authority.start();
  });
  afterAll(async () => {
    await target.stop();
    await authority.stop();
    rmSync(directory, { recursive: true, force: true });
  });

  it("runs a plan end to end and signs what it observed, with the key its status serves", async () => {
    await build();
    const status = (await (await fetch(`${origin}/_agentsafe/status`)).json()) as GatewayStatus;
    expect(status.acceptance?.kid).toMatch(/^[\w-]{43}$/);

    const open = await call("runs", plan);
    expect(open.status).toBe(201);
    const run = (await open.json()) as {
      run_id: string;
      coverage: { governed: { target_read: boolean }[] };
    };
    expect(run.coverage.governed.some((route) => route.target_read)).toBe(true);

    const decided = (await (
      await call("decisions", { run_id: run.run_id, write: "block" })
    ).json()) as {
      verdict: string;
    };
    expect(decided.verdict).toBe("BLOCK");

    const writesBefore = target.writes();
    const allowed = await write(CUSTOMER, { blocked: " " }, `${run.run_id}:update`);
    expect(allowed.status).toBe(200);
    const refused = await write(CANARY, { blocked: "All" }, `${run.run_id}:block`);
    expect([refused.status, refused.headers.get("agentsafe-execution")]).toEqual([
      403,
      "NOT_FORWARDED",
    ]);
    // A request that is not the write the plan names is refused before anything is asked.
    const differs = await write(CUSTOMER, { blocked: "Ship" }, `${run.run_id}:update`);
    expect([differs.status, ((await differs.json()) as { code: string }).code]).toEqual([
      409,
      "ACCEPTANCE_WRITE_DIFFERS",
    ]);

    const closed = await call("close", { run_id: run.run_id, zone: noZone });
    expect(closed.status).toBe(200);
    const { report: token, verdict } = (await closed.json()) as { report: string; verdict: string };
    expect(verdict).toBe("ACCEPTED");
    // One write reached the target: the permitted one. The outage case sent none on.
    expect(target.writes() - writesBefore).toBe(1);
    expect(target.version(CANARY)).toBe(1);
    // The run's header never reached the upstream.
    expect(
      target.seen.every((request) => request.headers[ACCEPTANCE_RUN_HEADER] === undefined),
    ).toBe(true);

    const read = await readAcceptanceReport(token, status.acceptance!.public_jwk);
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    const report = read.report;
    expect(report.fingerprint.digest).toBe(status.fingerprint?.digest);
    expect(report.permitted[0]).toMatchObject({
      verdict: "ALLOW",
      execution: "FORWARDED",
      effect: { confirmation: "CONFIRMED" },
      passed: true,
    });
    expect(report.prohibited[0]).toMatchObject({
      shadow: { verdict: "BLOCK" },
      sent: true,
      verdict: "BLOCK",
      execution: "NOT_FORWARDED",
      observation: { outcome: "UNCHANGED", version_before: 'W/"1"', version_after: 'W/"1"' },
      passed: true,
    });
    expect(
      report.outage.map((item) => [item.name, item.status, item.execution, item.upstream_writes]),
    ).toEqual([
      ["update", 503, "NOT_FORWARDED", 0],
      ["block", 503, "NOT_FORWARDED", 0],
    ]);
    await teardown();
    const events = parsed(io)
      .filter((line) => line["stream"] === "agent-safe.gateway-events/1")
      .map((line) => line["event"]);
    expect(events).toEqual(
      expect.arrayContaining([
        "ACCEPTANCE_RUN_OPENED",
        "ACCEPTANCE_SHADOW_DECIDED",
        "ACCEPTANCE_SIGNED",
      ]),
    );
    expect(io.out.join("\n")).not.toContain(run.run_id);
  });

  it("answers only the operator token, only JSON, and only the endpoints it has", async () => {
    await build();
    expect((await call("runs", plan, null)).status).toBe(401);
    expect((await call("runs", plan, "another-token")).status).toBe(401);
    expect((await call("elsewhere", plan)).status).toBe(404);
    const get = await fetch(`${origin}/_agentsafe/v1/acceptance/runs`, {
      headers: { authorization: `Bearer ${OPERATOR_TOKEN}` },
    });
    expect(get.status).toBe(405);
    const text = await fetch(`${origin}/_agentsafe/v1/acceptance/runs`, {
      method: "POST",
      headers: { authorization: `Bearer ${OPERATOR_TOKEN}`, "content-type": "text/plain" },
      body: "{}",
    });
    expect(text.status).toBe(415);
    for (const body of ["{", "[]", "null"]) {
      const answer = await fetch(`${origin}/_agentsafe/v1/acceptance/runs`, {
        method: "POST",
        headers: { authorization: `Bearer ${OPERATOR_TOKEN}`, "content-type": "application/json" },
        body,
      });
      expect([answer.status, ((await answer.json()) as { code: string }).code]).toEqual([
        400,
        "ACCEPTANCE_BODY_INVALID",
      ]);
    }
    expect((await call("decisions", { run_id: 7, write: "block" })).status).toBe(404);
    await teardown();
  });

  it("serves no run when its configuration names none, and refuses the run header", async () => {
    await build(null);
    expect((await call("runs", plan)).status).toBe(404);
    const status = (await (await fetch(`${origin}/_agentsafe/status`)).json()) as GatewayStatus;
    expect(status.acceptance).toBeNull();
    const tagged = await write(CUSTOMER, { blocked: " " }, "run:update");
    expect([tagged.status, ((await tagged.json()) as { code: string }).code]).toEqual([
      409,
      "ACCEPTANCE_RUN_UNKNOWN",
    ]);
    await teardown();
  });

  it("refuses to start with half the section, a relative path, or a key that is not Ed25519", async () => {
    for (const [section, field] of [
      [{ key: { file: join(directory, "acceptance.pem") } }, "acceptance.operatorToken.file"],
      [{ operatorToken: { file: join(directory, "operator-token") } }, "acceptance.key.file"],
      [{ ...acceptance(), key: { file: "acceptance.pem" } }, "acceptance.key.file"],
    ] as const) {
      expect(() => testConfig(target.baseUrl, { env: env(), file: file(section) })).toThrow(
        expect.objectContaining({ setting: field }) as GatewayConfigError,
      );
    }
    await expect(
      build({ ...acceptance(), key: { file: join(directory, "rsa.pem") } }),
    ).rejects.toThrow(new SecretError("CONFIG_SECRET_INVALID", "AGENTSAFE_ACCEPTANCE_KEY"));
  });

  it("names its key by the configured kid", async () => {
    await build({ ...acceptance(), kid: "acceptance-2026" });
    const status = (await (await fetch(`${origin}/_agentsafe/status`)).json()) as GatewayStatus;
    expect(status.acceptance?.kid).toBe("acceptance-2026");
    await teardown();
  });

  describe("agentsafe accept and verify acceptance", () => {
    const files = (planned: Record<string, unknown>): Record<string, string> => ({
      "/work/plan.yaml": toYaml({ ...plan, gateway: origin, ...planned }),
      "/work/token": `${OPERATOR_TOKEN}\n`,
    });

    it("runs the plan from the zone, writes the signed report, and the pinned key verifies it", async () => {
      await build();
      const io = fakeProcess({
        files: files({ mcp: [{ name: "tools", url: `${LOOPBACK_ORIGIN}:9` }] }),
        fetch,
      });
      await runAccept(io, [
        "--plan",
        "/work/plan.yaml",
        "--token-file",
        "/work/token",
        "--out",
        "/work/run.jws",
      ]);
      expect(io.exits).toEqual([0]);
      expect(io.out.join("")).toContain(
        "Report       ACCEPTED, signed by the gateway, written to /work/run.jws",
      );
      expect(io.out.join("")).toContain("shadow BLOCK, 403 NOT_FORWARDED");
      const token = io.stored.get("/work/run.jws")?.text ?? "";
      const status = (await (await fetch(`${origin}/_agentsafe/status`)).json()) as GatewayStatus;

      const verifier = fakeProcess({
        files: {
          "/work/run.jws": token,
          "/work/key.json": JSON.stringify({ acceptance: status.acceptance }),
          "/work/bare.json": JSON.stringify(status.acceptance?.public_jwk),
        },
        fetch,
      });
      await runVerifyAcceptance(verifier, [
        "/work/run.jws",
        "--key",
        "/work/key.json",
        "--current",
        "--gateway",
        `${origin}/`,
      ]);
      expect(verifier.exits).toEqual([0]);
      expect(verifier.out.join("")).toContain(
        "Acceptance  ACCEPTED, CURRENT (expires 2099-01-01T00:00:00Z)",
      );
      await runVerifyAcceptance(verifier, ["/work/run.jws", "--key", "/work/bare.json", "--json"]);
      expect(verifier.exits).toEqual([0, 0]);
      expect(JSON.parse(verifier.out.at(-1) ?? "{}")).toMatchObject({
        ok: true,
        code: null,
        verdict: "ACCEPTED",
        currency: null,
      });
      await teardown();
      // Another configuration is another deployment: the report is stale against it.
      await build({ ...acceptance(), kid: "acceptance-2027" });
      await runVerifyAcceptance(verifier, [
        "/work/run.jws",
        "--key",
        "/work/key.json",
        "--current",
        "--gateway",
        origin,
      ]);
      expect(verifier.exits.at(-1)).toBe(1);
      expect(verifier.out.at(-1)).toContain("ACCEPTED, STALE: configuration_digest");
      await teardown();
    });

    it("signs NOT_ACCEPTED when the zone reaches an origin directly, and says which", async () => {
      await build();
      const io = fakeProcess({
        files: files({
          prohibited: [],
          origins: [{ name: "erp", url: `${target.baseUrl}${CUSTOMER}` }],
        }),
        fetch,
      });
      await runAccept(io, ["--plan", "/work/plan.yaml", "--token-file", "/work/token", "--json"]);
      expect(io.exits).toEqual([1]);
      expect(JSON.parse(io.out.join(""))).toMatchObject({
        verdict: "NOT_ACCEPTED",
        report: "acceptance.jws",
        failures: ["origin erp: REACHABLE"],
      });
      expect(io.stored.has("acceptance.jws")).toBe(true);
      await teardown();
    });

    it("signs nothing, and says why, when it cannot run", async () => {
      await build();
      const run = async (
        argv: readonly string[],
        stored: Record<string, string> = files({}),
        env: Record<string, string> = {},
      ): Promise<{ exit: number | undefined; event: unknown }> => {
        const io = fakeProcess({ files: stored, fetch, env });
        await runAccept(io, argv);
        return { exit: io.exits[0], event: JSON.parse(io.err.join("") || "{}") };
      };
      const base = ["--plan", "/work/plan.yaml", "--token-file", "/work/token"];
      expect(await run(["--unknown"])).toMatchObject({
        exit: 2,
        event: { event: "ARGUMENT_INVALID" },
      });
      expect(await run([])).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_PLAN_REQUIRED" },
      });
      expect(await run(["--plan", "/work/none.yaml"])).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_PLAN_UNREADABLE" },
      });
      expect(await run(base, { ...files({}), "/work/plan.yaml": "a: [" })).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_PLAN_INVALID", detail: "not YAML" },
      });
      expect(await run(base, { ...files({ expires_at: "soon" }) })).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_PLAN_INVALID" },
      });
      expect(await run(["--plan", "/work/plan.yaml"])).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_TOKEN_REQUIRED" },
      });
      expect(
        await run(["--plan", "/work/plan.yaml"], files({}), {
          AGENTSAFE_ACCEPTANCE_TOKEN_FILE: "/work/none",
        }),
      ).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_TOKEN_REQUIRED" },
      });
      expect(await run([...base, "--tenant-key-file", "/work/none"])).toMatchObject({
        exit: 2,
        event: { event: "TENANT_KEY_UNREADABLE" },
      });
      expect(await run([...base, "--timeout-ms", "5"])).toMatchObject({
        exit: 2,
        event: { event: "ARGUMENT_INVALID", detail: "timeout-ms" },
      });
      expect(await run(base, { ...files({}), "/work/token": "another-token" })).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_RUN_NOT_OPENED", detail: "401 ACCEPTANCE_TOKEN_INVALID" },
      });
      await teardown();
    });

    it("refuses to verify without a report and a key, and fails a report another key signed", async () => {
      const run = async (argv: readonly string[], stored: Record<string, string> = {}) => {
        const io = fakeProcess({ files: stored, fetch });
        await runVerifyAcceptance(io, argv);
        return {
          exit: io.exits[0],
          out: io.out.join(""),
          event: JSON.parse(io.err.join("") || "{}") as unknown,
        };
      };
      const otherKey = JSON.stringify({
        kty: "OKP",
        crv: "Ed25519",
        x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      });
      expect(await run(["--bogus"])).toMatchObject({
        exit: 2,
        event: { event: "ARGUMENT_INVALID" },
      });
      expect(await run(["/work/r.jws"])).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_REPORT_AND_KEY_REQUIRED" },
      });
      expect(await run(["/work/r.jws", "--key", "/work/k.json"])).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_REPORT_UNREADABLE" },
      });
      for (const key of ["{", "[]", JSON.stringify({ kty: "RSA" })]) {
        expect(
          await run(["/work/r.jws", "--key", "/work/k.json"], {
            "/work/r.jws": "x",
            "/work/k.json": key,
          }),
        ).toMatchObject({
          exit: 2,
          event: { event: "ACCEPTANCE_KEY_UNREADABLE" },
        });
      }
      const stored = { "/work/r.jws": "a.b.c", "/work/k.json": otherKey };
      expect(
        await run(["/work/r.jws", "--key", "/work/k.json", "--current"], stored),
      ).toMatchObject({
        exit: 2,
        event: { event: "ACCEPTANCE_GATEWAY_REQUIRED" },
      });
      expect(
        await run(
          [
            "/work/r.jws",
            "--key",
            "/work/k.json",
            "--current",
            "--gateway",
            `${LOOPBACK_ORIGIN}:9`,
          ],
          stored,
        ),
      ).toMatchObject({ exit: 2, event: { event: "GATEWAY_UNREACHABLE" } });
      expect(await run(["/work/r.jws", "--key", "/work/k.json"], stored)).toMatchObject({
        exit: 1,
        out: "Acceptance  NOT VERIFIED (ACCEPTANCE_REPORT_MALFORMED)\n",
      });
    });
  });
});
