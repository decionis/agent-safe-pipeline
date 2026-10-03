import { afterEach, describe, expect, it } from "vitest";
import { Gateway, type GatewayContinuation } from "../../src/gateway/Gateway.js";
import {
  proofToken,
  UPSTREAM_PROOF_HEADER,
  UPSTREAM_PROOF_PATH,
  type TxtResolver,
} from "../../src/gateway/UpstreamProof.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import {
  collectedIo,
  testConfig,
  TENANT_KEY,
  TENANT_KEY_DIGEST,
  type CollectedIo,
} from "../support/GatewayHarness.js";

const WORKSPACE = "00000000-0000-4000-8000-000000000009";
const UPSTREAM = "https://api.acme.example/v2";
const ORIGIN = "https://api.acme.example";
const PROOF_URL = `${ORIGIN}${UPSTREAM_PROOF_PATH}`;
const GLOBEX = "https://api.globex.example";
/** An origin assembled from its parts, so no literal scheme sits beside a template hole. */
const origin = (scheme: "http" | "https", host: string, port: number): string =>
  `${scheme}://${host}:${port}`;
const TOKEN = proofToken({ tenant: "acme", org: WORKSPACE, origin: ORIGIN }, 1_759_492_800);

/** A hosted gateway for tenant `acme` that requires its upstream's proof. */
const hostedEnv = (): Record<string, string> => ({
  AGENTSAFE_HOSTED_GATEWAY: "true",
  AGENTSAFE_HOSTED_TENANT: "acme",
  AGENTSAFE_TENANT_KEY_DIGESTS: TENANT_KEY_DIGEST,
  AGENTSAFE_UPSTREAM_PROOF_REQUIRED: "true",
  DECIONIS_API_KEY: "synthetic-workspace-key",
  DECIONIS_API_URL: "https://api.decionis.example",
  DECIONIS_TENANT_ID: WORKSPACE,
});

interface Upstream {
  /** What the proof's path answers; null is a 404. */
  proof: string | null;
  readonly seen: string[];
}

interface Running {
  readonly gateway: Gateway;
  readonly io: CollectedIo;
  readonly upstream: Upstream;
  readonly port: number;
  readonly server: GatewayHttpServer;
}

const running: Running[] = [];

afterEach(async () => {
  for (const entry of running.splice(0)) {
    await entry.server.close(0);
    await entry.gateway.close();
  }
});

async function start(
  options: {
    readonly proof?: string | null;
    readonly txt?: TxtResolver;
    readonly continues?: GatewayContinuation;
    readonly upstream?: string;
  } = {},
): Promise<Running> {
  const upstream: Upstream = { proof: options.proof ?? null, seen: [] };
  const io = collectedIo();
  const env = hostedEnv();
  const gateway = await Gateway.create(testConfig(options.upstream ?? UPSTREAM, { env }), {
    env,
    io,
    upstreamFetch: async (input) => {
      const url = String(input);
      upstream.seen.push(url);
      if (url.endsWith(UPSTREAM_PROOF_PATH)) {
        return upstream.proof === null
          ? new Response("not here", { status: 404 })
          : new Response(upstream.proof, { status: 200 });
      }
      return new Response('{"orders":[]}', {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
    upstreamResolveTxt:
      options.txt ??
      (async () => {
        throw Object.assign(new Error("no record"), { code: "ENODATA" });
      }),
    ...(options.continues === undefined ? {} : { continues: options.continues }),
  });
  const server = new GatewayHttpServer(gateway);
  const { port } = await server.listen(0, "127.0.0.1");
  const entry = { gateway, io, upstream, port, server };
  running.push(entry);
  return entry;
}

/** Waits for the gateway's first look at its upstream's proof to end. */
async function looked(gateway: Gateway): Promise<void> {
  for (let attempt = 0; attempt < 200 && !gateway.upstreamProofSettled; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  expect(gateway.upstreamProofSettled).toBe(true);
}

async function get(
  port: number,
  key: string | null,
  path = "/orders",
): Promise<{ status: number; headers: Headers; body: Record<string, unknown> | string }> {
  const response = await fetch(new URL(path, origin("http", "127.0.0.1", port)), {
    headers: key === null ? {} : { "agentsafe-tenant-key": key },
  });
  const text = await response.text();
  let body: Record<string, unknown> | string = text;
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {
    // not JSON: kept as text
  }
  return { status: response.status, headers: response.headers, body };
}

const securityLines = (io: CollectedIo): Record<string, unknown>[] =>
  [...io.out, ...io.err]
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter(
      (line) => typeof line["event"] === "string" && String(line["event"]).startsWith("UPSTREAM_"),
    );

describe("a hosted gateway that requires its upstream's proof", () => {
  it("forwards nothing while the proof is not served, and says so only after the tenant key admits the request", async () => {
    const { gateway, io, upstream, port } = await start();
    await looked(gateway);
    expect(upstream.seen).toEqual([PROOF_URL]);

    // A caller without the tenant's key learns nothing about the proof.
    const missing = await get(port, null);
    expect([missing.status, missing.body]).toEqual([401, { code: "TENANT_KEY_MISSING" }]);
    const wrong = await get(port, "synthetic-wrong-key");
    expect([wrong.status, wrong.body]).toEqual([401, { code: "TENANT_KEY_INVALID" }]);

    const refused = await get(port, TENANT_KEY);
    expect(refused.status).toBe(503);
    expect(refused.body).toEqual({
      version: "agent-safe.gateway/1",
      state: "ERROR",
      verdict: null,
      reason_codes: ["UPSTREAM_UNVERIFIED"],
      execution: "NOT_FORWARDED",
      fallback: UPSTREAM,
    });
    expect(refused.headers.get("agentsafe-execution")).toBe("NOT_FORWARDED");
    expect(refused.headers.get("retry-after")).toBe("60");
    // Nothing went to the upstream but the look for the proof.
    expect(upstream.seen).toEqual([PROOF_URL]);
    // The gateway's own routes are not the tenant's traffic.
    expect((await get(port, null, "/_agentsafe/healthz")).status).toBe(200);

    expect(securityLines(io)).toMatchObject([
      { event: "UPSTREAM_UNVERIFIED", origin: ORIGIN, code: "UPSTREAM_PROOF_NOT_SERVED" },
    ]);
    expect(gateway.status().hosted?.upstream_proof).toMatchObject({
      state: "unverified",
      method: null,
      stops_at: null,
      code: null,
    });
    expect(gateway.status().counts["upstream_unverified"]).toBe(1);
  });

  it("forwards once the origin serves a token bound to the tenant, its workspace and the origin", async () => {
    const { gateway, upstream, port } = await start({ proof: `# acme\n${TOKEN}\n` });
    await looked(gateway);
    expect(gateway.upstreamProof()).toBe("FORWARD");
    const answer = await get(port, TENANT_KEY);
    expect([answer.status, answer.body]).toEqual([200, { orders: [] }]);
    expect(answer.headers.get("agentsafe-execution")).toBe("PASSTHROUGH");
    expect(answer.headers.get(UPSTREAM_PROOF_HEADER)).toBeNull();
    expect(upstream.seen).toEqual([PROOF_URL, `${UPSTREAM}/orders`]);
    expect(gateway.status().hosted?.upstream_proof).toMatchObject({
      state: "verified",
      method: "file",
    });
  });

  it("takes a TXT record once the origin has answered, and never a token bound to another tenant", async () => {
    const other = proofToken({ tenant: "globex", org: WORKSPACE, origin: ORIGIN }, 1_759_492_800);
    const names: string[] = [];
    const byDns = await start({
      proof: other,
      txt: async (name) => {
        names.push(name);
        return [[TOKEN]];
      },
    });
    await looked(byDns.gateway);
    expect(names).toEqual(["_agentsafe-challenge.api.acme.example"]);
    expect(byDns.gateway.status().hosted?.upstream_proof).toMatchObject({
      state: "verified",
      method: "dns",
    });
    expect((await get(byDns.port, TENANT_KEY)).status).toBe(200);

    const neither = await start({ proof: other });
    await looked(neither.gateway);
    expect((await get(neither.port, TENANT_KEY)).status).toBe(503);
  });

  it("marks what it forwards while the proof is missing, and a rebuild bound the same way keeps where the proof stood", async () => {
    const proven = await start({ proof: TOKEN });
    await looked(proven.gateway);
    const handed = proven.gateway.continuation();
    expect(handed.proof?.state).toEqual({ kind: "verified", method: "file" });

    // Rebuilt for any other reason: no look, no refusal, no wait.
    const rebuilt = await start({ continues: handed });
    expect(rebuilt.gateway.upstreamProofSettled).toBe(true);
    expect((await get(rebuilt.port, TENANT_KEY)).status).toBe(200);
    expect(rebuilt.upstream.seen).toEqual([`${UPSTREAM}/orders`]);

    // Handed on while missing: forwarded, and the tenant is told.
    const since = Date.now() - 60_000;
    const binding = handed.proof?.binding;
    if (binding === undefined) throw new Error("expected a proof to hand on");
    const marked = await start({
      continues: { ...handed, proof: { binding, state: { kind: "missing", since } } },
    });
    const answer = await get(marked.port, TENANT_KEY);
    expect(answer.status).toBe(200);
    expect(answer.headers.get(UPSTREAM_PROOF_HEADER)).toBe("missing");
    expect(marked.gateway.status().hosted?.upstream_proof).toMatchObject({
      state: "missing",
      stops_at: new Date(since + 72 * 60 * 60 * 1_000).toISOString(),
    });

    // A rebuild for another origin proves that origin from the start.
    const moved = await start({ continues: handed, upstream: GLOBEX });
    await looked(moved.gateway);
    expect(moved.upstream.seen).toEqual([`${GLOBEX}${UPSTREAM_PROOF_PATH}`]);
    expect((await get(moved.port, TENANT_KEY)).status).toBe(503);
  });

  it("stops looking once it has handed its proof on", async () => {
    const { gateway, upstream } = await start({ proof: TOKEN });
    await looked(gateway);
    gateway.handedOn();
    expect(gateway.status().hosted?.upstream_proof?.state).toBe("verified");
    expect(upstream.seen).toEqual([PROOF_URL]);
  });
});

describe("a gateway that requires no proof", () => {
  it("forwards as it always did, and has nothing to wait for", async () => {
    const env = { ...hostedEnv(), AGENTSAFE_UPSTREAM_PROOF_REQUIRED: "false" };
    const gateway = await Gateway.create(testConfig(UPSTREAM, { env }), {
      env,
      io: collectedIo(),
      upstreamFetch: async () => new Response("ok"),
    });
    expect(gateway.upstreamProofSettled).toBe(true);
    expect(gateway.upstreamProof()).toBe("FORWARD");
    expect(gateway.status().hosted?.upstream_proof).toBeNull();
    expect(gateway.continuation().proof).toBeNull();
    await gateway.close();
  });
});
