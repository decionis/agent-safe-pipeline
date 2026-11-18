import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  LOCAL_AUTHORITY_API_KEY,
  LocalAuthority,
  LocalPresence,
} from "@decionis/agent-safe-pipeline/testing";
import { Gateway } from "../../src/gateway/Gateway.js";
import { GatewayConfigError } from "../../src/gateway/GatewayConfig.js";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import {
  collectedIo,
  LOOPBACK_ORIGIN,
  testConfig,
  UpstreamDouble,
} from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const COMPANY = "c0ffee00-0000-4000-8000-000000000001";

/**
 * Every part of the request that is not a fact the profile names carries a
 * canary. The authority must see none of them, in any byte of any call.
 */
const CANARIES = {
  path: "PATHCANARY",
  query: "QUERYCANARY",
  authorization: "AUTHCANARY",
  correlation: "CORRELCANARY",
  idempotency: "IDEMCANARY",
  header: "HEADERCANARY",
  body: "BODYCANARY",
} as const;

const salesOrder = {
  customerNumber: "10000",
  currencyCode: "USD",
  externalDocumentNumber: "EXT-1",
  comment: `deliver to ${CANARIES.body}`,
  salesOrderLines: [{ lineType: "Item", lineObjectNumber: "1896-S", quantity: 2 }],
};
const PATH = `/v2.0/tenant-${CANARIES.path}/production/api/v2.0/companies(${COMPANY})/salesOrders`;

function call(path = PATH, body: unknown = salesOrder): InterceptedRequest {
  return {
    method: "POST",
    path,
    search: `?note=${CANARIES.query}`,
    headers: {
      host: "gateway.example",
      "content-type": "application/json",
      authorization: `Bearer ${CANARIES.authorization}`,
      "x-request-id": CANARIES.correlation,
      "idempotency-key": CANARIES.idempotency,
      "x-tenant-note": CANARIES.header,
    },
    body: Buffer.from(JSON.stringify(body), "utf8"),
    remoteAddress: "127.0.0.1",
    encrypted: false,
  };
}

/** Everything a fetch to the authority carried: its address, its headers and its body. */
interface Sent {
  readonly url: string;
  readonly text: string;
}

function spying(sent: Sent[]): typeof fetch {
  return async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    const headers = JSON.stringify([...new Headers(init?.headers ?? {}).entries()]);
    const body =
      init?.body === undefined || init.body === null
        ? ""
        : typeof init.body === "string"
          ? init.body
          : Buffer.from(init.body as Uint8Array).toString("utf8");
    sent.push({ url, text: `${url}\n${headers}\n${body}` });
    return await fetch(input, init);
  };
}

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 50));
const FACTS_FILE = {
  version: 1,
  interception: { profile: "businesscentral/api/v2", privacy: "facts" },
};

describe("the facts-only setting", () => {
  it("is full by default, and facts from the file or the environment", () => {
    expect(testConfig("http://127.0.0.1:1").interception.privacy).toBe("FULL");
    expect(testConfig("http://127.0.0.1:1", { file: FACTS_FILE }).interception.privacy).toBe(
      "FACTS",
    );
    const env = testConfig("http://127.0.0.1:1", {
      env: { AGENTSAFE_PRIVACY: "facts", AGENTSAFE_PROFILE: "walmart/api/v3" },
    });
    expect(env.interception.privacy).toBe("FACTS");
    expect(env.sources["interception.privacy"]).toBe("environment");
  });

  it("refuses, by name, every setting that would send a raw part of the request", () => {
    const refused = (file: Record<string, unknown>, env: Record<string, string> = {}): string => {
      try {
        testConfig("http://127.0.0.1:1", { file: { version: 1, ...file }, env });
      } catch (error) {
        if (error instanceof GatewayConfigError) return `${error.code} ${error.setting}`;
        throw error;
      }
      throw new Error("expected a refusal");
    };
    expect(refused({ interception: { privacy: "facts" } })).toBe(
      "CONFIG_MISSING interception.profile",
    );
    expect(
      refused({
        interception: {
          privacy: "facts",
          profile: "walmart/api/v3",
          routes: [{ path: "/payments", action: "payment.create" }],
        },
      }),
    ).toBe("CONFIG_INVALID interception.routes");
    expect(
      refused({
        interception: { privacy: "facts", profile: "walmart/api/v3", principalHeader: "x-agent" },
      }),
    ).toBe("CONFIG_INVALID interception.principalHeader");
    expect(
      refused({
        interception: { privacy: "facts", profile: "walmart/api/v3", unmatched: "passthrough" },
      }),
    ).toBe("CONFIG_INVALID interception.unmatched");
    expect(refused({ interception: { privacy: "names" } })).toBe(
      "CONFIG_INVALID interception.privacy",
    );
    expect(refused({}, { AGENTSAFE_PRIVACY: "some" })).toBe("CONFIG_INVALID AGENTSAFE_PRIVACY");
  });
});

describe("a facts-only gateway", () => {
  const upstream = new UpstreamDouble();
  const authority = new LocalAuthority({ policy: () => "ALLOW" });
  const env = {
    DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
    DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    DECIONIS_TENANT_ID: TENANT_ID,
  };
  beforeAll(async () => {
    await upstream.start();
    await authority.start();
  });
  afterAll(async () => {
    await authority.stop();
    await upstream.stop();
  });

  async function gatewayFor(mode: "enforcement" | "shadow", sent: Sent[]): Promise<Gateway> {
    const withUrl = { ...env, DECIONIS_API_URL: authority.baseUrl, AGENTSAFE_MODE: mode };
    return await Gateway.create(testConfig(upstream.baseUrl, { env: withUrl, file: FACTS_FILE }), {
      env: withUrl,
      io: collectedIo(),
      version: "9.9.9",
      authorityFetch: spying(sent),
    });
  }

  function expectNoCanary(sent: readonly Sent[]): void {
    expect(sent.length).toBeGreaterThan(0);
    for (const { text } of sent) {
      for (const canary of Object.values(CANARIES)) expect(text).not.toContain(canary);
      // Not even the plain digests, which a guess of a small body or a path could confirm.
      expect(text).not.toMatch(/request_sha256|body_sha256|body_bytes|content_type/);
    }
  }

  it("sends the authority the operation, its template and the named facts, and no raw byte", async () => {
    const sent: Sent[] = [];
    const gateway = await gatewayFor("enforcement", sent);
    const plan = gateway.plan("POST", PATH, `?note=${CANARIES.query}`);
    expect(plan).toMatchObject({ kind: "GOVERN", action: "sales.create" });
    const before = upstream.seen.length;
    const answer = await gateway.govern(call(), "sales.create");
    await settle();
    await gateway.close();
    expect(answer.status).toBe(201);
    expectNoCanary(sent);

    const evaluated = sent.find(({ url }) => url.endsWith("/v1/authority/grants"));
    const binding = JSON.parse(evaluated?.text.split("\n").slice(2).join("\n") ?? "{}") as {
      action: { type: string; resource: string; parameters: Record<string, unknown> };
      context: Record<string, unknown>;
    };
    expect(binding.action).toEqual({
      type: "sales.create",
      resource: "POST /companies({companyId})/salesOrders",
      parameters: {
        method: "POST",
        operation: "salesOrders.create",
        path_template: "/companies({companyId})/salesOrders",
      },
    });
    expect(binding.context).toMatchObject({
      company_id: COMPANY,
      environment: "production",
      customer_number: "10000",
      currency_code: "USD",
      external_document_number: "EXT-1",
      api_profile: { id: "businesscentral/api/v2", operation: "salesOrders.create" },
      ingress: "http",
    });
    expect(binding.context["request_hmac_sha256"]).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(binding.context["idempotency_key"]).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);

    // The upstream still receives the request exactly as the agent sent it.
    const forwarded = upstream.seen.slice(before).at(-1);
    expect(forwarded?.url).toBe(`${PATH}?note=${CANARIES.query}`);
    expect(forwarded?.headers["authorization"]).toBe(`Bearer ${CANARIES.authorization}`);
    expect(JSON.parse(forwarded?.body ?? "{}")).toEqual(salesOrder);
  });

  it("would see the raw request if it were sent: full privacy carries the path, query and body", async () => {
    const sent: Sent[] = [];
    const withUrl = { ...env, DECIONIS_API_URL: authority.baseUrl, AGENTSAFE_MODE: "enforcement" };
    const gateway = await Gateway.create(
      testConfig(upstream.baseUrl, {
        env: withUrl,
        file: { version: 1, interception: { profile: "businesscentral/api/v2" } },
      }),
      { env: withUrl, io: collectedIo(), version: "9.9.9", authorityFetch: spying(sent) },
    );
    await gateway.govern(call(), "sales.create");
    await settle();
    await gateway.close();
    const all = sent.map(({ text }) => text).join("\n");
    for (const canary of [CANARIES.path, CANARIES.query, CANARIES.body, CANARIES.idempotency]) {
      expect(all).toContain(canary);
    }
  });

  it("sends no raw byte in shadow either", async () => {
    const sent: Sent[] = [];
    const gateway = await gatewayFor("shadow", sent);
    const answer = await gateway.govern(call(), "sales.create");
    await settle();
    await gateway.close();
    expect(answer.status).toBe(201);
    expectNoCanary(sent);
  });

  it("refuses a call no profile operation names, and asks the authority nothing", async () => {
    const sent: Sent[] = [];
    const gateway = await gatewayFor("enforcement", sent);
    const server = new GatewayHttpServer(gateway);
    const { port } = await server.listen(0, "127.0.0.1");
    const before = upstream.seen.length;
    const response = await fetch(
      `${LOOPBACK_ORIGIN}:${port}/v2.0/production/api/v2.0/companies(${COMPANY})/notes?q=${CANARIES.query}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: CANARIES.body }),
      },
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ code: "PROFILE_OPERATION_UNMATCHED" });
    expect(response.headers.get("agentsafe-execution")).toBe("NOT_FORWARDED");
    // A read is not governed, so it still passes through.
    const read = await fetch(`${LOOPBACK_ORIGIN}:${port}/v2.0/production/api/v2.0/companies`);
    expect(read.status).toBe(200);
    await server.close(10);
    await gateway.close();
    expect(sent.filter(({ url }) => url.includes("/v1/authority/"))).toEqual([]);
    expect(upstream.seen.slice(before).map((seen) => seen.method)).toEqual(["GET"]);
  });
});

describe("facts-only digests keyed from the tenant's key in custody", () => {
  let verdict: "ALLOW" | "ESCALATE" = "ALLOW";
  const upstream = new UpstreamDouble();
  const presence = new LocalPresence({
    pendingLookups: 1,
    roles: { "synthetic-policy-approver": "FINANCE_LEAD" },
  });
  const authority = new LocalAuthority({
    presence,
    policy: () => verdict,
    managedApproverId: "synthetic-policy-approver",
  });
  const root = mkdtempSync(join(tmpdir(), "agentsafe-digest-key-"));
  const keyText = randomBytes(32).toString("base64url");
  const keyFile = join(root, "digest-key");
  writeFileSync(keyFile, `${keyText}\n`, { mode: 0o600 });
  const env = {
    DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
    DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    DECIONIS_TENANT_ID: TENANT_ID,
    AGENTSAFE_MODE: "enforcement",
  };
  beforeAll(async () => {
    await upstream.start();
    await presence.start();
    await authority.start();
  });
  afterAll(async () => {
    await authority.stop();
    await presence.stop();
    await upstream.stop();
    rmSync(root, { recursive: true, force: true });
  });

  const file = (
    interception: Record<string, unknown> = {},
    extra: Record<string, unknown> = {},
  ) => ({
    version: 1,
    interception: { profile: "businesscentral/api/v2", privacy: "facts", ...interception },
    ...extra,
  });

  async function replica(
    sent: Sent[],
    io = collectedIo(),
    options: {
      readonly key?: boolean;
      readonly tenant?: string;
      readonly extra?: Record<string, unknown>;
      readonly env?: Record<string, string>;
    } = {},
  ): Promise<Gateway> {
    const live = {
      ...env,
      DECIONIS_API_URL: authority.baseUrl,
      ...(options.tenant === undefined ? {} : { DECIONIS_TENANT_ID: options.tenant }),
      ...(options.env ?? {}),
    };
    const config = file(options.key === false ? {} : { digestKeyFile: keyFile }, options.extra);
    return await Gateway.create(testConfig(upstream.baseUrl, { env: live, file: config }), {
      env: live,
      io,
      version: "9.9.9",
      authorityFetch: spying(sent),
    });
  }

  /** The keyed values one call stated to the authority. */
  async function keyedOf(gateway: Gateway): Promise<{ request: unknown; idempotency: unknown }> {
    const before = authority.requests.length;
    const answer = await gateway.govern(call(), "sales.create");
    expect(answer.status).toBe(201);
    const asked = authority.requests
      .slice(before)
      .find((seen) => seen.path === "/v1/authority/grants");
    const context = (asked?.body as { context: Record<string, unknown> }).context;
    return { request: context["request_hmac_sha256"], idempotency: context["idempotency_key"] };
  }

  it("is refused without facts-only privacy, and by a relative path or an unreadable key", async () => {
    const refused = (fileValue: unknown): string | null => {
      try {
        testConfig("http://127.0.0.1:1", { file: fileValue });
        return null;
      } catch (error) {
        if (error instanceof GatewayConfigError) return `${error.code} ${error.setting}`;
        throw error;
      }
    };
    expect(
      refused({
        version: 1,
        interception: { profile: "businesscentral/api/v2", digestKeyFile: keyFile },
      }),
    ).toBe("CONFIG_INVALID interception.digestKeyFile");
    expect(refused(file({ digestKeyFile: "custody/digest-key" }))).toBe(
      "CONFIG_INVALID interception.digestKeyFile",
    );
    expect(refused(file({ digestKeyFile: keyFile }))).toBeNull();
    expect(
      testConfig("http://127.0.0.1:1", { file: file() }).interception.digestKeyFile,
    ).toBeNull();

    const short = join(root, "short-key");
    writeFileSync(short, randomBytes(16).toString("base64url"));
    for (const path of [short, join(root, "missing-key")]) {
      const live = { ...env, DECIONIS_API_URL: authority.baseUrl };
      await expect(
        Gateway.create(
          testConfig(upstream.baseUrl, { env: live, file: file({ digestKeyFile: path }) }),
          {
            env: live,
            io: collectedIo(),
          },
        ),
      ).rejects.toThrow(/^CONFIG_INVALID: interception\.digestKeyFile/);
    }
  });

  it("states the same keyed digests from every replica, and only for this tenant", async () => {
    const [a, b] = [await replica([]), await replica([])];
    const fromA = await keyedOf(a);
    const fromB = await keyedOf(b);
    expect(fromA.request).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(fromA.idempotency).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
    expect(fromB).toEqual(fromA);
    await a.close();
    await b.close();

    // A restarted replica derives the same key again.
    const restarted = await replica([]);
    expect(await keyedOf(restarted)).toEqual(fromA);
    await restarted.close();

    // Without the key each process keys with its own secret, as before.
    const [c, d] = [
      await replica([], collectedIo(), { key: false }),
      await replica([], collectedIo(), { key: false }),
    ];
    const fromC = await keyedOf(c);
    const fromD = await keyedOf(d);
    expect(fromC.request).not.toEqual(fromD.request);
    expect(fromC.idempotency).not.toEqual(fromD.idempotency);
    expect(fromC.request).not.toEqual(fromA.request);
    await c.close();
    await d.close();

    // Another tenant mounting the same file derives another key.
    const other = await replica([], collectedIo(), {
      tenant: "00000000-0000-4000-8000-000000000010",
    });
    const fromOther = await keyedOf(other);
    expect(fromOther.request).not.toEqual(fromA.request);
    expect(fromOther.idempotency).not.toEqual(fromA.idempotency);
    await other.close();
  });

  it("lets another replica resume a durable hold, and never logs or sends the key or the raw request", async () => {
    const holdKey = join(root, "hold-key");
    writeFileSync(holdKey, randomBytes(32).toString("base64url"), { mode: 0o600 });
    const durable = {
      extra: { holds: { dir: join(root, "holds"), keyFile: holdKey } },
      env: { AGENTSAFE_PRESENCE_MANAGED: "true" },
    };
    const sent: Sent[] = [];
    const ios = [collectedIo(), collectedIo()];
    const first = await replica(sent, ios[0], durable);
    verdict = "ESCALATE";
    const held = await first.govern(call(), "sales.create");
    expect(held.status).toBe(202);
    const body = JSON.parse(held.body.toString("utf8")) as Record<string, unknown>;
    await first.close();

    const second = await replica(sent, ios[1], durable);
    const before = upstream.seen.length;
    let resumed = await second.resume(String(body["intent_id"]), String(body["resume_token"]));
    for (let attempt = 0; attempt < 6 && resumed.status === 202; attempt += 1) {
      await settle();
      resumed = await second.resume(String(body["intent_id"]), String(body["resume_token"]));
    }
    verdict = "ALLOW";
    expect(resumed.status).toBe(201);
    expect(upstream.seen.length).toBe(before + 1);
    await second.close();

    expectNoRawOrKey(sent, ios);
  }, 30_000);

  function expectNoRawOrKey(
    sent: readonly Sent[],
    ios: readonly { out: string[]; err: string[] }[],
  ) {
    const keyBytes = Buffer.from(keyText, "base64url");
    const secrets = [keyText, keyBytes.toString("hex"), keyBytes.toString("base64")];
    expect(sent.length).toBeGreaterThan(0);
    for (const { text } of sent) {
      for (const canary of Object.values(CANARIES)) expect(text).not.toContain(canary);
      for (const secret of secrets) expect(text).not.toContain(secret);
      expect(text).not.toMatch(/request_sha256|body_sha256|body_bytes|content_type/);
    }
    for (const io of ios) {
      for (const line of [...io.out, ...io.err]) {
        for (const secret of secrets) expect(line).not.toContain(secret);
        expect(line).not.toContain(keyFile);
      }
    }
  }
});
