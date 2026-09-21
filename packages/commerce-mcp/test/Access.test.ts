import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { promisify } from "node:util";
import {
  chmod,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  unlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { runtimeAccess } from "../src/Access.js";
import { CommerceGateClient, type EvaluateActionInput } from "../src/CommerceGateClient.js";
import { CommerceGateConfiguration } from "../src/Configuration.js";
import { CommerceGateTools } from "../src/Tools.js";

const ORG = "11111111-1111-4111-8111-111111111111";
const DOSSIER = "22222222-2222-4222-8222-222222222222";
const KEY = "synthetic-trial-test-credential";
const ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:agentops-fixture";
const AWS_BASE = "https://commerce.decionis.com/aws";
const ORDER: EvaluateActionInput = {
  action: {
    action_type: "ORDER_ACCEPTANCE",
    actor: { type: "AGENT", id: "fixture" },
    platform: "fixture",
    idempotency_key: "fixture:order:1",
    payload: {
      order_id: "fixture-1",
      gross_amount: 100,
      discount_amount: 0,
      estimated_cost: 50,
      currency: "USD",
    },
  },
};
const EVALUATION = {
  outcome: "APPROVE",
  confidence: 0.9,
  policy_version: "fixture",
  objective_profile: "commerce",
  dossier_id: DOSSIER,
  evaluation_id: DOSSIER,
  mode: "SHADOW",
  fallback_to_legacy: false,
  governance_metrics: {
    override_drift_rate: 0,
    governance_tension_index: 0,
    boundary_volatility_score: 0,
    decision_volume_under_governance: 1,
  },
  idempotent_replay: false,
};
const directories: string[] = [];
async function trialEnvironment() {
  const directory = await mkdtemp(join(tmpdir(), "agentops-access-test-"));
  directories.push(directory);
  return { AGENTOPS_HOME: directory };
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
function provisionFetch() {
  return vi.fn<typeof fetch>(async () =>
    json({ org_id: ORG, raw_key: KEY, provisional: true, claim: { note: KEY, token: KEY } }),
  );
}
function toolsFor(configuration: CommerceGateConfiguration, apiFetch: typeof fetch) {
  const tools = new CommerceGateTools(
    configuration,
    new CommerceGateClient(configuration, apiFetch),
  ).build();
  return async (name: string, args: Record<string, unknown> = {}) => {
    const tool = tools.find((entry) => entry.name === `commercegate_${name}`);
    if (!tool) throw new Error("Unknown test tool");
    return (await tool.handler(args)).structuredContent;
  };
}

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe.skipIf(process.platform === "win32")("local first-use access", () => {
  it("coordinates two independent processes with one persistent mint", async () => {
    const env = await trialEnvironment();
    let mints = 0;
    const server = createServer((request, response) => {
      if (request.method !== "POST" || request.url !== "/v1/public/agents/provision") {
        response.writeHead(404).end();
        return;
      }
      mints++;
      request.resume();
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ org_id: ORG, raw_key: KEY, provisional: true }));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Missing loopback port");
      const script = `import { runtimeAccess } from ${JSON.stringify(new URL("../src/Access.ts", import.meta.url).href)};
        const access = runtimeAccess({ AGENTOPS_HOME: process.argv[1], DECIONIS_API_BASE: process.argv[2] }, "stdio");
        await access.resolve("shadow"); process.stdout.write("ready");`;
      const args = [
        "--import",
        "tsx",
        "--input-type=module",
        "-e",
        script,
        env.AGENTOPS_HOME,
        `http://127.0.0.1:${address.port}`,
      ];
      const children = await Promise.all([
        promisify(execFile)(process.execPath, args, { timeout: 12_000 }),
        promisify(execFile)(process.execPath, args, { timeout: 12_000 }),
      ]);
      expect(children.map((child) => child.stdout)).toEqual(["ready", "ready"]);
      expect(mints).toBe(1);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 15_000);

  it("disables new local provisioning on request while retaining a saved identity", async () => {
    const env = await trialEnvironment();
    const provision = provisionFetch();
    const disabled = { ...env, AGENTOPS_AUTO_PROVISION: "0" };
    expect(
      await runtimeAccess(disabled, "stdio", { fetch: provision })!.resolve("shadow"),
    ).toBeNull();
    expect(provision).not.toHaveBeenCalled();
    const access = await runtimeAccess(env, "stdio", { fetch: provision })!.resolve("shadow");
    expect(await runtimeAccess(disabled, "stdio", { fetch: provision })!.resolve("read")).toEqual(
      access,
    );
    expect(provision).toHaveBeenCalledOnce();
  });

  it("does not mint or write files for discovery, invalid input, evidence reads, or ERP", async () => {
    const env = await trialEnvironment();
    const provision = provisionFetch();
    const api = vi.fn<typeof fetch>();
    const config = new CommerceGateConfiguration(
      env,
      runtimeAccess(env, "stdio", { fetch: provision }),
    );
    const call = toolsFor(config, api);
    expect(await call("describe_capabilities")).toMatchObject({
      connection: { access: { source: "local_trial", first_shadow_call_can_provision: true } },
    });
    expect(await call("evaluate_action", {})).toMatchObject({
      ok: false,
      error: { code: "INVALID_INPUT" },
    });
    expect(await call("get_dossier", { dossier_id: DOSSIER })).toMatchObject({ ok: false });
    await config.resolveAccess("erp");
    expect(() => config.requireApiConnection()).toThrow("not connected");
    expect(await readdir(env.AGENTOPS_HOME)).toEqual([]);
    expect(provision).not.toHaveBeenCalled();
    expect(api).not.toHaveBeenCalled();
  });

  it("provisions once across simultaneous calls and independent stores, then persists for a restart", async () => {
    const env = await trialEnvironment();
    const provision = provisionFetch();
    const first = runtimeAccess(env, "stdio", { fetch: provision })!;
    const second = runtimeAccess(env, "stdio", { fetch: provision })!;
    const results = await Promise.all([
      first.resolve("shadow"),
      first.resolve("shadow"),
      second.resolve("shadow"),
    ]);
    expect(provision).toHaveBeenCalledOnce();
    expect(results).toEqual(
      Array(3).fill({
        apiKey: KEY,
        orgId: ORG,
        apiBaseUrl: "https://api.decionis.com",
        provisional: true,
      }),
    );
    expect(provision.mock.calls[0][0]).toBe("https://api.decionis.com/v1/public/agents/provision");
    expect(provision.mock.calls[0][1]).toMatchObject({
      redirect: "error",
      method: "POST",
      body: JSON.stringify({ agent_name: "AgentOps MCP Shadow" }),
    });
    expect((await stat(join(env.AGENTOPS_HOME, "credentials.json"))).mode & 0o777).toBe(0o600);
    expect(await runtimeAccess(env, "stdio", { fetch: provision })!.resolve("read")).toEqual(
      results[0],
    );
    expect(provision).toHaveBeenCalledOnce();
    await unlink(join(env.AGENTOPS_HOME, "credentials.json"));
    await expect(
      runtimeAccess(env, "stdio", { fetch: provision })!.resolve("shadow"),
    ).rejects.toThrow("no replacement workspace");
    expect(provision).toHaveBeenCalledOnce();
  });

  it("reports provisional and claim guidance without returning the credential or server claim token", async () => {
    const env = await trialEnvironment();
    const config = new CommerceGateConfiguration(
      env,
      runtimeAccess(env, "stdio", { fetch: provisionFetch() }),
    );
    const api = vi.fn<typeof fetch>(async () => json(EVALUATION));
    const result = await toolsFor(config, api)("evaluate_action", { ...ORDER });
    expect(result).toMatchObject({
      ok: true,
      access: {
        provisional: true,
        first_shadow_call_can_provision: false,
        claim_instructions: expect.stringContaining("provisional Shadow workspace"),
      },
    });
    expect(JSON.stringify(result)).not.toContain(KEY);
    expect(JSON.stringify(config.describe())).not.toContain(ORG);
    expect(config.describe().erp_guard_ready).toBe(false);
    await expect(config.resolveAccess("erp")).rejects.toMatchObject({
      code: "AUTHORIZATION_FAILED",
    });
    expect(api).toHaveBeenCalledOnce();
  });

  it.each([401, 403, 429, 500])(
    "keeps the same stored identity after an upstream %s",
    async (status) => {
      const env = await trialEnvironment();
      const provision = provisionFetch();
      const api = vi.fn<typeof fetch>(async () => json({ secret: KEY }, status));
      for (let restart = 0; restart < 2; restart++) {
        const config = new CommerceGateConfiguration(
          env,
          runtimeAccess(env, "stdio", { fetch: provision }),
        );
        const call = toolsFor(config, api);
        const result = await call("evaluate_action", { ...ORDER });
        expect(result).toMatchObject({ ok: false });
        expect(JSON.stringify(result)).not.toContain(KEY);
      }
      expect(provision).toHaveBeenCalledOnce();
      expect(api).toHaveBeenCalledTimes(2);
      for (const [, init] of api.mock.calls)
        expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${KEY}`);
    },
  );

  it.each(["transport", "quota", "malformed", "oversized", "non-provisional"])(
    "never retries an uncertain or refused %s mint, including after restart",
    async (kind) => {
      const env = await trialEnvironment();
      const provision = vi.fn<typeof fetch>(async () => {
        if (kind === "transport") throw new Error(KEY);
        if (kind === "quota") return json({ raw_key: KEY }, 429);
        if (kind === "malformed") return new Response(KEY);
        if (kind === "oversized") return new Response("x".repeat(65 * 1024));
        return json({ org_id: ORG, raw_key: KEY, provisional: false });
      });
      const access = runtimeAccess(env, "stdio", { fetch: provision })!;
      for (const source of [access, access, runtimeAccess(env, "stdio", { fetch: provision })!]) {
        await expect(source.resolve("shadow")).rejects.toThrow("no replacement workspace");
      }
      expect(provision).toHaveBeenCalledOnce();
      expect(await readdir(env.AGENTOPS_HOME)).toEqual(["provision.attempted"]);
    },
  );

  it.each(["corrupt", "public", "symlink", "wrong-base"])(
    "does not replace a %s credential file",
    async (kind) => {
      const env = await trialEnvironment();
      const provision = provisionFetch();
      const file = join(env.AGENTOPS_HOME, "credentials.json");
      await writeFile(
        file,
        kind === "corrupt"
          ? KEY
          : JSON.stringify({
              version: 1,
              provisional: true,
              api_key: KEY,
              org_id: ORG,
              api_base_url:
                kind === "wrong-base" ? "https://other.example.test" : "https://api.decionis.com",
            }),
        { mode: 0o600 },
      );
      if (kind === "public") await chmod(file, 0o644);
      if (kind === "symlink") {
        await unlink(file);
        await symlink(join(env.AGENTOPS_HOME, "missing.json"), file);
      }
      await expect(
        runtimeAccess(env, "stdio", { fetch: provision })!.resolve("shadow"),
      ).rejects.toThrow();
      expect(provision).not.toHaveBeenCalled();
    },
  );

  it.each([false, true])("fails closed on a contended or stale lock (stale=%s)", async (stale) => {
    const env = await trialEnvironment();
    const lock = join(env.AGENTOPS_HOME, "provision.lock");
    await writeFile(lock, "", { mode: 0o600 });
    if (stale) await utimes(lock, new Date(0), new Date(0));
    const provision = provisionFetch();
    await expect(
      runtimeAccess(env, "stdio", { fetch: provision, lockWaitMs: 1 })!.resolve("shadow"),
    ).rejects.toThrow("locked or incomplete");
    expect(provision).not.toHaveBeenCalled();
    expect(await readFile(lock, "utf8")).toBe("");
  });

  it("does not enable anonymous provisioning in HTTP, production, the AWS gateway or partial explicit configuration", () => {
    expect(runtimeAccess({}, "http")).toBeUndefined();
    for (const env of [
      { NODE_ENV: "production" },
      { DECIONIS_API_BASE: AWS_BASE },
      { DECIONIS_ORG_ID: ORG },
      { DECIONIS_API_KEY: KEY, AGENTOPS_ACCESS_SECRET_ARN: ARN },
    ]) {
      expect(runtimeAccess(env, "stdio")).toBeUndefined();
    }
  });
});

describe("durable managed access", () => {
  it.each([401, 429])("does not reload or replace managed access after HTTP %s", async (status) => {
    const env = { AGENTOPS_ACCESS_SECRET_ARN: ARN };
    const loadSecret = vi.fn(async () =>
      JSON.stringify({ api_key: KEY, org_id: ORG, api_base_url: AWS_BASE }),
    );
    const discovery = vi.fn<typeof fetch>();
    const config = new CommerceGateConfiguration(
      env,
      runtimeAccess(env, "http", { loadSecret, fetch: discovery }),
    );
    const api = vi.fn<typeof fetch>(async () => json({ secret: KEY }, status));
    const call = toolsFor(config, api);
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await call("evaluate_action", { ...ORDER });
      expect(result).toMatchObject({ ok: false });
      expect(JSON.stringify(result)).not.toContain(KEY);
    }
    expect(loadSecret).toHaveBeenCalledOnce();
    expect(discovery).not.toHaveBeenCalled();
    expect(api).toHaveBeenCalledTimes(2);
  });

  it("loads Secrets Manager using the default container execution-role credentials", async () => {
    const requests: string[] = [];
    const roleKey = "fixture";
    const server = createServer((request, response) => {
      requests.push(request.url ?? "");
      response.setHeader("content-type", "application/json");
      if (request.url === "/credentials") {
        response.end(
          JSON.stringify({
            AccessKeyId: roleKey,
            SecretAccessKey: "synthetic-role-secret",
            Token: "synthetic-role-session",
            Expiration: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
          }),
        );
      } else {
        expect(request.headers.authorization).toContain(`Credential=${roleKey}/`);
        expect(request.headers["x-amz-target"]).toContain("GetSecretValue");
        request.resume();
        response.end(
          JSON.stringify({
            SecretString: JSON.stringify({ api_key: KEY, org_id: ORG, api_base_url: AWS_BASE }),
          }),
        );
      }
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Missing loopback port");
      const origin = `http://127.0.0.1:${address.port}`;
      for (const name of [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
      ])
        vi.stubEnv(name, undefined);
      vi.stubEnv("AWS_EC2_METADATA_DISABLED", "true");
      vi.stubEnv("AWS_CONTAINER_CREDENTIALS_FULL_URI", `${origin}/credentials`);
      vi.stubEnv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "synthetic-role-access");
      vi.stubEnv("AWS_ENDPOINT_URL_SECRETS_MANAGER", origin);
      const access = runtimeAccess({ AGENTOPS_ACCESS_SECRET_ARN: ARN }, "http")!;
      expect(await access.resolve("read")).toEqual({
        apiKey: KEY,
        orgId: ORG,
        apiBaseUrl: AWS_BASE,
        provisional: false,
      });
      expect(requests).toEqual(["/credentials", "/"]);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 12_000);

  it("reports the Windows persistence limitation without blocking explicit credentials", () => {
    const options = runtimeAccess({}, "stdio", { platform: "win32" });
    const config = new CommerceGateConfiguration({}, options);
    expect(config.describe()).toMatchObject({
      access: { first_shadow_call_can_provision: false },
      configuration_issues: [expect.stringContaining("unavailable on Windows")],
    });
    expect(
      runtimeAccess({ DECIONIS_API_KEY: KEY, DECIONIS_ORG_ID: ORG }, "stdio", {
        platform: "win32",
      }),
    ).toBeUndefined();
  });

  it("lazily reuses a JSON secret and keeps its values out of diagnostics", async () => {
    const env = { AGENTOPS_ACCESS_SECRET_ARN: ARN };
    const loadSecret = vi.fn(async () =>
      JSON.stringify({ api_key: KEY, org_id: ORG, api_base_url: AWS_BASE }),
    );
    const discovery = vi.fn<typeof fetch>();
    const config = new CommerceGateConfiguration(
      env,
      runtimeAccess(env, "http", { loadSecret, fetch: discovery }),
    );
    expect(config.describe().access?.source).toBe("aws_secret");
    expect(loadSecret).not.toHaveBeenCalled();
    await Promise.all([config.resolveAccess("shadow"), config.resolveAccess("read")]);
    expect(config.requireTenantConnection()).toEqual({
      apiKey: KEY,
      orgId: ORG,
      apiBaseUrl: AWS_BASE,
    });
    expect(loadSecret).toHaveBeenCalledExactlyOnceWith(ARN);
    expect(discovery).not.toHaveBeenCalled();
    expect(JSON.stringify(config.describe())).not.toContain(KEY);
    expect(JSON.stringify(config.describe())).not.toContain(ORG);
    expect(JSON.stringify(config.describe())).not.toContain(ARN);
  });

  it("discovers a raw Marketplace key only at the trusted gateway, with redirects forbidden", async () => {
    const raw = "dcn_aws_synthetic-fixture";
    const discovery = vi.fn<typeof fetch>(async () =>
      json({ org_id: ORG, api_base_url: AWS_BASE }),
    );
    const loadSecret = vi.fn(async () => raw);
    const access = runtimeAccess({ AGENTOPS_ACCESS_SECRET_ARN: ARN }, "http", {
      loadSecret,
      fetch: discovery,
    })!;
    const result = await access.resolve("read");
    expect(result).toEqual({ apiKey: raw, orgId: ORG, apiBaseUrl: AWS_BASE, provisional: false });
    expect(discovery.mock.calls[0][0]).toBe(`${AWS_BASE}/commerce/session`);
    expect(discovery.mock.calls[0][1]).toMatchObject({
      method: "GET",
      redirect: "error",
      headers: { authorization: `Bearer ${raw}` },
    });
    await access.resolve("shadow");
    expect(loadSecret).toHaveBeenCalledOnce();
    expect(discovery).toHaveBeenCalledOnce();
  });

  it.each([
    "https://untrusted.invalid/aws",
    `${AWS_BASE}/other`,
    "https://commerce.decionis.com/other/../aws",
    "https://commerce.decionis.com",
  ])(
    "rejects a discovery base substitution %s without reload or fallback",
    async (api_base_url) => {
      const raw = "dcn_aws_synthetic-fixture";
      const loadSecret = vi.fn(async () => raw);
      const discovery = vi.fn<typeof fetch>(async () => json({ org_id: ORG, api_base_url }));
      const access = runtimeAccess({ AGENTOPS_ACCESS_SECRET_ARN: ARN }, "http", {
        loadSecret,
        fetch: discovery,
      })!;
      await expect(access.resolve("read")).rejects.toThrow("No anonymous workspace");
      await expect(access.resolve("shadow")).rejects.toThrow("No anonymous workspace");
      expect(loadSecret).toHaveBeenCalledOnce();
      expect(discovery).toHaveBeenCalledOnce();
    },
  );

  it("keeps secret-loader errors private and never retries them", async () => {
    const loadSecret = vi.fn(async () => {
      throw new Error(KEY);
    });
    const access = runtimeAccess({ AGENTOPS_ACCESS_SECRET_ARN: ARN }, "http", { loadSecret })!;
    await expect(access.resolve("read")).rejects.toThrow("No anonymous workspace");
    await expect(access.resolve("shadow")).rejects.not.toThrow(KEY);
    expect(loadSecret).toHaveBeenCalledOnce();
  });

  it("preserves the /aws prefix for evaluations, dossier/proof reads, reports and ERP", async () => {
    const config = new CommerceGateConfiguration({
      DECIONIS_API_KEY: KEY,
      DECIONIS_ORG_ID: ORG,
      DECIONIS_API_BASE: `${AWS_BASE}/`,
    });
    const api = vi.fn<typeof fetch>(async (url) =>
      String(url).includes("evaluate-decision")
        ? json(EVALUATION)
        : String(url).includes("/guard/validate")
          ? json({
              decision: "ALLOW",
              transaction_id: "fixture",
              execution_time_ms: 1,
              reason_code: "fixture",
              message: "fixture",
            })
          : json({}),
    );
    const client = new CommerceGateClient(config, api);
    await client.evaluateAction(ORDER);
    await client.getDossier(DOSSIER);
    await client.getProofPacket(DOSSIER);
    await client.listShadowReports({ days: 7 });
    await client.summarizeShadowReports({ days: 7 });
    await client.validateErpTransaction({
      erp_region: "westeurope",
      request: {
        transaction_id: "fixture",
        erp_type: "D365_BC",
        tenant_id: ORG,
        timestamp: "2026-09-21T00:00:00Z",
        agent_id: "fixture",
        currency: "USD",
        lines: [{ line_id: 1, sku: "fixture", quantity: 1, unit_price: 2, cost_base: 1 }],
      },
    });
    expect(api).toHaveBeenCalledTimes(6);
    for (const [url] of api.mock.calls)
      expect(String(url)).toMatch(/^https:\/\/commerce\.decionis\.com\/aws\/v1\//);
  });
});
