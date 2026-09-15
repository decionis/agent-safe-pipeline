import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { Agent, request } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ExecutorConfigLoader } from "../src/config/ExecutorConfig.js";
import { METRICS_CONTENT_TYPE } from "../src/http/Routes.js";
import { createTrustedExecutor, type TrustedExecutor } from "../src/TrustedExecutor.js";
import {
  CALLER_TOKEN,
  TENANT_ID,
  collectedEvents,
  loopbackEnvironment,
  openSecrets,
  proposal,
} from "./support/Environment.js";
import { sha256Hex } from "./support/Principals.js";
import { ProviderDouble } from "./support/ProviderDouble.js";
import {
  TestCertificateAuthority,
  type IssuedCertificate,
} from "./support/TestCertificateAuthority.js";

const ISSUER = "https://issuer.synthetic.example";
const OPERATOR_SAN = "spiffe://synthetic.example/ns/ops/sa/oncall";
const authority = new LocalAuthority();
const provider = new ProviderDouble();
const directory = mkdtempSync(join(tmpdir(), "agentsafe-principals-"));
const serverCa = new TestCertificateAuthority("Synthetic Server CA");
const clientCa = new TestCertificateAuthority("Synthetic Client CA");
const strangerCa = new TestCertificateAuthority("Synthetic Stranger CA");

let executor: TrustedExecutor;
let port = 0;
let operatorCert: IssuedCertificate;
let strangerCert: IssuedCertificate;
let signingKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
const auditLines: string[] = [];
const securityLines: string[] = [];

interface Reply {
  readonly status: number;
  readonly contentType: string;
  readonly text: string;
  readonly json: Record<string, unknown>;
}

function call(
  path: string,
  options: {
    readonly method?: "GET" | "POST";
    readonly token?: string;
    readonly cert?: IssuedCertificate;
    readonly body?: string;
  } = {},
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (options.token !== undefined) headers["authorization"] = `Bearer ${options.token}`;
    const agent = new Agent({
      ca: serverCa.certificate,
      servername: "localhost",
      keepAlive: false,
      ...(options.cert === undefined ? {} : { cert: options.cert.cert, key: options.cert.key }),
    });
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path,
        method: options.method ?? (options.body === undefined ? "GET" : "POST"),
        headers,
        agent,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: Record<string, unknown> = {};
          try {
            json = JSON.parse(text) as Record<string, unknown>;
          } catch {
            json = {};
          }
          resolve({
            status: response.statusCode ?? 0,
            contentType: String(response.headers["content-type"]),
            text,
            json,
          });
        });
      },
    );
    req.on("error", reject);
    req.end(options.body);
  });
}

async function workloadToken(claims: { sub?: string; aud?: string } = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1_000);
  return await new SignJWT({ "kubernetes.io/namespace": "agents" })
    .setProtectedHeader({ alg: "ES256", kid: "cluster-1" })
    .setIssuer(ISSUER)
    .setSubject(claims.sub ?? "system:serviceaccount:agents:batch-runner")
    .setAudience(claims.aud ?? "agentsafe")
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(signingKey);
}

beforeAll(async () => {
  await authority.start();
  await provider.start();
  const pair = await generateKeyPair("ES256");
  signingKey = pair.privateKey;
  const jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "cluster-1", alg: "ES256" }] };
  const server = serverCa.issueServer(["localhost"], ["127.0.0.1"]);
  operatorCert = clientCa.issueClient("oncall", [OPERATOR_SAN]);
  strangerCert = strangerCa.issueClient("stranger", [OPERATOR_SAN]);
  for (const dir of ["tls", "principals", "jwks"])
    mkdirSync(join(directory, dir), { recursive: true });
  writeFileSync(join(directory, "tls", "tls.crt"), server.cert);
  writeFileSync(join(directory, "tls", "tls.key"), server.key);
  writeFileSync(join(directory, "tls", "clients.pem"), clientCa.certificate);
  writeFileSync(join(directory, "jwks", "jwks.json"), JSON.stringify(jwks));
  writeFileSync(
    join(directory, "principals", "principals.json"),
    JSON.stringify({
      version: "agent-safe.principals/1",
      principals: [
        {
          id: "treasury-workflow",
          role: "PROPOSER",
          tenant_id: TENANT_ID,
          actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
          allowed_actions: ["forward_request"],
          credential: { kind: "BEARER", token_sha256: sha256Hex(CALLER_TOKEN) },
        },
        {
          id: "batch-runner",
          role: "PROPOSER",
          tenant_id: TENANT_ID,
          actor: { id: "synthetic-batch-agent", type: "AI_AGENT" },
          allowed_actions: ["forward_request"],
          credential: {
            kind: "WORKLOAD_JWT",
            issuer: ISSUER,
            subject: "system:serviceaccount:agents:batch-runner",
            required_claims: { "kubernetes.io/namespace": "agents" },
          },
        },
        {
          id: "ops-oncall",
          role: "OPERATOR",
          scopes: ["status", "metrics", "secrets.reload"],
          credential: { kind: "MTLS", san_uri: OPERATOR_SAN },
        },
      ],
    }),
  );
  const env = loopbackEnvironment({ authority, providerBaseUrl: provider.baseUrl }, "ENFORCEMENT");
  for (const key of [
    "EXECUTOR_TENANT_ID",
    "EXECUTOR_ACTOR_ID",
    "EXECUTOR_ACTOR_TYPE",
    "EXECUTOR_ACTOR_RUNTIME",
    "EXECUTOR_CALLER_TOKEN",
    "EXECUTOR_ALLOW_PLAINTEXT_LISTENER",
  ]) {
    delete env[key];
  }
  Object.assign(env, {
    EXECUTOR_PRINCIPALS_FILE: join(directory, "principals", "principals.json"),
    EXECUTOR_TLS_CERT_FILE: join(directory, "tls", "tls.crt"),
    EXECUTOR_TLS_KEY_FILE: join(directory, "tls", "tls.key"),
    EXECUTOR_TLS_CLIENT_CA_FILE: join(directory, "tls", "clients.pem"),
    EXECUTOR_JWT_AUDIENCE: "agentsafe",
    EXECUTOR_JWKS_FILE: join(directory, "jwks", "jwks.json"),
  });
  const config = ExecutorConfigLoader.load(env);
  executor = await createTrustedExecutor({
    config,
    secrets: openSecrets(env, config),
    dependencies: {
      emit: (line) => auditLines.push(line),
      security: collectedEvents(securityLines),
    },
  });
  port = (await executor.listen(0, "127.0.0.1")).port;
});

afterAll(async () => {
  await executor.close();
  await provider.stop();
  await authority.stop();
  rmSync(directory, { recursive: true, force: true });
});

describe("the executor with a principals file", () => {
  it("loads the principals and admits a bearer proposer, a workload proposer, and a certificate operator", async () => {
    expect(executor.principals.size).toBe(3);
    expect(executor.principals.legacy).toBe(false);
    const byBearer = await call("/v1/actions", {
      token: CALLER_TOKEN,
      body: JSON.stringify(proposal(25_00).body),
    });
    expect(byBearer.json).toMatchObject({ verdict: "ALLOW", outcome: "COMPLETED", executed: true });
    const byToken = await call("/v1/actions", {
      token: await workloadToken(),
      body: JSON.stringify(proposal(26_00).body),
    });
    expect(byToken.json).toMatchObject({ verdict: "ALLOW", outcome: "COMPLETED", executed: true });
    const callers = auditLines
      .map((line) => JSON.parse(line) as { caller_principal: string })
      .map((line) => line.caller_principal);
    expect(new Set(callers)).toEqual(new Set(["treasury-workflow", "batch-runner"]));
    const status = await call("/v1/control/status", { cert: operatorCert });
    expect(status.status).toBe(200);
    expect(status.json).toMatchObject({
      status: "ready",
      principals: { mode: "PRINCIPALS", count: 3 },
      actions: ["forward_request"],
    });
    expect(Number((status.json["evidence"] as { seq: number }).seq)).toBeGreaterThan(0);
    const metrics = await call("/metrics", { cert: operatorCert });
    expect(metrics.status).toBe(200);
    expect(metrics.contentType).toBe(METRICS_CONTENT_TYPE);
    expect(metrics.text).toContain('agentsafe_proposals_total{verdict="ALLOW"} 2');
    expect(metrics.text).toContain('agentsafe_operator_actions_total{action="status"} 1');
    const reload = await call("/v1/control/secrets/reload", {
      cert: operatorCert,
      method: "POST",
      body: "{}",
    });
    expect(reload.status).toBe(200);
    expect(reload.json).toMatchObject({ reason: "OPERATOR", rotated: [], refused: [] });
  });

  it("refuses the wrong role, the wrong audience, an ambiguous request, and a stranger's certificate", async () => {
    expect((await call("/metrics", { token: CALLER_TOKEN })).json).toEqual({
      code: "ROLE_FORBIDDEN",
    });
    expect((await call("/v1/actions", { cert: operatorCert, body: "{}" })).json).toEqual({
      code: "ROLE_FORBIDDEN",
    });
    expect(
      (await call("/v1/actions", { token: await workloadToken({ aud: "elsewhere" }), body: "{}" }))
        .json,
    ).toEqual({
      code: "JWT_AUDIENCE_MISMATCH",
    });
    expect(
      (
        await call("/v1/actions", {
          token: await workloadToken({ sub: "system:serviceaccount:agents:other" }),
          body: "{}",
        })
      ).status,
    ).toBe(401);
    expect(
      (await call("/v1/control/status", { cert: operatorCert, token: CALLER_TOKEN })).json,
    ).toEqual({ code: "AUTH_AMBIGUOUS" });
    expect((await call("/v1/control/status", { cert: strangerCert })).json).toEqual({
      code: "CALLER_NOT_AUTHENTICATED",
    });
    expect((await call("/v1/control/status")).status).toBe(401);
    expect((await call("/health")).status).toBe(200);
    const refusals = securityLines
      .map((line) => JSON.parse(line) as { event: string; method?: string; code?: string })
      .filter((event) => event.event === "AUTH_FAILED")
      .map((event) => `${event.method}:${event.code}`);
    expect(refusals).toEqual([
      "bearer:ROLE_FORBIDDEN",
      "mtls:ROLE_FORBIDDEN",
      "jwt:JWT_AUDIENCE_MISMATCH",
      "jwt:JWT_SUBJECT_UNKNOWN",
      "none:AUTH_AMBIGUOUS",
      "mtls:CALLER_NOT_AUTHENTICATED",
      "bearer:CALLER_NOT_AUTHENTICATED",
    ]);
    expect(executor.metrics.authFailures.get({ method: "jwt" })).toBe(2);
    expect(securityLines.some((line) => line.includes('"PRINCIPALS_LOADED"'))).toBe(true);
    expect(securityLines.some((line) => line.includes('"LEGACY_PRINCIPAL_MODE"'))).toBe(false);
  });
});
