import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { EDGE_COMMANDS, runEdge } from "../../src/cli/Edge.js";
import { readUsageReport } from "../../src/edge/UsageReport.js";
import { fakeProcess } from "../support/GatewayHarness.js";
import { repositoryPath } from "../support/RepositoryRoot.js";
import {
  USAGE_REPORT_VECTOR,
  VECTOR_INSTALLATION,
  VECTOR_ORG,
  vectorKey,
  vectorKeyPem,
  type UsageReportVector,
} from "../support/UsageReportVector.js";

const vector = JSON.parse(
  readFileSync(repositoryPath(...USAGE_REPORT_VECTOR), "utf8"),
) as UsageReportVector;

const files = (): Record<string, string> => ({
  "/work/evidence.log": `${vector.evidence.join("\n")}\n`,
  "/work/usage.pem": vectorKeyPem(),
  "/work/report.jws": `${vector.report}\n`,
  "/work/public.jwk": JSON.stringify(vector.key.public_jwk),
});

const lastJson = (lines: readonly string[]): Record<string, unknown> =>
  JSON.parse(lines.at(-1) ?? "null") as Record<string, unknown>;

describe("agentsafe edge usage-report", () => {
  it("counts a month from the collected log and prints the signed report", async () => {
    const io = fakeProcess({ files: files() });
    await runEdge(io, [
      "usage-report",
      "--period",
      "2026-09",
      "--log",
      "/work/evidence.log",
      "--key",
      "/work/usage.pem",
      "--key-id",
      "vector-edge-usage-report-1",
      "--installation",
      VECTOR_INSTALLATION,
      "--org",
      VECTOR_ORG,
    ]);
    expect(io.exits).toEqual([0]);
    const token = (io.out[0] ?? "").trim();
    const read = await readUsageReport(token, vectorKey().publicJwk);
    if (!read.ok) throw new Error(read.code);
    // The same counts and range the vector's report claims, under a fresh id.
    expect({ ...read.claims, jti: "", iat: 0 }).toEqual({ ...vector.claims, jti: "", iat: 0 });
    expect(lastJson(io.err)).toMatchObject({
      event: "USAGE_REPORT_SIGNED",
      kid: "vector-edge-usage-report-1",
      period: "2026-09",
    });
  });

  it("takes the key, the installation and the organisation from the executor's variables", async () => {
    const io = fakeProcess({
      files: {
        ...files(),
        "/journal/edge/usage.json": JSON.stringify({ installation_id: "inst_generated" }),
      },
      env: {
        EXECUTOR_EDGE_USAGE_SIGNING_KEY_FILE: "/work/usage.pem",
        EXECUTOR_EDGE_ORG_ID: VECTOR_ORG,
        EXECUTOR_JOURNAL_DIR: "/journal",
      },
    });
    await runEdge(io, [
      "usage-report",
      "--period=2026-09",
      "--log=/work/evidence.log",
      "--out=/work/out.jws",
    ]);
    expect(io.exits).toEqual([0]);
    expect(io.out).toEqual([]);
    expect(io.stored.get("/work/out.jws")?.mode).toBe(0o600);
    const read = await readUsageReport(
      io.stored.get("/work/out.jws")?.text.trim() ?? "",
      vectorKey().publicJwk,
    );
    expect(read).toMatchObject({
      ok: true,
      kid: vectorKey(null).kid,
      claims: { iss: "inst_generated" },
    });
    const fromEnv = fakeProcess({
      files: files(),
      env: {
        EXECUTOR_EDGE_USAGE_SIGNING_KEY: vectorKeyPem(),
        EXECUTOR_EDGE_USAGE_KEY_ID: "usage-key-env",
        EXECUTOR_EDGE_INSTALLATION_ID: "branch-7.executor-0",
        EXECUTOR_EDGE_ORG_ID: VECTOR_ORG,
      },
    });
    await runEdge(fromEnv, ["usage-report", "--period", "2026-09", "--log", "/work/evidence.log"]);
    const envRead = await readUsageReport((fromEnv.out[0] ?? "").trim(), vectorKey().publicJwk);
    expect(envRead).toMatchObject({ kid: "usage-key-env", claims: { iss: "branch-7.executor-0" } });
  });

  it("sends the report on demand with the organisation's key", async () => {
    const requests: { url: string; body: string }[] = [];
    const io = fakeProcess({
      files: { ...files(), "/run/decionis-key": "synthetic-api-key\n" },
      env: {
        EXECUTOR_EDGE_USAGE_SIGNING_KEY_FILE: "/work/usage.pem",
        EXECUTOR_EDGE_INSTALLATION_ID: VECTOR_INSTALLATION,
        EXECUTOR_EDGE_ORG_ID: VECTOR_ORG,
        DECIONIS_API_URL: "https://api.decionis.example",
        DECIONIS_API_KEY_FILE: "/run/decionis-key",
      },
      fetch: (async (url: string, init: RequestInit) => {
        requests.push({ url, body: String(init.body) });
        expect((init.headers as Record<string, string>)["authorization"]).toBe(
          "Bearer synthetic-api-key",
        );
        return new Response("{}", { status: 201 });
      }) as typeof fetch,
    });
    await runEdge(io, [
      "usage-report",
      "--period",
      "2026-09",
      "--log",
      "/work/evidence.log",
      "--send",
    ]);
    expect(io.exits).toEqual([0]);
    expect(requests[0]?.url).toBe("https://api.decionis.example/v1/edge/usage-reports");
    expect(lastJson(io.err)).toEqual({ event: "USAGE_REPORT_SENT", result: "DELIVERED" });
    const refused = fakeProcess({
      files: files(),
      env: {
        EXECUTOR_EDGE_USAGE_SIGNING_KEY_FILE: "/work/usage.pem",
        EXECUTOR_EDGE_INSTALLATION_ID: VECTOR_INSTALLATION,
        EXECUTOR_EDGE_ORG_ID: VECTOR_ORG,
        DECIONIS_API_URL: "https://api.decionis.example",
        DECIONIS_API_KEY: "synthetic-api-key",
      },
      fetch: (async () => new Response("{}", { status: 422 })) as typeof fetch,
    });
    await runEdge(refused, [
      "usage-report",
      "--period",
      "2026-09",
      "--log",
      "/work/evidence.log",
      "--send",
    ]);
    expect(refused.exits).toEqual([1]);
    expect(lastJson(refused.err)).toEqual({ event: "USAGE_REPORT_SENT", result: "USAGE_HTTP_422" });
    const nowhere = fakeProcess({
      files: files(),
      env: {
        EXECUTOR_EDGE_USAGE_SIGNING_KEY_FILE: "/work/usage.pem",
        EXECUTOR_EDGE_INSTALLATION_ID: VECTOR_INSTALLATION,
        EXECUTOR_EDGE_ORG_ID: VECTOR_ORG,
      },
    });
    await runEdge(nowhere, [
      "usage-report",
      "--period",
      "2026-09",
      "--log",
      "/work/evidence.log",
      "--send",
    ]);
    expect(nowhere.exits).toEqual([2]);
    expect(lastJson(nowhere.err)).toEqual({ event: "EDGE_USAGE_ERROR", code: "DECIONIS_REQUIRED" });
  });

  it("refuses to sign a count the chain does not support", async () => {
    const lines = [...vector.evidence];
    const tampered = JSON.parse(lines[3] ?? "{}") as Record<string, unknown>;
    tampered["event"] = "EXECUTION_FAILED";
    lines[3] = JSON.stringify(tampered);
    const io = fakeProcess({ files: { ...files(), "/work/evidence.log": lines.join("\n") } });
    await runEdge(io, [
      "usage-report",
      "--period=2026-09",
      "--log=/work/evidence.log",
      "--key=/work/usage.pem",
      `--installation=${VECTOR_INSTALLATION}`,
      `--org=${VECTOR_ORG}`,
    ]);
    expect(io.exits).toEqual([1]);
    expect(io.out).toEqual([]);
    expect(lastJson(io.err)).toMatchObject({
      event: "USAGE_COUNT_FAILED",
      findings: expect.arrayContaining([{ code: "CHAIN_HASH_MISMATCH", line: 4 }]),
    });
  });

  it("names what it needs and cannot find", async () => {
    const base = [
      "--period=2026-09",
      "--log=/work/evidence.log",
      "--key=/work/usage.pem",
      `--installation=${VECTOR_INSTALLATION}`,
      `--org=${VECTOR_ORG}`,
    ];
    const cases: [readonly string[], Record<string, string>, string][] = [
      [base.filter((argument) => !argument.startsWith("--period")), {}, "PERIOD_REQUIRED"],
      [[...base.slice(1), "--period=2026-13"], {}, "PERIOD_REQUIRED"],
      [base.filter((argument) => !argument.startsWith("--org")), {}, "ORG_REQUIRED"],
      [base.filter((argument) => !argument.startsWith("--log")), {}, "LOG_REQUIRED"],
      [[...base.slice(0, 1), "--log=/work/none.log", ...base.slice(2)], {}, "LOG_UNREADABLE"],
      [base.filter((argument) => !argument.startsWith("--key")), {}, "KEY_REQUIRED"],
      [[...base.slice(0, 2), "--key=/work/evidence.log", ...base.slice(3)], {}, "KEY_INVALID"],
      [
        base.filter((argument) => !argument.startsWith("--installation")),
        {},
        "INSTALLATION_REQUIRED",
      ],
      [
        base.filter((argument) => !argument.startsWith("--installation")),
        { EXECUTOR_JOURNAL_DIR: "/journal" },
        "INSTALLATION_REQUIRED",
      ],
      [[...base, "--unknown"], {}, "UNKNOWN_OPTION: unknown"],
    ];
    for (const [argv, env, code] of cases) {
      const io = fakeProcess({
        files: { ...files(), "/journal/edge/usage.json": "{not json" },
        env,
      });
      await runEdge(io, ["usage-report", ...argv]);
      expect(io.exits, code).toEqual([2]);
      expect(lastJson(io.err), code).toEqual({ event: "EDGE_USAGE_ERROR", code });
    }
  });
});

describe("agentsafe edge verify-usage-report", () => {
  it("checks the signature and recounts the report from the log", async () => {
    const io = fakeProcess({ files: files() });
    await runEdge(io, [
      "verify-usage-report",
      "/work/report.jws",
      "--log",
      "/work/evidence.log",
      "--public-jwk",
      "/work/public.jwk",
    ]);
    expect(io.exits).toEqual([0]);
    expect(lastJson(io.out)).toMatchObject({
      ok: true,
      kid: "vector-edge-usage-report-1",
      iss: VECTOR_INSTALLATION,
      aud: VECTOR_ORG,
      period: "2026-09",
      findings: [],
      recounted: { counts: { total: 4 }, delegated: 1 },
    });
    const withKey = fakeProcess({ files: files() });
    await runEdge(withKey, [
      "verify-usage-report",
      "/work/report.jws",
      "--log=/work/evidence.log",
      "--key=/work/usage.pem",
    ]);
    expect(withKey.exits).toEqual([0]);
  });

  it("fails a report the log does not reproduce, or a signature it cannot check", async () => {
    const short = fakeProcess({
      files: { ...files(), "/work/evidence.log": vector.evidence.slice(0, 5).join("\n") },
    });
    await runEdge(short, [
      "verify-usage-report",
      "/work/report.jws",
      "--log=/work/evidence.log",
      "--public-jwk=/work/public.jwk",
    ]);
    expect(short.exits).toEqual([1]);
    expect(lastJson(short.out)).toMatchObject({
      ok: false,
      findings: [{ code: "CHAIN_RANGE_BROKEN" }],
    });
    const other = fakeProcess({
      files: {
        ...files(),
        "/work/public.jwk": JSON.stringify({ ...vector.key.public_jwk, x: "A".repeat(43) }),
      },
    });
    await runEdge(other, [
      "verify-usage-report",
      "/work/report.jws",
      "--log=/work/evidence.log",
      "--public-jwk=/work/public.jwk",
    ]);
    expect(other.exits).toEqual([1]);
    expect(lastJson(other.out)).toEqual({ ok: false, code: "USAGE_REPORT_SIGNATURE_INVALID" });
    for (const [jwk, code] of [
      ["{not json", "PUBLIC_JWK_INVALID"],
      [undefined, "PUBLIC-JWK_UNREADABLE"],
    ] as const) {
      const io = fakeProcess({
        files: { ...files(), ...(jwk === undefined ? {} : { "/work/bad.jwk": jwk }) },
      });
      await runEdge(io, [
        "verify-usage-report",
        "/work/report.jws",
        "--log=/work/evidence.log",
        "--public-jwk=/work/bad.jwk",
      ]);
      expect(io.exits).toEqual([2]);
      expect(lastJson(io.err)).toEqual({ event: "EDGE_USAGE_ERROR", code });
    }
    const noReport = fakeProcess({ files: files() });
    await runEdge(noReport, ["verify-usage-report", "--log=/work/evidence.log"]);
    expect(lastJson(noReport.err)).toEqual({ event: "EDGE_USAGE_ERROR", code: "REPORT_REQUIRED" });
  });
});

describe("agentsafe edge usage-key and replay-schema", () => {
  it("prints the kid, the public JWK and the registration body", async () => {
    const io = fakeProcess({
      files: files(),
      env: { EXECUTOR_EDGE_INSTALLATION_ID: VECTOR_INSTALLATION },
    });
    await runEdge(io, ["usage-key", "--key", "/work/usage.pem"]);
    expect(io.exits).toEqual([0]);
    const key = vectorKey(null);
    expect(lastJson(io.out)).toEqual({
      kid: key.kid,
      public_jwk: key.publicJwk,
      registration: {
        kid: key.kid,
        issuer: VECTOR_INSTALLATION,
        algorithm: "EdDSA",
        public_jwk: key.publicJwk,
        purpose: "usage_report",
      },
    });
    const unnamed = fakeProcess({ files: files() });
    await runEdge(unnamed, ["usage-key", "--key=/work/usage.pem", "--key-id=usage-key-2"]);
    expect(lastJson(unnamed.out)).toMatchObject({
      kid: "usage-key-2",
      registration: { issuer: "<installation id>" },
    });
  });

  it("prints the replay store's DDL", async () => {
    const io = fakeProcess();
    await runEdge(io, ["replay-schema"]);
    expect(io.exits).toEqual([0]);
    expect(io.out.join("")).toContain("CREATE TABLE IF NOT EXISTS agentsafe_edge_replay (");
    const named = fakeProcess();
    await runEdge(named, ["replay-schema", "--table", "edge.claims"]);
    expect(named.out.join("")).toContain("ON edge.claims (expires_at);");
    const bad = fakeProcess();
    await runEdge(bad, ["replay-schema", "--table", "Claims"]);
    expect(bad.exits).toEqual([2]);
    expect(lastJson(bad.err)).toEqual({ event: "EDGE_USAGE_ERROR", code: "TABLE_INVALID" });
  });

  it("refuses a command it does not have", async () => {
    for (const argv of [[], ["publish"]]) {
      const io = fakeProcess();
      await runEdge(io, argv);
      expect(io.exits).toEqual([2]);
      expect(lastJson(io.err)).toEqual({
        event: "EDGE_COMMAND_REQUIRED",
        commands: [...EDGE_COMMANDS],
      });
    }
  });
});
