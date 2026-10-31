/**
 * Acceptance demo: `agentsafe accept` against a gateway on loopback.
 *
 * The build's other proofs prove the runtime; an acceptance run proves where
 * it was put. This demo proves the tool that makes that run: the gateway is a
 * real one, built from a real configuration with an acceptance key and an
 * operator token, and `accept`, `identity` and `verify acceptance` are the
 * real `agentsafe` binary, run as a child process the way an operator runs it.
 *
 * The run is played twice. First with a plan whose origin list is empty: the
 * permitted write lands once and is read back as asked, the prohibited write
 * is refused in shadow, then in enforcement, and its canary is read unchanged,
 * and the outage case refuses with the authority unreachable. The gateway
 * signs `ACCEPTED`, and the key `identity` prints verifies it against the
 * running fingerprint. Then with the target's own address as an origin: on
 * loopback the zone reaches it directly, so the gateway signs `NOT_ACCEPTED`
 * and names the origin. Both are the point: a run says what holds and what
 * does not.
 *
 * The target is the observer: every count below is what reached it. The run
 * is a self-checking proof and exits 0 only when each expectation holds. A
 * customer's run proves that customer's deployment and nothing else; this one
 * proves the tool. All identities and records are synthetic.
 */
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { Gateway, GatewayConfigLoader, GatewayHttpServer } from "@decionis/agentsafe";
import { stringify } from "yaml";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const COMPANY = "6f3c1a52-1d2e-4f5a-8b9c-0d1e2f3a4b5c";
const CUSTOMER = `/companies(${COMPANY})/customers(9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d)`;
const CANARY = `/companies(${COMPANY})/customers(00000000-0000-4000-8000-0000000000ca)`;
const LOOPBACK = "127.0.0.1";
const LOOPBACK_URL = "http://127.0.0.1";

/** One versioned customer per path, as Business Central answers it: a write applies its body and moves the version. */
class Target {
  private readonly records = new Map<
    string,
    { version: number; record: Record<string, unknown> }
  >();
  private server: Server | null = null;
  public writes = 0;
  public url = "";

  public version(path: string): number {
    return this.entry(path).version;
  }

  private entry(path: string): { version: number; record: Record<string, unknown> } {
    let entry = this.records.get(path);
    if (entry === undefined) {
      entry = {
        version: 1,
        record: { number: "C-90000", displayName: "Synthetic Customer", blocked: " " },
      };
      this.records.set(path, entry);
    }
    return entry;
  }

  public async start(): Promise<void> {
    const server = createServer((request, response) => {
      void this.handle(request, response);
    });
    await new Promise<void>((resolve) => server.listen(0, LOOPBACK, () => resolve()));
    const address = server.address();
    this.url = `${LOOPBACK_URL}:${typeof address === "object" && address !== null ? address.port : 0}`;
    this.server = server;
  }

  public async stop(): Promise<void> {
    this.server?.closeAllConnections();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const entry = this.entry(request.url ?? "/");
    if (request.method !== "GET") {
      this.writes += 1;
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

/** The real binary, as an operator runs it: its exit code and what it printed. */
async function agentsafe(
  args: readonly string[],
  env: Record<string, string>,
): Promise<{ readonly code: number; readonly stdout: string; readonly stderr: string }> {
  const cli = join(dirname(fileURLToPath(import.meta.resolve("@decionis/agentsafe"))), "Cli.js");
  return await new Promise((resolve) => {
    execFile(
      process.execPath,
      [cli, ...args],
      { env: { PATH: process.env["PATH"] ?? "", ...env }, timeout: 120_000 },
      (error, stdout, stderr) => {
        resolve({ code: error === null ? 0 : Number(error.code ?? 1), stdout, stderr });
      },
    );
  });
}

const failures: string[] = [];
function expect(claim: string, holds: boolean): void {
  process.stdout.write(`  ${holds ? "ok  " : "FAIL"} ${claim}\n`);
  if (!holds) failures.push(claim);
}

async function main(): Promise<void> {
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-acceptance-demo-"));
  const target = new Target();
  const authority = new LocalAuthority({
    // The canary's change is the one this synthetic policy refuses.
    policy: (request) =>
      (request.action as { parameters?: { body?: { blocked?: string } } }).parameters?.body
        ?.blocked === "All"
        ? "BLOCK"
        : "ALLOW",
    trustedEffectObserverIds: [LOCAL_AUTHORITY_API_KEY],
  });
  await target.start();
  await authority.start();
  const keyFile = join(directory, "acceptance.pem");
  const tokenFile = join(directory, "acceptance-token");
  writeFileSync(
    keyFile,
    generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    { mode: 0o600 },
  );
  writeFileSync(tokenFile, "synthetic-acceptance-operator-token\n", { mode: 0o600 });
  const env = {
    DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
    DECIONIS_API_URL: authority.baseUrl,
    DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    DECIONIS_TENANT_ID: TENANT_ID,
    AGENTSAFE_MODE: "enforcement",
  };
  const file = {
    version: 1,
    gateway: { upstream: target.url, listen: `${LOOPBACK}:1` },
    interception: { profile: "businesscentral/api/v2", refusalWindowMs: 100 },
    evidence: { observer: LOCAL_AUTHORITY_API_KEY },
    acceptance: { key: { file: keyFile }, operatorToken: { file: tokenFile } },
  };
  const configFile = join(directory, "agentsafe.yaml");
  writeFileSync(configFile, stringify(file));
  const silent = { stdout: () => undefined, stderr: () => undefined, color: false };
  const gateway = await Gateway.create(
    GatewayConfigLoader.load({ flags: {}, env, file, credentials: null, version: "0.0.0-demo" }),
    { env, io: silent },
  );
  const server = new GatewayHttpServer(gateway);
  const origin = `${LOOPBACK_URL}:${(await server.listen(0, LOOPBACK)).port}`;

  const plan = (origins: readonly { name: string; url: string }[]) =>
    stringify({
      version: "agent-safe.acceptance-plan/1",
      gateway: origin,
      expires_at: new Date(Date.now() + 30 * 24 * 3_600_000).toISOString().replace(/\.\d+Z$/, "Z"),
      permitted: [
        { name: "unblock-customer", method: "PATCH", path: CUSTOMER, body: { blocked: " " } },
      ],
      prohibited: [
        {
          name: "block-canary",
          method: "PATCH",
          path: CANARY,
          body: { blocked: "All" },
          canary: "customer C-90000, created for this run",
        },
      ],
      origins,
    });

  try {
    process.stdout.write(
      "\nAcceptance run 1: the agent's zone reaches the API only through the gateway\n\n",
    );
    writeFileSync(join(directory, "plan.yaml"), plan([]));
    const before = target.writes;
    const accepted = await agentsafe(
      [
        "accept",
        "--plan",
        join(directory, "plan.yaml"),
        "--token-file",
        tokenFile,
        "--out",
        join(directory, "run.jws"),
        "--json",
      ],
      {},
    );
    const answer = JSON.parse(accepted.stdout || "{}") as { verdict?: string; failures?: string[] };
    expect(
      "accept exits 0 and the gateway signed ACCEPTED",
      accepted.code === 0 && answer.verdict === "ACCEPTED",
    );
    expect("the permitted write reached the target exactly once", target.writes - before === 1);
    expect("the canary is unchanged", target.version(CANARY) === 1);

    const identity = await agentsafe(["identity", "--json", "--config", configFile], env);
    writeFileSync(join(directory, "acceptance-key.json"), identity.stdout);
    const verified = await agentsafe(
      [
        "verify",
        "acceptance",
        join(directory, "run.jws"),
        "--key",
        join(directory, "acceptance-key.json"),
        "--current",
        "--gateway",
        origin,
        "--json",
      ],
      {},
    );
    const verification = JSON.parse(verified.stdout || "{}") as {
      verdict?: string;
      currency?: { state?: string };
    };
    expect(
      "the key identity prints verifies the report, current against the running gateway",
      verified.code === 0 &&
        verification.verdict === "ACCEPTED" &&
        verification.currency?.state === "CURRENT",
    );
    const payload = JSON.parse(
      Buffer.from(
        readFileSync(join(directory, "run.jws"), "utf8").split(".")[1] ?? "",
        "base64url",
      ).toString(),
    ) as {
      permitted: { effect: { confirmation: string } | null }[];
      prohibited: { shadow: { verdict: string }; observation: { outcome: string } | null }[];
      outage: { status: number; upstream_writes: number }[];
    };
    expect(
      "the permitted write was read back as asked (CONFIRMED)",
      payload.permitted[0]?.effect?.confirmation === "CONFIRMED",
    );
    expect(
      "the prohibited write was refused in shadow, then observed UNCHANGED at its target",
      payload.prohibited[0]?.shadow.verdict === "BLOCK" &&
        payload.prohibited[0]?.observation?.outcome === "UNCHANGED",
    );
    expect(
      "with the authority unreachable, every write was refused and none reached the recording upstream",
      payload.outage.length === 2 &&
        payload.outage.every((item) => item.status === 503 && item.upstream_writes === 0),
    );

    process.stdout.write(
      "\nAcceptance run 2: the same gateway, and the agent's zone can reach the API directly\n\n",
    );
    writeFileSync(
      join(directory, "plan.yaml"),
      plan([{ name: "erp", url: `${target.url}${CUSTOMER}` }]),
    );
    const exposed = await agentsafe(
      [
        "accept",
        "--plan",
        join(directory, "plan.yaml"),
        "--token-file",
        tokenFile,
        "--out",
        join(directory, "run2.jws"),
        "--json",
      ],
      {},
    );
    const second = JSON.parse(exposed.stdout || "{}") as { verdict?: string; failures?: string[] };
    expect(
      "accept exits 1, the gateway signed NOT_ACCEPTED, and names the reachable origin",
      exposed.code === 1 &&
        second.verdict === "NOT_ACCEPTED" &&
        (second.failures ?? []).includes("origin erp: REACHABLE"),
    );
  } finally {
    await server.close(10);
    await gateway.close();
    await target.stop();
    await authority.stop();
    rmSync(directory, { recursive: true, force: true });
  }

  process.stdout.write(
    failures.length === 0
      ? "\nEvery expectation held. A run proves one deployment, under one fingerprint; this one proves the tool.\n\n"
      : `\n${failures.length} expectation(s) failed.\n\n`,
  );
  process.exit(failures.length === 0 ? 0 : 1);
}

main().catch((error: unknown) => {
  process.stderr.write(
    `${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
  );
  process.exit(1);
});
