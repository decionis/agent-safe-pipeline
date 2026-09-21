// End-to-end tests: spawn the real action entrypoint with INPUT_* env vars
// against a local mock Decionis API, and assert exit codes, outputs, summary,
// and — critically — the timing behavior of speculative shadow mode and the
// local-verdict short-circuit.
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const INDEX = fileURLToPath(new URL("../src/index.mjs", import.meta.url));

const ALLOW_RESPONSE = {
  outcome: "APPROVE",
  dossier_id: "dsr-int",
  verification: { signature: "sig-int" },
  policy_version: "pv-1",
  reason_codes: ["ok"],
};

const openServers = [];
after(async () => {
  await Promise.all(openServers.map((close) => close()));
});

/** Start a mock Decionis API. `routes` maps URL suffixes to {delayMs, status, body}. */
async function startMockApi(routes) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      const route =
        Object.entries(routes).find(([suffix]) => req.url?.endsWith(suffix))?.[1] ?? routes["*"];
      requests.push({ url: req.url, body: data ? JSON.parse(data) : null, at: Date.now() });
      const { delayMs = 0, status = 200, body = {} } = route ?? {};
      setTimeout(() => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      }, delayMs);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const close = () =>
    new Promise((resolve) => {
      server.closeAllConnections?.();
      server.close(resolve);
    });
  openServers.push(close);
  return { url: `http://127.0.0.1:${server.address().port}`, requests, close };
}

/** Parse GITHUB_OUTPUT heredoc format into a map (last write wins). */
function parseOutputs(text) {
  const outputs = {};
  // An output name is a word; the delimiter after `<<` is what the writer chose.
  const re = /^([\w-]+)<<(\S+)\n([\s\S]*?)\n\2$/gm;
  let m;
  while ((m = re.exec(text)) !== null) outputs[m[1]] = m[3];
  return outputs;
}

/** Run the action with the given inputs; returns exit code, logs, outputs, summary. */
async function runAction({ inputs = {}, policy = null, timeoutMs = 15000 }) {
  const dir = await mkdtemp(join(tmpdir(), "govern-int-"));
  const outputFile = join(dir, "outputs.txt");
  const summaryFile = join(dir, "summary.md");
  await writeFile(outputFile, "");
  await writeFile(summaryFile, "");
  if (policy) await writeFile(join(dir, "DECIONIS_POLICY.md"), policy);

  const base = Object.fromEntries(
    Object.entries(process.env).filter(
      ([k]) => !k.startsWith("GITHUB_") && !k.startsWith("INPUT_"),
    ),
  );
  const env = {
    ...base,
    GITHUB_OUTPUT: outputFile,
    GITHUB_STEP_SUMMARY: summaryFile,
    GITHUB_WORKSPACE: dir,
    ...Object.fromEntries(
      Object.entries(inputs).map(([k, v]) => [
        `INPUT_${k.toUpperCase().replace(/-/g, "_")}`,
        String(v),
      ]),
    ),
  };

  const startedAt = Date.now();
  const child = spawn(process.execPath, [INDEX], { env, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  const code = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`action did not exit within ${timeoutMs}ms\nstdout:\n${stdout}`));
    }, timeoutMs);
    child.on("close", (c) => {
      clearTimeout(timer);
      resolve(c ?? 0);
    });
  });
  return {
    code,
    stdout,
    stderr,
    durationMs: Date.now() - startedAt,
    outputs: parseOutputs(await readFile(outputFile, "utf8")),
    summary: await readFile(summaryFile, "utf8"),
  };
}

// GitHub injects action.yml defaults as INPUT_* env vars; a bare spawn does
// not, so tests that rely on the default policy path pass it explicitly.
const CREDS = {
  "api-key": "test-key",
  "org-id": "org-int",
  "workflow-key": "wf-int",
  "policy-file": "DECIONIS_POLICY.md",
};
const MARK = "node -e \"console.log('CMD_TS_' + Date.now())\"";
const markTime = (stdout) => {
  const m = /CMD_TS_(\d+)/.exec(stdout);
  return m ? Number(m[1]) : null;
};

const POLICY_BLOCK = `# Policy\n\n\`\`\`decionis\n{"version":1,"rules":[{"name":"Block gated","all":[{"field":"context.gate","op":"eq","value":true}],"action":"block","domain":"*"}]}\n\`\`\`\n`;
const POLICY_ALLOW = POLICY_BLOCK.replace('"action":"block"', '"action":"allow"').replace(
  "Block gated",
  "Allow gated",
);

describe("integration: speculative shadow (branch A)", () => {
  it("(a) starts the command before the delayed API responds, exits 0, records the verdict", async () => {
    const api = await startMockApi({ "*": { delayMs: 3000, body: ALLOW_RESPONSE } });
    const t0 = Date.now();
    const r = await runAction({
      inputs: {
        ...CREDS,
        mode: "shadow",
        run: MARK,
        "api-base-url": api.url,
        "request-timeout-ms": "8000",
      },
    });
    assert.equal(r.code, 0);
    const cmdTs = markTime(r.stdout);
    assert.ok(cmdTs, "command marker printed");
    assert.ok(cmdTs - t0 < 2500, `command started fast (took ${cmdTs - t0}ms)`);
    assert.ok(r.durationMs >= 2900, "step waited for the background verdict in grace");
    assert.equal(r.outputs.decision, "allow"); // APPROVE normalized
    assert.equal(r.outputs["decision-source"], "api");
    assert.equal(r.outputs.executed, "true");
    assert.match(r.outputs["verify-url"], /dsr-int/);
    assert.match(r.stdout, /Decionis timing —/);
    assert.equal(
      (r.summary.match(/Decionis Action Gate/g) ?? []).length,
      1,
      "summary written once",
    );
    await api.close();
  });

  it("(b) API unreachable: step exits with the command's code and only notices", async () => {
    const r = await runAction({
      inputs: {
        ...CREDS,
        mode: "shadow",
        run: 'node -e "process.exit(7)"',
        "api-base-url": "http://127.0.0.1:9",
        "request-timeout-ms": "2000",
      },
    });
    assert.equal(r.code, 7);
    assert.match(r.stdout, /::notice::Decionis \(non-fatal\) shadow evaluation/);
    assert.doesNotMatch(r.stdout, /::error::/);
    assert.equal(r.outputs.decision, "");
  });

  it("(c) shadow exit code is exactly the command's, even on success paths", async () => {
    const api = await startMockApi({ "*": { body: ALLOW_RESPONSE } });
    const r = await runAction({
      inputs: {
        ...CREDS,
        mode: "shadow",
        run: 'node -e "process.exit(3)"',
        "api-base-url": api.url,
        "request-timeout-ms": "3000",
      },
    });
    assert.equal(r.code, 3);
    assert.equal(r.outputs.decision, "allow");
    await api.close();
  });

  it("(k) missing credentials in shadow: command still runs, step never fails", async () => {
    const r = await runAction({
      inputs: { mode: "shadow", run: 'node -e "process.exit(5)"' },
    });
    assert.equal(r.code, 5);
    assert.match(r.stdout, /not configured yet/);
    assert.doesNotMatch(r.stdout, /::error::/);
  });
});

describe("integration: local verdict short-circuit (branches C/D)", () => {
  it("(d) local block fails fast without waiting for a slow API, and records bounded", async () => {
    const api = await startMockApi({ "*": { delayMs: 5000, body: ALLOW_RESPONSE } });
    const r = await runAction({
      inputs: {
        ...CREDS,
        mode: "enforce",
        run: MARK,
        payload: '{"gate":true}',
        "api-base-url": api.url,
        "request-timeout-ms": "1500",
      },
      policy: POLICY_BLOCK,
    });
    assert.equal(r.code, 1);
    assert.ok(r.durationMs < 4000, `short-circuited (took ${r.durationMs}ms vs 5s API)`);
    assert.equal(markTime(r.stdout), null, "gated command never ran");
    assert.equal(r.outputs.executed, "false");
    assert.equal(r.outputs.decision, "block");
    assert.equal(r.outputs["decision-source"], "local");
    assert.match(r.stdout, /BLOCKED execution locally \(rule "Block gated"/);
    assert.match(r.stdout, /⚡ Decionis local verdict 'block'/);
    assert.equal(api.requests.length, 1, "bounded dossier-recording call was attempted");
    await api.close();
  });

  it("(e) local allow runs the command while notarizing; API disagreement flags a mismatch", async () => {
    const api = await startMockApi({
      "*": { delayMs: 300, body: { ...ALLOW_RESPONSE, outcome: "REJECT" } },
    });
    const r = await runAction({
      inputs: {
        ...CREDS,
        mode: "enforce",
        run: 'node -e "setTimeout(() => {}, 800)"',
        payload: '{"gate":true}',
        "api-base-url": api.url,
        "request-timeout-ms": "5000",
      },
      policy: POLICY_ALLOW,
    });
    assert.equal(r.code, 0);
    assert.equal(r.outputs.executed, "true");
    assert.equal(r.outputs.decision, "allow", "the acted local verdict is reported");
    assert.equal(r.outputs["decision-source"], "local");
    assert.equal(r.outputs["verdict-mismatch"], "true");
    assert.equal(r.outputs["dossier-id"], "dsr-int", "API dossier still recorded");
    assert.match(r.stdout, /::warning::Decionis verdict mismatch/);
    await api.close();
  });

  it("(f) strict mode: deterministic local allow makes zero network calls", async () => {
    const api = await startMockApi({ "*": { body: ALLOW_RESPONSE } });
    const r = await runAction({
      inputs: {
        ...CREDS,
        mode: "enforce",
        run: MARK,
        payload: '{"gate":true}',
        "local-eval": "strict",
        "api-base-url": api.url,
      },
      policy: POLICY_ALLOW,
    });
    assert.equal(r.code, 0);
    assert.ok(markTime(r.stdout), "command ran");
    assert.equal(api.requests.length, 0, "no API request was made");
    assert.equal(r.outputs.decision, "allow");
    assert.equal(r.outputs["decision-source"], "local");
    assert.match(r.stdout, /API roundtrip skipped \(local-eval: strict\)/);
    await api.close();
  });
});

describe("integration: legacy blocking path (branch E)", () => {
  it("(g) no policy file: an API block fails the advisory step exactly like v1.8", async () => {
    const api = await startMockApi({ "*": { body: { ...ALLOW_RESPONSE, outcome: "REJECT" } } });
    const r = await runAction({
      inputs: { ...CREDS, mode: "enforce", "api-base-url": api.url },
    });
    assert.equal(r.code, 1);
    assert.equal(r.outputs.decision, "block");
    assert.equal(r.outputs["decision-source"], "api");
    assert.match(r.stdout, /::error::Decionis blocked this step/);
    await api.close();
  });

  it("(h) enforce fails closed on an API 500", async () => {
    const api = await startMockApi({ "*": { status: 500, body: { error: "boom" } } });
    const r = await runAction({
      inputs: { ...CREDS, mode: "enforce", "api-base-url": api.url },
    });
    assert.equal(r.code, 1);
    assert.match(r.stdout, /::error::Decionis API returned 500/);
    await api.close();
  });

  it("(i) shadow verdict-only swallows an API 500 and exits 0", async () => {
    const api = await startMockApi({ "*": { status: 500, body: { error: "boom" } } });
    const r = await runAction({
      inputs: { ...CREDS, mode: "shadow", "api-base-url": api.url },
    });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /::notice::Decionis \(non-fatal\) shadow evaluation/);
    assert.doesNotMatch(r.stdout, /::error::/);
    assert.ok(r.summary.includes("Decionis Action Gate"), "summary still written");
    await api.close();
  });

  it("(j) request-grant disables speculation: verdict, then grant, then the command", async () => {
    const api = await startMockApi({
      "/v1/protocol/evaluate-decision": { delayMs: 400, body: ALLOW_RESPONSE },
      "/v1/protocol/execution-grants/issue": {
        body: { execution_grant: "grant-jwt", expires_at: "2027-01-01T00:00:00Z" },
      },
    });
    const r = await runAction({
      inputs: {
        ...CREDS,
        mode: "shadow",
        run: "node -e \"console.log('CMD_TS_' + Date.now() + '_GRANT=' + (process.env.DECIONIS_EXECUTION_GRANT || 'none'))\"",
        "request-grant": "true",
        "api-base-url": api.url,
        "request-timeout-ms": "5000",
      },
    });
    assert.equal(r.code, 0);
    const cmdTs = markTime(r.stdout);
    assert.ok(cmdTs, "command ran");
    assert.ok(
      cmdTs >= api.requests[0].at,
      "the evaluate call completed before the command started (no speculation with grants)",
    );
    assert.match(r.stdout, /_GRANT=grant-jwt/);
    assert.equal(r.outputs["execution-grant"], "grant-jwt");
    await api.close();
  });
});
