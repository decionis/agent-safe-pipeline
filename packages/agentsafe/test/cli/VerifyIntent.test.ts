import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  renderVerifyIntentReport,
  runVerifyIntent,
  type VerifyIntentReport,
} from "../../src/cli/VerifyIntent.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const VECTORS_DIR = new URL("../../../../conformance/vectors/", import.meta.url);

async function corpus(): Promise<Record<string, string>> {
  const principal = await readFile(new URL("compromised-principal.json", VECTORS_DIR), "utf8");
  const zero = await readFile(new URL("negative-zero.json", VECTORS_DIR), "utf8");
  const broken = JSON.parse(principal) as Record<string, unknown>;
  return {
    "/work/vectors/compromised-principal.json": principal,
    "/work/vectors/negative-zero.json": zero,
    "/work/vectors/README.md": "# not a vector",
    "/work/broken.json": JSON.stringify({ ...broken, intent_hash: `sha256:${"0".repeat(64)}` }),
    "/work/binding.json": JSON.stringify(broken["binding"]),
    "/work/notes.txt": "plain text",
  };
}

describe("agentsafe verify intent", () => {
  it("checks a directory of vectors and reports each, skipping what is not JSON", async () => {
    const io = fakeProcess({ files: await corpus() });
    const report = runVerifyIntent(io, ["/work/vectors"]);
    expect(io.exits).toEqual([0]);
    expect(report?.files.map((file) => file.file)).toEqual([
      "/work/vectors/compromised-principal.json",
      "/work/vectors/negative-zero.json",
    ]);
    expect(report).toMatchObject({ reproduced: 2, computed: 0, failed: 0, exit: 0 });
    const text = io.out.join("");
    expect(text).toContain("base + 8 mutations");
    expect(text).toContain("9 distinct hashes");
    expect(text).toContain("CONFORMS: every pinned hash reproduced");
  });

  it("fails on a vector that does not reproduce and names the finding", async () => {
    const io = fakeProcess({ files: await corpus() });
    const report = runVerifyIntent(io, ["/work/broken.json", "/work/vectors/negative-zero.json"]);
    expect(io.exits).toEqual([1]);
    expect(report).toMatchObject({ reproduced: 1, failed: 1, exit: 1 });
    const text = io.out.join("");
    expect(text).toContain("FAILED");
    expect(text).toContain("HASH_MISMATCH: expected sha256:000");
    expect(text).toContain("DOES NOT CONFORM: 1 of 2 did not reproduce");
  });

  it("computes the bytes and the hash of a bare binding for comparison", async () => {
    const io = fakeProcess({ files: await corpus() });
    const report = runVerifyIntent(io, ["/work/binding.json"]);
    expect(io.exits).toEqual([0]);
    expect(report).toMatchObject({ reproduced: 0, computed: 1, failed: 0 });
    const text = io.out.join("");
    expect(text).toContain("COMPUTED");
    expect(text).toContain('canonical   {"action":');
    expect(text).toContain("hash        sha256:");
    expect(text).toContain("nothing was pinned");
  });

  it("prints one JSON line when asked", async () => {
    const io = fakeProcess({ files: await corpus() });
    runVerifyIntent(io, ["--json", "/work/vectors/negative-zero.json"]);
    expect(io.out).toHaveLength(1);
    const parsed = JSON.parse(io.out[0] ?? "") as VerifyIntentReport;
    expect(parsed.version).toBe("agent-safe.intent-conformance/1");
    expect(parsed.files[0]).toMatchObject({ kind: "canonical", ok: true, hashes: 1 });
    expect(io.exits).toEqual([0]);
  });

  it("refuses to run without a path, with an unknown option, or on a file it cannot read", async () => {
    const files = await corpus();
    const none = fakeProcess({ files });
    expect(runVerifyIntent(none, [])).toBeNull();
    expect(none.exits).toEqual([2]);
    expect(none.err.join("")).toContain("Name a vector");
    const option = fakeProcess({ files });
    expect(runVerifyIntent(option, ["--strict", "/work/binding.json"])).toBeNull();
    expect(option.exits).toEqual([2]);
    expect(option.err.join("")).toContain("UNKNOWN_OPTION");
    const missing = fakeProcess({ files });
    const report = runVerifyIntent(missing, ["/work/absent.json", "/work/notes.txt"]);
    expect(missing.exits).toEqual([2]);
    expect(report?.unreadable).toEqual(["/work/absent.json", "/work/notes.txt"]);
    expect(missing.out.join("")).toContain("UNREADABLE");
    expect(missing.out.join("")).toContain("NOTHING CHECKED");
  });

  it("colors the verdict on a terminal and not otherwise", async () => {
    const io = fakeProcess({ files: await corpus() });
    const report = runVerifyIntent(io, ["/work/vectors/negative-zero.json"]);
    if (report === null) throw new Error("no report");
    const colored = renderVerifyIntentReport(report, { color: true });
    expect(colored).toContain(String.fromCharCode(27));
    expect(renderVerifyIntentReport(report, { color: false })).not.toContain(
      String.fromCharCode(27),
    );
  });
});
