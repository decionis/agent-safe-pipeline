import { createHash, generateKeyPairSync } from "node:crypto";
import { CompactSign, importPKCS8 } from "jose";
import { describe, expect, it } from "vitest";
import { HashChain } from "../../src/audit/HashChain.js";
import {
  EVIDENCE_BUNDLE_VERSION,
  EvidenceError,
  EvidenceExport,
  LineWindow,
  type EvidenceBundleManifest,
} from "../../src/incident/EvidenceExport.js";
import type { PostureReport } from "../../src/posture/HostPosture.js";

const posture: PostureReport = {
  mode: "ENFORCED",
  findings: [
    { id: "ROOT_UID", ok: true },
    { id: "NODE_ENV", ok: false, subject: "development" },
  ],
  failed: [{ id: "NODE_ENV", ok: false, subject: "development" }],
  waived: [{ id: "ROOT_WRITABLE", ok: false }],
};

const code = (work: () => unknown): string => {
  try {
    work();
  } catch (error) {
    return error instanceof EvidenceError ? error.code : `unexpected ${String(error)}`;
  }
  return "no refusal";
};

interface Built {
  readonly exporter: EvidenceExport;
  readonly files: Map<string, string>;
  readonly dirs: string[];
  readonly audit: LineWindow;
  readonly security: LineWindow;
}

function build(
  options: {
    readonly dir?: string | null;
    readonly capacity?: number;
    readonly sign?: (payload: Uint8Array) => Promise<string>;
    readonly failWrite?: boolean;
  } = {},
): Built {
  const files = new Map<string, string>();
  const dirs: string[] = [];
  const audit = new LineWindow(options.capacity ?? 100);
  const security = new LineWindow(options.capacity ?? 100);
  const exporter = new EvidenceExport({
    dir: options.dir === undefined ? "/var/lib/agent-safe/evidence" : options.dir,
    audit,
    security,
    packageVersion: "0.1.0",
    imageDigest: `sha256:${"a".repeat(64)}`,
    posture: () => posture,
    openAttempts: () => ({ attempts: [], unknown: 0 }),
    heads: () => ({
      "agent-safe.executor-evidence/1": { seq: 3, hash: `sha256:${"b".repeat(64)}` },
    }),
    configuration: () => ({ mode: "ENFORCEMENT" }),
    secrets: () => [{ name: "DECIONIS_API_KEY", present: true, rotations: 2 }],
    clock: () => new Date("2026-03-02T10:00:00.000Z"),
    ...(options.sign === undefined ? {} : { sign: options.sign }),
    writeFile: (path, body) => {
      if (options.failWrite === true) throw new Error("EROFS");
      files.set(path, body);
    },
    makeDir: (path) => dirs.push(path),
  });
  return { exporter, files, dirs, audit, security };
}

const manifestOf = (files: Map<string, string>): EvidenceBundleManifest =>
  JSON.parse(
    files.get("/var/lib/agent-safe/evidence/2026-03-02T10-00-00-000Z/manifest.json") ?? "{}",
  ) as EvidenceBundleManifest;

describe("LineWindow", () => {
  it("keeps the last lines and counts what fell off the end", () => {
    const window = new LineWindow(3);
    for (const line of ["a", "b", "c", "d", "e"]) window.push(line);
    expect([...window.lines]).toEqual(["c", "d", "e"]);
    expect(window.dropped).toBe(2);
    expect(window.capacity).toBe(3);
    window.clear();
    expect([...window.lines]).toEqual([]);
    expect(window.dropped).toBe(0);
  });

  it("passes every line through to the writer it wraps", () => {
    const written: string[] = [];
    const window = new LineWindow(2);
    const write = window.tee((line) => written.push(line));
    write("one");
    write("two");
    write("three");
    expect(written).toEqual(["one", "two", "three"]);
    expect([...window.lines]).toEqual(["two", "three"]);
    expect(window.dropped).toBe(1);
  });

  it("refuses a capacity that is not one", () => {
    for (const capacity of [0, -1, 1.5, 200_001, Number.NaN]) {
      expect(() => new LineWindow(capacity), String(capacity)).toThrow("EVIDENCE_WINDOW_INVALID");
    }
    expect(new LineWindow(1).capacity).toBe(1);
  });
});

describe("EvidenceExport", () => {
  it("refuses to export when no directory was configured", async () => {
    const { exporter } = build({ dir: null });
    expect(exporter.configured).toBe(false);
    await expect(
      exporter.export({ principal: "synthetic-oncall", reason: "an incident" }),
    ).rejects.toThrow("EVIDENCE_DIR_NOT_CONFIGURED");
  });

  it("writes five files and digests every one of them in the manifest", async () => {
    const built = build();
    built.audit.push('{"stream":"agent-safe.executor-evidence/1","seq":1}');
    built.security.push('{"stream":"agent-safe.security/1","seq":1}');
    const bundle = await built.exporter.export({
      principal: "synthetic-oncall",
      reason: "payment rail incident",
    });
    expect(bundle.directory).toBe("/var/lib/agent-safe/evidence/2026-03-02T10-00-00-000Z");
    expect(built.dirs).toEqual([bundle.directory]);
    expect([...built.files.keys()].map((path) => path.split("/").pop())).toEqual([
      "audit.jsonl",
      "security-events.jsonl",
      "open-attempts.json",
      "posture.json",
      "manifest.json",
    ]);
    const manifest = manifestOf(built.files);
    expect(manifest.version).toBe(EVIDENCE_BUNDLE_VERSION);
    expect(manifest.exported_by).toBe("synthetic-oncall");
    expect(manifest.reason).toBe("payment rail incident");
    expect(manifest.files.map((file) => file.name)).toEqual([
      "audit.jsonl",
      "security-events.jsonl",
      "open-attempts.json",
      "posture.json",
    ]);
    for (const file of manifest.files) {
      const body = built.files.get(`${bundle.directory}/${file.name}`) ?? "";
      expect(file.sha256, file.name).toBe(
        `sha256:${createHash("sha256").update(body, "utf8").digest("hex")}`,
      );
      expect(file.bytes, file.name).toBe(Buffer.byteLength(body, "utf8"));
    }
  });

  it("says the image digest was reported rather than verified", async () => {
    const built = build();
    await built.exporter.export({ principal: "synthetic-oncall", reason: "an incident" });
    const manifest = manifestOf(built.files);
    expect(manifest.image).toEqual({ digest: `sha256:${"a".repeat(64)}`, self_verified: false });
  });

  it("carries the chain heads and the configuration as a digest, not as itself", async () => {
    const built = build();
    await built.exporter.export({ principal: "synthetic-oncall", reason: "an incident" });
    const manifest = manifestOf(built.files);
    expect(manifest.chains["agent-safe.executor-evidence/1"]).toEqual({
      seq: 3,
      hash: `sha256:${"b".repeat(64)}`,
    });
    expect(manifest.configuration_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(manifest)).not.toContain("ENFORCEMENT");
  });

  it("names each secret with its presence and rotations, and never a value or a digest of one", async () => {
    const built = build();
    await built.exporter.export({ principal: "synthetic-oncall", reason: "an incident" });
    const manifest = manifestOf(built.files);
    expect(manifest.secrets).toEqual([{ name: "DECIONIS_API_KEY", present: true, rotations: 2 }]);
    const text = JSON.stringify(manifest);
    expect(text).not.toContain("value");
    expect(text).not.toContain("sha256:d");
  });

  it("carries the posture by check, never by the value a check saw", async () => {
    const built = build();
    await built.exporter.export({ principal: "synthetic-oncall", reason: "an incident" });
    const written =
      built.files.get("/var/lib/agent-safe/evidence/2026-03-02T10-00-00-000Z/posture.json") ?? "";
    expect(JSON.parse(written)).toEqual({
      mode: "ENFORCED",
      failed: ["NODE_ENV"],
      waived: ["ROOT_WRITABLE"],
      checks: 2,
    });
    expect(written).not.toContain("development");
  });

  it("reports the lines it no longer held, so a partial range cannot look complete", async () => {
    const built = build({ capacity: 2 });
    for (const line of ["a", "b", "c", "d"]) built.audit.push(line);
    await built.exporter.export({ principal: "synthetic-oncall", reason: "an incident" });
    const manifest = manifestOf(built.files);
    const audit = manifest.files.find((file) => file.name === "audit.jsonl");
    expect(audit?.dropped).toBe(2);
    expect(manifest.files.find((file) => file.name === "posture.json")?.dropped).toBeUndefined();
  });

  it("truncates an operator's reason rather than carrying an unbounded string", async () => {
    const built = build();
    await built.exporter.export({ principal: "synthetic-oncall", reason: "x".repeat(400) });
    expect(manifestOf(built.files).reason.length).toBe(200);
  });

  it("signs the manifest when a key is configured, and says so", async () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const key = await importPKCS8(pem, "EdDSA");
    const built = build({
      sign: async (payload) =>
        await new CompactSign(payload).setProtectedHeader({ alg: "EdDSA" }).sign(key),
    });
    const bundle = await built.exporter.export({
      principal: "synthetic-oncall",
      reason: "an incident",
    });
    expect(bundle.signature).not.toBeNull();
    expect(
      built.files.get("/var/lib/agent-safe/evidence/2026-03-02T10-00-00-000Z/manifest.jws"),
    ).toContain(bundle.signature ?? "");
    const unsigned = await build().exporter.export({
      principal: "synthetic-oncall",
      reason: "an incident",
    });
    expect(unsigned.signature).toBeNull();
  });

  it("refuses rather than half-writing when the volume will not take it", async () => {
    const built = build({ failWrite: true });
    await expect(
      built.exporter.export({ principal: "synthetic-oncall", reason: "an incident" }),
    ).rejects.toThrow("EVIDENCE_WRITE_FAILED");
    expect(built.files.size).toBe(0);
  });

  it("refuses when the signing key cannot sign, rather than writing an unsigned bundle quietly", async () => {
    const built = build({ sign: () => Promise.reject(new Error("BAD_KEY")) });
    await expect(
      built.exporter.export({ principal: "synthetic-oncall", reason: "an incident" }),
    ).rejects.toThrow("EVIDENCE_SIGNING_FAILED");
    expect([...built.files.keys()].some((path) => path.endsWith("manifest.json"))).toBe(false);
  });

  it("names a fresh directory per export, so two in one incident do not overwrite", async () => {
    const dirs: string[] = [];
    let tick = 0;
    const exporter = new EvidenceExport({
      dir: "/evidence",
      audit: new LineWindow(10),
      security: new LineWindow(10),
      packageVersion: "0.1.0",
      imageDigest: null,
      posture: () => posture,
      openAttempts: () => ({}),
      heads: () => ({}),
      configuration: () => ({}),
      secrets: () => [],
      clock: () => new Date(Date.UTC(2026, 2, 2, 10, 0, tick++)),
      writeFile: () => undefined,
      makeDir: (path) => dirs.push(path),
    });
    await exporter.export({ principal: "synthetic-oncall", reason: "one" });
    await exporter.export({ principal: "synthetic-oncall", reason: "two" });
    expect(new Set(dirs).size).toBe(2);
  });

  it("is the only writer of its own error codes", () => {
    expect(code(() => new EvidenceError("EVIDENCE_WRITE_FAILED"))).toBe("no refusal");
    const error = new EvidenceError("EVIDENCE_DIR_NOT_CONFIGURED");
    expect(error.name).toBe("EvidenceError");
    expect(error.message).toBe("EVIDENCE_DIR_NOT_CONFIGURED");
  });

  it("writes lines the chain produced, so the bundle's streams verify", async () => {
    const built = build();
    const chain = new HashChain("agent-safe.executor-evidence/1");
    const write = built.audit.tee(() => undefined);
    for (const seq of [1, 2, 3]) chain.link({ event: "TEST", seq }, write);
    await built.exporter.export({ principal: "synthetic-oncall", reason: "an incident" });
    const body =
      built.files.get("/var/lib/agent-safe/evidence/2026-03-02T10-00-00-000Z/audit.jsonl") ?? "";
    expect(body.trim().split("\n").length).toBe(3);
    expect(JSON.parse(body.trim().split("\n")[2] ?? "{}")).toMatchObject({ seq: 3 });
  });
});
