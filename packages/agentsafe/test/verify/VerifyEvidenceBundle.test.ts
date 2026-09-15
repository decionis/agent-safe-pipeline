import { createHash, generateKeyPairSync } from "node:crypto";
import { CompactSign, compactVerify, importPKCS8, importSPKI } from "jose";
import { describe, expect, it } from "vitest";
import { HashChain } from "../../src/audit/HashChain.js";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { SECURITY_STREAM } from "../../src/incident/SecurityEvents.js";
import {
  verifyEvidenceBundle,
  type BundleFindingCode,
  type BundleSource,
} from "../../src/verify/VerifyEvidenceBundle.js";
import { EVIDENCE_BUNDLE_VERSION } from "../../src/incident/EvidenceExport.js";

const sha256 = (body: string): string =>
  `sha256:${createHash("sha256").update(body, "utf8").digest("hex")}`;

/** Three linked lines of one stream, as the executor would have written them. */
function stream(name: string, lines = 3): { readonly body: string; readonly head: HashChain } {
  const chain = new HashChain(name);
  const written: string[] = [];
  for (let seq = 1; seq <= lines; seq += 1) {
    chain.link({ event: "TEST", n: seq }, (line) => written.push(line));
  }
  return { body: `${written.join("\n")}\n`, head: chain };
}

/** A bundle as a map of files, built the way the exporter builds one. */
function bundle(
  overrides: {
    readonly audit?: string;
    readonly security?: string;
    readonly heads?: Readonly<Record<string, { readonly seq: number; readonly hash: string }>>;
    readonly drop?: string;
    readonly corrupt?: string;
    readonly manifest?: (manifest: Record<string, unknown>) => Record<string, unknown>;
  } = {},
): Map<string, string> {
  const audit = overrides.audit ?? stream(EVIDENCE_STREAM).body;
  const security = overrides.security ?? stream(SECURITY_STREAM).body;
  const attempts = `${JSON.stringify({ attempts: [], unknown: 0 }, null, 2)}\n`;
  const posture = `${JSON.stringify({ mode: "ENFORCED", failed: [], waived: [], checks: 3 }, null, 2)}\n`;
  const files = new Map<string, string>([
    ["audit.jsonl", audit],
    ["security-events.jsonl", security],
    ["open-attempts.json", attempts],
    ["posture.json", posture],
  ]);
  const auditChain = new HashChain(EVIDENCE_STREAM);
  const auditLines = audit.trim() === "" ? [] : audit.trim().split("\n");
  const lastAudit = auditLines.at(-1);
  const lastSecurity = security.trim() === "" ? undefined : security.trim().split("\n").at(-1);
  const headOf = (line: string | undefined): { readonly seq: number; readonly hash: string } => {
    if (line === undefined) return { seq: 0, hash: `sha256:${"0".repeat(64)}` };
    const parsed = JSON.parse(line) as { seq: number; hash: string };
    return { seq: parsed.seq, hash: parsed.hash };
  };
  void auditChain;
  let manifest: Record<string, unknown> = {
    version: EVIDENCE_BUNDLE_VERSION,
    exported_at: "2026-03-02T10:00:00.000Z",
    exported_by: "synthetic-oncall",
    reason: "an incident",
    package_version: "0.1.0",
    image: { digest: null, self_verified: false },
    configuration_digest: sha256("{}"),
    secrets: [],
    chains:
      overrides.heads ??
      ({ [EVIDENCE_STREAM]: headOf(lastAudit), [SECURITY_STREAM]: headOf(lastSecurity) } as Record<
        string,
        { readonly seq: number; readonly hash: string }
      >),
    files: [...files].map(([name, body]) => ({
      name,
      bytes: Buffer.byteLength(body, "utf8"),
      sha256: sha256(body),
    })),
  };
  if (overrides.manifest !== undefined) manifest = overrides.manifest(manifest);
  files.set("manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
  if (overrides.drop !== undefined) files.delete(overrides.drop);
  if (overrides.corrupt !== undefined) {
    files.set(overrides.corrupt, `${files.get(overrides.corrupt) ?? ""}tampered`);
  }
  return files;
}

const source = (
  files: Map<string, string>,
  verify?: BundleSource["verifySignature"],
): BundleSource => ({
  read: (name) => files.get(name) ?? null,
  ...(verify === undefined ? {} : { verifySignature: verify }),
});

const codes = (findings: readonly { readonly code: BundleFindingCode }[]): BundleFindingCode[] =>
  findings.map((finding) => finding.code);

describe("verifyEvidenceBundle", () => {
  it("accepts a bundle whose files and chains are what the manifest says", async () => {
    const report = await verifyEvidenceBundle(source(bundle()));
    expect(report.ok).toBe(true);
    expect(report.findings).toEqual([]);
    expect(report.files).toBe(4);
    expect(report.exportedBy).toBe("synthetic-oncall");
    expect(report.exportedAt).toBe("2026-03-02T10:00:00.000Z");
    expect(report.chains[EVIDENCE_STREAM]).toEqual({ lines: 3, head: 3 });
    expect(report.chains[SECURITY_STREAM]).toEqual({ lines: 3, head: 3 });
  });

  it("says plainly that an unsigned bundle proves only its own consistency", async () => {
    const report = await verifyEvidenceBundle(source(bundle()));
    expect(report.establishes).toBe("INTERNAL_CONSISTENCY");
  });

  it("proves origin only when a signature verifies against a key the reader brought", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const key = await importPKCS8(
      privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      "EdDSA",
    );
    const spki = await importSPKI(
      publicKey.export({ type: "spki", format: "pem" }).toString(),
      "EdDSA",
    );
    const files = bundle();
    const manifest = files.get("manifest.json") ?? "";
    const signature = await new CompactSign(Buffer.from(manifest, "utf8"))
      .setProtectedHeader({ alg: "EdDSA" })
      .sign(key);
    files.set("manifest.jws", `${signature}\n`);
    const verify = async (candidate: string, body: string): Promise<boolean> => {
      try {
        const verified = await compactVerify(candidate, spki);
        return Buffer.from(verified.payload).toString("utf8") === body;
      } catch {
        return false;
      }
    };
    const report = await verifyEvidenceBundle(source(files, verify));
    expect(report.ok).toBe(true);
    expect(report.establishes).toBe("ORIGIN_AND_CONSISTENCY");

    // A signature over a different manifest is a refusal, not an omission.
    const other = bundle({ manifest: (m) => ({ ...m, reason: "something else" }) });
    other.set("manifest.jws", `${signature}\n`);
    const refused = await verifyEvidenceBundle(source(other, verify));
    expect(codes(refused.findings)).toEqual(["BUNDLE_SIGNATURE_INVALID"]);
    expect(refused.establishes).toBe("INTERNAL_CONSISTENCY");
  });

  it("reports a flipped byte in any file, naming the file", async () => {
    for (const name of ["audit.jsonl", "open-attempts.json", "posture.json"]) {
      const report = await verifyEvidenceBundle(source(bundle({ corrupt: name })));
      expect(report.ok, name).toBe(false);
      expect(codes(report.findings), name).toContain("BUNDLE_FILE_DIGEST_MISMATCH");
      expect(report.findings[0]?.subject, name).toBe(name);
    }
  });

  it("reports a missing file, and a missing manifest before anything else", async () => {
    const missing = await verifyEvidenceBundle(source(bundle({ drop: "posture.json" })));
    expect(codes(missing.findings)).toEqual(["BUNDLE_FILE_MISSING"]);
    const none = await verifyEvidenceBundle(source(new Map()));
    expect(codes(none.findings)).toEqual(["BUNDLE_FILE_MISSING"]);
    expect(none.findings[0]?.subject).toBe("manifest.json");
    expect(none.files).toBe(0);
  });

  it("reports a manifest that is not one", async () => {
    const broken = new Map([["manifest.json", "{not json"]]);
    expect(codes((await verifyEvidenceBundle(source(broken))).findings)).toEqual([
      "BUNDLE_MANIFEST_INVALID",
    ]);
    const noFiles = new Map([
      ["manifest.json", JSON.stringify({ version: EVIDENCE_BUNDLE_VERSION })],
    ]);
    expect(codes((await verifyEvidenceBundle(source(noFiles))).findings)).toEqual([
      "BUNDLE_MANIFEST_INVALID",
    ]);
  });

  it("reports a version it does not know, without giving up on the rest", async () => {
    const report = await verifyEvidenceBundle(
      source(bundle({ manifest: (m) => ({ ...m, version: "agent-safe.evidence-bundle/9" }) })),
    );
    expect(codes(report.findings)).toEqual(["BUNDLE_VERSION_UNKNOWN"]);
    expect(report.chains[EVIDENCE_STREAM]).toEqual({ lines: 3, head: 3 });
  });

  it("reports a broken chain inside a stream the bundle carries", async () => {
    const lines = stream(EVIDENCE_STREAM).body.trim().split("\n");
    const tampered = lines.map((line, index) =>
      index === 1 ? line.replace('"TEST"', '"CHANGED"') : line,
    );
    const report = await verifyEvidenceBundle(
      source(bundle({ audit: `${tampered.join("\n")}\n` })),
    );
    expect(report.ok).toBe(false);
    expect(codes(report.findings)).toContain("BUNDLE_CHAIN_BROKEN");
    expect(report.findings[0]?.subject).toBe("audit.jsonl:2");
  });

  it("reports a stream whose last line is not the head the manifest claims", async () => {
    const report = await verifyEvidenceBundle(
      source(
        bundle({
          heads: {
            [EVIDENCE_STREAM]: { seq: 9, hash: `sha256:${"c".repeat(64)}` },
            [SECURITY_STREAM]: { seq: 3, hash: `sha256:${"d".repeat(64)}` },
          },
        }),
      ),
    );
    expect(report.ok).toBe(false);
    expect(codes(report.findings)).toEqual([
      "BUNDLE_CHAIN_HEAD_MISMATCH",
      "BUNDLE_CHAIN_HEAD_MISMATCH",
    ]);
  });

  it("sums the lines the process no longer held", async () => {
    const report = await verifyEvidenceBundle(
      source(
        bundle({
          manifest: (m) => ({
            ...m,
            files: (m["files"] as { name: string }[]).map((file) =>
              file.name === "audit.jsonl" ? { ...file, dropped: 12 } : file,
            ),
          }),
        }),
      ),
    );
    expect(report.dropped).toBe(12);
  });

  it("reports a file entry with no name rather than skipping it silently", async () => {
    const report = await verifyEvidenceBundle(
      source(bundle({ manifest: (m) => ({ ...m, files: [{ sha256: "sha256:x" }] }) })),
    );
    expect(codes(report.findings)).toEqual(["BUNDLE_MANIFEST_INVALID"]);
  });

  it("reports a size that disagrees even when the digest was also changed to match", async () => {
    const files = bundle();
    const body = `${files.get("posture.json") ?? ""} `;
    files.set("posture.json", body);
    const manifest = JSON.parse(files.get("manifest.json") ?? "{}") as {
      files: { name: string; bytes: number; sha256: string }[];
    };
    for (const file of manifest.files) {
      if (file.name === "posture.json") file.sha256 = sha256(body);
    }
    files.set("manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
    const report = await verifyEvidenceBundle(source(files));
    expect(codes(report.findings)).toEqual(["BUNDLE_FILE_SIZE_MISMATCH"]);
  });

  it("holds an empty stream to the genesis head rather than inventing one", async () => {
    const report = await verifyEvidenceBundle(source(bundle({ audit: "\n" })));
    expect(report.chains[EVIDENCE_STREAM]).toBeUndefined();
    expect(report.ok).toBe(true);
  });

  it("ignores a signature when the reader brought no verifier, and says so", async () => {
    const files = bundle();
    files.set("manifest.jws", "not.a.jws\n");
    const report = await verifyEvidenceBundle(source(files));
    expect(report.ok).toBe(true);
    expect(report.establishes).toBe("INTERNAL_CONSISTENCY");
  });
});
