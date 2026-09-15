import { createHash } from "node:crypto";
import { EVIDENCE_BUNDLE_VERSION } from "../incident/EvidenceExport.js";
import { verifyAuditChain, type ChainFinding } from "./VerifyAuditChain.js";

export type BundleFindingCode =
  | "BUNDLE_MANIFEST_INVALID"
  | "BUNDLE_VERSION_UNKNOWN"
  | "BUNDLE_FILE_MISSING"
  | "BUNDLE_FILE_DIGEST_MISMATCH"
  | "BUNDLE_FILE_SIZE_MISMATCH"
  | "BUNDLE_CHAIN_BROKEN"
  | "BUNDLE_CHAIN_HEAD_MISMATCH"
  | "BUNDLE_SIGNATURE_INVALID";

export interface BundleFinding {
  readonly code: BundleFindingCode;
  /** The file or stream the finding is about, when it is about one. */
  readonly subject: string | null;
  readonly expected?: string | number;
  readonly found?: string | number;
}

/**
 * What a verified bundle establishes. `origin` is the distinction that
 * matters: a bundle with no signature is internally consistent and says
 * nothing about who made it, and a reader who conflates the two has a
 * stronger belief than the evidence supports.
 */
export interface BundleVerification {
  readonly ok: boolean;
  readonly establishes: "INTERNAL_CONSISTENCY" | "ORIGIN_AND_CONSISTENCY";
  readonly exportedAt: string | null;
  readonly exportedBy: string | null;
  readonly files: number;
  /** Lines the process no longer held, summed across the streams that report it. */
  readonly dropped: number;
  readonly chains: Readonly<Record<string, { readonly lines: number; readonly head: number }>>;
  readonly findings: readonly BundleFinding[];
}

export interface BundleSource {
  /** The bundle's files by name; absent returns null rather than throwing. */
  read(name: string): string | null;
  /**
   * Verifies the detached JWS over the manifest bytes. Absent means no
   * verifier was supplied, which is not the same as a bundle without a
   * signature and is reported as such.
   */
  verifySignature?(signature: string, manifest: string): Promise<boolean>;
}

interface ManifestShape {
  readonly version?: unknown;
  readonly exported_at?: unknown;
  readonly exported_by?: unknown;
  readonly chains?: unknown;
  readonly files?: unknown;
}

const sha256 = (body: string): string =>
  `sha256:${createHash("sha256").update(body, "utf8").digest("hex")}`;

const CHAIN_FILES: Readonly<Record<string, string>> = {
  "audit.jsonl": "agent-safe.executor-evidence/1",
  "security-events.jsonl": "agent-safe.security/1",
};

/**
 * Verifies an evidence bundle offline: it recomputes every file's digest
 * against the manifest, walks both chained streams, checks that each stream's
 * last line is the head the manifest claims, and verifies the signature when
 * a bundle carries one and a verifier was supplied.
 *
 * It needs no key, no service and no network to do the first three. That is
 * the point of a bundle: an auditor holding the files can establish what the
 * files say without asking the party that produced them.
 */
export async function verifyEvidenceBundle(source: BundleSource): Promise<BundleVerification> {
  const findings: BundleFinding[] = [];
  const raw = source.read("manifest.json");
  if (raw === null) {
    return refusal([{ code: "BUNDLE_FILE_MISSING", subject: "manifest.json" }]);
  }
  let manifest: ManifestShape;
  try {
    manifest = JSON.parse(raw) as ManifestShape;
  } catch {
    return refusal([{ code: "BUNDLE_MANIFEST_INVALID", subject: "manifest.json" }]);
  }
  if (manifest.version !== EVIDENCE_BUNDLE_VERSION) {
    findings.push({
      code: "BUNDLE_VERSION_UNKNOWN",
      subject: "manifest.json",
      expected: EVIDENCE_BUNDLE_VERSION,
      found: String(manifest.version),
    });
  }
  const files = Array.isArray(manifest.files) ? manifest.files : null;
  if (files === null) {
    return refusal([{ code: "BUNDLE_MANIFEST_INVALID", subject: "files" }]);
  }
  const claimedHeads = asHeads(manifest.chains);
  const chains: Record<string, { readonly lines: number; readonly head: number }> = {};
  let dropped = 0;
  for (const entry of files) {
    const file = entry as { name?: unknown; sha256?: unknown; bytes?: unknown; dropped?: unknown };
    const name = typeof file.name === "string" ? file.name : null;
    if (name === null) {
      findings.push({ code: "BUNDLE_MANIFEST_INVALID", subject: "files[].name" });
      continue;
    }
    if (typeof file.dropped === "number") dropped += file.dropped;
    const body = source.read(name);
    if (body === null) {
      findings.push({ code: "BUNDLE_FILE_MISSING", subject: name });
      continue;
    }
    const digest = sha256(body);
    if (digest !== file.sha256) {
      findings.push({
        code: "BUNDLE_FILE_DIGEST_MISMATCH",
        subject: name,
        expected: String(file.sha256),
        found: digest,
      });
    }
    const bytes = Buffer.byteLength(body, "utf8");
    if (typeof file.bytes === "number" && bytes !== file.bytes) {
      findings.push({
        code: "BUNDLE_FILE_SIZE_MISMATCH",
        subject: name,
        expected: file.bytes,
        found: bytes,
      });
    }
    const stream = CHAIN_FILES[name];
    if (stream === undefined) continue;
    const chain = verifyAuditChain(body.replace(/\n$/, "").split("\n"));
    const summary = chain.streams[stream];
    if (!chain.ok) {
      for (const finding of chain.findings) {
        findings.push(chainFinding(name, finding));
      }
    }
    if (summary === undefined) continue;
    chains[stream] = { lines: summary.lines, head: summary.head.seq };
    const claimed = claimedHeads[stream];
    if (claimed === undefined) continue;
    if (claimed.seq !== summary.head.seq || claimed.hash !== summary.head.hash) {
      findings.push({
        code: "BUNDLE_CHAIN_HEAD_MISMATCH",
        subject: stream,
        expected: `${claimed.seq}:${claimed.hash}`,
        found: `${summary.head.seq}:${summary.head.hash}`,
      });
    }
  }
  const signature = source.read("manifest.jws");
  let establishes: BundleVerification["establishes"] = "INTERNAL_CONSISTENCY";
  if (signature !== null && source.verifySignature !== undefined) {
    const valid = await source.verifySignature(signature.trim(), raw);
    if (valid) establishes = "ORIGIN_AND_CONSISTENCY";
    else findings.push({ code: "BUNDLE_SIGNATURE_INVALID", subject: "manifest.jws" });
  }
  return {
    ok: findings.length === 0,
    establishes,
    exportedAt: typeof manifest.exported_at === "string" ? manifest.exported_at : null,
    exportedBy: typeof manifest.exported_by === "string" ? manifest.exported_by : null,
    files: files.length,
    dropped,
    chains,
    findings,
  };
}

function chainFinding(file: string, finding: ChainFinding): BundleFinding {
  return {
    code: "BUNDLE_CHAIN_BROKEN",
    subject: `${file}:${finding.line}`,
    expected: finding.code,
    found: finding.seq ?? 0,
  };
}

function asHeads(
  value: unknown,
): Readonly<Record<string, { readonly seq: number; readonly hash: string }>> {
  if (typeof value !== "object" || value === null) return {};
  const heads: Record<string, { readonly seq: number; readonly hash: string }> = {};
  for (const [stream, head] of Object.entries(value as Record<string, unknown>)) {
    if (typeof head !== "object" || head === null) continue;
    const { seq, hash } = head as { seq?: unknown; hash?: unknown };
    if (typeof seq === "number" && typeof hash === "string") heads[stream] = { seq, hash };
  }
  return heads;
}

function refusal(findings: readonly BundleFinding[]): BundleVerification {
  return {
    ok: false,
    establishes: "INTERNAL_CONSISTENCY",
    exportedAt: null,
    exportedBy: null,
    files: 0,
    dropped: 0,
    chains: {},
    findings: [...findings],
  };
}
