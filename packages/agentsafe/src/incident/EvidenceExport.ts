import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { JsonObject } from "@decionis/agent-safe-pipeline";
import type { ChainHead } from "../audit/HashChain.js";
import type { LineWriter } from "../audit/LineAuditSink.js";
import type { PostureReport } from "../posture/HostPosture.js";

export const EVIDENCE_BUNDLE_VERSION = "agent-safe.evidence-bundle/1";

const MAX_WINDOW_LINES = 200_000;

export class EvidenceError extends Error {
  public constructor(
    public readonly code:
      "EVIDENCE_DIR_NOT_CONFIGURED" | "EVIDENCE_WRITE_FAILED" | "EVIDENCE_SIGNING_FAILED",
  ) {
    super(code);
    this.name = "EvidenceError";
  }
}

/**
 * The last N lines of one stream, and how many fell off the end.
 *
 * The durable store for evidence is the log pipeline the lines are written
 * to; this window exists so an operator can take a bundle out of a running
 * process during an incident without first arranging log export. Saying how
 * many lines were dropped is the point: a bundle that silently held a partial
 * range would look like a complete one, and the chain's own sequence numbers
 * are what let a reader see the gap.
 */
export class LineWindow {
  private readonly buffer: string[] = [];
  private droppedCount = 0;

  public constructor(public readonly capacity: number) {
    if (!Number.isInteger(capacity) || capacity < 1 || capacity > MAX_WINDOW_LINES) {
      throw new RangeError("EVIDENCE_WINDOW_INVALID");
    }
  }

  public push(line: string): void {
    this.buffer.push(line);
    while (this.buffer.length > this.capacity) {
      this.buffer.shift();
      this.droppedCount += 1;
    }
  }

  /** Wraps a writer so every line it takes is also remembered here. */
  public tee(write: LineWriter): LineWriter {
    return (line) => {
      this.push(line);
      write(line);
    };
  }

  public get lines(): readonly string[] {
    return this.buffer;
  }

  public get dropped(): number {
    return this.droppedCount;
  }

  public clear(): void {
    this.buffer.length = 0;
    this.droppedCount = 0;
  }
}

/** One file in a bundle: what it is, how long, and what it hashes to. */
export interface BundleFile {
  readonly name: string;
  readonly bytes: number;
  readonly sha256: string;
  /** Lines this process no longer held when the bundle was made. */
  readonly dropped?: number;
}

/** The bundle's own record of itself, and the only file a signature covers. */
export interface EvidenceBundleManifest {
  readonly version: typeof EVIDENCE_BUNDLE_VERSION;
  readonly exported_at: string;
  readonly exported_by: string;
  readonly reason: string;
  readonly package_version: string;
  readonly image: { readonly digest: string | null; readonly self_verified: false };
  readonly configuration_digest: string;
  readonly secrets: readonly {
    readonly name: string;
    readonly present: boolean;
    readonly rotations: number;
  }[];
  readonly chains: Readonly<Record<string, { readonly seq: number; readonly hash: string }>>;
  readonly files: readonly BundleFile[];
}

export interface EvidenceExportInput {
  /** The operator who asked, and the reason they gave. */
  readonly principal: string;
  readonly reason: string;
}

export interface EvidenceExportOptions {
  readonly dir: string | null;
  readonly audit: LineWindow;
  readonly security: LineWindow;
  readonly packageVersion: string;
  /** As the platform reported it; a process cannot read its own image's digest. */
  readonly imageDigest: string | null;
  readonly posture: () => PostureReport;
  readonly openAttempts: () => JsonObject;
  readonly heads: () => Readonly<Record<string, ChainHead>>;
  /** The non-secret configuration, for a digest over what this process was told. */
  readonly configuration: () => JsonObject;
  /**
   * Secret names with presence and a rotation counter, and nothing else: not
   * a value, and not a digest of one either, because a low-entropy
   * credential's digest is a guessable oracle.
   */
  readonly secrets: () => readonly {
    readonly name: string;
    readonly present: boolean;
    readonly rotations: number;
  }[];
  readonly clock?: () => Date;
  /** Signs the manifest as a detached JWS; absent when no key is configured. */
  readonly sign?: (payload: Uint8Array) => Promise<string>;
  readonly writeFile?: (path: string, body: string) => void;
  readonly makeDir?: (path: string) => void;
}

export interface EvidenceBundle {
  readonly directory: string;
  readonly manifest: EvidenceBundleManifest;
  /** Present when a signing key was configured: a detached JWS over the manifest. */
  readonly signature: string | null;
}

const sha256 = (body: string): string =>
  `sha256:${createHash("sha256").update(body, "utf8").digest("hex")}`;

/**
 * An evidence bundle: what this process can say about an incident, written
 * where an operator can pick it up, with a manifest that digests every file
 * so a later reader can tell the bundle they hold is the bundle that was
 * made.
 *
 * What is deliberately not in it: any secret, any digest of a secret (a
 * low-entropy credential's digest is a guessable oracle), any request
 * parameter, and any provider body. The attempt journal holds parameters, so
 * it is named by identifier and state and never copied. What is in it is
 * identifiers, digests, statuses, counts and the two chained streams.
 *
 * Without a signing key the bundle proves its own internal consistency and
 * nothing about who produced it. With one it carries a detached JWS over the
 * manifest, and `verify-bundle` says which of the two a reader is holding
 * rather than letting the distinction pass unnoticed.
 */
export class EvidenceExport {
  private readonly clock: () => Date;
  private readonly write: (path: string, body: string) => void;
  private readonly makeDir: (path: string) => void;

  public constructor(private readonly options: EvidenceExportOptions) {
    this.clock = options.clock ?? ((): Date => new Date());
    this.write =
      options.writeFile ??
      ((path, body): void => {
        writeFileSync(path, body, { mode: 0o600 });
      });
    this.makeDir =
      options.makeDir ??
      ((path): void => {
        mkdirSync(path, { recursive: true, mode: 0o700 });
      });
  }

  public get configured(): boolean {
    return this.options.dir !== null;
  }

  public async export(input: EvidenceExportInput): Promise<EvidenceBundle> {
    const root = this.options.dir;
    if (root === null) throw new EvidenceError("EVIDENCE_DIR_NOT_CONFIGURED");
    const at = this.clock();
    // One directory per export, named by the instant, so two exports during
    // one incident do not overwrite each other.
    const directory = join(root, at.toISOString().replace(/[:.]/g, "-"));
    const posture = this.options.posture();
    const contents: readonly {
      readonly name: string;
      readonly body: string;
      readonly dropped?: number;
    }[] = [
      {
        name: "audit.jsonl",
        body: `${this.options.audit.lines.join("\n")}\n`,
        dropped: this.options.audit.dropped,
      },
      {
        name: "security-events.jsonl",
        body: `${this.options.security.lines.join("\n")}\n`,
        dropped: this.options.security.dropped,
      },
      {
        name: "open-attempts.json",
        body: `${JSON.stringify(this.options.openAttempts(), null, 2)}\n`,
      },
      {
        name: "posture.json",
        body: `${JSON.stringify(
          {
            mode: posture.mode,
            // Checks by name and outcome; a finding's own detail can name a
            // path, so only the check identifier travels.
            failed: posture.failed.map((finding) => finding.id),
            waived: posture.waived.map((finding) => finding.id),
            checks: posture.findings.length,
          },
          null,
          2,
        )}\n`,
      },
    ];
    try {
      this.makeDir(directory);
      for (const file of contents) this.write(join(directory, file.name), file.body);
    } catch {
      throw new EvidenceError("EVIDENCE_WRITE_FAILED");
    }
    const manifest: EvidenceBundleManifest = {
      version: EVIDENCE_BUNDLE_VERSION,
      exported_at: at.toISOString(),
      exported_by: input.principal,
      reason: input.reason.slice(0, 200),
      package_version: this.options.packageVersion,
      // Reported by the platform, not read from the running image: a process
      // cannot verify what it was built from, and saying otherwise would be
      // the most misleading line in the bundle.
      image: { digest: this.options.imageDigest, self_verified: false },
      configuration_digest: sha256(JSON.stringify(this.options.configuration())),
      secrets: this.options.secrets().map((secret) => ({ ...secret })),
      chains: Object.fromEntries(
        Object.entries(this.options.heads()).map(([stream, head]) => [
          stream,
          { seq: head.seq, hash: head.hash },
        ]),
      ),
      files: contents.map((file) => ({
        name: file.name,
        bytes: Buffer.byteLength(file.body, "utf8"),
        sha256: sha256(file.body),
        ...(file.dropped === undefined ? {} : { dropped: file.dropped }),
      })),
    };
    const body = `${JSON.stringify(manifest, null, 2)}\n`;
    let signature: string | null = null;
    if (this.options.sign !== undefined) {
      try {
        signature = await this.options.sign(Buffer.from(body, "utf8"));
      } catch {
        throw new EvidenceError("EVIDENCE_SIGNING_FAILED");
      }
    }
    try {
      this.write(join(directory, "manifest.json"), body);
      if (signature !== null) this.write(join(directory, "manifest.jws"), `${signature}\n`);
    } catch {
      throw new EvidenceError("EVIDENCE_WRITE_FAILED");
    }
    return { directory, manifest, signature };
  }
}
