import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { FileHoldStore, HoldStoreError } from "./HoldStore.js";

/**
 * One governed attempt whose outcome nobody knows: the upstream answered 5xx
 * or nothing after the request was sent. Kept by the client's
 * `Idempotency-Key`, so a retry with that key can be linked to it, and a
 * different request under that key refused.
 */
export interface IndeterminateAttempt {
  /** `retryDigest` of the request: what the key promised. */
  readonly requestDigest: string;
  readonly intentId: string;
  readonly decisionId: string | null;
  readonly dossierId: string | null;
  readonly recordedAt: string;
  readonly expiresAt: number;
}

/**
 * Where a gateway remembers its INDETERMINATE attempts, by the client's
 * idempotency key, within one tenant. Nothing else is kept: no body, no
 * header, and the key itself only as the name it is found by.
 */
export interface AttemptStore {
  /** False when the store is full or cannot write: the attempt is not remembered. */
  record(idempotencyKey: string, attempt: IndeterminateAttempt): boolean;
  /** The live record under a key; an expired or unreadable one is removed and is absent. */
  find(idempotencyKey: string): IndeterminateAttempt | undefined;
  /** Forgets the record under a key, only if it is for this request. */
  forget(idempotencyKey: string, requestDigest: string): void;
  close(): void;
}

/** How long an INDETERMINATE attempt is remembered: a day, well inside the hold store's seven-day ceiling. */
export const ATTEMPT_TTL_MS = 24 * 60 * 60 * 1_000;
/** The most INDETERMINATE attempts one gateway remembers. */
export const MAX_ATTEMPTS = 1_000;

/** In this process's memory: lost on restart, and seen only by this replica. */
export class MemoryAttemptStore implements AttemptStore {
  private readonly attempts = new Map<string, IndeterminateAttempt>();

  public constructor(private readonly clock: () => number) {}

  public record(idempotencyKey: string, attempt: IndeterminateAttempt): boolean {
    this.sweep();
    if (!this.attempts.has(idempotencyKey) && this.attempts.size >= MAX_ATTEMPTS) return false;
    this.attempts.set(idempotencyKey, attempt);
    return true;
  }

  public find(idempotencyKey: string): IndeterminateAttempt | undefined {
    const attempt = this.attempts.get(idempotencyKey);
    if (attempt === undefined) return undefined;
    if (attempt.expiresAt > this.clock()) return attempt;
    this.attempts.delete(idempotencyKey);
    return undefined;
  }

  public forget(idempotencyKey: string, requestDigest: string): void {
    if (this.attempts.get(idempotencyKey)?.requestDigest === requestDigest) {
      this.attempts.delete(idempotencyKey);
    }
  }

  public close(): void {
    this.attempts.clear();
  }

  private sweep(): void {
    const now = this.clock();
    for (const [key, attempt] of this.attempts) {
      if (attempt.expiresAt <= now) this.attempts.delete(key);
    }
  }
}

const FORMAT = "agentsafe.attempt/1";
const SUFFIX = ".attempt";
const TEMPORARY = ".tmp";
/** A half-written file older than this is an orphan a sweep removes. */
const ORPHAN_MS = 10 * 60_000;
/** The subdirectory of the hold directory the records live in. */
export const ATTEMPT_DIRECTORY = "attempts";

interface Sealed {
  readonly format: typeof FORMAT;
  readonly expiresAt: number;
  readonly iv: string;
  readonly tag: string;
  readonly data: string;
}

/**
 * INDETERMINATE attempts as files beside the durable holds, in the same
 * custody: the directory every replica mounts and the hold key. Each file is
 * sealed with AES-256-GCM under the hold key, its associated data the tenant
 * and the idempotency key, so a file copied to another tenant, or renamed to
 * another key, does not open. A file is named by an HMAC of the tenant and
 * the key under a name key derived from the hold key, so the directory says
 * nothing about the keys clients sent. A record is replaced by a rename, so a
 * reader on any replica sees a whole record or none.
 */
export class FileAttemptStore implements AttemptStore {
  private readonly key: Buffer;
  private readonly nameKey: Buffer;
  private readonly dir: string;

  public constructor(
    holdDir: string,
    keyFile: string,
    private readonly scope: string,
    private readonly clock: () => number,
  ) {
    this.key = FileHoldStore.readKey(keyFile);
    this.nameKey = Buffer.from(hkdfSync("sha256", this.key, Buffer.alloc(0), FORMAT, 32));
    this.dir = join(holdDir, ATTEMPT_DIRECTORY);
    try {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      statSync(this.dir);
    } catch {
      throw new HoldStoreError("HOLD_DIR_UNUSABLE");
    }
  }

  public record(idempotencyKey: string, attempt: IndeterminateAttempt): boolean {
    const path = this.path(idempotencyKey);
    if (this.sweep() >= MAX_ATTEMPTS && !FileAttemptStore.exists(path)) return false;
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(this.aad(idempotencyKey, attempt.expiresAt));
    const data = Buffer.concat([cipher.update(JSON.stringify(attempt), "utf8"), cipher.final()]);
    const sealed: Sealed = {
      format: FORMAT,
      expiresAt: attempt.expiresAt,
      iv: iv.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
      data: data.toString("base64url"),
    };
    const temporary = `${path}.${randomBytes(6).toString("hex")}${TEMPORARY}`;
    try {
      const fd = openSync(temporary, "wx", 0o600);
      try {
        writeSync(fd, JSON.stringify(sealed));
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(temporary, path);
      return true;
    } catch {
      rmSync(temporary, { force: true });
      return false;
    }
  }

  public find(idempotencyKey: string): IndeterminateAttempt | undefined {
    const path = this.path(idempotencyKey);
    let sealed: Sealed;
    try {
      sealed = JSON.parse(readFileSync(path, "utf8")) as Sealed;
    } catch {
      return undefined;
    }
    const attempt = this.unseal(idempotencyKey, sealed);
    if (attempt === null || attempt.expiresAt <= this.clock()) {
      rmSync(path, { force: true });
      return undefined;
    }
    return attempt;
  }

  public forget(idempotencyKey: string, requestDigest: string): void {
    if (this.find(idempotencyKey)?.requestDigest === requestDigest) {
      rmSync(this.path(idempotencyKey), { force: true });
    }
  }

  public close(): void {
    // The records are the next process's to read.
  }

  /** Removes expired records and orphaned temporary files; returns how many are live. */
  public sweep(): number {
    const now = this.clock();
    let live = 0;
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return 0;
    }
    for (const name of names) {
      const path = join(this.dir, name);
      if (name.endsWith(TEMPORARY)) {
        if (FileAttemptStore.olderThan(path, now - ORPHAN_MS)) rmSync(path, { force: true });
        continue;
      }
      if (!name.endsWith(SUFFIX)) continue;
      const expiresAt = FileAttemptStore.expiresAt(path);
      if (expiresAt === null || expiresAt <= now) {
        rmSync(path, { force: true });
        continue;
      }
      live += 1;
    }
    return live;
  }

  private unseal(idempotencyKey: string, sealed: Sealed): IndeterminateAttempt | null {
    if (sealed?.format !== FORMAT || typeof sealed.expiresAt !== "number") return null;
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.key,
        Buffer.from(sealed.iv, "base64url"),
      );
      decipher.setAAD(this.aad(idempotencyKey, sealed.expiresAt));
      decipher.setAuthTag(Buffer.from(sealed.tag, "base64url"));
      const plain = Buffer.concat([
        decipher.update(Buffer.from(sealed.data, "base64url")),
        decipher.final(),
      ]).toString("utf8");
      const attempt = JSON.parse(plain) as IndeterminateAttempt;
      return attempt.expiresAt === sealed.expiresAt && typeof attempt.requestDigest === "string"
        ? attempt
        : null;
    } catch {
      return null;
    }
  }

  private aad(idempotencyKey: string, expiresAt: number): Buffer {
    return Buffer.from(
      `${FORMAT}\u0000${this.scope}\u0000${idempotencyKey}\u0000${expiresAt}`,
      "utf8",
    );
  }

  private path(idempotencyKey: string): string {
    const name = createHmac("sha256", this.nameKey)
      .update(`${this.scope}\u0000${idempotencyKey}`, "utf8")
      .digest("hex");
    return join(this.dir, `${name}${SUFFIX}`);
  }

  private static exists(path: string): boolean {
    try {
      statSync(path);
      return true;
    } catch {
      return false;
    }
  }

  private static expiresAt(path: string): number | null {
    try {
      const sealed = JSON.parse(readFileSync(path, "utf8")) as Partial<Sealed>;
      return sealed.format === FORMAT && typeof sealed.expiresAt === "number"
        ? sealed.expiresAt
        : null;
    } catch {
      return null;
    }
  }

  private static olderThan(path: string, cutoff: number): boolean {
    try {
      return statSync(path).mtimeMs < cutoff;
    } catch {
      return false;
    }
  }
}
