import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
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
import type { CapturedIntent, DecisionGate } from "@decionis/agent-safe-pipeline";
import type { EscalationHandoff } from "../service/EscalationResolver.js";
import type { InterceptedRequest } from "./InterceptedRequest.js";

/** One held request: everything a resume needs to ask the authority again and forward it once. */
export interface HeldEscalation {
  readonly captured: CapturedIntent;
  readonly request: InterceptedRequest;
  readonly decision: DecisionGate;
  readonly handoff: EscalationHandoff | null;
  readonly heldAt: string;
  readonly expiresAt: number;
  /** SHA-256 of the resume token handed to the caller whose request was held; the token itself is not kept. */
  readonly resumeDigest: Buffer;
}

/**
 * Where a gateway keeps the requests it holds. A hold is put once, read by
 * the caller holding its resume token, and taken once: `claim` removes it
 * and returns it to exactly one caller, so a request is forwarded at most
 * once by this store; the authority's single-use grant is the backstop.
 */
export interface HoldStore {
  /** False when the store is full: the request is held in name only and cannot be resumed. */
  put(intentId: string, entry: HeldEscalation): boolean;
  /** The live hold under an id; an expired one is removed and is absent. */
  get(intentId: string): HeldEscalation | undefined;
  /** Removes the hold and returns it, to one caller only. */
  claim(intentId: string): HeldEscalation | undefined;
  delete(intentId: string): void;
  /** Removes expired holds; returns how many are live. */
  sweep(): number;
  /** Forgets what this process holds in memory; a durable store keeps its holds for the next process. */
  close(): void;
}

/** The most holds one gateway keeps. */
export const MAX_HELD = 1_000;

/** Holds in this process's memory: lost on restart, and seen only by this replica. */
export class MemoryHoldStore implements HoldStore {
  private readonly held = new Map<string, HeldEscalation>();

  public constructor(private readonly clock: () => number) {}

  public put(intentId: string, entry: HeldEscalation): boolean {
    this.sweep();
    if (this.held.size >= MAX_HELD) return false;
    this.held.set(intentId, entry);
    return true;
  }

  public get(intentId: string): HeldEscalation | undefined {
    this.sweep();
    return this.held.get(intentId);
  }

  public claim(intentId: string): HeldEscalation | undefined {
    const entry = this.get(intentId);
    if (entry !== undefined) this.held.delete(intentId);
    return entry;
  }

  public delete(intentId: string): void {
    this.held.delete(intentId);
  }

  public sweep(): number {
    const now = this.clock();
    for (const [id, entry] of this.held) {
      if (entry.expiresAt <= now) this.held.delete(id);
    }
    return this.held.size;
  }

  public close(): void {
    this.held.clear();
  }
}

/** Why a durable hold store cannot be used: the code, never the key or a path's contents. */
export class HoldStoreError extends Error {
  public constructor(
    public readonly code: "HOLD_KEY_UNREADABLE" | "HOLD_KEY_INVALID" | "HOLD_DIR_UNUSABLE",
  ) {
    super(code);
    this.name = "HoldStoreError";
  }
}

const FORMAT = "agentsafe.hold/1";
const SUFFIX = ".hold";
/** A claimed hold's file, left only if the claiming process died before removing it. */
const CLAIMED = ".claimed";
const TEMPORARY = ".tmp";
/** How long a claimed or half-written file may stay before a sweep removes it. */
const ORPHAN_MS = 10 * 60_000;

interface Sealed {
  readonly format: typeof FORMAT;
  readonly expiresAt: number;
  readonly iv: string;
  readonly tag: string;
  readonly data: string;
}

/**
 * Holds as files in a directory every replica of a gateway mounts: any
 * replica can resume a hold, and a restart or a reload loses none. Each file
 * is sealed with AES-256-GCM under a key read from a mounted file; the
 * associated data binds it to its scope (the tenant) and its intent id, so a
 * file copied to another tenant's directory or renamed to another intent does
 * not open. File names are digests of the intent id, never the id itself.
 *
 * A claim renames the file to a name only the claimant knows; the rename
 * succeeds for one caller and fails for every other, on one host or across
 * hosts sharing the directory.
 */
export class FileHoldStore implements HoldStore {
  private readonly key: Buffer;

  public constructor(
    private readonly dir: string,
    keyFile: string,
    private readonly scope: string,
    private readonly clock: () => number,
  ) {
    this.key = FileHoldStore.readKey(keyFile);
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      statSync(dir);
    } catch {
      throw new HoldStoreError("HOLD_DIR_UNUSABLE");
    }
  }

  /** The key: 32 bytes, written base64 or base64url (whitespace ignored), or hex. */
  public static readKey(keyFile: string): Buffer {
    let text: string;
    try {
      text = readFileSync(keyFile, "utf8").trim();
    } catch {
      throw new HoldStoreError("HOLD_KEY_UNREADABLE");
    }
    const key = /^[0-9a-f]{64}$/i.test(text)
      ? Buffer.from(text, "hex")
      : Buffer.from(text.replace(/\s+/g, ""), "base64url");
    if (key.length !== 32) throw new HoldStoreError("HOLD_KEY_INVALID");
    return key;
  }

  public put(intentId: string, entry: HeldEscalation): boolean {
    if (this.sweep() >= MAX_HELD) return false;
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(this.aad(intentId, entry.expiresAt));
    const data = Buffer.concat([
      cipher.update(JSON.stringify(FileHoldStore.encode(entry)), "utf8"),
      cipher.final(),
    ]);
    const sealed: Sealed = {
      format: FORMAT,
      expiresAt: entry.expiresAt,
      iv: iv.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
      data: data.toString("base64url"),
    };
    const path = this.path(intentId);
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

  public get(intentId: string): HeldEscalation | undefined {
    return this.open(intentId, this.path(intentId), true);
  }

  public claim(intentId: string): HeldEscalation | undefined {
    const path = this.path(intentId);
    const claimed = `${path}.${randomBytes(6).toString("hex")}${CLAIMED}`;
    try {
      renameSync(path, claimed);
    } catch {
      return undefined;
    }
    try {
      return this.open(intentId, claimed, false);
    } finally {
      rmSync(claimed, { force: true });
    }
  }

  public delete(intentId: string): void {
    rmSync(this.path(intentId), { force: true });
  }

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
      if (name.endsWith(CLAIMED) || name.endsWith(TEMPORARY)) {
        if (FileHoldStore.olderThan(path, now - ORPHAN_MS)) rmSync(path, { force: true });
        continue;
      }
      if (!name.endsWith(SUFFIX)) continue;
      const expiresAt = FileHoldStore.expiresAt(path);
      if (expiresAt === null || expiresAt <= now) {
        rmSync(path, { force: true });
        continue;
      }
      live += 1;
    }
    return live;
  }

  public close(): void {
    // The holds are the next process's to resume.
  }

  /** A hold's file, opened and checked; expired, unreadable or forged files are removed. */
  private open(intentId: string, path: string, removeBad: boolean): HeldEscalation | undefined {
    let sealed: Sealed;
    try {
      sealed = JSON.parse(readFileSync(path, "utf8")) as Sealed;
    } catch {
      return undefined;
    }
    const entry = this.unseal(intentId, sealed);
    if (entry === null || entry.expiresAt <= this.clock()) {
      if (removeBad) rmSync(path, { force: true });
      return undefined;
    }
    return entry;
  }

  private unseal(intentId: string, sealed: Sealed): HeldEscalation | null {
    if (sealed?.format !== FORMAT || typeof sealed.expiresAt !== "number") return null;
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.key,
        Buffer.from(sealed.iv, "base64url"),
      );
      decipher.setAAD(this.aad(intentId, sealed.expiresAt));
      decipher.setAuthTag(Buffer.from(sealed.tag, "base64url"));
      const plain = Buffer.concat([
        decipher.update(Buffer.from(sealed.data, "base64url")),
        decipher.final(),
      ]).toString("utf8");
      const entry = FileHoldStore.decode(JSON.parse(plain) as EncodedHold);
      return entry.expiresAt === sealed.expiresAt && entry.captured.intent.intentId === intentId
        ? entry
        : null;
    } catch {
      return null;
    }
  }

  private aad(intentId: string, expiresAt: number): Buffer {
    return Buffer.from(`${FORMAT}\u0000${this.scope}\u0000${intentId}\u0000${expiresAt}`, "utf8");
  }

  private path(intentId: string): string {
    const name = createHash("sha256")
      .update(`${this.scope}\u0000${intentId}`, "utf8")
      .digest("hex");
    return join(this.dir, `${name}${SUFFIX}`);
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

  private static encode(entry: HeldEscalation): EncodedHold {
    return {
      captured: entry.captured,
      request: { ...entry.request, body: entry.request.body.toString("base64") },
      decision: entry.decision,
      handoff: entry.handoff,
      heldAt: entry.heldAt,
      expiresAt: entry.expiresAt,
      resumeDigest: entry.resumeDigest.toString("base64"),
    };
  }

  private static decode(encoded: EncodedHold): HeldEscalation {
    return {
      ...encoded,
      request: { ...encoded.request, body: Buffer.from(encoded.request.body, "base64") },
      resumeDigest: Buffer.from(encoded.resumeDigest, "base64"),
    };
  }
}

type EncodedHold = Omit<HeldEscalation, "request" | "resumeDigest"> & {
  readonly request: Omit<InterceptedRequest, "body"> & { readonly body: string };
  readonly resumeDigest: string;
};
