import { createHash, timingSafeEqual } from "node:crypto";
import { inspect } from "node:util";

/**
 * A secret the executor holds, by name. The value lives in a `Buffer` that is
 * handed out only for the duration of `use`, zeroed on `dispose`, and never
 * produced by `toString`, `toJSON`, or `util.inspect`: an accidental
 * stringification yields the name, never the value. The digest is what
 * comparisons and rotation use, so the value itself is read as rarely as
 * possible. The copy a header or a client makes at the boundary is
 * unavoidable and is the reason the redactor exists.
 */
export class SecretHandle {
  private value: Buffer | null;
  private cachedDigest: Buffer | null = null;

  private constructor(
    public readonly name: string,
    value: Buffer,
  ) {
    this.value = value;
  }

  /** Takes ownership of `value`; the caller must not keep a reference. */
  public static fromBuffer(name: string, value: Buffer): SecretHandle {
    return new SecretHandle(name, value);
  }

  public static fromString(name: string, value: string): SecretHandle {
    return new SecretHandle(name, Buffer.from(value, "utf8"));
  }

  public get disposed(): boolean {
    return this.value === null;
  }

  public get byteLength(): number {
    return this.value?.length ?? 0;
  }

  /** The value, for the duration of the call only. */
  public use<T>(fn: (value: Buffer) => T): T {
    if (this.value === null) throw new Error(`SECRET_DISPOSED: ${this.name}`);
    return fn(this.value);
  }

  /** SHA-256 of the value, for comparison and rotation detection. */
  public digestBytes(): Buffer {
    if (this.cachedDigest === null) {
      this.cachedDigest = this.use((value) => createHash("sha256").update(value).digest());
    }
    return this.cachedDigest;
  }

  public digest(): `sha256:${string}` {
    return `sha256:${this.digestBytes().toString("hex")}`;
  }

  /** Constant-time equality on the digests. */
  public equals(other: SecretHandle): boolean {
    return timingSafeEqual(this.digestBytes(), other.digestBytes());
  }

  /** Zeroes the value; every later `use` is refused. The digest stays available. */
  public dispose(): void {
    if (this.value === null) return;
    this.digestBytes();
    this.value.fill(0);
    this.value = null;
  }

  public toString(): string {
    return `[SecretHandle ${this.name}]`;
  }

  public toJSON(): string {
    return this.toString();
  }

  public [inspect.custom](): string {
    return this.toString();
  }
}
