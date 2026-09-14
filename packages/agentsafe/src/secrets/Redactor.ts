import { createHash } from "node:crypto";

/** The longest line the emitter writes; the rest is cut and marked. */
export const MAX_LINE_BYTES = 16 * 1024;

export type RedactionPattern = "bearer" | "pem" | "jws" | "header" | "assertion" | "secret";

export interface Redaction {
  readonly line: string;
  readonly patterns: readonly RedactionPattern[];
}

/**
 * The last line of defence before a line leaves the process. It holds no
 * secret value: only the SHA-256 digests of the current secrets, so a whole
 * value that leaks is recognised by hashing the line's tokens, never by
 * searching for the value itself. Shape patterns catch what a digest cannot:
 * a bearer credential, a PEM block, a compact JWS, the configured downstream
 * header, an OAuth client assertion. Every pattern is a single linear scan.
 */
export class Redactor {
  public constructor(
    /** The digests of every current secret, `sha256:<hex>`, read at each call so rotation is followed. */
    private readonly digests: () => Iterable<string>,
    /** Header names whose values are credentials, lower case. */
    private readonly credentialHeaders: () => Iterable<string> = () => [],
  ) {}

  public redact(input: string): Redaction {
    const patterns = new Set<RedactionPattern>();
    let line = Redactor.bound(input);
    const pem = line.indexOf("-----BEGIN");
    if (pem !== -1) {
      line = `${line.slice(0, pem)}[REDACTED:pem]`;
      patterns.add("pem");
    }
    line = line.replace(/Bearer [\w.~+/=-]{16,}/g, () => {
      patterns.add("bearer");
      return "Bearer [REDACTED:bearer]";
    });
    line = line.replace(/\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]+/g, () => {
      patterns.add("jws");
      return "[REDACTED:jws]";
    });
    line = line.replace(/client_assertion=[\w.~+/=-]+/g, () => {
      patterns.add("assertion");
      return "client_assertion=[REDACTED:assertion]";
    });
    for (const header of this.credentialHeaders()) {
      line = Redactor.redactHeader(line, header, () => patterns.add("header"));
    }
    const digests = new Set(this.digests());
    if (digests.size > 0) {
      line = line.replace(/[\w.~+/=-]{16,}/g, (token) => {
        const digest = `sha256:${createHash("sha256").update(token).digest("hex")}`;
        if (!digests.has(digest)) return token;
        patterns.add("secret");
        return "[REDACTED:secret]";
      });
    }
    return { line, patterns: [...patterns] };
  }

  /** `<header>: <value>` or `"<header>":"<value>"`, case-insensitively, value redacted. */
  private static redactHeader(line: string, header: string, hit: () => void): string {
    const lower = line.toLowerCase();
    let from = 0;
    let out = "";
    let cursor = 0;
    for (;;) {
      const at = lower.indexOf(header, from);
      if (at === -1) break;
      let index = at + header.length;
      while (index < line.length && (line[index] === '"' || line[index] === " ")) index += 1;
      if (line[index] !== ":" && line[index] !== "=") {
        from = at + 1;
        continue;
      }
      index += 1;
      while (index < line.length && (line[index] === '"' || line[index] === " ")) index += 1;
      const start = index;
      while (
        index < line.length &&
        line[index] !== '"' &&
        line[index] !== "," &&
        line[index] !== " "
      ) {
        index += 1;
      }
      if (index > start) {
        hit();
        out += `${line.slice(cursor, start)}[REDACTED:header]`;
        cursor = index;
      }
      from = index;
    }
    return out + line.slice(cursor);
  }

  /** Control characters out, length bounded, so a line is one line. */
  private static bound(input: string): string {
    let text = "";
    for (const character of input) {
      const code = character.charCodeAt(0);
      text += code < 0x20 || code === 0x7f ? " " : character;
    }
    if (Buffer.byteLength(text) <= MAX_LINE_BYTES) return text;
    return `${Buffer.from(text)
      .subarray(0, MAX_LINE_BYTES - 12)
      .toString("utf8")}[TRUNCATED]`;
  }
}
