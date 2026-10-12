import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const CIPHER = "aes-256-gcm";
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
/** How the nonce, the body and the tag are written into the sealed value. */
const WIRE_ENCODING = "base64url";
const TEXT_ENCODING = "utf8";
const KEY_INVALID = "CARD_HOLDS_KEY_INVALID";

/**
 * What a shared hold store keeps of a grant at rest, sealed: the captured
 * intent and the decision, which carries the authority's grant token, and
 * later the authorization a claim returned. The database then holds no
 * bearer credential in clear, and a row copied out of it opens nowhere but
 * in a process that holds the deployment's hold key.
 *
 * AES-256-GCM under a 256-bit key, a fresh 96-bit nonce per seal, and the
 * row's own identity as associated data, so a sealed value moved to another
 * row, or to another table or namespace, does not open. The key is read
 * from the secret store at the moment of use and never written anywhere.
 */
export class CardHoldSeal {
  public static readonly VERSION = "v1";

  private constructor(private readonly key: Buffer) {}

  /** A key of exactly 32 bytes; anything else is refused by name, never echoed. */
  public static fromKey(key: Buffer): CardHoldSeal {
    if (key.length !== KEY_BYTES) throw new Error(KEY_INVALID);
    return new CardHoldSeal(Buffer.from(key));
  }

  /**
   * The key as a secret file carries it: 32 bytes as base64 or as 64 hex
   * characters, surrounding whitespace ignored. Raw bytes are not accepted,
   * so a key file is always text an operator can inspect for shape.
   */
  public static fromText(text: string): CardHoldSeal {
    const trimmed = text.trim();
    if (/^[0-9a-f]{64}$/i.test(trimmed)) return CardHoldSeal.fromKey(Buffer.from(trimmed, "hex"));
    if (/^[a-z0-9+/]{43}=?$/i.test(trimmed)) {
      return CardHoldSeal.fromKey(Buffer.from(trimmed, "base64"));
    }
    if (/^[\w-]{43}$/.test(trimmed))
      return CardHoldSeal.fromKey(Buffer.from(trimmed, WIRE_ENCODING));
    throw new Error(KEY_INVALID);
  }

  public seal(plaintext: string, associated: string): string {
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv(CIPHER, this.key, nonce);
    cipher.setAAD(Buffer.from(associated, TEXT_ENCODING));
    const body = Buffer.concat([cipher.update(plaintext, TEXT_ENCODING), cipher.final()]);
    const tag = cipher.getAuthTag();
    return [
      CardHoldSeal.VERSION,
      nonce.toString(WIRE_ENCODING),
      body.toString(WIRE_ENCODING),
      tag.toString(WIRE_ENCODING),
    ].join(".");
  }

  /** The plaintext, or null for anything that does not open under this key and this identity. */
  public open(sealed: string, associated: string): string | null {
    const parts = sealed.split(".");
    if (parts.length !== 4 || parts[0] !== CardHoldSeal.VERSION) return null;
    const [, nonceText, bodyText, tagText] = parts as [string, string, string, string];
    const nonce = Buffer.from(nonceText, WIRE_ENCODING);
    const tag = Buffer.from(tagText, WIRE_ENCODING);
    if (nonce.length !== NONCE_BYTES || tag.length !== TAG_BYTES) return null;
    try {
      const decipher = createDecipheriv(CIPHER, this.key, nonce);
      decipher.setAAD(Buffer.from(associated, TEXT_ENCODING));
      decipher.setAuthTag(tag);
      return Buffer.concat([
        decipher.update(Buffer.from(bodyText, WIRE_ENCODING)),
        decipher.final(),
      ]).toString(TEXT_ENCODING);
    } catch {
      return null;
    }
  }
}
