/**
 * The TLS ClientHello, read for one thing: the name the client is connecting
 * to, which the server_name extension carries in the clear. A transparent
 * interceptor has no other way to learn where a redirected TLS connection was
 * going, so this parser decides where bytes are sent; it is therefore small,
 * linear, and bounded, and it refuses anything it cannot place rather than
 * guess. It never reads past the handshake, never keeps a byte, and reports
 * the negotiated protocols (ALPN) beside the name because a later phase
 * decides from them what it can terminate.
 *
 * RFC 8446 section 4.1.2 (ClientHello), RFC 6066 section 3 (server_name),
 * RFC 7301 (ALPN).
 */

/** The reading of a client's first bytes as TLS. */
export type ClientHelloReading =
  /** The bytes are a TLS handshake but the ClientHello is not complete yet. */
  | { readonly kind: "NEED_MORE" }
  /** The bytes are not a TLS handshake record at all. */
  | { readonly kind: "NOT_TLS" }
  /** A ClientHello whose fields could not be read as the RFC lays them out. */
  | { readonly kind: "MALFORMED" }
  | {
      readonly kind: "CLIENT_HELLO";
      /** The server_name host, lowercase; null when the client sent none. */
      readonly serverName: string | null;
      readonly alpn: readonly string[];
    };

const RECORD_HANDSHAKE = 0x16;
const HANDSHAKE_CLIENT_HELLO = 0x01;
const RECORD_HEADER_LENGTH = 5;
const HANDSHAKE_HEADER_LENGTH = 4;
const EXTENSION_SERVER_NAME = 0x0000;
const EXTENSION_ALPN = 0x0010;
const SERVER_NAME_HOST_NAME = 0x00;
/** The largest record body TLS allows, plus the header. */
const MAX_RECORD_LENGTH = 16_384 + 256;
/** The most handshake bytes read before a hello is called malformed; well beyond any real one. */
export const MAX_CLIENT_HELLO_BYTES = 65_536;
/** RFC 1123 host name: labels of letters, digits and hyphens, at most 253 characters. */
const HOST_NAME =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

class Cursor {
  public offset = 0;

  public constructor(private readonly bytes: Uint8Array) {}

  public get remaining(): number {
    return this.bytes.length - this.offset;
  }

  public u8(): number {
    if (this.remaining < 1) throw new RangeError("short");
    const value = this.bytes[this.offset] ?? 0;
    this.offset += 1;
    return value;
  }

  public u16(): number {
    return (this.u8() << 8) | this.u8();
  }

  public u24(): number {
    return (this.u8() << 16) | (this.u8() << 8) | this.u8();
  }

  public skip(length: number): void {
    if (this.remaining < length) throw new RangeError("short");
    this.offset += length;
  }

  public take(length: number): Uint8Array {
    if (this.remaining < length) throw new RangeError("short");
    const slice = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }
}

/**
 * Collects the handshake bytes from consecutive handshake records: a
 * ClientHello may be fragmented across records, and a client may send the
 * first record of the next flight after it. Returns the handshake bytes read
 * so far and whether the records seen are handshake records.
 */
function handshakeBytes(
  bytes: Uint8Array,
):
  | { readonly kind: "NOT_TLS" }
  | { readonly kind: "NEED_MORE" }
  | { readonly kind: "MALFORMED" }
  | { readonly data: Uint8Array } {
  const fragments: Uint8Array[] = [];
  let total = 0;
  let offset = 0;
  // The hello's whole length, once its four-byte header has been read.
  let needed = 0;
  while (needed === 0 || total < needed) {
    if (bytes.length - offset < RECORD_HEADER_LENGTH) return { kind: "NEED_MORE" };
    const type = bytes[offset] ?? 0;
    const major = bytes[offset + 1] ?? 0;
    const length = ((bytes[offset + 3] ?? 0) << 8) | (bytes[offset + 4] ?? 0);
    if (type !== RECORD_HANDSHAKE || major !== 0x03 || length === 0 || length > MAX_RECORD_LENGTH) {
      // Not a handshake record where one was due: not TLS at all before any
      // record, and a broken hello once one has begun.
      return fragments.length === 0 ? { kind: "NOT_TLS" } : { kind: "MALFORMED" };
    }
    const start = offset + RECORD_HEADER_LENGTH;
    const end = start + length;
    if (bytes.length < end) return { kind: "NEED_MORE" };
    fragments.push(bytes.subarray(start, end));
    total += length;
    offset = end;
    if (needed === 0 && total >= HANDSHAKE_HEADER_LENGTH) {
      const head = concat(fragments, HANDSHAKE_HEADER_LENGTH);
      needed =
        HANDSHAKE_HEADER_LENGTH + (((head[1] ?? 0) << 16) | ((head[2] ?? 0) << 8) | (head[3] ?? 0));
      // A hello that announces itself larger than any real one is refused now,
      // not read for as long as the client cares to send.
      if (needed > MAX_CLIENT_HELLO_BYTES) return { kind: "MALFORMED" };
    }
  }
  // Only the hello itself: a record may already carry the first bytes of the
  // client's next message, which are not this parser's to read.
  return { data: concat(fragments, needed) };
}

function concat(fragments: readonly Uint8Array[], length: number): Uint8Array {
  const out = new Uint8Array(length);
  let offset = 0;
  for (const fragment of fragments) {
    const slice = fragment.subarray(0, Math.max(0, Math.min(fragment.length, length - offset)));
    out.set(slice, offset);
    offset += slice.length;
    if (offset >= length) break;
  }
  return out;
}

/** Reads a client's first bytes as a TLS ClientHello, or says why they are not one. */
export function readClientHello(bytes: Uint8Array): ClientHelloReading {
  const records = handshakeBytes(bytes);
  if ("kind" in records) return records;
  const cursor = new Cursor(records.data);
  try {
    if (cursor.u8() !== HANDSHAKE_CLIENT_HELLO) return { kind: "MALFORMED" };
    const length = cursor.u24();
    if (length !== cursor.remaining) return { kind: "MALFORMED" };
    cursor.u16(); // legacy_version
    cursor.skip(32); // random
    cursor.skip(cursor.u8()); // legacy_session_id
    cursor.skip(cursor.u16()); // cipher_suites
    cursor.skip(cursor.u8()); // legacy_compression_methods
    if (cursor.remaining === 0) return { kind: "CLIENT_HELLO", serverName: null, alpn: [] };
    const extensionsLength = cursor.u16();
    if (extensionsLength !== cursor.remaining) return { kind: "MALFORMED" };
    let serverName: string | null = null;
    let alpn: string[] = [];
    let sawServerName = false;
    let sawAlpn = false;
    while (cursor.remaining > 0) {
      const type = cursor.u16();
      const body = new Cursor(cursor.take(cursor.u16()));
      if (type === EXTENSION_SERVER_NAME) {
        if (sawServerName) return { kind: "MALFORMED" };
        sawServerName = true;
        serverName = readServerName(body);
        if (serverName === null) return { kind: "MALFORMED" };
      } else if (type === EXTENSION_ALPN) {
        if (sawAlpn) return { kind: "MALFORMED" };
        sawAlpn = true;
        alpn = readAlpn(body);
      }
    }
    return { kind: "CLIENT_HELLO", serverName, alpn };
  } catch {
    return { kind: "MALFORMED" };
  }
}

/** The one host_name entry the extension carries; null for anything else. */
function readServerName(body: Cursor): string | null {
  const listLength = body.u16();
  if (listLength !== body.remaining) return null;
  let host: string | null = null;
  while (body.remaining > 0) {
    const nameType = body.u8();
    const name = body.take(body.u16());
    if (nameType !== SERVER_NAME_HOST_NAME) continue;
    if (host !== null) return null;
    const text = asciiLowercase(name);
    if (text === null || !HOST_NAME.test(text)) return null;
    host = text;
  }
  return host;
}

function readAlpn(body: Cursor): string[] {
  const listLength = body.u16();
  if (listLength !== body.remaining) throw new RangeError("alpn");
  const protocols: string[] = [];
  while (body.remaining > 0) {
    const name = body.take(body.u8());
    const text = asciiLowercase(name);
    if (text === null || text.length === 0) throw new RangeError("alpn");
    protocols.push(text);
  }
  return protocols;
}

/** Printable ASCII only, lowercased; null when any byte is outside that. */
function asciiLowercase(bytes: Uint8Array): string | null {
  let text = "";
  for (const byte of bytes) {
    if (byte < 0x21 || byte > 0x7e) return null;
    text += String.fromCharCode(byte);
  }
  return text.toLowerCase();
}
