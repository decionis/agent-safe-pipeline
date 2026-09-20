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
const RECORD_VERSION_MAJOR = 0x03;
const HANDSHAKE_CLIENT_HELLO = 0x01;
const RECORD_HEADER_LENGTH = 5;
const HANDSHAKE_HEADER_LENGTH = 4;
const EXTENSION_SERVER_NAME = 0x0000;
const EXTENSION_ALPN = 0x0010;
const SERVER_NAME_HOST_NAME = 0x00;
/** The largest plaintext record TLS allows (RFC 8446 section 5.1). */
const MAX_RECORD_LENGTH = 16_384;
/** The most handshake bytes read before a hello is called malformed; well beyond any real one. */
export const MAX_CLIENT_HELLO_BYTES = 65_536;
/** RFC 1123 host name: labels of letters, digits and hyphens, at most 253 characters. */
const HOST_NAME =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
/** An ALPN protocol name as this interceptor will report it: printable ASCII, nothing else. */
const ALPN_PROTOCOL = /^[\x21-\x7e]+$/;

/** Thrown when a field claims more bytes than remain; the reader answers MALFORMED. */
class Short extends RangeError {}

class Cursor {
  private readonly view: DataView;
  public offset = 0;

  public constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  public get remaining(): number {
    return this.bytes.length - this.offset;
  }

  /** A read past the end throws from the view itself; the reader answers MALFORMED. */
  public u8(): number {
    const value = this.view.getUint8(this.offset);
    this.offset += 1;
    return value;
  }

  public u16(): number {
    const value = this.view.getUint16(this.offset);
    this.offset += 2;
    return value;
  }

  public u24(): number {
    return (this.u8() << 16) | this.u16();
  }

  /** Skipping past the end leaves nothing to read, and the next read throws. */
  public skip(length: number): void {
    this.offset += length;
  }

  /** Taking more than remains is refused here: a short slice would read as a shorter, valid field. */
  public take(length: number): Uint8Array {
    if (this.remaining < length) throw new Short();
    const slice = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }
}

type Refusal =
  { readonly kind: "NOT_TLS" } | { readonly kind: "NEED_MORE" } | { readonly kind: "MALFORMED" };
type Records = Refusal | { readonly fragments: readonly Uint8Array[] };

/**
 * Walks the handshake records from the start of the bytes until at least
 * `wanted` handshake bytes have been collected, or the bytes run out. A
 * ClientHello may be fragmented across records, and a client may already have
 * sent the first record of its next flight after it.
 */
function handshakeRecords(bytes: Uint8Array, wanted: number): Records {
  const fragments: Uint8Array[] = [];
  let total = 0;
  let offset = 0;
  while (total < wanted) {
    if (bytes.length - offset < RECORD_HEADER_LENGTH) return { kind: "NEED_MORE" };
    const header = new DataView(bytes.buffer, bytes.byteOffset + offset, RECORD_HEADER_LENGTH);
    const type = header.getUint8(0);
    const major = header.getUint8(1);
    const length = header.getUint16(3);
    if (
      type !== RECORD_HANDSHAKE ||
      major !== RECORD_VERSION_MAJOR ||
      length === 0 ||
      length > MAX_RECORD_LENGTH
    ) {
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
  }
  return { fragments };
}

/** The first `length` bytes of the fragments, in order: only the hello, never what follows it. */
function concat(fragments: readonly Uint8Array[], length: number): Uint8Array {
  const out = new Uint8Array(length);
  let offset = 0;
  for (const fragment of fragments) {
    const slice = fragment.subarray(0, Math.max(0, Math.min(fragment.length, length - offset)));
    out.set(slice, offset);
    offset += slice.length;
  }
  return out;
}

/** The handshake message bytes of the ClientHello, exactly as long as its header says. */
function handshakeBytes(bytes: Uint8Array): Refusal | { readonly data: Uint8Array } {
  const head = handshakeRecords(bytes, HANDSHAKE_HEADER_LENGTH);
  if ("kind" in head) return head;
  const header = new Cursor(concat(head.fragments, HANDSHAKE_HEADER_LENGTH));
  if (header.u8() !== HANDSHAKE_CLIENT_HELLO) return { kind: "MALFORMED" };
  const needed = HANDSHAKE_HEADER_LENGTH + header.u24();
  // A hello that announces itself larger than any real one is refused now,
  // not read for as long as the client cares to send.
  if (needed > MAX_CLIENT_HELLO_BYTES) return { kind: "MALFORMED" };
  const whole = handshakeRecords(bytes, needed);
  if ("kind" in whole) return whole;
  return { data: concat(whole.fragments, needed) };
}

/** Reads a client's first bytes as a TLS ClientHello, or says why they are not one. */
export function readClientHello(bytes: Uint8Array): ClientHelloReading {
  const records = handshakeBytes(bytes);
  if ("kind" in records) return records;
  const cursor = new Cursor(records.data);
  try {
    cursor.skip(HANDSHAKE_HEADER_LENGTH);
    cursor.u16(); // legacy_version
    cursor.skip(32); // random
    cursor.skip(cursor.u8()); // legacy_session_id
    cursor.skip(cursor.u16()); // cipher_suites
    cursor.skip(cursor.u8()); // legacy_compression_methods
    if (cursor.remaining === 0) return { kind: "CLIENT_HELLO", serverName: null, alpn: [] };
    const extensionsLength = cursor.u16();
    if (extensionsLength !== cursor.remaining) return { kind: "MALFORMED" };
    // Each extension may appear once (RFC 8446 section 4.2); a repeat is a
    // hello two parsers could read differently, and is refused.
    let serverName: string | null = null;
    let alpn: readonly string[] | null = null;
    while (cursor.remaining > 0) {
      const type = cursor.u16();
      const body = new Cursor(cursor.take(cursor.u16()));
      if (type === EXTENSION_SERVER_NAME) {
        if (serverName !== null) return { kind: "MALFORMED" };
        serverName = readServerName(body);
        if (serverName === null) return { kind: "MALFORMED" };
      } else if (type === EXTENSION_ALPN) {
        if (alpn !== null) return { kind: "MALFORMED" };
        alpn = readAlpn(body);
      }
    }
    return { kind: "CLIENT_HELLO", serverName, alpn: alpn ?? [] };
  } catch {
    // A field that ran past the bytes, or a length that disagreed with them:
    // a hello this parser cannot place, whatever the cause.
    return { kind: "MALFORMED" };
  }
}

/** The one host_name entry the extension carries; null for anything else. */
function readServerName(body: Cursor): string | null {
  if (body.u16() !== body.remaining) return null;
  let host: string | null = null;
  while (body.remaining > 0) {
    const nameType = body.u8();
    const name = latin1(body.take(body.u16())).toLowerCase();
    if (nameType !== SERVER_NAME_HOST_NAME) continue;
    if (host !== null || !HOST_NAME.test(name)) return null;
    host = name;
  }
  return host;
}

/** The protocol names in the order the client prefers them; a name outside printable ASCII is a refusal. */
function readAlpn(body: Cursor): readonly string[] {
  if (body.u16() !== body.remaining) throw new Short();
  const protocols: string[] = [];
  while (body.remaining > 0) {
    const name = latin1(body.take(body.u8()));
    if (!ALPN_PROTOCOL.test(name)) throw new Short();
    protocols.push(name);
  }
  return protocols;
}

function latin1(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return text;
}
