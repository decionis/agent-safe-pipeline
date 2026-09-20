/**
 * The DER the leaf issuer writes and reads: the handful of ASN.1 shapes an
 * X.509 certificate is made of, encoded minimally, and a walker over a DER
 * SEQUENCE's content. Minimal encoding is not a nicety here. A verifier in a
 * workload's runtime may be strict (Go's, Java's and the Rust web-PKI
 * libraries all refuse a length that is not in its shortest form), so a leaf
 * that OpenSSL would read and they would not is a leaf that governs Node and
 * fails Go. Each function encodes one shape and nothing else; the certificate
 * itself is composed in `LeafIssuer`.
 */

/** DER that cannot be walked: a length past the end of its container. */
export class MalformedDer extends RangeError {
  public constructor(message: string) {
    super(message);
    this.name = "MalformedDer";
  }
}

/** The length octets for `size` content bytes, in the shortest form DER allows. */
export function lengthOctets(size: number): Buffer {
  if (size < 0x80) return Buffer.from([size]);
  if (size < 0x100) return Buffer.from([0x81, size]);
  if (size < 0x10000) return Buffer.from([0x82, size >> 8, size & 0xff]);
  return Buffer.from([0x83, size >> 16, (size >> 8) & 0xff, size & 0xff]);
}

/** One element: tag, length, content. */
export function element(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), lengthOctets(content.length), content]);
}

export const sequence = (...parts: Buffer[]): Buffer => element(0x30, Buffer.concat(parts));
export const set = (...parts: Buffer[]): Buffer => element(0x31, Buffer.concat(parts));
export const octetString = (bytes: Buffer): Buffer => element(0x04, bytes);
export const bitString = (bytes: Buffer, unusedBits = 0): Buffer =>
  element(0x03, Buffer.concat([Buffer.from([unusedBits]), bytes]));
export const utf8String = (text: string): Buffer => element(0x0c, Buffer.from(text));
export const ia5String = (text: string): Buffer => element(0x16, Buffer.from(text));
// Written out rather than composed, so that nothing runs while the module loads.
export const booleanTrue = Buffer.from([0x01, 0x01, 0xff]);
export const asn1Null = Buffer.from([0x05, 0x00]);
/** A context-specific, constructed, explicitly tagged element: `[index]`. */
export const explicit = (index: number, content: Buffer): Buffer => element(0xa0 | index, content);
/** A context-specific, primitive, implicitly tagged element, such as a GeneralName's dNSName. */
export const implicit = (index: number, content: Buffer): Buffer => element(0x80 | index, content);

/**
 * A non-negative INTEGER from its big-endian magnitude: a leading zero is
 * added when the top bit is set, so the value is not read as negative.
 */
export function integer(magnitude: Buffer): Buffer {
  const first = magnitude.readUInt8(0);
  return element(
    0x02,
    (first & 0x80) === 0 ? magnitude : Buffer.concat([Buffer.from([0]), magnitude]),
  );
}

/** An OBJECT IDENTIFIER from its dotted form. */
export function oid(dotted: string): Buffer {
  const [first = 0, second = 0, ...rest] = dotted.split(".").map(Number);
  const bytes: number[] = [first * 40 + second];
  for (const part of rest) {
    const encoded: number[] = [part & 0x7f];
    let remaining = part >> 7;
    while (remaining > 0) {
      encoded.unshift((remaining & 0x7f) | 0x80);
      remaining >>= 7;
    }
    bytes.push(...encoded);
  }
  return element(0x06, Buffer.from(bytes));
}

/** A UTCTime, `YYMMDDHHMMSSZ`, which X.509 uses for dates before 2050. */
export function utcTime(date: Date): Buffer {
  const text = date.toISOString().replace(/[-:T]/g, "").slice(2, 14);
  return element(0x17, Buffer.from(`${text}Z`));
}

/** An X.509 Extension: identifier, `critical` only when true (DER omits the default), value. */
export function extension(identifier: string, critical: boolean, value: Buffer): Buffer {
  return sequence(oid(identifier), ...(critical ? [booleanTrue] : []), octetString(value));
}

/** The PEM of `bytes` under `label`, base64 in lines of 64. */
export function pem(label: string, bytes: Buffer): string {
  const base64 = bytes.toString("base64");
  const lines: string[] = [];
  for (let offset = 0; offset < base64.length; offset += 64) {
    lines.push(base64.slice(offset, offset + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/** One element as read: its tag, the bytes of the whole element, and of its content. */
export interface Element {
  readonly tag: number;
  readonly whole: Buffer;
  readonly content: Buffer;
}

/** The elements of a SEQUENCE's (or SET's) content, in order. */
export function children(content: Buffer): Element[] {
  const found: Element[] = [];
  let offset = 0;
  while (offset < content.length) {
    if (offset + 2 > content.length) throw new MalformedDer(`element header at ${offset} is cut`);
    const tag = content.readUInt8(offset);
    let size = content.readUInt8(offset + 1);
    let headerLength = 2;
    if (size & 0x80) {
      const count = size & 0x7f;
      if (offset + 2 + count > content.length) {
        throw new MalformedDer(`length octets at ${offset} are cut`);
      }
      size = 0;
      for (let index = 0; index < count; index += 1) {
        size = size * 0x100 + content.readUInt8(offset + 2 + index);
      }
      headerLength = 2 + count;
    }
    const end = offset + headerLength + size;
    if (end > content.length) throw new MalformedDer(`element at ${offset} runs past the end`);
    found.push({
      tag,
      whole: content.subarray(offset, end),
      content: content.subarray(offset + headerLength, end),
    });
    offset = end;
  }
  return found;
}

/**
 * The subject Name of a certificate, as encoded: the element after the
 * validity in its TBSCertificate, whether or not the version is present. These
 * are the bytes a leaf's issuer field must repeat exactly for a strict verifier
 * to chain them; OpenSSL compares names canonically, others compare bytes.
 */
export function subjectNameOf(certificate: Buffer): Buffer {
  const [outer] = children(certificate);
  if (outer === undefined || outer.tag !== 0x30) throw new MalformedDer("not a Certificate");
  const [tbs] = children(outer.content);
  if (tbs === undefined || tbs.tag !== 0x30) throw new MalformedDer("not a TBSCertificate");
  const fields = children(tbs.content);
  const versionless = fields[0]?.tag === 0xa0 ? fields.slice(1) : fields;
  // serial, signature algorithm, issuer, validity, subject
  const subject = versionless[4];
  if (subject === undefined || subject.tag !== 0x30) throw new MalformedDer("no subject Name");
  return subject.whole;
}
