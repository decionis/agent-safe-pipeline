import { generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { EgressPolicy } from "../../src/egress/EgressPolicy.js";

/** A certificate and its key, PEM-encoded, with the SPKI pin the policy would take. */
export interface IssuedCertificate {
  readonly cert: string;
  readonly key: string;
  readonly pin: string;
}

const ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
const COMMON_NAME = "2.5.4.3";
const BASIC_CONSTRAINTS = "2.5.29.19";
const KEY_USAGE = "2.5.29.15";
const SUBJECT_ALT_NAME = "2.5.29.17";
const EXTENDED_KEY_USAGE = "2.5.29.37";
const SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
const CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
const DAY_MS = 24 * 60 * 60 * 1_000;

function length(size: number): Buffer {
  if (size < 0x80) return Buffer.from([size]);
  if (size < 0x100) return Buffer.from([0x81, size]);
  return Buffer.from([0x82, size >> 8, size & 0xff]);
}

function der(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), length(content.length), content]);
}

const sequence = (...parts: Buffer[]): Buffer => der(0x30, Buffer.concat(parts));
const set = (...parts: Buffer[]): Buffer => der(0x31, Buffer.concat(parts));
const octetString = (bytes: Buffer): Buffer => der(0x04, bytes);
const bitString = (bytes: Buffer, unusedBits = 0): Buffer =>
  der(0x03, Buffer.concat([Buffer.from([unusedBits]), bytes]));
const utf8String = (text: string): Buffer => der(0x0c, Buffer.from(text, "utf8"));
const booleanTrue = der(0x01, Buffer.from([0xff]));
const explicit = (index: number, content: Buffer): Buffer => der(0xa0 | index, content);

function integer(value: Buffer): Buffer {
  const first = value[0] ?? 0;
  return der(0x02, (first & 0x80) === 0 ? value : Buffer.concat([Buffer.from([0]), value]));
}

function oid(dotted: string): Buffer {
  const parts = dotted.split(".").map(Number);
  const bytes: number[] = [(parts[0] ?? 0) * 40 + (parts[1] ?? 0)];
  for (const part of parts.slice(2)) {
    const encoded: number[] = [part & 0x7f];
    let rest = part >> 7;
    while (rest > 0) {
      encoded.unshift((rest & 0x7f) | 0x80);
      rest >>= 7;
    }
    bytes.push(...encoded);
  }
  return der(0x06, Buffer.from(bytes));
}

function utcTime(date: Date): Buffer {
  const text = date.toISOString().replace(/[-:T]/g, "").slice(2, 14);
  return der(0x17, Buffer.from(`${text}Z`, "ascii"));
}

const name = (commonName: string): Buffer =>
  sequence(set(sequence(oid(COMMON_NAME), utf8String(commonName))));

function extension(identifier: string, critical: boolean, value: Buffer): Buffer {
  return sequence(oid(identifier), ...(critical ? [booleanTrue] : []), octetString(value));
}

function generalNames(
  dns: readonly string[],
  ips: readonly string[],
  uris: readonly string[],
): Buffer {
  return sequence(
    ...dns.map((host) => der(0x82, Buffer.from(host, "ascii"))),
    ...ips.map((ip) => der(0x87, Buffer.from(ip.split(".").map(Number)))),
    ...uris.map((uri) => der(0x86, Buffer.from(uri, "ascii"))),
  );
}

function pem(label: string, bytes: Buffer): string {
  const lines = bytes.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

interface Subject {
  readonly commonName: string;
  readonly ca: boolean;
  readonly dns?: readonly string[];
  readonly ips?: readonly string[];
  readonly uris?: readonly string[];
  readonly usage: readonly string[];
}

/**
 * An X.509 v3 authority built in-process with a minimal DER encoder, so
 * tests can hold a real TLS conversation with nothing committed. P-256 keys,
 * ECDSA with SHA-256, a day either side of now, and the extensions Node's
 * verifier reads: basic constraints, key usage, subject alternative names,
 * and extended key usage. Test-only; nothing here is a certificate
 * authority anyone should trust.
 */
export class TestCertificateAuthority {
  public readonly certificate: string;
  private readonly privateKey: KeyObject;
  private readonly commonName: string;

  public constructor(commonName = "Synthetic Test CA") {
    this.commonName = commonName;
    const keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.privateKey = keys.privateKey;
    this.certificate = pem(
      "CERTIFICATE",
      TestCertificateAuthority.certificate(
        { commonName, ca: true, usage: [] },
        keys.publicKey,
        commonName,
        keys.privateKey,
      ),
    );
  }

  /** A server certificate for the given names and loopback addresses. */
  public issueServer(
    dns: readonly string[],
    ips: readonly string[] = ["127.0.0.1"],
  ): IssuedCertificate {
    return this.issue({
      commonName: dns[0] ?? "server",
      ca: false,
      dns,
      ips,
      usage: [SERVER_AUTH],
    });
  }

  /** A client certificate, optionally with a URI name for a workload identity. */
  public issueClient(commonName: string, uris: readonly string[] = []): IssuedCertificate {
    return this.issue({ commonName, ca: false, uris, usage: [CLIENT_AUTH] });
  }

  public static pinOf(publicKey: KeyObject): string {
    return EgressPolicy.spkiPin(publicKey.export({ type: "spki", format: "der" }));
  }

  private issue(subject: Subject): IssuedCertificate {
    const keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const cert = TestCertificateAuthority.certificate(
      subject,
      keys.publicKey,
      this.commonName,
      this.privateKey,
    );
    return {
      cert: pem("CERTIFICATE", cert),
      key: keys.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      pin: TestCertificateAuthority.pinOf(keys.publicKey),
    };
  }

  private static certificate(
    subject: Subject,
    publicKey: KeyObject,
    issuer: string,
    signer: KeyObject,
  ): Buffer {
    // A positive integer in minimal form: the first byte is never zero and never has its top bit set.
    const serial = randomBytes(12);
    serial[0] = ((serial[0] ?? 0) & 0x7f) | 0x01;
    const now = Date.now();
    const extensions = [
      extension(BASIC_CONSTRAINTS, true, subject.ca ? sequence(booleanTrue) : sequence()),
      extension(
        KEY_USAGE,
        true,
        subject.ca ? bitString(Buffer.from([0x86]), 1) : bitString(Buffer.from([0x80]), 7),
      ),
      ...(subject.ca
        ? []
        : [extension(EXTENDED_KEY_USAGE, false, sequence(...subject.usage.map(oid)))]),
      ...((subject.dns?.length ?? 0) + (subject.ips?.length ?? 0) + (subject.uris?.length ?? 0) > 0
        ? [
            extension(
              SUBJECT_ALT_NAME,
              false,
              generalNames(subject.dns ?? [], subject.ips ?? [], subject.uris ?? []),
            ),
          ]
        : []),
    ];
    const tbs = sequence(
      explicit(0, integer(Buffer.from([2]))),
      integer(serial),
      sequence(oid(ECDSA_WITH_SHA256)),
      name(issuer),
      sequence(utcTime(new Date(now - DAY_MS)), utcTime(new Date(now + DAY_MS))),
      name(subject.commonName),
      publicKey.export({ type: "spki", format: "der" }),
      explicit(3, sequence(...extensions)),
    );
    const signature = sign("sha256", tbs, signer);
    return sequence(tbs, sequence(oid(ECDSA_WITH_SHA256)), bitString(signature));
  }
}
