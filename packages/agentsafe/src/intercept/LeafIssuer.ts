/**
 * The certificates the governing interceptor presents to a workload: one leaf
 * per server name, minted from the operator's own certificate authority, so
 * that a workload whose runtime trusts that authority completes its TLS
 * handshake with the interceptor and never learns the difference. This is the
 * price of governing HTTPS transparently, stated in ADR 0005, and this module
 * is where it is paid: the authority's private key is read from a file the
 * operator mounts, the leaf's key is generated once per process and never
 * written anywhere, and each leaf names exactly one host, for a day.
 *
 * The shape is one X.509 v3 certificate with the extensions a TLS client
 * reads (basic constraints, key usage, extended key usage for server
 * authentication, one subject alternative name), written with the DER
 * functions in `Der.ts` and signed with the authority's key: ECDSA with
 * SHA-256 for an EC key, sha256WithRSAEncryption for an RSA key. The leaf's
 * issuer is the authority certificate's subject, taken byte for byte from the
 * certificate, so a verifier that compares names as bytes chains them.
 */
import {
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  X509Certificate,
  type KeyObject,
} from "node:crypto";
import {
  asn1Null,
  bitString,
  explicit,
  extension,
  implicit,
  integer,
  oid,
  pem,
  sequence,
  set,
  subjectNameOf,
  utcTime,
  utf8String,
} from "./Der.js";

export class LeafIssuerError extends Error {
  public constructor(
    public readonly code:
      "CA_CERTIFICATE_INVALID" | "CA_KEY_INVALID" | "CA_KEY_MISMATCH" | "CA_NOT_AN_AUTHORITY",
  ) {
    super(code);
    this.name = "LeafIssuerError";
  }
}

const ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
const SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
const COMMON_NAME = "2.5.4.3";
const BASIC_CONSTRAINTS = "2.5.29.19";
const KEY_USAGE = "2.5.29.15";
const SUBJECT_ALT_NAME = "2.5.29.17";
const EXTENDED_KEY_USAGE = "2.5.29.37";
const SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
const HOUR_MS = 60 * 60 * 1_000;
/** A leaf is valid for a day, backdated an hour for clocks that disagree. */
const LEAF_LIFETIME_MS = 24 * HOUR_MS;
const LEAF_BACKDATE_MS = HOUR_MS;
/** A cached leaf is reissued when no more than this remains, so no client sees one expire. */
const REISSUE_MARGIN_MS = 2 * HOUR_MS;
/** The most leaves kept at once; a governed set is a handful of hosts, and this is the ceiling. */
const MAX_CACHED_LEAVES = 1_000;

export interface OperatorAuthority {
  /** The authority's certificate, PEM. Sent to clients as the chain, so an intermediate works too. */
  readonly certificatePem: string;
  /** The authority's private key, PEM (PKCS#8 or traditional), EC or RSA. */
  readonly keyPem: string;
}

/** A minted leaf: what a TLS server presents for one host, and until when. */
export interface Leaf {
  /** The leaf certificate alone, PEM. */
  readonly certificatePem: string;
  /** The leaf followed by the authority's certificate: the chain a client is sent. */
  readonly chainPem: string;
  /** The leaf's private key, PKCS#8 PEM, this process's alone. */
  readonly keyPem: string;
  readonly notAfter: number;
}

/**
 * Mints and caches one leaf certificate per server name, signed by the
 * operator's authority. The TLS context that presents a leaf is the
 * listener's to build, under `src/http`, where sockets are opened.
 */
export class LeafIssuer {
  private readonly signer: KeyObject;
  private readonly signatureAlgorithm: Buffer;
  private readonly issuerName: Buffer;
  private readonly authorityPem: string;
  private readonly leafKeyPem: string;
  private readonly leafPublicKeyDer: Buffer;
  private readonly leaves = new Map<string, Leaf>();

  public constructor(
    authority: OperatorAuthority,
    private readonly clock: () => number = () => Date.now(),
  ) {
    let certificate: X509Certificate;
    try {
      certificate = new X509Certificate(authority.certificatePem);
    } catch {
      throw new LeafIssuerError("CA_CERTIFICATE_INVALID");
    }
    if (!certificate.ca) throw new LeafIssuerError("CA_NOT_AN_AUTHORITY");
    try {
      this.signer = createPrivateKey(authority.keyPem);
    } catch {
      throw new LeafIssuerError("CA_KEY_INVALID");
    }
    if (!certificate.checkPrivateKey(this.signer)) throw new LeafIssuerError("CA_KEY_MISMATCH");
    switch (this.signer.asymmetricKeyType) {
      case "ec":
        this.signatureAlgorithm = sequence(oid(ECDSA_WITH_SHA256));
        break;
      case "rsa":
        this.signatureAlgorithm = sequence(oid(SHA256_WITH_RSA), asn1Null);
        break;
      default:
        throw new LeafIssuerError("CA_KEY_INVALID");
    }
    this.issuerName = subjectNameOf(certificate.raw);
    this.authorityPem = certificate.toString();
    const keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.leafKeyPem = keys.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    this.leafPublicKeyDer = keys.publicKey.export({ type: "spki", format: "der" });
  }

  /** The leaf for `host`: minted now, or kept from before while it has more than two hours left. */
  public leafFor(host: string): Leaf {
    const now = this.clock();
    const cached = this.leaves.get(host);
    if (cached !== undefined && cached.notAfter - now > REISSUE_MARGIN_MS) return cached;
    if (this.leaves.size >= MAX_CACHED_LEAVES && cached === undefined) this.leaves.clear();
    const notAfter = now + LEAF_LIFETIME_MS;
    const certificatePem = pem(
      "CERTIFICATE",
      this.certificate(host, now - LEAF_BACKDATE_MS, notAfter),
    );
    const leaf: Leaf = {
      certificatePem,
      chainPem: `${certificatePem}${this.authorityPem}`,
      keyPem: this.leafKeyPem,
      notAfter,
    };
    this.leaves.set(host, leaf);
    return leaf;
  }

  private certificate(host: string, notBefore: number, notAfter: number): Buffer {
    // A positive serial in minimal form: the first byte is never zero and never has its top bit set.
    const serial = randomBytes(16);
    serial.writeUInt8((serial.readUInt8(0) & 0x7f) | 0x01, 0);
    const subject = sequence(set(sequence(oid(COMMON_NAME), utf8String(host))));
    const extensions = sequence(
      extension(BASIC_CONSTRAINTS, true, sequence()),
      extension(KEY_USAGE, true, bitString(Buffer.from([0x80]), 7)),
      extension(EXTENDED_KEY_USAGE, false, sequence(oid(SERVER_AUTH))),
      extension(SUBJECT_ALT_NAME, false, sequence(implicit(2, Buffer.from(host)))),
    );
    const tbs = sequence(
      explicit(0, integer(Buffer.from([2]))),
      integer(serial),
      this.signatureAlgorithm,
      this.issuerName,
      sequence(utcTime(new Date(notBefore)), utcTime(new Date(notAfter))),
      subject,
      this.leafPublicKeyDer,
      explicit(3, extensions),
    );
    const signature = sign("sha256", tbs, this.signer);
    return sequence(tbs, this.signatureAlgorithm, bitString(signature));
  }
}
