import { X509Certificate } from "node:crypto";
import { once } from "node:events";
import { connect, createSecureContext, createServer, type Server } from "node:tls";
import { afterEach, describe, expect, it } from "vitest";
import {
  asn1Null,
  children,
  lengthOctets,
  oid,
  sequence,
  subjectNameOf,
  type Element,
} from "../../src/intercept/Der.js";
import { LeafIssuer, LeafIssuerError } from "../../src/intercept/LeafIssuer.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";

/** A TLS server presenting the issuer's leaf for whatever name the client asks for. */
async function serverPresenting(issuer: LeafIssuer): Promise<{ server: Server; port: number }> {
  const server = createServer({
    SNICallback: (name, callback) => {
      const leaf = issuer.leafFor(name);
      callback(null, createSecureContext({ cert: leaf.chainPem, key: leaf.keyPem }));
    },
  });
  server.on("secureConnection", (socket) => socket.end("hello"));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { server, port: (server.address() as { port: number }).port };
}

describe("LeafIssuer", () => {
  const servers: Server[] = [];
  afterEach(async () => {
    for (const server of servers.splice(0)) await new Promise((resolve) => server.close(resolve));
  });

  for (const keyType of ["ec", "rsa"] as const) {
    it(`mints a leaf a client trusting only the ${keyType.toUpperCase()} authority accepts for that name`, async () => {
      const authority = new TestCertificateAuthority(`Operator ${keyType} CA`, keyType);
      const issuer = new LeafIssuer({
        certificatePem: authority.certificate,
        keyPem: authority.privateKeyPem,
      });
      const { server, port } = await serverPresenting(issuer);
      servers.push(server);
      const client = connect({
        host: "127.0.0.1",
        port,
        servername: "api.governed.example",
        ca: [authority.certificate],
      });
      await once(client, "secureConnect");
      expect(client.authorized).toBe(true);
      const presented = client.getPeerCertificate();
      expect(presented.subject.CN).toBe("api.governed.example");
      expect(presented.subjectaltname).toBe("DNS:api.governed.example");
      expect(presented.issuer.CN).toBe(`Operator ${keyType} CA`);
      client.destroy();

      const leaf = new X509Certificate(issuer.leafFor("api.governed.example").certificatePem);
      expect(leaf.ca).toBe(false);
      expect(leaf.keyUsage).toEqual(["1.3.6.1.5.5.7.3.1"]);
      expect(leaf.checkIssued(new X509Certificate(authority.certificate))).toBe(true);
      expect(leaf.verify(new X509Certificate(authority.certificate).publicKey)).toBe(true);
      expect(new Date(leaf.validTo).getTime() - new Date(leaf.validFrom).getTime()).toBe(
        25 * 60 * 60 * 1_000,
      );
    });
  }

  it("is refused by a client that does not trust the authority, and for a name the leaf does not carry", async () => {
    const authority = new TestCertificateAuthority();
    const other = new TestCertificateAuthority("Someone Else");
    const issuer = new LeafIssuer({
      certificatePem: authority.certificate,
      keyPem: authority.privateKeyPem,
    });
    const { server, port } = await serverPresenting(issuer);
    servers.push(server);
    const untrusting = connect({
      host: "127.0.0.1",
      port,
      servername: "api.governed.example",
      ca: [other.certificate],
    });
    const refusal = await new Promise<Error>((resolve) => untrusting.once("error", resolve));
    expect(refusal.message).toMatch(
      /self[- ]signed certificate in certificate chain|unable to (get|verify)/i,
    );
    const leaf = new X509Certificate(issuer.leafFor("api.governed.example").certificatePem);
    expect(leaf.checkHost("api.governed.example")).toBe("api.governed.example");
    expect(leaf.checkHost("other.governed.example")).toBeUndefined();
  });

  it("keeps a leaf while it has time left and reissues it when it has not, with one key for all", () => {
    let now = Date.UTC(2026, 8, 20, 12, 0, 0);
    const authority = new TestCertificateAuthority();
    const issuer = new LeafIssuer(
      { certificatePem: authority.certificate, keyPem: authority.privateKeyPem },
      () => now,
    );
    const first = issuer.leafFor("a.example");
    expect(issuer.leafFor("a.example")).toBe(first);
    expect(first.chainPem.startsWith(first.certificatePem)).toBe(true);
    expect(first.chainPem.endsWith(authority.certificate)).toBe(true);
    const certificate = new X509Certificate(first.certificatePem);
    expect(new Date(certificate.validFrom).getTime()).toBe(now - 60 * 60 * 1_000);
    expect(new Date(certificate.validTo).getTime()).toBe(first.notAfter);
    now += 21 * 60 * 60 * 1_000;
    expect(issuer.leafFor("a.example")).toBe(first);
    now += 2 * 60 * 60 * 1_000;
    const second = issuer.leafFor("a.example");
    expect(second).not.toBe(first);
    expect(second.keyPem).toBe(first.keyPem);
    expect(new X509Certificate(second.certificatePem).serialNumber).not.toBe(
      certificate.serialNumber,
    );
    const other = issuer.leafFor("b.example");
    expect(other.keyPem).toBe(first.keyPem);
    expect(new X509Certificate(other.certificatePem).subject).toBe("CN=b.example");
  });

  it("refuses an authority it cannot sign with", () => {
    const authority = new TestCertificateAuthority();
    const other = new TestCertificateAuthority("Other");
    const leaf = authority.issueServer(["leaf.example"]);
    const attempt = (certificatePem: string, keyPem: string): string => {
      try {
        new LeafIssuer({ certificatePem, keyPem });
        return "ISSUED";
      } catch (error) {
        if (!(error instanceof LeafIssuerError)) return "OTHER";
        expect(error.name).toBe("LeafIssuerError");
        expect(error.message).toBe(error.code);
        return error.code;
      }
    };
    expect(attempt("not a certificate", authority.privateKeyPem)).toBe("CA_CERTIFICATE_INVALID");
    expect(attempt(authority.certificate, "not a key")).toBe("CA_KEY_INVALID");
    expect(attempt(authority.certificate, other.privateKeyPem)).toBe("CA_KEY_MISMATCH");
    expect(attempt(leaf.cert, leaf.key)).toBe("CA_NOT_AN_AUTHORITY");
    // An authority whose key is neither EC nor RSA is refused rather than
    // signed with: the leaf's signature must be one every client verifies.
    const edwards = new TestCertificateAuthority("Edwards", "ed25519");
    expect(new X509Certificate(edwards.certificate).ca).toBe(true);
    expect(attempt(edwards.certificate, edwards.privateKeyPem)).toBe("CA_KEY_INVALID");
    expect(attempt(authority.certificate, authority.privateKeyPem)).toBe("ISSUED");
  });

  /** Every length in a DER structure is in its shortest form, down through the constructed elements. */
  function expectMinimal(content: Buffer): void {
    for (const found of children(content)) {
      const header = found.whole.length - found.content.length;
      expect(header, `tag ${found.tag.toString(16)}`).toBe(
        1 + lengthOctets(found.content.length).length,
      );
      // Constructed elements hold DER; so does each extension's OCTET STRING value.
      if ((found.tag & 0x20) !== 0 || found.tag === 0x04) expectMinimal(found.content);
    }
  }

  const fieldsOf = (certificatePem: string): { fields: Element[]; outer: Element[] } => {
    const raw = new X509Certificate(certificatePem).raw;
    expectMinimal(raw);
    const outer = children(children(raw)[0]!.content);
    return { fields: children(outer[0]!.content), outer };
  };

  for (const [keyType, algorithm] of [
    ["ec", sequence(oid("1.2.840.10045.4.3.2"))],
    ["rsa", sequence(oid("1.2.840.113549.1.1.11"), asn1Null)],
  ] as const) {
    it(`writes a strict-DER leaf under the ${keyType.toUpperCase()} authority, its issuer the authority's subject byte for byte`, () => {
      const authority = new TestCertificateAuthority("Strict CA", keyType);
      const issuer = new LeafIssuer({
        certificatePem: authority.certificate,
        keyPem: authority.privateKeyPem,
      });
      const { fields, outer } = fieldsOf(issuer.leafFor("strict.example").certificatePem);
      // version [0] { 2 }, serial, algorithm, issuer, validity, subject, SPKI, extensions [3]
      expect(fields).toHaveLength(8);
      expect(fields[0]!.whole.toString("hex")).toBe("a003020102");
      expect(fields[1]!.tag).toBe(0x02);
      expect(fields[1]!.content).toHaveLength(16);
      expect(fields[2]!.whole.equals(algorithm)).toBe(true);
      expect(outer[1]!.whole.equals(algorithm)).toBe(true);
      expect(outer[2]!.tag).toBe(0x03);
      const authoritySubject = subjectNameOf(new X509Certificate(authority.certificate).raw);
      expect(fields[3]!.whole.equals(authoritySubject)).toBe(true);
      expect(fields[4]!.content.subarray(0, 1)).toEqual(Buffer.from([0x17]));
      expect(fields[5]!.whole.includes(Buffer.from("strict.example"))).toBe(true);
      expect(fields[7]!.tag).toBe(0xa3);
      // Which extensions are critical is a choice a verifier acts on: basic
      // constraints and key usage are, the rest are not.
      const critical = new Map(
        children(children(fields[7]!.content)[0]!.content).map((extension) => {
          const parts = children(extension.content);
          return [parts[0]!.whole.toString("hex"), parts.length === 3];
        }),
      );
      expect(critical).toEqual(
        new Map([
          [oid("2.5.29.19").toString("hex"), true],
          [oid("2.5.29.15").toString("hex"), true],
          [oid("2.5.29.37").toString("hex"), false],
          [oid("2.5.29.17").toString("hex"), false],
        ]),
      );
    });
  }

  it("mints a positive serial with its top bit clear and its first byte never zero", () => {
    const authority = new TestCertificateAuthority();
    const issuer = new LeafIssuer({
      certificatePem: authority.certificate,
      keyPem: authority.privateKeyPem,
    });
    const seen = new Set<string>();
    for (let index = 0; index < 32; index += 1) {
      const { fields } = fieldsOf(issuer.leafFor(`serial-${index}.example`).certificatePem);
      const serial = fields[1]!.content;
      expect(serial).toHaveLength(16);
      expect(serial.readUInt8(0) & 0x80).toBe(0);
      expect(serial.readUInt8(0)).not.toBe(0);
      seen.add(serial.toString("hex"));
    }
    expect(seen.size).toBe(32);
  });

  it("reissues at exactly the margin, and evicts everything only when a new host finds it full", () => {
    let now = Date.UTC(2026, 8, 20, 12, 0, 0);
    const authority = new TestCertificateAuthority();
    const issuer = new LeafIssuer(
      { certificatePem: authority.certificate, keyPem: authority.privateKeyPem },
      () => now,
    );
    const first = issuer.leafFor("margin.example");
    now += 22 * 60 * 60 * 1_000 - 1;
    expect(issuer.leafFor("margin.example")).toBe(first);
    now += 1;
    expect(issuer.leafFor("margin.example")).not.toBe(first);

    // A thousand hosts fill a cache; a cached, fresh host survives a reissue
    // among them, and a new host beyond the ceiling clears them all.
    const full = new LeafIssuer(
      { certificatePem: authority.certificate, keyPem: authority.privateKeyPem },
      () => now,
    );
    const early = Array.from({ length: 999 }, (_, index) => full.leafFor(`h${index}.example`));
    now += 22 * 60 * 60 * 1_000;
    const late = full.leafFor("late.example");
    now += 60 * 60 * 1_000;
    expect(full.leafFor("h0.example")).not.toBe(early[0]);
    expect(full.leafFor("late.example")).toBe(late);
    expect(full.leafFor("h1.example")).not.toBe(early[1]);
    const beyond = full.leafFor("beyond.example");
    expect(full.leafFor("beyond.example")).toBe(beyond);
    expect(full.leafFor("late.example")).not.toBe(late);
  });
});
