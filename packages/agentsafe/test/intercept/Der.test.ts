import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  asn1Null,
  bitString,
  booleanTrue,
  children,
  element,
  explicit,
  extension,
  ia5String,
  implicit,
  integer,
  lengthOctets,
  MalformedDer,
  octetString,
  oid,
  pem,
  sequence,
  set,
  subjectNameOf,
  utcTime,
  utf8String,
} from "../../src/intercept/Der.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";

const hex = (bytes: Buffer): string => bytes.toString("hex");

describe("the DER writer", () => {
  it("encodes every length in its shortest form, at each boundary", () => {
    expect(hex(lengthOctets(0))).toBe("00");
    expect(hex(lengthOctets(0x7f))).toBe("7f");
    expect(hex(lengthOctets(0x80))).toBe("8180");
    expect(hex(lengthOctets(0xff))).toBe("81ff");
    expect(hex(lengthOctets(0x100))).toBe("820100");
    expect(hex(lengthOctets(0xffff))).toBe("82ffff");
    expect(hex(lengthOctets(0x10000))).toBe("83010000");
    expect(hex(lengthOctets(0x123456))).toBe("83123456");
    expect(hex(element(0x04, Buffer.alloc(0x80, 0xab)))).toBe(`048180${"ab".repeat(0x80)}`);
  });

  it("writes the primitive shapes a certificate is made of, byte for byte", () => {
    expect(hex(booleanTrue)).toBe("0101ff");
    expect(hex(asn1Null)).toBe("0500");
    expect(hex(integer(Buffer.from([2])))).toBe("020102");
    expect(hex(integer(Buffer.from([0x80, 0x01])))).toBe("0203008001");
    expect(hex(integer(Buffer.from([0x7f, 0xff])))).toBe("02027fff");
    expect(hex(bitString(Buffer.from([0x80]), 7))).toBe("03020780");
    expect(hex(bitString(Buffer.from([0xaa, 0x55])))).toBe("030300aa55");
    expect(hex(octetString(Buffer.from([1, 2, 3])))).toBe("0403010203");
    expect(hex(utf8String("é"))).toBe("0c02c3a9");
    expect(hex(ia5String("ab"))).toBe("16026162");
    expect(hex(utcTime(new Date(Date.UTC(2026, 8, 20, 12, 34, 56, 789))))).toBe(
      `170d${Buffer.from("260920123456Z").toString("hex")}`,
    );
    expect(hex(utcTime(new Date(Date.UTC(2031, 0, 1, 0, 0, 0))))).toBe(
      `170d${Buffer.from("310101000000Z").toString("hex")}`,
    );
  });

  it("writes object identifiers with multi-byte arcs in base 128", () => {
    expect(hex(oid("2.5.4.3"))).toBe("0603550403");
    expect(hex(oid("2.5.29.19"))).toBe("0603551d13");
    expect(hex(oid("1.2.840.113549.1.1.11"))).toBe("06092a864886f70d01010b");
    expect(hex(oid("1.2.840.10045.4.3.2"))).toBe("06082a8648ce3d040302");
    expect(hex(oid("1.3.6.1.5.5.7.3.1"))).toBe("06082b06010505070301");
    expect(hex(oid("2.16.840.1.101.3.4.2.1"))).toBe("0609608648016503040201");
  });

  it("writes the constructed shapes and the two tagging forms", () => {
    expect(hex(sequence())).toBe("3000");
    expect(hex(sequence(asn1Null, booleanTrue))).toBe("300505000101ff");
    expect(hex(set(asn1Null))).toBe("31020500");
    expect(hex(explicit(0, integer(Buffer.from([2]))))).toBe("a003020102");
    expect(hex(explicit(3, sequence()))).toBe("a3023000");
    expect(hex(implicit(2, Buffer.from("a.example")))).toBe(
      `8209${Buffer.from("a.example").toString("hex")}`,
    );
    expect(hex(extension("2.5.29.19", true, sequence()))).toBe("300c0603551d130101ff04023000");
    expect(hex(extension("2.5.29.37", false, sequence(oid("1.3.6.1.5.5.7.3.1"))))).toBe(
      "30130603551d25040c300a06082b06010505070301",
    );
  });

  it("wraps PEM at 64 columns under its label", () => {
    const one = Buffer.alloc(48, 1);
    expect(pem("THING", one)).toBe(
      `-----BEGIN THING-----\n${one.toString("base64")}\n-----END THING-----\n`,
    );
    expect(one.toString("base64")).toHaveLength(64);
    const two = Buffer.alloc(49, 2);
    const base64 = two.toString("base64");
    expect(pem("THING", two)).toBe(
      `-----BEGIN THING-----\n${base64.slice(0, 64)}\n${base64.slice(64)}\n-----END THING-----\n`,
    );
    const many = pem("CERTIFICATE", Buffer.alloc(1_000, 3)).split("\n");
    expect(many[0]).toBe("-----BEGIN CERTIFICATE-----");
    expect(many.at(-2)).toBe("-----END CERTIFICATE-----");
    expect(many.at(-1)).toBe("");
    const body = many.slice(1, -2);
    expect(body.length).toBe(Math.ceil((1_000 * 4) / 3 / 64));
    for (const line of body.slice(0, -1)) expect(line).toHaveLength(64);
    expect(body.at(-1)).toMatch(/^[a-z0-9+/=]{1,64}$/i);
  });
});

describe("the DER reader", () => {
  it("walks a sequence's content in order, through short and long lengths", () => {
    const long1 = element(0x04, Buffer.alloc(0x90, 0x11));
    const long2 = element(0x04, Buffer.alloc(0x1234, 0x22));
    const read = children(Buffer.concat([asn1Null, booleanTrue, long1, long2]));
    expect(read.map((found) => found.tag)).toEqual([0x05, 0x01, 0x04, 0x04]);
    expect(read.map((found) => found.content.length)).toEqual([0, 1, 0x90, 0x1234]);
    expect(read.map((found) => found.whole.length)).toEqual([2, 3, 0x90 + 3, 0x1234 + 4]);
    expect(read[2]?.content.equals(Buffer.alloc(0x90, 0x11))).toBe(true);
    expect(read[3]?.whole.equals(long2)).toBe(true);
    expect(children(Buffer.alloc(0))).toEqual([]);
    // A long form the writer never produces is still read: the reader is for
    // what OpenSSL hands back, not for what this module wrote.
    expect(children(Buffer.from([0x30, 0x81, 0x00]))).toMatchObject([
      { tag: 0x30, content: Buffer.alloc(0) },
    ]);
  });

  it("refuses an element cut anywhere in its header or its content, saying where", () => {
    for (const [cut, reason] of [
      [Buffer.from([0x30]), "element header at 0 is cut"],
      [Buffer.from([0x30, 0x82, 0x01]), "length octets at 0 are cut"],
      [Buffer.from([0x30, 0x03, 0x05, 0x00]), "element at 0 runs past the end"],
      [Buffer.concat([asn1Null, Buffer.from([0x04, 0x81])]), "length octets at 2 are cut"],
      [Buffer.concat([asn1Null, Buffer.from([0x04])]), "element header at 2 is cut"],
      [element(0x04, Buffer.alloc(0x100)).subarray(0, 0x100), "element at 0 runs past the end"],
    ] as const) {
      expect(() => children(cut), cut.toString("hex")).toThrow(new MalformedDer(reason));
    }
    const error = new MalformedDer("why");
    expect(error.name).toBe("MalformedDer");
    expect(error).toBeInstanceOf(RangeError);
  });

  it("finds the subject name of a certificate with or without the version, and nothing else", () => {
    const algorithm = sequence(oid("1.2.840.10045.4.3.2"));
    const name = (common: string): Buffer =>
      sequence(set(sequence(oid("2.5.4.3"), utf8String(common))));
    const validity = sequence(utcTime(new Date(0)), utcTime(new Date(HOUR)));
    const spki = sequence(sequence(oid("1.2.840.10045.2.1")), bitString(Buffer.alloc(3)));
    const rest = [integer(Buffer.from([1])), algorithm, name("Issuer"), validity];
    const v3 = sequence(
      sequence(
        explicit(0, integer(Buffer.from([2]))),
        ...rest,
        name("Subject"),
        spki,
        explicit(3, sequence()),
      ),
      algorithm,
      bitString(Buffer.alloc(4)),
    );
    const v1 = sequence(
      sequence(...rest, name("Subject"), spki),
      algorithm,
      bitString(Buffer.alloc(4)),
    );
    expect(subjectNameOf(v3).equals(name("Subject"))).toBe(true);
    expect(subjectNameOf(v1).equals(name("Subject"))).toBe(true);
    for (const [malformed, reason] of [
      [octetString(Buffer.alloc(4)), "not a Certificate"],
      [Buffer.alloc(0), "not a Certificate"],
      [sequence(octetString(Buffer.alloc(2))), "not a TBSCertificate"],
      [sequence(), "not a TBSCertificate"],
      [sequence(sequence()), "no subject Name"],
      [sequence(sequence(...rest)), "no subject Name"],
      [sequence(sequence(...rest, octetString(Buffer.alloc(1)))), "no subject Name"],
    ] as const) {
      expect(() => subjectNameOf(malformed), reason).toThrow(new MalformedDer(reason));
    }
    // A real authority's subject, as OpenSSL encoded it.
    const authority = new TestCertificateAuthority("Real Enough");
    const subject = subjectNameOf(new X509Certificate(authority.certificate).raw);
    expect(subject.subarray(0, 1)).toEqual(Buffer.from([0x30]));
    expect(subject.includes(Buffer.from("Real Enough"))).toBe(true);
  });
});

const HOUR = 60 * 60 * 1_000;
