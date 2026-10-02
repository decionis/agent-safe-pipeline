import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { calculateJwkThumbprint, CompactSign, decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { verifyUsage } from "../../src/edge/UsageCount.js";
import { usagePeriod, type UsagePeriod } from "../../src/edge/UsagePeriod.js";
import {
  claimedUsage,
  consistentClaims,
  readUsageReport,
  signUsageReport,
  USAGE_REPORT_TYPE,
  usageReportClaims,
  usageSigningKey,
  type UsageReportClaims,
} from "../../src/edge/UsageReport.js";
import { emptyUsage } from "../../src/edge/UsageTally.js";
import { repositoryPath } from "../support/RepositoryRoot.js";
import {
  USAGE_REPORT_VECTOR,
  usageReportVector,
  vectorKey,
  type UsageReportVector,
} from "../support/UsageReportVector.js";

const september = usagePeriod("2026-09") as UsagePeriod;

async function sign(payload: unknown, header: Record<string, unknown>): Promise<string> {
  return await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: "EdDSA", ...header })
    .sign(vectorKey().privateKey);
}

function claims(overrides: Partial<UsageReportClaims> = {}): UsageReportClaims {
  return {
    ...usageReportClaims({
      installationId: "synthetic-installation-1",
      orgId: "00000000-0000-4000-8000-000000000002",
      period: september,
      usage: emptyUsage(),
      stream: EVIDENCE_STREAM,
      now: Date.parse("2026-10-01T01:00:00.000Z"),
    }),
    ...overrides,
  };
}

describe("usage report claims", () => {
  it("states the period's bounds, the counts, the range and the bundles", () => {
    const built = usageReportClaims({
      installationId: "synthetic-installation-1",
      orgId: "org-synthetic",
      period: september,
      usage: {
        ...emptyUsage(),
        counts: {
          by_mode: { ENFORCEMENT: 1, SHADOW: 0 },
          by_verdict: { ALLOW: 1, ESCALATE: 0, BLOCK: 0 },
          total: 1,
        },
        first_seq: 4,
        first_hash: `sha256:${"1".repeat(64)}`,
        last_seq: 4,
        last_hash: `sha256:${"1".repeat(64)}`,
        bundles: ["jti-1"],
      },
      stream: EVIDENCE_STREAM,
      now: 1_790_000_000_999,
      jti: "synthetic-report-1",
    });
    expect(built).toEqual({
      iss: "synthetic-installation-1",
      aud: "org-synthetic",
      iat: 1_790_000_000,
      jti: "synthetic-report-1",
      period: "2026-09",
      period_start: "2026-09-01T00:00:00.000Z",
      period_end: "2026-10-01T00:00:00.000Z",
      counts: {
        by_mode: { ENFORCEMENT: 1, SHADOW: 0 },
        by_verdict: { ALLOW: 1, ESCALATE: 0, BLOCK: 0 },
        total: 1,
      },
      delegated: 0,
      chain: {
        stream: EVIDENCE_STREAM,
        first_seq: 4,
        last_seq: 4,
        first_hash: `sha256:${"1".repeat(64)}`,
        last_hash: `sha256:${"1".repeat(64)}`,
      },
      bundles: ["jti-1"],
    });
    expect(consistentClaims(built)).toBe(true);
    expect(claims().jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(claims().jti).not.toBe(claims().jti);
  });

  it("is consistent only when bounds, sums, delegation and range agree", () => {
    expect(consistentClaims(claims())).toBe(true);
    const counted = {
      counts: {
        by_mode: { ENFORCEMENT: 1, SHADOW: 1 },
        by_verdict: { ALLOW: 1, ESCALATE: 1, BLOCK: 0 },
        total: 2,
      },
      delegated: 1,
      chain: {
        stream: EVIDENCE_STREAM,
        first_seq: 1,
        last_seq: 2,
        first_hash: `sha256:${"1".repeat(64)}`,
        last_hash: `sha256:${"2".repeat(64)}`,
      },
    };
    expect(consistentClaims(claims(counted))).toBe(true);
    expect(consistentClaims(claims({ ...counted, delegated: 2 }))).toBe(true);
    for (const broken of [
      { period_start: "2026-09-01T00:00:00.001Z" },
      { period_end: "2026-10-01T00:00:01.000Z" },
      { ...counted, delegated: 3 },
      { ...counted, counts: { ...counted.counts, total: 3 } },
      { ...counted, counts: { ...counted.counts, by_mode: { ENFORCEMENT: 2, SHADOW: 1 } } },
      {
        ...counted,
        counts: { ...counted.counts, by_verdict: { ALLOW: 1, ESCALATE: 1, BLOCK: 1 } },
      },
      { ...counted, chain: { ...counted.chain, first_seq: null } },
      { ...counted, chain: { ...counted.chain, last_seq: null } },
      { ...counted, chain: { ...counted.chain, first_hash: null } },
      { ...counted, chain: { ...counted.chain, last_hash: null } },
      { chain: { ...counted.chain } },
    ] as Partial<UsageReportClaims>[]) {
      expect(consistentClaims(claims(broken)), JSON.stringify(broken)).toBe(false);
    }
  });

  it("carries the recount's view of the claims", () => {
    const vectorClaims = claims();
    expect(claimedUsage(vectorClaims)).toEqual({ ...emptyUsage(), stream: EVIDENCE_STREAM });
  });
});

describe("usage-report keys and signatures", () => {
  it("names a key by its RFC 7638 thumbprint unless a kid is configured", async () => {
    const key = vectorKey(null);
    expect(key.kid).toBe(await calculateJwkThumbprint(key.publicJwk));
    expect(key.publicJwk).toEqual({
      kty: "OKP",
      crv: "Ed25519",
      x: expect.stringMatching(/^[\w-]{43}$/),
    });
    expect(vectorKey("usage-key-7").kid).toBe("usage-key-7");
  });

  it("refuses a key that is not Ed25519", () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    expect(() => usageSigningKey(pem)).toThrow("USAGE_KEY_NOT_ED25519");
  });

  it("signs with EdDSA under the usage report's type and the key's kid, and reads it back", async () => {
    const key = vectorKey();
    const token = await signUsageReport(claims(), key);
    expect(decodeProtectedHeader(token)).toEqual({
      alg: "EdDSA",
      typ: USAGE_REPORT_TYPE,
      kid: "vector-edge-usage-report-1",
    });
    expect(USAGE_REPORT_TYPE).toBe("decionis-edge-usage+jwt");
    await expect(readUsageReport(token, key.publicJwk)).resolves.toEqual({
      ok: true,
      kid: "vector-edge-usage-report-1",
      claims: claims({ jti: (await readClaims(token)).jti }),
    });
  });

  it("refuses another key's signature, another type, a malformed token or inconsistent claims", async () => {
    const other = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }) as Record<
      string,
      unknown
    >;
    const token = await signUsageReport(claims(), vectorKey());
    const jwk = vectorKey().publicJwk;
    await expect(readUsageReport(token, other)).resolves.toEqual({
      ok: false,
      code: "USAGE_REPORT_SIGNATURE_INVALID",
    });
    await expect(readUsageReport("not-a-jws", jwk)).resolves.toEqual({
      ok: false,
      code: "USAGE_REPORT_MALFORMED",
    });
    for (const header of [
      { typ: "JWT", kid: "k" },
      { typ: USAGE_REPORT_TYPE },
      { typ: USAGE_REPORT_TYPE, kid: 7 },
    ]) {
      await expect(readUsageReport(await sign(claims(), header), jwk)).resolves.toEqual({
        ok: false,
        code: "USAGE_REPORT_MALFORMED",
      });
    }
    const rs = await new CompactSign(new TextEncoder().encode("{}"))
      .setProtectedHeader({ alg: "HS256", typ: USAGE_REPORT_TYPE, kid: "k" })
      .sign(new Uint8Array(32));
    await expect(readUsageReport(rs, jwk)).resolves.toMatchObject({
      code: "USAGE_REPORT_MALFORMED",
    });
    const header = { typ: USAGE_REPORT_TYPE, kid: "k" };
    const notJson = await new CompactSign(new TextEncoder().encode("{"))
      .setProtectedHeader({ alg: "EdDSA", ...header })
      .sign(vectorKey().privateKey);
    await expect(readUsageReport(notJson, jwk)).resolves.toEqual({
      ok: false,
      code: "USAGE_REPORT_MALFORMED",
    });
    for (const payload of [{ ...claims(), extra: 1 }, claims({ delegated: 1 })]) {
      await expect(readUsageReport(await sign(payload, header), jwk)).resolves.toEqual({
        ok: false,
        code: "USAGE_REPORT_INCONSISTENT",
      });
    }
  });
});

async function readClaims(token: string): Promise<UsageReportClaims> {
  const payload = token.split(".")[1] ?? "";
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as UsageReportClaims;
}

describe("the cross-check vector", () => {
  it("is the report this host signs for its evidence, byte for byte", async () => {
    const built = await usageReportVector();
    const path = repositoryPath(...USAGE_REPORT_VECTOR);
    if (process.env["AGENTSAFE_WRITE_VECTORS"] === "1") {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, `${JSON.stringify(built, null, 2)}\n`);
    }
    const committed = JSON.parse(readFileSync(path, "utf8")) as UsageReportVector;
    expect(committed).toEqual(JSON.parse(JSON.stringify(built)));
  });

  it("verifies against its own public key and recounts from its own evidence", async () => {
    const vector = JSON.parse(
      readFileSync(repositoryPath(...USAGE_REPORT_VECTOR), "utf8"),
    ) as UsageReportVector;
    const read = await readUsageReport(vector.report, vector.key.public_jwk);
    expect(read).toEqual({ ok: true, kid: vector.key.kid, claims: vector.claims });
    expect(vector.claims).toMatchObject({
      counts: {
        by_mode: { ENFORCEMENT: 3, SHADOW: 1 },
        by_verdict: { ALLOW: 2, ESCALATE: 1, BLOCK: 1 },
        total: 4,
      },
      delegated: 1,
      bundles: ["jti-1", "jti-2"],
    });
    const recount = verifyUsage(vector.evidence, claimedUsage(vector.claims), september);
    expect(recount.ok).toBe(true);
  });
});
