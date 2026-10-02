import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  type KeyObject,
} from "node:crypto";
import { z } from "zod";
import { usagePeriod, type UsagePeriod } from "./UsagePeriod.js";
import type { PeriodUsage } from "./UsageTally.js";

/** The JWS `typ` of a usage report, as Decionis ingestion checks it. */
export const USAGE_REPORT_TYPE = "decionis-edge-usage+jwt";

const identifier = z.string().min(1).max(200);
const count = z.number().int().nonnegative();
const sha256 = z.string().regex(/^sha256:[0-9a-f]{64}$/);

/** The claims of a usage report (Edge evaluator phase 4, section 3). */
export const UsageReportClaimsSchema = z.strictObject({
  /** The installation: one executor's evidence chain. */
  iss: identifier,
  /** The Decionis organisation. */
  aud: identifier,
  iat: count,
  jti: identifier,
  period: z.string().regex(/^2\d{3}-(?:0[1-9]|1[0-2])$/),
  period_start: z.string().datetime(),
  period_end: z.string().datetime(),
  counts: z.strictObject({
    by_mode: z.strictObject({ ENFORCEMENT: count, SHADOW: count }),
    by_verdict: z.strictObject({ ALLOW: count, ESCALATE: count, BLOCK: count }),
    total: count,
  }),
  delegated: count,
  chain: z.strictObject({
    stream: identifier,
    first_seq: count.nullable(),
    last_seq: count.nullable(),
    first_hash: sha256.nullable(),
    last_hash: sha256.nullable(),
  }),
  bundles: z.array(identifier).max(10_000),
});

export type UsageReportClaims = z.infer<typeof UsageReportClaimsSchema>;

/** The usage report's claims for one period, as this installation counted it. */
export function usageReportClaims(input: {
  readonly installationId: string;
  readonly orgId: string;
  readonly period: UsagePeriod;
  readonly usage: PeriodUsage;
  readonly stream: string;
  readonly now: number;
  /** The report's id; a fresh UUID unless a fixed vector names one. */
  readonly jti?: string;
}): UsageReportClaims {
  const { usage } = input;
  return {
    iss: input.installationId,
    aud: input.orgId,
    iat: Math.floor(input.now / 1000),
    jti: input.jti ?? randomUUID(),
    period: input.period.period,
    period_start: new Date(input.period.start).toISOString(),
    period_end: new Date(input.period.end).toISOString(),
    counts: usage.counts,
    delegated: usage.delegated,
    chain: {
      stream: input.stream,
      first_seq: usage.first_seq,
      last_seq: usage.last_seq,
      first_hash: usage.first_hash,
      last_hash: usage.last_hash,
    },
    bundles: [...usage.bundles],
  };
}

/** The usage the claims state, in the tally's shape, for a recount to compare with. */
export function claimedUsage(claims: UsageReportClaims): PeriodUsage & { readonly stream: string } {
  return {
    counts: claims.counts,
    delegated: claims.delegated,
    first_seq: claims.chain.first_seq,
    first_hash: claims.chain.first_hash,
    last_seq: claims.chain.last_seq,
    last_hash: claims.chain.last_hash,
    bundles: claims.bundles,
    stream: claims.chain.stream,
  };
}

/**
 * Whether the claims agree with themselves: the period's bounds are the
 * period's, each breakdown sums to the total, no more were delegated than
 * decided, and the range is named exactly when something was counted.
 */
export function consistentClaims(claims: UsageReportClaims): boolean {
  const period = usagePeriod(claims.period) as UsagePeriod;
  const { by_mode, by_verdict, total } = claims.counts;
  const range = [
    claims.chain.first_seq,
    claims.chain.last_seq,
    claims.chain.first_hash,
    claims.chain.last_hash,
  ];
  return (
    Date.parse(claims.period_start) === period.start &&
    Date.parse(claims.period_end) === period.end &&
    by_mode.ENFORCEMENT + by_mode.SHADOW === total &&
    by_verdict.ALLOW + by_verdict.ESCALATE + by_verdict.BLOCK === total &&
    claims.delegated <= total &&
    range.every((value) => (value === null) === (total === 0))
  );
}

/** An installation's usage-report key: Ed25519, with the `kid` it is registered under. */
export interface UsageSigningKey {
  readonly kid: string;
  readonly privateKey: KeyObject;
  /** The public half, as `POST /v1/execution/provider-keys` takes it. */
  readonly publicJwk: { readonly kty: "OKP"; readonly crv: "Ed25519"; readonly x: string };
}

/**
 * Reads a PKCS#8 PEM Ed25519 key. The `kid` is the one configured, or the
 * key's RFC 7638 thumbprint, so the same key always has the same id.
 */
export function usageSigningKey(pem: string, kid?: string | null): UsageSigningKey {
  const privateKey = createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("USAGE_KEY_NOT_ED25519");
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  const publicJwk = { kty: "OKP", crv: "Ed25519", x: String(jwk.x) } as const;
  const thumbprint = createHash("sha256")
    .update(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x }))
    .digest("base64url");
  return { kid: kid ?? thumbprint, privateKey, publicJwk };
}

/** The compact JWS Decionis ingests: `alg` EdDSA, `typ` the usage report's, `kid` the key's. */
export async function signUsageReport(
  claims: UsageReportClaims,
  key: UsageSigningKey,
): Promise<string> {
  const { CompactSign } = await import("jose");
  return await new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader({ alg: "EdDSA", typ: USAGE_REPORT_TYPE, kid: key.kid })
    .sign(key.privateKey);
}

export type UsageReportRead =
  | { readonly ok: true; readonly kid: string; readonly claims: UsageReportClaims }
  | { readonly ok: false; readonly code: string };

/**
 * Checks a usage report's signature against a public key and its claims
 * against the schema and themselves. It does not recount: `verifyUsage`
 * does that against the chain.
 */
export async function readUsageReport(
  token: string,
  publicJwk: Readonly<Record<string, unknown>>,
): Promise<UsageReportRead> {
  const { compactVerify, decodeProtectedHeader, importJWK } = await import("jose");
  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return { ok: false, code: "USAGE_REPORT_MALFORMED" };
  }
  if (
    header.alg !== "EdDSA" ||
    header.typ !== USAGE_REPORT_TYPE ||
    typeof header.kid !== "string"
  ) {
    return { ok: false, code: "USAGE_REPORT_MALFORMED" };
  }
  let payload: Uint8Array;
  try {
    const key = await importJWK({ ...publicJwk, alg: "EdDSA" }, "EdDSA");
    payload = (await compactVerify(token, key, { algorithms: ["EdDSA"] })).payload;
  } catch {
    return { ok: false, code: "USAGE_REPORT_SIGNATURE_INVALID" };
  }
  let parsed;
  try {
    parsed = UsageReportClaimsSchema.safeParse(JSON.parse(new TextDecoder().decode(payload)));
  } catch {
    return { ok: false, code: "USAGE_REPORT_MALFORMED" };
  }
  if (!parsed.success || !consistentClaims(parsed.data)) {
    return { ok: false, code: "USAGE_REPORT_INCONSISTENT" };
  }
  return { ok: true, kid: header.kid, claims: parsed.data };
}
