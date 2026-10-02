import { createHash, createPrivateKey } from "node:crypto";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { countUsage } from "../../src/edge/UsageCount.js";
import { usagePeriod, type UsagePeriod } from "../../src/edge/UsagePeriod.js";
import {
  signUsageReport,
  usageReportClaims,
  usageSigningKey,
  type UsageReportClaims,
  type UsageSigningKey,
} from "../../src/edge/UsageReport.js";
import { decision, EvidenceLog, lifecycle } from "./EvidenceLog.js";

/** Where the vector lives, relative to the repository root. */
export const USAGE_REPORT_VECTOR = ["conformance", "edge", "usage-report-v1.json"] as const;

/** The vector's key: Ed25519 from a seed anyone can recompute, and good for nothing else. */
export const VECTOR_SEED_TEXT = "agentsafe.edge.usage-report.vector.v1";
export const VECTOR_KID = "vector-edge-usage-report-1";
export const VECTOR_ORG = "00000000-0000-4000-8000-000000000002";
export const VECTOR_INSTALLATION = "synthetic-installation-1";

export function vectorKey(kid: string | null = VECTOR_KID): UsageSigningKey {
  const seed = createHash("sha256").update(VECTOR_SEED_TEXT, "utf8").digest();
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const pem = createPrivateKey({ key: der, format: "der", type: "pkcs8" })
    .export({ format: "pem", type: "pkcs8" })
    .toString();
  return usageSigningKey(pem, kid);
}

/** The PKCS#8 PEM of the vector key, for the CLI tests that read a key file. */
export function vectorKeyPem(): string {
  return vectorKey().privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}

export interface UsageReportVector {
  readonly description: string;
  readonly key: {
    readonly derivation: string;
    readonly kid: string;
    readonly public_jwk: { readonly kty: "OKP"; readonly crv: "Ed25519"; readonly x: string };
  };
  readonly period: string;
  /** The executor evidence lines the report was counted from, as collected. */
  readonly evidence: readonly string[];
  readonly claims: UsageReportClaims;
  /** The compact JWS Decionis ingests at `POST /v1/edge/usage-reports`. */
  readonly report: string;
}

/**
 * The cross-check vector: a September 2026 log with edge decisions in every
 * mode and verdict, one delegated, decisions just outside the month on both
 * sides, and lifecycle lines between; the report this host signs for it.
 * Every value is fixed, and Ed25519 is deterministic, so the vector is the
 * same bytes on every run.
 */
export async function usageReportVector(): Promise<UsageReportVector> {
  const log = new EvidenceLog().add(
    decision("2026-08-31T23:59:59.999Z", { intent_id: "synthetic-intent-0" }),
    lifecycle("2026-08-31T23:59:59.999Z"),
    decision("2026-09-01T00:00:00.000Z", { intent_id: "synthetic-intent-1" }),
    lifecycle("2026-09-01T00:00:00.100Z"),
    decision("2026-09-12T08:30:00.000Z", {
      intent_id: "synthetic-intent-2",
      verdict: "ESCALATE",
      delegated: true,
      reason_codes: ["POLICY_ESCALATE"],
    }),
    decision("2026-09-20T17:45:00.000Z", {
      intent_id: "synthetic-intent-3",
      verdict: "BLOCK",
      reason_codes: ["POLICY_BLOCK"],
      jti: "jti-2",
      bundle_id: "bundle-2",
    }),
    decision("2026-09-30T23:59:59.999Z", {
      intent_id: "synthetic-intent-4",
      mode: "SHADOW",
      jti: "jti-2",
      bundle_id: "bundle-2",
    }),
    decision("2026-10-01T00:00:00.000Z", { intent_id: "synthetic-intent-5", jti: "jti-2" }),
  );
  const period = usagePeriod("2026-09") as UsagePeriod;
  const usage = countUsage(log.lines, { stream: EVIDENCE_STREAM, period }).usage;
  const claims = usageReportClaims({
    installationId: VECTOR_INSTALLATION,
    orgId: VECTOR_ORG,
    period,
    usage,
    stream: EVIDENCE_STREAM,
    now: Date.parse("2026-10-01T01:00:00.000Z"),
    jti: "synthetic-usage-report-2026-09-1",
  });
  const key = vectorKey();
  return {
    description:
      "A usage report AgentSafe signs for September 2026, the evidence lines it was counted from, and the vector key's public half. Decionis ingestion verifies the report against the key (registered as a usage_report provider key with issuer synthetic-installation-1); `agentsafe edge verify-usage-report` recounts it from the evidence.",
    key: {
      derivation: `Ed25519 seed = SHA-256 of the UTF-8 string "${VECTOR_SEED_TEXT}"`,
      kid: key.kid,
      public_jwk: key.publicJwk,
    },
    period: "2026-09",
    evidence: log.lines,
    claims,
    report: await signUsageReport(claims, key),
  };
}
