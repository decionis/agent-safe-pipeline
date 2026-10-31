/**
 * The report of an acceptance run, `agent-safe.acceptance/1`: what the
 * gateway observed of the writes a plan named, what the agent's zone reported
 * of its own routes, the fingerprint both were observed under, and the fixed
 * list of what no run establishes
 * ([ADR 0009](../../../../docs/architecture/decisions/0009-acceptance-run-on-named-targets.md)).
 *
 * The gateway signs it with a key of its own, which signs nothing else. The
 * signature carries the gateway's word for what the gateway observed, and only
 * the zone's word for what the zone reported: every case says which. A report
 * establishes the named writes, targets and window, under one fingerprint;
 * it does not carry over to other adapters, routes or environments.
 */
import { createHash, createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { JsonObjectSchema, Rfc8785, type JsonValue } from "@decionis/agent-safe-pipeline";
import { z } from "zod";
import { zoneFindingsSchema, type ZoneFindings } from "./ZoneProbes.js";

export const ACCEPTANCE_REPORT_VERSION = "agent-safe.acceptance/1";

/** The JWS `typ` of an acceptance report. */
export const ACCEPTANCE_REPORT_TYPE = "agent-safe-acceptance+jwt";

/** What a report says of its own reach, in every report. */
export const ACCEPTANCE_SCOPE =
  "This report establishes the named writes, targets, origins and window, under the fingerprint it carries, and nothing else. It does not carry over to other adapters, routes or environments.";

/** What no run establishes, and why, in every report. */
export const STATED_NOT_RUN = [
  {
    case: "grants_after_issuance",
    reason:
      "The agent's zone never holds a grant, so it has none to alter, replay or carry to another boundary; the zone's credential scan is what reports what it does hold. The authority's and the provider's refusals of an altered, replayed or misdirected grant are established by the build: the Changed Conditions Test, the Compromised Principal Test and the provider conformance vectors.",
  },
  {
    case: "lost_outcome_and_restart",
    reason: "Established by the build's trusted-executor proof, not by a run.",
  },
  {
    case: "downstream_consequences",
    reason: "No record establishes what a confirmed effect leads to.",
  },
  {
    case: "executor_host_integrity",
    reason: "No record establishes that the host running the boundary is the one deployed.",
  },
  {
    case: "node_and_kernel_isolation",
    reason: "No record establishes the isolation the platform under the boundary provides.",
  },
] as const;

const identifier = z.string().min(1).max(200);
const sha256 = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const codes = z.array(z.string().min(1).max(120)).max(32);
const status = z.number().int().min(100).max(599).nullable();
const verdict = z.enum(["ALLOW", "BLOCK", "ESCALATE"]).nullable();
const method = z.enum(["POST", "PUT", "PATCH", "DELETE"]);
const target = z.string().min(1).max(2_000);

/** One chained line the gateway wrote for a case, by its place in its stream. */
const LineSchema = z.strictObject({
  stream: identifier,
  seq: z.number().int().positive(),
  hash: sha256,
  event: identifier,
});

/** What the gateway did with one request it governed, as it reported it. */
const GovernedSchema = z.strictObject({
  /** The upstream's answer, when the write reached it. */
  upstream_status: status,
  state: z.string().min(1).max(40).nullable(),
  verdict,
  execution: z.string().min(1).max(40).nullable(),
  intent_id: identifier.nullable(),
  decision_id: identifier.nullable(),
  dossier_id: identifier.nullable(),
  reason_codes: codes,
});

const PermittedSchema = z.strictObject({
  name: identifier,
  method,
  path: target,
  action: identifier.nullable(),
  observed_by: z.literal("GATEWAY"),
  ...GovernedSchema.shape,
  effect: z
    .strictObject({
      confirmation: z.enum(["CONFIRMED", "UNKNOWN", "PENDING"]),
      reason_codes: codes,
    })
    .nullable(),
  lines: z.array(LineSchema).max(16),
  passed: z.boolean(),
  failure: z.string().min(1).max(80).nullable(),
});

const ObservationSchema = z.strictObject({
  outcome: z.enum(["UNCHANGED", "CHANGED", "UNREADABLE"]),
  version_before: z.string().max(300).nullable(),
  version_after: z.string().max(300).nullable(),
  read_before_at: z.string().max(40).nullable(),
  read_after_at: z.string().max(40).nullable(),
});

const ProhibitedSchema = z.strictObject({
  name: identifier,
  method,
  path: target,
  action: identifier.nullable(),
  canary: z.string().min(1).max(300),
  observed_by: z.literal("GATEWAY"),
  shadow: z.strictObject({
    verdict,
    reason_codes: codes,
    decision_id: identifier.nullable(),
    dossier_id: identifier.nullable(),
  }),
  sent: z.boolean(),
  ...GovernedSchema.shape,
  observation: ObservationSchema.nullable(),
  lines: z.array(LineSchema).max(16),
  passed: z.boolean(),
  failure: z.string().min(1).max(80).nullable(),
});

const OutageSchema = z.strictObject({
  name: identifier,
  method,
  path: target,
  action: identifier.nullable(),
  observed_by: z.literal("GATEWAY"),
  /** Why the case did not run, or null when it ran. */
  skipped: z.enum(["FAIL_OPEN"]).nullable(),
  status,
  execution: z.string().min(1).max(40).nullable(),
  reason_codes: codes,
  /** Writes that reached the second gateway's recording upstream: none, to pass. */
  upstream_writes: z.number().int().nonnegative(),
  passed: z.boolean(),
  failure: z.string().min(1).max(80).nullable(),
});

const RouteSchema = z.strictObject({
  methods: z.array(z.string().min(1).max(10)).min(1).max(8),
  path: target,
  action: identifier.nullable(),
});

/** Which of the gateway's routes the authority decides, and which it does not, by kind. */
export const CoverageSchema = z.strictObject({
  governed: z
    .array(
      RouteSchema.extend({
        /** Whether a write here is read at its target, so its effect and a refusal can be observed. */
        target_read: z.boolean(),
      }),
    )
    .max(512),
  ungoverned: z
    .array(RouteSchema.extend({ kind: z.enum(["SHADOW", "FAIL_OPEN", "PASSTHROUGH"]) }))
    .max(512),
  /** Routes the gateway refuses outright, with nothing asked. */
  refused: z.array(RouteSchema).max(512),
  /** What happens to a read: relayed unchecked, checked against the profile, or refused unless known. */
  reads: z.enum(["PASSTHROUGH", "CHECK", "REFUSE_UNKNOWN"]),
});

export type Coverage = z.infer<typeof CoverageSchema>;

export const AcceptanceReportSchema = z.strictObject({
  report: z.literal(ACCEPTANCE_REPORT_VERSION),
  run_id: identifier,
  boundary_id: identifier,
  issued_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  plan_digest: sha256,
  fingerprint: z.strictObject({ digest: sha256, document: JsonObjectSchema }),
  coverage: CoverageSchema,
  permitted: z.array(PermittedSchema).max(16),
  prohibited: z.array(ProhibitedSchema).max(16),
  outage: z.array(OutageSchema).max(32),
  zone: zoneFindingsSchema,
  stated: z
    .array(z.strictObject({ case: identifier, reason: z.string().min(1).max(1_000) }))
    .max(16),
  verdict: z.enum(["ACCEPTED", "NOT_ACCEPTED"]),
  failures: z
    .array(z.strictObject({ case: identifier, name: identifier, code: identifier }))
    .max(128),
  scope: z.literal(ACCEPTANCE_SCOPE),
});

export type AcceptanceReport = z.infer<typeof AcceptanceReportSchema>;
export type PermittedCase = z.infer<typeof PermittedSchema>;
export type ProhibitedCase = z.infer<typeof ProhibitedSchema>;
export type OutageCase = z.infer<typeof OutageSchema>;
export type CaseLine = z.infer<typeof LineSchema>;
export type GovernedOutcome = z.infer<typeof GovernedSchema>;
export type TargetObservation = z.infer<typeof ObservationSchema>;

/**
 * Whether a permitted write went as the plan says it should: allowed,
 * forwarded once, answered `2xx`, and not read back as something else. A
 * write whose effect was not read passes as `PENDING`, which says so.
 */
export function judgePermitted(
  outcome: GovernedOutcome,
  effect: { readonly confirmation: "CONFIRMED" | "UNKNOWN" | "PENDING" } | null,
): { readonly passed: boolean; readonly failure: string | null } {
  if (outcome.verdict !== "ALLOW") {
    return { passed: false, failure: outcome.verdict === null ? "NOT_DECIDED" : "NOT_ALLOWED" };
  }
  if (outcome.execution !== "FORWARDED") return { passed: false, failure: "NOT_FORWARDED" };
  const status = outcome.upstream_status ?? 0;
  if (status < 200 || status > 299) {
    return { passed: false, failure: "UPSTREAM_REFUSED" };
  }
  if (effect?.confirmation === "UNKNOWN") return { passed: false, failure: "EFFECT_MISMATCH" };
  return { passed: true, failure: null };
}

/**
 * Whether a prohibited write was refused and its target read unchanged
 * after: decided BLOCK or ESCALATE in shadow, sent, refused in enforcement,
 * and observed `UNCHANGED`. Anything less fails, and says how.
 */
export function judgeProhibited(input: {
  readonly shadow: ProhibitedCase["shadow"]["verdict"];
  readonly sent: boolean;
  readonly outcome: GovernedOutcome;
  readonly observation: TargetObservation | null;
}): { readonly passed: boolean; readonly failure: string | null } {
  if (input.shadow === null) return { passed: false, failure: "SHADOW_UNDECIDED" };
  if (input.shadow === "ALLOW") return { passed: false, failure: "SHADOW_ALLOWED" };
  if (!input.sent) return { passed: false, failure: "NOT_SENT" };
  if (input.outcome.execution === "FORWARDED" || input.outcome.verdict === "ALLOW") {
    return { passed: false, failure: "FORWARDED" };
  }
  if (input.observation === null) return { passed: false, failure: "TARGET_NOT_OBSERVED" };
  if (input.observation.outcome === "CHANGED") {
    return { passed: false, failure: "TARGET_CHANGED" };
  }
  if (input.observation.outcome === "UNREADABLE") {
    return { passed: false, failure: "TARGET_UNREADABLE" };
  }
  return { passed: true, failure: null };
}

/** Whether the second gateway refused with the authority down and sent nothing on. */
export function judgeOutage(input: {
  readonly status: number | null;
  readonly execution: string | null;
  readonly upstreamWrites: number;
}): { readonly passed: boolean; readonly failure: string | null } {
  if (input.upstreamWrites > 0) return { passed: false, failure: "UPSTREAM_WRITTEN" };
  if (input.status !== 503 || input.execution !== "NOT_FORWARDED") {
    return { passed: false, failure: "NOT_FAIL_CLOSED" };
  }
  return { passed: true, failure: null };
}

/**
 * The zone's findings that fail a run, by case and name. An origin passes
 * only `CONTAINED`; a provider only when it refused both writes; the metadata
 * endpoint, when probed, only when it did not answer. Reachable MCP servers
 * and the credentials found are listed, not judged: what the zone may hold is
 * the operator's to say.
 */
export function zoneFailures(
  zone: ZoneFindings,
): readonly { readonly case: string; readonly name: string; readonly code: string }[] {
  const failures: { case: string; name: string; code: string }[] = [];
  for (const origin of zone.origins) {
    if (origin.verdict !== "CONTAINED") {
      failures.push({ case: "origin", name: origin.name, code: origin.verdict });
    }
  }
  for (const provider of zone.providers) {
    if (provider.verdict !== "REFUSED") {
      failures.push({ case: "provider", name: provider.name, code: provider.verdict });
    }
  }
  if (zone.metadata !== null && zone.metadata.verdict === "REACHABLE") {
    failures.push({ case: "metadata", name: "metadata", code: "REACHABLE" });
  }
  return failures;
}

/** The run's verdict: accepted only when every case that ran passed. */
export function acceptanceVerdict(cases: {
  readonly permitted: readonly PermittedCase[];
  readonly prohibited: readonly ProhibitedCase[];
  readonly outage: readonly OutageCase[];
  readonly zone: ZoneFindings;
}): Pick<AcceptanceReport, "verdict" | "failures"> {
  const failures = [
    ...cases.permitted.map((item) => ({ case: "permitted", item })),
    ...cases.prohibited.map((item) => ({ case: "prohibited", item })),
    ...cases.outage.map((item) => ({ case: "outage", item })),
  ]
    .filter(({ item }) => !item.passed)
    .map(({ case: kind, item }) => ({
      case: kind,
      name: item.name,
      code: item.failure ?? "FAILED",
    }));
  failures.push(...zoneFailures(cases.zone));
  return { verdict: failures.length === 0 ? "ACCEPTED" : "NOT_ACCEPTED", failures };
}

/** `sha256:` over a value's RFC 8785 form. */
export function canonicalDigest(value: JsonValue): string {
  return `sha256:${createHash("sha256").update(Rfc8785.stringify(value)).digest("hex")}`;
}

/** `sha256:` over the report as signed, the compact JWS's own bytes. */
export function reportDigest(token: string): string {
  return `sha256:${createHash("sha256").update(token).digest("hex")}`;
}

/** A gateway's acceptance key: Ed25519, with the `kid` reports carry. */
export interface AcceptanceSigningKey {
  readonly kid: string;
  readonly privateKey: KeyObject;
  readonly publicJwk: { readonly kty: "OKP"; readonly crv: "Ed25519"; readonly x: string };
}

/**
 * Reads a PKCS#8 PEM Ed25519 key. The `kid` is the one configured, or the
 * key's RFC 7638 thumbprint, so the same key always has the same id.
 */
export function acceptanceSigningKey(pem: string, kid?: string | null): AcceptanceSigningKey {
  const privateKey = createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("ACCEPTANCE_KEY_NOT_ED25519");
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  const publicJwk = { kty: "OKP", crv: "Ed25519", x: String(jwk.x) } as const;
  const thumbprint = createHash("sha256")
    .update(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x }))
    .digest("base64url");
  return { kid: kid ?? thumbprint, privateKey, publicJwk };
}

/** The compact JWS: `alg` EdDSA, `typ` the acceptance report's, `kid` the key's. */
export async function signAcceptanceReport(
  report: AcceptanceReport,
  key: AcceptanceSigningKey,
): Promise<string> {
  const { CompactSign } = await import("jose");
  return await new CompactSign(new TextEncoder().encode(JSON.stringify(report)))
    .setProtectedHeader({ alg: "EdDSA", typ: ACCEPTANCE_REPORT_TYPE, kid: key.kid })
    .sign(key.privateKey);
}

export type AcceptanceReportRead =
  | { readonly ok: true; readonly kid: string; readonly report: AcceptanceReport }
  | { readonly ok: false; readonly code: string };

/**
 * Checks a report's signature against a public key, its shape against the
 * schema, and that its fingerprint digest is the digest of the document it
 * carries. It does not ask whether the deployment is still the one tested:
 * that is a comparison with a running gateway, made apart from this.
 */
export async function readAcceptanceReport(
  token: string,
  publicJwk: Readonly<Record<string, unknown>>,
): Promise<AcceptanceReportRead> {
  const { compactVerify, decodeProtectedHeader, importJWK } = await import("jose");
  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return { ok: false, code: "ACCEPTANCE_REPORT_MALFORMED" };
  }
  if (
    header.alg !== "EdDSA" ||
    header.typ !== ACCEPTANCE_REPORT_TYPE ||
    typeof header.kid !== "string"
  ) {
    return { ok: false, code: "ACCEPTANCE_REPORT_MALFORMED" };
  }
  let payload: Uint8Array;
  try {
    // The header named EdDSA above; the key is imported as nothing else.
    const key = await importJWK(publicJwk, "EdDSA");
    payload = (await compactVerify(token, key)).payload;
  } catch {
    return { ok: false, code: "ACCEPTANCE_REPORT_SIGNATURE_INVALID" };
  }
  let parsed;
  try {
    parsed = AcceptanceReportSchema.safeParse(JSON.parse(new TextDecoder().decode(payload)));
  } catch {
    return { ok: false, code: "ACCEPTANCE_REPORT_MALFORMED" };
  }
  if (!parsed.success) return { ok: false, code: "ACCEPTANCE_REPORT_MALFORMED" };
  const report = parsed.data;
  if (canonicalDigest(report.fingerprint.document) !== report.fingerprint.digest) {
    return { ok: false, code: "ACCEPTANCE_REPORT_INCONSISTENT" };
  }
  const judged = acceptanceVerdict(report);
  if (judged.verdict !== report.verdict) {
    return { ok: false, code: "ACCEPTANCE_REPORT_INCONSISTENT" };
  }
  return { ok: true, kid: header.kid, report };
}

export type Currency =
  | { readonly state: "CURRENT" }
  | { readonly state: "EXPIRED"; readonly expired_at: string }
  | { readonly state: "STALE"; readonly changed: readonly string[] };

/**
 * Whether a report still describes a deployment: `EXPIRED` once its date
 * has passed, `STALE` with the fingerprint fields that differ when the
 * deployment is no longer the one tested, `CURRENT` otherwise. It changes
 * nothing anywhere: a stale report is reported, never enforced.
 */
export function currency(
  report: AcceptanceReport,
  running: { readonly digest: string; readonly document: object },
  now: number,
  changed: (before: object, after: object) => readonly string[],
): Currency {
  if (Date.parse(report.expires_at) <= now) {
    return { state: "EXPIRED", expired_at: report.expires_at };
  }
  if (running.digest !== report.fingerprint.digest) {
    return { state: "STALE", changed: changed(report.fingerprint.document, running.document) };
  }
  return { state: "CURRENT" };
}
