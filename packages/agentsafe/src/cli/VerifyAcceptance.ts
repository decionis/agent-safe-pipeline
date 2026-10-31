/**
 * `agentsafe verify acceptance <report> --key <file> [--current --gateway <url>] [--json]`:
 * checks an acceptance report offline, and, asked to, whether the deployment
 * it was made under is still the one running
 * ([ADR 0009](../../../../docs/architecture/decisions/0009-acceptance-run-on-named-targets.md)).
 *
 * The key is the verifier's, pinned from `agentsafe identity` on the gateway:
 * a report checked against a key it brought along proves nothing. Whether a
 * report is current changes nothing anywhere; it is reported, never enforced.
 * Exit `0`: verified, accepted, unexpired and, with `--current`, current.
 * Exit `1`: it did not verify, was not accepted, has expired or is stale.
 * Exit `2`: it could not be checked (an argument, a file, or no gateway).
 */
import { withoutTrailingSlashes } from "../acceptance/AcceptancePlan.js";
import {
  currency,
  readAcceptanceReport,
  type AcceptanceReport,
  type Currency,
} from "../acceptance/AcceptanceReport.js";
import {
  changedFields,
  type DeploymentFingerprintDocument,
} from "../posture/DeploymentFingerprint.js";
import { GATEWAY_PREFIX } from "../gateway/Gateway.js";
import { ArgumentError, parseArguments } from "./Arguments.js";
import type { CliProcess } from "./CliProcess.js";
import { readStatus } from "./Status.js";

export const VERIFY_ACCEPTANCE_ARGUMENTS = {
  valued: ["key", "gateway"],
  flags: ["current", "json"],
} as const;

export interface AcceptanceVerification {
  readonly ok: boolean;
  /** Why it is not ok, as a code; null when it is. */
  readonly code: string | null;
  readonly kid: string | null;
  readonly verdict: AcceptanceReport["verdict"] | null;
  readonly failures: AcceptanceReport["failures"];
  readonly issued_at: string | null;
  readonly expires_at: string | null;
  readonly fingerprint: string | null;
  /**
   * `EXPIRED` once the date has passed; with a running gateway's fingerprint,
   * `CURRENT` or `STALE` too; null when unexpired and compared with nothing.
   */
  readonly currency: Currency | null;
}

/**
 * The public key in a file: a bare Ed25519 JWK, or the JSON `agentsafe
 * identity --json` prints, whose `acceptance.public_jwk` it is. Null when the
 * file holds neither.
 */
export function publicKeyOf(text: string): Readonly<Record<string, unknown>> | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  const record = (candidate: unknown): Record<string, unknown> | null =>
    typeof candidate === "object" && candidate !== null && !Array.isArray(candidate)
      ? (candidate as Record<string, unknown>)
      : null;
  const outer = record(value);
  const key = record(record(outer?.["acceptance"])?.["public_jwk"]) ?? outer;
  return key?.["kty"] === "OKP" && key["crv"] === "Ed25519" && typeof key["x"] === "string"
    ? key
    : null;
}

/** A report's standing in one line. */
export function describeVerification(result: AcceptanceVerification): string {
  if (result.verdict === null) return `NOT VERIFIED (${result.code ?? "UNKNOWN"})`;
  const standing =
    result.currency === null
      ? ""
      : result.currency.state === "STALE"
        ? `, STALE: ${result.currency.changed.join(", ") || "fingerprint differs"}`
        : `, ${result.currency.state}`;
  return `${result.verdict}${standing} (expires ${result.expires_at ?? "?"})`;
}

/** Checks a report's signature, shape and verdict, then its expiry and, given one, a running fingerprint. */
export async function verifyAcceptance(
  token: string,
  publicJwk: Readonly<Record<string, unknown>>,
  now: number,
  running: { readonly digest: string; readonly document: DeploymentFingerprintDocument } | null,
): Promise<AcceptanceVerification> {
  const read = await readAcceptanceReport(token.trim(), publicJwk);
  if (!read.ok) {
    return {
      ok: false,
      code: read.code,
      kid: null,
      verdict: null,
      failures: [],
      issued_at: null,
      expires_at: null,
      fingerprint: null,
      currency: null,
    };
  }
  const { report } = read;
  // Without a running gateway to compare with, only the date is checked: a
  // report is never "current" against itself.
  const judged = currency(report, running ?? report.fingerprint, now, (before, after) =>
    changedFields(before as DeploymentFingerprintDocument, after as DeploymentFingerprintDocument),
  );
  const standing = running === null && judged.state === "CURRENT" ? null : judged;
  const code =
    report.verdict !== "ACCEPTED"
      ? "ACCEPTANCE_NOT_ACCEPTED"
      : standing?.state === "EXPIRED"
        ? "ACCEPTANCE_EXPIRED"
        : standing?.state === "STALE"
          ? "ACCEPTANCE_STALE"
          : null;
  return {
    ok: code === null,
    code,
    kid: read.kid,
    verdict: report.verdict,
    failures: report.failures,
    issued_at: report.issued_at,
    expires_at: report.expires_at,
    fingerprint: report.fingerprint.digest,
    currency: standing,
  };
}

export async function runVerifyAcceptance(io: CliProcess, argv: readonly string[]): Promise<void> {
  const refuse = (event: string, detail?: string): void => {
    io.stderr(`${JSON.stringify(detail === undefined ? { event } : { event, detail })}\n`);
    io.exit(2);
  };
  let parsed;
  try {
    parsed = parseArguments(argv, VERIFY_ACCEPTANCE_ARGUMENTS);
  } catch (error) {
    if (!(error instanceof ArgumentError)) throw error;
    return refuse("ARGUMENT_INVALID", error.message);
  }
  const reportPath = parsed.positionals[0];
  const keyPath = parsed.options.get("key");
  if (reportPath === undefined || typeof keyPath !== "string") {
    return refuse("ACCEPTANCE_REPORT_AND_KEY_REQUIRED");
  }
  const token = io.files.read(reportPath);
  if (token === null) return refuse("ACCEPTANCE_REPORT_UNREADABLE");
  const keyText = io.files.read(keyPath);
  const publicJwk = keyText === null ? null : publicKeyOf(keyText);
  if (publicJwk === null) return refuse("ACCEPTANCE_KEY_UNREADABLE");
  let running: { digest: string; document: DeploymentFingerprintDocument } | null = null;
  if (parsed.options.get("current") === true) {
    const gateway = parsed.options.get("gateway");
    if (typeof gateway !== "string") return refuse("ACCEPTANCE_GATEWAY_REQUIRED");
    const answer = await readStatus(
      io,
      `${withoutTrailingSlashes(gateway)}${GATEWAY_PREFIX}/status`,
    );
    if ("error" in answer) return refuse("GATEWAY_UNREACHABLE", answer.error);
    if (answer.status.fingerprint === undefined) return refuse("GATEWAY_FINGERPRINT_UNREPORTED");
    running = answer.status.fingerprint;
  }
  const result = await verifyAcceptance(token, publicJwk, Date.now(), running);
  io.stdout(
    parsed.options.get("json") === true
      ? `${JSON.stringify(result)}\n`
      : `Acceptance  ${describeVerification(result)}\n${result.failures
          .map((failure) => `  ${failure.case} ${failure.name}: ${failure.code}\n`)
          .join("")}`,
  );
  io.exit(result.ok ? 0 : 1);
}
