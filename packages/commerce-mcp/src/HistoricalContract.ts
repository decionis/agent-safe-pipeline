import { CommerceGateError } from "./Errors.js";

export const HISTORICAL_WINDOW_DAYS = 90;
export const HISTORICAL_TRIAL_DAYS = 14;
export const HISTORICAL_RESPONSE_BYTES = 100 * 1024;
export const HISTORICAL_API_PATH = "/commerce/history";

export type HistoricalSource =
  { kind: "synthetic" } | { kind: "connected_store"; connection_id: string };
export interface HistoricalStart {
  source: HistoricalSource;
  idempotency_key: string;
}
export type HistoricalSourceInfo =
  | { kind: "synthetic"; dataset_version: string; label: string }
  | { kind: "connected_store"; connection_id: string; platform: string; label: string };
export interface HistoricalSources {
  window_days: 90;
  mode: "historical_only";
  sources: HistoricalSourceInfo[];
  connected_store_required: boolean;
}
export interface HistoricalAssessment {
  assessment_id: string;
  status: "completed" | "failed";
  mode: "historical_only";
  window: { days: 90; start: string; end: string; timestamp_field: "transaction_at" };
  provenance: HistoricalSourceInfo;
  policy: { kind: "sample" | "merchant"; version: string; floor_percent: number } | null;
  summary: {
    transactions_scanned: number;
    evaluated: number;
    missing_cost: number;
    excluded_timestamp: number;
    evaluation_errors: number;
    allow: number;
    hold: number;
    escalate: number;
  };
  evidence: {
    record_id: string;
    transaction_at: string;
    decision: "PROCEED" | "HOLD" | "ESCALATE";
    reason_codes: string[];
    proof_ref: string | null;
  }[];
  coverage: { record_limit: 100; complete: boolean };
  truncated: boolean;
  error_code?: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CODE = /^[A-Z0-9_]{1,64}$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const SUMMARY_KEYS = [
  "transactions_scanned",
  "evaluated",
  "missing_cost",
  "excluded_timestamp",
  "evaluation_errors",
  "allow",
  "hold",
  "escalate",
] as const;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function text(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}
function utc(value: unknown): value is string {
  if (typeof value !== "string" || !UTC.test(value) || !Number.isFinite(Date.parse(value)))
    return false;
  return (
    new Date(value).toISOString() === (value.includes(".") ? value : value.replace("Z", ".000Z"))
  );
}
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}
function invalidInput(): never {
  throw new CommerceGateError(
    "INVALID_INPUT",
    "Use a listed history source and a bounded idempotency key or assessment UUID. Caller-supplied transactions, dates, policies and organizations are not accepted.",
  );
}
function invalidResponse(): never {
  throw new CommerceGateError(
    "INVALID_UPSTREAM_RESPONSE",
    "Commerce Gate did not return a valid historical assessment response. No result was accepted.",
  );
}

export function historicalEmptyInput(value: Record<string, unknown>): void {
  if (Object.keys(value).length) invalidInput();
}
export function historicalAssessmentId(value: Record<string, unknown>): string {
  if (
    !exact(value, ["assessment_id"]) ||
    typeof value.assessment_id !== "string" ||
    !UUID.test(value.assessment_id)
  )
    invalidInput();
  return value.assessment_id;
}
export function historicalStartInput(value: Record<string, unknown>): HistoricalStart {
  if (
    !exact(value, ["source", "idempotency_key"]) ||
    !text(value.idempotency_key, 200) ||
    !/^[\w.:-]+$/.test(value.idempotency_key) ||
    !record(value.source)
  )
    invalidInput();
  const source = value.source;
  if (source.kind === "synthetic" && exact(source, ["kind"])) {
    return { source: { kind: "synthetic" }, idempotency_key: value.idempotency_key };
  }
  if (
    source.kind === "connected_store" &&
    exact(source, ["kind", "connection_id"]) &&
    typeof source.connection_id === "string" &&
    UUID.test(source.connection_id)
  ) {
    return {
      source: { kind: "connected_store", connection_id: source.connection_id },
      idempotency_key: value.idempotency_key,
    };
  }
  return invalidInput();
}

function sourceInfo(value: unknown): HistoricalSourceInfo {
  if (!record(value) || !text(value.label, 200)) invalidResponse();
  if (
    value.kind === "synthetic" &&
    exact(value, ["kind", "label", "dataset_version"]) &&
    text(value.dataset_version, 100)
  ) {
    return { kind: "synthetic", label: value.label, dataset_version: value.dataset_version };
  }
  if (
    value.kind === "connected_store" &&
    exact(value, ["kind", "label", "connection_id", "platform"]) &&
    typeof value.connection_id === "string" &&
    UUID.test(value.connection_id) &&
    text(value.platform, 40)
  ) {
    return {
      kind: "connected_store",
      label: value.label,
      connection_id: value.connection_id,
      platform: value.platform,
    };
  }
  return invalidResponse();
}

export function historicalSourcesResponse(value: unknown): HistoricalSources {
  if (
    !record(value) ||
    !exact(value, ["mode", "window_days", "sources", "connected_store_required"]) ||
    value.mode !== "historical_only" ||
    value.window_days !== 90 ||
    typeof value.connected_store_required !== "boolean" ||
    !Array.isArray(value.sources) ||
    value.sources.length > 21
  )
    invalidResponse();
  return {
    mode: "historical_only",
    window_days: 90,
    connected_store_required: value.connected_store_required,
    sources: value.sources.map(sourceInfo),
  };
}

export function historicalAssessmentResponse(
  value: unknown,
  expectedId?: string,
): HistoricalAssessment {
  if (
    !record(value) ||
    !exact(value, [
      "assessment_id",
      "status",
      "mode",
      "window",
      "provenance",
      "policy",
      "summary",
      "evidence",
      "truncated",
      "coverage",
      "error_code",
    ]) ||
    typeof value.assessment_id !== "string" ||
    !UUID.test(value.assessment_id) ||
    (expectedId !== undefined && value.assessment_id !== expectedId) ||
    !["completed", "failed"].includes(String(value.status)) ||
    value.mode !== "historical_only" ||
    typeof value.truncated !== "boolean"
  )
    invalidResponse();
  const window = value.window;
  if (
    !record(window) ||
    !exact(window, ["days", "start", "end", "timestamp_field"]) ||
    window.days !== 90 ||
    window.timestamp_field !== "transaction_at" ||
    !utc(window.start) ||
    !utc(window.end) ||
    Date.parse(window.end) - Date.parse(window.start) !== 90 * 86_400_000
  )
    invalidResponse();
  const provenance = sourceInfo(value.provenance);
  const policy = value.policy;
  if (policy === null) {
    if (value.status !== "failed") invalidResponse();
  } else if (
    !record(policy) ||
    !exact(policy, ["kind", "version", "floor_percent"]) ||
    policy.kind !== (provenance.kind === "synthetic" ? "sample" : "merchant") ||
    !text(policy.version, 100) ||
    typeof policy.floor_percent !== "number" ||
    !Number.isFinite(policy.floor_percent) ||
    policy.floor_percent < 0 ||
    policy.floor_percent > 100
  )
    invalidResponse();
  const coverage = value.coverage;
  if (
    !record(coverage) ||
    !exact(coverage, ["record_limit", "complete"]) ||
    coverage.record_limit !== 100 ||
    typeof coverage.complete !== "boolean" ||
    (value.truncated && coverage.complete) ||
    (value.status === "failed" && coverage.complete)
  )
    invalidResponse();
  const summary = value.summary;
  if (
    !record(summary) ||
    !exact(summary, SUMMARY_KEYS) ||
    !SUMMARY_KEYS.every((key) => Number.isSafeInteger(summary[key]) && Number(summary[key]) >= 0)
  )
    invalidResponse();
  if (!Array.isArray(value.evidence) || value.evidence.length > 100) invalidResponse();
  const evidence = value.evidence.map((item): HistoricalAssessment["evidence"][number] => {
    if (
      !record(item) ||
      !exact(item, ["record_id", "transaction_at", "decision", "reason_codes", "proof_ref"]) ||
      typeof item.record_id !== "string" ||
      !/^[a-f0-9]{64}$/.test(item.record_id) ||
      !utc(item.transaction_at) ||
      Date.parse(item.transaction_at) < Date.parse(window.start as string) ||
      Date.parse(item.transaction_at) >= Date.parse(window.end as string) ||
      !["PROCEED", "HOLD", "ESCALATE"].includes(String(item.decision)) ||
      !Array.isArray(item.reason_codes) ||
      item.reason_codes.length > 4 ||
      !item.reason_codes.every((code) => typeof code === "string" && CODE.test(code)) ||
      !(item.proof_ref === null || text(item.proof_ref, 200))
    )
      invalidResponse();
    return {
      record_id: item.record_id,
      transaction_at: item.transaction_at,
      decision: item.decision as HistoricalAssessment["evidence"][number]["decision"],
      reason_codes: item.reason_codes as string[],
      proof_ref: item.proof_ref,
    };
  });
  if (
    value.error_code !== undefined &&
    !(typeof value.error_code === "string" && CODE.test(value.error_code))
  )
    invalidResponse();
  return {
    assessment_id: value.assessment_id,
    status: value.status as HistoricalAssessment["status"],
    mode: "historical_only",
    window: { days: 90, start: window.start, end: window.end, timestamp_field: "transaction_at" },
    provenance,
    policy:
      policy === null
        ? null
        : {
            kind: policy.kind as "sample" | "merchant",
            version: policy.version as string,
            floor_percent: policy.floor_percent as number,
          },
    coverage: { record_limit: 100, complete: coverage.complete },
    summary: Object.fromEntries(
      SUMMARY_KEYS.map((key) => [key, summary[key]]),
    ) as HistoricalAssessment["summary"],
    evidence,
    truncated: value.truncated,
    ...(value.error_code === undefined ? {} : { error_code: value.error_code as string }),
  };
}
