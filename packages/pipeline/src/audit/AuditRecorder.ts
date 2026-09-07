import { randomUUID } from "node:crypto";
import type { GateDecision } from "../decision/DecisionAuthority.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type { JsonObject, JsonValue } from "../intent/JsonValue.js";
import type { VerifiedAuthorization } from "../execution/AuthorizationVerifier.js";

export type AuditEventType =
  | "INTENT_CAPTURED"
  | "AUTHORITY_DECISION"
  | "AUTHORITY_FAILED_CLOSED"
  | "PRESENCE_ESCALATED"
  | "PRESENCE_RESOLVED"
  | "SHADOW_EVALUATED"
  | "GRANT_CONSUMED"
  | "EXECUTION_STARTED"
  | "EXECUTION_COMPLETED"
  | "EXECUTION_BLOCKED"
  | "EXECUTION_FAILED_BEFORE_DISPATCH"
  | "EXECUTION_OUTCOME_UNKNOWN"
  | "RECONCILIATION_COMPLETED"
  | "RECONCILIATION_NOT_EXECUTED"
  | "RECONCILIATION_UNKNOWN";

export type AuditAuthority = "AUTHORITATIVE" | "OBSERVATIONAL" | "NON_AUTHORITATIVE";

export interface AuditPolicyRevision {
  readonly policyId: string;
  readonly revisionId: string;
  readonly version?: string;
  readonly digest: `sha256:${string}`;
}

export interface AuditEvaluationEvidence {
  readonly evaluationId?: string;
  readonly materialInputDigest?: `sha256:${string}`;
  readonly policy?: AuditPolicyRevision;
  readonly evidenceReference?: string;
}

export interface AuditEventV1 {
  readonly schemaVersion: "agent-safe.audit/1";
  readonly eventId: string;
  readonly occurredAt: string;
  readonly eventType: AuditEventType;
  readonly authority: AuditAuthority;
  readonly correlation: {
    readonly intentId: string;
    readonly intentHash: string;
    readonly correlationId?: string;
    readonly decisionId?: string;
    readonly dossierId?: string;
    readonly grantId?: string;
  };
  readonly evaluation: {
    readonly evaluationId: string;
    readonly materialInputDigest: string;
    readonly policy: AuditPolicyRevision | null;
    readonly evidenceReference: string | null;
  } | null;
  readonly verdict: GateDecision["verdict"] | null;
  readonly reasonCodes: readonly string[];
  readonly durationMs: number | null;
  readonly metadata: Readonly<JsonObject>;
}

export interface AuditSink {
  write(event: AuditEventV1): Promise<void> | void;
}

export interface AuditRecordInput {
  readonly eventType: AuditEventType;
  readonly captured: CapturedIntent;
  readonly authority?: AuditAuthority;
  readonly decision?: GateDecision;
  readonly authorization?: VerifiedAuthorization;
  readonly decisionId?: string;
  readonly dossierId?: string;
  readonly grantId?: string;
  /** Verdict for events that carry no `GateDecision`, such as shadow observations. */
  readonly verdict?: GateDecision["verdict"];
  readonly evaluation?: AuditEvaluationEvidence;
  readonly reasonCodes?: readonly string[];
  readonly durationMs?: number;
  readonly metadata?: Readonly<Record<string, JsonValue>>;
}

export interface AuditRecorderOptions {
  readonly sink: AuditSink;
  readonly timeoutMs?: number;
  readonly failurePolicy?: "BEST_EFFORT" | "REQUIRE_BEFORE_EXECUTION";
  readonly metadataAllowlist?: readonly string[];
  readonly redactMetadata?: (key: string, value: JsonValue) => JsonValue | undefined;
  readonly clock?: () => Date;
  readonly createId?: () => string;
}

export interface AuditPolicyRevisionArtifact extends AuditPolicyRevision {
  /** Opaque location or object-store version used by an authorized replay system. */
  readonly artifactReference: string;
}

export interface AuditPolicyRevisionResolver {
  resolve(
    policyId: string,
    revisionId: string,
  ): Promise<AuditPolicyRevisionArtifact | null> | AuditPolicyRevisionArtifact | null;
}

export type AuditPolicyVerification =
  | { readonly status: "VERIFIED"; readonly artifact: AuditPolicyRevisionArtifact }
  | { readonly status: "NOT_REFERENCED"; readonly artifact: null }
  | {
      readonly status: "MISSING" | "DIGEST_MISMATCH" | "IDENTITY_MISMATCH" | "UNAVAILABLE";
      readonly artifact: null;
    };

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const AUDIT_AUTHORITIES = new Set<AuditAuthority>([
  "AUTHORITATIVE",
  "OBSERVATIONAL",
  "NON_AUTHORITATIVE",
]);
const AUDIT_VERDICTS = new Set<GateDecision["verdict"]>(["ALLOW", "ESCALATE", "BLOCK"]);
const RESTRICTED_METADATA_KEY =
  /authorization|credential|password|secret|token|parameters|context|provider[_-]?result/i;
const MAX_METADATA_DEPTH = 4;
const MAX_METADATA_ENTRIES = 50;
const MAX_METADATA_ARRAY = 20;
const MAX_METADATA_STRING = 500;
const MAX_METADATA_BYTES = 4 * 1024;

/**
 * Emits immutable, redacted lifecycle records through one bounded sink call.
 * Sink failures are converted to `false`; the recorder never retries because
 * retries could reorder evidence or couple provider execution to sink health.
 */
export class AuditRecorder {
  private readonly timeoutMs: number;
  private readonly failurePolicy: "BEST_EFFORT" | "REQUIRE_BEFORE_EXECUTION";
  private readonly metadataAllowlist: ReadonlySet<string>;
  private readonly clock: () => Date;
  private readonly createId: () => string;

  public constructor(private readonly options: AuditRecorderOptions) {
    this.timeoutMs = Math.min(Math.max(options.timeoutMs ?? 100, 1), 5_000);
    this.failurePolicy = options.failurePolicy ?? "BEST_EFFORT";
    this.metadataAllowlist = new Set(options.metadataAllowlist ?? []);
    this.clock = options.clock ?? (() => new Date());
    this.createId = options.createId ?? randomUUID;
    if (this.metadataAllowlist.size > MAX_METADATA_ENTRIES) {
      throw new Error("AUDIT_METADATA_ALLOWLIST_TOO_LARGE");
    }
    for (const key of this.metadataAllowlist) AuditRecorder.assertIdentifier(key);
  }

  public get requiresDeliveryBeforeExecution(): boolean {
    return this.failurePolicy === "REQUIRE_BEFORE_EXECUTION";
  }

  public async record(input: AuditRecordInput): Promise<boolean> {
    try {
      const event = this.event(input);
      const delivered = await new Promise<boolean>((resolve) => {
        let settled = false;
        const settle = (result: boolean): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          resolve(result);
        };
        const timeout = setTimeout(() => settle(false), this.timeoutMs);
        void Promise.resolve()
          .then(async () => await this.options.sink.write(event))
          .then(
            () => settle(true),
            () => settle(false),
          );
      });
      return delivered;
    } catch {
      return false;
    }
  }

  private event(input: AuditRecordInput): AuditEventV1 {
    AuditRecorder.assertIdentifier(input.captured.intent.intentId);
    AuditRecorder.assertDigest(input.captured.intentHash);
    if (
      input.durationMs !== undefined &&
      (!Number.isFinite(input.durationMs) || input.durationMs < 0)
    ) {
      throw new Error("AUDIT_DURATION_INVALID");
    }
    const reasonCodes = input.reasonCodes ?? input.decision?.reasonCodes ?? [];
    if (reasonCodes.length > 50) throw new Error("AUDIT_REASON_CODES_TOO_MANY");
    for (const reasonCode of reasonCodes) {
      AuditRecorder.assertIdentifier(reasonCode);
    }
    const authority = input.authority ?? AuditRecorder.defaultAuthority(input.eventType);
    if (!AUDIT_AUTHORITIES.has(authority)) throw new Error("AUDIT_AUTHORITY_INVALID");
    if (input.eventType === "SHADOW_EVALUATED" && authority !== "OBSERVATIONAL") {
      throw new Error("AUDIT_SHADOW_MUST_BE_OBSERVATIONAL");
    }
    const verdict = input.verdict ?? input.decision?.verdict ?? null;
    if (verdict !== null && !AUDIT_VERDICTS.has(verdict)) {
      throw new Error("AUDIT_VERDICT_INVALID");
    }

    const decisionId = input.decisionId ?? input.decision?.decisionId;
    const dossierId = input.dossierId ?? input.decision?.dossierId ?? undefined;
    const grantId = input.grantId ?? input.authorization?.grantId;
    // Observational evidence must never correlate to an execution grant.
    if (authority === "OBSERVATIONAL" && (grantId !== undefined || input.authorization)) {
      throw new Error("AUDIT_OBSERVATIONAL_GRANT_FORBIDDEN");
    }
    if (decisionId !== undefined) AuditRecorder.assertIdentifier(decisionId);
    if (dossierId !== undefined) AuditRecorder.assertIdentifier(dossierId);
    if (grantId !== undefined) AuditRecorder.assertIdentifier(grantId);
    if (input.captured.intent.correlationId !== undefined) {
      AuditRecorder.assertIdentifier(input.captured.intent.correlationId);
    }

    const evaluation = input.decision
      ? this.evaluation(input.captured, input.decision, input.evaluation)
      : null;
    const event: AuditEventV1 = {
      schemaVersion: "agent-safe.audit/1",
      eventId: this.boundedId(this.createId()),
      occurredAt: this.validDate(this.clock()).toISOString(),
      eventType: input.eventType,
      authority,
      correlation: {
        intentId: input.captured.intent.intentId,
        intentHash: input.captured.intentHash,
        ...(input.captured.intent.correlationId === undefined
          ? {}
          : { correlationId: input.captured.intent.correlationId }),
        ...(decisionId === undefined ? {} : { decisionId }),
        ...(dossierId === undefined ? {} : { dossierId }),
        ...(grantId === undefined ? {} : { grantId }),
      },
      evaluation,
      verdict,
      reasonCodes: [...reasonCodes],
      durationMs:
        input.durationMs === undefined ? null : Math.round(input.durationMs * 1_000) / 1_000,
      metadata: this.metadata(input.metadata),
    };
    return AuditRecorder.deepFreeze(event);
  }

  private evaluation(
    captured: CapturedIntent,
    decision: GateDecision,
    evidence?: AuditEvaluationEvidence,
  ): NonNullable<AuditEventV1["evaluation"]> {
    const evaluationId = evidence?.evaluationId ?? decision.decisionId;
    const materialInputDigest = evidence?.materialInputDigest ?? captured.intentHash;
    const evidenceReference = evidence?.evidenceReference ?? decision.dossierId;
    AuditRecorder.assertIdentifier(evaluationId);
    AuditRecorder.assertDigest(materialInputDigest);
    if (evidenceReference !== null) AuditRecorder.assertIdentifier(evidenceReference);

    let policy: AuditPolicyRevision | null = null;
    if (evidence?.policy !== undefined) {
      AuditRecorder.assertIdentifier(evidence.policy.policyId);
      AuditRecorder.assertIdentifier(evidence.policy.revisionId);
      if (/^(?:current|latest)$/i.test(evidence.policy.revisionId)) {
        throw new Error("AUDIT_POLICY_REVISION_MUTABLE_ALIAS");
      }
      if (evidence.policy.version !== undefined) {
        AuditRecorder.assertIdentifier(evidence.policy.version);
      }
      AuditRecorder.assertDigest(evidence.policy.digest);
      policy = { ...evidence.policy };
    }
    return {
      evaluationId,
      materialInputDigest,
      policy,
      evidenceReference,
    };
  }

  private metadata(input?: Readonly<Record<string, JsonValue>>): Readonly<JsonObject> {
    if (input === undefined) return Object.freeze({});
    const output: JsonObject = {};
    for (const [key, value] of Object.entries(input)) {
      if (!this.metadataAllowlist.has(key) || RESTRICTED_METADATA_KEY.test(key)) continue;
      const redacted =
        this.options.redactMetadata === undefined ? value : this.options.redactMetadata(key, value);
      if (redacted !== undefined) output[key] = this.copyJson(redacted, 0, { entries: 0 });
    }
    if (Buffer.byteLength(JSON.stringify(output), "utf8") > MAX_METADATA_BYTES) {
      throw new Error("AUDIT_METADATA_TOO_LARGE");
    }
    return AuditRecorder.deepFreeze(output);
  }

  private copyJson(value: JsonValue, depth: number, count: { entries: number }): JsonValue {
    if (depth > MAX_METADATA_DEPTH) throw new Error("AUDIT_METADATA_TOO_DEEP");
    if (typeof value === "string") {
      if (value.length > MAX_METADATA_STRING) throw new Error("AUDIT_METADATA_STRING_TOO_LONG");
      return value;
    }
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("AUDIT_METADATA_NUMBER_INVALID");
    }
    if (value === null || typeof value !== "object") return value;
    if (Array.isArray(value)) {
      if (value.length > MAX_METADATA_ARRAY) throw new Error("AUDIT_METADATA_ARRAY_TOO_LONG");
      return value.map((entry) => {
        count.entries += 1;
        if (count.entries > MAX_METADATA_ENTRIES) throw new Error("AUDIT_METADATA_TOO_COMPLEX");
        return this.copyJson(entry, depth + 1, count);
      });
    }
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("AUDIT_METADATA_OBJECT_INVALID");
    }
    const copy: JsonObject = {};
    for (const [key, entry] of Object.entries(value)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new Error("AUDIT_METADATA_KEY_INVALID");
      }
      count.entries += 1;
      if (count.entries > MAX_METADATA_ENTRIES) throw new Error("AUDIT_METADATA_TOO_COMPLEX");
      copy[key] = this.copyJson(entry, depth + 1, count);
    }
    return copy;
  }

  private boundedId(value: string): string {
    AuditRecorder.assertIdentifier(value);
    return value;
  }

  private validDate(value: Date): Date {
    if (!(value instanceof Date) || !Number.isFinite(value.valueOf())) {
      throw new Error("AUDIT_CLOCK_INVALID");
    }
    return value;
  }

  private static defaultAuthority(eventType: AuditEventType): AuditAuthority {
    if (eventType === "INTENT_CAPTURED") return "NON_AUTHORITATIVE";
    if (eventType === "SHADOW_EVALUATED") return "OBSERVATIONAL";
    if (eventType === "PRESENCE_ESCALATED" || eventType === "PRESENCE_RESOLVED") {
      return "NON_AUTHORITATIVE";
    }
    return "AUTHORITATIVE";
  }

  private static assertIdentifier(value: string): void {
    if (!isBoundedIdentifier(value)) throw new Error("AUDIT_IDENTIFIER_INVALID");
  }

  private static assertDigest(value: string): asserts value is `sha256:${string}` {
    if (!DIGEST_PATTERN.test(value)) throw new Error("AUDIT_DIGEST_INVALID");
  }

  private static deepFreeze<T>(value: T): T {
    if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
      Object.freeze(value);
      for (const child of Object.values(value as Record<string, unknown>)) {
        AuditRecorder.deepFreeze(child);
      }
    }
    return value;
  }
}

/** Resolves historical policy evidence by its pinned revision, never by a mutable alias. */
export class AuditPolicyRevisionVerifier {
  private readonly timeoutMs: number;

  public constructor(
    private readonly resolver: AuditPolicyRevisionResolver,
    timeoutMs = 1_000,
  ) {
    this.timeoutMs = Math.min(Math.max(timeoutMs, 1), 15_000);
  }

  public async verify(event: AuditEventV1): Promise<AuditPolicyVerification> {
    const reference = event.evaluation?.policy;
    if (reference === null || reference === undefined) {
      return { status: "NOT_REFERENCED", artifact: null };
    }

    const resolved = await new Promise<AuditPolicyRevisionArtifact | null | undefined>(
      (resolve) => {
        let settled = false;
        const settle = (value: AuditPolicyRevisionArtifact | null | undefined): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timeout);
          resolve(value);
        };
        const timeout = setTimeout(() => settle(undefined), this.timeoutMs);
        void Promise.resolve()
          .then(async () => await this.resolver.resolve(reference.policyId, reference.revisionId))
          .then(
            (artifact) => settle(artifact),
            () => settle(undefined),
          );
      },
    );
    if (resolved === undefined) return { status: "UNAVAILABLE", artifact: null };
    if (resolved === null) return { status: "MISSING", artifact: null };
    if (resolved.policyId !== reference.policyId || resolved.revisionId !== reference.revisionId) {
      return { status: "IDENTITY_MISMATCH", artifact: null };
    }
    if (resolved.digest !== reference.digest) {
      return { status: "DIGEST_MISMATCH", artifact: null };
    }
    if (
      !isBoundedIdentifier(resolved.artifactReference) ||
      !isBoundedIdentifier(resolved.policyId) ||
      !isBoundedIdentifier(resolved.revisionId) ||
      !DIGEST_PATTERN.test(resolved.digest)
    ) {
      return { status: "UNAVAILABLE", artifact: null };
    }
    return {
      status: "VERIFIED",
      artifact: Object.freeze({ ...resolved }),
    };
  }
}

function isBoundedIdentifier(value: string): boolean {
  if (value.length < 1 || value.length > 200) return false;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return false;
  }
  return true;
}
