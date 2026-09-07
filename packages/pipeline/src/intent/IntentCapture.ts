import { randomUUID } from "node:crypto";
import type { AuditRecorder } from "../audit/AuditRecorder.js";
import {
  AgentProposalSchema,
  ExecutionIntentSchema,
  RESERVED_CONTEXT_IDEMPOTENCY_KEY,
  TrustedIntentContextSchema,
  type AgentProposal,
  type CapturedIntent,
  type TrustedIntentContext,
} from "./ExecutionIntent.js";
import { CanonicalIntentHasher } from "./CanonicalIntentHasher.js";

export interface IntentCaptureOptions {
  readonly audit?: AuditRecorder;
  readonly hasher?: CanonicalIntentHasher;
  readonly clock?: () => Date;
  readonly createId?: () => string;
  readonly ttlSeconds?: number;
}

export class IntentCapture {
  private readonly hasher: CanonicalIntentHasher;
  private readonly clock: () => Date;
  private readonly createId: () => string;
  private readonly ttlSeconds: number;
  private readonly audit: AuditRecorder | undefined;

  public constructor(options?: IntentCaptureOptions) {
    this.hasher = options?.hasher ?? new CanonicalIntentHasher();
    this.clock = options?.clock ?? (() => new Date());
    this.createId = options?.createId ?? randomUUID;
    this.ttlSeconds = Math.min(Math.max(options?.ttlSeconds ?? 60, 1), 300);
    this.audit = options?.audit;
  }

  public capture(proposalInput: AgentProposal, trustedInput: TrustedIntentContext): CapturedIntent {
    this.hasher.assertInputBounded(proposalInput);
    this.hasher.assertInputBounded(trustedInput);
    const proposal = AgentProposalSchema.parse(proposalInput);
    const trusted = TrustedIntentContextSchema.parse(trustedInput);
    if (Object.hasOwn(trusted.context, RESERVED_CONTEXT_IDEMPOTENCY_KEY)) {
      throw new Error("INTENT_CONTEXT_KEY_RESERVED");
    }
    const capturedAt = this.clock();
    const expiresAt = new Date(capturedAt.valueOf() + this.ttlSeconds * 1_000);
    const intent = ExecutionIntentSchema.parse({
      version: "agent-safe.intent/1",
      intentId: this.createId(),
      tenantId: trusted.tenantId,
      capturedAt: capturedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      actor: trusted.actor,
      action: proposal.action,
      target: proposal.target,
      parameters: proposal.parameters,
      downstreamTarget: trusted.downstreamTarget,
      context: trusted.context,
      ...(trusted.correlationId === undefined ? {} : { correlationId: trusted.correlationId }),
      idempotencyKey: trusted.idempotencyKey,
    });
    return this.hasher.capture(intent);
  }

  /** Captures an intent and waits for the optional bounded audit sink once. */
  public async captureAndAudit(
    proposalInput: AgentProposal,
    trustedInput: TrustedIntentContext,
  ): Promise<CapturedIntent> {
    const captured = this.capture(proposalInput, trustedInput);
    await this.audit?.record({ eventType: "INTENT_CAPTURED", captured });
    return captured;
  }
}
