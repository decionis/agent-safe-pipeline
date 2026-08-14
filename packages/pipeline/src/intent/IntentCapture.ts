import { randomUUID } from "node:crypto";
import {
  AgentProposalSchema,
  ExecutionIntentSchema,
  TrustedIntentContextSchema,
  type AgentProposal,
  type CapturedIntent,
  type TrustedIntentContext,
} from "./ExecutionIntent.js";
import { CanonicalIntentHasher } from "./CanonicalIntentHasher.js";

export interface IntentCaptureOptions {
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

  public constructor(options?: IntentCaptureOptions) {
    this.hasher = options?.hasher ?? new CanonicalIntentHasher();
    this.clock = options?.clock ?? (() => new Date());
    this.createId = options?.createId ?? randomUUID;
    this.ttlSeconds = Math.min(Math.max(options?.ttlSeconds ?? 60, 1), 300);
  }

  public capture(proposalInput: AgentProposal, trustedInput: TrustedIntentContext): CapturedIntent {
    IntentCapture.assertSafeKeys(proposalInput);
    IntentCapture.assertSafeKeys(trustedInput);
    const proposal = AgentProposalSchema.parse(proposalInput);
    const trusted = TrustedIntentContextSchema.parse(trustedInput);
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

  private static assertSafeKeys(value: unknown): void {
    if (value === null || typeof value !== "object") return;
    for (const key of Object.keys(value)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new Error("UNSAFE_INTENT_KEY");
      }
      IntentCapture.assertSafeKeys((value as Record<string, unknown>)[key]);
    }
  }
}
