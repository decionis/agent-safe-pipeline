import { z } from "zod";
import { HumanApprovalGate, PresenceClient } from "@decionis/presence-node";
import {
  PresenceApprovalCoordinator,
  type AuditRecorder,
  type CapturedIntent,
  type DecionisGate,
  type GateDecision,
  type ManagedEscalationState,
  type PresenceApprovalClient,
} from "@decionis/agent-safe-pipeline";
import type { EscalationConfig } from "../config/ExecutorConfig.js";

const identifier = z.string().trim().min(1).max(200);

/**
 * What the caller is handed on an `ESCALATE`, and presents back verbatim to
 * resume. It carries the exact intent, so the process keeps nothing between
 * the two calls, and only what the mode needs: a Presence request id in
 * direct mode, the authority's escalation state in managed mode. Neither is
 * authority; a grant exists only after the authority evaluates again.
 */
export const EscalationHandoffSchema = z.discriminatedUnion("mode", [
  z.strictObject({
    mode: z.literal("DIRECT"),
    intent: z.record(z.string(), z.unknown()),
    request_id: identifier,
    approval_url: z.string().max(2_000).nullable(),
    expires_at: z.string().datetime().nullable(),
  }),
  z.strictObject({
    mode: z.literal("MANAGED"),
    intent: z.record(z.string(), z.unknown()),
    escalation: z.strictObject({
      escalationId: identifier,
      intentId: identifier,
      status: z.enum([
        "PENDING_PRESENCE",
        "PRESENCE_REQUESTED",
        "AWAITING_APPROVER",
        "PRESENCE_VERIFIED",
        "REAUTHORIZING",
        "GRANT_READY",
        "EXPIRED",
        "REJECTED",
        "BLOCKED",
        "CANCELLED",
        "FAILED",
      ]),
      outcome: z.enum(["ESCALATE_PENDING", "ALLOW", "BLOCK", "ERROR"]),
      expiresAt: z.string().datetime(),
      reasonCodes: z.array(z.string().max(200)).max(50).readonly(),
    }),
  }),
]);

export type EscalationHandoff = z.infer<typeof EscalationHandoffSchema>;

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

/** The handoff without the intent: what a mode knows, and what is echoed while pending. */
export type EscalationState = DistributiveOmit<EscalationHandoff, "intent">;

/** One step of a resumption: either a decision to run, or a state to report. */
export type EscalationResolution =
  | { readonly kind: "DECISION"; readonly decision: GateDecision }
  | {
      readonly kind: "PENDING";
      readonly handoff: EscalationState;
      readonly reasonCodes: readonly string[];
    }
  | {
      readonly kind: "REFUSED";
      readonly reasonCodes: readonly string[];
      readonly failClosed: boolean;
    };

export interface EscalationDependencies {
  readonly presence?: PresenceApprovalClient;
}

/**
 * Resolves an `ESCALATE` in the shape the adopter configured. Both shapes
 * are stateless on this side: the handoff the caller presents is validated
 * by the authority against the exact intent, so a request id or an
 * escalation id that belongs to another intent cannot produce a grant here.
 */
export class EscalationResolver {
  private readonly coordinator: PresenceApprovalCoordinator | null;
  private readonly presence: PresenceApprovalClient | null;

  public constructor(
    private readonly config: EscalationConfig,
    private readonly gate: DecionisGate,
    audit: AuditRecorder,
    dependencies: EscalationDependencies = {},
    /** The Presence credential for `DIRECT`, read from its handle by the caller for this build. */
    presenceApiKey: string | null = null,
  ) {
    if (config.mode !== "DIRECT") {
      this.coordinator = null;
      this.presence = null;
      return;
    }
    if (dependencies.presence === undefined && presenceApiKey === null) {
      throw new Error("CONFIG_SECRET_MISSING: PRESENCE_API_KEY");
    }
    this.presence =
      dependencies.presence ??
      new HumanApprovalGate(
        new PresenceClient({ baseUrl: config.presence.baseUrl, apiKey: presenceApiKey ?? "" }),
      );
    this.coordinator = new PresenceApprovalCoordinator(
      this.presence,
      gate,
      config.presence.organization,
      config.approverId,
      { audit, requirements: config.requirements },
    );
  }

  public get mode(): EscalationConfig["mode"] {
    return this.config.mode;
  }

  /** The first evaluation: in managed mode it also asks the authority to orchestrate. */
  public async evaluate(captured: CapturedIntent): Promise<GateDecision> {
    if (this.config.mode !== "MANAGED") return await this.gate.evaluate(captured);
    return await this.gate.evaluate(captured, undefined, {
      escalation: {
        mode: "MANAGED",
        approver: {
          principal_id: this.config.approverId,
          ...(this.config.approverRole === null ? {} : { role_id: this.config.approverRole }),
        },
        verification_requirements: {
          methods: this.config.requirements.methods,
          level: this.config.requirements.level,
        },
      },
    });
  }

  /**
   * What the caller is handed after an `ESCALATE`. In direct mode this opens
   * the Presence request, bound to the intent hash the person will see.
   */
  public async handoff(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<EscalationState | null> {
    if (this.config.mode === "MANAGED") {
      return decision.managedEscalation === undefined
        ? null
        : { mode: "MANAGED", escalation: decision.managedEscalation };
    }
    if (this.coordinator === null) return null;
    let result;
    try {
      result = await this.coordinator.request(captured);
    } catch {
      return null;
    }
    if (result.verdict !== "HUMAN_REQUIRED" || result.request_id === undefined) return null;
    return {
      mode: "DIRECT",
      request_id: result.request_id,
      approval_url: result.approval_url ?? null,
      expires_at: result.expires_at ?? null,
    };
  }

  /** One bounded lookup, then either a fresh decision or the state to report. */
  public async resume(
    captured: CapturedIntent,
    handoff: EscalationHandoff,
  ): Promise<EscalationResolution> {
    if (handoff.mode !== this.config.mode) {
      return { kind: "REFUSED", reasonCodes: ["ESCALATION_MODE_MISMATCH"], failClosed: true };
    }
    if (handoff.mode === "MANAGED") return await this.resumeManaged(captured, handoff.escalation);
    return await this.resumeDirect(captured, handoff);
  }

  private async resumeManaged(
    captured: CapturedIntent,
    state: ManagedEscalationState,
  ): Promise<EscalationResolution> {
    const status = await this.gate.getManagedEscalationStatus(captured, state);
    if (status.outcome === "ALLOW") return { kind: "DECISION", decision: status.decision };
    if (status.outcome === "ESCALATE_PENDING") {
      return {
        kind: "PENDING",
        handoff: {
          mode: "MANAGED",
          escalation: {
            escalationId: status.escalationId,
            intentId: status.intentId,
            status: status.status,
            outcome: status.outcome,
            expiresAt: status.expiresAt,
            reasonCodes: status.reasonCodes,
          },
        },
        reasonCodes: status.reasonCodes,
      };
    }
    return {
      kind: "REFUSED",
      reasonCodes: [status.status, ...status.reasonCodes],
      failClosed: status.outcome === "ERROR",
    };
  }

  private async resumeDirect(
    captured: CapturedIntent,
    handoff: Extract<EscalationHandoff, { mode: "DIRECT" }>,
  ): Promise<EscalationResolution> {
    if (this.presence === null || this.coordinator === null) {
      return { kind: "REFUSED", reasonCodes: ["ESCALATION_MODE_MISMATCH"], failClosed: true };
    }
    let outcome;
    try {
      outcome = await this.presence.outcome(handoff.request_id);
    } catch {
      return { kind: "REFUSED", reasonCodes: ["PRESENCE_UNAVAILABLE"], failClosed: true };
    }
    if (outcome.verdict === "HUMAN_REQUIRED") {
      return {
        kind: "PENDING",
        handoff: {
          mode: "DIRECT",
          request_id: handoff.request_id,
          approval_url: handoff.approval_url,
          expires_at: handoff.expires_at,
        },
        reasonCodes: ["PRESENCE_HUMAN_REQUIRED"],
      };
    }
    // Terminal: the coordinator verifies the receipt belongs to this request,
    // records it, and asks the authority again with the receipt as evidence.
    // The authority checks the receipt against the intent hash, so a receipt
    // for another intent yields no grant.
    return {
      kind: "DECISION",
      decision: await this.coordinator.resolveAndReauthorize(captured, outcome),
    };
  }
}
