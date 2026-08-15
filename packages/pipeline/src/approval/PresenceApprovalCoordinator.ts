import type { GateResult, HumanApprovalGate } from "@decionis/presence-node";
import type {
  DecisionAuthority,
  GateDecision,
  HumanApprovalEvidence,
} from "../decision/DecisionAuthority.js";
import { FailClosedDecision } from "../decision/DecisionAuthority.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";

export type PresenceGateResult = GateResult;
export type PresenceApprovalClient = Pick<HumanApprovalGate, "gate" | "outcome">;

export class PresenceApprovalCoordinator {
  public constructor(
    private readonly presence: PresenceApprovalClient,
    private readonly authority: DecisionAuthority,
    private readonly organization: string,
    private readonly approverId: string,
  ) {}

  public async request(captured: CapturedIntent): Promise<PresenceGateResult> {
    try {
      const result = await this.presence.gate(
        {
          action: {
            intent: captured.intent.action,
            target: captured.intent.target,
            surface: "agent_safe_pipeline",
          },
          agent: {
            id: captured.intent.actor.id,
            display: captured.intent.actor.id,
            role: captured.intent.actor.type,
          },
          approver: { id: this.approverId },
          organization: this.organization,
          presentation: {
            title: `Approve ${captured.intent.action}`,
            description: `Authorize this exact action against ${captured.intent.target}.`,
            displayFields: [
              { key: "action", label: "Action", value: captured.intent.action },
              { key: "target", label: "Target", value: captured.intent.target },
              { key: "intent_hash", label: "Intent hash", value: captured.intentHash },
            ],
          },
        },
        `presence:${captured.intent.idempotencyKey}`,
      );
      if (PresenceApprovalCoordinator.verdictOf(result) === null) {
        throw new Error("PRESENCE_RESPONSE_INVALID");
      }
      return result;
    } catch {
      throw new Error("PRESENCE_REQUEST_FAILED");
    }
  }

  public async resolveAndReauthorize(
    captured: CapturedIntent,
    result: PresenceGateResult,
  ): Promise<GateDecision> {
    let terminal: unknown;
    try {
      terminal =
        result.verdict === "HUMAN_REQUIRED" && result.request_id !== undefined
          ? await this.presence.outcome(result.request_id)
          : result;
    } catch {
      return FailClosedDecision.create(captured.intentHash, "PRESENCE_UNAVAILABLE");
    }
    const verdict = PresenceApprovalCoordinator.verdictOf(terminal);
    if (verdict === null) {
      return FailClosedDecision.create(captured.intentHash, "PRESENCE_RESPONSE_INVALID");
    }
    if (verdict !== "PROCEED") {
      return FailClosedDecision.create(captured.intentHash, `PRESENCE_${verdict}`);
    }
    const evidence = PresenceApprovalCoordinator.evidenceOf(terminal);
    if (evidence === null) {
      return FailClosedDecision.create(captured.intentHash, "PRESENCE_PROOF_MISSING");
    }
    try {
      return await this.authority.evaluate(captured, { humanApproval: evidence });
    } catch {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_UNAVAILABLE");
    }
  }

  private static evidenceOf(result: unknown): HumanApprovalEvidence | null {
    if (result === null || typeof result !== "object") return null;
    const candidate = result as { request_id?: unknown; receipt_dossier_id?: unknown };
    if (
      PresenceApprovalCoordinator.isBoundedIdentifier(candidate.receipt_dossier_id) &&
      PresenceApprovalCoordinator.isBoundedIdentifier(candidate.request_id)
    ) {
      return {
        provider: "presence",
        requestId: candidate.request_id,
        receiptDossierId: candidate.receipt_dossier_id,
      };
    }
    return null;
  }

  private static verdictOf(result: unknown): PresenceGateResult["verdict"] | null {
    if (result === null || typeof result !== "object") return null;
    const verdict = (result as { verdict?: unknown }).verdict;
    return verdict === "PROCEED" ||
      verdict === "HUMAN_REQUIRED" ||
      verdict === "DENIED" ||
      verdict === "ESCALATED"
      ? verdict
      : null;
  }

  private static isBoundedIdentifier(value: unknown): value is string {
    return typeof value === "string" && value.length > 0 && value.length <= 200;
  }
}
