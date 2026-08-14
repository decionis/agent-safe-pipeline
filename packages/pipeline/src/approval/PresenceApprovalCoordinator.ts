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
    return this.presence.gate(
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
  }

  public async resolveAndReauthorize(
    captured: CapturedIntent,
    result: PresenceGateResult,
  ): Promise<GateDecision> {
    const terminal =
      result.verdict === "HUMAN_REQUIRED" && result.request_id !== undefined
        ? await this.presence.outcome(result.request_id)
        : result;
    if (terminal.verdict !== "PROCEED") {
      return FailClosedDecision.create(captured.intentHash, `PRESENCE_${terminal.verdict}`);
    }
    const evidence = PresenceApprovalCoordinator.evidenceOf(terminal);
    if (evidence === null) {
      return FailClosedDecision.create(captured.intentHash, "PRESENCE_PROOF_MISSING");
    }
    return this.authority.evaluate(captured, { humanApproval: evidence });
  }

  private static evidenceOf(result: PresenceGateResult): HumanApprovalEvidence | null {
    if (result.receipt_dossier_id !== undefined && result.request_id !== undefined) {
      return {
        provider: "presence",
        requestId: result.request_id,
        receiptDossierId: result.receipt_dossier_id,
      };
    }
    return null;
  }
}
