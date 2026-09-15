import type { Principal } from "./PrincipalRegistry.js";

/**
 * The person who approves may not be the party that proposes, and a
 * proposer may not also hold the operator's keys. The authority's
 * maker-checker rule stays authoritative; this refuses the obvious
 * self-approval shapes before the authority is asked at all.
 */
export function assertSeparationOfDuties(
  principals: readonly Principal[],
  approverId: string | null,
): void {
  if (approverId === null) return;
  for (const principal of principals) {
    if (principal.role !== "PROPOSER") continue;
    if (principal.id === approverId || principal.actor?.id === approverId) {
      throw new Error(
        `CONFIG_INVALID: PRESENCE_APPROVER_ID (separation of duties: also proposer ${principal.id})`,
      );
    }
  }
}

/** Whether a proposal from this caller would have the approver, or an operator, approving their own work. */
export function separationViolated(
  caller: Principal,
  approverId: string | null,
  operators: readonly Principal[],
): boolean {
  const actorId = caller.actor?.id ?? null;
  if (approverId !== null && (caller.id === approverId || actorId === approverId)) return true;
  return operators.some((operator) => operator.id === caller.id || operator.id === actorId);
}
