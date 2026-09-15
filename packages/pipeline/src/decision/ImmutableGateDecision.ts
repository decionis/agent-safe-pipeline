import type { GateDecision } from "./DecisionAuthority.js";

export function immutableGateDecision(decision: GateDecision): GateDecision {
  return Object.freeze({
    ...decision,
    reasonCodes: Object.freeze([...decision.reasonCodes]),
    authorization:
      decision.authorization === null ? null : Object.freeze({ ...decision.authorization }),
    ...(decision.evidence === undefined
      ? {}
      : {
          evidence: Object.freeze({
            ...decision.evidence,
            ...(decision.evidence.humanApproval === undefined
              ? {}
              : { humanApproval: Object.freeze({ ...decision.evidence.humanApproval }) }),
          }),
        }),
    ...(decision.managedEscalation === undefined
      ? {}
      : {
          managedEscalation: Object.freeze({
            ...decision.managedEscalation,
            reasonCodes: Object.freeze([...decision.managedEscalation.reasonCodes]),
          }),
        }),
    ...(decision.hosted === undefined
      ? {}
      : {
          hosted: Object.freeze({
            ...decision.hosted,
            reasonCodes: Object.freeze([...decision.hosted.reasonCodes]),
          }),
        }),
  });
}
