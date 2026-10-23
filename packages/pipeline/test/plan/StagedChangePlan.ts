import type { GovernedPlan } from "../../src/plan/GovernedPlan.js";

/**
 * The staged change the demo runs, and the vector Decionis pins: a change
 * ticket, a drain, a deploy, a re-enable, and a rollback that may follow only
 * a failed deploy. Synthetic throughout.
 */
export const STAGED_CHANGE: GovernedPlan = {
  version: "agent-safe.plan/1",
  plan_id: "chg-1042",
  tenant_id: "00000000-0000-4000-8000-000000000010",
  steps: [
    { step_id: "open-change", action: "change.open", target: "change:CHG-1042" },
    { step_id: "drain", action: "traffic.drain", target: "lb:prod-eu/web" },
    {
      step_id: "deploy",
      action: "deployment.deploy",
      target: "deployment:prod-eu/web",
      parameters: { image: "registry.example/web:2.4.1" },
    },
    { step_id: "re-enable", action: "traffic.enable", target: "lb:prod-eu/web" },
    {
      step_id: "rollback",
      action: "deployment.rollback",
      target: "deployment:prod-eu/*",
      compensates: ["deploy"],
    },
  ],
  edges: [
    { from: "open-change", to: "drain", coupling: "ordered" },
    { from: "drain", to: "deploy", coupling: "ordered" },
    { from: "deploy", to: "re-enable", coupling: "all_or_escalate" },
  ],
  partial_commit: { admissible: [], otherwise: "ESCALATE" },
};

/** Pinned in Decionis too: both canonicalize the plan the same way, or a stamp never matches. */
export const STAGED_CHANGE_DIGEST =
  "sha256:e56112c5cb8de3037a62973d46881615201cc730f2effddca28653cff029b434";
