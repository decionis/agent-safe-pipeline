import { describe, expect, it } from "vitest";
import type { Principal } from "../../src/identity/PrincipalRegistry.js";
import {
  assertSeparationOfDuties,
  separationViolated,
} from "../../src/identity/SeparationOfDuties.js";

const proposer = (id: string, actorId: string): Principal => ({
  id,
  role: "PROPOSER",
  tenantId: "00000000-0000-4000-8000-000000000007",
  actor: { id: actorId, type: "AI_AGENT" },
  allowedActions: new Set(["forward_request"]),
  scopes: new Set(),
  credential: { kind: "BEARER", digest: () => Buffer.alloc(32) },
  rateLimit: null,
});
const operator = (id: string): Principal => ({
  id,
  role: "OPERATOR",
  tenantId: null,
  actor: null,
  allowedActions: new Set(),
  scopes: new Set(["status"]),
  credential: { kind: "MTLS", sanUri: `spiffe://synthetic.example/${id}`, fingerprint: null },
  rateLimit: null,
});

describe("separation of duties", () => {
  it("refuses a configuration whose approving person is also a proposer, by id or by actor", () => {
    const principals = [proposer("workflow", "payout-agent"), operator("oncall")];
    expect(() => assertSeparationOfDuties(principals, null)).not.toThrow();
    expect(() => assertSeparationOfDuties(principals, "synthetic-approver")).not.toThrow();
    expect(() => assertSeparationOfDuties(principals, "oncall")).not.toThrow();
    expect(() => assertSeparationOfDuties(principals, "workflow")).toThrow(
      "CONFIG_INVALID: PRESENCE_APPROVER_ID (separation of duties: also proposer workflow)",
    );
    expect(() => assertSeparationOfDuties(principals, "payout-agent")).toThrow(
      "CONFIG_INVALID: PRESENCE_APPROVER_ID (separation of duties: also proposer workflow)",
    );
  });

  it("flags a proposal the approving person or an operator would be approving for themselves", () => {
    const caller = proposer("workflow", "payout-agent");
    const operators = [operator("oncall"), operator("payout-agent")];
    expect(separationViolated(caller, null, [])).toBe(false);
    expect(separationViolated(caller, "synthetic-approver", [operator("oncall")])).toBe(false);
    expect(separationViolated(caller, "workflow", [])).toBe(true);
    expect(separationViolated(caller, "payout-agent", [])).toBe(true);
    expect(separationViolated(caller, null, operators)).toBe(true);
    expect(separationViolated(caller, null, [operator("workflow")])).toBe(true);
    expect(separationViolated({ ...caller, actor: null }, "payout-agent", operators)).toBe(false);
  });
});
