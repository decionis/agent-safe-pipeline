import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import {
  createFixtureAuthorityPair,
  type DecisionAuthority,
  type GateDecision,
  type JsonObject,
} from "@decionis/agent-safe-pipeline";
import { jcsDigest } from "../../../src/adapters/JcsDigest.js";
import { McpGuard, type McpTool } from "../../../src/adapters/mcp/McpGuard.js";
import type { McpToolBinding } from "../../../src/adapters/mcp/McpInvocation.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000004";
const ACTOR = { id: "synthetic-mcp-agent", type: "AI_AGENT" } as const;

const BINDING: McpToolBinding = {
  tool: "delete_customer",
  action: "delete_customer",
  system: "crm",
  operation: "delete_customer",
  target: "crm:customer:{customerId}",
  consequential: ["customerId"],
  argumentsSchema: z
    .object({ customerId: z.string().min(1).max(120), reason: z.string().max(200).optional() })
    .strict() as unknown as z.ZodType<JsonObject>,
};

function setup(verdict: "ALLOW" | "BLOCK" | "ESCALATE" = "ALLOW") {
  const invoke = vi.fn(async (args: JsonObject) => ({ deleted: args["customerId"] }));
  const tool: McpTool = { binding: BINDING, invoke };
  const pair = createFixtureAuthorityPair(() => verdict, { unsafeAllowDevelopmentFixture: true });
  const guard = new McpGuard({
    tools: [tool],
    authority: pair.authority,
    verifier: pair.verifier,
    tenantId: TENANT_ID,
    actor: ACTOR,
  });
  return { invoke, guard, pair };
}

describe("the MCP execution boundary", () => {
  it("runs a tool exactly once, behind a claimed grant, with the arguments a policy saw", async () => {
    const { invoke, guard } = setup();
    const outcome = await guard.guard({
      tool: "delete_customer",
      arguments: { customerId: "synthetic-42" },
    });

    expect(outcome).toMatchObject({ executed: true, verdict: "ALLOW" });
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith({ customerId: "synthetic-42" });
  });

  it("refuses the invocation when the policy does, and the tool is never reached", async () => {
    for (const verdict of ["BLOCK", "ESCALATE"] as const) {
      const { invoke, guard } = setup(verdict);
      const outcome = await guard.guard({
        tool: "delete_customer",
        arguments: { customerId: "synthetic-42" },
      });

      expect(outcome).toMatchObject({ executed: false, verdict, reason: "DECISION_NOT_ALLOW" });
      expect(invoke).not.toHaveBeenCalled();
    }
  });

  /**
   * The acceptance criterion this whole adapter exists for. MCP decided how
   * the tool is called; whether *this* call may run is decided elsewhere, and
   * the arguments the authority saw are the arguments the tool receives.
   */
  it("refuses an authority issued for one set of arguments, presented with another", async () => {
    const { invoke, pair } = setup();

    // A real ALLOW, for deleting the synthetic customer.
    let issued: GateDecision | null = null;
    const observed = new McpGuard({
      tools: [{ binding: BINDING, invoke: async () => ({ ok: true }) }],
      authority: {
        evaluate: async (captured) => {
          issued = await pair.authority.evaluate(captured);
          return issued;
        },
      },
      verifier: pair.verifier,
      tenantId: TENANT_ID,
      actor: ACTOR,
    });
    await observed.guard({ tool: "delete_customer", arguments: { customerId: "synthetic-42" } });
    expect(issued).not.toBeNull();

    // The model now asks for customer 9000 and the authority for 42 is
    // presented for it. The grant is genuine; the intent it covers is not
    // this one.
    const replaying = new McpGuard({
      tools: [{ binding: BINDING, invoke }],
      authority: { evaluate: async () => issued as unknown as GateDecision },
      verifier: pair.verifier,
      tenantId: TENANT_ID,
      actor: ACTOR,
    });
    const outcome = await replaying.guard({
      tool: "delete_customer",
      arguments: { customerId: "synthetic-9000" },
    });

    expect(outcome).toMatchObject({ executed: false, reason: "INTENT_BINDING_MISMATCH" });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("gives the tool the arguments the intent bound, digest for digest", async () => {
    const { pair } = setup();
    let seen: JsonObject | null = null;
    let boundDigest: unknown = null;
    const guard = new McpGuard({
      tools: [
        {
          binding: BINDING,
          invoke: async (args) => {
            seen = args;
            return { ok: true };
          },
        },
      ],
      authority: {
        evaluate: async (captured) => {
          boundDigest = captured.intent.context["mcp_arguments_digest"];
          // The caller's own copy is not what the tool will receive: the
          // parameters come off the hash-bound intent, and the handler
          // compares their canonical digest to this one before dispatching.
          Object.assign(supplied, { customerId: "synthetic-9000" });
          return await pair.authority.evaluate(captured);
        },
      },
      verifier: pair.verifier,
      tenantId: TENANT_ID,
      actor: ACTOR,
    });
    const supplied: Record<string, string> = { customerId: "synthetic-42", reason: "duplicate" };
    await guard.guard({ tool: "delete_customer", arguments: { ...supplied } });

    expect(seen).toEqual({ customerId: "synthetic-42", reason: "duplicate" });
    expect(jcsDigest(seen as unknown as JsonObject)).toBe(boundDigest);
  });

  it("refuses a tool nobody bound rather than letting it through", async () => {
    const { invoke, guard } = setup();
    expect(guard.governs("delete_customer")).toBe(true);
    expect(guard.governs("send_email")).toBe(false);

    const outcome = await guard.guard({ tool: "send_email", arguments: { to: "a@example.com" } });
    // Refused before the authority was asked: no decision, no dossier, and
    // adding a consequential tool cannot quietly add an ungoverned path.
    expect(outcome).toMatchObject({
      executed: false,
      intentHash: null,
      verdict: null,
      dossierId: null,
      reason: "MCP_TOOL_NOT_BOUND",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("refuses an argument the tool's schema does not name, rather than dropping it", async () => {
    const { invoke, guard } = setup();
    const outcome = await guard.guard({
      tool: "delete_customer",
      arguments: { customerId: "synthetic-42", alsoDeleteBackups: true },
    });

    expect(outcome).toMatchObject({ executed: false, reason: "MCP_ARGUMENTS_INVALID" });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("refuses a target it cannot resolve from the arguments", async () => {
    const { invoke, guard } = setup();
    expect(
      await guard.guard({ tool: "delete_customer", arguments: { customerId: "" } }),
    ).toMatchObject({ executed: false, reason: "MCP_ARGUMENTS_INVALID" });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("binds the tool, the canonical arguments and the consequential names into the intent", async () => {
    const captured: JsonObject[] = [];
    const { pair } = setup();
    const recording: DecisionAuthority = {
      evaluate: async (intent) => {
        captured.push(intent.intent.context);
        return await pair.authority.evaluate(intent);
      },
    };
    const guard = new McpGuard({
      tools: [{ binding: BINDING, invoke: async () => ({ ok: true }) }],
      authority: recording,
      verifier: pair.verifier,
      tenantId: TENANT_ID,
      actor: ACTOR,
    });
    await guard.guard({
      tool: "delete_customer",
      arguments: { customerId: "synthetic-42" },
      server: "crm-tools",
      transport: "stdio",
      principal: "agent-7",
    });

    expect(captured[0]).toMatchObject({
      ingress: "mcp",
      mcp_tool: "delete_customer",
      mcp_server: "crm-tools",
      mcp_transport: "stdio",
      mcp_consequential: ["customerId"],
      claimed_principal: "agent-7",
    });
    expect(captured[0]?.["mcp_arguments_digest"]).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
