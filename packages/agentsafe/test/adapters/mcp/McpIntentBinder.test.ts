import { z } from "zod";
import { describe, expect, it } from "vitest";
import type { JsonObject } from "@decionis/agent-safe-pipeline";
import { jcsDigest } from "../../../src/adapters/JcsDigest.js";
import {
  McpBindingError,
  bindMcpInvocation,
  bindingFor,
} from "../../../src/adapters/mcp/McpIntentBinder.js";
import {
  MAX_TEMPLATE_PLACEHOLDERS,
  fillTarget,
  type McpToolBinding,
} from "../../../src/adapters/mcp/McpInvocation.js";

const BINDING: McpToolBinding = {
  tool: "transfer_funds",
  action: "payment.send",
  system: "core",
  operation: "payment.send",
  environment: "production",
  target: "core:account:{account}",
  consequential: ["amount", "account", "note"],
  argumentsSchema: z
    .object({
      account: z.string().min(1).max(64),
      amount: z.number().positive(),
      note: z.string().max(200).optional(),
    })
    .strict() as unknown as z.ZodType<JsonObject>,
};

const TRUSTED = { idempotencyKey: "mcp-1" };

describe("binding an MCP invocation to an action", () => {
  it("derives the action and the target rather than accepting them from the caller", () => {
    const bound = bindMcpInvocation(
      { tool: "transfer_funds", arguments: { account: "GB33", amount: 50_000 } },
      BINDING,
      TRUSTED,
    );

    expect(bound.proposal).toEqual({
      action: "payment.send",
      target: "core:account:GB33",
      parameters: { account: "GB33", amount: 50_000 },
    });
    expect(bound.context).toMatchObject({
      ingress: "mcp",
      mcp_tool: "transfer_funds",
      mcp_consequential: ["amount", "account"],
    });
    expect(bound.argumentsDigest).toBe(jcsDigest({ account: "GB33", amount: 50_000 }));
    expect(bound.idempotencyKey).toBe("mcp-1");
  });

  it("prefers the host's own principal to the one the caller claimed", () => {
    const claimed = bindMcpInvocation(
      { tool: "transfer_funds", arguments: { account: "GB33", amount: 1 }, principal: "agent-7" },
      BINDING,
      TRUSTED,
    );
    expect(claimed.context["claimed_principal"]).toBe("agent-7");

    const authenticated = bindMcpInvocation(
      { tool: "transfer_funds", arguments: { account: "GB33", amount: 1 }, principal: "agent-7" },
      BINDING,
      { ...TRUSTED, principal: "treasury-agent" },
    );
    expect(authenticated.context["claimed_principal"]).toBe("treasury-agent");

    const neither = bindMcpInvocation(
      { tool: "transfer_funds", arguments: { account: "GB33", amount: 1 } },
      BINDING,
      TRUSTED,
    );
    expect(Object.hasOwn(neither.context, "claimed_principal")).toBe(false);
  });

  it("takes the caller's idempotency key and correlation when it has them", () => {
    const bound = bindMcpInvocation(
      {
        tool: "transfer_funds",
        arguments: { account: "GB33", amount: 1 },
        idempotencyKey: "run-9",
        correlationId: "trace-9",
      },
      BINDING,
      TRUSTED,
    );
    expect(bound.idempotencyKey).toBe("run-9");
    expect(bound.correlationId).toBe("trace-9");
  });

  it("refuses everything it cannot bind, before the authority is asked", () => {
    const refusals: [unknown, string][] = [
      [{ tool: "something_else", arguments: {} }, "MCP_TOOL_MISMATCH"],
      [{ tool: "transfer_funds", arguments: { account: "GB33" } }, "MCP_ARGUMENTS_INVALID"],
      [
        { tool: "transfer_funds", arguments: { account: "GB33", amount: 1, extra: true } },
        "MCP_ARGUMENTS_INVALID",
      ],
      [
        { tool: "transfer_funds", arguments: { account: "GB33", amount: -1 } },
        "MCP_ARGUMENTS_INVALID",
      ],
      [{ tool: "transfer funds", arguments: {} }, "MCP_INVOCATION_INVALID"],
      [{ tool: "transfer_funds", arguments: {}, unexpected: 1 }, "MCP_INVOCATION_INVALID"],
    ];
    for (const [invocation, code] of refusals) {
      expect(() => bindMcpInvocation(invocation as never, BINDING, TRUSTED)).toThrow(
        new McpBindingError(code as never),
      );
    }
  });

  it("refuses a target the arguments cannot fill", () => {
    const unfillable: McpToolBinding = { ...BINDING, target: "core:account:{missing}" };
    expect(() =>
      bindMcpInvocation(
        { tool: "transfer_funds", arguments: { account: "GB33", amount: 1 } },
        unfillable,
        TRUSTED,
      ),
    ).toThrow("MCP_TARGET_UNRESOLVED");
  });

  it("names itself and its code, so a caller can tell one refusal from another", () => {
    const error = new McpBindingError("MCP_TOOL_NOT_BOUND");
    expect(error.name).toBe("McpBindingError");
    expect(error.code).toBe("MCP_TOOL_NOT_BOUND");
    expect(error.message).toBe("MCP_TOOL_NOT_BOUND");
    expect(error).toBeInstanceOf(Error);
  });

  it("refuses a tool nobody bound", () => {
    const bindings = new Map([[BINDING.tool, BINDING]]);
    expect(bindingFor(bindings, "transfer_funds")).toBe(BINDING);
    expect(() => bindingFor(bindings, "send_email")).toThrow("MCP_TOOL_NOT_BOUND");
  });
});

describe("filling a target template", () => {
  it("substitutes scalars and leaves the rest of the template alone", () => {
    expect(fillTarget("core:account:{account}", { account: "GB33" })).toBe("core:account:GB33");
    expect(
      fillTarget("k8s:{cluster}/{ns}:{replicas}", { cluster: "eu", ns: "a", replicas: 96 }),
    ).toBe("k8s:eu/a:96");
    expect(fillTarget("flag:{on}", { on: true })).toBe("flag:true");
    expect(fillTarget("crm:customer", {})).toBe("crm:customer");
  });

  it("refuses rather than producing a target with a hole in it", () => {
    expect(fillTarget("core:{missing}", { account: "GB33" })).toBeNull();
    // An empty placeholder names no argument, even if one is named "".
    expect(fillTarget("core:{}", { "": "anything" })).toBeNull();
    expect(fillTarget("core:{account", { account: "GB33" })).toBeNull();
    expect(fillTarget("core:}", {})).toBeNull();
    expect(fillTarget("core:{account}", { account: "" })).toBeNull();
    expect(fillTarget("core:{account}", { account: null })).toBeNull();
    expect(fillTarget("core:{account}", { account: { nested: 1 } })).toBeNull();
    expect(fillTarget("core:{account}", { account: [1] })).toBeNull();
    expect(fillTarget("core:{n}", { n: Number.NaN })).toBeNull();
    expect(fillTarget("", {})).toBeNull();
    expect(fillTarget("x:{v}", { v: "y".repeat(500) })).toBeNull();
  });

  it("bounds how many placeholders one template may have", () => {
    const names = Array.from({ length: MAX_TEMPLATE_PLACEHOLDERS + 1 }, (_, at) => `a${at}`);
    const args = Object.fromEntries(names.map((name) => [name, "x"]));
    expect(fillTarget(names.map((name) => `{${name}}`).join(""), args)).toBeNull();
    expect(
      fillTarget(
        names
          .slice(0, MAX_TEMPLATE_PLACEHOLDERS)
          .map((name) => `{${name}}`)
          .join(""),
        args,
      ),
    ).toBe("x".repeat(MAX_TEMPLATE_PLACEHOLDERS));
  });
});
