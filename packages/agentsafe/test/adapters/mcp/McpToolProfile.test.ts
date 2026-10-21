import { existsSync, readdirSync, readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import {
  createFixtureAuthorityPair,
  McpProfileError,
  McpToolProfile,
  type CapturedIntent,
  type DecisionGate,
  type JsonObject,
} from "@decionis/agent-safe-pipeline";
import { McpGuard } from "../../../src/adapters/mcp/McpGuard.js";
import {
  McpBindingError,
  bindMcpInvocation,
  profiledBinding,
} from "../../../src/adapters/mcp/McpIntentBinder.js";
import type { McpInvocation } from "../../../src/adapters/mcp/McpInvocation.js";

/** The specification's vectors, found by walking up from this file to the repository root. */
function vectorsDirectory(): URL {
  let directory = new URL("./", import.meta.url);
  for (let depth = 0; depth < 8; depth += 1) {
    const candidate = new URL("spec/profiles/mcp/v1/vectors/", directory);
    if (existsSync(candidate)) return candidate;
    directory = new URL("../", directory);
  }
  throw new Error("spec/profiles/mcp/v1/vectors not found above the test");
}

interface Vector {
  readonly description: string;
  readonly definition: unknown;
  readonly invocation?: McpInvocation;
  readonly session?: string;
  readonly expected?: {
    readonly action: string;
    readonly target: string;
    readonly operation: string;
    readonly system: string;
    readonly environment?: string;
    readonly consequential: readonly string[];
    readonly session?: { readonly subject: string };
  };
  readonly refusal?: string;
  readonly error?: string;
}

const VECTORS = vectorsDirectory();
const vectors: [string, Vector][] = readdirSync(VECTORS)
  .filter((name) => name.endsWith(".json"))
  .sort()
  .map((name) => [name, JSON.parse(readFileSync(new URL(name, VECTORS), "utf8")) as Vector]);

/** What one vector's invocation binds to, as the vectors state it, or the code that refused it. */
function bound(vector: Vector): Vector["expected"] | string {
  const profile = McpToolProfile.parse(vector.definition);
  const invocation = vector.invocation!;
  const binding = profiledBinding(profile, invocation.tool);
  if (binding === null) return "MCP_TOOL_NOT_BOUND";
  try {
    const result = bindMcpInvocation(invocation, binding, {
      idempotencyKey: "synthetic-vector",
      ...(vector.session === undefined ? {} : { subject: vector.session }),
    });
    return {
      action: result.proposal.action,
      target: result.proposal.target,
      operation: binding.operation,
      system: binding.system,
      ...(binding.environment === undefined ? {} : { environment: binding.environment }),
      consequential: result.context["mcp_consequential"] as string[],
      ...(result.context["session"] === undefined
        ? {}
        : { session: result.context["session"] as { subject: string } }),
    };
  } catch (error) {
    if (error instanceof McpBindingError) return error.code;
    throw error;
  }
}

describe("agent-safe.profile.mcp/1 vectors, held by the guard's binder", () => {
  it("has vectors for binding, for each subject refusal and for definition refusals", () => {
    const refusals = new Set(vectors.map(([, vector]) => vector.refusal));
    for (const code of ["SUBJECT_MISMATCH", "SUBJECT_ABSENT", "SUBJECT_SESSION_REQUIRED"])
      expect(refusals).toContain(code);
    expect(vectors.filter(([, vector]) => vector.expected !== undefined).length).toBeGreaterThan(2);
    expect(vectors.filter(([, vector]) => vector.error !== undefined).length).toBeGreaterThan(5);
  });

  it.each(vectors)("%s", (_name, vector) => {
    if (vector.error !== undefined) {
      let code = "no refusal";
      try {
        McpToolProfile.parse(vector.definition);
      } catch (error) {
        code = error instanceof McpProfileError ? error.code : String(error);
      }
      expect(code).toBe(vector.error);
      return;
    }
    expect(bound(vector)).toEqual(vector.refusal ?? vector.expected);
  });
});

describe("McpGuard over a tool profile", () => {
  const definition = JSON.parse(
    readFileSync(new URL("binds-from-profile.json", VECTORS), "utf8"),
  ) as Vector;
  const profile = McpToolProfile.parse(definition.definition);

  function setup() {
    const invoke = vi.fn(async (args: JsonObject) => ({ updated: args["customerNumber"] }));
    const seen: CapturedIntent[] = [];
    const pair = createFixtureAuthorityPair(() => "ALLOW", { unsafeAllowDevelopmentFixture: true });
    const authority = {
      evaluate: async (captured: CapturedIntent): Promise<DecisionGate> => {
        seen.push(captured);
        return await pair.authority.evaluate(captured);
      },
    };
    const guard = new McpGuard({
      tools: [{ tool: "update_credit_limit", invoke }],
      profile,
      authority,
      verifier: pair.verifier,
      tenantId: "00000000-0000-4000-8000-000000000004",
      actor: { id: "synthetic-mcp-agent", type: "AI_AGENT" },
    });
    return { invoke, seen, guard };
  }

  it("runs a profiled tool once, for the session's customer, and states it to the authority", async () => {
    const { invoke, seen, guard } = setup();
    expect(guard.governs("update_credit_limit")).toBe(true);
    expect(guard.governs("refresh_exchange_rates")).toBe(false);
    const outcome = await guard.guard(
      { tool: "update_credit_limit", arguments: { customerNumber: "C-10000", creditLimit: 2500 } },
      { subject: "C-10000" },
    );
    expect(outcome).toMatchObject({ executed: true, verdict: "ALLOW" });
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(seen[0]?.intent).toMatchObject({
      action: "customer.credit_limit.update",
      target: "erp:customer:C-10000",
      downstreamTarget: {
        system: "erp.example",
        operation: "customers.updateCreditLimit",
        environment: "test",
      },
    });
    expect(seen[0]?.intent.context["session"]).toEqual({ subject: "C-10000" });
  });

  it("refuses another customer, or no session, before the authority is asked", async () => {
    const { invoke, seen, guard } = setup();
    const other = await guard.guard(
      { tool: "update_credit_limit", arguments: { customerNumber: "C-20000", creditLimit: 1 } },
      { subject: "C-10000" },
    );
    expect(other).toEqual({
      executed: false,
      intentHash: null,
      verdict: null,
      dossierId: null,
      reason: "SUBJECT_MISMATCH",
    });
    const none = await guard.guard({
      tool: "update_credit_limit",
      arguments: { customerNumber: "C-10000", creditLimit: 1 },
    });
    expect(none).toMatchObject({ executed: false, reason: "SUBJECT_SESSION_REQUIRED" });
    expect(invoke).not.toHaveBeenCalled();
    expect(seen).toEqual([]);
  });

  it("refuses at construction a profiled tool the profile does not declare, or one named twice", () => {
    const base = {
      authority: createFixtureAuthorityPair(() => "ALLOW", { unsafeAllowDevelopmentFixture: true })
        .authority,
      verifier: createFixtureAuthorityPair(() => "ALLOW", { unsafeAllowDevelopmentFixture: true })
        .verifier,
      tenantId: "00000000-0000-4000-8000-000000000004",
      actor: { id: "synthetic-mcp-agent", type: "AI_AGENT" },
    };
    const invoke = async (): Promise<null> => null;
    expect(
      () => new McpGuard({ ...base, profile, tools: [{ tool: "delete_customer", invoke }] }),
    ).toThrow("MCP_TOOL_NOT_PROFILED");
    expect(
      () => new McpGuard({ ...base, tools: [{ tool: "update_credit_limit", invoke }] }),
    ).toThrow("MCP_TOOL_NOT_PROFILED");
    expect(
      () =>
        new McpGuard({
          ...base,
          profile,
          tools: [
            { tool: "update_credit_limit", invoke },
            { tool: "update_credit_limit", invoke },
          ],
        }),
    ).toThrow("MCP_TOOL_DUPLICATE");
  });
});
