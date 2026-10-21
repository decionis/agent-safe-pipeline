import { existsSync, readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  McpProfileError,
  McpToolProfile,
  mcpProfileJsonSchema,
} from "../../src/profile/McpToolProfile.js";

/** The specification, found by walking up from this file to the repository root. */
function specification(): URL {
  let directory = new URL("./", import.meta.url);
  for (let depth = 0; depth < 8; depth += 1) {
    const candidate = new URL("spec/profiles/mcp/v1/", directory);
    if (existsSync(candidate)) return candidate;
    directory = new URL("../", directory);
  }
  throw new Error("spec/profiles/mcp/v1 not found above the test");
}

const SPEC = specification();
const json = <T>(url: URL): T => JSON.parse(readFileSync(url, "utf8")) as T;
const vectors = readdirSync(new URL("vectors/", SPEC))
  .filter((name) => name.endsWith(".json"))
  .sort()
  .map(
    (name) =>
      [name, json<{ definition: unknown; error?: string }>(new URL(`vectors/${name}`, SPEC))] as [
        string,
        { definition: unknown; error?: string },
      ],
  );

function refusal(work: () => unknown): string {
  try {
    work();
  } catch (error) {
    return error instanceof McpProfileError ? error.code : `unexpected ${String(error)}`;
  }
  return "no refusal";
}

describe("agent-safe.profile.mcp/1 definitions", () => {
  it.each(vectors)("%s parses or is refused as its vector says", (_name, vector) => {
    if (vector.error !== undefined) {
      expect(refusal(() => McpToolProfile.parse(vector.definition))).toBe(vector.error);
    } else {
      expect(McpToolProfile.parse(vector.definition).tools().length).toBeGreaterThan(0);
    }
  });

  const profile = McpToolProfile.parse(
    json<{ definition: unknown }>(new URL("vectors/binds-from-profile.json", SPEC)).definition,
  );

  it("names its tools, and nothing for a tool it does not declare", () => {
    expect(profile.id).toBe("erp/mcp/v1");
    expect(profile.tools()).toEqual(["update_credit_limit", "refresh_exchange_rates"]);
    expect(profile.tool("delete_customer")).toBeNull();
    expect(refusal(() => profile.argumentsSchema("delete_customer"))).toBe("MCP_PROFILE_INVALID");
  });

  it("accepts the declared arguments of their types, and refuses any other", () => {
    const schema = profile.argumentsSchema("update_credit_limit");
    expect(schema).toBe(profile.argumentsSchema("update_credit_limit"));
    expect(schema.safeParse({ customerNumber: "C-1", creditLimit: 10 }).success).toBe(true);
    expect(schema.safeParse({ customerNumber: "C-1" }).success).toBe(false);
    expect(schema.safeParse({ customerNumber: "C-1", creditLimit: Infinity }).success).toBe(false);
    expect(schema.safeParse({ customerNumber: 1, creditLimit: 10 }).success).toBe(false);
    expect(schema.safeParse({ customerNumber: "C-1", creditLimit: 10, extra: true }).success).toBe(
      false,
    );
    const rates = profile.argumentsSchema("refresh_exchange_rates");
    expect(rates.safeParse({ currencies: ["EUR", { code: "USD" }] }).success).toBe(true);
    expect(rates.safeParse({ currencies: "EUR" }).success).toBe(false);
  });

  it("checks a call's subject against the session's", () => {
    const tool = profile.tool("update_credit_limit")!;
    const rates = profile.tool("refresh_exchange_rates")!;
    expect(McpToolProfile.checkSubject(tool, { customerNumber: "C-1" }, "C-1")).toBe("MATCH");
    expect(McpToolProfile.checkSubject(tool, { customerNumber: "C-2" }, "C-1")).toBe(
      "SUBJECT_MISMATCH",
    );
    expect(McpToolProfile.checkSubject(tool, { customerNumber: true }, "C-1")).toBe(
      "SUBJECT_ABSENT",
    );
    expect(McpToolProfile.checkSubject(tool, { customerNumber: 7 }, "7")).toBe("MATCH");
    expect(McpToolProfile.checkSubject(tool, {}, "C-1")).toBe("SUBJECT_ABSENT");
    expect(McpToolProfile.checkSubject(rates, {}, "C-1")).toBe("MATCH");
    expect(McpToolProfile.subjectOf(rates, {})).toBeUndefined();
  });

  it("refuses an argument of every other type that bounds its length, and a long target", () => {
    const definition = (argument: Record<string, unknown>, target = "erp:x") => ({
      profile: "agent-safe.profile.mcp/1",
      id: "erp/mcp/v1",
      title: "Synthetic ERP MCP server",
      system: "erp.example",
      tools: [
        {
          tool: "t",
          action: "t.run",
          operation: "t.run",
          summary: "Run t.",
          target,
          consequential: [],
          arguments: { value: argument },
        },
      ],
    });
    for (const type of ["integer", "boolean", "array", "object"]) {
      expect(refusal(() => McpToolProfile.parse(definition({ type, maxLength: 3 })))).toBe(
        "MCP_PROFILE_INVALID",
      );
    }
    const many = Array.from({ length: 17 }, () => "{value}").join(":");
    expect(
      refusal(() => McpToolProfile.parse(definition({ type: "string", required: true }, many))),
    ).toBe("MCP_PROFILE_INVALID");
    expect(
      refusal(() => McpToolProfile.parse(definition({ type: "string", required: true }, "a}b"))),
    ).toBe("MCP_PROFILE_INVALID");
    expect(
      refusal(() => McpToolProfile.parse(definition({ type: "string", required: true }, "{}"))),
    ).toBe("MCP_PROFILE_INVALID");
  });
});

describe("spec/profiles/mcp/v1/schema.json", () => {
  it("is generated from the validator this package runs", () => {
    expect(json(new URL("schema.json", SPEC))).toEqual(mcpProfileJsonSchema());
  });
});
