import { readFile, readdir } from "node:fs/promises";
import { describe, expect, expectTypeOf, it } from "vitest";
import type { z } from "zod";
import type { AuthorityIntentBinding } from "../../src/intent/ExecutionIntent.js";
import {
  AuthorityIntentBindingSchema,
  INTENT_SCHEMA_ID,
  intentBindingJsonSchema,
} from "../../src/intent/IntentBindingSchema.js";
import type { JsonValue } from "../../src/intent/JsonValue.js";

const VECTORS_DIR = new URL("../../../../conformance/vectors/", import.meta.url);
const PINNED = new URL("../../../../conformance/agent-safe-intent-v1.json", import.meta.url);
const PUBLISHED = new URL("../../../../spec/intent/v1/schema.json", import.meta.url);

interface Vector {
  readonly binding: JsonValue;
  readonly mutations?: readonly { readonly path: string; readonly binding: JsonValue }[];
}

/** Whether a vector's `binding` is a whole intent binding, as opposed to a canonicalization case over any JSON object. */
function isIntentBinding(value: JsonValue): boolean {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    value["protocol_version"] === "agent-safe.intent/1"
  );
}

async function everyBinding(): Promise<readonly { name: string; binding: JsonValue }[]> {
  const pinned = JSON.parse(await readFile(PINNED, "utf8")) as Vector;
  const bindings = [{ name: "agent-safe-intent-v1.json", binding: pinned.binding }];
  for (const file of (await readdir(VECTORS_DIR)).filter((name) => name.endsWith(".json"))) {
    const vector = JSON.parse(await readFile(new URL(file, VECTORS_DIR), "utf8")) as Vector;
    if (!isIntentBinding(vector.binding)) continue;
    bindings.push({ name: file, binding: vector.binding });
    for (const mutation of vector.mutations ?? []) {
      bindings.push({ name: `${file} ${mutation.path}`, binding: mutation.binding });
    }
  }
  return bindings;
}

describe("the agent-safe.intent/1 binding schema", () => {
  it("accepts every published vector, base and mutation alike", async () => {
    const bindings = await everyBinding();
    // The pinned vector, the Compromised Principal base and its eight mutations at least.
    expect(bindings.length).toBeGreaterThanOrEqual(10);
    for (const { name, binding } of bindings) {
      const result = AuthorityIntentBindingSchema.safeParse(binding);
      expect(result.success, `${name}: ${JSON.stringify(result.error?.issues ?? [])}`).toBe(true);
    }
  });

  it("accepts, by type, everything the hasher produces", () => {
    // Whatever `bindingOf` returns is valid input to the schema: the wire
    // interface extends the schema's input type, so the two cannot drift apart.
    expectTypeOf<AuthorityIntentBinding>().toExtend<z.input<typeof AuthorityIntentBindingSchema>>();
  });

  it("refuses what the contract refuses: unknown keys, another version, a missing idempotency key", async () => {
    const first = (await everyBinding())[0];
    if (first === undefined) throw new Error("no vector");
    const base = first.binding as Record<string, JsonValue>;
    const refused: Record<string, unknown>[] = [
      { ...base, policy_projection: {} },
      { ...base, protocol_version: "agent-safe.intent/2" },
      { ...base, actor: { ...(base["actor"] as object), extra: "x" } },
      { ...base, context: { source: "conformance" } },
      { ...base, expected_effect_digest: "sha256:short" },
      { ...base, downstream_target: { system: "shopify" } },
    ];
    for (const document of refused) {
      expect(AuthorityIntentBindingSchema.safeParse(document).success).toBe(false);
    }
    expect(
      AuthorityIntentBindingSchema.safeParse({
        ...base,
        expected_effect_digest: `sha256:${"a".repeat(64)}`,
        context: { ...(base["context"] as object), nested: { list: [1, "two", null] } },
      }).success,
    ).toBe(true);
  });

  it("is the JSON Schema published under spec/intent/v1, byte for byte", async () => {
    const document = intentBindingJsonSchema();
    expect(document["$id"]).toBe(INTENT_SCHEMA_ID);
    expect(document["$schema"]).toMatch(/draft\/2020-12\/schema$/);
    expect(document["additionalProperties"]).toBe(false);
    expect((document["$defs"] as Record<string, unknown>)["JsonValue"]).toBeDefined();
    expect(await readFile(PUBLISHED, "utf8")).toBe(`${JSON.stringify(document, null, 2)}\n`);
  });
});
