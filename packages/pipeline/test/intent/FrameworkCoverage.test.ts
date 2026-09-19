import { readFile, readdir } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { CanonicalIntentHasher } from "../../src/intent/CanonicalIntentHasher.js";
import type { AgentProposal, TrustedIntentContext } from "../../src/intent/ExecutionIntent.js";
import { AuthorityIntentBindingSchema } from "../../src/intent/IntentBindingSchema.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type { JsonObject } from "../../src/intent/JsonValue.js";

/**
 * The framework coverage files under conformance/frameworks: a tool-call
 * record in the framework's own shape, the proposal it becomes, the trusted
 * context the runtime adds, and the binding, bytes and hash that result.
 * The mapping from record to proposal is the whole adapter, and it is
 * written here once per framework, the way an integration writes it.
 */
const FRAMEWORKS_DIR = new URL("../../../../conformance/frameworks/", import.meta.url);

const CAPABILITIES = [
  "action_identity",
  "parameters",
  "target_identity",
  "principal",
  "expiry",
  "idempotency",
  "intent_digest",
  "effect_correlation",
] as const;
const LABELS = new Set(["native", "adapter", "not_represented", "not_tested"]);

interface CoverageFile {
  readonly framework: "openai" | "vercel" | "langchain";
  readonly record: Record<string, unknown>;
  readonly proposal: AgentProposal;
  readonly trusted_context: TrustedIntentContext;
  readonly capture: { intent_id: string; captured_at: string; ttl_seconds: number };
  readonly binding: JsonObject;
  readonly canonical_json: string;
  readonly intent_hash: string;
  readonly coverage: Record<string, string>;
}

/** The target is the adapter's to name: here, the order the refund is for. */
function target(parameters: JsonObject): string {
  return `shopify:order:${String(parameters["orderId"])}`;
}

/** Each adapter, as an integration would write it: a few lines from the record to the proposal. */
const adapters: Record<
  CoverageFile["framework"],
  (record: Record<string, unknown>) => AgentProposal
> = {
  openai: (record) => {
    // A Responses API function_call item: the arguments are a JSON string.
    const parameters = JSON.parse(record["arguments"] as string) as JsonObject;
    return { action: record["name"] as string, target: target(parameters), parameters };
  },
  vercel: (record) => {
    // An AI SDK tool-call part: the input is already an object.
    const parameters = record["input"] as JsonObject;
    return { action: record["toolName"] as string, target: target(parameters), parameters };
  },
  langchain: (record) => {
    // A LangChain ToolCall: the args are already an object.
    const parameters = record["args"] as JsonObject;
    return { action: record["name"] as string, target: target(parameters), parameters };
  },
};

async function files(): Promise<readonly CoverageFile[]> {
  const names = (await readdir(FRAMEWORKS_DIR)).filter((name) => name.endsWith(".json")).sort();
  return Promise.all(
    names.map(
      async (name) =>
        JSON.parse(await readFile(new URL(name, FRAMEWORKS_DIR), "utf8")) as CoverageFile,
    ),
  );
}

describe("framework coverage", () => {
  it("covers the three frameworks the specification names", async () => {
    expect((await files()).map((file) => file.framework)).toEqual([
      "langchain",
      "openai",
      "vercel",
    ]);
  });

  it("reproduces every file: record to proposal to binding to hash", async () => {
    for (const file of await files()) {
      const proposal = adapters[file.framework](file.record);
      expect(proposal, file.framework).toEqual(file.proposal);
      const capture = new IntentCapture({
        clock: () => new Date(file.capture.captured_at),
        createId: () => file.capture.intent_id,
        ttlSeconds: file.capture.ttl_seconds,
      });
      const captured = capture.capture(proposal, file.trusted_context);
      expect(CanonicalIntentHasher.bindingOf(captured.intent), file.framework).toEqual(
        file.binding,
      );
      expect(captured.canonicalIntent, file.framework).toBe(file.canonical_json);
      expect(captured.intentHash, file.framework).toBe(file.intent_hash);
      expect(AuthorityIntentBindingSchema.safeParse(file.binding).success).toBe(true);
    }
  });

  it("labels every capability with one of the four labels, and means what it says", async () => {
    for (const file of await files()) {
      expect(Object.keys(file.coverage).sort()).toEqual([...CAPABILITIES].sort());
      for (const label of Object.values(file.coverage)) expect(LABELS.has(label)).toBe(true);
      // The action name and a call id the result echoes are in every record.
      expect(file.coverage["action_identity"]).toBe("native");
      expect(file.coverage["effect_correlation"]).toBe("native");
      expect(file.trusted_context.context["tool_call_id"]).toBeDefined();
      // "native" parameters means the record holds the object that is hashed;
      // "adapter" means the adapter had to produce it (here, by parsing text).
      const recordParameters = file.record["input"] ?? file.record["args"];
      if (file.coverage["parameters"] === "native") {
        expect(recordParameters).toEqual(file.proposal.parameters);
      } else {
        expect(recordParameters).toBeUndefined();
        expect(typeof file.record["arguments"]).toBe("string");
      }
      // What the record cannot say, the trusted context says: the binding has it either way.
      for (const capability of ["target_identity", "principal", "expiry", "idempotency"]) {
        expect(file.coverage[capability]).toBe("adapter");
      }
      expect(file.binding["actor"]).toEqual(file.trusted_context.actor);
      expect((file.binding["action"] as JsonObject)["resource"]).toBe(file.proposal.target);
    }
  });
});
