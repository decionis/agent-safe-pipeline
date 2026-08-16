import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import fc, {
  type IProperty,
  type JsonValue as FastCheckJsonValue,
  type Parameters as FastCheckParameters,
} from "fast-check";
import { describe, expect, it } from "vitest";
import { CanonicalIntentHasher } from "../../src/intent/CanonicalIntentHasher.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type { ExecutionIntent, TrustedIntentContext } from "../../src/intent/ExecutionIntent.js";
import type { JsonObject, JsonValue } from "../../src/intent/JsonValue.js";

const fixedId = "00000000-0000-4000-8000-000000000001";
const fixedDate = new Date("2026-08-16T10:00:00.000Z");
const forbiddenKeys = new Set(["__proto__", "constructor", "prototype"]);
const seed = 20_260_816;
const configuredRuns = Number.parseInt(process.env.FUZZ_RUNS ?? "1000", 10);
const numRuns = Number.isSafeInteger(configuredRuns)
  ? Math.min(Math.max(configuredRuns, 1), 10_000)
  : 1000;

const trustedContext: TrustedIntentContext = {
  tenantId: "00000000-0000-4000-8000-000000000002",
  actor: { id: "synthetic-fuzz-agent", type: "AI_AGENT", runtime: "test" },
  downstreamTarget: {
    system: "synthetic-commerce",
    operation: "synthetic-operation",
    endpoint: "POST https://api.example/synthetic-operation",
  },
  context: { source: "synthetic-property-fuzz" },
  idempotencyKey: "synthetic-fuzz-idempotency",
};

const capture = new IntentCapture({
  clock: () => fixedDate,
  createId: () => fixedId,
});

function sanitizeJson(value: FastCheckJsonValue): JsonValue {
  if (Array.isArray(value)) return value.map((entry) => sanitizeJson(entry));
  if (value === null || typeof value !== "object") return value;

  const sanitized: JsonObject = {};
  for (const [key, entry] of Object.entries(value)) {
    if (!forbiddenKeys.has(key) && entry !== undefined) {
      sanitized[key] = sanitizeJson(entry);
    }
  }
  return sanitized;
}

function reverseObjectOrder(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map((entry) => reverseObjectOrder(entry));
  if (value === null || typeof value !== "object") return value;

  const reversed: JsonObject = {};
  for (const [key, entry] of Object.entries(value).reverse()) {
    reversed[key] = reverseObjectOrder(entry);
  }
  return reversed;
}

function captureParameters(parameters: JsonObject) {
  return capture.capture(
    {
      action: "synthetic.operation",
      target: "synthetic:resource",
      parameters,
    },
    trustedContext,
  );
}

function readConformanceParameters(): JsonObject[] {
  const conformanceDirectory = new URL("../../../../conformance/", import.meta.url);
  const paths = [
    new URL("agent-safe-intent-v1.json", conformanceDirectory),
    ...readdirSync(new URL("vectors/", conformanceDirectory))
      .filter((path) => path.endsWith(".json"))
      .sort()
      .map((path) => new URL(`vectors/${path}`, conformanceDirectory)),
  ];
  return paths.map((path) => {
    const vector = JSON.parse(readFileSync(path, "utf8")) as {
      binding: JsonObject & { action?: { parameters?: JsonObject } };
    };
    return vector.binding.action?.parameters ?? vector.binding;
  });
}

function recordFailure(error: unknown): void {
  const reportPath = process.env.FUZZ_REPORT_PATH;
  if (reportPath === undefined || reportPath.length === 0) return;
  mkdirSync(dirname(reportPath), { recursive: true });
  writeFileSync(reportPath, `${error instanceof Error ? error.stack : String(error)}\n`, {
    flag: "a",
  });
}

function assertFuzz<Ts>(property: IProperty<Ts>, parameters: FastCheckParameters<Ts> = {}): void {
  try {
    fc.assert(property, {
      seed,
      numRuns,
      interruptAfterTimeLimit: 30_000,
      markInterruptAsFailure: true,
      ...parameters,
    });
  } catch (error) {
    recordFailure(error);
    throw error;
  }
}

const jsonObjectArbitrary = fc
  .dictionary(fc.string({ maxLength: 32 }), fc.jsonValue({ maxDepth: 4 }), { maxKeys: 16 })
  .map((value) => sanitizeJson(value) as JsonObject);

describe("CanonicalIntentHasher property fuzzing", () => {
  it("is deterministic across arbitrary object insertion orders", () => {
    assertFuzz(
      fc.property(jsonObjectArbitrary, (parameters) => {
        const original = captureParameters(parameters);
        const reordered = captureParameters(reverseObjectOrder(parameters) as JsonObject);

        expect(reordered.canonicalIntent).toBe(original.canonicalIntent);
        expect(reordered.intentHash).toBe(original.intentHash);
        expect(original.byteLength).toBe(Buffer.byteLength(original.canonicalIntent, "utf8"));
      }),
      { examples: readConformanceParameters().map((parameters) => [parameters]) },
    );
  });

  it("rejects arbitrary forbidden keys without mutating Object.prototype", () => {
    assertFuzz(
      fc.property(
        fc.constantFrom(...forbiddenKeys),
        fc.jsonValue({ maxDepth: 3 }),
        (forbiddenKey, payload) => {
          const parameters = JSON.parse(
            JSON.stringify({ safe: { [forbiddenKey]: payload } }),
          ) as JsonObject;

          expect(() => captureParameters(parameters)).toThrow("UNSAFE_INTENT_KEY");
          expect(Object.prototype).not.toHaveProperty("pollutedByAgentSafeFuzz");
        },
      ),
    );
  });

  it("rejects arbitrary non-finite numbers at the hashing boundary", () => {
    const baseIntent = captureParameters({ value: 0 }).intent;
    assertFuzz(
      fc.property(
        fc.constantFrom(Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY),
        (value) => {
          const intent = {
            ...baseIntent,
            parameters: { value },
          } as ExecutionIntent;
          expect(() => new CanonicalIntentHasher().capture(intent)).toThrow("INVALID_NUMBER");
        },
      ),
    );
  });

  it("rejects arrays beyond arbitrary configured boundaries", () => {
    const baseIntent = captureParameters({ values: [] }).intent;
    assertFuzz(
      fc.property(
        fc.integer({ min: 1, max: 64 }),
        fc.integer({ min: 1, max: 16 }),
        (limit, excess) => {
          const intent = {
            ...baseIntent,
            parameters: { values: Array.from({ length: limit + excess }, () => null) },
          } as ExecutionIntent;
          expect(() =>
            new CanonicalIntentHasher({ maxArrayLength: limit }).capture(intent),
          ).toThrow("INTENT_ARRAY_TOO_LARGE");
        },
      ),
    );
  });
});
