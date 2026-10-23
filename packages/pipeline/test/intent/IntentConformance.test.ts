import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { CanonicalIntentHasher } from "../../src/intent/CanonicalIntentHasher.js";
import type { TrustedIntentContext } from "../../src/intent/ExecutionIntent.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type { JsonValue } from "../../src/intent/JsonValue.js";

interface ConformanceVector {
  description?: string;
  binding: JsonValue;
  canonical_json?: string;
  intent_hash: string;
  /** Single-field mutations of the binding, each of which MUST hash differently. */
  mutations?: readonly {
    path: string;
    description: string;
    binding: JsonValue;
    canonical_json: string;
    intent_hash: string;
  }[];
}

const VECTORS_DIR = new URL("../../../../conformance/vectors/", import.meta.url);

describe("agent-safe.intent/1 conformance", () => {
  it("matches the public cross-implementation SHA-256 vector", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL("../../../../conformance/agent-safe-intent-v1.json", import.meta.url),
        "utf8",
      ),
    ) as { binding: JsonValue; intent_hash: string };
    const canonical = CanonicalIntentHasher.stringify(fixture.binding);
    const actual = `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;

    expect(actual).toBe(fixture.intent_hash);
  });

  it("discovers and validates every vector in conformance/vectors/", async () => {
    const files = (await readdir(VECTORS_DIR)).filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThanOrEqual(6);

    for (const file of files) {
      const vector = JSON.parse(
        await readFile(new URL(file, VECTORS_DIR), "utf8"),
      ) as ConformanceVector;

      // 1. the hasher's canonicalization must equal the published bytes
      const canonical = CanonicalIntentHasher.stringify(vector.binding);
      expect(canonical, `${file}: canonical JSON mismatch`).toBe(vector.canonical_json);

      // 2. the published SHA-256 must match those bytes
      const actual = `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
      expect(actual, `${file}: hash mismatch`).toBe(vector.intent_hash);

      // 3. every mutation the vector names is another intent: its own bytes,
      //    its own hash, and never the base's or another mutation's
      const hashes = new Set([vector.intent_hash]);
      for (const mutation of vector.mutations ?? []) {
        const mutated = CanonicalIntentHasher.stringify(mutation.binding);
        expect(mutated, `${file}: ${mutation.path} canonical JSON mismatch`).toBe(
          mutation.canonical_json,
        );
        const digest = `sha256:${createHash("sha256").update(mutated, "utf8").digest("hex")}`;
        expect(digest, `${file}: ${mutation.path} hash mismatch`).toBe(mutation.intent_hash);
        expect(hashes.has(digest), `${file}: ${mutation.path} hashes like another intent`).toBe(
          false,
        );
        hashes.add(digest);
      }
    }
  });

  it("binds every field a compromised principal could change, so a grant for one intent authorises no other", async () => {
    const vector = JSON.parse(
      await readFile(new URL("compromised-principal.json", VECTORS_DIR), "utf8"),
    ) as Required<ConformanceVector>;
    const paths = vector.mutations.map((mutation) => mutation.path);
    // The parameters, the resource, the principal, the expiry, the trusted
    // runtime's idempotency key and the environment: each is inside the hash.
    expect(paths).toEqual(
      expect.arrayContaining([
        "action.parameters.replicas",
        "action.parameters.service",
        "action.parameters.cluster",
        "action.resource",
        "actor.id",
        "expires_at",
        "context.idempotency_key",
        "downstream_target.environment",
      ]),
    );
    expect(new Set(vector.mutations.map((mutation) => mutation.intent_hash)).size).toBe(
      vector.mutations.length,
    );
  });

  it("captures the policy-projection vectors from an intent, with and without the projection", async () => {
    const read = async (name: string) =>
      JSON.parse(await readFile(new URL(name, VECTORS_DIR), "utf8")) as Required<ConformanceVector>;
    const projected = await read("policy-projection.json");
    const absent = await read("policy-projection-absent.json");
    const intents = new IntentCapture({
      clock: () => new Date("2026-10-20T10:00:00.000Z"),
      createId: () => "44444444-4444-4444-8444-444444444444",
      ttlSeconds: 60,
    });
    const proposal = {
      action: "order.acknowledge",
      target: "walmart-marketplace/orders/synthetic-1001",
      parameters: { purchase_order_id: "synthetic-1001" },
    };
    const trusted: TrustedIntentContext = {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-commerce-walmart", type: "SERVICE", runtime: "walmart-connector" },
      downstreamTarget: {
        system: "walmart-marketplace",
        operation: "POST /v3/orders/{purchaseOrderId}/acknowledge",
        environment: "sandbox",
      },
      context: { lane: "sandbox", source: "conformance" },
      idempotencyKey: "walmart-marketplace:order.acknowledge:synthetic-1001:1",
    };

    const withProjection = intents.capture(proposal, {
      ...trusted,
      policyProjection: {
        decisionType: "ORDER_ACCEPTANCE",
        transactionType: "order_acceptance",
        workflowKey: "commerce_order_acceptance",
        channel: "connector",
      },
    });
    expect(CanonicalIntentHasher.bindingOf(withProjection.intent)).toEqual(projected.binding);
    expect(withProjection.canonicalIntent).toBe(projected.canonical_json);
    expect(withProjection.intentHash).toBe(projected.intent_hash);

    // Without the projection the intent is the one an intent without it has
    // always been: these bytes and this hash were reproduced with the
    // published @decionis/agent-safe-pipeline 0.4.0, run apart from this tree.
    const without = intents.capture(proposal, trusted);
    expect(CanonicalIntentHasher.bindingOf(without.intent)).toEqual(absent.binding);
    expect(without.canonicalIntent).toBe(absent.canonical_json);
    expect(without.intentHash).toBe(
      "sha256:bbd2b45a06920fe1a0caf82a51bd2d70394114ed8f687bec1277784537e21717",
    );
    expect(absent.intent_hash).toBe(without.intentHash);

    // Removing the projection is a mutation like any other, and it is exactly
    // the absent vector: a grant for one policy path authorises no other.
    const removed = projected.mutations.find((mutation) => mutation.path === "policy_projection");
    expect(removed?.binding).toEqual(absent.binding);
    expect(removed?.intent_hash).toBe(absent.intent_hash);
    expect(projected.mutations.map((mutation) => mutation.path)).toEqual([
      "policy_projection.decision_type",
      "policy_projection.transaction_type",
      "policy_projection.workflow_key",
      "policy_projection.channel",
      "policy_projection",
    ]);
  });

  it("captures the target-precondition vector from an intent, and the same intent without it", async () => {
    const vector = JSON.parse(
      await readFile(new URL("target-precondition.json", VECTORS_DIR), "utf8"),
    ) as Required<ConformanceVector>;
    const intents = new IntentCapture({
      clock: () => new Date("2026-10-23T12:00:00.000Z"),
      createId: () => "55555555-5555-4555-8555-555555555555",
      ttlSeconds: 60,
    });
    const proposal = {
      action: "customer.update",
      target: "businesscentral/customers/9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      parameters: { blocked: "All" },
    };
    const trusted: TrustedIntentContext = {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: {
        id: "synthetic-collections-agent",
        type: "AI_AGENT",
        runtime: "business-central-connector",
      },
      downstreamTarget: {
        system: "business-central",
        operation: "PATCH /companies({companyId})/customers({customerId})",
        environment: "sandbox",
      },
      context: { lane: "sandbox", source: "conformance" },
      idempotencyKey: "business-central:customer.update:9a8b7c6d:1",
    };

    const read = intents.capture(proposal, {
      ...trusted,
      precondition: {
        version: 'W/"JzE5OzEyMzQ1Njc4OTAxMjM0NTY3ODkwOzAwOyc="',
        state: " ",
        source: "businesscentral/api/v2#customers.get",
        read_at: "2026-10-23T11:59:59.000Z",
      },
    });
    expect(CanonicalIntentHasher.bindingOf(read.intent)).toEqual(vector.binding);
    expect(read.canonicalIntent).toBe(vector.canonical_json);
    expect(read.intentHash).toBe(vector.intent_hash);

    // Without a precondition the capture writes no agent_safe key at all, so
    // the intent is the one it was before preconditions existed.
    const without = intents.capture(proposal, trusted);
    const removed = vector.mutations.find((mutation) => mutation.path === "context.agent_safe");
    expect(without.intent.context).not.toHaveProperty("agent_safe");
    expect(removed?.binding).toEqual(CanonicalIntentHasher.bindingOf(without.intent));
    expect(removed?.intent_hash).toBe(without.intentHash);
    expect(vector.mutations.map((mutation) => mutation.path)).toEqual([
      "context.agent_safe.precondition.version",
      "context.agent_safe.precondition.state",
      "context.agent_safe.precondition.read_at",
      "context.agent_safe",
    ]);
  });

  it("keeps composed and decomposed text intentionally distinct (no NFC)", async () => {
    const nfc = CanonicalIntentHasher.stringify({ text: "caf\u00e9" });
    const nfd = CanonicalIntentHasher.stringify({ text: "cafe\u0301" });
    expect(nfc).not.toBe(nfd);
  });

  it("canonicalizes negative zero to 0 (JS JSON encoding)", async () => {
    expect(CanonicalIntentHasher.stringify({ amount: -0 })).toBe('{"amount":0}');
  });
});
