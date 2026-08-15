import { createHash } from "node:crypto";
import type { AuthorityIntentBinding, CapturedIntent, ExecutionIntent } from "./ExecutionIntent.js";
import type { JsonValue } from "./JsonValue.js";

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export interface CanonicalLimits {
  readonly maxDepth: number;
  readonly maxEntries: number;
  readonly maxArrayLength: number;
  readonly maxBytes: number;
}

export class CanonicalIntentHasher {
  private readonly limits: CanonicalLimits;

  public constructor(limits?: Partial<CanonicalLimits>) {
    this.limits = {
      maxDepth: limits?.maxDepth ?? 20,
      maxEntries: limits?.maxEntries ?? 5_000,
      maxArrayLength: limits?.maxArrayLength ?? 1_000,
      maxBytes: limits?.maxBytes ?? 100 * 1024,
    };
  }

  public capture(intent: ExecutionIntent): CapturedIntent {
    const binding = CanonicalIntentHasher.bindingOf(intent);
    let entries = 0;
    this.assertBounded(binding as unknown as JsonValue, 0, () => {
      entries += 1;
      if (entries > this.limits.maxEntries) {
        throw new Error("INTENT_TOO_COMPLEX");
      }
    });
    const canonicalIntent = CanonicalIntentHasher.stringify(binding as unknown as JsonValue);
    const byteLength = Buffer.byteLength(canonicalIntent, "utf8");
    if (byteLength > this.limits.maxBytes) throw new Error("INTENT_TOO_LARGE");
    const digest = createHash("sha256").update(canonicalIntent, "utf8").digest("hex");
    return Object.freeze({
      intent: CanonicalIntentHasher.deepFreeze(intent),
      canonicalIntent,
      intentHash: `sha256:${digest}`,
      byteLength,
    });
  }

  public assertInputBounded(value: unknown): void {
    const pending: Array<{
      readonly value: unknown;
      readonly depth: number;
      readonly leaving: boolean;
    }> = [{ value, depth: 0, leaving: false }];
    const ancestors = new WeakSet<object>();
    let entries = 0;

    while (pending.length > 0) {
      const current = pending.pop();
      if (current === undefined || current.value === null || typeof current.value !== "object") {
        continue;
      }
      if (current.leaving) {
        ancestors.delete(current.value);
        continue;
      }
      if (current.depth > this.limits.maxDepth) throw new Error("INTENT_TOO_DEEP");
      if (ancestors.has(current.value)) throw new Error("CYCLIC_INTENT");
      ancestors.add(current.value);
      pending.push({ value: current.value, depth: current.depth, leaving: true });

      if (Array.isArray(current.value)) {
        if (current.value.length > this.limits.maxArrayLength) {
          throw new Error("INTENT_ARRAY_TOO_LARGE");
        }
        for (const child of current.value) {
          entries += 1;
          if (entries > this.limits.maxEntries) throw new Error("INTENT_TOO_COMPLEX");
          pending.push({ value: child, depth: current.depth + 1, leaving: false });
        }
        continue;
      }

      const prototype = Object.getPrototypeOf(current.value) as unknown;
      if (prototype !== Object.prototype && prototype !== null) {
        throw new Error("INVALID_JSON_OBJECT");
      }
      for (const key of Object.keys(current.value)) {
        if (FORBIDDEN_KEYS.has(key)) throw new Error("UNSAFE_INTENT_KEY");
        entries += 1;
        if (entries > this.limits.maxEntries) throw new Error("INTENT_TOO_COMPLEX");
        pending.push({
          value: (current.value as Record<string, unknown>)[key],
          depth: current.depth + 1,
          leaving: false,
        });
      }
    }
  }

  public static bindingOf(intent: ExecutionIntent): AuthorityIntentBinding {
    return {
      protocol_version: intent.version,
      tenant_id: intent.tenantId,
      intent_id: intent.intentId,
      idempotency_key: intent.idempotencyKey,
      captured_at: intent.capturedAt,
      expires_at: intent.expiresAt,
      actor: {
        id: intent.actor.id,
        type: intent.actor.type,
        ...(intent.actor.runtime === undefined ? {} : { runtime: intent.actor.runtime }),
        ...(intent.actor.trustLevel === undefined ? {} : { trust_level: intent.actor.trustLevel }),
      },
      action: {
        type: intent.action,
        resource: intent.target,
        parameters: intent.parameters,
      },
      context: intent.context,
      downstream_target: {
        system: intent.downstreamTarget.system,
        operation: intent.downstreamTarget.operation,
        ...(intent.downstreamTarget.endpoint === undefined
          ? {}
          : { endpoint: intent.downstreamTarget.endpoint }),
      },
    };
  }

  public static stringify(value: JsonValue): string {
    return JSON.stringify(CanonicalIntentHasher.canonicalize(value));
  }

  private static canonicalize(value: JsonValue): JsonValue {
    if (Array.isArray(value)) return value.map((item) => CanonicalIntentHasher.canonicalize(item));
    if (value === null || typeof value !== "object") return value;
    const normalized: Record<string, JsonValue> = {};
    for (const key of Object.keys(value).sort()) {
      const entry = value[key];
      if (entry !== undefined) normalized[key] = CanonicalIntentHasher.canonicalize(entry);
    }
    return normalized;
  }

  private static deepFreeze<T>(value: T): Readonly<T> {
    if (value && typeof value === "object" && !Object.isFrozen(value)) {
      Object.freeze(value);
      for (const child of Object.values(value as Record<string, unknown>)) {
        CanonicalIntentHasher.deepFreeze(child);
      }
    }
    return value;
  }

  private assertBounded(value: JsonValue, depth: number, count: () => void): void {
    if (depth > this.limits.maxDepth) throw new Error("INTENT_TOO_DEEP");
    if (value === null || typeof value !== "object") {
      if (typeof value === "number" && !Number.isFinite(value)) throw new Error("INVALID_NUMBER");
      return;
    }
    if (Array.isArray(value)) {
      if (value.length > this.limits.maxArrayLength) throw new Error("INTENT_ARRAY_TOO_LARGE");
      for (const child of value) {
        count();
        this.assertBounded(child, depth + 1, count);
      }
      return;
    }
    for (const [key, child] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(key)) throw new Error("UNSAFE_INTENT_KEY");
      count();
      this.assertBounded(child, depth + 1, count);
    }
  }
}
