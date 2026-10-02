import { createHash, createPrivateKey, sign, type KeyObject } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DecisionAuthority } from "../../../src/decision/DecisionAuthority.js";
import { immutableGateDecision } from "../../../src/decision/ImmutableGateDecision.js";
import { EdgeBundleManager } from "../../../src/decision/edge/EdgeBundleManager.js";
import type { BundleRead, EdgeBundleSource } from "../../../src/decision/edge/EdgeBundleSource.js";
import {
  EdgeDecisionAuthority,
  type EdgeDecisionRecord,
} from "../../../src/decision/edge/EdgeDecisionAuthority.js";
import { EDGE_MODULE_ABI_VERSION, EdgeModule } from "../../../src/decision/edge/EdgeModule.js";
import { ActionRegistry } from "../../../src/execution/ActionRegistry.js";
import {
  LocalAuthorizationVerifier,
  LocalGrants,
} from "../../../src/execution/LocalAuthorizationVerifier.js";
import { InMemoryReplayStore } from "../../../src/execution/ReplayStore.js";
import { SafeExecutor } from "../../../src/execution/SafeExecutor.js";
import { IntentCapture } from "../../../src/intent/IntentCapture.js";

/**
 * The host against the real Decionis edge module. The module is proprietary
 * and is never committed here, so this suite runs only when both are given:
 *
 * - `AGENTSAFE_EDGE_WASM`: an edge build with the public test keys
 *   (`cargo build --release --target wasm32-unknown-unknown
 *   --no-default-features --features test-keys` in `crates/policy-core`);
 * - `AGENTSAFE_EDGE_CONFORMANCE`: that checkout's `conformance/policy-core`,
 *   for the issuer-signed bundles and the `decide` parity vectors.
 *
 * Without them it is skipped, and says why in its name.
 */
const WASM = process.env["AGENTSAFE_EDGE_WASM"] ?? "";
const CORPUS = process.env["AGENTSAFE_EDGE_CONFORMANCE"] ?? "";
const available = WASM !== "" && CORPUS !== "" && existsSync(WASM) && existsSync(CORPUS);

/** The public test keys' seeds, as the module's test key set documents them. */
function testKey(seedText: string): KeyObject {
  const seed = createHash("sha256").update(seedText, "utf8").digest();
  return createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
}

/** `stableJsonStringify`: keys sorted recursively, as the bundle digest is computed. */
function stable(value: unknown): string {
  const canonical = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(canonical);
    if (item === null || typeof item !== "object") return item;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(item).sort()) {
      sorted[key] = canonical((item as Record<string, unknown>)[key]);
    }
    return sorted;
  };
  return JSON.stringify(canonical(value));
}

interface PolicyBundle {
  readonly bundle_id: string;
  readonly version: string;
}

function signBundle(
  bundle: PolicyBundle,
  claims: { orgId: string; jti: string; nbf: number; exp: number },
  kid = "decionis-policy-bundle-test-1",
  key = testKey("decionis-policy-bundle-test-key/1"),
): string {
  const b64 = (text: string): string => Buffer.from(text, "utf8").toString("base64url");
  const header = b64(JSON.stringify({ alg: "EdDSA", typ: "decionis-policy-bundle+jwt", kid }));
  const payload = b64(
    JSON.stringify({
      iss: "decionis",
      aud: claims.orgId,
      iat: claims.nbf,
      nbf: claims.nbf,
      exp: claims.exp,
      jti: claims.jti,
      bundle_id: bundle.bundle_id,
      policy_version: bundle.version,
      bundle_digest: `sha256:${createHash("sha256").update(stable(bundle), "utf8").digest("hex")}`,
      core_abi: 2,
      bundle,
    }),
  );
  const input = `${header}.${payload}`;
  return `${input}.${sign(null, Buffer.from(input, "ascii"), key).toString("base64url")}`;
}

const DecideCorpusSchema = z.object({
  bundles: z.array(
    z.object({
      bundle: z.object({ bundle_id: z.string(), version: z.string() }).passthrough(),
      org_id: z.string(),
      jti: z.string(),
      nbf: z.number(),
      exp: z.number(),
    }),
  ),
  vectors: z.array(
    z.object({
      id: z.string(),
      bundle: z.number().int(),
      input: z.record(z.string(), z.unknown()).optional(),
      input_json: z.string().optional(),
      expected: z.union([
        z.object({ ok: z.literal(true), result: z.unknown() }),
        z.object({ ok: z.literal(false), code: z.string() }),
      ]),
    }),
  ),
});

function corpus<T>(name: string, schema: z.ZodType<T>): T {
  return schema.parse(JSON.parse(readFileSync(join(CORPUS, name), "utf8")));
}

const SignedBundlesSchema = z.object({
  meta: z.object({ org_id: z.string() }).passthrough(),
  bundles: z.array(
    z.object({ signed_bundle: z.string(), kid: z.string(), jti: z.string() }).passthrough(),
  ),
});

/** The rules of the corpus's payments bundle: under 10,000 approve, 10,000 and over escalate. */
const PAYMENTS_BUNDLE = 0;
const NOW = Date.parse("2026-10-01T12:00:00.000Z");

class FixedSource implements EdgeBundleSource {
  public readonly kind = "url";
  public constructor(public answer: BundleRead) {}
  public async read(): Promise<BundleRead> {
    return this.answer;
  }
}

describe.skipIf(!available)(
  "the Decionis edge module (needs AGENTSAFE_EDGE_WASM and AGENTSAFE_EDGE_CONFORMANCE)",
  () => {
    beforeEach(() => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(NOW);
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it("is an ABI 3 module the host starts on", () => {
      const module = EdgeModule.fromFile(WASM);
      expect(module.isFaulted).toBe(false);
      expect(EDGE_MODULE_ABI_VERSION).toBe(3);
    });

    it("loads every bundle the Decionis issuer signed (test key decionis-policy-bundle-test-v1)", () => {
      const signed = corpus("signed-bundles.json", SignedBundlesSchema);
      const module = EdgeModule.fromFile(WASM);
      for (const bundle of signed.bundles) {
        const loaded = module.loadBundle({
          signed_bundle: bundle.signed_bundle,
          org_id: signed.meta.org_id,
          now: "2026-10-02T00:00:00.000Z",
        });
        expect(loaded, bundle.jti).toMatchObject({
          ok: true,
          result: { kid: "decionis-policy-bundle-test-v1" },
        });
        const handle = (loaded as { result: { handle: number } }).result.handle;
        expect(module.unloadBundle(handle)).toBe(true);
      }
      expect(
        module.loadBundle({
          signed_bundle: signed.bundles[0]?.signed_bundle ?? "",
          org_id: "another-organisation",
          now: "2026-10-02T00:00:00.000Z",
        }),
      ).toEqual({ ok: false, code: "bundle_audience_mismatch" });
    });

    it("decides every parity vector exactly as the hosted contract does", () => {
      const { bundles, vectors } = corpus("decide.json", DecideCorpusSchema);
      const module = EdgeModule.fromFile(WASM);
      const failures: string[] = [];
      let decided = 0;
      // At most 16 bundles fit in a module at once: one is loaded at a time.
      let current: { readonly bundle: number; readonly handle: number } | null = null;
      const ordered = [...vectors].sort((a, b) => a.bundle - b.bundle);
      for (const vector of ordered) {
        if (vector.input === undefined) continue; // raw-text inputs test the module's parser, not the host
        let handle: number | undefined =
          current?.bundle === vector.bundle ? current.handle : undefined;
        if (handle === undefined) {
          if (current !== null) module.unloadBundle(current.handle);
          const entry = bundles[vector.bundle];
          if (entry === undefined) throw new Error(`${vector.id}: no bundle ${vector.bundle}`);
          const loaded = module.loadBundle({
            signed_bundle: signBundle(entry.bundle, {
              orgId: entry.org_id,
              jti: entry.jti,
              nbf: entry.nbf,
              exp: entry.exp,
            }),
            org_id: entry.org_id,
            now: new Date(entry.nbf * 1_000).toISOString(),
          });
          if (!loaded.ok) throw new Error(`${vector.id}: load refused ${loaded.code}`);
          handle = (loaded.result as { handle: number }).handle;
          current = { bundle: vector.bundle, handle };
        }
        const answer = module.decide(handle, vector.input);
        decided += 1;
        const expected = vector.expected.ok
          ? { ok: true, result: vector.expected.result }
          : { ok: false, code: vector.expected.code };
        if (JSON.stringify(answer) !== JSON.stringify(expected)) {
          failures.push(`${vector.id}: ${JSON.stringify(answer)}`);
        }
      }
      expect(failures).toEqual([]);
      expect(decided).toBeGreaterThan(500);
    });

    describe("through the host", () => {
      function payments(jti = "edge-host-1", exp = NOW / 1_000 + 86_400) {
        const { bundles } = corpus("decide.json", DecideCorpusSchema);
        const entry = bundles[PAYMENTS_BUNDLE];
        if (entry === undefined) throw new Error("no payments bundle");
        return {
          orgId: entry.org_id,
          read: {
            ok: true,
            signedBundle: signBundle(entry.bundle, {
              orgId: entry.org_id,
              jti,
              nbf: NOW / 1_000 - 3_600,
              exp,
            }),
          } as BundleRead,
        };
      }

      async function setup(options: { onUnavailable?: "hosted" | "block"; exp?: number } = {}) {
        const module = EdgeModule.fromFile(WASM);
        const bundle = payments("edge-host-1", options.exp);
        const source = new FixedSource(bundle.read);
        const bundles = new EdgeBundleManager({ module, source, orgId: bundle.orgId });
        expect(await bundles.refresh()).toBeNull();
        const records: EdgeDecisionRecord[] = [];
        const hostedEvaluate = vi.fn(async (captured: { intentHash: string }) =>
          immutableGateDecision({
            verdict: "ESCALATE",
            decisionId: "hosted-1",
            dossierId: "hosted-dossier-1",
            intentHash: captured.intentHash,
            reasonCodes: ["HOSTED_ESCALATE"],
            authorization: null,
            failClosed: false,
          }),
        );
        const hosted: DecisionAuthority = {
          evaluationMode: "ENFORCEMENT",
          evaluate: hostedEvaluate as unknown as DecisionAuthority["evaluate"],
        };
        const grants = new LocalGrants();
        const authority = new EdgeDecisionAuthority({
          module,
          bundles,
          hosted,
          grants,
          ...(options.onUnavailable === undefined ? {} : { onUnavailable: options.onUnavailable }),
          record: (record) => records.push(record),
        });
        const execute = vi.fn(async () => ({ posted: true }));
        const registry = new ActionRegistry()
          .register("payments.transfer", {
            parametersSchema: z.object({}).passthrough(),
            execute,
          })
          .seal();
        const executor = new SafeExecutor(
          registry,
          new LocalAuthorizationVerifier({
            grants,
            replay: new InMemoryReplayStore(),
            record: () => undefined,
          }),
        );
        return { module, source, bundles, records, hostedEvaluate, authority, execute, executor };
      }

      function transfer(amount: number) {
        return new IntentCapture({ ttlSeconds: 120 }).capture(
          {
            action: "payments.transfer",
            target: "acct:ops-01",
            parameters: { amount, currency: "USD", beneficiary: "synthetic-beneficiary-77" },
          },
          {
            tenantId: payments().orgId,
            actor: { id: "synthetic-payments-agent", type: "agent", runtime: "agentsafe" },
            downstreamTarget: { system: "core-banking", operation: "transfer" },
            idempotencyKey: `transfer-${amount}`,
            context: {},
          },
        );
      }

      it("ALLOW executes once, and a replay is refused", async () => {
        const { authority, executor, execute, hostedEvaluate, records } = await setup();
        const captured = transfer(250);
        const decision = await authority.evaluate(captured);
        expect(decision).toMatchObject({ verdict: "ALLOW", failClosed: false });
        expect(hostedEvaluate).not.toHaveBeenCalled();
        expect((await executor.run(captured, decision)).outcome).toBe("COMPLETED");
        expect((await executor.run(captured, decision)).outcome).toBe("BLOCKED");
        const again = await authority.evaluate(captured);
        expect((await executor.run(captured, again)).outcome).toBe("BLOCKED");
        expect(execute).toHaveBeenCalledTimes(1);
        expect(records[0]).toMatchObject({
          event: "EDGE_DECISION",
          verdict: "ALLOW",
          kid: "decionis-policy-bundle-test-1",
          jti: "edge-host-1",
          evaluation_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
        });
        const text = JSON.stringify(records);
        expect(text).not.toContain("synthetic-beneficiary-77");
        expect(text).not.toContain('"amount"');
      });

      it("ESCALATE goes to the hosted gate with the same intent", async () => {
        const { authority, hostedEvaluate, records } = await setup();
        const captured = transfer(50_000);
        const decision = await authority.evaluate(captured);
        expect(hostedEvaluate).toHaveBeenCalledWith(captured, undefined, {});
        expect(decision.decisionId).toBe("hosted-1");
        expect(records[0]).toMatchObject({ verdict: "ESCALATE", delegated: true });
      });

      it("BLOCK refuses locally", async () => {
        const { authority, executor, execute, hostedEvaluate } = await setup();
        const captured = new IntentCapture({ ttlSeconds: 120 }).capture(
          {
            action: "payments.transfer",
            target: "acct:ops-01",
            parameters: { amount: 250, currency: "USD" },
          },
          {
            tenantId: payments().orgId,
            actor: { id: "synthetic-payments-agent", type: "agent" },
            downstreamTarget: { system: "core-banking", operation: "transfer" },
            idempotencyKey: "transfer-high-risk",
            context: { risk_band: "high" },
          },
        );
        const decision = await authority.evaluate(captured);
        expect(decision).toMatchObject({ verdict: "BLOCK", authorization: null });
        expect(hostedEvaluate).not.toHaveBeenCalled();
        expect((await executor.run(captured, decision)).outcome).toBe("BLOCKED");
        expect(execute).not.toHaveBeenCalled();
      });

      it("on expiry, asks Decionis or refuses, as configured", async () => {
        const exp = NOW / 1_000 + 60;
        const hostedWay = await setup({ exp });
        const blockWay = await setup({ exp, onUnavailable: "block" });
        vi.setSystemTime((exp + 1) * 1_000);
        const hosted = await hostedWay.authority.evaluate(transfer(250));
        expect(hosted.decisionId).toBe("hosted-1");
        const blocked = await blockWay.authority.evaluate(transfer(250));
        expect(blocked).toMatchObject({
          verdict: "BLOCK",
          failClosed: true,
          reasonCodes: ["EDGE_BUNDLE_UNAVAILABLE"],
        });
      });

      it("a refresh swaps in the new bundle and releases the old one", async () => {
        const { authority, source, bundles, records, module } = await setup();
        await authority.evaluate(transfer(250));
        source.answer = payments("edge-host-2").read;
        expect(await bundles.refresh()).toBeNull();
        await authority.evaluate(transfer(260));
        expect(records.map((record) => (record as { jti: string }).jti)).toEqual([
          "edge-host-1",
          "edge-host-2",
        ]);
        expect(module.unloadBundle(1)).toBe(false);
      });
    });
  },
);
