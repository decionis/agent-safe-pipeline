import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { demoPolicy } from "../../src/gateway/DemoAuthority.js";
import { Gateway } from "../../src/gateway/Gateway.js";
import type { InstallSurface } from "../../src/gateway/InstallSurface.js";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import { collectedIo, testConfig, UpstreamDouble } from "../support/GatewayHarness.js";
import { repositoryPath } from "../support/RepositoryRoot.js";

/**
 * Deployment-independent enforcement.
 *
 * The claim is not that four runtimes produce the same bytes — they do not,
 * and should not: each binds its own enforcement boundary and its own
 * workload, so the intent hashes differ by exactly those fields. The claim is
 * that the *decision* does not move. The same intent, under the same policy,
 * with the same trusted signals, is allowed, blocked or escalated the same way
 * whether AgentSafe is a container, a pod, a package or a process on a host.
 *
 * A different hash is not a different decision, and this is where that
 * sentence is held to.
 */

const TENANT_ID = "00000000-0000-4000-8000-000000000009";

interface RuntimeShape {
  readonly name: string;
  readonly surface: InstallSurface | null;
  readonly environment: Readonly<Record<string, string>>;
}

interface RuntimeCase {
  readonly id: string;
  readonly request: { method: string; path: string; body: Record<string, unknown> | null };
  readonly expected: { verdict: string; state: string; execution: string };
}

interface CrossRuntimeVector {
  readonly vector_version: "agent-safe.cross-runtime/1";
  readonly runtimes: readonly RuntimeShape[];
  readonly cases: readonly RuntimeCase[];
}

const DIRECTORY = repositoryPath("conformance", "runtime");

async function vectors(): Promise<readonly CrossRuntimeVector[]> {
  const names = (await readdir(DIRECTORY)).filter((name) => name.endsWith(".json")).sort();
  expect(names.length).toBeGreaterThanOrEqual(1);
  return Promise.all(
    names.map(
      async (name) =>
        JSON.parse(await readFile(join(DIRECTORY, name), "utf8")) as CrossRuntimeVector,
    ),
  );
}

function request(one: RuntimeCase["request"]): InterceptedRequest {
  const body = one.body === null ? Buffer.alloc(0) : Buffer.from(JSON.stringify(one.body), "utf8");
  return {
    method: one.method,
    path: one.path,
    search: "",
    headers: {
      host: "gateway.example",
      ...(one.body === null ? {} : { "content-type": "application/json" }),
    },
    body,
    remoteAddress: "127.0.0.1",
    encrypted: false,
  };
}

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 30));

describe("the same intent and policy across runtimes", () => {
  const upstream = new UpstreamDouble();
  const authority = new LocalAuthority({ policy: demoPolicy });

  beforeAll(async () => {
    await upstream.start();
    await authority.start();
  });
  afterAll(async () => {
    await authority.stop();
    await upstream.stop();
  });

  it("decides identically in every runtime, and binds its own runtime metadata", async () => {
    for (const vector of await vectors()) {
      expect(vector.vector_version).toBe("agent-safe.cross-runtime/1");
      for (const one of vector.cases) {
        const observed: {
          runtime: string;
          state: unknown;
          verdict: unknown;
          execution: unknown;
          reasons: unknown;
          intentHash: string;
          action: unknown;
          boundary: unknown;
          workload: unknown;
        }[] = [];

        for (const runtime of vector.runtimes) {
          const env = {
            DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
            DECIONIS_API_URL: authority.baseUrl,
            DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
            DECIONIS_TENANT_ID: TENANT_ID,
            AGENTSAFE_MODE: "enforcement",
            ...runtime.environment,
          };
          const io = collectedIo();
          const gateway = await Gateway.create(testConfig(upstream.baseUrl, { env }), {
            env,
            io,
            version: "0.0.0-test",
            surface: runtime.surface,
          });
          const before = authority.requests.length;
          await gateway.govern(request(one.request), `http.${one.request.method.toLowerCase()}`);
          await settle();
          const report = io.out
            .map((line) => JSON.parse(line) as Record<string, unknown>)
            .filter((line) => line["event"] === "INTERCEPTED")
            .at(-1);
          const call = authority.requests
            .slice(before)
            .find((seen) => seen.path.endsWith("/enforce-and-bind"));
          const body = call?.body as {
            intent_hash: string;
            action: unknown;
            context: Record<string, unknown>;
          };
          observed.push({
            runtime: runtime.name,
            state: report?.["state"],
            verdict: report?.["verdict"],
            execution: report?.["execution"],
            reasons: report?.["reason_codes"],
            intentHash: body.intent_hash,
            action: body.action,
            boundary: body.context["enforcement_boundary"],
            workload: body.context["workload"],
          });
          await gateway.close();
        }

        const first = observed[0];
        expect(first, one.id).toBeDefined();
        for (const seen of observed) {
          const where = `${one.id} in ${seen.runtime}`;
          // The decision, identically, everywhere.
          expect(seen.verdict, where).toBe(one.expected.verdict);
          expect(seen.state, where).toBe(one.expected.state);
          expect(seen.execution, where).toBe(one.expected.execution);
          expect(seen.reasons, where).toEqual(first?.reasons);
          // The action the authority decided over, identically, everywhere.
          expect(seen.action, where).toEqual(first?.action);
        }

        // And the runtime metadata differing, which is the whole point of
        // saying the decision does not: a boundary and a workload per runtime,
        // so the hashes differ and the verdicts do not.
        const hashes = new Set(observed.map((seen) => seen.intentHash));
        expect(hashes.size, one.id).toBe(observed.length);
        expect(observed.find((seen) => seen.runtime === "native")?.workload).toBeUndefined();
        expect(observed.find((seen) => seen.runtime === "docker")?.workload).toMatchObject({
          runtime: "docker",
          provenance: { source: "docker", trust_level: "supplied" },
        });
        for (const seen of observed) {
          expect(seen.boundary, `${one.id} in ${seen.runtime}`).toBeDefined();
          // The pod and the node are this instance, never the boundary.
          expect(JSON.stringify(seen.boundary)).not.toContain("agentsafe-7c9f-xk2");
          expect(JSON.stringify(seen.boundary)).not.toContain("ip-10-0-4-21");
        }
      }
    }
  }, 120_000);
});
