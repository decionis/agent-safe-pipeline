import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { createGate } from "../../src/decision/CreateGate.js";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { ShadowGate } from "../../src/decision/ShadowGate.js";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import { captured, json, TENANT_ID, verdictBody } from "../support/AuthorityDouble.js";

const ORG_ID = "11111111-1111-4111-8111-111111111111";
const HOSTED = {
  DECIONIS_API_KEY: "org-key",
  DECIONIS_TENANT_ID: ORG_ID,
  DECIONIS_API_URL: "http://127.0.0.1:3001",
  DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
};

function local(verdict: "ALLOW" | "ESCALATE" | "BLOCK" = "ALLOW") {
  return createFixtureAuthorityPair(() => verdict, { unsafeAllowDevelopmentFixture: true });
}

function registry() {
  return new ActionRegistry()
    .register("deploy", {
      parametersSchema: z.object({ environment: z.string() }).strict(),
      execute: async ({ parameters, dispatch }) =>
        await dispatch.run(async () => ({ deployed: parameters.environment })),
    })
    .seal();
}

describe("createGate", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns the local pair itself, untouched and offline, when no key is set", async () => {
    const pair = local();
    const fetchMock = vi.fn<typeof fetch>();

    for (const env of [{}, { DECIONIS_API_KEY: "" }, { DECIONIS_API_KEY: "   " }]) {
      const gate = createGate({ local: pair, tenantId: TENANT_ID, env, fetch: fetchMock });
      expect(gate.mode).toBe("LOCAL");
      expect(gate.tenantId).toBe(TENANT_ID);
      // The very same objects, not equivalents: nothing was wrapped or rebuilt.
      expect(gate.authority).toBe(pair.authority);
      expect(gate.verifier).toBe(pair.verifier);
    }

    // A hosted variable on its own changes nothing without the key.
    const gate = createGate({
      local: pair,
      tenantId: TENANT_ID,
      env: { DECIONIS_TENANT_ID: ORG_ID, DECIONIS_MODE: "ENFORCEMENT" },
      fetch: fetchMock,
    });
    const intent = captured();
    const decision = await gate.authority.evaluate(intent);
    const result = await new SafeExecutor(registry(), gate.verifier).run(intent, decision);
    expect(decision.hosted).toBeUndefined();
    expect(Object.keys(decision).sort()).toEqual(
      Object.keys(await pair.authority.evaluate(intent)).sort(),
    );
    expect(result.outcome).toBe("COMPLETED");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("runs the hosted gate in SHADOW mode by default, keeping the local verifier", async () => {
    const pair = local();
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(async () => json(verdictBody(intent, "BLOCK", "SHADOW")));

    const gate = createGate({ local: pair, tenantId: TENANT_ID, env: HOSTED, fetch: fetchMock });
    expect(gate.mode).toBe("SHADOW");
    expect(gate.tenantId).toBe(ORG_ID);
    expect(gate.authority).toBeInstanceOf(ShadowGate);
    expect(gate.verifier).toBe(pair.verifier);

    const decision = await gate.authority.evaluate(intent);
    const result = await new SafeExecutor(registry(), gate.verifier).run(intent, decision);
    expect(decision.verdict).toBe("ALLOW");
    expect(decision.hosted).toMatchObject({
      mode: "SHADOW",
      governs: false,
      verdict: "BLOCK",
      dossierId: "dossier-1",
    });
    expect(result.outcome).toBe("COMPLETED");

    const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:3001/v1/authority/enforce-and-bind");
    expect((request.headers as Record<string, string>).authorization).toBe("Bearer org-key");
    expect(JSON.parse(request.body as string)).toMatchObject({ mode: "SHADOW" });
  });

  it("pairs an ENFORCEMENT gate with the Decionis grant verifier", async () => {
    const pair = local("BLOCK");
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(async () => json(verdictBody(intent, "ALLOW")));

    for (const spelling of ["enforce", "ENFORCE", "Enforcement", " enforcement "]) {
      const gate = createGate({
        local: pair,
        tenantId: TENANT_ID,
        env: { ...HOSTED, DECIONIS_MODE: spelling },
        fetch: fetchMock,
      });
      expect(gate.mode, spelling).toBe("ENFORCEMENT");
      expect(gate.authority, spelling).toBeInstanceOf(ShadowGate);
      expect(gate.authority.evaluationMode, spelling).toBe("ENFORCEMENT");
      expect(gate.verifier, spelling).toBeInstanceOf(DecionisGrantVerifier);
    }
    for (const spelling of ["shadow", "SHADOW", " Shadow "]) {
      expect(
        createGate({
          local: pair,
          tenantId: TENANT_ID,
          env: { ...HOSTED, DECIONIS_MODE: spelling },
        }).mode,
        spelling,
      ).toBe("SHADOW");
    }

    // The local fixture blocks, so the hosted ALLOW cannot loosen it.
    const gate = createGate({
      local: pair,
      tenantId: TENANT_ID,
      env: { ...HOSTED, DECIONIS_MODE: "ENFORCEMENT" },
      fetch: fetchMock,
    });
    const decision = await gate.authority.evaluate(intent);
    expect(decision).toMatchObject({ verdict: "BLOCK", authorization: null });
    expect(decision.hosted).toMatchObject({
      governs: false,
      verdict: "ALLOW",
      dossierId: "dossier-1",
    });

    const allowed = createGate({
      local: local("ALLOW"),
      tenantId: TENANT_ID,
      env: { ...HOSTED, DECIONIS_MODE: "ENFORCEMENT" },
      fetch: fetchMock,
    });
    const hostedGoverns = await allowed.authority.evaluate(intent);
    expect(hostedGoverns.hosted?.governs).toBe(true);
    expect(hostedGoverns.authorization?.token).toBe("token");
  });

  it("refuses a hosted configuration it cannot honour instead of staying local", () => {
    const pair = local();
    const attempt = (env: Record<string, string>) =>
      createGate({ local: pair, tenantId: TENANT_ID, env: { ...HOSTED, ...env } });

    expect(() => attempt({ DECIONIS_TENANT_ID: "" })).toThrow("DECIONIS_TENANT_ID_MISSING");
    expect(() =>
      createGate({ local: pair, tenantId: TENANT_ID, env: { DECIONIS_API_KEY: "org-key" } }),
    ).toThrow("DECIONIS_TENANT_ID_MISSING");
    expect(() => attempt({ DECIONIS_MODE: "PARALLEL" })).toThrow("DECIONIS_MODE_INVALID");
    expect(() => attempt({ DECIONIS_MODE: "observe" })).toThrow("DECIONIS_MODE_INVALID");
    expect(() => attempt({ DECIONIS_TIMEOUT_MS: "1s" })).toThrow("DECIONIS_TIMEOUT_MS_INVALID");
    expect(() => attempt({ DECIONIS_TIMEOUT_MS: "-1" })).toThrow("DECIONIS_TIMEOUT_MS_INVALID");
    expect(() => attempt({ DECIONIS_TIMEOUT_MS: "1.5" })).toThrow("DECIONIS_TIMEOUT_MS_INVALID");
    expect(() => attempt({ DECIONIS_ALLOW_INSECURE_LOOPBACK: "" })).toThrow(
      "DECIONIS_URL_MUST_USE_HTTPS",
    );
    expect(() => attempt({ DECIONIS_API_URL: "https://user:secret@example.com" })).toThrow(
      "DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS",
    );
  });

  it("defaults to the production API over HTTPS and reads process.env when no env is given", async () => {
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(async () => json(verdictBody(intent, "ALLOW", "SHADOW")));
    vi.stubEnv("DECIONIS_API_KEY", "org-key");
    vi.stubEnv("DECIONIS_TENANT_ID", ORG_ID);
    vi.stubEnv("DECIONIS_API_URL", "");
    vi.stubEnv("DECIONIS_MODE", "");
    vi.stubEnv("DECIONIS_TIMEOUT_MS", "");

    const gate = createGate({ local: local(), tenantId: TENANT_ID, fetch: fetchMock });
    expect(gate.mode).toBe("SHADOW");
    await gate.authority.evaluate(intent);
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    // The production host stays in the source; a test names no real domain.
    expect(url.startsWith("https://")).toBe(true);
    expect(url.endsWith("/v1/authority/enforce-and-bind")).toBe(true);
  });

  it("bounds the hosted call by DECIONIS_TIMEOUT_MS and records a timeout as fail-closed", async () => {
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(
      (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), {
            once: true,
          });
        }),
    );

    const gate = createGate({
      local: local(),
      tenantId: TENANT_ID,
      env: { ...HOSTED, DECIONIS_TIMEOUT_MS: "5" },
      fetch: fetchMock,
    });
    const decision = await gate.authority.evaluate(intent);
    expect(decision.verdict).toBe("ALLOW");
    expect(decision.hosted).toMatchObject({
      governs: false,
      verdict: "BLOCK",
      failClosed: true,
      dossierId: null,
      reasonCodes: ["AUTHORITY_UNAVAILABLE"],
    });
  });
});
