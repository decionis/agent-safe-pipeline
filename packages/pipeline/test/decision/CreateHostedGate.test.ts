import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import {
  createHostedGate,
  hostedRequested,
  resolveHostedCredentials,
} from "../../src/decision/CreateGate.js";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { ProvisionError } from "../../src/decision/Provision.js";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import { type CredentialFiles } from "../../src/http/StoredCredentials.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import { HOSTED_HINT, printHostedOutcome } from "../../src/report/HostedOutcome.js";
import {
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_AUTHORITY_PROVISIONAL_ORG_ID,
  LocalAuthority,
} from "../../src/testing/LocalAuthority.js";
import { TENANT_ID } from "../support/AuthorityDouble.js";

const OWNED_ORG = "11111111-1111-4111-8111-111111111111";

/** A credential store in memory, so a test owns its own file. */
function memoryFiles(): CredentialFiles & { readonly stored: Map<string, string> } {
  const stored = new Map<string, string>();
  return {
    stored,
    read: (path) => stored.get(path) ?? null,
    write: (path, text) => {
      stored.set(path, text);
    },
    mkdir: () => undefined,
  };
}

function local(verdict: "ALLOW" | "ESCALATE" | "BLOCK" = "BLOCK") {
  return createFixtureAuthorityPair(() => verdict, { unsafeAllowDevelopmentFixture: true });
}

function intentFor(tenantId: string) {
  return new IntentCapture().capture(
    { action: "delete_customer", target: "crm:customer:synthetic-42", parameters: { id: "42" } },
    {
      tenantId,
      actor: { id: "synthetic-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "crm", operation: "delete_customer" },
      idempotencyKey: `delete-${tenantId}`,
      context: {},
    },
  );
}

function sink() {
  const chunks: string[] = [];
  return { chunks, out: { write: (chunk: string) => chunks.push(chunk) } };
}

let authority: LocalAuthority;
let env: Record<string, string>;

beforeAll(async () => {
  authority = new LocalAuthority({ verificationLinks: true });
  await authority.start();
  env = {
    DECIONIS_HOSTED: "1",
    DECIONIS_API_URL: authority.baseUrl,
    DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    AGENTSAFE_HOME: "/synthetic/agentsafe",
  };
});

afterAll(async () => {
  await authority.stop();
});

describe("hostedRequested", () => {
  it("reads DECIONIS_HOSTED as a switch", () => {
    for (const value of ["1", "true", "TRUE", " yes ", "on"]) {
      expect(hostedRequested({ DECIONIS_HOSTED: value })).toBe(true);
    }
    for (const value of [undefined, "", "0", "false", "no", "maybe"]) {
      expect(hostedRequested({ DECIONIS_HOSTED: value })).toBe(false);
    }
  });
});

describe("createHostedGate", () => {
  it("is the local pair, with no credentials and the hint, when nothing is set", async () => {
    const pair = local();
    const gate = await createHostedGate({ local: pair, tenantId: TENANT_ID, env: {} });
    expect(gate.mode).toBe("LOCAL");
    expect(gate.authority).toBe(pair.authority);
    expect(gate.credentials).toBeNull();
    expect(gate.fetchDossier).toBeNull();
    const { chunks, out } = sink();
    await printHostedOutcome(gate, await gate.authority.evaluate(intentFor(TENANT_ID)), { out });
    expect(chunks).toEqual([`${HOSTED_HINT}\n`]);
    const quiet = sink();
    await printHostedOutcome(gate, await gate.authority.evaluate(intentFor(TENANT_ID)), {
      out: quiet.out,
      hint: false,
    });
    expect(quiet.chunks).toEqual([]);
  });

  it("provisions a workspace on the first run, stores its key, and reuses it on the second", async () => {
    const files = memoryFiles();
    const notices: string[] = [];
    const first = await createHostedGate({
      local: local(),
      tenantId: TENANT_ID,
      env,
      store: { files, home: "/synthetic/home" },
      source: { repo: "decionis/agent-safe-pipeline", example: "basic-agent", surface: "github" },
      notice: (line) => notices.push(line),
    });
    expect(first.mode).toBe("SHADOW");
    expect(first.tenantId).toBe(LOCAL_AUTHORITY_PROVISIONAL_ORG_ID);
    expect(first.credentials).toMatchObject({
      source: "provisioned",
      tenantId: LOCAL_AUTHORITY_PROVISIONAL_ORG_ID,
      endpoint: authority.baseUrl,
      path: "/synthetic/agentsafe/credentials.json",
      provisional: true,
    });
    expect(first.credentials?.claim).toEqual({
      note: "synthetic workspace on loopback; there is nothing to claim",
    });
    expect(notices).toEqual([
      `decionis: provisioned a free workspace ${LOCAL_AUTHORITY_PROVISIONAL_ORG_ID} (provisional, no account; 50 governed decisions a month)`,
      "decionis: key stored at /synthetic/agentsafe/credentials.json; the next run reuses this workspace",
      "decionis: synthetic workspace on loopback; there is nothing to claim",
    ]);
    const stored = JSON.parse(files.stored.get("/synthetic/agentsafe/credentials.json") ?? "{}");
    expect(stored).toEqual({
      version: 1,
      decionis: {
        apiKey: LOCAL_AUTHORITY_API_KEY,
        tenantId: LOCAL_AUTHORITY_PROVISIONAL_ORG_ID,
        endpoint: authority.baseUrl,
        provisional: true,
      },
    });
    // The provisioning call identified itself, surface included.
    const provision = authority.requests.find((r) => r.path === "/v1/public/agents/provision");
    expect(provision?.body).toEqual({ agent_name: "agent-safe-pipeline basic-agent" });

    const provisionsBefore = authority.requests.filter(
      (r) => r.path === "/v1/public/agents/provision",
    ).length;
    const second = await createHostedGate({
      local: local(),
      tenantId: TENANT_ID,
      env,
      store: { files },
      notice: (line) => notices.push(line),
    });
    expect(second.credentials).toMatchObject({ source: "stored", provisional: true });
    expect(authority.requests.filter((r) => r.path === "/v1/public/agents/provision").length).toBe(
      provisionsBefore,
    );
    expect(notices).toHaveLength(3);
  });

  it("ends a hosted run with the decision, the verification page and the signed dossier", async () => {
    const files = memoryFiles();
    const gate = await createHostedGate({
      local: local("BLOCK"),
      tenantId: TENANT_ID,
      env,
      store: { files },
      notice: () => undefined,
    });
    const intent = intentFor(gate.tenantId);
    const decision = await gate.authority.evaluate(intent);
    // Shadow: the local verdict governs; the hosted one is recorded beside it, with its link.
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.hosted).toMatchObject({ mode: "SHADOW", governs: false, verdict: "ALLOW" });
    expect(decision.hosted?.verificationUrl).toBe(
      `${authority.baseUrl}/verify/${decision.hosted?.dossierId ?? ""}?sig=synthetic`,
    );
    const registry = new ActionRegistry()
      .register("delete_customer", {
        parametersSchema: z.object({ id: z.string() }).strict(),
        execute: async ({ dispatch }) => await dispatch.run(async () => ({ deleted: true })),
      })
      .seal();
    const result = await new SafeExecutor(registry, gate.verifier).run(intent, decision);
    expect(result.outcome).toBe("BLOCKED");

    const { chunks, out } = sink();
    await printHostedOutcome(gate, decision, { out });
    const text = chunks.join("");
    expect(text).toContain("verdict: BLOCK\n");
    expect(text).toContain("decionis: ALLOW (SHADOW, recorded beside the local verdict)\n");
    expect(text).toContain(`dossier: ${decision.hosted?.dossierId ?? ""}\n`);
    expect(text).toContain(
      `verify it in a browser, no account needed: ${decision.hosted?.verificationUrl ?? ""}\n`,
    );
    expect(text).toContain("verify it yourself, no account needed: pnpm decionis:verify ");
    expect(text).toContain(`signed dossier: ${decision.hosted?.dossierId ?? ""} (`);
    expect(text).toContain("bytes, ALLOW)\n");
    expect(text).toMatch(/Ed25519 by key [\w-]+ at \d{4}-\d{2}-\d{2}T/);
    expect(text).toContain("0 signed artifact(s)\n");
    expect(text).toContain("issuer: synthetic_loopback\n");
    expect(text).not.toContain(HOSTED_HINT);
  });

  it("says when the signed record could not be fetched, and still prints the decision", async () => {
    const gate = await createHostedGate({
      local: local("ALLOW"),
      tenantId: TENANT_ID,
      env,
      store: false,
      notice: () => undefined,
    });
    expect(gate.credentials?.path).toBeNull();
    const decision = await gate.authority.evaluate(intentFor(gate.tenantId));
    const broken = {
      ...gate,
      fetchDossier: () => Promise.reject(new Error("boom")),
    };
    const { chunks, out } = sink();
    await printHostedOutcome(broken, decision, { out });
    expect(chunks.join("")).toContain(
      "signed dossier: not fetched (DOSSIER_UNAVAILABLE); the record is still there under your key\n",
    );
    const missing = sink();
    await printHostedOutcome(
      gate,
      {
        ...decision,
        hosted: { ...(decision.hosted as NonNullable<typeof decision.hosted>), dossierId: null },
      },
      { out: missing.out },
    );
    expect(missing.chunks.join("")).toContain("dossier: none\n");
    expect(missing.chunks.join("")).not.toContain("signed dossier");
  });

  it("keeps a key in the environment ahead of the switch, in the mode asked for", async () => {
    const gate = await createHostedGate({
      local: local(),
      tenantId: TENANT_ID,
      env: {
        ...env,
        DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
        DECIONIS_TENANT_ID: OWNED_ORG,
        DECIONIS_MODE: "ENFORCEMENT",
      },
      store: false,
    });
    expect(gate.mode).toBe("ENFORCEMENT");
    expect(gate.credentials).toEqual({
      source: "environment",
      tenantId: OWNED_ORG,
      endpoint: authority.baseUrl,
      path: null,
      provisional: false,
      claim: null,
    });
    expect(gate.fetchDossier).not.toBeNull();
  });

  it("ignores a stored login for another authority and provisions afresh", async () => {
    const files = memoryFiles();
    files.stored.set(
      "/synthetic/agentsafe/credentials.json",
      JSON.stringify({
        version: 1,
        decionis: {
          apiKey: "elsewhere-key",
          tenantId: OWNED_ORG,
          endpoint: "https://other.example",
        },
      }),
    );
    const gate = await createHostedGate({
      local: local(),
      tenantId: TENANT_ID,
      env,
      store: { files },
      notice: () => undefined,
    });
    expect(gate.credentials?.source).toBe("provisioned");
    expect(gate.tenantId).toBe(LOCAL_AUTHORITY_PROVISIONAL_ORG_ID);
  });

  it("resolves credentials for a process that is not a gate, and needs the tenant beside a key", async () => {
    expect(await resolveHostedCredentials({ env: {} })).toBeNull();
    await expect(resolveHostedCredentials({ env: { DECIONIS_API_KEY: "k" } })).rejects.toThrow(
      "DECIONIS_TENANT_ID_MISSING",
    );
    const owned = await resolveHostedCredentials({
      env: { DECIONIS_API_KEY: " k ", DECIONIS_TENANT_ID: OWNED_ORG },
    });
    expect(owned?.apiKey).toBe("k");
    expect(owned?.credentials).toMatchObject({ source: "environment", tenantId: OWNED_ORG });
    const files = memoryFiles();
    const provisioned = await resolveHostedCredentials({
      env,
      store: { files },
      notice: () => undefined,
      source: { example: "trusted-executor" },
    });
    expect(provisioned?.apiKey).toBe(LOCAL_AUTHORITY_API_KEY);
    expect(provisioned?.env["DECIONIS_TENANT_ID"]).toBe(LOCAL_AUTHORITY_PROVISIONAL_ORG_ID);
    expect(provisioned?.credentials.source).toBe("provisioned");
  });

  it("refuses in production, and surfaces a provisioning refusal by its code", async () => {
    await expect(
      createHostedGate({
        local: local(),
        tenantId: TENANT_ID,
        env: { ...env, NODE_ENV: "production" },
        store: false,
      }),
    ).rejects.toThrow("DECIONIS_HOSTED_REFUSED_IN_PRODUCTION");
    const limited = vi.fn<typeof fetch>(() =>
      Promise.resolve(new Response("{}", { status: 429, headers: { "retry-after": "120" } })),
    );
    await expect(
      createHostedGate({
        local: local(),
        tenantId: TENANT_ID,
        env,
        store: false,
        fetch: limited,
      }),
    ).rejects.toMatchObject({
      name: "ProvisionError",
      code: "PROVISION_LIMIT_REACHED",
      status: 429,
      retryAfterSeconds: 120,
    });
    expect(new ProvisionError("PROVISION_REFUSED", 400).message).toBe("PROVISION_REFUSED");
  });
});
