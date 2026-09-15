import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  LEGACY_CALLER_ID,
  PrincipalRegistry,
  type Principal,
} from "../../src/identity/PrincipalRegistry.js";
import {
  PrincipalsError,
  parsePrincipalsFile,
  type PrincipalEntry,
} from "../../src/identity/PrincipalsFile.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";
import { CALLER_TOKEN, TENANT_ID } from "../support/Environment.js";
import { principalsFile, sha256Hex } from "../support/Principals.js";

const context = { registeredActions: ["forward_request"], jwtConfigured: true, mutualTls: true };
const entries = (): readonly PrincipalEntry[] => parsePrincipalsFile(principalsFile());

function registry(overrides: Partial<typeof context> = {}): PrincipalRegistry {
  return PrincipalRegistry.fromEntries(entries(), { ...context, ...overrides });
}

function refusal(work: () => unknown): string {
  try {
    work();
    return "";
  } catch (error) {
    if (error instanceof PrincipalsError) return error.message;
    throw error;
  }
}

describe("PrincipalRegistry.fromEntries", () => {
  it("builds each principal from its entry, keeping only what the door and the service need", () => {
    const built = registry();
    expect(built.legacy).toBe(false);
    expect(built.size).toBe(3);
    expect(built.all.map((principal) => principal.id)).toEqual([
      "treasury-workflow",
      "ops-oncall",
      "batch-runner",
    ]);
    expect(built.proposers.map((principal) => principal.id)).toEqual([
      "treasury-workflow",
      "batch-runner",
    ]);
    expect(built.operators.map((principal) => principal.id)).toEqual(["ops-oncall"]);
    const workflow = built.principal("treasury-workflow") as Principal;
    expect(workflow).toMatchObject({
      role: "PROPOSER",
      tenantId: TENANT_ID,
      actor: { id: "synthetic-payout-agent", type: "AI_AGENT", runtime: "workflow-runner" },
      rateLimit: { count: 100, windowSeconds: 60 },
    });
    expect([...workflow.allowedActions]).toEqual(["forward_request"]);
    expect(workflow.scopes.size).toBe(0);
    expect(workflow.credential.kind).toBe("BEARER");
    expect(
      workflow.credential.kind === "BEARER" &&
        Buffer.from(workflow.credential.digest()).toString("hex"),
    ).toBe(sha256Hex(CALLER_TOKEN));
    const oncall = built.principal("ops-oncall") as Principal;
    expect(oncall).toMatchObject({
      role: "OPERATOR",
      tenantId: null,
      actor: null,
      rateLimit: null,
    });
    expect([...oncall.scopes]).toEqual(["status", "metrics", "secrets.reload"]);
    expect(oncall.allowedActions.size).toBe(0);
    expect(oncall.credential).toEqual({
      kind: "MTLS",
      sanUri: "spiffe://synthetic.example/ns/ops/sa/oncall",
      fingerprint: null,
    });
    const batch = built.principal("batch-runner") as Principal;
    expect(batch.actor).toEqual({ id: "synthetic-batch-agent", type: "AI_AGENT" });
    expect(batch.credential).toEqual({
      kind: "WORKLOAD_JWT",
      issuer: "https://issuer.synthetic.example",
      subject: "system:serviceaccount:agents:batch-runner",
      audience: null,
      requiredClaims: { "kubernetes.io/namespace": "agents" },
    });
    expect(built.principal("nobody")).toBeNull();
  });

  it("keeps a fingerprint pin, a named audience, and an empty claim set when the file gives them", () => {
    const pinned = JSON.parse(principalsFile()) as { principals: Record<string, unknown>[] };
    pinned.principals[1] = {
      ...pinned.principals[1],
      credential: {
        kind: "MTLS",
        san_uri: "spiffe://synthetic.example/ns/ops/sa/oncall",
        cert_fingerprint_sha256: "a".repeat(64),
      },
    };
    pinned.principals[2] = {
      ...pinned.principals[2],
      credential: {
        kind: "WORKLOAD_JWT",
        issuer: "https://issuer.synthetic.example",
        subject: "s",
        audience: "agentsafe-batch",
      },
    };
    const built = PrincipalRegistry.fromEntries(
      parsePrincipalsFile(JSON.stringify(pinned)),
      context,
    );
    expect(built.principal("ops-oncall")?.credential).toMatchObject({
      fingerprint: "a".repeat(64),
    });
    expect(built.principal("batch-runner")?.credential).toMatchObject({
      audience: "agentsafe-batch",
      requiredClaims: {},
    });
    expect(built.audiences()).toEqual(["agentsafe-batch"]);
    expect(registry().audiences()).toEqual([]);
  });

  it("refuses an action nobody registered, a workload token without a verifier, and a certificate without a client CA", () => {
    expect(refusal(() => registry({ registeredActions: ["other_action"] }))).toBe(
      "PRINCIPALS_UNKNOWN_ACTION: treasury-workflow/forward_request",
    );
    expect(refusal(() => registry({ jwtConfigured: false }))).toBe(
      "PRINCIPALS_JWT_UNCONFIGURED: batch-runner",
    );
    expect(refusal(() => registry({ mutualTls: false }))).toBe(
      "PRINCIPALS_MTLS_UNCONFIGURED: ops-oncall",
    );
    const operatorsOnly = entries().filter((entry) => entry.role === "OPERATOR");
    expect(
      PrincipalRegistry.fromEntries(operatorsOnly, { ...context, registeredActions: [] }).size,
    ).toBe(1);
  });
});

describe("PrincipalRegistry.legacy", () => {
  it("is one proposer over every registered action whose token follows the handle", () => {
    let token = SecretHandle.fromString("EXECUTOR_CALLER_TOKEN", CALLER_TOKEN);
    const built = PrincipalRegistry.legacy({
      tenantId: TENANT_ID,
      actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
      registeredActions: ["forward_request", "custom_action"],
      callerToken: () => token.digestBytes(),
    });
    expect(built.legacy).toBe(true);
    expect(built.size).toBe(1);
    const caller = built.principal(LEGACY_CALLER_ID) as Principal;
    expect(caller).toMatchObject({
      id: "legacy-caller",
      role: "PROPOSER",
      tenantId: TENANT_ID,
      actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
      rateLimit: null,
    });
    expect([...caller.allowedActions]).toEqual(["forward_request", "custom_action"]);
    expect(built.byBearerDigest(CALLER_TOKEN)?.id).toBe("legacy-caller");
    token = SecretHandle.fromString("EXECUTOR_CALLER_TOKEN", "synthetic-rotated-token-0123456789");
    expect(built.byBearerDigest(CALLER_TOKEN)).toBeNull();
    expect(built.byBearerDigest("synthetic-rotated-token-0123456789")?.id).toBe("legacy-caller");
    expect(built.operators).toEqual([]);
  });
});

describe("PrincipalRegistry lookups", () => {
  it("finds a bearer by digest after comparing every bearer digest, never fewer", () => {
    const withTwo = JSON.parse(principalsFile()) as { principals: Record<string, unknown>[] };
    withTwo.principals.push({
      ...withTwo.principals[0],
      id: "second-bearer",
      credential: {
        kind: "BEARER",
        token_sha256: sha256Hex("synthetic-second-token-abcdef0123456789"),
      },
    });
    const compare = vi.fn((a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b)));
    const built = PrincipalRegistry.fromEntries(
      parsePrincipalsFile(JSON.stringify(withTwo)),
      context,
      compare,
    );
    expect(built.byBearerDigest(CALLER_TOKEN)?.id).toBe("treasury-workflow");
    expect(compare).toHaveBeenCalledTimes(2);
    expect(compare.mock.calls[0]?.[0]).toEqual(createHash("sha256").update(CALLER_TOKEN).digest());
    compare.mockClear();
    expect(built.byBearerDigest("synthetic-second-token-abcdef0123456789")?.id).toBe(
      "second-bearer",
    );
    expect(compare).toHaveBeenCalledTimes(2);
    compare.mockClear();
    expect(built.byBearerDigest("synthetic-unknown-token-0123456789")).toBeNull();
    expect(compare).toHaveBeenCalledTimes(2);
    expect(built.byBearerDigest("")).toBeNull();
  });

  it("finds a certificate by SAN URI, honours a pin, and ignores every other kind", () => {
    const built = registry();
    const oncall = built.byCertificate(["spiffe://synthetic.example/ns/ops/sa/oncall"], "ab");
    expect(oncall?.id).toBe("ops-oncall");
    expect(
      built.byCertificate(["dns:other", "spiffe://synthetic.example/ns/ops/sa/oncall"], "AB:CD")
        ?.id,
    ).toBe("ops-oncall");
    expect(built.byCertificate(["spiffe://synthetic.example/ns/ops/sa/other"], "ab")).toBeNull();
    expect(built.byCertificate([], "ab")).toBeNull();
    const pinned = JSON.parse(principalsFile()) as { principals: Record<string, unknown>[] };
    pinned.principals[1] = {
      ...pinned.principals[1],
      credential: {
        kind: "MTLS",
        san_uri: "spiffe://synthetic.example/ns/ops/sa/oncall",
        cert_fingerprint_sha256: "ab".repeat(32),
      },
    };
    const strict = PrincipalRegistry.fromEntries(
      parsePrincipalsFile(JSON.stringify(pinned)),
      context,
    );
    const san = ["spiffe://synthetic.example/ns/ops/sa/oncall"];
    expect(strict.byCertificate(san, "ab".repeat(32))?.id).toBe("ops-oncall");
    expect(strict.byCertificate(san, "AB:".repeat(31) + "AB")?.id).toBe("ops-oncall");
    expect(strict.byCertificate(san, "cd".repeat(32))).toBeNull();
  });

  it("names the principal whose rate limit will not parse", () => {
    // The refusal has to say which principal, because a file may name two
    // hundred of them and the value itself must not be echoed back.
    expect(() =>
      PrincipalRegistry.fromEntries(
        parsePrincipalsFile(
          principalsFile({
            principals: [
              {
                id: "treasury-workflow",
                role: "PROPOSER",
                tenant_id: TENANT_ID,
                actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
                allowed_actions: ["forward_request"],
                credential: { kind: "BEARER", token_sha256: sha256Hex(CALLER_TOKEN) },
                rate_limit: "0/60",
              },
            ],
          }),
        ),
        { registeredActions: ["forward_request"], jwtConfigured: false, mutualTls: false },
      ),
    ).toThrow("principals/treasury-workflow/rate_limit");
  });

  it("gives a proposer no scopes and an operator no actions, and leaves an absent runtime absent", () => {
    const built = registry();
    const proposer = built.proposers[0];
    const operator = built.operators[0];
    expect(proposer?.tenantId).toBe(TENANT_ID);
    expect(proposer?.actor?.id).toBe("synthetic-payout-agent");
    expect([...(proposer?.scopes ?? [])]).toEqual([]);
    expect(operator?.tenantId).toBeNull();
    expect(operator?.actor).toBeNull();
    expect([...(operator?.allowedActions ?? [])]).toEqual([]);
    // An actor with no runtime carries no such key: the actor travels inside
    // the hashed intent, and a key set to undefined is a different canonical
    // form from a key that is not there.
    const withoutRuntime = built.proposers.find((one) => one.actor?.runtime === undefined);
    expect(withoutRuntime, "a fixture proposer with no runtime").toBeDefined();
    expect(Object.keys(withoutRuntime?.actor ?? {}).sort()).toEqual(["id", "type"]);
    const withRuntime = built.proposers.find((one) => one.actor?.runtime !== undefined);
    if (withRuntime !== undefined) {
      expect(Object.keys(withRuntime.actor ?? {}).sort()).toEqual(["id", "runtime", "type"]);
    }
  });

  it("finds a workload by issuer and subject, and knows which issuers it trusts", () => {
    const built = registry();
    expect(built.issuerKnown("https://issuer.synthetic.example")).toBe(true);
    expect(built.issuerKnown("https://other.synthetic.example")).toBe(false);
    // Two issuers, so knowing one is not knowing them all: a cluster that
    // rotates its API server's name has both trusted for a while.
    const twoIssuers = PrincipalRegistry.fromEntries(
      parsePrincipalsFile(
        principalsFile({
          principals: [
            {
              id: "batch-runner",
              role: "PROPOSER",
              tenant_id: TENANT_ID,
              actor: { id: "synthetic-batch-agent", type: "AI_AGENT" },
              allowed_actions: ["forward_request"],
              credential: {
                kind: "WORKLOAD_JWT",
                issuer: "https://issuer.synthetic.example",
                subject: "system:serviceaccount:agents:batch-runner",
              },
            },
            {
              id: "second-runner",
              role: "PROPOSER",
              tenant_id: TENANT_ID,
              actor: { id: "synthetic-second-agent", type: "AI_AGENT" },
              allowed_actions: ["forward_request"],
              credential: {
                kind: "WORKLOAD_JWT",
                issuer: "https://second.synthetic.example",
                subject: "system:serviceaccount:agents:second-runner",
              },
            },
          ],
        }),
      ),
      context,
    );
    expect(twoIssuers.issuerKnown("https://issuer.synthetic.example")).toBe(true);
    expect(twoIssuers.issuerKnown("https://second.synthetic.example")).toBe(true);
    expect(twoIssuers.issuerKnown("https://third.synthetic.example")).toBe(false);
    expect([...twoIssuers.audiences()].sort()).toEqual([]);
    const named = built.byJwt(
      "https://issuer.synthetic.example",
      "system:serviceaccount:agents:batch-runner",
    );
    expect(named?.principal.id).toBe("batch-runner");
    // The credential comes back narrowed, so a caller reads the issuer and
    // the claims without asking the kind a second time.
    expect(named?.credential.issuer).toBe("https://issuer.synthetic.example");
    // This fixture names no audience of its own, so the configured one is
    // what the door will require.
    expect(named?.credential.audience).toBeNull();
    expect(
      built.byJwt("https://issuer.synthetic.example", "system:serviceaccount:agents:other"),
    ).toBeNull();
    expect(
      built.byJwt("https://other.synthetic.example", "system:serviceaccount:agents:batch-runner"),
    ).toBeNull();
  });
});
