import { describe, expect, it } from "vitest";
import {
  MAX_PRINCIPALS,
  PrincipalsError,
  credentialIdentity,
  parsePrincipalsFile,
} from "../../src/identity/PrincipalsFile.js";
import { TENANT_ID } from "../support/Environment.js";
import { principalsFile, sha256Hex } from "../support/Principals.js";

function refusal(text: string): string {
  try {
    parsePrincipalsFile(text);
    return "";
  } catch (error) {
    if (error instanceof PrincipalsError) return error.message;
    throw error;
  }
}

const withPrincipals = (principals: unknown[]): string =>
  JSON.stringify({ version: "agent-safe.principals/1", principals });

describe("parsePrincipalsFile", () => {
  it("parses one of each role and credential kind, keeping digests and identities only", () => {
    const entries = parsePrincipalsFile(principalsFile());
    expect(entries.map((entry) => `${entry.id}:${entry.role}:${entry.credential.kind}`)).toEqual([
      "treasury-workflow:PROPOSER:BEARER",
      "ops-oncall:OPERATOR:MTLS",
      "batch-runner:PROPOSER:WORKLOAD_JWT",
    ]);
    expect(JSON.stringify(entries)).not.toContain("synthetic-caller-token");
    expect(credentialIdentity(entries[0]?.credential ?? { kind: "BEARER", token_sha256: "" })).toBe(
      `BEARER:${sha256Hex("synthetic-caller-token-0123456789abcdef")}`,
    );
    expect(credentialIdentity({ kind: "MTLS", san_uri: "spiffe://a" })).toBe("MTLS:spiffe://a");
    expect(credentialIdentity({ kind: "WORKLOAD_JWT", issuer: "i", subject: "s" })).toBe(
      "WORKLOAD_JWT:i|s",
    );
  });

  it("refuses what is not a principals file, naming the path and never a value", () => {
    expect(refusal("not json")).toBe("PRINCIPALS_INVALID: not JSON");
    expect(refusal(JSON.stringify({ version: "agent-safe.principals/2", principals: [] }))).toBe(
      "PRINCIPALS_INVALID: version",
    );
    expect(refusal(withPrincipals([]))).toBe("PRINCIPALS_INVALID: principals");
    const proposer = JSON.parse(principalsFile()).principals[0] as Record<string, unknown>;
    expect(
      refusal(
        withPrincipals([{ ...proposer, credential: { kind: "BEARER", token_sha256: "short" } }]),
      ),
    ).toBe("PRINCIPALS_INVALID: principals.0.credential.token_sha256");
    expect(refusal(withPrincipals([{ ...proposer, token: "leaked-value" }]))).toBe(
      "PRINCIPALS_INVALID: principals.0",
    );
    expect(refusal(withPrincipals([{ ...proposer, tenant_id: "not-a-uuid" }]))).toBe(
      "PRINCIPALS_INVALID: principals.0.tenant_id",
    );
    expect(refusal(withPrincipals([{ ...proposer, allowed_actions: [] }]))).toBe(
      "PRINCIPALS_INVALID: principals.0.allowed_actions",
    );
    expect(refusal(withPrincipals([{ ...proposer, rate_limit: "0/60" }]))).toBe(
      "PRINCIPALS_INVALID: principals.0.rate_limit",
    );
    expect(
      refusal(
        withPrincipals([
          {
            id: "ops",
            role: "OPERATOR",
            scopes: ["everything"],
            credential: { kind: "MTLS", san_uri: "spiffe://x" },
          },
        ]),
      ),
    ).toBe("PRINCIPALS_INVALID: principals.0.scopes.0");
    expect(
      refusal(
        withPrincipals([
          {
            id: "ops",
            role: "OPERATOR",
            scopes: [],
            credential: { kind: "MTLS", san_uri: "spiffe://x" },
          },
        ]),
      ),
    ).toBe("PRINCIPALS_INVALID: principals.0.scopes");
    expect(
      refusal(
        withPrincipals([
          {
            id: "ops",
            role: "OPERATOR",
            scopes: ["status"],
            credential: { kind: "MTLS", san_uri: "no-scheme" },
          },
        ]),
      ),
    ).toBe("PRINCIPALS_INVALID: principals.0.credential.san_uri");
    const many = Array.from({ length: MAX_PRINCIPALS + 1 }, (_, index) => ({
      ...proposer,
      id: `p-${index}`,
      credential: { kind: "BEARER", token_sha256: sha256Hex(`t-${index}`) },
    }));
    expect(refusal(withPrincipals(many))).toBe("PRINCIPALS_INVALID: principals");
    expect(refusal(withPrincipals(many.slice(0, MAX_PRINCIPALS)))).toBe("");
  });

  it("refuses a duplicate id and a credential identity claimed twice", () => {
    const proposer = JSON.parse(principalsFile()).principals[0] as Record<string, unknown>;
    expect(
      refusal(
        withPrincipals([
          proposer,
          { ...proposer, credential: { kind: "BEARER", token_sha256: sha256Hex("other") } },
        ]),
      ),
    ).toBe("PRINCIPALS_DUPLICATE_ID: treasury-workflow");
    expect(refusal(withPrincipals([proposer, { ...proposer, id: "second" }]))).toBe(
      "PRINCIPALS_CREDENTIAL_SHARED: second",
    );
    const mtls = (id: string): Record<string, unknown> => ({
      id,
      role: "OPERATOR",
      scopes: ["status"],
      credential: {
        kind: "MTLS",
        san_uri: "spiffe://synthetic.example/ns/ops/sa/oncall",
        cert_fingerprint_sha256: sha256Hex(id),
      },
    });
    expect(refusal(withPrincipals([mtls("a"), mtls("b")]))).toBe("PRINCIPALS_CREDENTIAL_SHARED: b");
    const jwt = (id: string, subject: string): Record<string, unknown> => ({
      ...proposer,
      id,
      credential: { kind: "WORKLOAD_JWT", issuer: "https://issuer.synthetic.example", subject },
    });
    expect(refusal(withPrincipals([jwt("a", "s1"), jwt("b", "s1")]))).toBe(
      "PRINCIPALS_CREDENTIAL_SHARED: b",
    );
    expect(refusal(withPrincipals([jwt("a", "s1"), jwt("b", "s2")]))).toBe("");
    expect(TENANT_ID).toMatch(/^[0-9a-f-]{36}$/);
  });
});
