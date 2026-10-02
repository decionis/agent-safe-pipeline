import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { HashChain } from "../../src/audit/HashChain.js";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { UrlUsageDelivery, UsageMeter } from "../../src/edge/UsageMeter.js";
import { readUsageReport } from "../../src/edge/UsageReport.js";
import { verifyEntitlement } from "../../src/edge/Entitlement.js";
import { licenceWarnings } from "../../src/edge/EntitlementEvaluation.js";
import { collectedEvents } from "../support/Environment.js";
import { repositoryPath } from "../support/RepositoryRoot.js";
import {
  USAGE_REPORT_VECTOR,
  VECTOR_INSTALLATION,
  VECTOR_ORG,
  vectorKey,
  type UsageReportVector,
} from "../support/UsageReportVector.js";

/**
 * End to end with the Decionis ingestion verifier, when its source is named:
 * `DECIONIS_EDGE_USAGE_VERIFIER` is the path of Decionis's
 * `apps/api/src/services/edge/EdgeUsageReport.ts` in a checkout with its
 * dependencies installed. It runs where both repositories are present and is
 * skipped elsewhere; the vector under conformance/edge is what Decionis's own
 * suite verifies in its place.
 */
const verifierPath = process.env["DECIONIS_EDGE_USAGE_VERIFIER"];

interface DecionisVerifier {
  readonly EdgeUsageReport: {
    verify(input: {
      token: string;
      orgId: string;
      findProviderKey: (query: {
        org_id: string;
        kid: string;
        purpose: string;
      }) => Promise<Record<string, unknown> | null>;
      nowMs?: number;
    }): Promise<
      | { ok: true; report: { billable: number; claims: Record<string, unknown>; kid: string } }
      | { ok: false; code: string }
    >;
  };
}

function registered(kid: string, issuer: string) {
  return async (query: { org_id: string; kid: string; purpose: string }) =>
    query.org_id === VECTOR_ORG && query.kid === kid && query.purpose === "usage_report"
      ? { kid, issuer, algorithm: "EdDSA", public_jwk: { ...vectorKey().publicJwk, kid } }
      : null;
}

describe.skipIf(verifierPath === undefined)("Decionis ingestion of AgentSafe usage reports", () => {
  const load = async (): Promise<DecionisVerifier> =>
    (await import(/* @vite-ignore */ verifierPath ?? "")) as DecionisVerifier;
  const nowMs = Date.parse("2026-10-02T12:00:00.000Z");

  it("verifies the conformance vector and bills total minus delegated", async () => {
    const vector = JSON.parse(
      readFileSync(repositoryPath(...USAGE_REPORT_VECTOR), "utf8"),
    ) as UsageReportVector;
    const { EdgeUsageReport } = await load();
    const verified = await EdgeUsageReport.verify({
      token: vector.report,
      orgId: VECTOR_ORG,
      findProviderKey: registered(vector.key.kid, VECTOR_INSTALLATION),
      nowMs,
    });
    expect(verified).toMatchObject({
      ok: true,
      report: { billable: 3, kid: vector.key.kid, claims: vector.claims },
    });
  });

  it("reads the report Decionis's own suite captured from this producer", async () => {
    // apps/api/src/services/edge/EdgeUsageReport.ts -> apps/api/test/fixtures/edge/
    const api = dirname(dirname(dirname(dirname(verifierPath ?? ""))));
    const captured = JSON.parse(
      readFileSync(join(api, "test", "fixtures", "edge", "agentsafe-usage-report.json"), "utf8"),
    ) as {
      report: string;
      claims: Record<string, unknown>;
      provider_key: { public_jwk: Record<string, unknown> };
    };
    await expect(
      readUsageReport(captured.report, captured.provider_key.public_jwk),
    ).resolves.toMatchObject({
      ok: true,
      claims: captured.claims,
    });
  });

  it("verifies the report the running executor sends, and refuses it under another issuer", async () => {
    const sent: string[] = [];
    const clock = { now: Date.parse("2026-09-15T00:00:00.000Z") };
    const chain = new HashChain(EVIDENCE_STREAM);
    const meter = new UsageMeter({
      orgId: VECTOR_ORG,
      chain,
      installationId: VECTOR_INSTALLATION,
      stateDir: null,
      checkpointLines: 100,
      events: collectedEvents(),
      key: () => vectorKey("synthetic-usage-key-live"),
      delivery: new UrlUsageDelivery({
        baseUrl: "https://api.decionis.example",
        apiKey: () => "synthetic-api-key",
        fetch: (async (_url: string, init: RequestInit) => {
          sent.push((JSON.parse(String(init.body)) as { report: string }).report);
          return new Response("{}", { status: 201 });
        }) as typeof fetch,
      }),
      clock: () => clock.now,
    });
    for (const fields of [
      { verdict: "ALLOW", delegated: false },
      { verdict: "ESCALATE", delegated: true },
    ]) {
      const record = {
        at: new Date(clock.now).toISOString(),
        mode: "ENFORCEMENT",
        jti: "jti-1",
        ...fields,
      };
      chain.link({ event: "EDGE_DECISION", ...record }, () =>
        meter.observe({ ...record, seq: chain.head.seq, hash: chain.head.hash }),
      );
    }
    clock.now = Date.parse("2026-10-01T00:10:00.000Z");
    await meter.report();
    const { EdgeUsageReport } = await load();
    const token = sent[0] ?? "";
    await expect(
      EdgeUsageReport.verify({
        token,
        orgId: VECTOR_ORG,
        findProviderKey: registered("synthetic-usage-key-live", VECTOR_INSTALLATION),
        nowMs,
      }),
    ).resolves.toMatchObject({ ok: true, report: { billable: 1 } });
    await expect(
      EdgeUsageReport.verify({
        token,
        orgId: VECTOR_ORG,
        findProviderKey: registered("synthetic-usage-key-live", "synthetic-installation-2"),
        nowMs,
      }),
    ).resolves.toEqual({
      ok: false,
      code: "USAGE_REPORT_ISSUER_MISMATCH",
      kid: "synthetic-usage-key-live",
    });
  });

  it("reads and evaluates the entitlement Decionis issues", async () => {
    const edge = dirname(verifierPath ?? "");
    const { PolicyBundleSigningKey } = (await import(
      /* @vite-ignore */ join(edge, "PolicyBundleSigningKey.ts")
    )) as {
      PolicyBundleSigningKey: {
        deriveFromSecret(secret: string): unknown;
        buildSigner(
          key: unknown,
          kid: string,
        ): { publicJwk: Record<string, unknown>; keyId: string };
      };
    };
    const { EdgeEntitlementDocument } = (await import(
      /* @vite-ignore */ join(edge, "EdgeEntitlementDocument.ts")
    )) as {
      EdgeEntitlementDocument: {
        issue(input: Record<string, unknown>): Promise<{ entitlement: string }>;
      };
    };
    const signer = PolicyBundleSigningKey.buildSigner(
      PolicyBundleSigningKey.deriveFromSecret("synthetic-entitlement-secret"),
      "synthetic-policy-bundle-key",
    );
    const jwks = JSON.stringify({ keys: [{ ...signer.publicJwk, kid: signer.keyId }] });
    const issue = async (facts: Record<string, unknown>) =>
      (
        await EdgeEntitlementDocument.issue({
          orgId: VECTOR_ORG,
          nowMs,
          signer,
          facts: {
            plan: "enterprise",
            tier: "self_managed",
            volume_band: "band-synthetic",
            included_actions_per_month: 5,
            edge_addon: false,
            operator_pilot: false,
            ...facts,
          },
        })
      ).entitlement;
    const entitled = await verifyEntitlement({ token: await issue({}), jwks });
    expect(entitled.status).toBe("read");
    const evaluate = (entitlement: typeof entitled, governed: number) =>
      licenceWarnings({
        entitlement,
        orgId: VECTOR_ORG,
        now: nowMs,
        governed,
        reporting: true,
        undelivered: [],
      });
    expect(evaluate(entitled, 5)).toEqual([]);
    expect(evaluate(entitled, 6)).toEqual(["INCLUDED_ACTIONS_EXCEEDED"]);
    expect(evaluate(entitled, 0)).toEqual([]);
    const premium = await verifyEntitlement({
      token: await issue({ plan: "premium", tier: "hosted", volume_band: null }),
      jwks,
    });
    expect(evaluate(premium, 0)).toEqual(["EDGE_NOT_ENTITLED"]);
    const later = licenceWarnings({
      entitlement: entitled,
      orgId: VECTOR_ORG,
      now: nowMs + 35 * 86_400_000,
      governed: 0,
      reporting: true,
      undelivered: [],
    });
    expect(later).toEqual(["ENTITLEMENT_EXPIRED"]);
  });
});
