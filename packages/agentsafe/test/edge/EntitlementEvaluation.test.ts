import { describe, expect, it } from "vitest";
import {
  DEFAULT_REPORT_DUE_DAYS,
  ENTITLEMENT_TYPE,
  licenceWarnings,
  type LicenceInput,
} from "../../src/edge/EntitlementEvaluation.js";

const NOW = Date.parse("2026-10-02T12:00:00.000Z");
const ORG = "org-synthetic";

function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: "decionis-synthetic",
    aud: ORG,
    iat: Math.floor(NOW / 1000) - 86_400,
    exp: Math.floor(NOW / 1000) + 365 * 86_400,
    plan: "enterprise",
    tier: "self_managed",
    included_actions_per_month: 1_000,
    volume_band: null,
    edge: true,
    usage_report_due_days: 35,
    ...overrides,
  };
}

function input(overrides: Partial<LicenceInput> = {}): LicenceInput {
  return {
    entitlement: { status: "read", claims: claims() },
    orgId: ORG,
    now: NOW,
    governed: 10,
    reporting: true,
    undelivered: [],
    ...overrides,
  };
}

describe("licenceWarnings", () => {
  it("names the entitlement's own type and a default due period", () => {
    expect(ENTITLEMENT_TYPE).toBe("decionis-edge-entitlement+jwt");
    expect(DEFAULT_REPORT_DUE_DAYS).toBe(35);
  });

  it("says nothing when the entitlement is current, covers the edge and the count is inside it", () => {
    expect(licenceWarnings(input())).toEqual([]);
    for (const tier of ["hosted", "dedicated", "self_managed"]) {
      expect(
        licenceWarnings(input({ entitlement: { status: "read", claims: claims({ tier }) } })),
        tier,
      ).toEqual([]);
    }
    expect(licenceWarnings(input({ governed: 1_000 }))).toEqual([]);
  });

  it("warns about a missing or unverifiable entitlement and reads nothing from it", () => {
    expect(licenceWarnings(input({ entitlement: { status: "missing" } }))).toEqual([
      "ENTITLEMENT_MISSING",
    ]);
    expect(licenceWarnings(input({ entitlement: { status: "read", claims: null } }))).toEqual([
      "ENTITLEMENT_INVALID",
    ]);
  });

  it("refuses claims that are not an entitlement, or are another organisation's", () => {
    for (const bad of [
      claims({ aud: "org-other" }),
      claims({ edge: "true" }),
      claims({ tier: "free" }),
      claims({ exp: -1 }),
      claims({ included_actions_per_month: 1.5 }),
      claims({ usage_report_due_days: undefined }),
      claims({ plan: "" }),
      claims({ iss: "" }),
      claims({ aud: "" }),
      claims({ iat: undefined }),
      null,
    ]) {
      expect(
        licenceWarnings(input({ entitlement: { status: "read", claims: bad }, orgId: "" })),
        JSON.stringify(bad),
      ).toEqual(["ENTITLEMENT_INVALID"]);
      expect(
        licenceWarnings(input({ entitlement: { status: "read", claims: bad } })),
        JSON.stringify(bad),
      ).toEqual(["ENTITLEMENT_INVALID"]);
    }
    // A claim this host does not read is no reason to refuse the rest.
    expect(
      licenceWarnings(input({ entitlement: { status: "read", claims: claims({ region: "eu" }) } })),
    ).toEqual([]);
  });

  it("warns at the instant the entitlement expires, and still reads it", () => {
    const exp = Math.floor(NOW / 1000);
    expect(
      licenceWarnings(
        input({ entitlement: { status: "read", claims: claims({ exp, edge: false }) } }),
      ),
    ).toEqual(["ENTITLEMENT_EXPIRED", "EDGE_NOT_ENTITLED"]);
    expect(
      licenceWarnings(input({ entitlement: { status: "read", claims: claims({ exp: exp + 1 }) } })),
    ).toEqual([]);
  });

  it("warns when the plan does not include the edge evaluator", () => {
    expect(
      licenceWarnings(input({ entitlement: { status: "read", claims: claims({ edge: false }) } })),
    ).toEqual(["EDGE_NOT_ENTITLED"]);
  });

  it("warns past the included actions, and never when the plan states none", () => {
    expect(licenceWarnings(input({ governed: 1_001 }))).toEqual(["INCLUDED_ACTIONS_EXCEEDED"]);
    expect(
      licenceWarnings(
        input({
          governed: 1_000_000,
          entitlement: {
            status: "read",
            claims: claims({ included_actions_per_month: null }),
          },
        }),
      ),
    ).toEqual([]);
    expect(
      licenceWarnings(
        input({
          governed: 1,
          entitlement: { status: "read", claims: claims({ included_actions_per_month: 0 }) },
        }),
      ),
    ).toEqual(["INCLUDED_ACTIONS_EXCEEDED"]);
  });

  it("warns past a volume band's ceiling, when the band states one", () => {
    const band = (volume_band: unknown, governed: number) =>
      licenceWarnings(
        input({
          governed,
          entitlement: {
            status: "read",
            claims: claims({ volume_band, included_actions_per_month: null }),
          },
        }),
      );
    expect(band({ name: "band-2", max_actions_per_month: 500 }, 501)).toEqual([
      "VOLUME_BAND_EXCEEDED",
    ]);
    expect(band({ name: "band-2", max_actions_per_month: 500 }, 500)).toEqual([]);
    expect(band({ max_actions_per_month: 0 }, 1)).toEqual(["VOLUME_BAND_EXCEEDED"]);
    expect(band("band-2", 1_000_000)).toEqual([]);
    expect(band({ name: "band-2" }, 1_000_000)).toEqual([]);
    expect(band({ max_actions_per_month: -1 }, 0)).toEqual([]);
  });

  it("warns when no usage-report key is configured", () => {
    expect(licenceWarnings(input({ reporting: false }))).toEqual(["USAGE_REPORT_KEY_MISSING"]);
  });

  it("warns once a report is past its due days, from the entitlement or 35 without one", () => {
    // September ended 2026-10-01; due 35 days later, 2026-11-05.
    const due = Date.parse("2026-11-05T00:00:00.000Z");
    expect(licenceWarnings(input({ undelivered: ["2026-09"], now: due - 1 }))).toEqual([]);
    const late = input({
      undelivered: ["2026-08", "2026-09"],
      now: due,
      entitlement: { status: "read", claims: claims({ exp: Math.floor(due / 1000) + 10 }) },
    });
    expect(licenceWarnings(late)).toEqual(["USAGE_REPORT_OVERDUE"]);
    expect(
      licenceWarnings(
        input({ undelivered: ["2026-09"], now: due, entitlement: { status: "missing" } }),
      ),
    ).toEqual(["ENTITLEMENT_MISSING", "USAGE_REPORT_OVERDUE"]);
    expect(
      licenceWarnings(
        input({ undelivered: ["2026-09"], now: due - 1, entitlement: { status: "missing" } }),
      ),
    ).toEqual(["ENTITLEMENT_MISSING"]);
    const prompt = claims({ usage_report_due_days: 5, exp: Math.floor(due / 1000) });
    const fifth = Date.parse("2026-10-06T00:00:00.000Z");
    expect(
      licenceWarnings(
        input({
          undelivered: ["2026-09"],
          now: fifth,
          entitlement: { status: "read", claims: prompt },
        }),
      ),
    ).toEqual(["USAGE_REPORT_OVERDUE"]);
    expect(
      licenceWarnings(
        input({
          undelivered: ["2026-09"],
          now: fifth - 1,
          entitlement: { status: "read", claims: prompt },
        }),
      ),
    ).toEqual([]);
  });

  it("lists every standing warning in one fixed order", () => {
    expect(
      licenceWarnings(
        input({
          governed: 2_000,
          reporting: false,
          undelivered: ["2026-01"],
          entitlement: {
            status: "read",
            claims: claims({
              exp: 1,
              edge: false,
              volume_band: { max_actions_per_month: 10 },
            }),
          },
        }),
      ),
    ).toEqual([
      "ENTITLEMENT_EXPIRED",
      "EDGE_NOT_ENTITLED",
      "INCLUDED_ACTIONS_EXCEEDED",
      "VOLUME_BAND_EXCEEDED",
      "USAGE_REPORT_KEY_MISSING",
      "USAGE_REPORT_OVERDUE",
    ]);
  });
});
