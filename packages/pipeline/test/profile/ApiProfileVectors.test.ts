import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  API_PROFILE_CONTRACT,
  ApiProfile,
  ApiProfileError,
  apiProfileJsonSchema,
  type ApiProfileMatch,
  type ApiRequest,
  type ApiSubjectCheck,
} from "../../src/profile/ApiProfile.js";
import type { JsonValue } from "../../src/intent/JsonValue.js";
import { ApiProfiles } from "../../src/profile/ApiProfiles.js";
import { BUILT_IN_API_PROFILES } from "../../src/profile/BuiltInApiProfiles.js";

/**
 * The published specification and the shipped profiles, found by walking up
 * from this file to the repository root, so the test reads the same files
 * from a mutation-testing sandbox as from the package.
 */
function repository(): URL {
  let directory = new URL("./", import.meta.url);
  for (let depth = 0; depth < 8; depth += 1) {
    if (existsSync(new URL("spec/profiles/api/v1/", directory))) return directory;
    directory = new URL("../", directory);
  }
  throw new Error("spec/profiles/api/v1 not found above the test");
}

const ROOT = repository();
const SPEC = new URL("spec/profiles/api/v1/", ROOT);

interface Vector {
  readonly description: string;
  readonly profile?: string;
  readonly definition?: unknown;
  readonly request?: ApiRequest;
  readonly expected?: {
    operation: string;
    action: string;
    facts: Record<string, unknown>;
    policy_projection: unknown;
    subject?: string | null;
  } | null;
  readonly error?: string;
  /** The subject a session is pinned to, for the checks below. */
  readonly session?: string;
  readonly request_check?: ApiSubjectCheck;
  /** A read's answer, as its JSON body. */
  readonly response?: JsonValue;
  readonly response_check?: ApiSubjectCheck;
}

function json<T>(url: URL): T {
  return JSON.parse(readFileSync(url, "utf8")) as T;
}

function vectorsIn(directory: URL): Array<[string, Vector]> {
  return readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => [name, json<Vector>(new URL(name, directory))]);
}

/** Every profile directory under profiles/, as `<platform>/<api>/<version>`. */
function profileIds(): string[] {
  const found: string[] = [];
  const walk = (relative: string): void => {
    const directory = new URL(`profiles/${relative}`, ROOT);
    for (const entry of readdirSync(directory).sort()) {
      if (!statSync(new URL(`profiles/${relative}${entry}`, ROOT)).isDirectory()) continue;
      const child = `${relative}${entry}/`;
      const file = new URL(`profiles/${child}profile.json`, ROOT);
      if (existsSync(file) && json<{ profile: string }>(file).profile === API_PROFILE_CONTRACT) {
        found.push(child.slice(0, -1));
      } else {
        walk(child);
      }
    }
  };
  walk("");
  return found;
}

/** A match as a vector states it: snake-case projection key, facts as written. */
function asVector(match: ApiProfileMatch | null): Vector["expected"] {
  return match === null
    ? null
    : {
        operation: match.operation,
        action: match.action,
        facts: match.facts,
        policy_projection: match.policyProjection,
        ...(match.subject === undefined ? {} : { subject: match.subject }),
      };
}

/** A vector's subject checks, when it pins a session: the call's, then its answer's. */
function expectChecks(profile: ApiProfile, match: ApiProfileMatch | null, vector: Vector): void {
  if (vector.session === undefined) return;
  expect(match).not.toBeNull();
  expect(profile.checkRequest(match!, vector.request?.query ?? {}, vector.session)).toBe(
    vector.request_check,
  );
  if (vector.response_check !== undefined) {
    expect(profile.checkResponse(match!.operation, vector.response, vector.session)).toBe(
      vector.response_check,
    );
  }
}

function refusal(work: () => unknown): string {
  try {
    work();
  } catch (error) {
    return error instanceof ApiProfileError ? error.code : `unexpected ${String(error)}`;
  }
  return "no refusal";
}

describe("agent-safe.profile.api/1 definition vectors", () => {
  const vectors = vectorsIn(new URL("vectors/", SPEC));

  it("has vectors for matching and for refusal", () => {
    expect(vectors.filter(([, vector]) => vector.error === undefined).length).toBeGreaterThan(3);
    expect(vectors.filter(([, vector]) => vector.error !== undefined).length).toBeGreaterThan(3);
  });

  it.each(vectors)("%s", (_name, vector) => {
    if (vector.error !== undefined) {
      expect(refusal(() => ApiProfile.parse(vector.definition))).toBe(vector.error);
      return;
    }
    const profile = ApiProfile.parse(vector.definition);
    const match = profile.match(vector.request!);
    expect(asVector(match)).toEqual(vector.expected);
    expectChecks(profile, match, vector);
  });

  it("checks subjects in reads and answers, both ways", () => {
    const checked = vectors.filter(([, vector]) => vector.session !== undefined);
    const outcomes = new Set(
      checked.flatMap(([, vector]) => [vector.request_check, vector.response_check]),
    );
    for (const outcome of [
      "MATCH",
      "SUBJECT_ABSENT",
      "SUBJECT_MISMATCH",
      "QUERY_PARAMETER_REFUSED",
      "RESPONSE_UNREADABLE",
      "RESPONSE_KEY_REFUSED",
      "RESPONSE_SUBJECT_ABSENT",
      "RESPONSE_SUBJECT_MISMATCH",
    ])
      expect(outcomes).toContain(outcome);
  });
});

describe("the profiles this build ships", () => {
  const ids = profileIds();

  it("ships every profile under profiles/, mirrored exactly", () => {
    expect(ids).toEqual(["businesscentral/api/v2", "walmart/api/v3"]);
    expect([...ApiProfiles.ids()].sort()).toEqual(ids);
    for (const id of ids) {
      expect(BUILT_IN_API_PROFILES.find((profile) => profile.id === id)).toEqual(
        json(new URL(`profiles/${id}/profile.json`, ROOT)),
      );
    }
  });

  it.each(ids)("%s matches its manifest", (id) => {
    const directory = new URL(`profiles/${id}/`, ROOT);
    const manifest = readFileSync(new URL("MANIFEST.sha256", directory), "utf8")
      .trim()
      .split("\n")
      .map((line) => line.split("  ") as [string, string]);
    expect(manifest.map(([, file]) => file)).toContain("profile.json");
    for (const [digest, file] of manifest) {
      expect(
        createHash("sha256")
          .update(readFileSync(new URL(file, directory)))
          .digest("hex"),
      ).toBe(digest);
    }
  });

  it.each(ids)("%s answers each of its vectors, and every operation has one", (id) => {
    const profile = ApiProfiles.get(id)!;
    const vectors = vectorsIn(new URL(`profiles/${id}/vectors/`, ROOT));
    const covered = new Set<string>();
    for (const [name, vector] of vectors) {
      expect(vector.profile, name).toBe(id);
      const match = profile.match(vector.request!);
      expect(asVector(match), name).toEqual(vector.expected);
      expectChecks(profile, match, vector);
      if (match !== null) covered.add(match.operation);
    }
    expect([...covered].sort()).toEqual(
      profile.definition.operations.map((operation) => operation.id).sort(),
    );
    expect(vectors.some(([, vector]) => vector.expected === null)).toBe(true);
  });
});

describe("ApiProfile", () => {
  const walmart = ApiProfiles.get("walmart/api/v3")!;

  it("names the operation from method, path and query before any body is read", () => {
    expect(walmart.operationFor("POST", "/v3/orders/42/acknowledge")?.id).toBe(
      "orders.acknowledge",
    );
    expect(walmart.operationFor("PUT", "/v3/price", { promo: "true" })?.id).toBe(
      "prices.promotion",
    );
    expect(walmart.operationFor("PUT", "/v3/price")?.id).toBe("prices.update");
    expect(walmart.operationFor("GET", "/v3/orders/42")).toBeNull();
    expect(walmart.operationFor("POST", "/v3/orders/42/acknowledge?x=1")).toBeNull();
  });

  it("states its action types once each, and answers an unknown id with null", () => {
    expect(walmart.actions()).toEqual([
      "order.acknowledge",
      "order.cancel",
      "order.refund",
      "order.ship",
      "promotion.change",
      "price.change",
      "inventory.update",
      "feed.submit",
    ]);
    expect(walmart.operation("orders.cancel")?.action).toBe("order.cancel");
    expect(walmart.operation("orders.delete")).toBeNull();
    expect(ApiProfiles.get("walmart/api/v9")).toBeNull();
  });

  it("matches nothing for a placeholder that does not decode or would leave its segment", () => {
    expect(walmart.match({ method: "POST", path: "/v3/orders/%E0%A4%A/acknowledge" })).toBeNull();
    expect(walmart.match({ method: "POST", path: "/v3/orders/a%2Fb/acknowledge" })).toBeNull();
    expect(walmart.match({ method: "POST", path: "/v3/orders/''/acknowledge" })).toBeNull();
    expect(walmart.match({ method: "POST", path: "/v3/orders/%2E%2E/acknowledge" })).toBeNull();
  });

  it("never reads a fact from an inherited member", () => {
    const profile = ApiProfile.parse({
      profile: API_PROFILE_CONTRACT,
      id: "example/api/v1",
      platform: "example",
      title: "Example",
      prefixes: [""],
      operations: [
        {
          id: "things.post",
          method: "POST",
          path: "/things",
          action: "thing.create",
          summary: "Create a thing.",
          facts: { kind: "/body/constructor", owner: "/query/toString", first: "/body/items/01" },
          policy_projection: null,
        },
      ],
    });
    expect(
      profile.match({ method: "POST", path: "/things", body: { items: ["a", "b"] } })?.facts,
    ).toEqual({});
  });

  it("refuses a malformed template and a repeated placeholder", () => {
    const definition = (path: string) => ({
      profile: API_PROFILE_CONTRACT,
      id: "example/api/v1",
      platform: "example",
      title: "Example",
      prefixes: [""],
      operations: [
        {
          id: "things.post",
          method: "POST",
          path,
          action: "thing.create",
          summary: "Create a thing.",
          facts: {},
          policy_projection: null,
        },
      ],
    });
    expect(refusal(() => ApiProfile.parse(definition("/things/{id}/{id}")))).toBe(
      "API_PROFILE_INVALID",
    );
    expect(refusal(() => ApiProfile.parse(definition("/things/{id")))).toBe("API_PROFILE_INVALID");
    expect(refusal(() => ApiProfile.parse(definition("/things/{1d}")))).toBe("API_PROFILE_INVALID");
    expect(refusal(() => ApiProfile.parse(definition("things")))).toBe("API_PROFILE_INVALID");
  });
});

describe("ApiProfile subjects", () => {
  const businessCentral = ApiProfiles.get("businesscentral/api/v2")!;
  const base = "/v2.0/production/api/v2.0/companies(6f3c1a52-1d2e-4f5a-8b9c-0d1e2f3a4b5c)";

  it("seals a registry over writes only: a read is never an intent", () => {
    expect(businessCentral.actions()).not.toContain("customer.read");
    expect(businessCentral.actions()).toContain("sales.create");
    expect(ApiProfile.isRead(businessCentral.operation("customers.list")!)).toBe(true);
    expect(ApiProfile.isRead(businessCentral.operation("salesOrders.create")!)).toBe(false);
  });

  it("tells a read that only resembles an operation from one that matches none", () => {
    expect(businessCentral.resembles("GET", `${base}/customers`)).toBe(true);
    expect(businessCentral.resembles("GET", `${base}/CUSTOMERS`)).toBe(true);
    expect(businessCentral.resembles("GET", `${base}/%63ustomers`)).toBe(true);
    expect(businessCentral.resembles("GET", `${base}/%E0%A4%A`)).toBe(true);
    expect(businessCentral.resembles("GET", `${base}/items`)).toBe(false);
    expect(businessCentral.resembles("DELETE", `${base}/customers`)).toBe(false);
  });

  it("tells a path below a checked read from the read and from one that matches none", () => {
    expect(businessCentral.beneath("GET", `${base}/customers/$count`)).toBe(true);
    expect(businessCentral.beneath("GET", `${base}/Customers/%24count`)).toBe(true);
    expect(
      businessCentral.beneath(
        "GET",
        `${base}/customers(3b7d2c10-5e4f-4a6b-9c8d-7e6f5a4b3c2d)/picture`,
      ),
    ).toBe(true);
    expect(businessCentral.beneath("GET", `${base}/%E0%A4%A`)).toBe(true);
    expect(businessCentral.beneath("GET", `${base}/customers`)).toBe(false);
    expect(businessCentral.beneath("GET", `${base}/customersAndMore`)).toBe(false);
    expect(businessCentral.beneath("GET", `${base}/items/$count`)).toBe(false);
    expect(businessCentral.beneath("DELETE", `${base}/customers/$count`)).toBe(false);
  });

  it("checks a write's answer where the operation names a response subject, and nothing else", () => {
    expect(
      businessCentral.checkResponse("salesOrders.create", { customerNumber: "C-1" }, "C-1"),
    ).toBe("MATCH");
    expect(
      businessCentral.checkResponse("salesOrders.create", { customerNumber: "C-2" }, "C-1"),
    ).toBe("RESPONSE_SUBJECT_MISMATCH");
    expect(businessCentral.checkResponse("salesInvoices.post", {}, "C-1")).toBeNull();
    expect(businessCentral.checkResponse("customers.list", { value: [] }, "C-1")).toBe("MATCH");
    expect(
      businessCentral.checkResponse("customers.list", { "@odata.count": 1, value: [] }, "C-1"),
    ).toBe("RESPONSE_KEY_REFUSED");
    expect(businessCentral.checkResponse("customers.list", { value: {} }, "C-1")).toBe(
      "RESPONSE_UNREADABLE",
    );
    expect(businessCentral.checkResponse("customers.get", undefined, "C-1")).toBe(
      "RESPONSE_UNREADABLE",
    );
    expect(businessCentral.checkResponse("customers.get", { number: "C-1" }, "C-1")).toBe("MATCH");
    expect(businessCentral.checkResponse("customers.get", "C-1", "C-1")).toBe(
      "RESPONSE_SUBJECT_ABSENT",
    );
  });
});

describe("spec/profiles/api/v1/schema.json", () => {
  it("is generated from the validator this package runs", () => {
    expect(json(new URL("schema.json", SPEC))).toEqual(apiProfileJsonSchema());
  });
});
