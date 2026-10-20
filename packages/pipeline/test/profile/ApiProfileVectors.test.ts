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
} from "../../src/profile/ApiProfile.js";
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
  } | null;
  readonly error?: string;
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
      };
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
    expect(asVector(profile.match(vector.request!))).toEqual(vector.expected);
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

describe("spec/profiles/api/v1/schema.json", () => {
  it("is generated from the validator this package runs", () => {
    expect(json(new URL("schema.json", SPEC))).toEqual(apiProfileJsonSchema());
  });
});
