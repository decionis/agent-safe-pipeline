import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { EgressPolicy, type EgressDestination } from "../../src/egress/EgressPolicy.js";
import { offlineEnvironment } from "../support/Environment.js";

const AUTHORITY = "https://authority.decionis.example";
const DOWNSTREAM = "https://payouts.provider.example";
const CA_BUNDLE = "-----BEGIN CERTIFICATE-----\nc3ludGhldGlj\n-----END CERTIFICATE-----\n";

const direct = (): Record<string, string> => ({
  ...offlineEnvironment(),
  EXECUTOR_ESCALATION: "DIRECT",
  PRESENCE_API_URL: "https://presence.decionis.example/api",
  PRESENCE_API_KEY: "synthetic-presence-key",
  PRESENCE_ORGANIZATION: "Synthetic Treasury",
  PRESENCE_APPROVER_ID: "synthetic-approver",
  PRESENCE_VERIFICATION_LEVEL: "HIGH_CONFIDENCE",
  PRESENCE_VERIFICATION_METHODS: "WEBAUTHN,ACTIVE_LIVENESS",
  PRESENCE_HARDWARE_PKI_REQUIRED: "true",
  PRESENCE_DISALLOW_VIRTUAL_CAMERAS: "false",
});

const check = (policy: EgressPolicy, url: string): string =>
  ((result) => (result.allowed ? "ALLOWED" : result.code))(policy.check(new URL(url)));

describe("EgressPolicy.fromConfig", () => {
  it("seals exactly the origins and path prefixes the configuration names", () => {
    const policy = EgressPolicy.fromConfig(
      ExecutorConfigLoader.load(offlineEnvironment()),
      () => "",
    );
    expect(policy.origins).toEqual([AUTHORITY, DOWNSTREAM]);
    expect(check(policy, `${AUTHORITY}/v1/authority/enforce-and-bind`)).toBe("ALLOWED");
    expect(check(policy, `${DOWNSTREAM}/v1/payouts`)).toBe("ALLOWED");
    expect(check(policy, `${DOWNSTREAM}/v1/payouts/payout-1-v1`)).toBe("ALLOWED");
    expect(check(policy, `${DOWNSTREAM}/v1/payouts-admin`)).toBe("EGRESS_PATH_NOT_ALLOWED");
    expect(check(policy, `${DOWNSTREAM}/v1/refunds`)).toBe("EGRESS_PATH_NOT_ALLOWED");
    expect(check(policy, `${DOWNSTREAM}/`)).toBe("EGRESS_PATH_NOT_ALLOWED");
    expect(check(policy, "https://presence.decionis.example/api")).toBe(
      "EGRESS_ORIGIN_NOT_ALLOWED",
    );
    const result = policy.check(new URL(`${DOWNSTREAM}/v1/payouts/x`));
    expect(result.allowed && result.destination).toEqual({
      origin: DOWNSTREAM,
      pathPrefixes: ["/v1/payouts", "/v1/payouts/"],
      ca: null,
      pins: [],
    });
  });

  it("adds the Presence origin for the direct shape only, and one prefix without a lookup", () => {
    const withPresence = EgressPolicy.fromConfig(ExecutorConfigLoader.load(direct()), () => "");
    expect(withPresence.origins).toEqual([
      AUTHORITY,
      "https://presence.decionis.example",
      DOWNSTREAM,
    ]);
    expect(check(withPresence, "https://presence.decionis.example/api/v1/sessions")).toBe(
      "ALLOWED",
    );
    expect(check(withPresence, "https://presence.decionis.example/admin")).toBe(
      "EGRESS_PATH_NOT_ALLOWED",
    );
    const env = offlineEnvironment();
    delete env["DOWNSTREAM_LOOKUP_URL"];
    const single = EgressPolicy.fromConfig(ExecutorConfigLoader.load(env), () => "");
    const result = single.check(new URL(`${DOWNSTREAM}/v1/payouts`));
    expect(result.allowed && result.destination.pathPrefixes).toEqual(["/v1/payouts"]);
  });

  it("reads each CA bundle once from the path the configuration names, and refuses what is not one", () => {
    const files: Record<string, string> = {
      "/etc/agent-safe/authority-ca.pem": CA_BUNDLE,
      "/etc/agent-safe/presence-ca.pem": `${CA_BUNDLE}${CA_BUNDLE}`,
      "/etc/agent-safe/downstream-ca.pem": CA_BUNDLE,
    };
    const readFile = vi.fn((path: string) => files[path] ?? "not a bundle");
    const pins = `sha256/${"A".repeat(43)}=,sha256/${"B".repeat(43)}=`;
    const config = ExecutorConfigLoader.load({
      ...direct(),
      DECIONIS_CA_FILE: "/etc/agent-safe/authority-ca.pem",
      DECIONIS_SPKI_PINS: pins,
      PRESENCE_CA_FILE: "/etc/agent-safe/presence-ca.pem",
      DOWNSTREAM_CA_FILE: "/etc/agent-safe/downstream-ca.pem",
    });
    const policy = EgressPolicy.fromConfig(config, readFile);
    expect(readFile.mock.calls.map(([path]) => path)).toEqual([
      "/etc/agent-safe/authority-ca.pem",
      "/etc/agent-safe/presence-ca.pem",
      "/etc/agent-safe/downstream-ca.pem",
      "/etc/agent-safe/downstream-ca.pem",
    ]);
    const authority = policy.check(new URL(`${AUTHORITY}/v1/authority/enforce-and-bind`));
    expect(authority.allowed && authority.destination).toEqual({
      origin: AUTHORITY,
      pathPrefixes: ["/"],
      ca: CA_BUNDLE,
      pins: [`sha256/${"A".repeat(43)}=`, `sha256/${"B".repeat(43)}=`],
    });
    const presence = policy.check(new URL("https://presence.decionis.example/api/x"));
    expect(presence.allowed && presence.destination.ca).toBe(`${CA_BUNDLE}${CA_BUNDLE}`);
    for (const [key, path] of [
      ["DECIONIS_CA_FILE", "/etc/agent-safe/authority-ca.pem"],
      ["PRESENCE_CA_FILE", "/etc/agent-safe/presence-ca.pem"],
      ["DOWNSTREAM_CA_FILE", "/etc/agent-safe/downstream-ca.pem"],
    ] as const) {
      expect(() =>
        EgressPolicy.fromConfig(config, (candidate) =>
          candidate === path ? "-----BEGIN PRIVATE KEY-----" : CA_BUNDLE,
        ),
      ).toThrow(`CONFIG_INVALID: ${key} (not a PEM certificate bundle)`);
    }
  });
});

describe("EgressPolicy.fromConfig for the token endpoint and the JWKS", () => {
  it("seals the token endpoint under the downstream's anchor only for the private-key kind", () => {
    const base = offlineEnvironment();
    delete base["DOWNSTREAM_CREDENTIAL"];
    delete base["DOWNSTREAM_CREDENTIAL_HEADER"];
    const withToken = EgressPolicy.fromConfig(
      ExecutorConfigLoader.load({
        ...base,
        DOWNSTREAM_CREDENTIAL_KIND: "PRIVATE_KEY_JWT",
        DOWNSTREAM_TOKEN_URL: `${DOWNSTREAM}/oauth/token`,
        DOWNSTREAM_CLIENT_ID: "synthetic-client",
        DOWNSTREAM_PRIVATE_KEY: "synthetic-key-material",
      }),
      () => "",
    );
    expect(check(withToken, `${DOWNSTREAM}/oauth/token`)).toBe("ALLOWED");
    expect(check(withToken, `${DOWNSTREAM}/oauth/revoke`)).toBe("EGRESS_PATH_NOT_ALLOWED");
    const signed = EgressPolicy.fromConfig(
      ExecutorConfigLoader.load({
        ...base,
        DOWNSTREAM_CREDENTIAL_KIND: "SIGNED_REQUEST",
        DOWNSTREAM_SIGNING_KEY: "synthetic-key-material",
        DOWNSTREAM_SIGNING_KEY_ID: "k1",
      }),
      () => "",
    );
    expect(check(signed, `${DOWNSTREAM}/oauth/token`)).toBe("EGRESS_PATH_NOT_ALLOWED");
    expect(
      check(
        EgressPolicy.fromConfig(ExecutorConfigLoader.load(offlineEnvironment()), () => ""),
        `${DOWNSTREAM}/oauth/token`,
      ),
    ).toBe("EGRESS_PATH_NOT_ALLOWED");
  });

  it("seals the JWKS address with its own anchor, and nothing when there is none", () => {
    const readFile = vi.fn((path: string) =>
      path === "/etc/agent-safe/jwks-ca.pem" ? CA_BUNDLE : "not a bundle",
    );
    const refreshed = EgressPolicy.fromConfig(
      ExecutorConfigLoader.load({
        ...offlineEnvironment(),
        EXECUTOR_JWT_AUDIENCE: "agentsafe",
        EXECUTOR_JWKS_FILE: "/var/run/agent-safe/jwks/jwks.json",
        EXECUTOR_JWKS_URL: "https://kubernetes.default.svc.cluster.example/openid/v1/jwks",
        EXECUTOR_JWKS_CA_FILE: "/etc/agent-safe/jwks-ca.pem",
      }),
      readFile,
    );
    expect(refreshed.origins).toEqual([
      AUTHORITY,
      DOWNSTREAM,
      "https://kubernetes.default.svc.cluster.example",
    ]);
    const result = refreshed.check(
      new URL("https://kubernetes.default.svc.cluster.example/openid/v1/jwks"),
    );
    expect(result.allowed && result.destination).toEqual({
      origin: "https://kubernetes.default.svc.cluster.example",
      pathPrefixes: ["/openid/v1/jwks"],
      ca: CA_BUNDLE,
      pins: [],
    });
    expect(check(refreshed, "https://kubernetes.default.svc.cluster.example/api/v1/secrets")).toBe(
      "EGRESS_PATH_NOT_ALLOWED",
    );
    expect(readFile).toHaveBeenCalledWith("/etc/agent-safe/jwks-ca.pem");
    expect(() =>
      EgressPolicy.fromConfig(
        ExecutorConfigLoader.load({
          ...offlineEnvironment(),
          EXECUTOR_JWT_AUDIENCE: "agentsafe",
          EXECUTOR_JWKS_FILE: "/var/run/agent-safe/jwks/jwks.json",
          EXECUTOR_JWKS_URL: "https://kubernetes.default.svc.cluster.example/openid/v1/jwks",
          EXECUTOR_JWKS_CA_FILE: "/etc/agent-safe/jwks-ca.pem",
        }),
        (path) =>
          path === "/etc/agent-safe/jwks-ca.pem" ? "-----BEGIN PRIVATE KEY-----" : CA_BUNDLE,
      ),
    ).toThrow("CONFIG_INVALID: EXECUTOR_JWKS_CA_FILE (not a PEM certificate bundle)");
    const unanchored = EgressPolicy.fromConfig(
      ExecutorConfigLoader.load({
        ...offlineEnvironment(),
        EXECUTOR_JWT_AUDIENCE: "agentsafe",
        EXECUTOR_JWKS_FILE: "/var/run/agent-safe/jwks/jwks.json",
        EXECUTOR_JWKS_URL: "https://kubernetes.default.svc.cluster.example/openid/v1/jwks",
      }),
      () => {
        throw new Error("no file should be read");
      },
    );
    const plain = unanchored.check(
      new URL("https://kubernetes.default.svc.cluster.example/openid/v1/jwks"),
    );
    expect(plain.allowed && plain.destination.ca).toBeNull();
    const local = EgressPolicy.fromConfig(
      ExecutorConfigLoader.load({
        ...offlineEnvironment(),
        EXECUTOR_JWT_AUDIENCE: "agentsafe",
        EXECUTOR_JWKS_FILE: "/var/run/agent-safe/jwks/jwks.json",
      }),
      () => "",
    );
    expect(local.origins).toEqual([AUTHORITY, DOWNSTREAM]);
  });
});

describe("EgressPolicy.check", () => {
  const policy = new EgressPolicy([
    { origin: AUTHORITY, pathPrefixes: ["/"], ca: null, pins: [] },
    { origin: DOWNSTREAM, pathPrefixes: ["/v1/payouts"], ca: null, pins: [] },
    { origin: "http://127.0.0.1:8765", pathPrefixes: ["/dispatches"], ca: null, pins: [] },
  ]);

  it("refuses a scheme that is not HTTPS, or plain HTTP anywhere but loopback, before the origin is looked at", () => {
    expect(check(policy, "ftp://authority.decionis.example/x")).toBe("EGRESS_SCHEME_NOT_ALLOWED");
    expect(check(policy, "data:text/plain,hello")).toBe("EGRESS_SCHEME_NOT_ALLOWED");
    expect(check(policy, "http://authority.decionis.example/v1")).toBe("EGRESS_SCHEME_NOT_ALLOWED");
    expect(check(policy, "http://127.0.0.1:8765/dispatches/k")).toBe("ALLOWED");
    expect(check(policy, "http://127.0.0.1:1/dispatches")).toBe("EGRESS_ORIGIN_NOT_ALLOWED");
  });

  it("refuses credentials in the URL, an unlisted origin, a port that differs, and a path outside the prefix", () => {
    expect(check(policy, `https://user:pass@authority.decionis.example/v1`)).toBe(
      "EGRESS_ORIGIN_NOT_ALLOWED",
    );
    expect(check(policy, `https://user@authority.decionis.example/v1`)).toBe(
      "EGRESS_ORIGIN_NOT_ALLOWED",
    );
    expect(check(policy, `https://:secret@authority.decionis.example/v1`)).toBe(
      "EGRESS_ORIGIN_NOT_ALLOWED",
    );
    expect(check(policy, "https://elsewhere.example/v1/payouts")).toBe("EGRESS_ORIGIN_NOT_ALLOWED");
    expect(check(policy, `${DOWNSTREAM}:8443/v1/payouts`)).toBe("EGRESS_ORIGIN_NOT_ALLOWED");
    expect(check(policy, `${DOWNSTREAM}/v1/payouts`)).toBe("ALLOWED");
    expect(check(policy, `${DOWNSTREAM}/v1/payouts/x?y=1`)).toBe("ALLOWED");
    expect(check(policy, `${DOWNSTREAM}/v1/payoutsx`)).toBe("EGRESS_PATH_NOT_ALLOWED");
    expect(check(policy, `${DOWNSTREAM}/v1`)).toBe("EGRESS_PATH_NOT_ALLOWED");
    expect(check(policy, `${AUTHORITY}/anything/at/all`)).toBe("ALLOWED");
    expect(check(policy, `${AUTHORITY}`)).toBe("ALLOWED");
  });

  it("merges the prefixes of one origin named twice and keeps the first anchor", () => {
    const first: EgressDestination = {
      origin: DOWNSTREAM,
      pathPrefixes: ["/v1/payouts"],
      ca: CA_BUNDLE,
      pins: [`sha256/${"A".repeat(43)}=`, `sha256/${"B".repeat(43)}=`],
    };
    const merged = new EgressPolicy([
      first,
      { origin: DOWNSTREAM, pathPrefixes: ["/v1/lookups", "/v1/payouts"], ca: null, pins: [] },
    ]);
    expect(merged.origins).toEqual([DOWNSTREAM]);
    const result = merged.check(new URL(`${DOWNSTREAM}/v1/lookups/k`));
    expect(result.allowed && result.destination).toEqual({
      ...first,
      pathPrefixes: ["/v1/payouts", "/v1/lookups"],
    });
  });
});

describe("EgressPolicy helpers", () => {
  it("matches a prefix as a path segment, never as a shared spelling", () => {
    expect(EgressPolicy.underPrefix("/v1/payouts", "/v1/payouts")).toBe(true);
    expect(EgressPolicy.underPrefix("/v1/payouts/", "/v1/payouts")).toBe(true);
    expect(EgressPolicy.underPrefix("/v1/payouts/k", "/v1/payouts")).toBe(true);
    expect(EgressPolicy.underPrefix("/v1/payouts/k", "/v1/payouts/")).toBe(true);
    expect(EgressPolicy.underPrefix("/v1/payouts", "/v1/payouts/")).toBe(false);
    expect(EgressPolicy.underPrefix("/v1/payoutsx", "/v1/payouts")).toBe(false);
    expect(EgressPolicy.underPrefix("/v1", "/v1/payouts")).toBe(false);
    expect(EgressPolicy.underPrefix("/", "/")).toBe(true);
    expect(EgressPolicy.underPrefix("/x/y", "/")).toBe(true);
  });

  it("refuses the addresses a configured name must never resolve to, and keeps a loopback origin on this host", () => {
    const refused = [
      "127.0.0.1",
      "127.255.255.254",
      "0.0.0.0",
      "0.1.2.3",
      "169.254.169.254",
      "224.0.0.1",
      "239.255.255.255",
      "240.0.0.1",
      "255.255.255.255",
      "::",
      "::1",
      "fe80::1",
      "febf::1",
      "ff02::1",
      "::ffff:127.0.0.1",
      "::ffff:169.254.169.254",
      "not-an-address",
      "",
    ];
    const allowed = [
      "10.0.0.5",
      "172.16.0.9",
      "192.168.1.1",
      "100.64.0.1",
      "8.8.8.8",
      "1.0.0.0",
      "126.255.255.255",
      "128.0.0.1",
      "169.253.255.255",
      "169.255.0.0",
      "223.255.255.255",
      "2001:db8::1",
      "fc00::1",
      "fec0::1",
      "::2",
      "::ffff:10.0.0.5",
    ];
    for (const address of refused)
      expect([address, EgressPolicy.addressRefused(address, false)]).toEqual([address, true]);
    for (const address of allowed)
      expect([address, EgressPolicy.addressRefused(address, false)]).toEqual([address, false]);
    expect(EgressPolicy.addressRefused("127.0.0.1", true)).toBe(false);
    expect(EgressPolicy.addressRefused("127.0.0.53", true)).toBe(false);
    expect(EgressPolicy.addressRefused("::1", true)).toBe(false);
    expect(EgressPolicy.addressRefused("10.0.0.5", true)).toBe(true);
    expect(EgressPolicy.addressRefused("::2", true)).toBe(true);
    expect(EgressPolicy.addressRefused("bad", true)).toBe(true);
  });

  it("knows the three loopback spellings the configuration accepts", () => {
    expect(EgressPolicy.isLoopbackHost("localhost")).toBe(true);
    expect(EgressPolicy.isLoopbackHost("127.0.0.1")).toBe(true);
    expect(EgressPolicy.isLoopbackHost("[::1]")).toBe(true);
    expect(EgressPolicy.isLoopbackHost("127.0.0.2")).toBe(false);
    expect(EgressPolicy.isLoopbackHost("localhost.example")).toBe(false);
    expect(EgressPolicy.isLoopbackHost("")).toBe(false);
  });

  it("derives the origin and the prefix from a configured URL, cutting at a placeholder", () => {
    expect(EgressPolicy.originOf("https://Payouts.Provider.example:443/v1/payouts")).toBe(
      DOWNSTREAM,
    );
    expect(EgressPolicy.originOf("http://127.0.0.1:8765/dispatches")).toBe("http://127.0.0.1:8765");
    expect(EgressPolicy.prefixOf(`${DOWNSTREAM}/v1/payouts/{idempotency_key}`)).toBe(
      "/v1/payouts/",
    );
    expect(EgressPolicy.prefixOf(`${DOWNSTREAM}/v1/payouts`)).toBe("/v1/payouts");
    expect(EgressPolicy.prefixOf(AUTHORITY)).toBe("/");
    expect(EgressPolicy.prefixOf(`${AUTHORITY}/api/`)).toBe("/api/");
  });

  it("pins a SubjectPublicKeyInfo as sha256 over its DER, base64, with the scheme in front", () => {
    const spki = Buffer.from("synthetic-subject-public-key-info");
    const expected = createHash("sha256").update(spki).digest("base64");
    expect(EgressPolicy.spkiPin(spki)).toBe(`sha256/${expected}`);
    expect(EgressPolicy.spkiPin(spki)).toMatch(/^sha256\/[\w+/]{43}=$/);
    expect(EgressPolicy.spkiPin(Buffer.from("other"))).not.toBe(`sha256/${expected}`);
  });
});
