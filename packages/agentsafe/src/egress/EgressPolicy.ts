import { createHash } from "node:crypto";
import { BlockList, isIP } from "node:net";
import type { ExecutorConfig, TrustAnchor } from "../config/ExecutorConfig.js";
import type { EgressCode } from "./EgressError.js";

/** One origin this process may reach, the paths under it, and how it is trusted. */
export interface EgressDestination {
  readonly origin: string;
  readonly pathPrefixes: readonly string[];
  /** The PEM bundle to verify the peer against; the platform's store when null. */
  readonly ca: string | null;
  readonly pins: readonly string[];
}

export type EgressCheck =
  | { readonly allowed: true; readonly destination: EgressDestination }
  | { readonly allowed: false; readonly code: EgressCode };

/**
 * The sealed allowlist of where this process may open a connection: the
 * authority, the Presence service when this process holds that credential,
 * and the downstream and its lookup, each with the path prefix the
 * configuration named and the trust anchor it declared. Nothing is added at
 * run time; a handler that reaches elsewhere is refused before a socket
 * exists. Private address ranges are allowed by design, because that is
 * where an institution's systems live; what a configured name must never
 * resolve to is this host, the link, multicast, or nowhere.
 */
export class EgressPolicy {
  private readonly destinations: ReadonlyMap<string, EgressDestination>;

  public constructor(destinations: readonly EgressDestination[]) {
    const merged = new Map<string, EgressDestination>();
    for (const destination of destinations) {
      const existing = merged.get(destination.origin);
      merged.set(
        destination.origin,
        existing === undefined
          ? destination
          : {
              ...existing,
              pathPrefixes: [...new Set([...existing.pathPrefixes, ...destination.pathPrefixes])],
            },
      );
    }
    this.destinations = merged;
  }

  /** The policy a configuration implies; CA bundles are read once, here. */
  public static fromConfig(
    config: ExecutorConfig,
    readFile: (path: string) => string,
  ): EgressPolicy {
    const trust = config.egress.trust;
    const anchored = (
      urls: readonly string[],
      anchor: TrustAnchor,
      key: string,
    ): EgressDestination[] =>
      urls.map((url) => ({
        origin: EgressPolicy.originOf(url),
        pathPrefixes: [EgressPolicy.prefixOf(url)],
        ca: anchor.caFile === null ? null : EgressPolicy.bundle(readFile(anchor.caFile), key),
        pins: anchor.pins,
      }));
    const downstream = [
      config.downstream.url,
      ...(config.downstream.lookupUrl === null ? [] : [config.downstream.lookupUrl]),
      ...(config.downstream.credential.kind === "PRIVATE_KEY_JWT"
        ? [config.downstream.credential.tokenUrl]
        : []),
      ...(config.banking.lookupByReferenceUrl === null
        ? []
        : [config.banking.lookupByReferenceUrl]),
    ];
    const jwt = config.identity.jwt;
    const jwks =
      jwt === null || jwt.jwksUrl === null
        ? []
        : anchored([jwt.jwksUrl], { caFile: jwt.jwksCaFile, pins: [] }, "EXECUTOR_JWKS_CA_FILE");
    return new EgressPolicy([
      ...anchored([config.authority.baseUrl], trust.authority, "DECIONIS_CA_FILE"),
      ...(config.escalation.mode === "DIRECT"
        ? anchored([config.escalation.presence.baseUrl], trust.presence, "PRESENCE_CA_FILE")
        : []),
      ...anchored(downstream, trust.downstream, "DOWNSTREAM_CA_FILE"),
      ...jwks,
    ]);
  }

  public get origins(): readonly string[] {
    return [...this.destinations.keys()];
  }

  /** Scheme, origin, then path, in that order; the first failure is the answer. */
  public check(url: URL): EgressCheck {
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return { allowed: false, code: "EGRESS_SCHEME_NOT_ALLOWED" };
    }
    if (url.protocol === "http:" && !EgressPolicy.isLoopbackHost(url.hostname)) {
      return { allowed: false, code: "EGRESS_SCHEME_NOT_ALLOWED" };
    }
    if (url.username !== "" || url.password !== "") {
      return { allowed: false, code: "EGRESS_ORIGIN_NOT_ALLOWED" };
    }
    const destination = this.destinations.get(url.origin);
    if (destination === undefined) return { allowed: false, code: "EGRESS_ORIGIN_NOT_ALLOWED" };
    const under = destination.pathPrefixes.some((prefix) =>
      EgressPolicy.underPrefix(url.pathname, prefix),
    );
    if (!under) return { allowed: false, code: "EGRESS_PATH_NOT_ALLOWED" };
    return { allowed: true, destination };
  }

  /** The prefix itself, or anything below it as a path segment; never a sibling that merely shares characters. */
  public static underPrefix(pathname: string, prefix: string): boolean {
    return pathname === prefix || pathname.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`);
  }

  /**
   * Whether a resolved address may be connected to for an origin. A loopback
   * origin must stay on this host; any other must never resolve to this
   * host, the link, multicast, or nowhere. The lists are built per call so
   * that nothing about them is decided at module load.
   */
  public static addressRefused(address: string, loopbackOrigin: boolean): boolean {
    const family = isIP(address);
    if (family === 0) return true;
    const type = family === 4 ? "ipv4" : "ipv6";
    const list = new BlockList();
    if (loopbackOrigin) {
      list.addSubnet("127.0.0.0", 8, "ipv4");
      list.addAddress("::1", "ipv6");
      return !list.check(address, type);
    }
    list.addSubnet("0.0.0.0", 8, "ipv4");
    list.addSubnet("127.0.0.0", 8, "ipv4");
    list.addSubnet("169.254.0.0", 16, "ipv4");
    list.addSubnet("224.0.0.0", 4, "ipv4");
    list.addSubnet("240.0.0.0", 4, "ipv4");
    list.addAddress("::", "ipv6");
    list.addAddress("::1", "ipv6");
    list.addSubnet("fe80::", 10, "ipv6");
    list.addSubnet("ff00::", 8, "ipv6");
    return list.check(address, type);
  }

  /** The three loopback spellings the configuration accepts. */
  public static isLoopbackHost(hostname: string): boolean {
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
  }

  /** The origin the configuration named, exactly as the URL class spells it. */
  public static originOf(url: string): string {
    return new URL(url).origin;
  }

  /** The path the configuration named, cut at a placeholder such as `{idempotency_key}`. */
  public static prefixOf(url: string): string {
    return new URL(url.split("{")[0] ?? url).pathname;
  }

  /** `sha256/<base64>` over a DER SubjectPublicKeyInfo: the pin form the configuration takes. */
  public static spkiPin(spki: Uint8Array): string {
    return `sha256/${createHash("sha256").update(spki).digest("base64")}`;
  }

  private static bundle(text: string, key: string): string {
    if (!text.includes("-----BEGIN CERTIFICATE-----")) {
      throw new Error(`CONFIG_INVALID: ${key} (not a PEM certificate bundle)`);
    }
    return text;
  }
}
