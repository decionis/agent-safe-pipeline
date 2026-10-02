import { readFile } from "node:fs/promises";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { ENTITLEMENT_TYPE, type EntitlementState } from "./EntitlementEvaluation.js";

/** Where Decionis publishes the keys that sign policy bundles and the entitlement. */
export const ENTITLEMENT_JWKS_PATH = "/.well-known/decionis-policy-bundle-jwks.json";
export const ENTITLEMENT_PATH = "/v1/edge/entitlement";

const COMPACT_JWS = /^[\w-]+\.[\w-]+\.[\w-]+$/;
const MAX_BYTES = 256 * 1024;

/** The signed entitlement and the keys to check it with, as a source read them. */
export interface EntitlementMaterial {
  /** The compact JWS, or null when there is none to read. */
  readonly token: string | null;
  /** The JWKS document's text, or null when it could not be read. */
  readonly jwks: string | null;
}

export interface EntitlementSource {
  read(): Promise<EntitlementMaterial>;
}

/** A base URL without its trailing slashes, trimmed in one pass. */
export function withoutTrailingSlash(url: string): string {
  let end = url.length;
  while (end > 0 && url[end - 1] === "/") end -= 1;
  return url.slice(0, end);
}

/**
 * The compact JWS out of what a source returned: the JWS on its own, or a
 * JSON object carrying it as `entitlement` or `signed_entitlement`.
 */
export function entitlementTokenOf(text: string): string | null {
  const trimmed = text.trim();
  let candidate: unknown = trimmed;
  if (trimmed.startsWith("{")) {
    try {
      const body = JSON.parse(trimmed) as Record<string, unknown>;
      candidate = body["signed_entitlement"] ?? body["entitlement"];
    } catch {
      return null;
    }
  }
  return typeof candidate === "string" && COMPACT_JWS.test(candidate) ? candidate : null;
}

/**
 * Checks the entitlement's signature against the JWKS: `alg` EdDSA, the
 * entitlement's `typ`, a `kid` the JWKS holds. Its claims are evaluated
 * elsewhere (`licenceWarnings`), so an expired entitlement is still read.
 */
export async function verifyEntitlement(material: EntitlementMaterial): Promise<EntitlementState> {
  if (material.token === null) return { status: "missing" };
  const { compactVerify, decodeProtectedHeader, importJWK } = await import("jose");
  try {
    const header = decodeProtectedHeader(material.token);
    const keys = (JSON.parse(material.jwks ?? "null") as { keys?: unknown }).keys;
    const jwk = Array.isArray(keys)
      ? (keys as Record<string, unknown>[]).find((key) => key["kid"] === header.kid)
      : undefined;
    if (header.alg !== "EdDSA" || header.typ !== ENTITLEMENT_TYPE || jwk === undefined) {
      return { status: "read", claims: null };
    }
    const key = await importJWK({ ...jwk, alg: "EdDSA" }, "EdDSA");
    const { payload } = await compactVerify(material.token, key, { algorithms: ["EdDSA"] });
    return { status: "read", claims: JSON.parse(new TextDecoder().decode(payload)) };
  } catch {
    return { status: "read", claims: null };
  }
}

async function boundedText(response: Response): Promise<string | null> {
  const text = await response.text();
  return Buffer.byteLength(text) > MAX_BYTES ? null : text;
}

/**
 * `GET /v1/edge/entitlement` with the organisation's key, and the JWKS from
 * its well-known path on the same origin, both through the guarded fetch.
 * A failure of either is a missing entitlement or keys, never an error: the
 * entitlement only ever warns.
 */
export class UrlEntitlementSource implements EntitlementSource {
  public constructor(
    private readonly options: {
      readonly baseUrl: string;
      readonly apiKey: () => string;
      readonly fetch: FetchLike;
      readonly timeoutMs?: number;
    },
  ) {}

  public async read(): Promise<EntitlementMaterial> {
    const base = withoutTrailingSlash(this.options.baseUrl);
    const [entitlement, jwks] = await Promise.all([
      this.get(`${base}${ENTITLEMENT_PATH}`, true),
      this.get(`${base}${ENTITLEMENT_JWKS_PATH}`, false),
    ]);
    return { token: entitlement === null ? null : entitlementTokenOf(entitlement), jwks };
  }

  private async get(url: string, authenticated: boolean): Promise<string | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 10_000);
    try {
      const response = await this.options.fetch(url, {
        method: "GET",
        headers: {
          accept: "application/json",
          ...(authenticated ? { authorization: `Bearer ${this.options.apiKey()}` } : {}),
        },
        signal: controller.signal,
      });
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        return null;
      }
      return await boundedText(response);
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }
}

/**
 * The air-gapped form: the entitlement an operator downloaded and placed on
 * disk, and the Decionis JWKS pinned beside it. Either file missing is a
 * missing entitlement or keys.
 */
export class FileEntitlementSource implements EntitlementSource {
  public constructor(
    private readonly entitlementFile: string | null,
    private readonly jwksFile: string | null,
  ) {}

  public async read(): Promise<EntitlementMaterial> {
    const read = async (path: string | null): Promise<string | null> => {
      if (path === null) return null;
      try {
        const text = await readFile(path, "utf8");
        return Buffer.byteLength(text) > MAX_BYTES ? null : text;
      } catch {
        return null;
      }
    };
    const entitlement = await read(this.entitlementFile);
    return {
      token: entitlement === null ? null : entitlementTokenOf(entitlement),
      jwks: await read(this.jwksFile),
    };
  }
}
