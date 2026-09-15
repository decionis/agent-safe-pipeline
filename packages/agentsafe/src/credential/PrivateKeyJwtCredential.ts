import { randomUUID } from "node:crypto";
import { importPKCS8, SignJWT } from "jose";
import { z } from "zod";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { SecretHandle } from "../secrets/SecretHandle.js";
import { CredentialError } from "./CredentialError.js";
import type { DownstreamCredential } from "./DownstreamCredential.js";

export type PrivateKeyJwtAlgorithm = "ES256" | "PS256";

export interface PrivateKeyJwtOptions {
  /** The token endpoint; a sealed egress destination under the downstream's anchor. */
  readonly tokenUrl: string;
  readonly clientId: string;
  readonly keyId: string | null;
  readonly algorithm: PrivateKeyJwtAlgorithm;
  /** The assertion's audience; the token endpoint itself when null. */
  readonly audience: string | null;
  readonly scope: string | null;
  readonly timeoutMs: number;
}

export const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ASSERTION_LIFETIME_SECONDS = 60;
const REFRESH_MARGIN_SECONDS = 30;

const TokenResponseSchema = z.object({
  access_token: z.string().min(1).max(8_192),
  token_type: z.string().min(1).max(32),
  expires_in: z.coerce
    .number()
    .int()
    .positive()
    .max(30 * 24 * 60 * 60),
});

/**
 * OAuth 2.0 client credentials with `private_key_jwt`, the FAPI baseline:
 * an assertion signed with this process's private key proves the client to
 * the token endpoint, and the access token it returns is held as a secret
 * handle until thirty seconds before it expires, one refresh in flight at a
 * time. A token that cannot be obtained is a failure before dispatch: the
 * handler asks for headers before `dispatch.run`, so the downstream never
 * sees a request this process could not authenticate.
 */
export class PrivateKeyJwtCredential implements DownstreamCredential {
  private cached: { readonly token: SecretHandle; readonly refreshAt: number } | null = null;
  private pending: Promise<SecretHandle> | null = null;

  public readonly kind = "PRIVATE_KEY_JWT" as const;

  public constructor(
    private readonly options: PrivateKeyJwtOptions,
    private readonly key: () => SecretHandle,
    private readonly fetchImpl: FetchLike,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** The bearer header for any request; what is signed is the assertion to the token endpoint, not the request. */
  public readonly headersFor: DownstreamCredential["headersFor"] = async () => {
    const token = await this.token();
    return { authorization: token.use((value) => `Bearer ${value.toString("utf8")}`) };
  };

  /** Whether a token is held and still fresh; for status, never the value. */
  public get fresh(): boolean {
    return this.cached !== null && this.clock() < this.cached.refreshAt;
  }

  public close(): void {
    this.cached?.token.dispose();
    this.cached = null;
  }

  private async token(): Promise<SecretHandle> {
    if (this.cached !== null && this.clock() < this.cached.refreshAt) return this.cached.token;
    if (this.pending === null) {
      this.pending = this.obtain().finally(() => {
        this.pending = null;
      });
    }
    return await this.pending;
  }

  private async obtain(): Promise<SecretHandle> {
    const now = Math.floor(this.clock() / 1_000);
    const { options } = this;
    const assertion = await this.key().use(async (pem) => {
      const key = await importPKCS8(pem.toString("utf8"), options.algorithm);
      return await new SignJWT({})
        .setProtectedHeader({
          alg: options.algorithm,
          ...(options.keyId === null ? {} : { kid: options.keyId }),
        })
        .setIssuer(options.clientId)
        .setSubject(options.clientId)
        .setAudience(options.audience ?? options.tokenUrl)
        .setJti(randomUUID())
        .setIssuedAt(now)
        .setExpirationTime(now + ASSERTION_LIFETIME_SECONDS)
        .sign(key);
    });
    const form = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: options.clientId,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion,
      ...(options.scope === null ? {} : { scope: options.scope }),
    });
    let response: Response;
    try {
      response = await this.fetchImpl(options.tokenUrl, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
        body: form.toString(),
        signal: AbortSignal.timeout(options.timeoutMs),
      });
    } catch {
      throw new CredentialError("DOWNSTREAM_TOKEN_UNREACHABLE");
    }
    if (!response.ok) throw new CredentialError("DOWNSTREAM_TOKEN_REFUSED");
    let parsed: z.infer<typeof TokenResponseSchema>;
    try {
      parsed = TokenResponseSchema.parse(await response.json());
    } catch {
      throw new CredentialError("DOWNSTREAM_TOKEN_INVALID");
    }
    if (parsed.token_type.toLowerCase() !== "bearer") {
      throw new CredentialError("DOWNSTREAM_TOKEN_INVALID");
    }
    const previous = this.cached;
    const token = SecretHandle.fromString("DOWNSTREAM_ACCESS_TOKEN", parsed.access_token);
    this.cached = {
      token,
      refreshAt: this.clock() + Math.max(parsed.expires_in - REFRESH_MARGIN_SECONDS, 1) * 1_000,
    };
    previous?.token.dispose();
    return token;
  }
}
