import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import type { SecretHandle } from "../secrets/SecretHandle.js";
import type { DownstreamCredential, DownstreamRequest } from "./DownstreamCredential.js";

export type SignedRequestAlgorithm = "ed25519" | "hmac-sha256";

export interface SignedRequestOptions {
  readonly algorithm: SignedRequestAlgorithm;
  readonly keyId: string;
}

/** The covered components, in the order the signature base lists them. */
export const SIGNED_COMPONENTS = [
  "@method",
  "@path",
  "content-digest",
  "idempotency-key",
  "x-agent-safe-intent-hash",
] as const;

export const SIGNATURE_LABEL = "agentsafe";

/** What a verifier on the downstream side needs to rebuild the base. */
export interface SignedRequestMaterial {
  readonly method: string;
  readonly path: string;
  readonly body: string | null;
  readonly idempotencyKey: string;
  readonly intentHash: string;
}

/**
 * RFC 9421 HTTP message signatures over a fixed set of components, with an
 * RFC 9530 content digest: the method, the path, the body's digest, the
 * idempotency key, and the intent hash, so the downstream can prove that
 * this process, holding this key, sent this request for this intent. The
 * handler must send `idempotency-key` and `x-agent-safe-intent-hash` with
 * the values it asked the credential to sign; the reference handler does.
 * Ed25519 or HMAC-SHA256; the key is a secret handle read at each request.
 */
export class SignedRequestCredential implements DownstreamCredential {
  public readonly kind = "SIGNED_REQUEST" as const;

  public constructor(
    private readonly options: SignedRequestOptions,
    private readonly key: () => SecretHandle,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** The RFC 9530 digest of a body, the empty body included. */
  public static contentDigest(body: string | null): string {
    return `sha-256=:${createHash("sha256")
      .update(body ?? "", "utf8")
      .digest("base64")}:`;
  }

  /** The signature parameters, as they appear in `signature-input` and at the base's end. */
  public static parameters(
    created: number,
    keyId: string,
    algorithm: SignedRequestAlgorithm,
  ): string {
    const components = SIGNED_COMPONENTS.map((component) => `"${component}"`).join(" ");
    return `(${components});created=${created};keyid="${keyId}";alg="${algorithm}"`;
  }

  /** The signature base, exactly as both sides must build it. */
  public static base(material: SignedRequestMaterial, parameters: string): string {
    return [
      `"@method": ${material.method.toUpperCase()}`,
      `"@path": ${material.path}`,
      `"content-digest": ${SignedRequestCredential.contentDigest(material.body)}`,
      `"idempotency-key": ${material.idempotencyKey}`,
      `"x-agent-safe-intent-hash": ${material.intentHash}`,
      `"@signature-params": ${parameters}`,
    ].join("\n");
  }

  /**
   * What the downstream runs: rebuild the base from the request it received
   * and the parameters in `signature-input`, then check the signature with
   * the public key (Ed25519) or the shared secret (HMAC-SHA256).
   */
  public static verify(
    material: SignedRequestMaterial,
    headers: Readonly<Record<string, string>>,
    verifier: { readonly publicKeyPem: string } | { readonly secret: Uint8Array },
  ): boolean {
    const input = headers["signature-input"] ?? "";
    const signature = headers["signature"] ?? "";
    const digest = headers["content-digest"] ?? "";
    const prefix = `${SIGNATURE_LABEL}=`;
    if (
      !input.startsWith(prefix) ||
      !signature.startsWith(`${prefix}:`) ||
      !signature.endsWith(":")
    ) {
      return false;
    }
    if (digest !== SignedRequestCredential.contentDigest(material.body)) return false;
    const parameters = input.slice(prefix.length);
    const algorithm = /;alg="([a-z0-9-]+)"/.exec(parameters)?.[1];
    const base = Buffer.from(SignedRequestCredential.base(material, parameters), "utf8");
    const bytes = Buffer.from(signature.slice(prefix.length + 1, -1), "base64");
    if ("publicKeyPem" in verifier) {
      if (algorithm !== "ed25519") return false;
      return verify(null, base, createPublicKey(verifier.publicKeyPem), bytes);
    }
    if (algorithm !== "hmac-sha256") return false;
    const expected = createHmac("sha256", verifier.secret).update(base).digest();
    return expected.length === bytes.length && expected.equals(bytes);
  }

  public async headersFor(request: DownstreamRequest): Promise<Readonly<Record<string, string>>> {
    const created = Math.floor(this.clock() / 1_000);
    const parameters = SignedRequestCredential.parameters(
      created,
      this.options.keyId,
      this.options.algorithm,
    );
    const material: SignedRequestMaterial = {
      method: request.method,
      path: new URL(request.url).pathname,
      body: request.body,
      idempotencyKey: request.idempotencyKey,
      intentHash: request.intentHash,
    };
    const base = Buffer.from(SignedRequestCredential.base(material, parameters), "utf8");
    const signature = this.key().use((material) =>
      this.options.algorithm === "ed25519"
        ? sign(null, base, createPrivateKey(material))
        : createHmac("sha256", material).update(base).digest(),
    );
    return await Promise.resolve({
      "content-digest": SignedRequestCredential.contentDigest(request.body),
      "signature-input": `${SIGNATURE_LABEL}=${parameters}`,
      signature: `${SIGNATURE_LABEL}=:${signature.toString("base64")}:`,
    });
  }
}
