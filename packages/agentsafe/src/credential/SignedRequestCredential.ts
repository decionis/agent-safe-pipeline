import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import type { SecretHandle } from "../secrets/SecretHandle.js";
import type { DownstreamCredential, DownstreamRequest } from "./DownstreamCredential.js";

export type SignedRequestAlgorithm = "ed25519" | "hmac-sha256";

export interface SignedRequestOptions {
  readonly algorithm: SignedRequestAlgorithm;
  readonly keyId: string;
}

/** Covered on every request: what was sent, to where, for which intent. */
export const BASE_COMPONENTS = [
  "@method",
  "@path",
  "content-digest",
  "idempotency-key",
  "x-agent-safe-intent-hash",
] as const;

/** Covered on a dispatch: which grant, and which decision, this request executes under. */
export const GRANT_COMPONENTS = ["x-agent-safe-grant-id", "x-agent-safe-decision-id"] as const;

/** Covered when the authority attested the claim: its proof, bound to this request. */
export const ATTESTATION_COMPONENT = "x-agent-safe-claim-attestation" as const;

/** Every component this credential can cover, in the order the base lists them. */
export const SIGNED_COMPONENTS = [
  ...BASE_COMPONENTS,
  ...GRANT_COMPONENTS,
  ATTESTATION_COMPONENT,
] as const;

export type SignedComponent = (typeof SIGNED_COMPONENTS)[number];

export const SIGNATURE_LABEL = "agentsafe";

/** What a verifier on the downstream side needs to rebuild the base. */
export interface SignedRequestMaterial {
  readonly method: string;
  readonly path: string;
  readonly body: string | null;
  readonly idempotencyKey: string;
  readonly intentHash: string;
  readonly grantId?: string;
  readonly decisionId?: string;
  readonly claimAttestation?: string;
}

/** What a downstream may insist the signature cover before it acts. */
export interface SignedRequestVerification {
  /**
   * Components that must be among the covered ones. A system of record that
   * effects anything requires the grant pair and the attestation; a read that
   * effects nothing may accept the base alone. The base is always required.
   */
  readonly require?: readonly SignedComponent[];
}

const COMPONENT_LIST = /^\(((?:"[^"]+"(?: |(?=\))))*)\)/;
/** `signature-input`: this credential's label, then the parameters from their opening parenthesis. */
const SIGNATURE_INPUT = /^agentsafe=(\(.*)/;
/** `signature`: this credential's label, then the base64 signature between colons. */
const SIGNATURE = /^agentsafe=:(.*):$/;

/**
 * RFC 9421 HTTP message signatures with an RFC 9530 content digest. The base
 * always covers the method, the path, the body's digest, the idempotency key
 * and the intent hash, so the downstream can prove that this process,
 * holding this key, sent this request for this intent. A dispatch also
 * covers the grant id and the decision id, and, when the authority attested
 * the claim, the attestation itself: then the downstream can prove that the
 * authority claimed this grant for this intent, which is the difference
 * between refusing an unsigned instruction and refusing an unauthorized one.
 *
 * `signature-input` names exactly what was covered, and the verifier rebuilds
 * from that rather than from a fixed list: a request that carries a grant
 * header the signature does not cover proves nothing about that grant. The
 * handler must send every covered header with the value it asked the
 * credential to sign; the reference handlers do. Ed25519 or HMAC-SHA256;
 * the key is a secret handle read at each request.
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
      .update(body ?? "")
      .digest("base64")}:`;
  }

  /** The components this material can cover, in base order. */
  public static componentsFor(material: SignedRequestMaterial): readonly SignedComponent[] {
    const covered: SignedComponent[] = [...BASE_COMPONENTS];
    if (material.grantId !== undefined && material.decisionId !== undefined) {
      covered.push(...GRANT_COMPONENTS);
      if (material.claimAttestation !== undefined) covered.push(ATTESTATION_COMPONENT);
    }
    return covered;
  }

  /** The signature parameters, as they appear in `signature-input` and at the base's end. */
  public static parameters(
    created: number,
    keyId: string,
    algorithm: SignedRequestAlgorithm,
    components: readonly SignedComponent[] = BASE_COMPONENTS,
  ): string {
    const list = components.map((component) => `"${component}"`).join(" ");
    return `(${list});created=${created};keyid="${keyId}";alg="${algorithm}"`;
  }

  /** The covered components a `signature-input` names, or null when it names one this credential does not know. */
  public static coveredComponents(parameters: string): readonly SignedComponent[] | null {
    const list = COMPONENT_LIST.exec(parameters)?.[1];
    if (list === undefined) return null;
    const names = list.length === 0 ? [] : list.split(" ").map((quoted) => quoted.slice(1, -1));
    const known = new Set<string>(SIGNED_COMPONENTS);
    if (names.some((name) => !known.has(name)) || new Set(names).size !== names.length) return null;
    return names as SignedComponent[];
  }

  /** One line of the base, or null when the material cannot supply the component. */
  private static line(component: SignedComponent, material: SignedRequestMaterial): string | null {
    switch (component) {
      case "@method":
        return `"@method": ${material.method.toUpperCase()}`;
      case "@path":
        return `"@path": ${material.path}`;
      case "content-digest":
        return `"content-digest": ${SignedRequestCredential.contentDigest(material.body)}`;
      case "idempotency-key":
        return `"idempotency-key": ${material.idempotencyKey}`;
      case "x-agent-safe-intent-hash":
        return `"x-agent-safe-intent-hash": ${material.intentHash}`;
      case "x-agent-safe-grant-id":
        return material.grantId === undefined
          ? null
          : `"x-agent-safe-grant-id": ${material.grantId}`;
      case "x-agent-safe-decision-id":
        return material.decisionId === undefined
          ? null
          : `"x-agent-safe-decision-id": ${material.decisionId}`;
      case "x-agent-safe-claim-attestation":
        return material.claimAttestation === undefined
          ? null
          : `"x-agent-safe-claim-attestation": ${material.claimAttestation}`;
    }
  }

  /**
   * The signature base, exactly as both sides must build it: one line per
   * covered component in the order `parameters` lists them, then the
   * parameters. Null when the parameters name a component the material does
   * not have, which on the signing side is a bug and on the verifying side
   * is a request that does not carry what its signature claims to cover.
   */
  public static base(material: SignedRequestMaterial, parameters: string): string | null {
    const components = SignedRequestCredential.coveredComponents(parameters);
    if (components === null) return null;
    const lines: string[] = [];
    for (const component of components) {
      const line = SignedRequestCredential.line(component, material);
      if (line === null) return null;
      lines.push(line);
    }
    lines.push(`"@signature-params": ${parameters}`);
    return lines.join("\n");
  }

  /**
   * What the downstream runs: read which components the signature covers,
   * refuse if any it requires is missing, rebuild the base from the request
   * it received, then check the signature with the public key (Ed25519) or
   * the shared secret (HMAC-SHA256). The base five are always required; a
   * system of record passes the grant pair and the attestation too.
   *
   * The base is built from `material`, which is what the downstream will act
   * on. A header that says something else is not checked separately: if the
   * two disagree, the base differs from the one that was signed and the
   * signature fails, which is the refusal that matters.
   */
  public static verify(
    material: SignedRequestMaterial,
    headers: Readonly<Record<string, string>>,
    verifier: { readonly publicKeyPem: string } | { readonly secret: Uint8Array },
    verification: SignedRequestVerification = {},
  ): boolean {
    // Stryker disable next-line StringLiteral: an absent header and a string that is not this credential's parse the same, to nothing; the fallback satisfies the type.
    const header = (name: string): string => headers[name] ?? "";
    // A `signature-input` that does not carry the label yields no covered
    // list, which is the refusal below; the parameters need no check of
    // their own.
    // Stryker disable next-line StringLiteral: a non-match and any string that is not a component list parse the same, to nothing; the fallback satisfies the type.
    const parameters = SIGNATURE_INPUT.exec(header("signature-input"))?.[1] ?? "";
    const encoded = SIGNATURE.exec(header("signature"))?.[1];
    if (encoded === undefined) return false;
    if (header("content-digest") !== SignedRequestCredential.contentDigest(material.body)) {
      return false;
    }
    const covered = SignedRequestCredential.coveredComponents(parameters);
    if (covered === null) return false;
    for (const component of [...BASE_COMPONENTS, ...(verification.require ?? [])]) {
      if (!covered.includes(component)) return false;
    }
    const built = SignedRequestCredential.base(material, parameters);
    if (built === null) return false;
    const base = Buffer.from(built);
    const bytes = Buffer.from(encoded, "base64");
    switch (/;alg="([a-z0-9-]+)"/.exec(parameters)?.[1]) {
      case "ed25519":
        return (
          "publicKeyPem" in verifier &&
          verify(null, base, createPublicKey(verifier.publicKeyPem), bytes)
        );
      case "hmac-sha256": {
        if (!("secret" in verifier)) return false;
        const expected = createHmac("sha256", verifier.secret).update(base).digest();
        // A MAC is compared in constant time, and only at its own length: a
        // signature of another length is not a MAC over this base at all.
        return bytes.length === expected.length && timingSafeEqual(expected, bytes);
      }
      default:
        return false;
    }
  }

  /**
   * The material a downstream rebuilds from the request it received. The
   * grant fields come from the headers only when present, so a request that
   * carries none is verified against the base and refused by a downstream
   * that requires more.
   */
  public static materialFrom(received: {
    readonly method: string;
    readonly path: string;
    readonly body: string | null;
    readonly headers: Readonly<Record<string, string>>;
  }): SignedRequestMaterial {
    const { headers } = received;
    const grantId = headers["x-agent-safe-grant-id"];
    const decisionId = headers["x-agent-safe-decision-id"];
    const claimAttestation = headers["x-agent-safe-claim-attestation"];
    return {
      method: received.method,
      path: received.path,
      body: received.body,
      idempotencyKey: headers["idempotency-key"] ?? "",
      intentHash: headers["x-agent-safe-intent-hash"] ?? "",
      ...(grantId === undefined ? {} : { grantId }),
      ...(decisionId === undefined ? {} : { decisionId }),
      ...(claimAttestation === undefined ? {} : { claimAttestation }),
    };
  }

  /** The headers a handler must send beside the signature, with the values the signature covers. */
  public static coveredHeaders(request: DownstreamRequest): Readonly<Record<string, string>> {
    return {
      "idempotency-key": request.idempotencyKey,
      "x-agent-safe-intent-hash": request.intentHash,
      ...(request.grant === undefined
        ? {}
        : {
            "x-agent-safe-grant-id": request.grant.id,
            "x-agent-safe-decision-id": request.grant.decisionId,
            ...(request.grant.claimAttestation === undefined
              ? {}
              : { "x-agent-safe-claim-attestation": request.grant.claimAttestation }),
          }),
    };
  }

  public async headersFor(request: DownstreamRequest): Promise<Readonly<Record<string, string>>> {
    const created = Math.floor(this.clock() / 1_000);
    // The material is exactly what the covered headers will say, read the way
    // a downstream reads them, so the two sides cannot drift.
    const covered = SignedRequestCredential.coveredHeaders(request);
    const material = SignedRequestCredential.materialFrom({
      method: request.method,
      path: new URL(request.url).pathname,
      body: request.body,
      headers: covered,
    });
    const parameters = SignedRequestCredential.parameters(
      created,
      this.options.keyId,
      this.options.algorithm,
      SignedRequestCredential.componentsFor(material),
    );
    // The components were chosen from this material one line up, so every one
    // resolves; the branch exists so the type narrows, not because it can run.
    const built = SignedRequestCredential.base(material, parameters);
    // Stryker disable next-line all: unreachable by construction, and a test that reached it would be testing the type checker.
    if (built === null) throw new Error("SIGNED_REQUEST_BASE_UNBUILDABLE");
    const base = Buffer.from(built);
    const signature = this.key().use((material) =>
      this.options.algorithm === "ed25519"
        ? sign(null, base, createPrivateKey(material))
        : createHmac("sha256", material).update(base).digest(),
    );
    return await Promise.resolve({
      ...covered,
      "content-digest": SignedRequestCredential.contentDigest(request.body),
      "signature-input": `${SIGNATURE_LABEL}=${parameters}`,
      signature: `${SIGNATURE_LABEL}=:${signature.toString("base64")}:`,
    });
  }
}
