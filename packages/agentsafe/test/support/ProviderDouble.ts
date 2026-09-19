import { createHash, sign, type KeyObject } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";

const LOOPBACK_ORIGIN = "http://127.0.0.1";

/** What a verifying provider signs its effect receipts with, and who it signs as. */
export interface ReceiptSigner {
  readonly kid: string;
  readonly issuer: string;
  readonly audience: string;
  readonly privateKey: KeyObject;
}

/**
 * A downstream provider with the two properties that matter: it deduplicates
 * on the idempotency key, and it can lose a response after taking effect.
 */
export class ProviderDouble {
  public readonly effects = new Set<string>();
  public readonly requests: {
    readonly path: string;
    readonly headers: IncomingMessage["headers"];
    readonly body: string;
  }[] = [];
  /** The access token the token endpoint hands out; never a value a real provider would issue. */
  public readonly accessToken = "synthetic-provider-access-token-0123456789";
  /** When set, every effected dispatch answers with a signed receipt of the effect (VP-3). */
  public receipts: ReceiptSigner | null = null;
  private loseNextResponse = false;
  private server: Server | null = null;
  private port = 0;

  public get baseUrl(): string {
    return `${LOOPBACK_ORIGIN}:${this.port}`;
  }

  public get dispatches(): number {
    return this.requests.filter((request) => request.path === "/dispatches").length;
  }

  public loseNext(): void {
    this.loseNextResponse = true;
  }

  public async start(): Promise<void> {
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        const path = request.url ?? "/";
        const body = Buffer.concat(chunks).toString("utf8");
        this.requests.push({ path, headers: request.headers, body });
        const reply = (
          status: number,
          body: unknown,
          headers: Record<string, string> = {},
        ): void => {
          response.writeHead(status, { "content-type": "application/json", ...headers });
          response.end(JSON.stringify(body));
        };
        if (request.method === "POST" && path === "/oauth/token") {
          const form = new URLSearchParams(body);
          if (form.get("grant_type") !== "client_credentials" || !form.has("client_assertion")) {
            return reply(400, { error: "invalid_request" });
          }
          return reply(200, {
            access_token: this.accessToken,
            token_type: "Bearer",
            expires_in: 300,
          });
        }
        if (request.method === "POST" && path === "/dispatches") {
          const key = String(request.headers["idempotency-key"] ?? "");
          if (this.effects.has(key)) return reply(200, { duplicate: true });
          this.effects.add(key);
          if (this.loseNextResponse) {
            this.loseNextResponse = false;
            request.socket.destroy();
            return;
          }
          const receipt = this.receipt(request, key);
          return reply(
            202,
            { accepted: true },
            receipt === null ? {} : { "x-agent-safe-effect-receipt": receipt },
          );
        }
        if (request.method === "GET" && path.startsWith("/dispatches/")) {
          const key = decodeURIComponent(path.slice("/dispatches/".length));
          return this.effects.has(key) ? reply(200, { effected: true }) : reply(404, {});
        }
        reply(404, {});
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    this.port = typeof address === "object" && address !== null ? address.port : 0;
    this.server = server;
  }

  public async stop(): Promise<void> {
    const server = this.server;
    if (server === null) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  /**
   * The receipt a verifying provider returns: signed with its own key, the
   * grant it effected under as subject, the claim it answered named by the
   * digest it copies from the attestation the executor forwarded. This double
   * has already been the authority's client in the attestation's terms; here
   * it is the provider, so it reads the attestation's payload and signs.
   */
  private receipt(request: IncomingMessage, idempotencyKey: string): string | null {
    const signer = this.receipts;
    const attestation = request.headers["x-agent-safe-claim-attestation"];
    if (signer === null || typeof attestation !== "string") return null;
    const [, encodedClaims = ""] = attestation.split(".");
    const claims = JSON.parse(Buffer.from(encodedClaims, "base64url").toString("utf8")) as {
      sub: string;
      decision_id: string;
      dossier_id: string;
      claim_token_digest: string;
      jti: string;
      binding: { intent_hash: string; expected_effect_digest?: string };
    };
    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
    const header = encode({ alg: "EdDSA", typ: "decionis-effect-receipt+jwt", kid: signer.kid });
    const payload = encode({
      iss: signer.issuer,
      aud: signer.audience,
      sub: claims.sub,
      decision_id: claims.decision_id,
      dossier_id: claims.dossier_id,
      claim_token_digest: claims.claim_token_digest,
      attestation_jti: claims.jti,
      intent_hash: claims.binding.intent_hash,
      idempotency_key: idempotencyKey,
      effect: {
        status: "EFFECTED",
        reference: `provider:dispatch:${createHash("sha256").update(idempotencyKey).digest("hex").slice(0, 12)}`,
        ...(claims.binding.expected_effect_digest === undefined
          ? {}
          : { digest: claims.binding.expected_effect_digest }),
        effected_at: new Date().toISOString(),
      },
      iat: Math.floor(Date.now() / 1_000),
      jti: `receipt-${this.effects.size}`,
    });
    const signature = sign(null, Buffer.from(`${header}.${payload}`, "ascii"), signer.privateKey);
    return `${header}.${payload}.${signature.toString("base64url")}`;
  }
}
