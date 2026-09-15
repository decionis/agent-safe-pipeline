import { constants } from "node:crypto";
import type { RequestListener } from "node:http";
import { createServer, type Server, type ServerOptions } from "node:https";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import type { SecretHandle } from "../secrets/SecretHandle.js";

export type TlsMinVersion = "TLSv1.2" | "TLSv1.3";

/** What the listener presents and, when a client CA is set, what it asks for. */
export interface TlsMaterial {
  readonly cert: string;
  readonly key: SecretHandle;
  readonly clientCa: string | null;
}

export interface TlsListenerOptions {
  readonly minVersion: TlsMinVersion;
  /** Read at construction and at every rotation: the certificate, the key handle, the client CA. */
  readonly material: () => TlsMaterial;
  readonly events: SecurityEvents;
}

/** For TLS 1.2 only: ECDHE with an AEAD cipher; TLS 1.3 has nothing else to offer. */
export const TLS12_CIPHERS = [
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
].join(":");

/**
 * The TLS listener: TLS 1.3 by default, 1.2 only with AEAD ciphers, no
 * renegotiation, HTTP/1.1 only. When a client CA is configured every
 * connection is asked for a certificate, but the handshake admits a client
 * without one deliberately, because the kubelet's HTTPS probes present
 * none; the door then requires `socket.authorized` on every route that is
 * not public, so a probe reaches `/health` and nothing else. The context is
 * replaced in place when the key rotates, and connections already open keep
 * the context they negotiated.
 */
export class TlsListener {
  public readonly mutual: boolean;

  public constructor(private readonly options: TlsListenerOptions) {
    this.mutual = options.material().clientCa !== null;
  }

  public createServer(handler: RequestListener): Server {
    return createServer(this.context(), handler);
  }

  public rotate(server: Server): void {
    server.setSecureContext(this.context());
    this.options.events.emit({ event: "TLS_CONTEXT_ROTATED" });
  }

  private context(): ServerOptions {
    const material = this.options.material();
    return material.key.use((key) => ({
      cert: material.cert,
      key,
      ...(material.clientCa === null ? {} : { ca: material.clientCa, requestCert: true }),
      rejectUnauthorized: false,
      minVersion: this.options.minVersion,
      maxVersion: "TLSv1.3",
      ciphers: TLS12_CIPHERS,
      honorCipherOrder: true,
      secureOptions: constants.SSL_OP_NO_RENEGOTIATION,
      ALPNProtocols: ["http/1.1"],
    }));
  }
}
