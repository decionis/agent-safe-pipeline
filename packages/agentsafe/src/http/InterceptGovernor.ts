/**
 * The govern phase of transparent interception: for the destinations an
 * operator lists, the interceptor does not splice the connection through but
 * becomes its other end. A TLS connection is terminated with a leaf certificate
 * minted for the server name from the operator's own authority; a plaintext
 * connection is read as it is. Either way the bytes then reach the gateway's
 * listener, which runs the same lifecycle the addressed gateway runs: the
 * request is captured as an intent, the authority decides, and exactly the
 * authorized request is forwarded once to the real destination, or held, or
 * refused. Destinations not listed are the observe phase's business, spliced
 * through and counted, or refused, as the operator chose.
 *
 * TLS is terminated over a stream that replays the bytes already read while
 * the destination was being decided: Node's TLS reads a raw socket through
 * its handle, beneath the JavaScript stream those bytes were read from, so
 * handing it the socket would lose the hello. The adapter is the one seam
 * where the interceptor's own code touches the ciphertext, and it copies.
 */
import type { Socket } from "node:net";
import { Duplex } from "node:stream";
import { createSecureContext, TLSSocket } from "node:tls";
import type { InterceptProtocol } from "../intercept/Destination.js";
import type { LeafIssuer } from "../intercept/LeafIssuer.js";
import type { GatewayHttpServer } from "./GatewayHttpServer.js";

export type UnlistedPolicy = "passthrough" | "refuse";

export interface GovernorOptions {
  /** The hosts whose connections are governed, lowercase. */
  readonly hosts: ReadonlySet<string>;
  /** What becomes of a destination not listed: spliced through and counted, or refused. */
  readonly unlisted: UnlistedPolicy;
  /** Mints the leaf a governed TLS connection is terminated with; null refuses governed TLS. */
  readonly issuer: LeafIssuer | null;
  /** How long a governed TLS handshake may take. */
  readonly handshakeTimeoutMs: number;
}

export interface GovernorDependencies {
  /** The gateway listener for a governed host, created on first use and kept. */
  readonly gatewayFor: (host: string, protocol: InterceptProtocol) => Promise<GatewayHttpServer>;
}

export class GovernError extends Error {
  public constructor(
    public readonly code:
      "GOVERN_TLS_UNAVAILABLE" | "GOVERN_HANDSHAKE_FAILED" | "GOVERN_GATEWAY_UNAVAILABLE",
    public readonly detail: string | null = null,
  ) {
    super(detail === null ? code : `${code}: ${detail}`);
    this.name = "GovernError";
  }
}

export const GOVERN_DEFAULTS = {
  unlisted: "passthrough",
  handshakeTimeoutMs: 10_000,
} as const;

/**
 * A stream over a socket whose first bytes were already read: it delivers
 * those bytes first, then whatever the socket delivers, and writes through.
 */
export function replayed(socket: Socket, head: Buffer): Duplex {
  const adapter = new Duplex({
    read() {
      socket.resume();
    },
    write(chunk: Buffer, _encoding, callback) {
      socket.write(chunk, callback);
    },
    final(callback) {
      socket.end(callback);
    },
    destroy(error, callback) {
      socket.destroy();
      callback(error);
    },
  });
  adapter.push(head);
  socket.on("data", (chunk: Buffer) => {
    if (!adapter.push(chunk)) socket.pause();
  });
  socket.once("end", () => adapter.push(null));
  socket.once("error", (error) => adapter.destroy(error));
  socket.once("close", () => adapter.destroy());
  return adapter;
}

export class InterceptGovernor {
  public constructor(
    private readonly options: GovernorOptions,
    private readonly dependencies: GovernorDependencies,
  ) {}

  public get unlisted(): UnlistedPolicy {
    return this.options.unlisted;
  }

  public get hosts(): ReadonlySet<string> {
    return this.options.hosts;
  }

  public governs(host: string): boolean {
    return this.options.hosts.has(host);
  }

  /**
   * Takes a governed connection: terminates TLS where TLS was spoken, and
   * hands the plaintext stream to the host's gateway listener. Rejects with a
   * `GovernError` naming what could not be done; the caller refuses the
   * connection by that name, and the connection is closed.
   */
  public async take(
    client: Socket,
    head: Buffer,
    destination: { readonly protocol: InterceptProtocol; readonly host: string },
  ): Promise<void> {
    const listener = await this.dependencies
      .gatewayFor(destination.host, destination.protocol)
      .catch((error: unknown) => {
        throw new GovernError(
          "GOVERN_GATEWAY_UNAVAILABLE",
          error instanceof Error ? error.message : "UNKNOWN",
        );
      });
    if (destination.protocol === "HTTP") {
      // A plaintext request is read from the socket itself, the head first;
      // the socket was paused while the destination was decided.
      client.unshift(head);
      listener.accept(client);
      client.resume();
      return;
    }
    if (this.options.issuer === null) throw new GovernError("GOVERN_TLS_UNAVAILABLE");
    const leaf = this.options.issuer.leafFor(destination.host);
    const secured = new TLSSocket(replayed(client, head), {
      isServer: true,
      secureContext: createSecureContext({ cert: leaf.chainPem, key: leaf.keyPem }),
      // HTTP/1.1 alone: a client offering h2 as well settles for it, and one
      // offering h2 alone is refused at the handshake rather than misread.
      ALPNProtocols: ["http/1.1"],
    });
    await new Promise<void>((resolve, reject) => {
      // A client that goes away during the handshake closes or ends the
      // stream underneath without an error surfacing here; each is a refusal
      // now, not a wait for the timer. Once the handshake is done, the same
      // events are the connection's own business, and the one error a socket
      // can emit is absorbed by the listener left here for it.
      let pending = true;
      const timer = setTimeout(() => {
        secured.destroy();
        reject(new GovernError("GOVERN_HANDSHAKE_FAILED", "TIMEOUT"));
      }, this.options.handshakeTimeoutMs);
      const settle = (error: GovernError | null): void => {
        if (!pending) return;
        pending = false;
        clearTimeout(timer);
        if (error === null) {
          resolve();
          return;
        }
        secured.destroy();
        reject(error);
      };
      secured.once("secure", () => settle(null));
      secured.once("error", (error: Error) =>
        settle(new GovernError("GOVERN_HANDSHAKE_FAILED", errorCode(error))),
      );
      secured.once("close", () => settle(new GovernError("GOVERN_HANDSHAKE_FAILED", "CLOSED")));
      secured.once("end", () => settle(new GovernError("GOVERN_HANDSHAKE_FAILED", "CLOSED")));
    });
    listener.accept(secured);
  }
}

/** OpenSSL's name for a handshake failure, which Node puts on the error as its code. */
function errorCode(error: Error): string {
  return (error as { code?: string }).code ?? error.message;
}
