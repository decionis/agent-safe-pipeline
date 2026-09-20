/**
 * The transparent interceptor: the hop a workload's outbound HTTP and TLS
 * connections are redirected into by the network (an iptables REDIRECT in the
 * pod or container, written by `packaging/intercept/Redirect.sh`) without the
 * workload knowing. Each connection arrives with its destination rewritten to
 * this process, so the interceptor reads the destination from the client's
 * own first bytes, the TLS server name or the HTTP host, dials it, and splices
 * the two sockets. A connection whose destination no byte names is refused:
 * the interceptor forwards to what the client asked for, or to nothing.
 *
 * That is the observe phase, and every destination starts in it: nothing is
 * decrypted, nothing is decided and no request is altered; what is kept is
 * where the workload went, in the ledger, so an operator learns what a
 * workload reaches before governing it. For the destinations an operator
 * lists, the governor (`InterceptGovernor`) takes the connection instead:
 * TLS is terminated under the operator's authority and the gateway's
 * lifecycle runs over each request. Same hop, same ledger.
 */
import { createServer, type AddressInfo, type Server, type Socket } from "node:net";
import { transparentDial, type Dial } from "../egress/TransparentDial.js";
import {
  readDestination,
  type DestinationReading,
  type InterceptProtocol,
} from "../intercept/Destination.js";
import {
  InterceptLedger,
  type InterceptRefusal,
  type GovernedCountsSource,
  type InterceptReport,
} from "../intercept/InterceptLedger.js";
import { GovernError, type InterceptGovernor } from "./InterceptGovernor.js";

/** One listener: the port it binds, and the port the redirected connections were addressed to. */
export interface InterceptListenerSpec {
  readonly port: number;
  readonly destinationPort: number;
}

export interface InterceptorOptions {
  /** The address the listeners bind; loopback, since REDIRECT delivers locally generated packets there. */
  readonly bind: string;
  readonly listeners: readonly InterceptListenerSpec[];
  /** How long a client has to send bytes that name a destination. */
  readonly peekTimeoutMs: number;
  readonly connectTimeoutMs: number;
  /** How long a spliced connection may stay silent in both directions. */
  readonly idleTimeoutMs: number;
  readonly maxConnections: number;
}

export const INTERCEPT_DEFAULTS = {
  bind: "127.0.0.1",
  httpPort: 15_001,
  httpsPort: 15_002,
  peekTimeoutMs: 5_000,
  connectTimeoutMs: 10_000,
  idleTimeoutMs: 300_000,
  maxConnections: 10_000,
} as const;

export interface BoundListener {
  readonly address: string;
  readonly port: number;
  readonly destinationPort: number;
}

export type InterceptEvent =
  | {
      readonly event: "INTERCEPT_STARTED";
      readonly at: string;
      readonly listeners: readonly { readonly listen: string; readonly for_port: number }[];
    }
  | {
      readonly event: "INTERCEPT_OBSERVED";
      readonly at: string;
      readonly protocol: InterceptProtocol;
      readonly host: string;
      readonly port: number;
      /** Taken by the gateway rather than spliced through. */
      readonly governed: boolean;
      readonly method?: string;
      readonly target?: string;
      readonly alpn?: readonly string[];
    }
  | {
      readonly event: "INTERCEPT_REFUSED";
      readonly at: string;
      readonly reason: InterceptRefusal;
      readonly protocol: InterceptProtocol | null;
      readonly host?: string;
      readonly port?: number;
      readonly detail?: string;
    }
  | {
      readonly event: "INTERCEPT_GOVERNING";
      readonly at: string;
      readonly hosts: readonly string[];
      readonly unlisted: "passthrough" | "refuse";
      /** Whether governed TLS is terminated: an operator authority was given. */
      readonly tls: boolean;
    }
  | InterceptReport
  | { readonly event: "INTERCEPT_STOPPED"; readonly at: string; readonly signal: string };

export interface InterceptorDependencies {
  readonly emit: (event: InterceptEvent) => void;
  readonly dial?: Dial;
  readonly now?: () => Date;
  /** The govern phase, when an operator listed destinations; null observes everything. */
  readonly governor?: InterceptGovernor | null;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"]);

export class Interceptor {
  private readonly ledger = new InterceptLedger();
  private readonly servers: Server[] = [];
  private readonly bound: BoundListener[] = [];
  private readonly active = new Set<Socket>();
  private readonly dial: Dial;
  private readonly now: () => Date;
  private readonly emit: (event: InterceptEvent) => void;
  private readonly governor: InterceptGovernor | null;

  public constructor(
    private readonly options: InterceptorOptions,
    dependencies: InterceptorDependencies,
  ) {
    this.emit = dependencies.emit;
    this.dial = dependencies.dial ?? transparentDial;
    this.now = dependencies.now ?? (() => new Date());
    this.governor = dependencies.governor ?? null;
  }

  /** Binds every listener; a port that cannot be bound closes the ones already bound and rejects. */
  public async listen(): Promise<readonly BoundListener[]> {
    try {
      for (const spec of this.options.listeners) {
        // Half-open stays ours to handle: a client that finishes sending keeps
        // reading the answer, and the destination's end is the client's end.
        const server = createServer({ noDelay: true, allowHalfOpen: true }, (socket) =>
          this.accept(socket, spec),
        );
        await new Promise<void>((resolve, reject) => {
          server.once("error", reject);
          server.listen(spec.port, this.options.bind, () => {
            server.removeListener("error", reject);
            resolve();
          });
        });
        const address = server.address() as AddressInfo;
        this.servers.push(server);
        this.bound.push({
          address: address.address,
          port: address.port,
          destinationPort: spec.destinationPort,
        });
      }
    } catch (error) {
      await this.close();
      throw error;
    }
    this.emit({
      event: "INTERCEPT_STARTED",
      at: this.now().toISOString(),
      listeners: this.bound.map((listener) => ({
        listen: `${listener.address}:${listener.port}`,
        for_port: listener.destinationPort,
      })),
    });
    return this.bound;
  }

  public listeners(): readonly BoundListener[] {
    return this.bound;
  }

  public report(governed?: GovernedCountsSource): InterceptReport {
    return this.ledger.report(this.now().toISOString(), governed);
  }

  /** Stops accepting, drops every connection, and waits for the listeners to close. */
  public async close(): Promise<void> {
    for (const socket of this.active) socket.destroy();
    this.active.clear();
    const closing = this.servers.splice(0);
    this.bound.splice(0);
    await Promise.all(
      closing.map(
        (server) =>
          new Promise<void>((resolve) => {
            server.close(() => resolve());
          }),
      ),
    );
  }

  private accept(client: Socket, spec: InterceptListenerSpec): void {
    client.on("error", () => undefined);
    if (this.active.size >= this.options.maxConnections) {
      this.refuse(client, "TOO_MANY_CONNECTIONS", null, undefined, undefined, true);
      return;
    }
    this.active.add(client);
    client.once("close", () => this.active.delete(client));
    this.peek(client, spec);
  }

  /** Reads the client's first bytes until they name a destination, or refuse one, or run out of time. */
  private peek(client: Socket, spec: InterceptListenerSpec): void {
    const chunks: Buffer[] = [];
    let length = 0;
    const finish = (): void => {
      clearTimeout(timer);
      client.removeListener("data", onData);
      client.removeListener("end", onEnd);
      client.removeListener("close", onEnd);
    };
    const timer = setTimeout(() => {
      finish();
      this.refuse(client, "PEEK_TIMEOUT", null, undefined, undefined, true);
    }, this.options.peekTimeoutMs);
    const onEnd = (): void => {
      finish();
      this.refuse(client, "DESTINATION_UNKNOWN", null, undefined, undefined, true);
    };
    const onData = (chunk: Buffer): void => {
      chunks.push(chunk);
      length += chunk.length;
      const bytes = Buffer.concat(chunks, length);
      const reading = readDestination(bytes, spec.destinationPort);
      if (reading.kind === "NEED_MORE") return;
      finish();
      if (reading.kind === "REFUSED") {
        this.refuse(client, reading.reason, reading.protocol, undefined, reading.detail, true);
        return;
      }
      void this.place(client, bytes, reading);
    };
    client.on("data", onData);
    client.once("end", onEnd);
    client.once("close", onEnd);
  }

  private async place(
    client: Socket,
    head: Buffer,
    destination: Extract<DestinationReading, { kind: "DESTINATION" }>,
  ): Promise<void> {
    const at = this.now().toISOString();
    const { protocol, host, port } = destination;
    if (this.isSelf(host, port)) {
      this.refuse(client, "HOST_IS_INTERCEPTOR", protocol, { host, port }, undefined, true);
      return;
    }
    const governed = this.governor?.governs(host) ?? false;
    if (!governed && this.governor?.unlisted === "refuse") {
      this.refuse(client, "UNLISTED_DESTINATION", protocol, { host, port }, undefined, true);
      return;
    }
    const key = this.ledger.record(host, port, protocol, destination.method ?? null, at, governed);
    this.emit({
      event: "INTERCEPT_OBSERVED",
      at,
      protocol,
      host,
      port,
      governed,
      ...(destination.method === undefined ? {} : { method: destination.method }),
      ...(destination.target === undefined ? {} : { target: destination.target }),
      ...(destination.alpn === undefined || destination.alpn.length === 0
        ? {}
        : { alpn: destination.alpn }),
    });
    client.pause();
    if (governed && this.governor !== null) {
      // The gateway becomes the connection's other end; nothing is dialled here.
      try {
        await this.governor.take(client, head, destination);
      } catch (error) {
        const detail = error instanceof GovernError ? error.message : "UNKNOWN";
        this.refuse(client, "GOVERN_UNAVAILABLE", protocol, { host, port }, detail, false);
        return;
      }
      this.ledger.placed();
      return;
    }
    // A client that has already finished sending while the destination is
    // dialled must still have its end delivered once the splice is up.
    let clientEnded = false;
    const onEnd = (): void => {
      clientEnded = true;
    };
    client.once("end", onEnd);
    let upstream: Socket;
    try {
      upstream = await this.dial(host, port, this.options.connectTimeoutMs);
    } catch (error) {
      const code = (error as { code?: string }).code ?? "UNREACHABLE";
      this.refuse(client, "UPSTREAM_UNREACHABLE", protocol, { host, port }, code, false);
      return;
    }
    client.removeListener("end", onEnd);
    if (client.destroyed) {
      upstream.destroy();
      return;
    }
    this.ledger.placed();
    this.splice(client, upstream, head, key, clientEnded);
  }

  /** Both directions, with back-pressure, half-close, an idle bound, and the bytes counted once at the end. */
  private splice(
    client: Socket,
    upstream: Socket,
    head: Buffer,
    key: string,
    clientEnded: boolean,
  ): void {
    let toDestination = head.length;
    let fromDestination = 0;
    let closed = false;
    const closeBoth = (): void => {
      if (closed) return;
      closed = true;
      this.ledger.bytes(key, toDestination, fromDestination);
      client.destroy();
      upstream.destroy();
    };
    upstream.on("error", () => undefined);
    upstream.setNoDelay(true);
    upstream.write(head);
    client.setTimeout(this.options.idleTimeoutMs);
    upstream.setTimeout(this.options.idleTimeoutMs);
    client.on("data", (chunk: Buffer) => {
      toDestination += chunk.length;
      if (!upstream.write(chunk)) client.pause();
    });
    upstream.on("drain", () => client.resume());
    upstream.on("data", (chunk: Buffer) => {
      fromDestination += chunk.length;
      if (!client.write(chunk)) upstream.pause();
    });
    client.on("drain", () => upstream.resume());
    client.on("end", () => upstream.end());
    upstream.on("end", () => client.end());
    for (const socket of [client, upstream]) {
      socket.on("close", closeBoth);
      socket.on("error", closeBoth);
      socket.on("timeout", closeBoth);
    }
    if (clientEnded) upstream.end();
    client.resume();
  }

  private refuse(
    client: Socket,
    reason: InterceptRefusal,
    protocol: InterceptProtocol | null,
    destination: { readonly host: string; readonly port: number } | undefined,
    detail: string | undefined,
    counts: boolean,
  ): void {
    const at = this.now().toISOString();
    this.ledger.refuse(reason, at, counts);
    this.emit({
      event: "INTERCEPT_REFUSED",
      at,
      reason,
      protocol,
      ...(destination === undefined ? {} : destination),
      ...(detail === undefined ? {} : { detail }),
    });
    client.destroy();
  }

  /** Whether a destination is one of this interceptor's own listeners: a connection that would loop. */
  private isSelf(host: string, port: number): boolean {
    if (!LOOPBACK_HOSTS.has(host) && host !== this.options.bind) return false;
    return this.bound.some((listener) => listener.port === port);
  }
}
