import type { Duplex } from "node:stream";

export const TCP_TRANSPORT = "agentsafe-tcp-relay/1";
export const TCP_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const TCP_TICKET = /^[\w-]{43}$/;
export const TCP_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function tenantHostname(host: string | undefined, domain: string | null): string | null {
  if (!host || !domain || !host.endsWith(`.${domain}`)) return null;
  const label = host.slice(0, -domain.length - 1);
  if (
    !TCP_LABEL.test(label) ||
    ["www", "api", "status", "admin", "console", "agentsafe-provisioner", "tcp-broker"].includes(
      label,
    )
  )
    return null;
  return host;
}

/** Refusal responses contain only our constants, never peer headers or control-API text. */
export function refuseTcp(socket: Duplex, status: number, code: string): void {
  if (socket.destroyed) return;
  const reasons: Record<number, string> = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    409: "Conflict",
    429: "Too Many Requests",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
  };
  const body = JSON.stringify({ code });
  socket.end(
    `HTTP/1.1 ${status} ${reasons[status] ?? "Error"}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
  );
  const timer = setTimeout(() => socket.destroy(), 1_000);
  timer.unref();
  socket.once("close", () => clearTimeout(timer));
}

export function connectedTcp(socket: Duplex): void {
  socket.write("HTTP/1.1 200 Connection Established\r\nCache-Control: no-store\r\n\r\n");
}

/** Reads one bounded control line and leaves the stream paused, including on failure. */
export function controlLine(
  socket: Duplex,
  initial: Buffer,
  timeoutMs: number,
): Promise<{ line: string; tail: Buffer }> {
  return new Promise((resolve, reject) => {
    let buffered: Buffer = initial;
    let done = false;
    const finish = (error?: Error): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.pause();
      socket.off("data", data);
      socket.off("error", failed);
      socket.off("end", ended);
      socket.off("close", ended);
      if (error) reject(error);
    };
    const check = (): void => {
      const end = buffered.indexOf(10);
      if (end > 1_024 || (end === -1 && buffered.length > 1_024))
        return finish(new Error("TCP_CONTROL_TOO_LARGE"));
      if (end !== -1) {
        const value = {
          line: buffered.subarray(0, end).toString("utf8"),
          tail: buffered.subarray(end + 1),
        };
        finish();
        resolve(value);
      }
    };
    const data = (chunk: Buffer): void => {
      buffered = Buffer.concat([buffered, chunk]);
      check();
    };
    const failed = (): void => finish(new Error("TCP_CONNECTION_FAILED"));
    const ended = (): void => finish(new Error("TCP_CONNECTION_CLOSED"));
    const timer = setTimeout(() => finish(new Error("TCP_CONTROL_TIMEOUT")), timeoutMs);
    timer.unref();
    socket.on("data", data);
    socket.once("error", failed);
    socket.once("end", ended);
    socket.once("close", ended);
    check();
    if (!done) socket.resume();
  });
}

/** Bounded opaque stream relay. A FIN is forwarded independently in each direction. */
export function spliceTcp(
  left: Duplex,
  right: Duplex,
  options: {
    leftHead?: Buffer;
    rightHead?: Buffer;
    idleMs: number;
    lifetimeMs: number;
    maxBytes: number;
    closed: () => void;
  },
): () => void {
  let bytes = 0;
  let stopped = false;
  const stop = (): void => {
    if (stopped) return;
    stopped = true;
    clearTimeout(idle);
    clearTimeout(lifetime);
    left.unpipe(right);
    right.unpipe(left);
    left.off("data", count);
    right.off("data", count);
    left.destroy();
    right.destroy();
    options.closed();
  };
  const count = (chunk: Buffer): void => {
    bytes += chunk.length;
    if (bytes > options.maxBytes) stop();
    else idle.refresh();
  };
  const idle = setTimeout(stop, options.idleMs);
  const lifetime = setTimeout(stop, options.lifetimeMs);
  idle.unref();
  lifetime.unref();
  left.on("data", count);
  right.on("data", count);
  left.once("error", stop);
  right.once("error", stop);
  left.once("close", stop);
  right.once("close", stop);
  if (options.leftHead?.length) left.unshift(options.leftHead);
  if (options.rightHead?.length) right.unshift(options.rightHead);
  left.pipe(right);
  right.pipe(left);
  return stop;
}
