import type { Socket } from "node:net";

/** Protocol failures are codes only: never include credentials or received bytes. */
export class TcpClientError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "TcpClientError";
  }
}

interface Frame {
  readonly frame: Buffer;
  readonly tail: Buffer;
}

/** Stop in paused mode and return every byte after the delimiter to the caller. */
function readFrame(
  socket: Socket,
  delimiter: Buffer,
  maxBytes: number,
  timeoutMs: number,
  initial: Buffer,
  signal?: AbortSignal,
): Promise<Frame> {
  return new Promise((resolve, reject) => {
    let bytes = initial;
    let settled = false;
    const clean = (): void => {
      clearTimeout(timer);
      socket.pause();
      socket.removeListener("data", data);
      socket.removeListener("end", ended);
      socket.removeListener("close", ended);
      socket.removeListener("error", failed);
      signal?.removeEventListener("abort", aborted);
    };
    const finish = (error?: TcpClientError, frame?: Frame): void => {
      if (settled) return;
      settled = true;
      clean();
      if (error !== undefined) reject(error);
      else if (frame !== undefined) resolve(frame);
    };
    const inspect = (): void => {
      const end = bytes.indexOf(delimiter);
      if (end >= 0) {
        if (end + delimiter.length > maxBytes) finish(new TcpClientError("TCP_FRAME_TOO_LARGE"));
        else
          finish(undefined, {
            frame: bytes.subarray(0, end),
            tail: bytes.subarray(end + delimiter.length),
          });
      } else if (bytes.length >= maxBytes) finish(new TcpClientError("TCP_FRAME_TOO_LARGE"));
    };
    const data = (chunk: Buffer): void => {
      bytes = bytes.length === 0 ? chunk : Buffer.concat([bytes, chunk]);
      inspect();
    };
    const ended = (): void => finish(new TcpClientError("TCP_PROTOCOL_CLOSED"));
    const failed = (): void => finish(new TcpClientError("TCP_PROTOCOL_FAILED"));
    const aborted = (): void => finish(new TcpClientError("TCP_STOPPED"));
    const timer = setTimeout(() => finish(new TcpClientError("TCP_PROTOCOL_TIMEOUT")), timeoutMs);
    socket.on("data", data);
    socket.once("end", ended);
    socket.once("close", ended);
    socket.once("error", failed);
    signal?.addEventListener("abort", aborted, { once: true });
    if (signal?.aborted === true) aborted();
    else {
      inspect();
      if (!settled && (socket.destroyed || socket.readableEnded)) ended();
      if (!settled) socket.resume();
    }
  });
}

/** The newline counts toward the limit. The socket remains paused; no tail is discarded. */
export async function readLine(
  socket: Socket,
  maxBytes: number,
  timeoutMs: number,
  initial: Buffer = Buffer.alloc(0),
  signal?: AbortSignal,
): Promise<{ readonly line: string; readonly tail: Buffer }> {
  const read = await readFrame(socket, Buffer.from("\n"), maxBytes, timeoutMs, initial, signal);
  try {
    return { line: new TextDecoder("utf-8", { fatal: true }).decode(read.frame), tail: read.tail };
  } catch {
    throw new TcpClientError("TCP_CONTROL_INVALID");
  }
}

/** Strict HTTP/1.1 framing; a successful CONNECT has no HTTP body. */
export async function readConnectResponse(
  socket: Socket,
  maxBytes: number,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<{ readonly status: number; readonly tail: Buffer }> {
  const read = await readFrame(
    socket,
    Buffer.from("\r\n\r\n"),
    maxBytes,
    timeoutMs,
    Buffer.alloc(0),
    signal,
  );
  const lines = read.frame.toString("latin1").split("\r\n");
  const match = /^HTTP\/1\.1 ([1-5]\d{2})(?: [\x20-\x7e]*)?$/.exec(lines.shift() ?? "");
  if (match === null) throw new TcpClientError("TCP_RESPONSE_INVALID");
  for (const line of lines) {
    const header = /^([!#$%&'*+.^\w`|~-]+):[\t\x20-\x7e]*$/.exec(line);
    if (
      header === null ||
      (match[1] === "200" && /^(?:content-length|transfer-encoding)$/i.test(header[1] ?? ""))
    ) {
      throw new TcpClientError("TCP_RESPONSE_INVALID");
    }
  }
  return { status: Number(match[1]), tail: read.tail };
}

export function requireControl(line: string, type: "attach"): void {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    throw new TcpClientError("TCP_CONTROL_INVALID");
  }
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== 1 ||
    (value as { type?: unknown }).type !== type
  ) {
    throw new TcpClientError("TCP_CONTROL_INVALID");
  }
}
