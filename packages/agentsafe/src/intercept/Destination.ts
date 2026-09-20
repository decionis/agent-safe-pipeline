/**
 * Where a redirected connection was going, read from its first bytes. A
 * connection arrives at the interceptor with its original address rewritten,
 * so the only witnesses to the destination are the client's own bytes: the
 * server_name of a TLS ClientHello, or the authority of an HTTP/1 request.
 * Anything else is a destination nobody can name, and is refused rather than
 * sent somewhere by guess.
 */
import { readClientHello } from "./ClientHello.js";
import { readRequestHead, type RequestHeadRefusal } from "./RequestHead.js";

export type InterceptProtocol = "TLS" | "HTTP";

export type DestinationReading =
  /** The bytes so far decide nothing yet; read more, under the bound. */
  | { readonly kind: "NEED_MORE" }
  | {
      readonly kind: "DESTINATION";
      readonly protocol: InterceptProtocol;
      readonly host: string;
      readonly port: number;
      /** The request line's method and target for HTTP; TLS carries neither in the clear. */
      readonly method?: string;
      readonly target?: string;
      readonly alpn?: readonly string[];
    }
  | {
      readonly kind: "REFUSED";
      readonly reason: DestinationRefusal;
      readonly protocol: InterceptProtocol | null;
      readonly detail?: RequestHeadRefusal;
    };

export type DestinationRefusal =
  /** Neither TLS with a server name nor HTTP/1 with a host: no witness to the destination. */
  | "DESTINATION_UNKNOWN"
  /** TLS or HTTP whose head does not follow its grammar. */
  | "MALFORMED";

/** The most bytes read while waiting for a head; a hello or a head that needs more is refused. */
export const MAX_PEEK_BYTES = 65_536;

/**
 * Reads the destination from a connection's first bytes. `fallbackPort` is
 * the port the connection was addressed to before it was redirected, which
 * the listener knows and the bytes may not name.
 */
export function readDestination(bytes: Uint8Array, fallbackPort: number): DestinationReading {
  const hello = readClientHello(bytes);
  switch (hello.kind) {
    case "NEED_MORE":
      return bytes.length >= MAX_PEEK_BYTES
        ? { kind: "REFUSED", reason: "MALFORMED", protocol: "TLS" }
        : { kind: "NEED_MORE" };
    case "MALFORMED":
      return { kind: "REFUSED", reason: "MALFORMED", protocol: "TLS" };
    case "CLIENT_HELLO":
      if (hello.serverName === null) {
        return { kind: "REFUSED", reason: "DESTINATION_UNKNOWN", protocol: "TLS" };
      }
      return {
        kind: "DESTINATION",
        protocol: "TLS",
        host: hello.serverName,
        port: fallbackPort,
        alpn: hello.alpn,
      };
    case "NOT_TLS":
      break;
  }
  const head = readRequestHead(bytes);
  switch (head.kind) {
    case "NEED_MORE":
      return bytes.length >= MAX_PEEK_BYTES
        ? { kind: "REFUSED", reason: "MALFORMED", protocol: "HTTP", detail: "HEAD_TOO_LONG" }
        : { kind: "NEED_MORE" };
    case "MALFORMED":
      return { kind: "REFUSED", reason: "MALFORMED", protocol: "HTTP", detail: head.reason };
    case "REQUEST":
      return {
        kind: "DESTINATION",
        protocol: "HTTP",
        host: head.host,
        port: head.port ?? fallbackPort,
        method: head.method,
        target: head.target,
      };
    case "NOT_HTTP":
      return { kind: "REFUSED", reason: "DESTINATION_UNKNOWN", protocol: null };
  }
}
