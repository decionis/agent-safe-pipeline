/**
 * The head of a plaintext HTTP/1 request, read for where it was going: the
 * `Host` header, or the authority of an absolute-form target, which a
 * transparent interceptor has no other way to learn once the destination
 * address has been rewritten to it. It reads the request line and the header
 * names and values only as far as `Host`, keeps nothing, and refuses a head
 * that two parsers could read differently (a repeated `Host`, a target that
 * disagrees with it, a line the grammar does not allow) rather than choose.
 *
 * RFC 9112 sections 3 (request line), 3.2 (request target) and 5 (field
 * syntax); RFC 9110 section 7.2 (Host).
 */

/** The reading of a client's first bytes as HTTP/1. */
export type RequestHeadReading =
  /** The bytes are an HTTP request whose head has not fully arrived. */
  | { readonly kind: "NEED_MORE" }
  /** The bytes are not an HTTP/1 request. */
  | { readonly kind: "NOT_HTTP" }
  /** An HTTP/1 request whose destination cannot be placed with certainty. */
  | { readonly kind: "MALFORMED"; readonly reason: RequestHeadRefusal }
  | {
      readonly kind: "REQUEST";
      readonly method: string;
      /** The path and query, as sent. */
      readonly target: string;
      readonly host: string;
      /** The port the authority named; null when it named none. */
      readonly port: number | null;
    };

export type RequestHeadRefusal =
  | "REQUEST_LINE_INVALID"
  | "HOST_MISSING"
  | "HOST_REPEATED"
  | "HOST_INVALID"
  | "TARGET_INVALID"
  | "TARGET_DISAGREES_WITH_HOST"
  | "HEADER_INVALID"
  | "HEAD_TOO_LONG";

/** The most head bytes read before a request is refused as too long to place. */
export const MAX_REQUEST_HEAD_BYTES = 16_384;

const HEAD_END = "\r\n\r\n";
const TOKEN = /^[!#$%&'*+\-.^`|~\w]+$/;
const REQUEST_LINE = /^([!#$%&'*+\-.^`|~\w]+) (\S+) HTTP\/1\.[01]$/;
const HOST_NAME =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_LITERAL = /^\[[0-9a-f:.]+\]$/;
const METHODS_WITHOUT_ORIGIN_FORM = new Set(["CONNECT"]);

/** Reads a client's first bytes as an HTTP/1 request head, or says why they are not one. */
export function readRequestHead(bytes: Uint8Array): RequestHeadReading {
  const text = latin1(
    bytes.subarray(0, Math.min(bytes.length, MAX_REQUEST_HEAD_BYTES + HEAD_END.length)),
  );
  const end = text.indexOf(HEAD_END);
  if (end === -1) {
    if (!looksLikeRequestLine(text)) return { kind: "NOT_HTTP" };
    return bytes.length > MAX_REQUEST_HEAD_BYTES
      ? { kind: "MALFORMED", reason: "HEAD_TOO_LONG" }
      : { kind: "NEED_MORE" };
  }
  const lines = text.slice(0, end).split("\r\n");
  const requestLine = lines.shift() ?? "";
  const match = REQUEST_LINE.exec(requestLine);
  if (match === null) {
    return looksLikeRequestLine(text)
      ? { kind: "MALFORMED", reason: "REQUEST_LINE_INVALID" }
      : { kind: "NOT_HTTP" };
  }
  const method = match[1] ?? "";
  const rawTarget = match[2] ?? "";
  if (METHODS_WITHOUT_ORIGIN_FORM.has(method))
    return { kind: "MALFORMED", reason: "TARGET_INVALID" };

  let hostHeader: string | null = null;
  for (const line of lines) {
    const header = readHeaderLine(line);
    if (header === null) return { kind: "MALFORMED", reason: "HEADER_INVALID" };
    if (header.name !== "host") continue;
    if (hostHeader !== null) return { kind: "MALFORMED", reason: "HOST_REPEATED" };
    hostHeader = header.value;
  }

  let target = rawTarget;
  let authority: Authority | null = null;
  if (!rawTarget.startsWith("/")) {
    const absolute = /^http:\/\/([^/?#]+)(\/\S*)?$/i.exec(rawTarget);
    if (absolute === null) return { kind: "MALFORMED", reason: "TARGET_INVALID" };
    authority = parseAuthority(absolute[1] ?? "");
    if (authority === null) return { kind: "MALFORMED", reason: "TARGET_INVALID" };
    target = absolute[2] ?? "/";
  }
  if (hostHeader === null) {
    if (authority === null) return { kind: "MALFORMED", reason: "HOST_MISSING" };
  } else {
    const fromHeader = parseAuthority(hostHeader);
    if (fromHeader === null) return { kind: "MALFORMED", reason: "HOST_INVALID" };
    if (
      authority !== null &&
      (authority.host !== fromHeader.host || authority.port !== fromHeader.port)
    ) {
      return { kind: "MALFORMED", reason: "TARGET_DISAGREES_WITH_HOST" };
    }
    authority ??= fromHeader;
  }
  return { kind: "REQUEST", method, target, host: authority.host, port: authority.port };
}

interface Authority {
  readonly host: string;
  readonly port: number | null;
}

/** `host[:port]`, with the host a name, an IPv4 address or a bracketed IPv6 address. */
export function parseAuthority(value: string): Authority | null {
  const text = value.trim().toLowerCase();
  if (text.length === 0 || text.length > 260) return null;
  let host: string;
  let rest: string;
  if (text.startsWith("[")) {
    const close = text.indexOf("]");
    if (close === -1) return null;
    host = text.slice(0, close + 1);
    rest = text.slice(close + 1);
    if (!IPV6_LITERAL.test(host)) return null;
  } else {
    const colon = text.indexOf(":");
    host = colon === -1 ? text : text.slice(0, colon);
    rest = colon === -1 ? "" : text.slice(colon);
    if (!HOST_NAME.test(host) && !IPV4.test(host)) return null;
  }
  if (rest === "") return { host, port: null };
  if (!/^:\d{1,5}$/.test(rest)) return null;
  const port = Number(rest.slice(1));
  if (port < 1 || port > 65_535) return null;
  return { host, port };
}

/**
 * Whether the first bytes could still be an HTTP request line: an uppercase
 * method token, then a space or the end of what has arrived. Enough to tell a
 * request from a binary protocol before the head is complete.
 */
function looksLikeRequestLine(text: string): boolean {
  return /^[A-Z][!#$%&'*+\-.^`|~\w]{0,19}(?: |$)/.test(text.slice(0, 21));
}

/**
 * One header line as `name: value`, the name a token lowercased and the value
 * without its optional leading and trailing space or tab. A line with a bare
 * CR or LF, or no colon, or a name that is not a token, is not a header.
 */
function readHeaderLine(line: string): { readonly name: string; readonly value: string } | null {
  if (line.includes("\n") || line.includes("\r")) return null;
  const colon = line.indexOf(":");
  if (colon <= 0) return null;
  const name = line.slice(0, colon);
  if (!TOKEN.test(name)) return null;
  let start = colon + 1;
  let end = line.length;
  while (start < end && (line[start] === " " || line[start] === "\t")) start += 1;
  while (end > start && (line[end - 1] === " " || line[end - 1] === "\t")) end -= 1;
  return { name: name.toLowerCase(), value: line.slice(start, end) };
}

function latin1(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return text;
}
