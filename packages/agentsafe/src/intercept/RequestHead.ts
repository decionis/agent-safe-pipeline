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
const LINE_END = "\r\n";
const TOKEN = /^[!#$%&'*+\-.^`|~\w]+$/;
/** Method, target and version: the target is origin-form or absolute-form, checked after. */
const REQUEST_LINE = /^([!#$%&'*+\-.^`|~\w]+) (\S+) HTTP\/1\.[01]$/;
/** Absolute-form target: the scheme this interceptor speaks, an authority, and a path that may be absent. */
const ABSOLUTE_TARGET = /^http:\/\/([^/?#]+)(\/\S*)?$/i;
/** A method token followed by a space, or by the end of what has arrived so far. */
const REQUEST_LINE_START = /^[A-Z][!#$%&'*+\-.^`|~\w]{0,19}(?: |$)/;
/** RFC 1123 host name: labels of letters, digits and hyphens, at most 253 characters. */
const HOST_NAME =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
/** A bracketed IPv6 literal, then an optional port. */
const IPV6_AUTHORITY = /^(\[[0-9a-f:.]+\])(?::(\d{1,5}))?$/;
/** A name or IPv4 address, then an optional port. */
const NAMED_AUTHORITY = /^([a-z0-9.-]+)(?::(\d{1,5}))?$/;
/** One decimal octet, no leading zero. */
const OCTET = /^(?:0|[1-9]\d{0,2})$/;
/** What can only be meant as an address. */
const DIGITS_AND_DOTS = /^[\d.]+$/;

const NEED_MORE = { kind: "NEED_MORE" } as const;
const NOT_HTTP = { kind: "NOT_HTTP" } as const;
const malformed = (reason: RequestHeadRefusal): RequestHeadReading => ({
  kind: "MALFORMED",
  reason,
});

/** Reads a client's first bytes as an HTTP/1 request head, or says why they are not one. */
export function readRequestHead(bytes: Uint8Array): RequestHeadReading {
  // Only as much as a head may be, plus the terminator that would end it.
  const window = Math.min(bytes.length, MAX_REQUEST_HEAD_BYTES + HEAD_END.length);
  const text = latin1(bytes.subarray(0, window));
  const end = text.indexOf(HEAD_END);
  if (end === -1) {
    if (!REQUEST_LINE_START.test(text)) return NOT_HTTP;
    return bytes.length > MAX_REQUEST_HEAD_BYTES ? malformed("HEAD_TOO_LONG") : NEED_MORE;
  }
  const head = text.slice(0, end);
  const firstLineEnd = head.indexOf(LINE_END);
  const requestLine = firstLineEnd === -1 ? head : head.slice(0, firstLineEnd);
  const headerLines =
    firstLineEnd === -1 ? [] : head.slice(firstLineEnd + LINE_END.length).split(LINE_END);
  const match = REQUEST_LINE.exec(requestLine);
  if (match === null) {
    return REQUEST_LINE_START.test(text) ? malformed("REQUEST_LINE_INVALID") : NOT_HTTP;
  }
  // Stryker disable next-line all: both groups are matched whenever the line is; the fallbacks satisfy the type.
  const [method, rawTarget] = [match[1] ?? "", match[2] ?? ""];

  let hostHeader: string | null = null;
  for (const line of headerLines) {
    const header = readHeaderLine(line);
    if (header === null) return malformed("HEADER_INVALID");
    if (header.name !== "host") continue;
    if (hostHeader !== null) return malformed("HOST_REPEATED");
    hostHeader = header.value;
  }

  let target = rawTarget;
  let authority: Authority | null = null;
  if (!rawTarget.startsWith("/")) {
    const absolute = ABSOLUTE_TARGET.exec(rawTarget);
    if (absolute === null) return malformed("TARGET_INVALID");
    // Stryker disable next-line all: the authority group is matched whenever the target is; the fallback satisfies the type.
    authority = parseAuthority(absolute[1] ?? "");
    if (authority === null) return malformed("TARGET_INVALID");
    target = absolute[2] ?? "/";
  }
  if (hostHeader === null) {
    if (authority === null) return malformed("HOST_MISSING");
  } else {
    const fromHeader = parseAuthority(hostHeader);
    if (fromHeader === null) return malformed("HOST_INVALID");
    if (
      authority !== null &&
      (authority.host !== fromHeader.host || authority.port !== fromHeader.port)
    ) {
      return malformed("TARGET_DISAGREES_WITH_HOST");
    }
    authority ??= fromHeader;
  }
  return { kind: "REQUEST", method, target, host: authority.host, port: authority.port };
}

interface Authority {
  readonly host: string;
  readonly port: number | null;
}

/** `host[:port]`, with the host a name, an IPv4 address or a bracketed IPv6 address, lowercased. */
export function parseAuthority(value: string): Authority | null {
  const text = value.toLowerCase();
  const match = IPV6_AUTHORITY.exec(text) ?? NAMED_AUTHORITY.exec(text);
  if (match === null) return null;
  // Stryker disable next-line all: the host group is matched whenever the authority is; the fallback satisfies the type.
  const host = match[1] ?? "";
  if (!host.startsWith("[") && !isHost(host)) return null;
  const digits = match[2];
  if (digits === undefined) return { host, port: null };
  const port = Number(digits);
  if (port < 1 || port > 65_535) return null;
  return { host, port };
}

/**
 * A host name, or an IPv4 address. Digits and dots alone are read as an
 * address and must be a valid one: `256.1.1.1` is a name to the grammar and an
 * address to a reader, which is exactly the disagreement this parser refuses.
 */
function isHost(host: string): boolean {
  if (DIGITS_AND_DOTS.test(host)) return isIpv4(host);
  return HOST_NAME.test(host);
}

/** Four decimal octets, each without a leading zero and at most 255. */
function isIpv4(text: string): boolean {
  const octets = text.split(".");
  return octets.length === 4 && octets.every((octet) => OCTET.test(octet) && Number(octet) <= 255);
}

/**
 * One header line as `name: value`, the name a token lowercased and the value
 * without its optional leading and trailing space or tab. A line with a bare
 * CR or LF, no colon, or a name that is not a token is not a header.
 */
function readHeaderLine(line: string): { readonly name: string; readonly value: string } | null {
  if (line.includes("\n") || line.includes("\r")) return null;
  const colon = line.indexOf(":");
  if (colon === -1) return null;
  const name = line.slice(0, colon);
  if (!TOKEN.test(name)) return null;
  return { name: name.toLowerCase(), value: trimBlanks(line.slice(colon + 1)) };
}

/** Without the optional leading and trailing spaces and tabs; nothing else is whitespace to HTTP. */
function trimBlanks(value: string): string {
  // Both searches find the same absence in a blank value, and the slice from
  // one past the other's end is empty.
  const start = value.search(/[^ \t]/);
  const end = value.search(/[^ \t][ \t]*$/);
  return value.slice(start, end + 1);
}

function latin1(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return text;
}
