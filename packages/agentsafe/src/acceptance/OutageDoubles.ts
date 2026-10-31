/**
 * The doubles the outage case's second gateway runs against: an authority
 * that cannot be reached, and an upstream that records what reaches it and
 * effects nothing. The second gateway is built from the configuration the
 * deployed process loaded, so what it shows is that configuration, under
 * this runtime, failing closed; it shows nothing about the real authority or
 * the real upstream, which it never contacts.
 */
import type { ApiProfile, JsonObject, JsonValue } from "@decionis/agent-safe-pipeline";
import type { FetchLike } from "../handlers/HandlerRegistration.js";

/** The authority, unreachable: every call fails before a byte is sent. */
export const AUTHORITY_UNREACHABLE: FetchLike = () =>
  Promise.reject(new Error("AUTHORITY_UNREACHABLE"));

/** The version a read of the recording upstream states. */
export const OUTAGE_VERSION = "acceptance-outage";

/**
 * An answer that states a version, and a state, wherever any write's
 * precondition looks for one: the read the gateway makes before it asks the
 * authority then succeeds, so the case reaches the authority it cannot ask.
 */
export function statingAnswer(profile: ApiProfile | null): {
  readonly headers: Record<string, string>;
  readonly body: JsonValue | undefined;
} {
  const headers: Record<string, string> = {};
  let body: JsonValue | undefined;
  // Stryker disable next-line ArrayDeclaration: with no profile there is no operation, and a string in its place names no precondition either.
  const pointers = (profile?.definition.operations ?? []).flatMap((operation) =>
    operation.precondition === undefined
      ? []
      : [operation.precondition.version, operation.precondition.state].filter(
          (pointer): pointer is string => pointer !== undefined,
        ),
  );
  for (const pointer of pointers) {
    const segments = pointer
      .slice(1)
      .split("/")
      .map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"));
    if (segments[0] === "headers") {
      headers[segments[1]!] = OUTAGE_VERSION;
      continue;
    }
    if (segments.length === 1) {
      body = OUTAGE_VERSION;
      continue;
    }
    // Only a string or an object built here is ever in place: a string gives way.
    if (typeof body !== "object") body = {};
    let node = body as JsonObject;
    for (const segment of segments.slice(1, -1)) {
      const next = node[segment];
      node[segment] = typeof next === "object" ? next : {};
      node = node[segment] as JsonObject;
    }
    node[segments.at(-1)!] = OUTAGE_VERSION;
  }
  return { headers, body };
}

/**
 * The upstream the second gateway forwards to: a read is answered with the
 * stating answer, and anything else is counted and refused. A write counted
 * here is one that would have reached the real upstream with the authority
 * down, which is what the case looks for.
 */
export function recordingUpstream(profile: ApiProfile | null): {
  readonly fetch: FetchLike;
  readonly writes: () => number;
} {
  let writes = 0;
  const answer = statingAnswer(profile);
  const fetch: FetchLike = (_input, init) => {
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "GET" || method === "HEAD") {
      return Promise.resolve(
        // No stated body is `undefined` here, which a response sends as none.
        new Response(JSON.stringify(answer.body), {
          status: 200,
          headers: { "content-type": "application/json", ...answer.headers },
        }),
      );
    }
    writes += 1;
    return Promise.resolve(new Response(null, { status: 502 }));
  };
  return { fetch, writes: () => writes };
}
