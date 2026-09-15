import { Socket } from "node:net";

/**
 * What one connection attempt to an address did. This is the host primitive
 * the containment probe classifies: it opens a socket, reports how the
 * attempt ended, and closes it without writing a byte.
 *
 * It lives here rather than beside the probe because sockets open only under
 * `src/http` and `src/egress`, and because none of its outcomes can be told
 * apart from their mutants by a test in this process: a kernel decides which
 * of them happens.
 */
export type DialOutcome =
  | { readonly state: "CONNECTED" }
  | { readonly state: "REFUSED" }
  | { readonly state: "TIMED_OUT" }
  | { readonly state: "UNREACHABLE"; readonly code: string }
  | { readonly state: "UNRESOLVED"; readonly code: string }
  | { readonly state: "OTHER"; readonly code: string };

/** Error codes that mean the packet never reached a host that answered. */
const UNREACHABLE = new Set(["EHOSTUNREACH", "ENETUNREACH", "ENETDOWN", "EHOSTDOWN"]);

/** Error codes that mean the name did not resolve, which is not an answer either. */
const UNRESOLVED = new Set(["ENOTFOUND", "EAI_AGAIN", "EAI_NONAME"]);

const codeOf = (error: unknown): string => {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : "UNKNOWN";
};

/** Classify a single error into the outcome the probe reads. */
export function dialOutcomeFor(code: string): DialOutcome {
  if (code === "ECONNREFUSED") return { state: "REFUSED" };
  if (code === "ETIMEDOUT") return { state: "TIMED_OUT" };
  if (UNREACHABLE.has(code)) return { state: "UNREACHABLE", code };
  if (UNRESOLVED.has(code)) return { state: "UNRESOLVED", code };
  return { state: "OTHER", code };
}

/**
 * Open a socket to `host:port` and report how it ended. Nothing is written
 * and nothing is read: a probe that authenticated would have to hold the
 * credential it is checking the absence of.
 */
export async function dial(host: string, port: number, timeoutMs: number): Promise<DialOutcome> {
  return await new Promise<DialOutcome>((resolve) => {
    const socket = new Socket();
    let settled = false;
    const finish = (outcome: DialOutcome): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(outcome);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish({ state: "CONNECTED" }));
    socket.once("timeout", () => finish({ state: "TIMED_OUT" }));
    socket.once("error", (error: unknown) => finish(dialOutcomeFor(codeOf(error))));
    socket.connect(port, host);
  });
}
