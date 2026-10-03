import { createHash } from "node:crypto";
import { EgressError } from "../egress/EgressError.js";
import { EgressPolicy } from "../egress/EgressPolicy.js";
import { GuardedFetch, type AddressResolver } from "../egress/GuardedFetch.js";
import type { FetchLike } from "../handlers/HandlerRegistration.js";
import { SecurityEvents, type SecurityEvent } from "../incident/SecurityEvents.js";

/**
 * Where an upstream's origin serves its proof: one fixed path, so a token is
 * never part of a URL and an origin that echoes its URL cannot serve one.
 */
export const UPSTREAM_PROOF_PATH = "/.well-known/agentsafe-upstream";
/** The label a TXT proof is published under, in front of the upstream's host name. */
export const UPSTREAM_PROOF_TXT_LABEL = "_agentsafe-challenge";
/** The header a forwarded answer carries while its upstream's proof is missing. */
export const UPSTREAM_PROOF_HEADER = "agentsafe-upstream-proof";
/** The most a proof file may be; a longer answer is not a proof. */
export const MAX_PROOF_BYTES = 1_024;
export const PROOF_TIMEOUT_MS = 10_000;
const HOUR_MS = 60 * 60 * 1_000;
/** A proven upstream is checked again a day later, give or take the jitter. */
export const PROOF_RECHECK_MS = 24 * HOUR_MS;
export const PROOF_JITTER_MS = HOUR_MS;
/** While a proof is missing it is looked for every hour, and the gateway forwards for the grace. */
export const PROOF_MISSING_RECHECK_MS = HOUR_MS;
export const PROOF_GRACE_MS = 72 * HOUR_MS;
/** While the gateway forwards nothing, it looks every minute. */
export const PROOF_PENDING_RETRY_MS = 60_000;

const TOKEN_DOMAIN = "agentsafe-upstream\nv1\n";
/** Ten digits; anchors would add nothing, since what it is tested on is ten characters at most. */
const ISSUED = /\d{10}/;
const REQUEST_HEADERS = { accept: "text/plain", "user-agent": "agentsafe-upstream-proof/1" };

/**
 * Whom a proof is for: the tenant's id, the Decionis organization it runs
 * under, and the upstream's origin as the WHATWG URL spells it (lower-case
 * host, no default port, no path). The base path is never part of it: the
 * gateway is sealed to the whole origin, so the proof covers the whole origin.
 */
export interface ProofBinding {
  readonly tenant: string;
  readonly org: string;
  readonly origin: string;
}

function token(binding: ProofBinding, issued: string): string {
  const digest = createHash("sha256")
    .update(`${TOKEN_DOMAIN}${binding.tenant}\n${binding.org}\n${binding.origin}\n${issued}`)
    .digest()
    .subarray(0, 16)
    .toString("base64url");
  return `v1.${issued}.${digest}`;
}

/**
 * The token that proves an origin for a tenant and an organization, issued
 * at a time in Unix seconds: `v1.<issued>.<base64url of the first 16 bytes
 * of SHA-256("agentsafe-upstream\nv1\n" + tenant + "\n" + org + "\n" +
 * origin + "\n" + issued)>`. There is no secret in it: whoever asks for a
 * token is given it, and what proves control is that only the origin's
 * controller can serve it there.
 */
export function proofToken(binding: ProofBinding, issued: number): string {
  return token(binding, String(issued));
}

/**
 * Whether any candidate, trimmed, is a token bound to this tenant,
 * organization and origin, at any issue time: its age is onboarding's
 * concern, never a recheck's.
 */
export function provesUpstream(candidates: readonly string[], binding: ProofBinding): boolean {
  return candidates.some((candidate) => {
    const line = candidate.trim();
    const issued = line.slice(3, 13);
    return ISSUED.test(issued) && line === token(binding, issued);
  });
}

/**
 * A proof file's lines. A comment, a blank line and anything else that is not
 * a token never proves anything, so nothing needs removing; a byte-order
 * mark is dropped and a line's carriage return is trimmed with its spaces.
 */
export function proofLines(body: Uint8Array): readonly string[] {
  return new TextDecoder().decode(body).split("\n");
}

export type ProofMethod = "file" | "dns";

/**
 * What one check found. `missing` is definitive: the origin answered over
 * verified TLS and served no token bound to the tenant. `unreachable` is no
 * answer at all, which says nothing about the proof.
 */
export type ProofOutcome =
  | { readonly kind: "proven"; readonly method: ProofMethod }
  | { readonly kind: "missing" }
  | { readonly kind: "unreachable"; readonly code: string };

/** TXT lookup as `dns.promises.resolveTxt` answers it: each record as its strings. */
export type TxtResolver = (name: string) => Promise<string[][]>;

export interface UpstreamProofCheckOptions {
  readonly resolveTxt: TxtResolver;
  /** Name resolution for the GET; the system resolver when absent. */
  readonly resolve?: AddressResolver;
  /** A transport under the guard, for a test; `node:https` when absent. */
  readonly transport?: FetchLike;
}

const MISSING: ProofOutcome = { kind: "missing" };

/**
 * One look at whether an upstream's origin serves a token bound to its
 * tenant. The GET goes through a guarded egress of the check's own, sealed
 * to the origin and the proof's path: public addresses only, a loopback name
 * refused, TLS verified against the public roots, redirects never followed,
 * at most 1 KiB, and no header of the tenant's. When the origin answers
 * without a token, a TXT record at `_agentsafe-challenge.<host>` may prove it
 * instead; a record alone never does, because DNS is not authenticated and
 * only an answer over verified TLS ties the name to the origin traffic
 * reaches. Nothing it reads is kept or written anywhere: what it returns is
 * an outcome and a code.
 */
export class UpstreamProofCheck {
  private readonly guard: GuardedFetch;
  private readonly resolveTxt: TxtResolver;

  public constructor(
    private readonly binding: ProofBinding,
    options: UpstreamProofCheckOptions,
  ) {
    const { resolveTxt, ...seams } = options;
    this.resolveTxt = resolveTxt;
    this.guard = new GuardedFetch({
      ...seams,
      policy: new EgressPolicy([
        {
          origin: binding.origin,
          pathPrefixes: [UPSTREAM_PROOF_PATH],
          ca: null,
          // Stryker disable next-line ArrayDeclaration: a pin binds only a real handshake, and a public-only check makes none with a test's loopback peer.
          pins: [],
        },
      ]),
      // What the check meets is its outcome, not the tenant's egress, so none
      // of it reaches a security stream or the alerts read from one.
      events: new SecurityEvents(() => undefined),
      maxResponseBytes: MAX_PROOF_BYTES,
      timeoutMs: PROOF_TIMEOUT_MS,
      publicOnly: true,
    });
  }

  /** Looks once. Never rejects: every failure is an outcome. */
  public async check(): Promise<ProofOutcome> {
    const url = new URL(UPSTREAM_PROOF_PATH, this.binding.origin);
    // Public-only lets a loopback name through, as the gateway refuses it in
    // its configuration instead; the check refuses it itself.
    if (EgressPolicy.isLoopbackHost(url.hostname)) {
      return { kind: "unreachable", code: "EGRESS_ADDRESS_REFUSED" };
    }
    let proven = false;
    try {
      const response = await this.guard.fetch(url, {
        headers: REQUEST_HEADERS,
        redirect: "manual",
      });
      proven =
        response.status === 200 &&
        provesUpstream(proofLines(new Uint8Array(await response.arrayBuffer())), this.binding);
    } catch (error) {
      // An answer over the bound is an answer, and not a proof; anything else is no answer.
      if (!(error instanceof EgressError && error.code === "EGRESS_BODY_TOO_LARGE")) {
        return { kind: "unreachable", code: UpstreamProofCheck.codeOf(error) };
      }
    }
    return proven ? { kind: "proven", method: "file" } : await this.txt(url.hostname);
  }

  public close(): void {
    this.guard.close();
  }

  /** The TXT record at the origin's name, once the origin has answered; an address has no name. */
  private async txt(hostname: string): Promise<ProofOutcome> {
    if (EgressPolicy.addressOf(hostname) !== null) return MISSING;
    let records: string[][];
    try {
      records = await this.resolveTxt(`${UPSTREAM_PROOF_TXT_LABEL}.${hostname}`);
    } catch (error) {
      // No such name or no such record is an answer; a resolver that failed is not.
      const code = UpstreamProofCheck.codeOf(error);
      if (code !== "ENODATA" && code !== "ENOTFOUND") return { kind: "unreachable", code };
      records = [];
    }
    // A record proves the origin when it contains the token: its strings
    // joined, as one value, whose parts are separated by spaces or `=`.
    const parts = records.flatMap((strings) => strings.join("").split(/[\s=]/));
    return provesUpstream(parts, this.binding) ? { kind: "proven", method: "dns" } : MISSING;
  }

  private static codeOf(error: unknown): string {
    const code = (error as { code?: unknown } | null)?.code;
    return typeof code === "string" ? code : "UPSTREAM_UNREACHABLE";
  }
}

/**
 * Where a tenant's proof stands in this process. `pending`: not yet seen;
 * `verified`: seen, by file or by TXT; `missing`: gone since a time, and
 * forwarded for the grace after it; `unverified`: not served when first
 * looked for, or gone for longer than the grace.
 */
export type ProofState =
  | { readonly kind: "pending" }
  | { readonly kind: "verified"; readonly method: ProofMethod }
  | { readonly kind: "missing"; readonly since: number }
  | { readonly kind: "unverified" };

/** What a change of state is reported as, on the tenant's security stream, before its origin. */
export type ProofEvent =
  | { readonly event: "UPSTREAM_PROOF_MISSING"; readonly stops_at: string }
  | {
      readonly event: "UPSTREAM_UNVERIFIED";
      readonly code: "UPSTREAM_PROOF_NOT_SERVED" | "UPSTREAM_PROOF_GRACE_ENDED";
    }
  | { readonly event: "UPSTREAM_PROOF_RESTORED"; readonly method: ProofMethod };

export interface ProofStep {
  readonly state: ProofState;
  readonly event: ProofEvent | null;
}

/** What a tenant's request gets: forwarded, forwarded and marked, or refused. */
export type ProofAdmission = "FORWARD" | "MISSING" | "REFUSE";

export const PENDING: ProofState = { kind: "pending" };
const UNVERIFIED: ProofState = { kind: "unverified" };

/**
 * The state after a check's outcome at a time. A proof seen is verified,
 * and restores a tenant that had lost it. A grace that has run out ends in
 * unverified, whatever the check found short of a proof. A miss starts the
 * grace for a verified tenant, and makes a tenant never seen unverified. An
 * origin that did not answer changes nothing.
 */
export function advance(state: ProofState, outcome: ProofOutcome, now: number): ProofStep {
  if (outcome.kind === "proven") {
    const restored = state.kind === "missing" || state.kind === "unverified";
    return {
      state: { kind: "verified", method: outcome.method },
      event: restored ? { event: "UPSTREAM_PROOF_RESTORED", method: outcome.method } : null,
    };
  }
  switch (state.kind) {
    case "missing":
      return inGrace(state, now)
        ? { state, event: null }
        : {
            state: UNVERIFIED,
            event: { event: "UPSTREAM_UNVERIFIED", code: "UPSTREAM_PROOF_GRACE_ENDED" },
          };
    case "verified":
      return outcome.kind === "missing"
        ? {
            state: { kind: "missing", since: now },
            event: {
              event: "UPSTREAM_PROOF_MISSING",
              stops_at: new Date(now + PROOF_GRACE_MS).toISOString(),
            },
          }
        : { state, event: null };
    case "pending":
      return outcome.kind === "missing"
        ? {
            state: UNVERIFIED,
            event: { event: "UPSTREAM_UNVERIFIED", code: "UPSTREAM_PROOF_NOT_SERVED" },
          }
        : { state, event: null };
    default:
      return { state, event: null };
  }
}

/** What a request gets in a state at a time: the grace ends on the clock, not at the next check. */
export function admission(state: ProofState, now: number): ProofAdmission {
  switch (state.kind) {
    case "verified":
      return "FORWARD";
    case "missing":
      return inGrace(state, now) ? "MISSING" : "REFUSE";
    default:
      return "REFUSE";
  }
}

function inGrace(state: { readonly since: number }, now: number): boolean {
  return now < state.since + PROOF_GRACE_MS;
}

/**
 * How long until the next check, with `random` in [0, 1): a day either side
 * of an hour once verified, so a fleet's checks do not fall together; every
 * hour while missing, and at the end of the grace; every minute otherwise.
 */
export function nextCheckIn(state: ProofState, now: number, random: number): number {
  switch (state.kind) {
    case "verified":
      return PROOF_RECHECK_MS + (random * 2 - 1) * PROOF_JITTER_MS;
    case "missing":
      return Math.min(PROOF_MISSING_RECHECK_MS, state.since + PROOF_GRACE_MS - now);
    default:
      return PROOF_PENDING_RETRY_MS;
  }
}

/** What the operator's status shows of a tenant's proof: its state and times, never its text. */
export interface ProofSnapshot {
  readonly state: ProofState["kind"];
  readonly method: ProofMethod | null;
  readonly checked_at: string | null;
  readonly stops_at: string | null;
  /** Why the last check had no answer, when it had none. */
  readonly code: string | null;
}

export interface UpstreamProofMonitorOptions {
  readonly origin: string;
  /** One look; never rejects. */
  readonly check: () => Promise<ProofOutcome>;
  /** Puts a change of state on the tenant's security stream. */
  readonly report: (event: SecurityEvent) => void;
  readonly clock: () => number;
  readonly random: () => number;
  /** Where the gateway this one replaces left the same proof, or `PENDING`. */
  readonly initial: ProofState;
}

/**
 * A tenant's proof, kept: checked at once while pending, then on the cadence
 * its state sets, each change reported. It holds no socket and no timer
 * that keeps a process alive.
 */
export class UpstreamProofMonitor {
  private state: ProofState;
  private settledOnce: boolean;
  private checkedAt: number | null = null;
  private lastCode: string | null = null;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private stopped = false;

  public constructor(private readonly options: UpstreamProofMonitorOptions) {
    this.state = options.initial;
    this.settledOnce = options.initial.kind !== "pending";
  }

  /** Checks now when nothing is known yet; otherwise when the state says to. */
  public start(): void {
    if (this.state.kind === "pending") void this.run();
    else this.schedule();
  }

  /** Whether a check has finished, or the state came from a gateway whose check had. */
  public get settled(): boolean {
    return this.settledOnce;
  }

  public get current(): ProofState {
    return this.state;
  }

  public admits(): ProofAdmission {
    return admission(this.state, this.options.clock());
  }

  public snapshot(): ProofSnapshot {
    const state = this.state;
    return {
      state: state.kind,
      method: state.kind === "verified" ? state.method : null,
      checked_at: this.checkedAt === null ? null : new Date(this.checkedAt).toISOString(),
      stops_at:
        state.kind === "missing" ? new Date(state.since + PROOF_GRACE_MS).toISOString() : null,
      code: this.lastCode,
    };
  }

  /** No further check, and a check in flight changes nothing when it ends. */
  public stop(): void {
    this.stopped = true;
    clearTimeout(this.timer);
  }

  private async run(): Promise<void> {
    const outcome = await this.options.check();
    if (this.stopped) return;
    const now = this.options.clock();
    const step = advance(this.state, outcome, now);
    this.state = step.state;
    this.checkedAt = now;
    this.lastCode = outcome.kind === "unreachable" ? outcome.code : null;
    this.settledOnce = true;
    if (step.event !== null) this.options.report({ ...step.event, origin: this.options.origin });
    this.schedule();
  }

  private schedule(): void {
    const delay = nextCheckIn(this.state, this.options.clock(), this.options.random());
    this.timer = setTimeout(() => void this.run(), delay);
    this.timer.unref();
  }
}
