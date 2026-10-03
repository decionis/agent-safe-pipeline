import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EgressError } from "../../src/egress/EgressError.js";
import { GuardedFetch } from "../../src/egress/GuardedFetch.js";
import type { FetchLike } from "../../src/handlers/HandlerRegistration.js";
import type { SecurityEvent } from "../../src/incident/SecurityEvents.js";
import {
  advance,
  admission,
  MAX_PROOF_BYTES,
  MAX_PROOF_RECORDS,
  nextCheckIn,
  PENDING,
  PROOF_GRACE_MS,
  PROOF_JITTER_MS,
  PROOF_MISSING_RECHECK_MS,
  PROOF_PENDING_RETRY_MS,
  PROOF_RECHECK_MS,
  proofLines,
  proofToken,
  provesUpstream,
  sameBinding,
  UPSTREAM_PROOF_HEADER,
  UPSTREAM_PROOF_PATH,
  UPSTREAM_PROOF_TXT_LABEL,
  UpstreamProofCheck,
  UpstreamProofMonitor,
  type ProofBinding,
  type ProofOutcome,
  type ProofStanding,
  type ProofState,
  type TxtResolver,
} from "../../src/gateway/UpstreamProof.js";

/** The specification's golden vector: both repositories compute exactly this. */
const BINDING: ProofBinding = {
  tenant: "acme",
  org: "6f1c1e0e-2a8b-4a35-9c55-0d6f0a3d2b11",
  origin: "https://api.acme.example",
};
const ISSUED = 1_759_492_800;
const GOLDEN = "v1.1759492800.GCO1YWc5UIsWe8_w9vbzTQ";
const HOUR = 60 * 60 * 1_000;

/** The token spelled out from the specification, without the module, for any issue text at all. */
function spelled(binding: ProofBinding, issued: string): string {
  const digest = createHash("sha256")
    .update(
      `agentsafe-upstream\nv1\n${binding.tenant}\n${binding.org}\n${binding.origin}\n${issued}`,
    )
    .digest()
    .subarray(0, 16)
    .toString("base64url");
  return `v1.${issued}.${digest}`;
}

describe("the proof token", () => {
  it("is the specification's golden vector", () => {
    expect(proofToken(BINDING, ISSUED)).toBe(GOLDEN);
    expect(spelled(BINDING, String(ISSUED))).toBe(GOLDEN);
    expect(PROOF_GRACE_MS).toBe(72 * HOUR);
    expect(MAX_PROOF_BYTES).toBe(1_024);
    expect(UPSTREAM_PROOF_HEADER).toBe("agentsafe-upstream-proof");
  });

  it("binds the tenant, the organization, the origin and the issue time, and nothing else proves it", () => {
    expect(provesUpstream([GOLDEN], BINDING)).toBe(true);
    for (const other of [
      { ...BINDING, tenant: "acme2" },
      { ...BINDING, org: "00000000-0000-4000-8000-000000000009" },
      { ...BINDING, origin: "https://api.acme.example:8443" },
      { ...BINDING, origin: "https://acme.example" },
    ]) {
      expect(proofToken(other, ISSUED)).not.toBe(GOLDEN);
      expect(provesUpstream([GOLDEN], other)).toBe(false);
      expect(provesUpstream([proofToken(other, ISSUED)], BINDING)).toBe(false);
    }
    expect(proofToken(BINDING, ISSUED + 1)).not.toBe(GOLDEN);
    // A digest that is not the issue time's own does not prove it.
    expect(provesUpstream([`v1.${ISSUED + 1}.${GOLDEN.slice(-22)}`], BINDING)).toBe(false);
  });

  it("proves at any age: a recheck never asks how old a token is", () => {
    for (const issued of [1_000_000_000, 4_102_444_800, 9_999_999_999]) {
      expect(provesUpstream([proofToken(BINDING, issued)], BINDING)).toBe(true);
    }
  });

  it("is ten digits of issue time, a version and the digest, and nothing around them", () => {
    const refused = [
      spelled(BINDING, "123"),
      spelled(BINDING, "abcdefghij"),
      spelled(BINDING, "1bcdefghij"),
      spelled(BINDING, "123456789a"),
      spelled(BINDING, "12345678901"),
      `x${GOLDEN}`,
      `${GOLDEN}x`,
      `${GOLDEN}.x`,
      GOLDEN.replace("v1.", "v2."),
      GOLDEN.slice(0, -1),
      `agentsafe-upstream=${GOLDEN}`,
      "",
    ];
    for (const line of refused)
      expect([line, provesUpstream([line], BINDING)]).toEqual([line, false]);
  });

  it("finds the token among other lines, with its spaces and line ending trimmed", () => {
    expect(provesUpstream([], BINDING)).toBe(false);
    expect(provesUpstream(["# AgentSafe hosted tenant", "", GOLDEN, "other"], BINDING)).toBe(true);
    expect(provesUpstream([`  ${GOLDEN}`], BINDING)).toBe(true);
    expect(provesUpstream([`${GOLDEN}\r`], BINDING)).toBe(true);
    expect(provesUpstream([`\t${GOLDEN} \r`], BINDING)).toBe(true);
    expect(provesUpstream([`${GOLDEN}  `], BINDING)).toBe(true);
    // Only the ends: white space inside a token is part of what fails to match.
    expect(provesUpstream([`${GOLDEN.slice(0, 13)} ${GOLDEN.slice(13)}`], BINDING)).toBe(false);
    expect(provesUpstream([" \t\r\n"], BINDING)).toBe(false);
  });

  it("trims exactly the white space Python's str.strip() does, so onboarding and the host read one proof alike", () => {
    // Every code point Python's str.isspace() is true for, and nothing else.
    const python = [
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000,
      0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028,
      0x2029, 0x202f, 0x205f, 0x3000,
    ];
    for (const code of python) {
      const space = String.fromCharCode(code);
      expect([code, provesUpstream([`${space}${space}${GOLDEN}${space}`], BINDING)]).toEqual([
        code,
        true,
      ]);
    }
    // JavaScript's trim() would take these; Python's strip() does not, and neither does the host.
    for (const code of [0xfeff, 0x180e, 0x200b]) {
      const other = String.fromCharCode(code);
      expect([code, provesUpstream([`${other}${GOLDEN}`], BINDING)]).toEqual([code, false]);
      expect([code, provesUpstream([`${GOLDEN}${other}`], BINDING)]).toEqual([code, false]);
    }
  });
});

describe("whether a kept proof holds for a binding", () => {
  it("holds only for the same tenant, organization and origin, all three", () => {
    expect(sameBinding(BINDING, { ...BINDING })).toBe(true);
    for (const other of [
      { ...BINDING, tenant: "globex" },
      { ...BINDING, org: "00000000-0000-4000-8000-000000000009" },
      { ...BINDING, origin: "https://api.globex.example" },
    ]) {
      expect(sameBinding(BINDING, other)).toBe(false);
      expect(sameBinding(other, BINDING)).toBe(false);
    }
  });
});

describe("a proof file's lines", () => {
  it("are its lines as UTF-8, without a byte-order mark at its start", () => {
    expect(proofLines(Buffer.from("a\nb\r\n\nc", "utf8"))).toEqual(["a", "b\r", "", "c"]);
    const file = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from(`${GOLDEN}\r\n# workspace caf\u00e9\n`, "utf8"),
    ]);
    const lines = proofLines(file);
    expect(lines).toEqual([`${GOLDEN}\r`, "# workspace caf\u00e9", ""]);
    expect(provesUpstream(lines, BINDING)).toBe(true);
    expect(provesUpstream(proofLines(new Uint8Array()), BINDING)).toBe(false);
  });

  it("are none at all when the body is not UTF-8, whatever one line holds", () => {
    for (const stray of [[0xff], [0xc3, 0x28], [0xed, 0xa0, 0x80]]) {
      const file = Buffer.concat([
        Buffer.from(`${GOLDEN}\n# workspace `, "utf8"),
        Buffer.from(stray),
        Buffer.from("\n", "utf8"),
      ]);
      expect(proofLines(file)).toEqual([]);
    }
  });
});

interface Sent {
  readonly url: string;
  readonly init: RequestInit | undefined;
}

/** A check whose GET answers `transport` and whose TXT lookup answers `txt`, both recorded. */
function harness(
  transport: FetchLike,
  txt: TxtResolver = async () => {
    throw Object.assign(new Error("no record"), { code: "ENODATA" });
  },
  origin: string = BINDING.origin,
): { check: UpstreamProofCheck; sent: Sent[]; looked: string[] } {
  const sent: Sent[] = [];
  const looked: string[] = [];
  const check = new UpstreamProofCheck(
    { ...BINDING, origin },
    {
      transport: async (input, init) => {
        sent.push({ url: String(input), init });
        return await transport(input, init);
      },
      resolveTxt: async (name) => {
        looked.push(name);
        return await txt(name);
      },
      resolve: async () => [{ address: "203.0.113.10", family: 4 }],
    },
  );
  return { check, sent, looked };
}

const answer =
  (status: number, body: string | null = null, headers: Record<string, string> = {}): FetchLike =>
  async () =>
    new Response(body, { status, headers });
const failing =
  (error: unknown): FetchLike =>
  async () => {
    throw error;
  };
const records =
  (...values: string[][]): TxtResolver =>
  async () =>
    values;
const lookupFails =
  (code: string | null): TxtResolver =>
  async () => {
    throw code === null ? new Error("resolver failed") : Object.assign(new Error(code), { code });
  };
const PROVEN_FILE: ProofOutcome = { kind: "proven", method: "file" };
const PROVEN_DNS: ProofOutcome = { kind: "proven", method: "dns" };
const MISSING: ProofOutcome = { kind: "missing" };

describe("one look at an upstream's proof", () => {
  it("proves by its file at the fixed path, asking with nothing of the tenant's and following nothing", async () => {
    const { check, sent, looked } = harness(answer(200, `# acme\r\n${GOLDEN}\r\n`));
    expect(await check.check()).toEqual(PROVEN_FILE);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe(`${BINDING.origin}${UPSTREAM_PROOF_PATH}`);
    expect(UPSTREAM_PROOF_PATH).toBe("/.well-known/agentsafe-upstream");
    expect(sent[0]?.init?.redirect).toBe("manual");
    expect(sent[0]?.init?.method).toBeUndefined();
    expect(sent[0]?.init?.body).toBeUndefined();
    expect(sent[0]?.init?.headers).toEqual({
      accept: "text/plain",
      "user-agent": "agentsafe-upstream-proof/1",
    });
    expect(looked).toEqual([]);
  });

  it("reads a file only from a 200, and otherwise looks for the TXT record at the origin's name", async () => {
    const notFound = harness(answer(404, GOLDEN), records([GOLDEN]));
    expect(await notFound.check.check()).toEqual(PROVEN_DNS);
    expect(notFound.looked).toEqual([`_agentsafe-challenge.api.acme.example`]);
    expect(UPSTREAM_PROOF_TXT_LABEL).toBe("_agentsafe-challenge");
    // A record's strings are one value, wherever DNS split them.
    const chunked = harness(
      answer(200, proofToken({ ...BINDING, tenant: "globex" }, ISSUED)),
      records(["unrelated=1"], [GOLDEN.slice(0, 9), GOLDEN.slice(9)]),
    );
    expect(await chunked.check.check()).toEqual(PROVEN_DNS);
    const neither = harness(answer(404, GOLDEN), records(["v=spf1 -all"], [`${GOLDEN}x`]));
    expect(await neither.check.check()).toEqual(MISSING);
    // A record is the token and nothing else, trimmed, as onboarding reads it.
    expect(await harness(answer(404), records([` ${GOLDEN}\t`])).check.check()).toEqual(PROVEN_DNS);
    for (const value of [
      `agentsafe-upstream=${GOLDEN}`,
      `agentsafe-upstream ${GOLDEN}`,
      `${GOLDEN}=`,
      `${GOLDEN} ${GOLDEN}`,
    ]) {
      expect([value, await harness(answer(404), records([value])).check.check()]).toEqual([
        value,
        MISSING,
      ]);
    }
    // A redirect is an answer from the origin, without the file at the origin itself.
    const moved = harness(answer(302, null, { location: "https://www.acme.example/proof" }));
    expect(await moved.check.check()).toEqual(MISSING);
    expect(moved.sent).toHaveLength(1);
    // So is a server error: the origin answered over verified TLS and served no token.
    expect(await harness(answer(503, GOLDEN)).check.check()).toEqual(MISSING);
  });

  it("reads the first 32 TXT records, and none longer than a proof file", async () => {
    expect(MAX_PROOF_RECORDS).toBe(32);
    const filler = Array.from({ length: 31 }, (_, index) => [`v=filler${index}`]);
    expect(await harness(answer(404), records(...filler, [GOLDEN])).check.check()).toEqual(
      PROVEN_DNS,
    );
    expect(
      await harness(answer(404), records(...filler, ["v=one-more"], [GOLDEN])).check.check(),
    ).toEqual(MISSING);
    // A record is measured in bytes, its strings joined, before it is trimmed.
    const padded = (pad: string, count: number): string => `${GOLDEN}${pad.repeat(count)}`;
    expect(Buffer.byteLength(padded(" ", 988))).toBe(MAX_PROOF_BYTES);
    expect(await harness(answer(404), records([padded(" ", 988)])).check.check()).toEqual(
      PROVEN_DNS,
    );
    expect(
      await harness(answer(404), records([padded(" ", 500), " ".repeat(488)])).check.check(),
    ).toEqual(PROVEN_DNS);
    expect(await harness(answer(404), records([padded(" ", 989)])).check.check()).toEqual(MISSING);
    // Two bytes each in UTF-8: 531 characters, 1,026 bytes.
    expect(await harness(answer(404), records([padded("\u00a0", 495)])).check.check()).toEqual(
      MISSING,
    );
    expect(await harness(answer(404), records([padded("\u00a0", 494)])).check.check()).toEqual(
      PROVEN_DNS,
    );
  });

  it("takes an answer over the bound as an answer that is not a proof", async () => {
    const large = new EgressError("EGRESS_BODY_TOO_LARGE", BINDING.origin);
    expect(await harness(failing(large)).check.check()).toEqual(MISSING);
    expect(await harness(failing(large), records([GOLDEN])).check.check()).toEqual(PROVEN_DNS);
  });

  it("is a miss when no record exists, and no answer when the resolver itself failed", async () => {
    for (const code of ["ENODATA", "ENOTFOUND"]) {
      expect(await harness(answer(404), lookupFails(code)).check.check()).toEqual(MISSING);
    }
    for (const code of ["ESERVFAIL", "ETIMEOUT", "ECONNREFUSED"]) {
      expect(await harness(answer(404), lookupFails(code)).check.check()).toEqual({
        kind: "unreachable",
        code,
      });
    }
    expect(await harness(answer(404), lookupFails(null)).check.check()).toEqual({
      kind: "unreachable",
      code: "UPSTREAM_UNREACHABLE",
    });
  });

  it("never takes a TXT record from an origin that gave no verified answer", async () => {
    for (const [error, code] of [
      [new EgressError("EGRESS_TLS_REJECTED", BINDING.origin), "EGRESS_TLS_REJECTED"],
      [
        new EgressError("EGRESS_TLS_CLIENT_CERT_REFUSED", BINDING.origin),
        "EGRESS_TLS_CLIENT_CERT_REFUSED",
      ],
      [new EgressError("EGRESS_TIMEOUT", BINDING.origin), "EGRESS_TIMEOUT"],
      [Object.assign(new Error("connect"), { code: "ECONNREFUSED" }), "ECONNREFUSED"],
      [new Error("no code"), "UPSTREAM_UNREACHABLE"],
      [null, "UPSTREAM_UNREACHABLE"],
    ] as const) {
      const { check, looked } = harness(failing(error), records([GOLDEN]));
      expect(await check.check()).toEqual({ kind: "unreachable", code });
      expect(looked).toEqual([]);
    }
  });

  it("has no name to look up for an address, and treats the origin's answer as the whole proof", async () => {
    for (const origin of ["https://203.0.113.10", "https://[2001:db8::10]"]) {
      const { check, sent, looked } = harness(answer(404), records([GOLDEN]), origin);
      expect(await check.check()).toEqual(MISSING);
      expect(sent[0]?.url).toBe(`${origin}${UPSTREAM_PROOF_PATH}`);
      expect(looked).toEqual([]);
    }
    const proven = harness(
      answer(200, proofToken({ ...BINDING, origin: "https://[2001:db8::10]" }, ISSUED)),
      records(),
      "https://[2001:db8::10]",
    );
    expect(await proven.check.check()).toEqual(PROVEN_FILE);
  });

  it("refuses loopback names and inward addresses before any request", async () => {
    for (const origin of [
      "https://localhost",
      "https://127.0.0.1",
      "https://[::1]",
      "https://10.0.0.5",
      "https://192.168.4.4",
    ]) {
      const { check, sent, looked } = harness(answer(200, GOLDEN), records([GOLDEN]), origin);
      expect([origin, await check.check()]).toEqual([
        origin,
        { kind: "unreachable", code: "EGRESS_ADDRESS_REFUSED" },
      ]);
      expect(sent).toEqual([]);
      expect(looked).toEqual([]);
    }
  });

  it("closes its own egress", () => {
    const close = vi.spyOn(GuardedFetch.prototype, "close");
    harness(answer(200)).check.close();
    expect(close).toHaveBeenCalledTimes(1);
    close.mockRestore();
  });
});

const VERIFIED_FILE: ProofState = { kind: "verified", method: "file" };
const VERIFIED_DNS: ProofState = { kind: "verified", method: "dns" };
const UNVERIFIED: ProofState = { kind: "unverified" };
const UNREACHABLE: ProofOutcome = { kind: "unreachable", code: "ECONNREFUSED" };
const T0 = Date.parse("2026-10-03T12:00:00.000Z");

describe("the state a look leaves", () => {
  it("verifies a proof seen, and restores only a tenant that had lost it", () => {
    expect(advance(PENDING, PROVEN_FILE, T0)).toEqual({ state: VERIFIED_FILE, event: null });
    expect(advance(VERIFIED_FILE, PROVEN_DNS, T0)).toEqual({ state: VERIFIED_DNS, event: null });
    expect(advance({ kind: "missing", since: T0 }, PROVEN_FILE, T0 + 5 * HOUR)).toEqual({
      state: VERIFIED_FILE,
      event: { event: "UPSTREAM_PROOF_RESTORED", method: "file" },
    });
    // Seen again after the grace ran out, too.
    expect(advance({ kind: "missing", since: T0 }, PROVEN_DNS, T0 + PROOF_GRACE_MS)).toEqual({
      state: VERIFIED_DNS,
      event: { event: "UPSTREAM_PROOF_RESTORED", method: "dns" },
    });
    expect(advance(UNVERIFIED, PROVEN_DNS, T0)).toEqual({
      state: VERIFIED_DNS,
      event: { event: "UPSTREAM_PROOF_RESTORED", method: "dns" },
    });
  });

  it("starts the grace on a verified tenant's miss, and ends it on the clock, answered or not", () => {
    expect(advance(VERIFIED_DNS, MISSING, T0)).toEqual({
      state: { kind: "missing", since: T0 },
      event: { event: "UPSTREAM_PROOF_MISSING", stops_at: "2026-10-06T12:00:00.000Z" },
    });
    const missing: ProofState = { kind: "missing", since: T0 };
    for (const outcome of [MISSING, UNREACHABLE]) {
      expect(advance(missing, outcome, T0 + PROOF_GRACE_MS - 1)).toEqual({
        state: missing,
        event: null,
      });
      expect(advance(missing, outcome, T0 + PROOF_GRACE_MS)).toEqual({
        state: UNVERIFIED,
        event: { event: "UPSTREAM_UNVERIFIED", code: "UPSTREAM_PROOF_GRACE_ENDED" },
      });
    }
  });

  it("makes a tenant never seen unverified at its first miss, and changes nothing without an answer", () => {
    expect(advance(PENDING, MISSING, T0)).toEqual({
      state: UNVERIFIED,
      event: { event: "UPSTREAM_UNVERIFIED", code: "UPSTREAM_PROOF_NOT_SERVED" },
    });
    expect(advance(UNVERIFIED, MISSING, T0)).toEqual({ state: UNVERIFIED, event: null });
    for (const state of [PENDING, VERIFIED_FILE, UNVERIFIED]) {
      expect(advance(state, UNREACHABLE, T0)).toEqual({ state, event: null });
    }
  });

  it("forwards when verified, marks for the grace, and refuses otherwise", () => {
    expect(admission(VERIFIED_FILE, T0)).toBe("FORWARD");
    const missing: ProofState = { kind: "missing", since: T0 };
    expect(admission(missing, T0)).toBe("MISSING");
    expect(admission(missing, T0 + PROOF_GRACE_MS - 1)).toBe("MISSING");
    expect(admission(missing, T0 + PROOF_GRACE_MS)).toBe("REFUSE");
    expect(admission(PENDING, T0)).toBe("REFUSE");
    expect(admission(UNVERIFIED, T0)).toBe("REFUSE");
  });

  it("looks again a day later give or take an hour, hourly while missing and at the grace's end, and every minute otherwise", () => {
    expect(PROOF_RECHECK_MS).toBe(24 * HOUR);
    expect(PROOF_JITTER_MS).toBe(HOUR);
    expect(nextCheckIn(VERIFIED_FILE, T0, 0)).toBe(23 * HOUR);
    expect(nextCheckIn(VERIFIED_FILE, T0, 0.5)).toBe(24 * HOUR);
    expect(nextCheckIn(VERIFIED_FILE, T0, 0.75)).toBe(24.5 * HOUR);
    expect(nextCheckIn(VERIFIED_FILE, T0, 1)).toBe(25 * HOUR);
    const missing: ProofState = { kind: "missing", since: T0 };
    expect(nextCheckIn(missing, T0, 0.5)).toBe(PROOF_MISSING_RECHECK_MS);
    expect(nextCheckIn(missing, T0 + PROOF_GRACE_MS - 10 * 60_000, 0.5)).toBe(10 * 60_000);
    expect(nextCheckIn(PENDING, T0, 0.5)).toBe(60_000);
    expect(nextCheckIn(UNVERIFIED, T0, 0.5)).toBe(PROOF_PENDING_RETRY_MS);
  });
});

/** A look whose outcome the test hands over when it chooses. */
function deferred(): { promise: Promise<ProofOutcome>; settle: (outcome: ProofOutcome) => void } {
  let settle: (outcome: ProofOutcome) => void = () => undefined;
  const promise = new Promise<ProofOutcome>((resolve) => {
    settle = resolve;
  });
  return { promise, settle };
}

describe("a tenant's proof, kept", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function monitor(outcomes: ProofOutcome[]): {
    monitor: UpstreamProofMonitor;
    events: SecurityEvent[];
    checks: () => number;
  } {
    const events: SecurityEvent[] = [];
    let checks = 0;
    const kept = new UpstreamProofMonitor({
      origin: BINDING.origin,
      check: async () => {
        checks += 1;
        return outcomes.shift() ?? UNREACHABLE;
      },
      report: (event) => events.push(event),
      clock: () => Date.now(),
      random: () => 0.5,
    });
    return { monitor: kept, events, checks: () => checks };
  }

  /** A proof verified by file at a time, its next look a day after it. */
  const verifiedAt = (at: number): ProofStanding => ({
    state: VERIFIED_FILE,
    checkedAt: at,
    code: null,
    dueAt: at + PROOF_RECHECK_MS,
    settled: true,
  });

  it("looks at once while pending, every minute until it sees the proof, then daily", async () => {
    const look = deferred();
    const outcomes: ProofOutcome[] = [UNREACHABLE, PROVEN_FILE];
    const events: SecurityEvent[] = [];
    let checks = 0;
    const kept = new UpstreamProofMonitor({
      origin: BINDING.origin,
      check: () => {
        checks += 1;
        return checks === 1 ? look.promise : Promise.resolve(outcomes.shift() ?? UNREACHABLE);
      },
      report: (event) => events.push(event),
      clock: () => Date.now(),
      random: () => 0.5,
    });
    expect(kept.settled).toBe(false);
    expect(kept.current).toEqual(PENDING);
    expect(kept.snapshot()).toEqual({
      state: "pending",
      method: null,
      checked_at: null,
      stops_at: null,
      code: null,
    });
    kept.start();
    expect(checks).toBe(1);
    expect(kept.settled).toBe(false);
    expect(kept.admits()).toBe("REFUSE");
    await vi.advanceTimersByTimeAsync(5_000);
    look.settle(UNREACHABLE);
    await vi.advanceTimersByTimeAsync(0);
    expect(kept.settled).toBe(true);
    expect(kept.current).toEqual(PENDING);
    expect(kept.snapshot()).toMatchObject({
      state: "pending",
      checked_at: "2026-10-03T12:00:05.000Z",
      code: "ECONNREFUSED",
    });
    await vi.advanceTimersByTimeAsync(PROOF_PENDING_RETRY_MS - 1);
    expect(checks).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(checks).toBe(2);
    await vi.advanceTimersByTimeAsync(PROOF_PENDING_RETRY_MS);
    expect(checks).toBe(3);
    expect(kept.current).toEqual(VERIFIED_FILE);
    expect(kept.admits()).toBe("FORWARD");
    expect(kept.snapshot()).toEqual({
      state: "verified",
      method: "file",
      checked_at: "2026-10-03T12:02:05.000Z",
      stops_at: null,
      code: null,
    });
    // The first proof seen is not news on the security stream.
    expect(events).toEqual([]);
    await vi.advanceTimersByTimeAsync(PROOF_RECHECK_MS - 1);
    expect(checks).toBe(3);
    await vi.advanceTimersByTimeAsync(1);
    expect(checks).toBe(4);
    kept.stop();
  });

  it("marks a verified tenant whose proof is gone, refuses it after the grace, and restores it when it is back", async () => {
    const outcomes: ProofOutcome[] = [MISSING, ...Array<ProofOutcome>(71).fill(MISSING), MISSING];
    const { monitor: kept, events, checks } = monitor(outcomes);
    kept.resume(verifiedAt(T0));
    expect(kept.settled).toBe(true);
    expect(checks()).toBe(0);
    await vi.advanceTimersByTimeAsync(PROOF_RECHECK_MS);
    expect(checks()).toBe(1);
    const since = T0 + PROOF_RECHECK_MS;
    expect(kept.admits()).toBe("MISSING");
    expect(events).toEqual([
      {
        event: "UPSTREAM_PROOF_MISSING",
        origin: BINDING.origin,
        stops_at: new Date(since + PROOF_GRACE_MS).toISOString(),
      },
    ]);
    expect(kept.snapshot()).toMatchObject({
      state: "missing",
      stops_at: new Date(since + PROOF_GRACE_MS).toISOString(),
    });
    await vi.advanceTimersByTimeAsync(PROOF_GRACE_MS - 1);
    expect(kept.admits()).toBe("MISSING");
    expect(events).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(checks()).toBe(73);
    expect(kept.admits()).toBe("REFUSE");
    expect(events.at(-1)).toEqual({
      event: "UPSTREAM_UNVERIFIED",
      origin: BINDING.origin,
      code: "UPSTREAM_PROOF_GRACE_ENDED",
    });
    outcomes.push(PROVEN_DNS);
    await vi.advanceTimersByTimeAsync(PROOF_PENDING_RETRY_MS);
    expect(kept.admits()).toBe("FORWARD");
    expect(events.at(-1)).toEqual({
      event: "UPSTREAM_PROOF_RESTORED",
      origin: BINDING.origin,
      method: "dns",
    });
    kept.stop();
  });

  it("makes a tenant whose origin answers without a proof unverified at once", async () => {
    const { monitor: kept, events } = monitor([MISSING]);
    kept.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(kept.admits()).toBe("REFUSE");
    expect(events).toEqual([
      { event: "UPSTREAM_UNVERIFIED", origin: BINDING.origin, code: "UPSTREAM_PROOF_NOT_SERVED" },
    ]);
    kept.stop();
  });

  it("stops: no further look, and a look in flight changes nothing when it ends", async () => {
    const look = deferred();
    const events: SecurityEvent[] = [];
    let checks = 0;
    const kept = new UpstreamProofMonitor({
      origin: BINDING.origin,
      check: () => {
        checks += 1;
        return look.promise;
      },
      report: (event) => events.push(event),
      clock: () => Date.now(),
      random: () => 0.5,
    });
    kept.start();
    kept.stop();
    look.settle(PROVEN_FILE);
    await vi.advanceTimersByTimeAsync(PROOF_RECHECK_MS * 2);
    expect(checks).toBe(1);
    expect(kept.current).toEqual(PENDING);
    expect(kept.settled).toBe(false);
    expect(events).toEqual([]);

    const waiting = monitor([PROVEN_FILE]);
    waiting.monitor.resume(verifiedAt(T0));
    waiting.monitor.stop();
    await vi.advanceTimersByTimeAsync(PROOF_RECHECK_MS * 2);
    expect(waiting.checks()).toBe(0);
  });

  it("stands where its last look left it, and is due when its next look is", async () => {
    const look = deferred();
    let checks = 0;
    const kept = new UpstreamProofMonitor({
      origin: BINDING.origin,
      check: () => {
        checks += 1;
        return checks === 1 ? Promise.resolve(PROVEN_FILE) : look.promise;
      },
      report: () => undefined,
      clock: () => Date.now(),
      random: () => 0.25,
    });
    expect(kept.standing()).toEqual({
      state: PENDING,
      checkedAt: null,
      code: null,
      dueAt: null,
      settled: false,
    });
    kept.start();
    await vi.advanceTimersByTimeAsync(0);
    // Verified, its next look a day less half an hour away (random 0.25).
    const due = T0 + PROOF_RECHECK_MS - PROOF_JITTER_MS / 2;
    expect(kept.standing()).toEqual({
      state: VERIFIED_FILE,
      checkedAt: T0,
      code: null,
      dueAt: due,
      settled: true,
    });
    await vi.advanceTimersByTimeAsync(due - T0);
    // A look in flight has no time it is due: whoever takes over looks at once.
    expect(checks).toBe(2);
    expect(kept.standing()).toMatchObject({ checkedAt: T0, dueAt: null });
    kept.stop();
    look.settle(MISSING);
    await vi.advanceTimersByTimeAsync(0);
    expect(kept.standing()).toEqual({
      state: VERIFIED_FILE,
      checkedAt: T0,
      code: null,
      dueAt: null,
      settled: true,
    });
  });

  it("takes over a standing whole: the next look stays when it was due, and the last look is still the last", async () => {
    const before = T0 - 5 * HOUR;
    const { monitor: kept, events, checks } = monitor([MISSING]);
    kept.resume({
      state: { kind: "pending" },
      checkedAt: before,
      code: "ETIMEDOUT",
      dueAt: T0 + 30_000,
      settled: true,
    });
    expect(kept.settled).toBe(true);
    expect(kept.current).toEqual(PENDING);
    expect(kept.snapshot()).toEqual({
      state: "pending",
      method: null,
      checked_at: new Date(before).toISOString(),
      stops_at: null,
      code: "ETIMEDOUT",
    });
    // Not a fresh minute from the takeover: thirty seconds, when it was due.
    await vi.advanceTimersByTimeAsync(30_000 - 1);
    expect(checks()).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(checks()).toBe(1);
    expect(events).toEqual([
      { event: "UPSTREAM_UNVERIFIED", origin: BINDING.origin, code: "UPSTREAM_PROOF_NOT_SERVED" },
    ]);
    kept.stop();

    // A verified proof whose next look was 20 hours away is looked at in 20 hours, not 24.
    const daily = monitor([PROVEN_DNS]);
    daily.monitor.resume(verifiedAt(Date.now() - 4 * HOUR));
    expect(daily.monitor.admits()).toBe("FORWARD");
    await vi.advanceTimersByTimeAsync(20 * HOUR - 1);
    expect(daily.checks()).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(daily.checks()).toBe(1);
    daily.monitor.stop();
  });

  it("looks at once when what it takes over had a look in flight, or was already due", async () => {
    for (const dueAt of [null, T0 - HOUR]) {
      const { monitor: kept, checks } = monitor([PROVEN_FILE]);
      kept.resume({ ...verifiedAt(T0 - 2 * HOUR), dueAt });
      expect(checks()).toBe(0);
      await vi.advanceTimersByTimeAsync(1);
      expect([dueAt, checks()]).toEqual([dueAt, 1]);
      kept.stop();
    }
  });
});

describe("a tenant's proof, kept, in a real process", () => {
  it("never keeps the process alive for its next look", () => {
    const kept = new UpstreamProofMonitor({
      origin: BINDING.origin,
      check: async () => UNREACHABLE,
      report: () => undefined,
      clock: () => Date.now(),
      random: () => 0.5,
    });
    kept.resume({
      state: VERIFIED_FILE,
      checkedAt: Date.now(),
      code: null,
      dueAt: Date.now() + PROOF_RECHECK_MS,
      settled: true,
    });
    const timer = (kept as unknown as { readonly timer: ReturnType<typeof setTimeout> }).timer;
    expect(timer.hasRef()).toBe(false);
    kept.stop();
  });
});
