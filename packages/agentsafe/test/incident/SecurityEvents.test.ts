import { describe, expect, it } from "vitest";
import { CHAIN_GENESIS, HashChain } from "../../src/audit/HashChain.js";
import {
  SECURITY_STREAM,
  SecurityEvents,
  type SecurityEvent,
} from "../../src/incident/SecurityEvents.js";
import { verifyAuditChain } from "../../src/verify/VerifyAuditChain.js";

describe("SecurityEvents", () => {
  it("writes one validated, chained line per event with the stream and the time", () => {
    const lines: string[] = [];
    const events = new SecurityEvents((line) => lines.push(line), { clock: () => new Date(0) });
    events.emit({ event: "SECRET_ROTATED", name: "DECIONIS_API_KEY" });
    events.emit({ event: "POSTURE_VERIFIED", checks: 21, waived: 2 });
    const parsed = lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(parsed[0]).toMatchObject({
      stream: SECURITY_STREAM,
      seq: 1,
      prev_hash: CHAIN_GENESIS,
      at: "1970-01-01T00:00:00.000Z",
      event: "SECRET_ROTATED",
      name: "DECIONIS_API_KEY",
    });
    expect(parsed[1]).toMatchObject({
      stream: SECURITY_STREAM,
      seq: 2,
      prev_hash: parsed[0]?.["hash"],
      event: "POSTURE_VERIFIED",
      checks: 21,
      waived: 2,
    });
    expect(Object.keys(parsed[0] ?? {})).toEqual([
      "stream",
      "seq",
      "prev_hash",
      "at",
      "event",
      "name",
      "hash",
    ]);
    expect(verifyAuditChain(lines).ok).toBe(true);
    expect(events.head).toEqual({ seq: 2, hash: parsed[1]?.["hash"] });
    expect(events.dropped).toBe(0);
  });

  it("continues a chain it is handed and tells subscribers about each event written", () => {
    const lines: string[] = [];
    const seen: string[] = [];
    const chain = new HashChain(SECURITY_STREAM, { seq: 41, hash: `sha256:${"a".repeat(64)}` });
    const events = new SecurityEvents((line) => lines.push(line), { chain });
    const stop = events.subscribe((event) => seen.push(event.event));
    events.emit({
      event: "EGRESS_REFUSED",
      origin: "https://elsewhere.example",
      code: "EGRESS_ORIGIN_NOT_ALLOWED",
    });
    events.emit({ event: "AUTH_FAILED", method: "mtls", code: "CALLER_NOT_AUTHENTICATED" });
    stop();
    events.emit({ event: "TLS_CONTEXT_ROTATED" });
    events.emit({ event: "CHAIN_CHECKPOINT", chain: SECURITY_STREAM, head: 44 });
    events.emit({ event: "CHAIN_RESUMED", chain: SECURITY_STREAM, head: 44 });
    expect(seen).toEqual(["EGRESS_REFUSED", "AUTH_FAILED"]);
    expect(lines.map((line) => (JSON.parse(line) as { seq: number }).seq)).toEqual([
      42, 43, 44, 45, 46,
    ]);
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({ prev_hash: `sha256:${"a".repeat(64)}` });
    expect(events.chain).toBe(chain);
  });

  it("drops and counts an event that does not fit the schema, never throwing", () => {
    const lines: string[] = [];
    const events = new SecurityEvents((line) => lines.push(line));
    events.emit({ event: "POSTURE_DRIFT", check: "not a code" } as SecurityEvent);
    events.emit({ event: "SECRET_ROTATED", name: "X", value: "leak" } as unknown as SecurityEvent);
    events.emit({ event: "UNKNOWN_EVENT" } as unknown as SecurityEvent);
    expect(lines).toEqual([]);
    expect(events.dropped).toBe(3);
  });
});
