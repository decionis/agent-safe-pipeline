import { describe, expect, it } from "vitest";
import {
  SECURITY_STREAM,
  SecurityEvents,
  type SecurityEvent,
} from "../../src/incident/SecurityEvents.js";

describe("SecurityEvents", () => {
  it("writes one validated line per event with the stream and the time", () => {
    const lines: string[] = [];
    const events = new SecurityEvents(
      (line) => lines.push(line),
      () => new Date(0),
    );
    events.emit({ event: "SECRET_ROTATED", name: "DECIONIS_API_KEY" });
    events.emit({ event: "POSTURE_VERIFIED", checks: 21, waived: 2 });
    expect(lines.map((line) => JSON.parse(line))).toEqual([
      {
        stream: SECURITY_STREAM,
        at: "1970-01-01T00:00:00.000Z",
        event: "SECRET_ROTATED",
        name: "DECIONIS_API_KEY",
      },
      {
        stream: SECURITY_STREAM,
        at: "1970-01-01T00:00:00.000Z",
        event: "POSTURE_VERIFIED",
        checks: 21,
        waived: 2,
      },
    ]);
    expect(events.dropped).toBe(0);
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
