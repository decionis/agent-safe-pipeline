import { describe, expect, it } from "vitest";
import { LineEmitter } from "../../src/logging/LineEmitter.js";
import { Redactor } from "../../src/secrets/Redactor.js";

describe("LineEmitter", () => {
  it("routes audit and process lines to stdout, security lines to stderr, all redacted", () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const caught: (readonly string[])[] = [];
    const emitter = new LineEmitter(
      { stdout: (line) => stdout.push(line), stderr: (line) => stderr.push(line) },
      new Redactor(() => []),
    );
    emitter.reportRedactions((patterns) => caught.push(patterns));
    emitter.audit('{"event":"EXECUTION_COMPLETED"}');
    emitter.process('{"event":"LISTENING"}');
    emitter.security(`{"event":"AUTH_FAILED","detail":"Bearer ${"x".repeat(40)}"}`);
    expect(stdout).toEqual(['{"event":"EXECUTION_COMPLETED"}', '{"event":"LISTENING"}']);
    expect(stderr).toEqual(['{"event":"AUTH_FAILED","detail":"Bearer [REDACTED:bearer]"}']);
    expect(caught).toEqual([["bearer"]]);
  });

  it("writes the line even when a redaction happened", () => {
    const stdout: string[] = [];
    const emitter = new LineEmitter(
      { stdout: (line) => stdout.push(line), stderr: () => undefined },
      new Redactor(() => []),
    );
    emitter.audit(`correlation ${"eyJ".padEnd(12, "a")}.${"b".repeat(12)}.${"c".repeat(12)}`);
    expect(stdout).toEqual(["correlation [REDACTED:jws]"]);
  });
});
