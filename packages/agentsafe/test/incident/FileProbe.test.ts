import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { regularFileExists, watchDirectory } from "../../src/incident/FileProbe.js";

const root = mkdtempSync(join(tmpdir(), "agentsafe-probe-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("regularFileExists", () => {
  it("answers for a file, and answers rather than throwing for everything else", () => {
    const file = join(root, "halted");
    writeFileSync(file, "stop\n");
    expect(regularFileExists(file)).toBe(true);
    // A directory is not a halt file, and neither is a path that is not
    // there: the look runs inside a poll's callback, so it has to answer.
    expect(regularFileExists(root)).toBe(false);
    expect(regularFileExists(join(root, "never-created"))).toBe(false);
    expect(regularFileExists(join(file, "through-a-file"))).toBe(false);
    expect(regularFileExists("")).toBe(false);
    rmSync(file);
    expect(regularFileExists(file)).toBe(false);
  });

  it("follows a directory and lets go of it, without holding the process open", () => {
    const directory = mkdtempSync(join(root, "followed-"));
    const watcher = watchDirectory(directory, () => undefined);
    // A watch is a handle to close, and closing it twice is not an error:
    // the halt switch closes on every `start()` and again on `stop()`.
    expect(typeof watcher.close).toBe("function");
    watcher.close();
    watcher.close();
    rmSync(directory, { recursive: true, force: true });
  });

  it("refuses to follow a directory that is not there", () => {
    // The halt switch catches this: a directory it cannot watch leaves the
    // poll as the only follower, which is the one that has to work anyway.
    expect(() => watchDirectory(join(root, "no-such-directory"), () => undefined)).toThrow();
  });
});
