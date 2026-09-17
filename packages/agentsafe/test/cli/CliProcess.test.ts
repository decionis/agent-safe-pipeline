import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { nodeCliProcess, nodeFiles } from "../../src/cli/CliProcess.js";

describe("the real process seam", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-cli-"));
  afterAll(() => rmSync(directory, { recursive: true, force: true }));

  it("reads, writes with a mode, makes directories and removes files", () => {
    const files = nodeFiles();
    const nested = join(directory, "a", "b");
    files.mkdir(nested);
    const path = join(nested, "credentials.json");
    expect(files.exists(path)).toBe(false);
    expect(files.read(path)).toBeNull();
    files.write(path, "{}", 0o600);
    expect(files.exists(path)).toBe(true);
    expect(files.read(path)).toBe("{}");
    expect(statSync(path).mode & 0o777).toBe(0o600);
    files.write(path, "{ }");
    expect(files.read(path)).toBe("{ }");
    files.remove(path);
    files.remove(path);
    expect(files.exists(path)).toBe(false);
  });

  it("describes the process it runs in", () => {
    const io = nodeCliProcess();
    expect(io.cwd).toBe(process.cwd());
    expect(io.home.length).toBeGreaterThan(0);
    expect(typeof io.isTTY).toBe("boolean");
    expect(typeof io.color).toBe("boolean");
    expect(io.env).toBe(process.env);
    expect(io.fetch).toBe(fetch);
    let seen = "";
    const write = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      seen += String(chunk);
      return true;
    }) as typeof process.stderr.write;
    try {
      io.stderr("line\n");
    } finally {
      process.stderr.write = write;
    }
    expect(seen).toBe("line\n");
  });
});
