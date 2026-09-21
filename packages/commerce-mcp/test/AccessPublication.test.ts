import type * as FileSystem from "node:fs/promises";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import { runtimeAccess } from "../src/Access.js";
import type { ResolvedAccess } from "../src/Configuration.js";

const publication = vi.hoisted(() => ({
  beforeWrite: undefined as (() => Promise<void>) | undefined,
}));
vi.mock("node:fs/promises", async (importOriginal) => {
  const fs = await importOriginal<typeof FileSystem>();
  return {
    ...fs,
    async open(...args: Parameters<typeof fs.open>) {
      const file = await fs.open(...args);
      if (args[1] === "wx" && /credentials\.(?:pending|json)$/.test(String(args[0]))) {
        const write = file.writeFile.bind(file);
        file.writeFile = async (...writeArgs: Parameters<typeof file.writeFile>) => {
          await publication.beforeWrite?.();
          return write(...writeArgs);
        };
      }
      return file;
    },
  };
});

it.skipIf(process.platform === "win32")(
  "readers never observe an empty credential while another process publishes access",
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "agentops-publication-test-"));
    let beganWrite!: () => void;
    let releaseWrite!: () => void;
    const began = new Promise<void>((resolve) => {
      beganWrite = resolve;
    });
    const release = new Promise<void>((resolve) => {
      releaseWrite = resolve;
    });
    publication.beforeWrite = async () => {
      beganWrite();
      await release;
    };
    const fetch = vi.fn<typeof globalThis.fetch>(
      async () =>
        new Response(
          JSON.stringify({
            org_id: "11111111-1111-4111-8111-111111111111",
            raw_key: "synthetic-publication-key",
            provisional: true,
          }),
        ),
    );
    const environment = { AGENTOPS_HOME: directory };
    const writer = runtimeAccess(environment, "stdio", { fetch })!.resolve("shadow");
    let contender: Promise<ResolvedAccess | null> | undefined;
    try {
      await began;
      const otherProcess = runtimeAccess(environment, "stdio", { fetch })!;
      // With the old direct write, this read parsed the empty credentials.json
      // and failed instead of observing that no credential was published yet.
      expect(await otherProcess.resolve("read")).toBeNull();
      contender = otherProcess.resolve("shadow");
      releaseWrite();
      const [first, second] = await Promise.all([writer, contender]);
      expect(second).toEqual(first);
      expect(fetch).toHaveBeenCalledOnce();
      expect(JSON.parse(await readFile(join(directory, "credentials.json"), "utf8"))).toMatchObject(
        { api_key: "synthetic-publication-key" },
      );
    } finally {
      releaseWrite();
      await Promise.allSettled([writer, contender]);
      publication.beforeWrite = undefined;
      await rm(directory, { recursive: true, force: true });
    }
  },
);
