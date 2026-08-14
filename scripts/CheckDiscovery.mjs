import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { URL } from "node:url";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");
const short = (await read("llms.txt")).trim();
const full = await read("llms-full.txt");
if (!full.startsWith(`${short}\n`)) throw new Error("llms-full.txt must embed llms.txt verbatim");

const packageManifest = JSON.parse(await read("packages/pipeline/package.json"));
const packageInventory = new Set(
  [...full.matchAll(/^- Package: (.+)$/gm)].map((match) => match[1]),
);
if (packageInventory.size !== 1 || !packageInventory.has(packageManifest.name)) {
  throw new Error("llms-full package inventory drifted from packages/pipeline/package.json");
}

const exampleDirectories = (await readdir(new URL("examples/", root), { withFileTypes: true }))
  .filter((entry) => entry.isDirectory())
  .map((entry) => `examples/${entry.name}`);
const exampleInventory = new Set(
  [...full.matchAll(/^- Example: (.+)$/gm)].map((match) => match[1]),
);
if (
  exampleDirectories.length !== exampleInventory.size ||
  exampleDirectories.some((directory) => !exampleInventory.has(directory))
) {
  throw new Error("llms-full example inventory drifted from the workspace");
}

for (const directory of exampleDirectories) {
  const files = new Set(await readdir(new URL(`${directory}/`, root)));
  for (const required of ["README.md", "package.json", "src"]) {
    if (!files.has(required)) throw new Error(`${join(directory, required)} is required`);
  }
}
