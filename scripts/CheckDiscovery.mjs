import { access, readFile, readdir } from "node:fs/promises";
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

if (process.argv.includes("--check-links")) {
  const trimTrailingPunctuation = (value) => {
    let end = value.length;
    while (end > 0 && ".,;:".includes(value[end - 1])) end -= 1;
    return value.slice(0, end);
  };
  const urls = [
    ...new Set(
      [...short.matchAll(/https?:\/\/[^\s)<>\]"'`]+/g)].map((match) =>
        trimTrailingPunctuation(match[0]),
      ),
    ),
  ];
  const failures = [];
  const warnings = [];

  const probe = async (url) => {
    const localPath = url.match(
      /^https:\/\/github\.com\/decionis\/agent-safe-pipeline\/blob\/master\/(.+)$/,
    )?.[1];
    if (localPath) {
      try {
        await access(new URL(decodeURIComponent(localPath), root));
        return { ok: true, status: "local" };
      } catch {
        return { ok: false, status: 404 };
      }
    }

    for (const method of ["HEAD", "GET"]) {
      try {
        const response = await fetch(url, {
          method,
          redirect: "follow",
          signal: AbortSignal.timeout(20_000),
          headers: { "user-agent": "agent-safe-discovery-check" },
        });
        if (response.status < 400) return { ok: true, status: response.status };
        if (method === "GET") return { ok: false, status: response.status };
      } catch (error) {
        const code = error?.cause?.code ?? error?.code ?? error?.name;
        if (code === "ENOTFOUND" || code === "EAI_AGAIN") return { ok: false, code, dns: true };
        if (method === "GET") return { ok: false, code, transient: true };
      }
    }
    return { ok: false, transient: true };
  };

  for (const url of urls) {
    const result = await probe(url);
    if (result.ok) {
      process.stdout.write(`ok    ${result.status}  ${url}\n`);
    } else if (result.dns || result.status === 404 || result.status === 410) {
      const reason = result.dns ? `DNS ${result.code}` : String(result.status);
      failures.push(`${url} (${reason})`);
    } else {
      warnings.push(`${url} (${result.status ?? result.code ?? "unreachable"})`);
    }
  }

  for (const warning of warnings) process.stdout.write(`::warning::discovery: ${warning}\n`);
  for (const failure of failures) process.stderr.write(`::error::discovery: ${failure}\n`);
  if (failures.length > 0) throw new Error(`${failures.length} discovery link(s) failed`);
}
