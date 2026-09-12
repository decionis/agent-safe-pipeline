import { existsSync } from "node:fs";
import { access, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { URL } from "node:url";
import { DiscoveryUrlPolicyError, probeAllowedDiscoveryUrl } from "./DiscoveryUrlPolicy.mjs";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");
const short = (await read("llms.txt")).trim();
const full = await read("llms-full.txt");
if (!full.startsWith(`${short}\n`)) throw new Error("llms-full.txt must embed llms.txt verbatim");

const packageDirectories = (await readdir(new URL("packages/", root), { withFileTypes: true }))
  .filter((entry) => entry.isDirectory())
  .map((entry) => `packages/${entry.name}`);
const workspacePackages = new Set();
for (const directory of packageDirectories) {
  const manifest = JSON.parse(await read(`${directory}/package.json`));
  if (!manifest.private) workspacePackages.add(manifest.name);
}
const packageInventory = new Set(
  [...full.matchAll(/^- Package: (.+)$/gm)].map((match) => match[1]),
);
if (
  packageInventory.size !== workspacePackages.size ||
  [...workspacePackages].some((name) => !packageInventory.has(name))
) {
  throw new Error(
    `llms-full package inventory drifted from packages/*/package.json (expected: ${[...workspacePackages].join(", ")})`,
  );
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

// The two hand-written example inventories: the root README's map and the
// npm README's list (which must link absolutely, because it renders off-repo).
{
  const rootReadme = await read("README.md");
  const packageReadme = await read("packages/pipeline/README.md");
  const drifted = [];
  for (const directory of exampleDirectories) {
    if (!rootReadme.includes(directory)) drifted.push(`README.md does not name ${directory}`);
    const absolute = `https://github.com/decionis/agent-safe-pipeline/tree/master/${directory}`;
    if (!packageReadme.includes(absolute)) {
      drifted.push(`packages/pipeline/README.md does not link ${absolute}`);
    }
  }
  if (drifted.length > 0) {
    throw new Error(
      `README example inventory drifted from the workspace:\n- ${drifted.join("\n- ")}`,
    );
  }
}

// EVALUATION-PATH.md is a hand-written inventory of files, scripts and
// packages; discovery.rules.md §3 asks that every such inventory be gated.
{
  const { evaluationPathProblems } = await import("./EvaluationPathChecks.mjs");
  const rootManifest = JSON.parse(await read("package.json"));
  const declaredDependencies = new Set();
  for (const directory of packageDirectories) {
    const manifest = JSON.parse(await read(`${directory}/package.json`));
    for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
      for (const name of Object.keys(manifest[field] ?? {})) {
        if (name.startsWith("@decionis/")) declaredDependencies.add(name);
      }
    }
  }
  const exists = new Set();
  const problems = evaluationPathProblems({
    document: await read("EVALUATION-PATH.md"),
    fileExists: (path) => {
      if (exists.has(path)) return true;
      return existsSync(new URL(path, root));
    },
    rootScripts: rootManifest.scripts ?? {},
    workspacePackages,
    declaredDependencies,
  });
  if (problems.length > 0) {
    throw new Error(`EVALUATION-PATH.md drifted:\n- ${problems.join("\n- ")}`);
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
        const status = await probeAllowedDiscoveryUrl(url, method);
        if (status < 400) return { ok: true, status };
        if (method === "GET") return { ok: false, status };
      } catch (error) {
        if (error instanceof DiscoveryUrlPolicyError) {
          return { ok: false, code: error.code, policy: true };
        }
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
    } else if (result.policy || result.dns || result.status === 404 || result.status === 410) {
      const reason = result.policy
        ? result.code
        : result.dns
          ? `DNS ${result.code}`
          : String(result.status);
      failures.push(`${url} (${reason})`);
    } else {
      warnings.push(`${url} (${result.status ?? result.code ?? "unreachable"})`);
    }
  }

  for (const warning of warnings) process.stdout.write(`::warning::discovery: ${warning}\n`);
  for (const failure of failures) process.stderr.write(`::error::discovery: ${failure}\n`);
  if (failures.length > 0) throw new Error(`${failures.length} discovery link(s) failed`);
}
