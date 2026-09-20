/**
 * The CycloneDX SBOM of a workspace package's production dependency tree, from
 * the tree the repository's lockfile pins and the release job installed with
 * `pnpm install --frozen-lockfile`: every version is the one the lockfile
 * resolved and the tests ran against, every registry package carries the
 * SHA-512 the lockfile holds for its tarball, and nothing is fetched to write
 * it. The release once read this from an `npm install` of the packed tarball,
 * which resolved the declared ranges afresh from the registry at release time,
 * unpinned by anything; this is the same document from the pinned tree.
 *
 * Usage: ReleaseSbom.mjs <package-dir> <out.cdx.json> [library|application] [--packed <tarball>...]
 *
 * A workspace package the tree links from source has no tarball in the
 * lockfile; `--packed` names the tarball the release ships for it, and its
 * component then carries that tarball's SHA-512 and registry location, so the
 * runtime's SBOM names the very pipeline tarball the same release publishes.
 *
 * The root component's version and purl are what `FinalizeReleaseSbom.mjs`
 * checks against the packed tarball; the serial number and the timestamp are
 * that script's to set and to drop.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import { parse } from "yaml";

const USAGE =
  "Usage: ReleaseSbom.mjs <package-dir> <out.cdx.json> [library|application] [--packed <tarball>...]";
const positional = [];
const packedTarballs = [];
const argv = process.argv.slice(2);
for (let index = 0; index < argv.length; index += 1) {
  if (argv[index] === "--packed") {
    index += 1;
    if (argv[index] === undefined) throw new Error(USAGE);
    packedTarballs.push(argv[index]);
  } else {
    positional.push(argv[index]);
  }
}
const [packageDirArgument, outPath, rootType = "library"] = positional;
if (!packageDirArgument || !outPath || !["library", "application"].includes(rootType)) {
  throw new Error(USAGE);
}

/** The repository root: where the workspace file is, walking up from the package. */
function workspaceRoot(from) {
  let directory = resolve(from);
  for (;;) {
    if (existsSync(join(directory, "pnpm-workspace.yaml"))) return directory;
    const parent = dirname(directory);
    if (parent === directory) throw new Error("no pnpm-workspace.yaml above the package");
    directory = parent;
  }
}

const packageDir = realpathSync(resolve(packageDirArgument));
const root = workspaceRoot(packageDir);
const lock = parse(readFileSync(join(root, "pnpm-lock.yaml"), "utf8"));
if (String(lock.lockfileVersion) !== "9.0") {
  throw new Error(`pnpm-lock.yaml is lockfile version ${String(lock.lockfileVersion)}, not 9.0`);
}
/** A package pnpm fetched lives in a virtual store, `node_modules/.pnpm/<name>@<version>/…`. */
const STORE_SEGMENT = `${sep}node_modules${sep}.pnpm${sep}`;

const manifestOf = (directory) => JSON.parse(readFileSync(join(directory, "package.json"), "utf8"));

/** What a tarball says it is, and its digest: the word a release's SBOM gives for a package it ships. */
function packedOf(tarballPath) {
  const path = resolve(tarballPath);
  const manifest = JSON.parse(
    execFileSync(
      "tar",
      ["--extract", "--gzip", "--to-stdout", "--file", path, "package/package.json"],
      {
        encoding: "utf8",
      },
    ),
  );
  return {
    name: manifest.name,
    version: manifest.version,
    sha512: createHash("sha512").update(readFileSync(path)).digest("hex"),
  };
}
const packed = new Map(
  packedTarballs.map(packedOf).map((entry) => [`${entry.name}@${entry.version}`, entry]),
);

function purlOf(name, version) {
  const [scope, bare] = name.startsWith("@") ? name.split("/") : [null, name];
  return scope === null
    ? `pkg:npm/${bare}@${version}`
    : `pkg:npm/${encodeURIComponent(scope)}/${bare}@${version}`;
}

function personOf(value) {
  if (typeof value === "string") return value;
  if (typeof value !== "object" || value === null || typeof value.name !== "string") return null;
  return value.email ? `${value.name} <${value.email}>` : value.name;
}

function urlOf(value) {
  if (typeof value === "string") return value;
  return typeof value === "object" && value !== null && typeof value.url === "string"
    ? value.url
    : null;
}

function licensesOf(license) {
  if (typeof license !== "string" || license === "") return [];
  return /\s(?:AND|OR|WITH)\s/.test(license) || license.startsWith("(")
    ? [{ expression: license }]
    : [{ license: { id: license } }];
}

/** A component from an installed package: its manifest, and the lockfile's word on its tarball. */
function componentOf(name, manifest, directory, type) {
  const version = manifest.version;
  const references = [];
  const registry = directory.includes(STORE_SEGMENT);
  const shipped = packed.get(`${name}@${version}`);
  const locked = registry ? lock.packages?.[`${name}@${version}`] : undefined;
  if (registry || shipped !== undefined) {
    const tarball =
      locked?.resolution?.tarball ??
      `https://registry.npmjs.org/${name}/-/${name.split("/").pop()}-${version}.tgz`;
    references.push({ type: "distribution", url: tarball });
  }
  const vcs = urlOf(manifest.repository);
  if (vcs !== null) references.push({ type: "vcs", url: vcs });
  if (typeof manifest.homepage === "string") {
    references.push({ type: "website", url: manifest.homepage });
  }
  const bugs = urlOf(manifest.bugs);
  if (bugs !== null) references.push({ type: "issue-tracker", url: bugs });
  const author = personOf(manifest.author);
  const integrity = locked?.resolution?.integrity;
  if (registry && typeof integrity !== "string") {
    throw new Error(`pnpm-lock.yaml holds no integrity for ${name}@${version}`);
  }
  let hashes = [];
  if (typeof integrity === "string" && integrity.startsWith("sha512-")) {
    hashes = [
      { alg: "SHA-512", content: Buffer.from(integrity.slice(7), "base64").toString("hex") },
    ];
  } else if (shipped !== undefined) {
    hashes = [{ alg: "SHA-512", content: shipped.sha512 }];
  }
  return {
    "bom-ref": `${name}@${version}`,
    type,
    name,
    version,
    scope: "required",
    ...(author === null ? {} : { author }),
    ...(typeof manifest.description === "string" ? { description: manifest.description } : {}),
    purl: purlOf(name, version),
    properties: [],
    externalReferences: references,
    ...(hashes.length === 0 ? {} : { hashes }),
    licenses: licensesOf(manifest.license),
  };
}

const components = new Map();
const edges = new Map();

/**
 * Where Node would find `dependency` from a module in `directory`: the nearest
 * `node_modules/<dependency>` on the way up, skipping directories that are
 * themselves `node_modules`, as the resolver does. In pnpm's layout that is
 * the package's own `node_modules` for what it declares and the virtual
 * store's for the rest.
 */
function locate(directory, dependency) {
  for (let current = directory; ; current = dirname(current)) {
    if (basename(current) !== "node_modules") {
      const candidate = join(current, "node_modules", dependency);
      if (existsSync(candidate)) return realpathSync(candidate);
    }
    if (dirname(current) === current) return null;
  }
}

/** Walks the installed production tree the way Node resolves it. */
function visit(name, directory, manifest, type) {
  const ref = `${name}@${manifest.version}`;
  if (components.has(ref)) return ref;
  components.set(ref, componentOf(name, manifest, directory, type));
  const dependsOn = new Set();
  edges.set(ref, dependsOn);
  const declared = {
    ...(manifest.dependencies ?? {}),
    ...(manifest.optionalDependencies ?? {}),
  };
  for (const dependency of Object.keys(declared).sort()) {
    const real = locate(directory, dependency);
    if (real === null) {
      if (manifest.optionalDependencies?.[dependency] !== undefined) continue;
      throw new Error(`${ref} depends on ${dependency}, which is not installed where it resolves`);
    }
    dependsOn.add(visit(dependency, real, manifestOf(real), "library"));
  }
  return ref;
}

const rootManifest = manifestOf(packageDir);
const rootRef = visit(rootManifest.name, packageDir, rootManifest, rootType);
const rootComponent = components.get(rootRef);
components.delete(rootRef);
const graph = (ref) => ({ ref, dependsOn: [...(edges.get(ref) ?? [])].sort() });
const sorted = [...components.keys()].sort();
const sbom = {
  $schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: "urn:uuid:00000000-0000-5000-8000-000000000000",
  version: 1,
  metadata: {
    lifecycles: [{ phase: "build" }],
    tools: [
      {
        vendor: "decionis",
        name: "ReleaseSbom.mjs",
        version: manifestOf(root).version,
      },
    ],
    component: rootComponent,
  },
  components: sorted.map((ref) => components.get(ref)),
  dependencies: [graph(rootRef), ...sorted.map(graph)],
};
writeFileSync(outPath, `${JSON.stringify(sbom, null, 2)}\n`);
for (const ref of packed.keys()) {
  if (!components.has(ref))
    throw new Error(`${ref} was packed but is not in the tree of ${rootRef}`);
}
const hashed = sorted.filter((ref) => components.get(ref).hashes !== undefined).length;
process.stdout.write(
  `Wrote the SBOM of ${rootRef} from the lockfile's tree: ${String(sorted.length)} components, ${String(hashed)} with a tarball's hash.\n`,
);
