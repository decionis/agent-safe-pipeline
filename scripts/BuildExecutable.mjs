/**
 * Builds the runtime as one self-contained executable: the CLI and every
 * dependency bundled to CommonJS and injected into an official Node
 * release binary as a Node single executable application. The result needs
 * no Node on the host and is what the Linux packages, the installer and the
 * Homebrew formula distribute. It is the same code the npm package and the
 * image run; nothing about authority, binding, claim or finalization is
 * different in it.
 *
 *   node scripts/BuildExecutable.mjs [--out <dir>] [--target <os>-<arch>] [--layout sea|launcher]
 *
 * Runs after `pnpm build`. The Node binary is the release `node.json` pins,
 * downloaded from nodejs.org and refused unless its SHA-256 is the pinned
 * one: the executable is built from a known Node, never from whichever one
 * happens to run this script (a Node built with a shared library, as
 * Homebrew's is, cannot carry an application at all). The target is this
 * machine's unless named; a cross-target build injects into the other
 * platform's binary, which is valid because the blob is platform-neutral,
 * and cannot be run here. The bundle is written beside the executable so a
 * release can attach it for inspection.
 *
 * Two layouts. `sea` is one file, the application inside the Node binary.
 * `launcher`, the default for darwin-x64 where Node does not support single
 * executables, is three files that ship together: the same bundle, the same
 * pinned Node beside it, and an `agentsafe` shell launcher that runs one on
 * the other. Either way what the installer, the formula and the packages
 * distribute is the directory the archive holds, and `agentsafe` inside it.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const argument = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};
const out = resolve(argument("--out") ?? join(root, "packaging", "sea", "out"));
const target =
  argument("--target") ?? `${process.platform}-${process.arch === "x64" ? "x64" : process.arch}`;
const [targetOs] = target.split("-");
/** Node has no single-executable support on x64 macOS; that target ships the launcher layout. */
const layout = argument("--layout") ?? (target === "darwin-x64" ? "launcher" : "sea");
if (layout !== "sea" && layout !== "launcher") throw new Error(`unknown layout ${layout}`);
const pinned = JSON.parse(readFileSync(join(root, "packaging/sea/node.json"), "utf8"));
const runtimeManifest = JSON.parse(
  readFileSync(join(root, "packages/agentsafe/package.json"), "utf8"),
);
const pipelineManifest = JSON.parse(
  readFileSync(join(root, "packages/pipeline/package.json"), "utf8"),
);
const entry = join(root, "packages/agentsafe/dist/Cli.js");
const bundle = join(out, "agentsafe.cjs");
const blob = join(out, "sea-prep.blob");
const executable = join(out, "agentsafe");
/** The fuse string Node documents for `postject`; it marks where the blob goes. */
const SEA_FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
const NODE_ARCHIVE_PATTERN = /^node-v\d+\.\d+\.\d+-(?:darwin|linux)-(?:x64|arm64)\.tar\.gz$/;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited with ${result.status ?? result.signal}`);
  }
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** The pinned Node binary for a target, downloaded once into the cache and verified every time. */
async function nodeBinary(forTarget) {
  const [forOs, forArch] = forTarget.split("-");
  const expected = pinned.sha256[forTarget];
  if (typeof expected !== "string") throw new Error(`no pinned Node for ${forTarget}`);
  const archiveName = `node-v${pinned.version}-${forOs}-${forArch}.tar.gz`;
  if (!NODE_ARCHIVE_PATTERN.test(archiveName))
    throw new Error(`unexpected archive name ${archiveName}`);
  const cache = join(root, "packaging", "sea", "cache");
  mkdirSync(cache, { recursive: true });
  const archive = join(cache, archiveName);
  if (!existsSync(archive) || sha256(archive) !== expected) {
    const url = `${pinned.base}/v${pinned.version}/${archiveName}`;
    process.stdout.write(`downloading ${url}\n`);
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url}: ${response.status}`);
    writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
  }
  const actual = sha256(archive);
  if (actual !== expected) {
    throw new Error(
      `${archiveName}: SHA-256 ${actual} is not the pinned ${expected}; refusing to build from it`,
    );
  }
  const extracted = join(cache, `node-v${pinned.version}-${forOs}-${forArch}`);
  if (!existsSync(join(extracted, "bin", "node"))) {
    run("tar", [
      "-xzf",
      archive,
      "-C",
      cache,
      `node-v${pinned.version}-${forOs}-${forArch}/bin/node`,
    ]);
  }
  return join(extracted, "bin", "node");
}

const hostTarget = `${process.platform}-${process.arch === "x64" ? "x64" : process.arch}`;
const native = target === hostTarget;

mkdirSync(out, { recursive: true });
statSync(entry);

// 1. One CommonJS bundle. Every workspace and third-party module is inlined;
//    Node's own modules stay external. Licence comments are kept at the end
//    of the file, because the bundle ships.
const esbuild = require("esbuild");
await esbuild.build({
  entryPoints: [entry],
  bundle: true,
  platform: "node",
  target: "node22",
  format: "cjs",
  outfile: bundle,
  legalComments: "eof",
  minify: false,
  sourcemap: false,
  logLevel: "warning",
  define: {
    __AGENTSAFE_VERSION__: JSON.stringify(runtimeManifest.version),
    __AGENT_SAFE_PIPELINE_VERSION__: JSON.stringify(pipelineManifest.version),
    "import.meta.url": JSON.stringify("file:///agentsafe/bundle"),
  },
});

const hostNode = await nodeBinary(hostTarget);
if (layout === "launcher") {
  // The pinned Node beside the bundle, and a launcher that runs one on the
  // other from wherever the directory ends up, symlinks resolved.
  copyFileSync(native ? hostNode : await nodeBinary(target), join(out, "node"));
  chmodSync(join(out, "node"), 0o755);
  writeFileSync(
    executable,
    [
      "#!/bin/sh",
      "# AgentSafe: the bundled runtime on the Node release shipped beside it.",
      'self="$0"',
      'while [ -L "$self" ]; do',
      '  dir="$(cd "$(dirname "$self")" && pwd)"',
      '  self="$(readlink "$self")"',
      '  case "$self" in /*) ;; *) self="$dir/$self" ;; esac',
      "done",
      'dir="$(cd "$(dirname "$self")" && pwd)"',
      'exec "$dir/node" "$dir/agentsafe.cjs" "$@"',
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
} else {
  // 2. The blob, from the bundle, generated by the pinned Node itself: a blob
  //    is specific to the Node version that reads it, so the one that runs
  //    this script cannot make it. The experimental-feature warning is off:
  //    the feature is the packaging, and the operator did not choose it.
  writeFileSync(
    join(out, "sea-config.json"),
    JSON.stringify(
      {
        main: bundle,
        output: blob,
        disableExperimentalSEAWarning: true,
        useCodeCache: false,
        useSnapshot: false,
      },
      null,
      2,
    ),
  );
  run(hostNode, ["--experimental-sea-config", join(out, "sea-config.json")]);

  // 3. A copy of the pinned Node, unsigned on macOS so it can be edited,
  //    injected, then signed ad hoc so the kernel loads it again.
  copyFileSync(native ? hostNode : await nodeBinary(target), executable);
  chmodSync(executable, 0o755);
  if (targetOs === "darwin" && process.platform === "darwin")
    run("codesign", ["--remove-signature", executable]);
  run(process.execPath, [
    require.resolve("postject/dist/cli.js"),
    executable,
    "NODE_SEA_BLOB",
    blob,
    "--sentinel-fuse",
    SEA_FUSE,
    ...(targetOs === "darwin" ? ["--macho-segment-name", "NODE_SEA"] : []),
  ]);
  if (targetOs === "darwin" && process.platform === "darwin")
    run("codesign", ["--sign", "-", executable]);
}

// 4. When it can run here, it runs, and says the version the manifest says.
if (native) {
  const version = spawnSync(executable, ["version"], { encoding: "utf8" });
  if (version.status !== 0 || version.stdout.trim() !== runtimeManifest.version) {
    throw new Error(
      `the executable did not report ${runtimeManifest.version}: ${version.stdout}${version.stderr}`,
    );
  }
}
process.stdout.write(
  `${JSON.stringify({
    executable,
    target,
    layout,
    version: runtimeManifest.version,
    node: pinned.version,
    verified: native,
    bytes: statSync(executable).size,
    bundleBytes: statSync(bundle).size,
  })}\n`,
);
