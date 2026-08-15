import { readFile, readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const allowedDependencyLicenses = new Set([
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "BlueOak-1.0.0",
  "ISC",
  "MIT",
  "Python-2.0",
]);
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const inventory = spawnSync(pnpm, ["licenses", "list", "--json"], {
  encoding: "utf8",
});

if (inventory.status !== 0) {
  process.stderr.write(inventory.stderr);
  process.exit(inventory.status ?? 1);
}

const licenses = Object.keys(JSON.parse(inventory.stdout));
const unsupported = licenses.filter((license) => !allowedDependencyLicenses.has(license));
if (unsupported.length > 0) {
  throw new Error(`Unreviewed workspace dependency licenses: ${unsupported.join(", ")}`);
}

const repositoryLicense = await readFile("LICENSE", "utf8");
const packageLicense = await readFile("packages/pipeline/LICENSE", "utf8");
const apacheLicenseMarkers = [
  "Apache License",
  "Version 2.0, January 2004",
  "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
  "END OF TERMS AND CONDITIONS",
  'Licensed under the Apache License, Version 2.0 (the "License")',
];

for (const marker of apacheLicenseMarkers) {
  if (!repositoryLicense.includes(marker)) {
    throw new Error(`LICENSE is not the complete Apache-2.0 license: missing ${marker}`);
  }
}

if (packageLicense !== repositoryLicense) {
  throw new Error("packages/pipeline/LICENSE must match the repository Apache-2.0 license");
}

const exampleManifests = (await readdir("examples", { withFileTypes: true }))
  .filter((entry) => entry.isDirectory())
  .map((entry) => `examples/${entry.name}/package.json`);
const manifests = ["package.json", "packages/pipeline/package.json", ...exampleManifests];

for (const path of manifests) {
  const manifest = JSON.parse(await readFile(path, "utf8"));
  if (manifest.license !== "Apache-2.0") {
    throw new Error(`${path} must declare Apache-2.0`);
  }

  if (
    path === "packages/pipeline/package.json" &&
    (!Array.isArray(manifest.files) || !manifest.files.includes("LICENSE"))
  ) {
    throw new Error("packages/pipeline/package.json must include LICENSE in published files");
  }
}

process.stdout.write("License metadata and workspace dependencies satisfy the allowlist.\n");
