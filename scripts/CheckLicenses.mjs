import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const APACHE_2_CANONICAL_SHA256 =
  "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const policy = JSON.parse(await readFile("license-policy.json", "utf8"));
const inventory = spawnSync(pnpm, ["licenses", "list", "--json"], { encoding: "utf8" });

if (inventory.status !== 0) {
  process.stderr.write(inventory.stderr);
  process.exit(inventory.status ?? 1);
}

const dependenciesByLicense = JSON.parse(inventory.stdout);
const allowedLicenses = new Set(Object.keys(policy.allowedLicenses));
const exceptions = policy.packageExceptions ?? [];
const githubExceptions = policy.githubPackageExceptions ?? [];

for (const [license, justification] of Object.entries(policy.allowedLicenses)) {
  if (typeof justification !== "string" || justification.trim().length < 20) {
    throw new Error(`Allowed license ${license} requires a written justification`);
  }
}

for (const [license, packages] of Object.entries(dependenciesByLicense)) {
  if (allowedLicenses.has(license)) continue;
  const unreviewed = packages.filter(
    (dependency) =>
      !exceptions.some(
        (exception) =>
          exception.package === dependency.name &&
          exception.license === license &&
          typeof exception.justification === "string" &&
          exception.justification.trim().length >= 20,
      ),
  );
  if (unreviewed.length > 0) {
    throw new Error(
      `Unreviewed dependency license ${license}: ${unreviewed.map(({ name }) => name).join(", ")}`,
    );
  }
}

for (const exception of exceptions) {
  if (
    typeof exception.package !== "string" ||
    typeof exception.license !== "string" ||
    typeof exception.justification !== "string" ||
    exception.justification.trim().length < 20
  ) {
    throw new Error(
      "Every package-scoped license exception requires package, license, and justification",
    );
  }
  if (
    !dependenciesByLicense[exception.license]?.some(
      (dependency) => dependency.name === exception.package,
    )
  ) {
    throw new Error(`Stale license exception: ${exception.package} (${exception.license})`);
  }
}

for (const exception of githubExceptions) {
  if (
    typeof exception.package !== "string" ||
    typeof exception.license !== "string" ||
    typeof exception.justification !== "string" ||
    exception.justification.trim().length < 20
  ) {
    throw new Error(
      "Every GitHub package-scoped license exception requires package, license, and justification",
    );
  }
}

const supplyChainWorkflow = await readFile(".github/workflows/supply-chain.yml", "utf8");
for (const exception of [...exceptions, ...githubExceptions]) {
  const purl = `pkg:npm/${exception.package}`;
  if (supplyChainWorkflow.split(purl).length - 1 < 2) {
    throw new Error(`Both dependency-review passes must declare the exception ${purl}`);
  }
}

const repositoryLicense = await readFile("LICENSE", "utf8");
const packageLicense = await readFile("packages/pipeline/LICENSE", "utf8");
const repositoryNotice = await readFile("NOTICE", "utf8");
const packageNotice = await readFile("packages/pipeline/NOTICE", "utf8");
const licenseDigest = createHash("sha256").update(repositoryLicense).digest("hex");

if (licenseDigest !== APACHE_2_CANONICAL_SHA256) {
  throw new Error(
    `LICENSE must be the canonical Apache-2.0 text (expected SHA-256 ${APACHE_2_CANONICAL_SHA256})`,
  );
}
if (packageLicense !== repositoryLicense) {
  throw new Error("packages/pipeline/LICENSE must match the canonical repository LICENSE");
}
if (packageNotice !== repositoryNotice) {
  throw new Error("packages/pipeline/NOTICE must match the repository NOTICE");
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

  if (path === "package.json" || path === "packages/pipeline/package.json") {
    for (const field of ["author", "bugs", "description", "homepage", "repository"]) {
      if (manifest[field] === undefined || manifest[field] === null || manifest[field] === "") {
        throw new Error(`${path} must declare ${field}`);
      }
    }
  }

  if (path === "packages/pipeline/package.json") {
    for (const requiredFile of ["LICENSE", "NOTICE"]) {
      if (!Array.isArray(manifest.files) || !manifest.files.includes(requiredFile)) {
        throw new Error(`packages/pipeline/package.json must publish ${requiredFile}`);
      }
    }
  }
}

const repositoryManifest = JSON.parse(await readFile("package.json", "utf8"));
const packageManifest = JSON.parse(await readFile("packages/pipeline/package.json", "utf8"));
const presenceManifest = JSON.parse(
  await readFile("packages/pipeline/node_modules/@decionis/presence-node/package.json", "utf8"),
);
if (
  repositoryManifest.engines?.node !== packageManifest.engines?.node ||
  packageManifest.engines?.node !== presenceManifest.engines?.node
) {
  throw new Error(
    "Workspace and package Node.js engines must match the strictest production dependency",
  );
}

process.stdout.write("Canonical Apache-2.0 metadata and dependency licenses satisfy policy.\n");
