import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const APACHE_2_CANONICAL_SHA256 =
  "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
const COMMERCEGATE_EXTENSION_MIT_SHA256 =
  "cbc49796baa849d838099985b54644fd837896b2554825bd540559f0816209b9";
const REPOSITORY_NOTICE_SHA256 = "a30e1a182522a04ad586c296730a588f310ab5f0f5ba914bc148f3486cd015e6";
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const policy = JSON.parse(await readFile("license-policy.json", "utf8"));
const inventory = spawnSync(pnpm, ["licenses", "list", "--json"], {
  encoding: "utf8",
  env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" },
  maxBuffer: 16 * 1024 * 1024,
});

if (inventory.status !== 0) {
  const details = [
    inventory.error?.stack,
    inventory.stderr?.trim(),
    inventory.stdout?.trim(),
    inventory.signal ? `terminated by signal ${inventory.signal}` : undefined,
  ].filter(Boolean);
  throw new Error(
    `pnpm license inventory failed with status ${inventory.status ?? "unknown"}${details.length > 0 ? `:\n${details.join("\n")}` : " without diagnostic output"}`,
  );
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
const commercePackageLicense = await readFile("packages/commerce-mcp/LICENSE", "utf8");
const commercePackageManifest = JSON.parse(
  await readFile("packages/commerce-mcp/package.json", "utf8"),
);
const extensionLicense = await readFile("packages/commerce-mcp-claude-extension/LICENSE", "utf8");
const extensionManifest = JSON.parse(
  await readFile("packages/commerce-mcp-claude-extension/package.json", "utf8"),
);
const extensionNotices = await readFile(
  "packages/commerce-mcp-claude-extension/THIRD_PARTY_NOTICES.md",
  "utf8",
);
const licenseDigest = createHash("sha256").update(repositoryLicense).digest("hex");
const noticeDigest = createHash("sha256").update(repositoryNotice).digest("hex");
const extensionLicenseDigest = createHash("sha256").update(extensionLicense).digest("hex");

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
if (noticeDigest !== REPOSITORY_NOTICE_SHA256) {
  throw new Error(
    `NOTICE drifted from the reviewed attribution text (expected SHA-256 ${REPOSITORY_NOTICE_SHA256})`,
  );
}
if (
  commercePackageManifest.license !== "Apache-2.0" ||
  commercePackageLicense !== repositoryLicense.slice(1)
) {
  throw new Error("packages/commerce-mcp must retain the canonical Apache-2.0 license");
}
if (
  extensionManifest.license !== "MIT" ||
  extensionLicenseDigest !== COMMERCEGATE_EXTENSION_MIT_SHA256
) {
  throw new Error("packages/commerce-mcp-claude-extension must retain its canonical MIT license");
}
if (
  extensionManifest.devDependencies?.["@decionis/commerce"] !==
  `workspace:${commercePackageManifest.version}`
) {
  throw new Error(
    "Claude extension must pin the Apache CommerceGate runtime as a build dependency",
  );
}
for (const requiredAttribution of [
  "runtime remains licensed under Apache License 2.0",
  "vendor/commerce-mcp/LICENSE",
  "vendor/commerce-mcp/NOTICE",
  "vendor/commerce-mcp/package.json",
]) {
  if (!extensionNotices.includes(requiredAttribution)) {
    throw new Error(`Claude extension third-party notice is missing: ${requiredAttribution}`);
  }
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
