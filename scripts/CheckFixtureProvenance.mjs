import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const git = spawnSync(
  "git",
  [
    "ls-files",
    "-z",
    "conformance/*.json",
    "policies/*.json",
    "examples/*/src/*.ts",
    "packages/pipeline/test/*.ts",
    "packages/pipeline/test/**/*.ts",
  ],
  { encoding: "utf8" },
);
if (git.status !== 0) process.exit(git.status ?? 1);

const fixtureFiles = [...new Set(git.stdout.split("\0").filter(Boolean))].sort();
if (fixtureFiles.length < 10) throw new Error("Fixture-family discovery returned too few files");

const manifest = JSON.parse(await readFile("fixtures/manifest.json", "utf8"));
const manifestFiles = manifest.fixtures?.map(({ path }) => path).sort() ?? [];
if (manifest.schemaVersion !== 1) throw new Error("Unsupported fixture manifest schema");
if (manifest.owner?.contact !== "security@decionis.com") {
  throw new Error("Fixture manifest must name security@decionis.com as data/security owner");
}
if (manifest.brandOwner !== "Decionis Inc.") {
  throw new Error("Fixture manifest must name Decionis Inc. as brand owner");
}
if (manifest.license !== "Apache-2.0") {
  throw new Error("Fixture manifest must declare Apache-2.0");
}
if (new Set(manifestFiles).size !== manifestFiles.length) {
  throw new Error("Fixture manifest contains duplicate paths");
}
if (JSON.stringify(manifestFiles) !== JSON.stringify(fixtureFiles)) {
  const declared = new Set(manifestFiles);
  const discovered = new Set(fixtureFiles);
  const missing = fixtureFiles.filter((path) => !declared.has(path));
  const stale = manifestFiles.filter((path) => !discovered.has(path));
  throw new Error(
    `Fixture manifest differs from Git discovery (missing: ${missing.join(", ") || "none"}; stale: ${stale.join(", ") || "none"})`,
  );
}
for (const fixture of manifest.fixtures) {
  if (fixture.source !== "synthetic" || fixture.containsCustomerData !== false) {
    throw new Error(`${fixture.path}: fixture manifest must attest synthetic, non-customer data`);
  }
}

const syntheticIdentity = /^(?:synthetic-|fixture_)/;
const reservedFixtureUuid =
  /^(?:00000000-0000-4000-8000-00000000000[1-9]|11111111-1111-4111-8111-111111111111)$/;
const identityPatterns = [
  /actor:\s*\{\s*id:\s*["']([^"']+)["']/g,
  /\b(?:customerId|orderId|request_id|receipt_dossier_id):\s*["']([^"']+)["']/g,
  /["']([^"'\n]*approver[^"'\n]*)["']/g,
];
const tenantPatterns = [
  /\btenantId:\s*["']([^"']+)["']/g,
  /["']tenant_id["']:\s*["']([^"']+)["']/g,
];
const failures = [];

for (const path of fixtureFiles) {
  const text = await readFile(path, "utf8");
  for (const pattern of identityPatterns) {
    for (const match of text.matchAll(pattern)) {
      if (!syntheticIdentity.test(match[1])) {
        failures.push(`${path}: fixture identity must use synthetic-/fixture_ prefix: ${match[1]}`);
      }
    }
  }
  for (const pattern of tenantPatterns) {
    for (const match of text.matchAll(pattern)) {
      if (!reservedFixtureUuid.test(match[1])) {
        failures.push(
          `${path}: tenant fixture must use the reserved fixture UUID block: ${match[1]}`,
        );
      }
    }
  }

  if (path.startsWith("examples/") && /20\d\d-\d\d-\d\dT/.test(text)) {
    failures.push(`${path}: executable demos must derive timestamps at read time`);
  }
  for (const match of text.matchAll(/https?:\/\/([^/"'\s]+)/g)) {
    const hostname = new URL(match[0]).hostname;
    if (
      hostname !== "localhost" &&
      hostname !== "127.0.0.1" &&
      hostname !== "example.com" &&
      !hostname.endsWith(".example") &&
      !hostname.endsWith(".invalid")
    ) {
      failures.push(`${path}: fixture URL must use a reserved domain or loopback: ${hostname}`);
    }
  }
}

const conformance = JSON.parse(await readFile("conformance/agent-safe-intent-v1.json", "utf8"));
if (!reservedFixtureUuid.test(conformance.binding.tenant_id)) {
  failures.push("conformance vector tenant_id is outside the reserved fixture UUID block");
}
if (!syntheticIdentity.test(conformance.binding.actor.id)) {
  failures.push("conformance vector actor.id must use the synthetic- prefix");
}

if (failures.length > 0) throw new Error(failures.join("\n"));
process.stdout.write(
  `Verified ${fixtureFiles.length} manifested fixture-bearing files use reserved synthetic identities and domains.\n`,
);
