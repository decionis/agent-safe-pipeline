#!/usr/bin/env node
/**
 * Refresh the vendored CommerceGate OpenAPI contract from its canonical
 * public location. The drift tests pin this package's client routes,
 * request shapes and response projections to the vendored copy, so a
 * contract change on commerce.decionis.com is picked up by re-running
 * this script and reviewing the diff, never by tests reaching the network.
 *
 *   node scripts/SyncContract.mjs          # write contract/CommerceGateOpenApi.json
 *   node scripts/SyncContract.mjs --check  # exit 1 if the vendored copy differs
 */
import { readFile, writeFile } from "node:fs/promises";

const CONTRACT_URL = "https://commerce.decionis.com/.well-known/openapi.json";
const target = new URL("../contract/CommerceGateOpenApi.json", import.meta.url);
const check = process.argv.includes("--check");

const response = await fetch(CONTRACT_URL, {
  headers: { accept: "application/json", "user-agent": "decionis-commerce-mcp-contract-sync" },
  signal: AbortSignal.timeout(15_000),
});
if (!response.ok) {
  throw new Error(`${CONTRACT_URL} returned HTTP ${response.status}`);
}
const live = `${JSON.stringify(await response.json(), null, 2)}\n`;

if (check) {
  const vendored = await readFile(target, "utf8");
  if (vendored !== live) {
    console.error(
      "contract/CommerceGateOpenApi.json differs from the published contract; run scripts/SyncContract.mjs and review the diff.",
    );
    process.exit(1);
  }
  console.log("Vendored CommerceGate OpenAPI contract matches the published contract.");
} else {
  await writeFile(target, live);
  console.log(`Wrote ${target.pathname}`);
}
