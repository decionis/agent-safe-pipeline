/**
 * Writes the published JSON Schemas of the profile definitions from the
 * pipeline's own validators, so the document a third party validates against
 * and the validators this package runs are one definition:
 *
 * - spec/profiles/api/v1/schema.json, `agent-safe.profile.api/1`;
 * - spec/profiles/mcp/v1/schema.json, `agent-safe.profile.mcp/1`.
 *
 * `--check` compares instead of writing and exits 1 on a difference; the
 * pipeline's tests do the same on every run.
 *
 *   pnpm --filter @decionis/agent-safe-pipeline build
 *   node scripts/GenerateProfileSchema.mjs [--check]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { apiProfileJsonSchema, mcpProfileJsonSchema } from "../packages/pipeline/dist/Index.js";

const SCHEMAS = [
  ["spec/profiles/api/v1/schema.json", apiProfileJsonSchema],
  ["spec/profiles/mcp/v1/schema.json", mcpProfileJsonSchema],
];

let differs = false;
for (const [relative, generate] of SCHEMAS) {
  const path = fileURLToPath(new URL(`../${relative}`, import.meta.url));
  // The document as it is written: two-space JSON and one trailing newline.
  const rendered = `${JSON.stringify(generate(), null, 2)}\n`;
  if (process.argv.includes("--check")) {
    let current = null;
    try {
      current = readFileSync(path, "utf8");
    } catch {
      current = null;
    }
    if (current !== rendered) {
      process.stderr.write(
        `${relative} differs from the pipeline's profile schema; run node scripts/GenerateProfileSchema.mjs\n`,
      );
      differs = true;
    } else {
      process.stdout.write(`${relative} is current\n`);
    }
  } else {
    writeFileSync(path, rendered, "utf8");
    process.stdout.write(`wrote ${path}\n`);
  }
}
if (differs) process.exit(1);
