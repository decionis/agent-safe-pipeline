/**
 * Writes the published JSON Schema of the `agent-safe.intent/1` binding,
 * spec/intent/v1/schema.json, from the pipeline's own strict schema, so the
 * document a third party validates against and the validator this package
 * runs are one definition. `--check` compares instead of writing and exits 1
 * on a difference; the pipeline's tests do the same on every run.
 *
 *   pnpm --filter @decionis/agent-safe-pipeline build
 *   node scripts/GenerateIntentSchema.mjs [--check]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { intentBindingJsonSchema } from "../packages/pipeline/dist/Index.js";

export const SCHEMA_PATH = fileURLToPath(new URL("../spec/intent/v1/schema.json", import.meta.url));

/** The document as it is written: two-space JSON and one trailing newline. */
export function renderIntentSchema() {
  return `${JSON.stringify(intentBindingJsonSchema(), null, 2)}\n`;
}

const rendered = renderIntentSchema();
if (process.argv.includes("--check")) {
  let current = null;
  try {
    current = readFileSync(SCHEMA_PATH, "utf8");
  } catch {
    current = null;
  }
  if (current !== rendered) {
    process.stderr.write(
      `spec/intent/v1/schema.json differs from the pipeline's schema; run node scripts/GenerateIntentSchema.mjs\n`,
    );
    process.exit(1);
  }
  process.stdout.write("spec/intent/v1/schema.json is current\n");
} else {
  writeFileSync(SCHEMA_PATH, rendered, "utf8");
  process.stdout.write(`wrote ${SCHEMA_PATH}\n`);
}
