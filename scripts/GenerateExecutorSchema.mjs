/**
 * Writes the published JSON Schema of the `agent-safe.executors.native/1`
 * wire objects, spec/executors/native/v1/schema.json, from the pipeline's own
 * validators, so the document a third party validates against and the
 * validators this package runs are one definition. `--check` compares instead
 * of writing and exits 1 on a difference; the pipeline's tests do the same on
 * every run.
 *
 *   pnpm --filter @decionis/agent-safe-pipeline build
 *   node scripts/GenerateExecutorSchema.mjs [--check]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { nativeExecutorJsonSchema } from "../packages/pipeline/dist/Index.js";

export const SCHEMA_PATH = fileURLToPath(
  new URL("../spec/executors/native/v1/schema.json", import.meta.url),
);

/** The document as it is written: two-space JSON and one trailing newline. */
export function renderExecutorSchema() {
  return `${JSON.stringify(nativeExecutorJsonSchema(), null, 2)}\n`;
}

const rendered = renderExecutorSchema();
if (process.argv.includes("--check")) {
  let current = null;
  try {
    current = readFileSync(SCHEMA_PATH, "utf8");
  } catch {
    current = null;
  }
  if (current !== rendered) {
    process.stderr.write(
      `spec/executors/native/v1/schema.json differs from the pipeline's schema; run node scripts/GenerateExecutorSchema.mjs\n`,
    );
    process.exit(1);
  }
  process.stdout.write("spec/executors/native/v1/schema.json is current\n");
} else {
  writeFileSync(SCHEMA_PATH, rendered, "utf8");
  process.stdout.write(`wrote ${SCHEMA_PATH}\n`);
}
