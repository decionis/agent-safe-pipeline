import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import canonical from "../../contract/CommercePreflight.v1.json" with { type: "json" };
import {
  COMMERCE_CHECK_IDS,
  COMMERCE_PREFLIGHT_CHECKS,
  COMMERCE_PREFLIGHT_VERSION,
} from "../../src/preflight/Contracts.js";
import {
  commerceCheckResultSchema,
  commercePreflightFactsSchema,
  commercePreflightInputSchema,
  commercePreflightResultSchema,
  type PreflightJsonSchema,
} from "../../src/preflight/Schema.js";
import { SUPPORTED_ACTION_TYPES } from "../../src/CommerceGateClient.js";

describe("generated preflight contract projection", () => {
  it("uses the exact server schemas, source provenance and eleven-check catalog", async () => {
    const openApi = JSON.parse(
      await readFile(new URL("../../contract/CommerceGateOpenApi.json", import.meta.url), "utf8"),
    );
    const { schemas, ...catalog } = canonical;
    expect(openApi["x-commerce-preflight"]).toEqual(catalog);
    expect(catalog).toMatchObject({
      release_status: "source_candidate",
      opt_in: true,
      policy_authority: "server",
      execution_available: false,
    });
    expect(catalog.source_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(catalog.supported_action_types).toEqual(SUPPORTED_ACTION_TYPES);
    expect(catalog.version).toBe(COMMERCE_PREFLIGHT_VERSION);
    expect(catalog.checks).toEqual(COMMERCE_PREFLIGHT_CHECKS);
    expect(catalog.checks.map((check) => check.id)).toEqual(COMMERCE_CHECK_IDS);
    for (const [name, schema] of Object.entries(schemas)) {
      expect(openApi.components.schemas[name], name).toEqual(schema);
    }
    expect(commercePreflightInputSchema).toEqual(schemas.CommercePreflightInput);
    expect(commercePreflightFactsSchema).toEqual(schemas.CommercePreflightFacts);
    expect(commercePreflightResultSchema).toEqual(schemas.CommercePreflightResult);
    expect(commerceCheckResultSchema).toEqual(schemas.CommerceCheckResult);
    expect(
      openApi.components.schemas.CommerceEvaluationRequest.properties.context.properties
        .commerce_preflight.$ref,
    ).toBe("#/components/schemas/CommercePreflightInput");
  });

  it("pins hand-written README check names to the generated catalog and marks the feature unreleased", async () => {
    const readme = await readFile(new URL("../../README.md", import.meta.url), "utf8");
    const rows = [...readme.matchAll(/^\| (P\d{2})\s*\| ([^|]+)\|$/gm)].map((match) => ({
      id: match[1],
      name: match[2].trim(),
    }));
    expect(rows).toEqual(canonical.checks.map(({ id, name }) => ({ id, name })));
    expect(readme).toContain("unreleased source candidate");
    expect(readme).toContain("do not install this unreleased change");
  });

  it("fails review if generated JSON introduces a constraint this bounded parser does not support", () => {
    const supported = new Set([
      "type",
      "const",
      "enum",
      "anyOf",
      "required",
      "properties",
      "additionalProperties",
      "items",
      "minimum",
      "maximum",
      "minLength",
      "maxLength",
      "minItems",
      "maxItems",
      "pattern",
      "format",
      "description",
    ]);
    function inspect(schema: PreflightJsonSchema) {
      expect(Object.keys(schema).filter((key) => !supported.has(key))).toEqual([]);
      expect(schema.additionalProperties).not.toBe(true);
      if (schema.format !== undefined) expect(schema.format).toBe("date-time");
      for (const child of Object.values(schema.properties ?? {})) inspect(child);
      for (const child of schema.anyOf ?? []) inspect(child);
      if (schema.items) inspect(schema.items);
      if (typeof schema.additionalProperties === "object") inspect(schema.additionalProperties);
    }
    inspect(commercePreflightInputSchema);
    inspect(commercePreflightResultSchema);
  });
});
