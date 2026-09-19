import { z } from "zod";

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

/**
 * Named in the schema registry so that the published JSON Schema of the
 * intent binding (`intentBindingJsonSchema`) refers to it as `JsonValue`
 * rather than by a generated name; parsing is unaffected.
 */
export const JsonValueSchema: z.ZodType<JsonValue> = z
  .lazy(() =>
    z.union([
      z.boolean(),
      z.number().finite(),
      z.string(),
      z.null(),
      z.array(JsonValueSchema),
      z.record(z.string(), JsonValueSchema),
    ]),
  )
  .meta({ id: "JsonValue", description: "Any JSON value; numbers are finite." });

export const JsonObjectSchema: z.ZodType<JsonObject> = z.record(z.string(), JsonValueSchema);
