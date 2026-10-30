import type { JsonValue } from "./JsonValue.js";

/**
 * The RFC 8785 (JCS) text of a JSON value: the form the authority digests an
 * execution payload in (`execution_payload_digest`, profile `RFC8785/JCS`), and
 * the form every verifier in another language computes.
 *
 * It differs from the intent's canonical form (`CanonicalIntentHasher`) in
 * key order alone. RFC 8785 sorts every key by UTF-16 code unit, so `"10"`
 * comes before `"9"`; the intent's form puts a key that is an array index
 * first, in numeric order, as `JSON.stringify` writes an ECMAScript object
 * (spec/intent/v1 §4). The text is therefore written here key by key, never
 * by `JSON.stringify` over a rebuilt object, which would reorder such keys.
 * Strings and numbers are written by `JSON.stringify`, whose output RFC 8785
 * adopts for I-JSON values.
 */
export class Rfc8785 {
  public static stringify(value: JsonValue): string {
    if (Array.isArray(value)) return `[${value.map((item) => Rfc8785.stringify(item)).join(",")}]`;
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    const entries: string[] = [];
    // The default sort compares UTF-16 code units, which is the order RFC 8785 names.
    for (const key of Object.keys(value).sort()) {
      const entry = value[key];
      if (entry !== undefined) entries.push(`${JSON.stringify(key)}:${Rfc8785.stringify(entry)}`);
    }
    return `{${entries.join(",")}}`;
  }
}
