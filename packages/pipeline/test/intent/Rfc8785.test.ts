import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { CanonicalIntentHasher } from "../../src/intent/CanonicalIntentHasher.js";
import type { JsonValue } from "../../src/intent/JsonValue.js";
import { Rfc8785 } from "../../src/intent/Rfc8785.js";

const VECTORS_DIR = new URL("../../../../conformance/vectors/", import.meta.url);

describe("Rfc8785", () => {
  it("sorts every key by UTF-16 code unit, array indices included", () => {
    expect(Rfc8785.stringify({ "10": 1, "9": 2, "-1": 3, a: 4, A: 5, "": 6 })).toBe(
      '{"":6,"-1":3,"10":1,"9":2,"A":5,"a":4}',
    );
    expect(Rfc8785.stringify({ Éclair: 4, zé: 1, za: 2, Z: 3 })).toBe(
      '{"Z":3,"za":2,"zé":1,"Éclair":4}',
    );
  });

  it("keeps array order, sorts nested objects, and writes values as JSON.stringify does", () => {
    expect(
      Rfc8785.stringify({ list: [{ "2": "b", "10": "a" }, 1e21, -0, 1.5, "é\n"], none: null }),
    ).toBe('{"list":[{"10":"a","2":"b"},1e+21,0,1.5,"é\\n"],"none":null}');
  });

  it("drops a property whose value is undefined, as the intent's form does", () => {
    const value = { kept: true, dropped: undefined } as unknown as JsonValue;
    expect(Rfc8785.stringify(value)).toBe('{"kept":true}');
  });

  it("differs from the intent's canonical form only in where array-index keys go", async () => {
    // The array-index vector pins the one difference; on every vector without
    // such keys the two forms are the same bytes.
    const vector = JSON.parse(
      await readFile(new URL("array-index-keys.json", VECTORS_DIR), "utf8"),
    ) as { binding: JsonValue; canonical_json: string };
    expect(Rfc8785.stringify(vector.binding)).not.toBe(vector.canonical_json);
    expect(Rfc8785.stringify(vector.binding)).toContain('"line_quantities":{"1":4,"10":12,"2":1}');

    const compromised = JSON.parse(
      await readFile(new URL("compromised-principal.json", VECTORS_DIR), "utf8"),
    ) as { binding: JsonValue };
    expect(Rfc8785.stringify(compromised.binding)).toBe(
      CanonicalIntentHasher.stringify(compromised.binding),
    );
  });
});
