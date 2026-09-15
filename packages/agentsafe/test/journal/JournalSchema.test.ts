import { describe, expect, it } from "vitest";

/**
 * The record schema has to be constructible at all.
 *
 * A discriminated union whose discriminator is not a field of every member
 * is refused by the schema library while the module is loading, which takes
 * every other test in this package's journal suite with it. So this file
 * imports the module inside the test rather than at the top, and asserts the
 * import itself succeeds: a broken record contract is one failing assertion
 * here instead of a suite that never ran.
 */
describe("the journal's record schema", () => {
  it("can be built, and discriminates the four records on one field", async () => {
    const module = await import("../../src/journal/ExecutionJournal.js");
    const definition = module.JournalRecordSchema.def as unknown as {
      readonly discriminator: string;
      readonly options: readonly { readonly def: { readonly shape: Record<string, unknown> } }[];
    };
    expect(definition.discriminator).toBe("record");
    expect(definition.options).toHaveLength(4);
    // Every member carries the discriminator, which is what makes the union
    // constructible, and its own fields beyond it.
    for (const option of definition.options) {
      expect(Object.keys(option.def.shape)).toContain("record");
      expect(Object.keys(option.def.shape).length).toBeGreaterThan(4);
    }
    expect(module.JOURNAL_VERSION).toBe("agent-safe.attempts/1");
  });
});
