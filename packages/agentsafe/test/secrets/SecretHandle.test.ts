import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";

const VALUE = "synthetic-secret-value-0123456789";

describe("SecretHandle", () => {
  it("hands the value out only inside use and never through a string form", () => {
    const handle = SecretHandle.fromString("DECIONIS_API_KEY", VALUE);
    expect(handle.use((value) => value.toString("utf8"))).toBe(VALUE);
    expect(handle.byteLength).toBe(VALUE.length);
    for (const form of [
      String(handle),
      `${handle}`,
      JSON.stringify({ handle }),
      inspect(handle),
      inspect({ nested: handle }),
    ]) {
      expect(form).not.toContain(VALUE);
      expect(form).toContain("DECIONIS_API_KEY");
    }
  });

  it("digests stably, compares in constant time, and keeps the digest after disposal", () => {
    const one = SecretHandle.fromString("EXECUTOR_CALLER_TOKEN", VALUE);
    const two = SecretHandle.fromBuffer("EXECUTOR_CALLER_TOKEN", Buffer.from(VALUE));
    const other = SecretHandle.fromString("EXECUTOR_CALLER_TOKEN", `${VALUE}-changed`);
    expect(one.digest()).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(one.digest()).toBe(two.digest());
    expect(one.equals(two)).toBe(true);
    expect(one.equals(other)).toBe(false);
    one.dispose();
    expect(one.disposed).toBe(true);
    expect(one.digest()).toBe(two.digest());
  });

  it("zeroes the value on disposal and refuses every later use", () => {
    let captured: Buffer | null = null;
    const handle = SecretHandle.fromString("DOWNSTREAM_CREDENTIAL", VALUE);
    handle.use((value) => {
      captured = value;
    });
    handle.dispose();
    expect(captured).not.toBeNull();
    expect((captured as unknown as Buffer).every((byte) => byte === 0)).toBe(true);
    expect(() => handle.use(() => undefined)).toThrow("SECRET_DISPOSED: DOWNSTREAM_CREDENTIAL");
    expect(handle.byteLength).toBe(0);
    handle.dispose();
  });
});
