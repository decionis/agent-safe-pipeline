import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CHAIN_GENESIS, HashChain, type ChainHead } from "../../src/audit/HashChain.js";

/** The digest the verifier recomputes, written independently: sorted keys, `hash` left out. */
function independentDigest(record: Record<string, unknown>): string {
  const sorted = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(sorted);
    if (value === null || typeof value !== "object") return value;
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .filter((key) => key !== "hash" || value !== record)
        .sort()
        .map((key) => [key, sorted((value as Record<string, unknown>)[key])]),
    );
  };
  const material = { ...record };
  delete material["hash"];
  return `sha256:${createHash("sha256")
    .update(JSON.stringify(sorted(material)))
    .digest("hex")}`;
}

describe("HashChain", () => {
  it("starts from genesis and links each line to the one before it", () => {
    const chain = new HashChain("agent-safe.test/1");
    const written: string[] = [];
    const write = (line: string): void => {
      written.push(line);
    };
    expect(CHAIN_GENESIS).toBe(`sha256:${"0".repeat(64)}`);
    expect(chain.head).toEqual({ seq: 0, hash: CHAIN_GENESIS });
    expect(chain.stream).toBe("agent-safe.test/1");
    const first = chain.link({ event: "ONE", nested: { b: 1, a: [true, null] } }, write);
    const second = chain.link({ event: "TWO" }, write);
    expect(written).toEqual([first.line, second.line]);
    expect(first.seq).toBe(1);
    expect(first.prev_hash).toBe(CHAIN_GENESIS);
    expect(second.seq).toBe(2);
    expect(second.prev_hash).toBe(first.hash);
    expect(chain.head).toEqual({ seq: 2, hash: second.hash });
    const parsed = JSON.parse(first.line) as Record<string, unknown>;
    expect(Object.keys(parsed)).toEqual(["stream", "seq", "prev_hash", "event", "nested", "hash"]);
    expect(parsed).toEqual({
      stream: "agent-safe.test/1",
      seq: 1,
      prev_hash: CHAIN_GENESIS,
      event: "ONE",
      nested: { b: 1, a: [true, null] },
      hash: first.hash,
    });
    expect(first.hash).toBe(independentDigest(parsed));
    expect(first.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(second.hash).toBe(independentDigest(JSON.parse(second.line) as Record<string, unknown>));
    expect(first.hash).not.toBe(second.hash);
  });

  it("digests every field but the hash, whatever the key order", () => {
    const record = {
      stream: "s",
      seq: 1,
      prev_hash: CHAIN_GENESIS,
      event: "X",
      hash: "sha256:ignored",
    };
    const reordered = {
      hash: "sha256:other",
      event: "X",
      prev_hash: CHAIN_GENESIS,
      seq: 1,
      stream: "s",
    };
    expect(HashChain.digest(record)).toBe(HashChain.digest(reordered));
    expect(HashChain.digest(record)).toBe(independentDigest(record));
    expect(HashChain.digest({ ...record, event: "Y" })).not.toBe(HashChain.digest(record));
    expect(HashChain.digest({ ...record, seq: 2 })).not.toBe(HashChain.digest(record));
  });

  it("continues from a head it is handed", () => {
    const head: ChainHead = { seq: 41, hash: `sha256:${"a".repeat(64)}` };
    const chain = new HashChain("agent-safe.test/1", head);
    expect(chain.head).toBe(head);
    const next = chain.link({ event: "RESUMED" }, () => undefined);
    expect(next.seq).toBe(42);
    expect(next.prev_hash).toBe(head.hash);
    expect(JSON.parse(next.line)).toMatchObject({ seq: 42, prev_hash: head.hash });
  });

  it("keeps the envelope over a field that shares its name", () => {
    const chain = new HashChain("agent-safe.test/1");
    const record = chain.link(
      { seq: 99, stream: "forged", prev_hash: "forged", hash: "forged", event: "X" },
      () => undefined,
    );
    const parsed = JSON.parse(record.line) as Record<string, unknown>;
    expect(parsed).toEqual({
      stream: "agent-safe.test/1",
      seq: 1,
      prev_hash: CHAIN_GENESIS,
      event: "X",
      hash: record.hash,
    });
    expect(record.hash).toBe(independentDigest(parsed));
  });

  it("writes the line, then tells each listener the new head, until it is removed", () => {
    const chain = new HashChain("agent-safe.test/1");
    const order: string[] = [];
    const first: ChainHead[] = [];
    const second: ChainHead[] = [];
    const stopFirst = chain.onLink((head) => first.push(head));
    chain.onLink((head) => {
      order.push(`listener:${head.seq}`);
      second.push(head);
    });
    const write = (line: string): void => {
      order.push(`write:${(JSON.parse(line) as { seq: number }).seq}`);
    };
    const one = chain.link({ event: "ONE" }, write);
    stopFirst();
    stopFirst();
    const two = chain.link({ event: "TWO" }, write);
    expect(order).toEqual(["write:1", "listener:1", "write:2", "listener:2"]);
    expect(first).toEqual([{ seq: 1, hash: one.hash }]);
    expect(second).toEqual([
      { seq: 1, hash: one.hash },
      { seq: 2, hash: two.hash },
    ]);
  });

  it("lets a listener write a line of its own without interleaving the sequence", () => {
    const chain = new HashChain("agent-safe.test/1");
    const written: number[] = [];
    const write = (line: string): void => {
      written.push((JSON.parse(line) as { seq: number }).seq);
    };
    chain.onLink((head) => {
      if (head.seq === 1) chain.link({ event: "FROM_LISTENER" }, write);
    });
    chain.link({ event: "ONE" }, write);
    chain.link({ event: "THREE" }, write);
    expect(written).toEqual([1, 2, 3]);
  });
});
