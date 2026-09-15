import { describe, expect, it } from "vitest";
import { EgressError } from "../../src/egress/EgressError.js";
import {
  isGlobalFetchLocked,
  lockGlobalFetch,
  type FetchHolder,
} from "../../src/egress/GlobalFetchLock.js";
import { nodeProcess } from "../../src/Serve.js";

describe("lockGlobalFetch", () => {
  it("replaces fetch with a refusal that nothing can reassign, redefine, or unlock", () => {
    const holder: FetchHolder = { fetch: () => Promise.resolve(new Response("open")) };
    expect(isGlobalFetchLocked(holder)).toBe(false);
    lockGlobalFetch(holder);
    expect(isGlobalFetchLocked(holder)).toBe(true);
    const locked = holder.fetch as () => Promise<Response>;
    expect(() => locked()).toThrow(EgressError);
    expect(() => locked()).toThrow("EGRESS_GLOBAL_FETCH_LOCKED");
    expect(() => {
      holder.fetch = () => Promise.resolve(new Response("reopened"));
    }).toThrow(TypeError);
    expect(() => Object.defineProperty(holder, "fetch", { value: 1 })).toThrow(TypeError);
    expect(() => {
      delete holder.fetch;
    }).toThrow(TypeError);
    expect(Object.isFrozen(holder.fetch)).toBe(true);
    lockGlobalFetch(holder);
    expect(holder.fetch).toBe(locked);
  });

  it("does not mistake a writable or unmarked fetch for the lock", () => {
    expect(isGlobalFetchLocked({})).toBe(false);
    expect(isGlobalFetchLocked({ fetch: () => undefined })).toBe(false);
    const marked = (): never => {
      throw new Error("no");
    };
    Object.defineProperty(marked, Symbol.for("agent-safe.fetch-locked"), { value: true });
    const writable: FetchHolder = {};
    Object.defineProperty(writable, "fetch", {
      value: marked,
      writable: true,
      configurable: false,
    });
    expect(isGlobalFetchLocked(writable)).toBe(false);
    const configurable: FetchHolder = {};
    Object.defineProperty(configurable, "fetch", {
      value: marked,
      writable: false,
      configurable: true,
    });
    expect(isGlobalFetchLocked(configurable)).toBe(false);
  });

  it("is what the real process seals at start", () => {
    const holder: FetchHolder = { fetch: globalThis.fetch };
    nodeProcess(holder).lockFetch();
    expect(isGlobalFetchLocked(holder)).toBe(true);
    expect(isGlobalFetchLocked()).toBe(false);
  });
});
