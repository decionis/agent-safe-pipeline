import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  EDGE_MODULE_ABI_VERSION,
  EdgeModule,
  EdgeModuleError,
} from "../../../src/decision/edge/EdgeModule.js";
import { doubleClaims, edgeModuleDouble, signedBundle } from "../../support/EdgeModuleDouble.js";

/** The smallest valid WebAssembly module: the magic number and version, and nothing else. */
const EMPTY_MODULE = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

function refusal(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(EdgeModuleError);
    expect((error as EdgeModuleError).name).toBe("EdgeModuleError");
    expect((error as Error).message).toBe((error as EdgeModuleError).code);
    return (error as EdgeModuleError).code;
  }
  throw new Error("expected a refusal");
}

const load = {
  signed_bundle: signedBundle(doubleClaims()),
  org_id: "org-1",
  now: "2026-10-02T00:00:00.000Z",
};

describe("EdgeModule: what it refuses to start on", () => {
  it("speaks ABI 3", () => {
    expect(EDGE_MODULE_ABI_VERSION).toBe(3);
  });

  it("refuses a path it cannot read", () => {
    expect(refusal(() => EdgeModule.fromFile("/nonexistent/edge.wasm"))).toBe(
      "EDGE_MODULE_UNREADABLE",
    );
  });

  it("refuses bytes that are not WebAssembly", () => {
    const dir = mkdtempSync(join(tmpdir(), "edge-module-"));
    const path = join(dir, "edge.wasm");
    writeFileSync(path, "not a module");
    expect(refusal(() => EdgeModule.fromFile(path))).toBe("EDGE_MODULE_INVALID");
  });

  it("refuses a valid module that exports nothing", () => {
    expect(refusal(() => EdgeModule.fromBytes(EMPTY_MODULE))).toBe("EDGE_MODULE_INVALID");
  });

  it("refuses an instance without memory", () => {
    const double = edgeModuleDouble();
    const exports = { ...double.exports };
    delete (exports as Record<string, unknown>)["memory"];
    expect(refusal(() => EdgeModule.fromExports(exports))).toBe("EDGE_MODULE_INVALID");
  });

  for (const name of [
    "alloc",
    "dealloc",
    "abi_version",
    "load_bundle",
    "evaluate_bundle",
    "unload_bundle",
  ]) {
    it(`refuses an instance without ${name}`, () => {
      expect(
        refusal(() => EdgeModule.fromExports(edgeModuleDouble({ omit: [name] }).exports)),
      ).toBe("EDGE_MODULE_INVALID");
    });
  }

  it("refuses an ABI 2 module, which has no decide, as unsupported", () => {
    expect(
      refusal(() => EdgeModule.fromExports(edgeModuleDouble({ omit: ["decide"] }).exports)),
    ).toBe("EDGE_MODULE_ABI_UNSUPPORTED");
  });

  it("refuses a module declaring any ABI but 3", () => {
    for (const abi of [1, 2, 4]) {
      expect(refusal(() => EdgeModule.fromExports(edgeModuleDouble({ abi }).exports))).toBe(
        "EDGE_MODULE_ABI_UNSUPPORTED",
      );
    }
  });

  it("refuses a module whose abi_version traps", () => {
    expect(
      refusal(() => EdgeModule.fromExports(edgeModuleDouble({ abiThrows: true }).exports)),
    ).toBe("EDGE_MODULE_INVALID");
  });
});

describe("EdgeModule: calls", () => {
  it("passes JSON in and reads the envelope out, releasing both buffers", () => {
    const double = edgeModuleDouble();
    const module = EdgeModule.fromExports(double.exports);
    const loaded = module.loadBundle(load);
    expect(loaded).toEqual({
      ok: true,
      result: {
        handle: 1,
        bundle_id: "bundle-1",
        policy_version: "policy-2026.10",
        kid: "decionis-policy-bundle-test-v1",
        not_before: "2026-10-01T00:00:00.000Z",
        expires_at: "2026-10-05T00:00:00.000Z",
      },
    });
    expect(double.loadInputs).toEqual([load]);
    expect(double.outstanding()).toBe(0);
    const decided = module.decide(1, {
      binding: { action: { type: "x.block" } },
      mode: "ENFORCEMENT",
      now: load.now,
    });
    expect(decided.ok).toBe(true);
    expect(double.decideInputs).toEqual([
      { binding: { action: { type: "x.block" } }, mode: "ENFORCEMENT", now: load.now },
    ]);
    expect(double.outstanding()).toBe(0);
    expect(module.isFaulted).toBe(false);
  });

  it("reads a refusal's code and drops its message", () => {
    const module = EdgeModule.fromExports(edgeModuleDouble().exports);
    expect(module.loadBundle({ ...load, org_id: "org-2" })).toEqual({
      ok: false,
      code: "bundle_audience_mismatch",
    });
  });

  it("reads a large input written after the memory grew", () => {
    const double = edgeModuleDouble();
    const module = EdgeModule.fromExports(double.exports);
    const big = "x".repeat(200_000);
    module.loadBundle(load);
    expect(
      module.decide(1, { binding: { action: { type: big } }, mode: "SHADOW", now: load.now }).ok,
    ).toBe(true);
    expect((double.decideInputs[0]?.["binding"] as { action: { type: string } }).action.type).toBe(
      big,
    );
  });

  it("releases a handle once", () => {
    const double = edgeModuleDouble();
    const module = EdgeModule.fromExports(double.exports);
    module.loadBundle(load);
    expect(module.unloadBundle(1)).toBe(true);
    expect(module.unloadBundle(1)).toBe(false);
  });

  const faults: [string, Parameters<typeof edgeModuleDouble>[0]][] = [
    ["an envelope that is not one", { decide: () => ({ result: 1 }) }],
    ["a refusal without a code", { decide: () => ({ ok: false, error: {} }) }],
    ["an ok envelope without a result", { decide: () => ({ ok: true }) }],
    ["a null envelope", { decide: () => null }],
  ];
  for (const [name, behaviour] of faults) {
    it(`treats ${name} as a fault, and answers nothing afterwards`, () => {
      const module = EdgeModule.fromExports(edgeModuleDouble(behaviour).exports);
      expect(refusal(() => module.decide(1, {}))).toBe("EDGE_MODULE_FAULTED");
      expect(module.isFaulted).toBe(true);
      expect(refusal(() => module.loadBundle(load))).toBe("EDGE_MODULE_FAULTED");
      expect(module.unloadBundle(1)).toBe(false);
    });
  }

  it("treats a failed allocation as a fault", () => {
    const double = edgeModuleDouble();
    (double.exports as Record<string, unknown>)["alloc"] = () => 0;
    const module = EdgeModule.fromExports(double.exports);
    expect(refusal(() => module.loadBundle(load))).toBe("EDGE_MODULE_FAULTED");
    expect(module.isFaulted).toBe(true);
  });

  it("treats a trap in a call as a fault", () => {
    const double = edgeModuleDouble({
      decide: () => {
        throw new WebAssembly.RuntimeError("unreachable");
      },
    });
    const module = EdgeModule.fromExports(double.exports);
    expect(refusal(() => module.decide(1, {}))).toBe("EDGE_MODULE_FAULTED");
  });

  it("treats a trap in unload as a fault", () => {
    const double = edgeModuleDouble();
    (double.exports as Record<string, unknown>)["unload_bundle"] = () => {
      throw new WebAssembly.RuntimeError("unreachable");
    };
    const module = EdgeModule.fromExports(double.exports);
    expect(module.unloadBundle(1)).toBe(false);
    expect(module.isFaulted).toBe(true);
  });
});
