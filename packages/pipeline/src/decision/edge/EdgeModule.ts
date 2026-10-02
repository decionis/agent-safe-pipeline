import { readFileSync } from "node:fs";

/** The module ABI this host speaks: ABI 2's bundle exports plus `decide`. */
export const EDGE_MODULE_ABI_VERSION = 3;

/** Why a module was refused, or why a call into it failed. Never a message from the module. */
export type EdgeModuleErrorCode =
  | "EDGE_MODULE_UNREADABLE"
  | "EDGE_MODULE_INVALID"
  | "EDGE_MODULE_ABI_UNSUPPORTED"
  | "EDGE_MODULE_FAULTED";

export class EdgeModuleError extends Error {
  public constructor(public readonly code: EdgeModuleErrorCode) {
    super(code);
    this.name = "EdgeModuleError";
  }
}

/**
 * One answer from the module: its result, or the refusal code it gave. The
 * module's own message is dropped here; it may quote the input, and nothing
 * of the input belongs in a log line.
 */
export type EdgeEnvelope =
  { readonly ok: true; readonly result: unknown } | { readonly ok: false; readonly code: string };

/** The exports ABI 3 requires, as this host calls them. */
interface EdgeExports {
  readonly memory: WebAssembly.Memory;
  alloc(len: number): number;
  dealloc(ptr: number, len: number): void;
  abi_version(): number;
  load_bundle(ptr: number, len: number): bigint;
  decide(handle: number, ptr: number, len: number): bigint;
  unload_bundle(handle: number): number;
}

const FUNCTIONS = [
  "alloc",
  "dealloc",
  "abi_version",
  "load_bundle",
  "evaluate_bundle",
  "decide",
  "unload_bundle",
] as const;

/**
 * The host side of the Decionis edge evaluator: the proprietary WebAssembly
 * module, licensed separately and not part of this package, instantiated with
 * no imports. This class knows the module's calling convention and nothing of
 * its policy semantics.
 *
 * A module that does not export ABI 3 is refused at construction, so a
 * process configured for the edge never starts on an older or a foreign
 * module. A call that traps marks the instance faulted: its memory can no
 * longer be trusted, so every later call refuses rather than answering from
 * it.
 */
export class EdgeModule {
  private faulted = false;
  private readonly encoder = new TextEncoder();
  private readonly decoder = new TextDecoder("utf-8", { fatal: true });

  private constructor(private readonly exports: EdgeExports) {}

  /** Reads, compiles and instantiates the module at `path`. */
  public static fromFile(path: string): EdgeModule {
    let bytes: Uint8Array<ArrayBuffer>;
    try {
      bytes = readFileSync(path);
    } catch {
      throw new EdgeModuleError("EDGE_MODULE_UNREADABLE");
    }
    return EdgeModule.fromBytes(bytes);
  }

  /**
   * Compiles and instantiates `bytes` synchronously, so a refusal is a
   * refusal to start rather than a promise someone forgets to await.
   */
  public static fromBytes(bytes: Uint8Array<ArrayBuffer>): EdgeModule {
    let instance: WebAssembly.Instance;
    try {
      instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
    } catch {
      throw new EdgeModuleError("EDGE_MODULE_INVALID");
    }
    return EdgeModule.fromExports(instance.exports);
  }

  /** Checks an instance's exports against ABI 3. */
  public static fromExports(exports: WebAssembly.Exports): EdgeModule {
    if (!(exports["memory"] instanceof WebAssembly.Memory)) {
      throw new EdgeModuleError("EDGE_MODULE_INVALID");
    }
    for (const name of FUNCTIONS) {
      if (typeof exports[name] !== "function") {
        // An ABI 2 module lacks `decide`; it is an older module, not a broken one.
        throw new EdgeModuleError(
          name === "decide" ? "EDGE_MODULE_ABI_UNSUPPORTED" : "EDGE_MODULE_INVALID",
        );
      }
    }
    const module = new EdgeModule(exports as unknown as EdgeExports);
    let version: unknown;
    try {
      version = module.exports.abi_version();
    } catch {
      throw new EdgeModuleError("EDGE_MODULE_INVALID");
    }
    if (version !== EDGE_MODULE_ABI_VERSION) {
      throw new EdgeModuleError("EDGE_MODULE_ABI_UNSUPPORTED");
    }
    return module;
  }

  /** True once a call trapped; the instance answers nothing after that. */
  public get isFaulted(): boolean {
    return this.faulted;
  }

  /** `load_bundle({signed_bundle, org_id, now})`. */
  public loadBundle(input: {
    readonly signed_bundle: string;
    readonly org_id: string;
    readonly now: string;
  }): EdgeEnvelope {
    return this.call(input, (ptr, len) => this.exports.load_bundle(ptr, len));
  }

  /** `decide(handle, {binding, mode, now})`. */
  public decide(handle: number, input: unknown): EdgeEnvelope {
    return this.call(input, (ptr, len) => this.exports.decide(handle, ptr, len));
  }

  /** `unload_bundle(handle)`: true when the handle was loaded and is now released. */
  public unloadBundle(handle: number): boolean {
    if (this.faulted) return false;
    try {
      return this.exports.unload_bundle(handle) === 1;
    } catch {
      this.faulted = true;
      return false;
    }
  }

  private call(input: unknown, invoke: (ptr: number, len: number) => bigint): EdgeEnvelope {
    if (this.faulted) throw new EdgeModuleError("EDGE_MODULE_FAULTED");
    try {
      const bytes = this.encoder.encode(JSON.stringify(input));
      const ptr = this.exports.alloc(bytes.length);
      if (ptr === 0) throw new EdgeModuleError("EDGE_MODULE_FAULTED");
      // The buffer is read after `alloc`, which may have grown the memory.
      new Uint8Array(this.exports.memory.buffer, ptr, bytes.length).set(bytes);
      const packed = invoke(ptr, bytes.length);
      this.exports.dealloc(ptr, bytes.length);
      const outPtr = Number(packed >> 32n);
      const outLen = Number(packed & 0xffffffffn);
      const text = this.decoder.decode(
        new Uint8Array(this.exports.memory.buffer, outPtr, outLen).slice(),
      );
      this.exports.dealloc(outPtr, outLen);
      return EdgeModule.envelope(JSON.parse(text));
    } catch {
      this.faulted = true;
      throw new EdgeModuleError("EDGE_MODULE_FAULTED");
    }
  }

  private static envelope(value: unknown): EdgeEnvelope {
    const envelope = value as {
      readonly ok?: unknown;
      readonly result?: unknown;
      readonly error?: { readonly code?: unknown };
    };
    if (envelope.ok === true && "result" in envelope) return { ok: true, result: envelope.result };
    if (envelope.ok === false && typeof envelope.error?.code === "string") {
      return { ok: false, code: envelope.error.code };
    }
    throw new EdgeModuleError("EDGE_MODULE_FAULTED");
  }
}
