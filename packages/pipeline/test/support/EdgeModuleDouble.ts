/**
 * A test double of the Decionis edge evaluator's ABI 3, in JavaScript over a
 * real `WebAssembly.Memory`, so the host's calling convention (alloc, write,
 * call, read the packed u64, dealloc) is exercised exactly as against the
 * module. It verifies nothing: a "signed bundle" here is
 * `test.<base64url JSON claims>.sig`, and a verdict is chosen by the intent's
 * action type. The real module's semantics are tested against the real module.
 */
export interface DoubleClaims {
  readonly bundle_id: string;
  readonly policy_version: string;
  readonly kid: string;
  readonly jti: string;
  readonly aud: string;
  readonly nbf: string;
  readonly exp: string;
}

export interface DoubleBehaviour {
  readonly abi?: number;
  readonly omit?: readonly string[];
  /** Replaces the load result. */
  readonly load?: (input: Record<string, unknown>) => unknown;
  /** Replaces the decide result. */
  readonly decide?: (handle: number, input: Record<string, unknown>) => unknown;
  /** Makes `abi_version` throw. */
  readonly abiThrows?: boolean;
}

export interface EdgeModuleDouble {
  readonly exports: WebAssembly.Exports;
  /** Handles currently loaded. */
  readonly loaded: Set<number>;
  readonly decideInputs: Record<string, unknown>[];
  readonly loadInputs: Record<string, unknown>[];
  /** Outstanding allocations (alloc minus dealloc). */
  outstanding(): number;
}

export function signedBundle(claims: DoubleClaims): string {
  return `test.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`;
}

export function doubleClaims(overrides: Partial<DoubleClaims> = {}): DoubleClaims {
  return {
    bundle_id: "bundle-1",
    policy_version: "policy-2026.10",
    kid: "decionis-policy-bundle-test-v1",
    jti: "jti-1",
    aud: "org-1",
    nbf: "2026-10-01T00:00:00.000Z",
    exp: "2026-10-05T00:00:00.000Z",
    ...overrides,
  };
}

const ok = (result: unknown): unknown => ({ ok: true, result });
const refused = (code: string): unknown => ({
  ok: false,
  error: { code, message: `refused: ${code}` },
});

export function edgeModuleDouble(behaviour: DoubleBehaviour = {}): EdgeModuleDouble {
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 64 });
  let next = 8;
  let live = 0;
  let handles = 0;
  const loaded = new Set<number>();
  const claimsByHandle = new Map<number, DoubleClaims>();
  const decideInputs: Record<string, unknown>[] = [];
  const loadInputs: Record<string, unknown>[] = [];

  const alloc = (len: number): number => {
    const ptr = next;
    next += len + 8;
    while (next > memory.buffer.byteLength) memory.grow(1);
    live += 1;
    return ptr;
  };
  const read = (ptr: number, len: number): Record<string, unknown> =>
    JSON.parse(new TextDecoder().decode(new Uint8Array(memory.buffer, ptr, len).slice())) as Record<
      string,
      unknown
    >;
  const write = (value: unknown): bigint => {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    const ptr = alloc(bytes.length);
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    return (BigInt(ptr) << 32n) | BigInt(bytes.length);
  };

  const defaultLoad = (input: Record<string, unknown>): unknown => {
    const parts = String(input["signed_bundle"]).split(".");
    let claims: DoubleClaims;
    try {
      claims = JSON.parse(Buffer.from(parts[1] ?? "", "base64url").toString()) as DoubleClaims;
    } catch {
      return refused("bundle_malformed");
    }
    if (claims.aud !== input["org_id"]) return refused("bundle_audience_mismatch");
    const now = Date.parse(String(input["now"]));
    if (now >= Date.parse(claims.exp)) return refused("bundle_expired");
    if (now < Date.parse(claims.nbf)) return refused("bundle_not_yet_valid");
    handles += 1;
    loaded.add(handles);
    claimsByHandle.set(handles, claims);
    return ok({
      handle: handles,
      bundle_id: claims.bundle_id,
      policy_version: claims.policy_version,
      kid: claims.kid,
      not_before: claims.nbf,
      expires_at: claims.exp,
    });
  };

  const defaultDecide = (handle: number, input: Record<string, unknown>): unknown => {
    const claims = claimsByHandle.get(handle);
    if (claims === undefined || !loaded.has(handle)) return refused("bundle_handle_unknown");
    const now = Date.parse(String(input["now"]));
    if (now >= Date.parse(claims.exp)) return refused("bundle_expired");
    const binding = input["binding"] as { readonly action?: { readonly type?: string } };
    const action = binding.action?.type ?? "";
    const verdict = action.endsWith(".block")
      ? "BLOCK"
      : action.endsWith(".escalate")
        ? "ESCALATE"
        : "ALLOW";
    return ok({
      verdict,
      reason_codes: [`POLICY_${verdict}`],
      policy_version: claims.policy_version,
      bundle: {
        bundle_id: claims.bundle_id,
        policy_version: claims.policy_version,
        kid: claims.kid,
        jti: claims.jti,
      },
      authority_requirement: verdict === "ESCALATE" ? { kind: "HUMAN_APPROVAL" } : null,
      evaluation_digest: `sha256:${"e".repeat(64)}`,
    });
  };

  const functions: Record<string, unknown> = {
    alloc,
    dealloc: () => {
      live -= 1;
    },
    abi_version: () => {
      if (behaviour.abiThrows === true) throw new Error("trap");
      return behaviour.abi ?? 3;
    },
    load_bundle: (ptr: number, len: number): bigint => {
      const input = read(ptr, len);
      loadInputs.push(input);
      return write((behaviour.load ?? defaultLoad)(input));
    },
    evaluate_bundle: (): bigint => write(refused("unsupported")),
    decide: (handle: number, ptr: number, len: number): bigint => {
      const input = read(ptr, len);
      decideInputs.push(input);
      return write((behaviour.decide ?? defaultDecide)(handle, input));
    },
    unload_bundle: (handle: number): number => (loaded.delete(handle) ? 1 : 0),
  };
  const exports: Record<string, unknown> = { memory };
  for (const [name, fn] of Object.entries(functions)) {
    if (!(behaviour.omit ?? []).includes(name)) exports[name] = fn;
  }
  return {
    exports: exports as WebAssembly.Exports,
    loaded,
    decideInputs,
    loadInputs,
    outstanding: () => live,
  };
}
