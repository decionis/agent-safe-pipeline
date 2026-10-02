import { EdgeModule } from "@decionis/agent-safe-pipeline";

/**
 * A stand-in for the Decionis edge evaluator (ABI 3), in JavaScript over a
 * real `WebAssembly.Memory`. It verifies nothing: a "signed bundle" is
 * `test.<base64url JSON claims>.sig`. Its policy mirrors the loopback
 * authority's, by amount: under 10,000 ALLOW, under 100,000 ESCALATE,
 * otherwise BLOCK, so the same proposal gets the same verdict either way.
 */
export interface EdgeDoubleClaims {
  readonly bundle_id: string;
  readonly policy_version: string;
  readonly kid: string;
  readonly jti: string;
  readonly aud: string;
  readonly nbf: string;
  readonly exp: string;
}

export function edgeBundle(overrides: Partial<EdgeDoubleClaims> = {}): string {
  const claims: EdgeDoubleClaims = {
    bundle_id: "bundle-1",
    policy_version: "policy-2026.10",
    kid: "decionis-policy-bundle-test-v1",
    jti: "jti-1",
    aud: "org-synthetic",
    nbf: new Date(Date.now() - 3_600_000).toISOString(),
    exp: new Date(Date.now() + 86_400_000).toISOString(),
    ...overrides,
  };
  return `test.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.sig`;
}

export function edgeModuleDouble(abi = 3): EdgeModule {
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 64 });
  let next = 8;
  let handles = 0;
  const loaded = new Map<number, EdgeDoubleClaims>();
  const alloc = (len: number): number => {
    const ptr = next;
    next += len + 8;
    while (next > memory.buffer.byteLength) memory.grow(1);
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
  const refused = (code: string): unknown => ({ ok: false, error: { code, message: code } });
  const exports = {
    memory,
    alloc,
    dealloc: (): void => undefined,
    abi_version: (): number => abi,
    evaluate_bundle: (): bigint => write(refused("unsupported")),
    load_bundle: (ptr: number, len: number): bigint => {
      const input = read(ptr, len);
      const claims = JSON.parse(
        Buffer.from(String(input["signed_bundle"]).split(".")[1] ?? "", "base64url").toString(),
      ) as EdgeDoubleClaims;
      if (claims.aud !== input["org_id"]) return write(refused("bundle_audience_mismatch"));
      if (Date.parse(String(input["now"])) >= Date.parse(claims.exp)) {
        return write(refused("bundle_expired"));
      }
      handles += 1;
      loaded.set(handles, claims);
      return write({
        ok: true,
        result: {
          handle: handles,
          bundle_id: claims.bundle_id,
          policy_version: claims.policy_version,
          kid: claims.kid,
          not_before: claims.nbf,
          expires_at: claims.exp,
        },
      });
    },
    decide: (handle: number, ptr: number, len: number): bigint => {
      const claims = loaded.get(handle);
      if (claims === undefined) return write(refused("bundle_handle_unknown"));
      const input = read(ptr, len);
      const binding = input["binding"] as {
        readonly action: { readonly parameters: { readonly amountMinor?: number } };
      };
      const amount = binding.action.parameters.amountMinor ?? 0;
      const verdict = amount < 10_000 ? "ALLOW" : amount < 100_000 ? "ESCALATE" : "BLOCK";
      return write({
        ok: true,
        result: {
          verdict,
          reason_codes: [`EDGE_POLICY_${verdict}`],
          policy_version: claims.policy_version,
          bundle: {
            bundle_id: claims.bundle_id,
            policy_version: claims.policy_version,
            kid: claims.kid,
            jti: claims.jti,
          },
          authority_requirement: null,
          evaluation_digest: `sha256:${"e".repeat(64)}`,
        },
      });
    },
    unload_bundle: (handle: number): number => (loaded.delete(handle) ? 1 : 0),
  };
  return EdgeModule.fromExports(exports as unknown as WebAssembly.Exports);
}
