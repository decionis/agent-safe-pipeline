import { SecretHandle } from "./SecretHandle.js";
import {
  SecretError,
  type ReloadReason,
  type ReloadReport,
  type SecretName,
  type SecretStore,
} from "./SecretStore.js";

/**
 * Secrets given as environment variables. They cannot rotate and they sit in
 * the process environment for its whole life, which is why production
 * refuses this store: there every secret is a mounted file.
 */
export class EnvSecretStore implements SecretStore {
  private constructor(private readonly handles: ReadonlyMap<SecretName, SecretHandle>) {}

  public static open(
    env: Readonly<Record<string, string | undefined>>,
    names: readonly SecretName[],
  ): EnvSecretStore {
    const handles = new Map<SecretName, SecretHandle>();
    for (const name of names) {
      const value = env[name];
      if (value === undefined) throw new SecretError("CONFIG_SECRET_MISSING", name);
      const trimmed = value.trim();
      if (trimmed.length === 0) throw new SecretError("CONFIG_SECRET_EMPTY", name);
      handles.set(name, SecretHandle.fromString(name, trimmed));
    }
    return new EnvSecretStore(handles);
  }

  public has(name: SecretName): boolean {
    return this.handles.has(name);
  }

  public get(name: SecretName): SecretHandle {
    const handle = this.handles.get(name);
    if (handle === undefined) throw new SecretError("SECRET_UNKNOWN", name);
    return handle;
  }

  public onRotate(): () => void {
    return () => undefined;
  }

  public reload(reason: ReloadReason): Promise<ReloadReport> {
    return Promise.resolve({ reason, rotated: [], refused: [] });
  }

  public close(): void {
    for (const handle of this.handles.values()) handle.dispose();
  }
}
