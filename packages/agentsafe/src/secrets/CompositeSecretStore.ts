import type { SecurityEvents } from "../incident/SecurityEvents.js";
import { EnvSecretStore } from "./EnvSecretStore.js";
import { FileSecretStore } from "./FileSecretStore.js";
import type { SecretHandle } from "./SecretHandle.js";
import {
  SecretError,
  type ReloadReason,
  type ReloadReport,
  type SecretName,
  type SecretStore,
} from "./SecretStore.js";

export interface EnvironmentSecretOptions {
  readonly events: SecurityEvents;
  /** Under production every secret must be a mounted file. */
  readonly production: boolean;
  /** Refuse a secret file another user could read; off only for development. */
  readonly enforcePermissions: boolean;
  readonly watch?: boolean;
  readonly pollMs?: number;
  readonly graceMs?: number;
  readonly euid?: number;
  readonly egid?: number;
}

/**
 * The secrets a deployment supplies, wherever each one came from: a mounted
 * file (`<NAME>_FILE`) for the ones that can rotate, or the environment
 * (`<NAME>`) outside production. A name given both ways is refused, as is a
 * name given neither way; in production a name given in the environment is
 * refused too, because the file is the only shape whose permissions and
 * rotation this process can verify.
 */
export class CompositeSecretStore implements SecretStore {
  private constructor(
    private readonly byName: ReadonlyMap<SecretName, SecretStore>,
    private readonly stores: readonly SecretStore[],
  ) {}

  public static fromEnvironment(
    env: Readonly<Record<string, string | undefined>>,
    required: readonly SecretName[],
    options: EnvironmentSecretOptions,
  ): CompositeSecretStore {
    const files: Partial<Record<SecretName, string>> = {};
    const fromEnvironment: SecretName[] = [];
    for (const name of required) {
      const direct = env[name];
      const path = env[`${name}_FILE`];
      if (direct !== undefined && path !== undefined) {
        throw new SecretError("CONFIG_SECRET_AMBIGUOUS", name);
      }
      if (path !== undefined) {
        files[name] = path;
      } else if (direct !== undefined) {
        if (options.production) throw new SecretError("CONFIG_SECRET_IN_ENV", name);
        fromEnvironment.push(name);
      } else {
        throw new SecretError("CONFIG_SECRET_MISSING", name);
      }
    }
    const stores: SecretStore[] = [];
    const byName = new Map<SecretName, SecretStore>();
    if (Object.keys(files).length > 0) {
      const store = FileSecretStore.open({
        files,
        events: options.events,
        enforcePermissions: options.enforcePermissions,
        ...(options.watch === undefined ? {} : { watch: options.watch }),
        ...(options.pollMs === undefined ? {} : { pollMs: options.pollMs }),
        ...(options.graceMs === undefined ? {} : { graceMs: options.graceMs }),
        ...(options.euid === undefined ? {} : { euid: options.euid }),
        ...(options.egid === undefined ? {} : { egid: options.egid }),
      });
      stores.push(store);
      for (const name of Object.keys(files) as SecretName[]) byName.set(name, store);
    }
    if (fromEnvironment.length > 0) {
      const store = EnvSecretStore.open(env, fromEnvironment);
      stores.push(store);
      for (const name of fromEnvironment) byName.set(name, store);
    }
    return new CompositeSecretStore(byName, stores);
  }

  /** The names this store holds, for the redactor's digest set. */
  public names(): readonly SecretName[] {
    return [...this.byName.keys()];
  }

  public has(name: SecretName): boolean {
    return this.byName.has(name);
  }

  public get(name: SecretName): SecretHandle {
    const store = this.byName.get(name);
    if (store === undefined) throw new SecretError("SECRET_UNKNOWN", name);
    return store.get(name);
  }

  public onRotate(name: SecretName, listener: (next: SecretHandle) => void): () => void {
    const store = this.byName.get(name);
    if (store === undefined) throw new SecretError("SECRET_UNKNOWN", name);
    return store.onRotate(name, listener);
  }

  public async reload(reason: ReloadReason): Promise<ReloadReport> {
    const rotated: SecretName[] = [];
    const refused: { name: SecretName; code: string }[] = [];
    for (const store of this.stores) {
      const report = await store.reload(reason);
      rotated.push(...report.rotated);
      refused.push(...report.refused);
    }
    return { reason, rotated, refused };
  }

  public close(): void {
    for (const store of this.stores) store.close();
  }
}
