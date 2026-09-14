import { readFileSync } from "node:fs";

/**
 * A secret the executor holds: the caller token, the Decionis API key, the
 * downstream credential. Each is supplied once, either as the environment
 * variable itself or as `<NAME>_FILE`, the path of a mounted file, which is
 * what the Kubernetes manifest uses so the value never sits in the pod
 * specification. A failure names the variable and never the value, and
 * nothing here logs.
 */
export class SecretStore {
  public static resolve(env: Readonly<Record<string, string | undefined>>, name: string): string {
    const direct = env[name];
    const path = env[`${name}_FILE`];
    if (direct !== undefined && path !== undefined) {
      throw new Error(`CONFIG_SECRET_AMBIGUOUS: ${name}`);
    }
    if (path !== undefined) return SecretStore.readFile(path, name);
    if (direct === undefined) throw new Error(`CONFIG_SECRET_MISSING: ${name}`);
    const value = direct.trim();
    if (value.length === 0) throw new Error(`CONFIG_SECRET_EMPTY: ${name}`);
    return value;
  }

  private static readFile(path: string, name: string): string {
    let value: string;
    try {
      value = readFileSync(path, "utf8").trim();
    } catch {
      throw new Error(`CONFIG_SECRET_FILE_UNREADABLE: ${name}`);
    }
    if (value.length === 0) throw new Error(`CONFIG_SECRET_EMPTY: ${name}`);
    return value;
  }
}
