import { accessSync, constants, realpathSync, statSync } from "node:fs";
import { url as inspectorUrl } from "node:inspector";
import { resolve, sep } from "node:path";
import { FileSecretStore } from "../secrets/FileSecretStore.js";
import type { SecretName } from "../secrets/SecretStore.js";

export type PostureCheckId =
  | "ROOT_UID"
  | "ROOT_WRITABLE"
  | "CWD_WRITABLE"
  | "SA_TOKEN_PRESENT"
  | "NODE_ENV"
  | "PROXY_ENV"
  | "NODE_OPTIONS"
  | "EXTRA_CA"
  | "TLS_REJECT_DISABLED"
  | "KEYLOG"
  | "INSPECTOR_ACTIVE"
  | "SECRET_IN_ENV"
  | "SECRET_FILE_OUTSIDE_DIR"
  | "SECRET_FILE_MODE"
  | "SECRET_FILE_OWNER"
  | "PERMISSION_MODEL_ABSENT"
  | "PERMISSION_FS_WRITE"
  | "PERMISSION_CHILD_PROCESS"
  | "PERMISSION_WORKER";

/** The checks a deployment may waive by declaring development posture; the rest never are. */
export const WAIVABLE_CHECKS: ReadonlySet<PostureCheckId> = new Set<PostureCheckId>([
  "ROOT_WRITABLE",
  "CWD_WRITABLE",
  "NODE_ENV",
  "PROXY_ENV",
  "NODE_OPTIONS",
  "EXTRA_CA",
  "KEYLOG",
  "INSPECTOR_ACTIVE",
  "SECRET_FILE_OUTSIDE_DIR",
  "SECRET_FILE_MODE",
  "SECRET_FILE_OWNER",
  "PERMISSION_MODEL_ABSENT",
  "PERMISSION_FS_WRITE",
  "PERMISSION_CHILD_PROCESS",
  "PERMISSION_WORKER",
]);

/** The checks cheap enough to repeat while running, whose regression is drift. */
export const DRIFT_CHECKS: ReadonlySet<PostureCheckId> = new Set<PostureCheckId>([
  "SA_TOKEN_PRESENT",
  "PROXY_ENV",
  "NODE_OPTIONS",
  "EXTRA_CA",
  "TLS_REJECT_DISABLED",
  "KEYLOG",
  "INSPECTOR_ACTIVE",
  "SECRET_FILE_OUTSIDE_DIR",
  "SECRET_FILE_MODE",
  "SECRET_FILE_OWNER",
  "PERMISSION_MODEL_ABSENT",
  "PERMISSION_FS_WRITE",
  "PERMISSION_CHILD_PROCESS",
  "PERMISSION_WORKER",
]);

/** The environment keys the posture inspects. Their values are never reported. */
export const INSPECTED_ENVIRONMENT = [
  "NODE_ENV",
  "NODE_OPTIONS",
  "NODE_EXTRA_CA_CERTS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "SSLKEYLOGFILE",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "NODE_USE_ENV_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
] as const;

export const SERVICE_ACCOUNT_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token";

export interface PostureFinding {
  readonly id: PostureCheckId;
  readonly ok: boolean;
  /** A secret name or a check detail that identifies where, never a value. */
  readonly subject?: string;
}

/** What the checks need to know about the host; a fixture in tests, the process in production. */
export interface PostureFacts {
  readonly euid: number;
  readonly egid: number;
  readonly cwd: string;
  writable(path: string): boolean;
  fileStat(path: string): {
    readonly isFile: boolean;
    readonly mode: number;
    readonly uid: number;
    readonly gid: number;
  } | null;
  realpath(path: string): string | null;
  inspectorActive(): boolean;
  permission(): { readonly active: boolean; has(scope: string, reference?: string): boolean };
}

/** What the checks need to know about the configuration. */
export interface PostureConfig {
  readonly production: boolean;
  /** Present inspected environment keys; absent keys are not listed. */
  readonly environment: Readonly<Record<string, string>>;
  /** Secrets supplied through the environment rather than a file. */
  readonly secretsInEnvironment: readonly SecretName[];
  readonly secretFiles: Readonly<Partial<Record<SecretName, string>>>;
  readonly secretsDir: string | null;
}

export function processFacts(): PostureFacts {
  return {
    euid: process.geteuid?.() ?? -1,
    egid: process.getegid?.() ?? -1,
    cwd: process.cwd(),
    writable: (path) => {
      try {
        accessSync(path, constants.W_OK);
        return true;
      } catch {
        return false;
      }
    },
    fileStat: (path) => {
      try {
        const stat = statSync(path);
        return { isFile: stat.isFile(), mode: stat.mode, uid: stat.uid, gid: stat.gid };
      } catch {
        return null;
      }
    },
    realpath: (path) => {
      try {
        return realpathSync(path);
      } catch {
        return null;
      }
    },
    inspectorActive: () =>
      inspectorUrl() !== undefined || process.execArgv.some((arg) => arg.startsWith("--inspect")),
    permission: () => {
      const permission = (
        process as { permission?: { has(scope: string, reference?: string): boolean } }
      ).permission;
      return permission === undefined
        ? { active: false, has: () => true }
        : { active: true, has: (scope, reference) => permission.has(scope, reference) };
    },
  };
}

/** Every check, in a stable order; a finding per check, never a value in it. */
export function evaluate(config: PostureConfig, facts: PostureFacts): PostureFinding[] {
  const findings: PostureFinding[] = [];
  const env = config.environment;
  const has = (key: string): boolean => env[key] !== undefined;

  findings.push({ id: "ROOT_UID", ok: facts.euid !== 0 });
  findings.push({ id: "ROOT_WRITABLE", ok: !facts.writable(sep) });
  findings.push({ id: "CWD_WRITABLE", ok: !facts.writable(facts.cwd) });
  findings.push({ id: "SA_TOKEN_PRESENT", ok: facts.fileStat(SERVICE_ACCOUNT_TOKEN) === null });
  findings.push({ id: "NODE_ENV", ok: env["NODE_ENV"] === "production" });
  findings.push({
    id: "PROXY_ENV",
    ok: !INSPECTED_ENVIRONMENT.filter((key) => /proxy/i.test(key)).some(has),
  });
  findings.push({ id: "NODE_OPTIONS", ok: !has("NODE_OPTIONS") });
  findings.push({ id: "EXTRA_CA", ok: !has("NODE_EXTRA_CA_CERTS") });
  findings.push({ id: "TLS_REJECT_DISABLED", ok: env["NODE_TLS_REJECT_UNAUTHORIZED"] !== "0" });
  findings.push({ id: "KEYLOG", ok: !has("SSLKEYLOGFILE") });
  findings.push({ id: "INSPECTOR_ACTIVE", ok: !facts.inspectorActive() });
  for (const name of config.secretsInEnvironment) {
    findings.push({ id: "SECRET_IN_ENV", ok: !config.production, subject: name });
  }
  const directory = config.secretsDir === null ? null : resolve(config.secretsDir);
  for (const [name, path] of Object.entries(config.secretFiles) as [SecretName, string][]) {
    if (directory !== null) {
      const real = facts.realpath(path);
      const inside = real !== null && real.startsWith(`${directory}${sep}`);
      findings.push({ id: "SECRET_FILE_OUTSIDE_DIR", ok: inside, subject: name });
    }
    const stat = facts.fileStat(path);
    const refusal =
      stat === null || !stat.isFile
        ? "CONFIG_SECRET_FILE_MODE"
        : FileSecretStore.permissionRefusal(stat.mode, stat.uid, stat.gid, facts.euid, facts.egid);
    findings.push({
      id: "SECRET_FILE_MODE",
      ok: refusal !== "CONFIG_SECRET_FILE_MODE",
      subject: name,
    });
    findings.push({
      id: "SECRET_FILE_OWNER",
      ok: refusal !== "CONFIG_SECRET_FILE_OWNER",
      subject: name,
    });
  }
  const permission = facts.permission();
  findings.push({ id: "PERMISSION_MODEL_ABSENT", ok: permission.active });
  findings.push({
    id: "PERMISSION_FS_WRITE",
    ok: permission.active && !permission.has("fs.write", sep),
  });
  findings.push({
    id: "PERMISSION_CHILD_PROCESS",
    ok: permission.active && !permission.has("child"),
  });
  findings.push({ id: "PERMISSION_WORKER", ok: permission.active && !permission.has("worker") });
  return findings;
}
