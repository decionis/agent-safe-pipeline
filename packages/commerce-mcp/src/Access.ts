import { constants, type Stats } from "node:fs";
import { link, lstat, mkdir, open, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  CommerceGateConfiguration,
  normalizeApiBase,
  type AccessOptions,
  type ResolvedAccess,
} from "./Configuration.js";
import { CommerceGateError } from "./Errors.js";
import { MCP_SERVER_VERSION } from "./Version.js";

const ACCESS_TIMEOUT_MS = 8_000;
const MAX_ACCESS_BYTES = 64 * 1024;
const AWS_GATEWAY = "https://commerce.decionis.com/aws";

export interface AccessDependencies {
  fetch?: typeof fetch;
  loadSecret?: (arn: string) => Promise<string>;
  home?: string;
  lockWaitMs?: number;
  platform?: typeof process.platform;
}

function failure(
  message = "AgentOps access could not be initialized. Existing credentials were kept; no replacement workspace was created.",
): CommerceGateError {
  return new CommerceGateError("CONFIGURATION_INVALID", message);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function key(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 4_096 &&
    value.trim() === value &&
    [...value].every((character) => character.charCodeAt(0) > 31 && character.charCodeAt(0) !== 127)
  );
}

function checkedAccess(value: unknown, provisional: boolean): ResolvedAccess {
  if (
    !record(value) ||
    !key(value.api_key) ||
    typeof value.org_id !== "string" ||
    typeof value.api_base_url !== "string"
  )
    throw failure();
  const connection = new CommerceGateConfiguration({
    DECIONIS_API_KEY: value.api_key,
    DECIONIS_ORG_ID: value.org_id,
    DECIONIS_API_BASE: value.api_base_url,
  }).requireTenantConnection();
  return { ...connection, provisional };
}

/** Bounded bootstrap/discovery only; never forwards redirects or error bodies. */
async function accessJson(url: string, init: RequestInit, doFetch: typeof fetch): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ACCESS_TIMEOUT_MS);
  try {
    const response = await doFetch(url, { ...init, redirect: "error", signal: controller.signal });
    if (!response.ok) {
      await response.body?.cancel();
      throw failure(
        "AgentOps access setup was refused or unavailable. No replacement workspace was created; configure owned access or restore the existing credential.",
      );
    }
    if (Number(response.headers.get("content-length")) > MAX_ACCESS_BYTES) throw failure();
    const reader = response.body?.getReader();
    if (!reader) throw failure();
    const chunks: Uint8Array[] = [];
    let length = 0;
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        length += chunk.value.length;
        if (length > MAX_ACCESS_BYTES) throw failure();
        chunks.push(chunk.value);
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw failure();
  } finally {
    controller.abort();
    clearTimeout(timer);
  }
}

async function loadAwsSecret(arn: string): Promise<string> {
  const parts = arn.split(":");
  if (
    arn.length > 2_048 ||
    parts.length !== 7 ||
    parts[0] !== "arn" ||
    !["aws", "aws-us-gov", "aws-cn"].includes(parts[1]) ||
    parts[2] !== "secretsmanager" ||
    !/^[a-z0-9-]{5,32}$/.test(parts[3]) ||
    !/^\d{12}$/.test(parts[4]) ||
    parts[5] !== "secret" ||
    !/^[\w/+=.@-]{1,512}$/.test(parts[6])
  )
    throw failure();
  const { GetSecretValueCommand, SecretsManagerClient } =
    await import("@aws-sdk/client-secrets-manager");
  // No static credential is supplied: the SDK uses the execution role's default chain.
  const client = new SecretsManagerClient({ region: parts[3], maxAttempts: 1 });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ACCESS_TIMEOUT_MS);
  try {
    const result = await client.send(new GetSecretValueCommand({ SecretId: arn }), {
      abortSignal: controller.signal,
    });
    if (
      typeof result.SecretString !== "string" ||
      Buffer.byteLength(result.SecretString) > MAX_ACCESS_BYTES
    )
      throw failure();
    return result.SecretString;
  } catch {
    throw failure(
      "AgentOps could not load its configured access secret. Check the execution role's GetSecretValue permission; anonymous access was not created.",
    );
  } finally {
    clearTimeout(timer);
    client.destroy();
  }
}

function managedAccess(
  arn: string,
  environment: Record<string, string | undefined>,
  dependencies: AccessDependencies,
): AccessOptions {
  let pending: Promise<ResolvedAccess> | undefined;
  return {
    source: "aws_secret",
    resolve: () =>
      (pending ??= (async () => {
        try {
          const secret = (await (dependencies.loadSecret ?? loadAwsSecret)(arn)).trim();
          if (!secret.startsWith("dcn_aws_"))
            return checkedAccess(JSON.parse(secret) as unknown, false);
          if (!key(secret)) throw failure();
          const base = normalizeApiBase(environment.DECIONIS_API_BASE ?? AWS_GATEWAY);
          if (base.issue || !base.value.endsWith("/aws")) throw failure();
          const session = await accessJson(
            `${base.value}/commerce/session`,
            {
              method: "GET",
              headers: { authorization: `Bearer ${secret}`, accept: "application/json" },
            },
            dependencies.fetch ?? fetch,
          );
          if (!record(session) || session.api_base_url !== base.value) throw failure();
          return checkedAccess({ ...session, api_key: secret }, false);
        } catch {
          throw failure(
            "AgentOps could not resolve its configured access secret. No anonymous workspace or replacement credential was created.",
          );
        }
      })()),
  };
}

function assertPrivate(stat: Stats, directory: boolean): void {
  if (
    (directory ? !stat.isDirectory() : !stat.isFile()) ||
    stat.isSymbolicLink() ||
    (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))
  )
    throw failure();
}

function missing(error: unknown): boolean {
  return record(error) && error.code === "ENOENT";
}

class TrialStore {
  readonly directory: string;
  private readonly credentials: string;
  private readonly lock: string;
  private readonly attempted: string;

  constructor(
    environment: Record<string, string | undefined>,
    private readonly apiBaseUrl: string,
    private readonly dependencies: AccessDependencies,
  ) {
    this.directory =
      environment.AGENTOPS_HOME?.trim() ||
      join(
        environment.XDG_CONFIG_HOME?.trim() || join(dependencies.home ?? homedir(), ".config"),
        "agentops",
      );
    this.credentials = join(this.directory, "credentials.json");
    this.lock = join(this.directory, "provision.lock");
    this.attempted = join(this.directory, "provision.attempted");
  }

  async read(): Promise<ResolvedAccess | null> {
    try {
      assertPrivate(await lstat(this.directory), true);
    } catch (error) {
      if (missing(error)) return null;
      throw failure();
    }
    let file;
    try {
      file = await open(this.credentials, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (error) {
      if (missing(error)) return null;
      throw failure();
    }
    try {
      const stat = await file.stat();
      assertPrivate(stat, false);
      if (stat.size > MAX_ACCESS_BYTES) throw failure();
      const stored: unknown = JSON.parse(await file.readFile("utf8"));
      if (!record(stored) || stored.version !== 1 || stored.provisional !== true) throw failure();
      const result = checkedAccess(stored, true);
      if (result.apiBaseUrl !== this.apiBaseUrl) throw failure();
      return result;
    } catch {
      throw failure();
    } finally {
      await file.close();
    }
  }

  private async syncDirectory(): Promise<void> {
    const directory = await open(this.directory, constants.O_RDONLY | constants.O_DIRECTORY);
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }

  async provision(): Promise<ResolvedAccess> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    assertPrivate(await lstat(this.directory), true);
    const deadline = Date.now() + Math.min(this.dependencies.lockWaitMs ?? 10_000, 10_000);
    let lock;
    while (!lock) {
      const stored = await this.read();
      if (stored) return stored;
      try {
        lock = await open(this.lock, "wx", 0o600);
      } catch (error) {
        if (!record(error) || error.code !== "EEXIST") throw failure();
        let stat;
        try {
          stat = await lstat(this.lock);
        } catch (lockError) {
          if (missing(lockError)) continue;
          throw failure();
        }
        assertPrivate(stat, false);
        // A stale or timed-out lock is an uncertain prior attempt, never permission to mint again.
        if (Date.now() - stat.mtimeMs > 60_000 || Date.now() >= deadline)
          throw failure(
            "Local AgentOps access setup is locked or incomplete. Restore the existing credential or inspect the private setup files; no new workspace was created.",
          );
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
    try {
      const stored = await this.read();
      if (stored) return stored;
      // Persist intent before the network call. An uncertain response, crash, quota
      // refusal, or later missing credential must never silently create a new tenant.
      const attempt = await open(this.attempted, "wx", 0o600);
      try {
        await attempt.sync();
      } finally {
        await attempt.close();
      }
      await this.syncDirectory();
      const response = await accessJson(
        `${this.apiBaseUrl}/v1/public/agents/provision`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: "application/json",
            "user-agent": `decionis-commercegate-mcp/${MCP_SERVER_VERSION}`,
          },
          body: JSON.stringify({ agent_name: "AgentOps MCP Shadow" }),
        },
        this.dependencies.fetch ?? fetch,
      );
      if (!record(response) || response.provisional !== true) throw failure();
      const access = checkedAccess(
        { api_key: response.raw_key, org_id: response.org_id, api_base_url: this.apiBaseUrl },
        true,
      );
      const pendingFile = join(this.directory, "credentials.pending");
      const file = await open(pendingFile, "wx", 0o600);
      try {
        await file.writeFile(
          JSON.stringify({
            version: 1,
            api_key: access.apiKey,
            org_id: access.orgId,
            api_base_url: access.apiBaseUrl,
            provisional: true,
          }),
        );
        await file.sync();
      } finally {
        await file.close();
      }
      // Publish only complete bytes. link is atomic and refuses to replace
      // an existing credential; readers never observe a half-written file.
      await link(pendingFile, this.credentials);
      await unlink(pendingFile);
      await this.syncDirectory();
      return access;
    } catch {
      throw failure();
    } finally {
      await lock.close();
      await unlink(this.lock);
    }
  }
}

/** Creates no files, network requests, tenants, or credentials. */
export function runtimeAccess(
  environment: Record<string, string | undefined>,
  transport: string,
  dependencies: AccessDependencies = {},
): AccessOptions | undefined {
  if (environment.DECIONIS_API_KEY?.trim() || environment.DECIONIS_ORG_ID?.trim()) return undefined;
  const secretArn = environment.AGENTOPS_ACCESS_SECRET_ARN?.trim();
  if (secretArn) return managedAccess(secretArn, environment, dependencies);
  const base = normalizeApiBase(environment.DECIONIS_API_BASE);
  if (
    transport !== "stdio" ||
    environment.NODE_ENV === "production" ||
    base.issue ||
    base.value.endsWith("/aws")
  )
    return undefined;
  if ((dependencies.platform ?? process.platform) === "win32") {
    return {
      source: "local_trial",
      canProvision: false,
      configurationIssue:
        "Automatic local provisioning is unavailable on Windows until secure credential persistence is supported. Configure existing DECIONIS_API_KEY and DECIONIS_ORG_ID instead.",
      resolve: async () => null,
    };
  }
  const store = new TrialStore(environment, base.value, dependencies);
  let pending: Promise<ResolvedAccess> | undefined;
  const options: AccessOptions = {
    source: "local_trial",
    canProvision: environment.AGENTOPS_AUTO_PROVISION !== "0",
    async resolve(purpose) {
      if (pending) return pending;
      const existing = await store.read();
      if (pending) return pending;
      if (existing) return (pending = Promise.resolve(existing));
      if (purpose !== "shadow" || options.canProvision === false) return null;
      // Recheck after the asynchronous read: concurrent calls share one attempt.
      options.canProvision = false;
      return (pending ??= store.provision());
    },
  };
  return options;
}
