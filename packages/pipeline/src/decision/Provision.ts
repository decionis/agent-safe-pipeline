/**
 * A free Decionis key, issued in the run itself. `POST
 * /v1/public/agents/provision` mints a provisional workspace with no
 * account, no email and no card: an organization id, a key returned exactly
 * once, an allowance of governed decisions, and the way a person later
 * claims it. Every dossier such a workspace mints is signed with the
 * `provisional_anonymous` issuer tier, so a verifier can always tell it
 * from an owned organization's record. The call carries the client
 * identification the hosted gate carries, so the authority can say which
 * repository, example and surface the workspace came from.
 */
import { z } from "zod";
import { AuthorityBaseUrl } from "../http/AuthorityBaseUrl.js";
import { BoundedResponseBody } from "../http/BoundedResponseBody.js";
import { userAgent, type ClientSource } from "../http/ClientIdentification.js";

export interface ProvisionOptions {
  /** The authority to provision from; HTTPS, or loopback when allowed. */
  readonly baseUrl: string;
  readonly allowInsecureLoopback?: boolean;
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
  readonly source?: ClientSource;
  /** Shown to the person who later claims the workspace. */
  readonly agentName?: string;
}

export interface ProvisionedWorkspace {
  readonly orgId: string;
  /** The key, seen here and nowhere else; the caller stores it. */
  readonly rawKey: string;
  readonly provisional: true;
  /** The caps on the anonymous lane, as the authority stated them. */
  readonly limits: Readonly<Record<string, unknown>>;
  /** How a person attaches themselves to the workspace, as the authority stated it. */
  readonly claim: Readonly<Record<string, unknown>>;
}

const MAX_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_AGENT_NAME = 64;

/**
 * Mirrors `AgentProvisionResponse`: the four fields the caller needs are
 * required; the rest of the contract is open and rides along as it came.
 */
const ProvisionResponseSchema = z
  .object({
    org_id: z.string().uuid(),
    raw_key: z.string().min(1).max(4_096),
    provisional: z.literal(true),
    limits: z.record(z.string(), z.unknown()).default({}),
    claim: z.record(z.string(), z.unknown()).default({}),
  })
  .passthrough();

export class ProvisionError extends Error {
  public constructor(
    public readonly code:
      | "PROVISION_LIMIT_REACHED"
      | "PROVISION_REFUSED"
      | "PROVISION_UNAVAILABLE"
      | "PROVISION_RESPONSE_INVALID"
      | "PROVISION_TIMED_OUT",
    public readonly status: number | null,
    /** Seconds to wait before another attempt, when the authority said. */
    public readonly retryAfterSeconds: number | null = null,
  ) {
    super(code);
    this.name = "ProvisionError";
  }
}

function retryAfter(response: Response): number | null {
  const value = response.headers.get("retry-after");
  if (value === null || !/^\d{1,7}$/.test(value.trim())) return null;
  return Number(value.trim());
}

/** Mints a provisional workspace, or throws a `ProvisionError` that names why. */
export async function provisionWorkspace(options: ProvisionOptions): Promise<ProvisionedWorkspace> {
  const baseUrl = AuthorityBaseUrl.normalize(
    options.baseUrl,
    options.allowInsecureLoopback ?? false,
  );
  const doFetch = options.fetch ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const agentName = options.agentName?.slice(0, MAX_AGENT_NAME);
  let response: Response;
  try {
    response = await doFetch(`${baseUrl}/v1/public/agents/provision`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        "user-agent": userAgent(options.source),
      },
      body: JSON.stringify(agentName === undefined ? {} : { agent_name: agentName }),
      redirect: "error",
      signal: controller.signal,
    });
  } catch {
    clearTimeout(timer);
    throw new ProvisionError(
      controller.signal.aborted ? "PROVISION_TIMED_OUT" : "PROVISION_UNAVAILABLE",
      null,
    );
  }
  let text: string | null;
  try {
    text = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
  } catch {
    text = null;
  } finally {
    clearTimeout(timer);
  }
  if (response.status === 429) {
    throw new ProvisionError("PROVISION_LIMIT_REACHED", 429, retryAfter(response));
  }
  if (response.status >= 500) {
    throw new ProvisionError("PROVISION_UNAVAILABLE", response.status, retryAfter(response));
  }
  if (response.status !== 201 && response.status !== 200) {
    throw new ProvisionError("PROVISION_REFUSED", response.status);
  }
  if (text === null) throw new ProvisionError("PROVISION_RESPONSE_INVALID", response.status);
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new ProvisionError("PROVISION_RESPONSE_INVALID", response.status);
  }
  const parsed = ProvisionResponseSchema.safeParse(body);
  if (!parsed.success) throw new ProvisionError("PROVISION_RESPONSE_INVALID", response.status);
  return {
    orgId: parsed.data.org_id,
    rawKey: parsed.data.raw_key,
    provisional: true,
    limits: parsed.data.limits,
    claim: parsed.data.claim,
  };
}
