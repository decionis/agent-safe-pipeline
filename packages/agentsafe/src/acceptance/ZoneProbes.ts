import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { delimiter, join } from "node:path";
import { z } from "zod";
import { verdictFor, type ContainmentVerdict } from "../containment/ContainmentProbe.js";
import type { DownstreamRequest } from "../credential/DownstreamCredential.js";
import { SignedRequestCredential } from "../credential/SignedRequestCredential.js";
import type { DialOutcome } from "../egress/TcpProbe.js";
import { SecretHandle } from "../secrets/SecretHandle.js";

/**
 * The acceptance run's "other routes" case, as the agent's zone observes it
 * (ADR 0009). The tool runs these from the zone because only the zone can see
 * them: whether an origin answers a read sent around the gateway, whether a
 * verifying provider refuses a write the executor did not sign, which MCP
 * servers answer a dial, which credentials the zone holds, and whether the
 * cloud metadata endpoint answers.
 *
 * Every finding here is the zone's word. The gateway puts them in the signed
 * report marked as reported by the zone, and its signature does not vouch for
 * them: a compromised caller can report whatever it likes. They are read the
 * way the containment probe's findings are read:
 *
 * - `REACHABLE` is proof of a hole. Something off the zone answered.
 * - `CONTAINED` is consistent with enforcement and never establishes it. A
 *   drop looks like an outage. For an origin it also needs the same read to
 *   have succeeded through the gateway, which rules out the origin being down.
 * - `INCONCLUSIVE` is anything else: a name that did not resolve, a control
 *   read that failed, a status that says neither yes nor no.
 *
 * Nothing here holds or sends a credential of the operator's. The direct read
 * carries no header the module sets; the provider's write is sent with no
 * signature, then with a key generated for the one request and discarded. A
 * finding holds statuses, codes, names and kinds: never a header value, a
 * body, or any part of a credential's value.
 */
export type ZoneVerdict = ContainmentVerdict;

/** Bounds on what the zone may report, which `zoneFindingsSchema` enforces. */
export const ZONE_LIMITS = Object.freeze({
  /** Origins, providers and MCP servers, each. */
  targets: 64,
  credentials: 512,
  /** A plan label. */
  name: 256,
  /** A host and port, IPv6 brackets included. */
  address: 300,
  /** An environment variable's name, or a file's. */
  credentialName: 1_024,
});

/** A dial, as `egress/TcpProbe.ts` makes one. */
export type ZoneDial = (host: string, port: number, timeoutMs: number) => Promise<DialOutcome>;

/** One request the zone sends. */
export interface ZoneRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string | null;
  readonly timeoutMs: number;
  /** The most of the response body the probe reads. Zero reads none of it. */
  readonly maxBodyBytes: number;
}

export interface ZoneResponse {
  readonly status: number;
  /** At most `maxBodyBytes` of the body, as UTF-8. */
  readonly body: string;
}

/**
 * The zone's HTTP client. Sockets open only under `src/http` and
 * `src/egress`, so the client is handed in, as the containment probe is handed
 * its dial. It must connect to the URL's own host, never through a proxy the
 * environment names (`HTTP_PROXY`, `HTTPS_PROXY`, `NODE_USE_ENV_PROXY`); follow
 * no redirect; send no header but the ones given and the ones HTTP framing
 * needs; and reject with an error whose `code` names the failure, `ETIMEDOUT`
 * when `timeoutMs` passes, as `node:http` does.
 */
export type ZoneHttp = (request: ZoneRequest) => Promise<ZoneResponse>;

export interface ZoneProbeOptions {
  readonly dial: ZoneDial;
  readonly http: ZoneHttp;
  /** Per dial and per request. */
  readonly timeoutMs?: number;
  readonly clock?: () => Date;
}

export interface OriginProbeOptions extends ZoneProbeOptions {
  /** The deployed gateway's base URL. The control read goes there, with the origin read's path and query. */
  readonly gateway: string;
  /** Sent on the control read only, such as a tenant key and the run's tag. Never on the direct read. */
  readonly gatewayHeaders?: Readonly<Record<string, string>>;
}

export type McpProbeOptions = Omit<ZoneProbeOptions, "http">;

export interface MetadataProbeOptions extends ZoneProbeOptions {
  /** The metadata endpoint, `http://169.254.169.254/` unless a test names another. */
  readonly url?: string;
}

/** A target as the plan names it. */
export interface ZoneTarget {
  readonly name: string;
  readonly url: string;
}

/**
 * A verifying provider and the one write the plan names at its canary
 * resource. `body` is the JSON text the write sends, or null for none.
 */
export interface ProviderTarget extends ZoneTarget {
  readonly write: {
    readonly method: string;
    readonly path: string;
    readonly body: string | null;
  };
}

/** What one request came back with. */
export interface ZoneExchange {
  /** The HTTP status, or null when no HTTP answer came back. */
  readonly status: number | null;
  /** `ANSWERED` when a status came back; otherwise why not, as a code. Never a message off the network. */
  readonly detail: string;
}

/**
 * One origin's read, sent around the gateway and through it. `REACHABLE`
 * when the direct dial was answered, an RST included, whatever the read then
 * did; `CONTAINED` only when the direct dial met silence and the control read
 * answered `2xx`; `INCONCLUSIVE` otherwise.
 */
export interface OriginFinding {
  readonly name: string;
  /** The origin's host and port. No path, query or header. */
  readonly address: string;
  /** The read sent straight to the origin, with no credential and no proxy. */
  readonly direct: ZoneExchange;
  /** The same read through the gateway: the control that tells a drop from an outage. */
  readonly control: ZoneExchange;
  readonly verdict: ZoneVerdict;
  readonly at: string;
}

/** One write sent to a provider. */
export interface ProviderAttempt extends ZoneExchange {
  /** The refusal's `reason_code`, when the body was JSON naming one as a code. The body is not kept. */
  readonly reason_code: string | null;
}

/** The write signed with a key the provider cannot know. */
export interface ProviderSignedAttempt extends ProviderAttempt {
  /** The `keyid` the signature named: generated for this request, held by nobody afterwards. */
  readonly key_id: string;
}

/** `ACCEPTED` is a failure: a write the executor did not sign landed on the operator's canary. */
export type ProviderProbeVerdict = "REFUSED" | "ACCEPTED" | "INCONCLUSIVE";

/**
 * A verifying provider's answer to writes it must refuse. `REFUSED` when both
 * answered `4xx`; `ACCEPTED` when either answered `2xx`; `INCONCLUSIVE`
 * otherwise. The signed write is not sent once the unattested one was
 * accepted, since the finding is already a failure and a second write would
 * only change the canary again: `signed` is then null.
 */
export interface ProviderFinding {
  readonly name: string;
  readonly unattested: ProviderAttempt;
  readonly signed: ProviderSignedAttempt | null;
  readonly verdict: ProviderProbeVerdict;
  readonly at: string;
}

/** An MCP server's host and port, dialled and nothing more: no MCP message is sent. */
export interface McpFinding {
  readonly name: string;
  readonly address: string;
  readonly verdict: ZoneVerdict;
  /** Why, as a code. */
  readonly detail: string;
  readonly at: string;
}

/**
 * The cloud metadata endpoint, read with a bare `GET /`. `REACHABLE` when the
 * dial was answered; otherwise the containment probe's verdict for the dial.
 * There is no gateway path to compare with, so `CONTAINED` here has no
 * control behind it.
 */
export interface MetadataFinding {
  readonly address: string;
  readonly status: number | null;
  readonly detail: string;
  readonly verdict: ZoneVerdict;
  readonly at: string;
}

/** What a finding says a credential is. A fixed word, never derived from the value's text. */
export const CREDENTIAL_KINDS = [
  "jwt",
  "pem-private-key",
  "url-with-userinfo",
  "aws-access-key",
  "aws-secret-key",
  "aws-session-token",
  "azure-client-secret",
  "github-token",
  "credential-file-path",
  "secret-like",
  "service-account-token",
  "web-identity-token",
  "aws-credentials",
  "gcp-credentials",
  "azure-cli-credentials",
  "kubeconfig",
  "docker-config",
  "netrc",
  "npmrc",
] as const;

export type CredentialKind = (typeof CREDENTIAL_KINDS)[number];

/**
 * A credential the zone holds, by name and kind. `name` is the environment
 * variable's name, a well-known file's path (`~/` for the home directory), or
 * `$VARIABLE` for the file a variable names. `own` marks the run's own
 * credentials, which are reported like any other.
 */
export interface CredentialFinding {
  readonly source: "environment" | "file";
  readonly name: string;
  readonly kind: CredentialKind;
  readonly own: boolean;
}

/** Everything the zone reports, as the tool sends it to the gateway when the run closes. */
export interface ZoneFindings {
  readonly origins: readonly OriginFinding[];
  readonly providers: readonly ProviderFinding[];
  readonly mcp: readonly McpFinding[];
  readonly credentials: readonly CredentialFinding[];
  /** Null when the plan did not name the metadata endpoint. */
  readonly metadata: MetadataFinding | null;
}

export const METADATA_URL = "http://169.254.169.254/";

const DEFAULT_TIMEOUT_MS = 5_000;
const METADATA_TIMEOUT_MS = 2_000;
/** Enough for a refusal's JSON; the rest of a body is not read. */
const REFUSAL_BODY_BYTES = 4_096;
const ANSWERED = "ANSWERED";
const UNKNOWN = "UNKNOWN";
const CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const KEY_ID = /^agentsafe-acceptance-[0-9a-f]{32}$/;
const SCHEMES: ReadonlySet<string> = new Set(["http:", "https:"]);

interface Target {
  readonly url: URL;
  readonly host: string;
  readonly port: number;
  readonly address: string;
}

/** A value that is a code, or null. A message, a value or anything else is not kept. */
function code(value: unknown): string | null {
  return typeof value === "string" && CODE.test(value) ? value : null;
}

function codeOf(error: unknown): string {
  return code((error as { code?: unknown } | null)?.code) ?? UNKNOWN;
}

/** The status's class, `2` for `2xx`; `0` for no answer. */
function classOf(status: number | null): number {
  return Math.floor((status ?? 0) / 100);
}

/**
 * A target the zone can probe: an `http` or `https` URL with no userinfo. One
 * the operator cannot spell is refused rather than probed, and the error names
 * the plan's label, never the URL, which could carry a credential.
 */
function targetOf(target: ZoneTarget): Target {
  const url = URL.parse(target.url);
  if (url === null || !SCHEMES.has(url.protocol) || url.username !== "" || url.password !== "") {
    throw new Error(`ZONE_TARGET_INVALID: ${target.name}`);
  }
  const port = url.port === "" ? (url.protocol === "https:" ? 443 : 80) : Number(url.port);
  const host = url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
  return { url, host, port, address: `${url.hostname}:${String(port)}` };
}

/** A base URL's origin and path prefix, with a path and query appended. */
function under(base: ZoneTarget, pathAndQuery: string): string {
  const { url } = targetOf(base);
  const prefix = url.pathname.endsWith("/") ? url.pathname.slice(0, -1) : url.pathname;
  return `${url.origin}${prefix}${pathAndQuery}`;
}

async function exchange(
  http: ZoneHttp,
  request: ZoneRequest,
): Promise<ZoneExchange & { readonly body: string | null }> {
  try {
    const response = await http(request);
    return { status: response.status, detail: ANSWERED, body: response.body };
  } catch (error) {
    return { status: null, detail: codeOf(error), body: null };
  }
}

/**
 * Dial, then read only if the dial connected. The verdict is the dial's: a
 * connection that answered is a hole whatever the read did next, and a read is
 * never sent where the dial met silence or a refusal.
 */
async function directRead(
  target: Target,
  options: ZoneProbeOptions,
  timeoutMs: number,
): Promise<ZoneExchange & { readonly verdict: ZoneVerdict }> {
  const outcome = await options.dial(target.host, target.port, timeoutMs);
  if (outcome.state !== "CONNECTED") {
    const { verdict, detail } = verdictFor(outcome);
    return { status: null, detail: code(detail) ?? UNKNOWN, verdict };
  }
  const read = await exchange(options.http, {
    method: "GET",
    url: target.url.href,
    headers: {},
    body: null,
    timeoutMs,
    maxBodyBytes: 0,
  });
  return { status: read.status, detail: read.detail, verdict: "REACHABLE" };
}

const now = (options: { readonly clock?: () => Date }): string =>
  (options.clock ?? ((): Date => new Date()))().toISOString();

/**
 * Read one origin directly and through the gateway. The direct read is a
 * `GET` of the plan's read URL with no header the probe sets, after a dial to
 * its host and port; the control is the same path and query through the
 * gateway, with the gateway's headers. Both are sent whatever the first one
 * did, so the report shows the gateway path working beside every verdict.
 *
 * It establishes that an origin answered from the zone (`REACHABLE`). It
 * never establishes that the origin is unreachable: `CONTAINED` says only that
 * the zone met silence while the gateway's path worked.
 */
export async function probeOrigin(
  origin: ZoneTarget,
  options: OriginProbeOptions,
): Promise<OriginFinding> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const target = targetOf(origin);
  const controlUrl = under(
    { name: "gateway", url: options.gateway },
    `${target.url.pathname}${target.url.search}`,
  );
  const direct = await directRead(target, options, timeoutMs);
  const control = await exchange(options.http, {
    method: "GET",
    url: controlUrl,
    headers: options.gatewayHeaders ?? {},
    body: null,
    timeoutMs,
    maxBodyBytes: 0,
  });
  const verdict =
    direct.verdict !== "CONTAINED"
      ? direct.verdict
      : classOf(control.status) === 2
        ? "CONTAINED"
        : "INCONCLUSIVE";
  return {
    name: origin.name,
    address: target.address,
    direct: { status: direct.status, detail: direct.detail },
    control: { status: control.status, detail: control.detail },
    verdict,
    at: now(options),
  };
}

async function attempt(http: ZoneHttp, request: ZoneRequest): Promise<ProviderAttempt> {
  const answer = await exchange(http, request);
  return { status: answer.status, reason_code: reasonCodeOf(answer.body), detail: answer.detail };
}

/**
 * The `reason_code` a refusal's JSON body names, when it is a code. Nothing
 * else of the body survives. No body reads as the text `null`, which, like a
 * body that is not JSON, throws on the way and names none.
 */
function reasonCodeOf(body: string | null): string | null {
  try {
    return code((JSON.parse(String(body)) as { reason_code?: unknown }).reason_code);
  } catch {
    return null;
  }
}

/**
 * Headers for one write, signed (RFC 9421, Ed25519) with a key generated here
 * for this request alone. The provider has never seen the key, so a provider
 * that verifies refuses it; the signature is otherwise well formed, so the
 * refusal is about the key and not the shape.
 */
async function unknownKeyHeaders(
  request: { readonly method: string; readonly url: string; readonly body: string | null },
  clock: () => Date,
): Promise<{ readonly keyId: string; readonly headers: Readonly<Record<string, string>> }> {
  const keyId = `agentsafe-acceptance-${randomBytes(16).toString("hex")}`;
  // The key lives in this call's scope and nowhere else. Its public half is
  // never exported, so no provider could have registered it.
  const pem = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });
  const handle = SecretHandle.fromString(keyId, String(pem));
  const credential = new SignedRequestCredential(
    { algorithm: "ed25519", keyId },
    () => handle,
    () => clock().getTime(),
  );
  const headers = await credential.headersFor({
    // The credential covers whatever method it is handed; the type names the
    // two a handler sends, and a plan's write may use another.
    method: request.method as DownstreamRequest["method"],
    url: request.url,
    body: request.body,
    idempotencyKey: randomUUID(),
    intentHash: `sha256:${randomBytes(32).toString("hex")}`,
  });
  return { keyId, headers };
}

/**
 * Send the plan's write to a verifying provider twice, from the zone: first
 * with no signature, then signed with a key the provider cannot know. A
 * provider that holds the boundary refuses both with a `4xx`.
 *
 * It establishes how this provider answered these two requests. It does not
 * establish that the provider refuses a grant replayed or altered after
 * issuance: the zone holds no grant to try, and those refusals are the
 * build's to show (the provider conformance vectors).
 */
export async function probeProvider(
  provider: ProviderTarget,
  options: ZoneProbeOptions,
): Promise<ProviderFinding> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const clock = options.clock ?? ((): Date => new Date());
  if (!provider.write.path.startsWith("/"))
    throw new Error(`ZONE_TARGET_INVALID: ${provider.name}`);
  const write = {
    method: provider.write.method.toUpperCase(),
    url: under(provider, provider.write.path),
    body: provider.write.body,
  };
  const base = { ...write, timeoutMs, maxBodyBytes: REFUSAL_BODY_BYTES };
  const json: Readonly<Record<string, string>> =
    write.body === null ? {} : { "content-type": "application/json" };
  const unattested = await attempt(options.http, { ...base, headers: json });
  if (classOf(unattested.status) === 2) {
    return {
      name: provider.name,
      unattested,
      signed: null,
      verdict: "ACCEPTED",
      at: clock().toISOString(),
    };
  }
  const { keyId, headers } = await unknownKeyHeaders(write, clock);
  const signed = {
    ...(await attempt(options.http, { ...base, headers: { ...json, ...headers } })),
    key_id: keyId,
  };
  const verdict =
    classOf(signed.status) === 2
      ? "ACCEPTED"
      : classOf(unattested.status) === 4 && classOf(signed.status) === 4
        ? "REFUSED"
        : "INCONCLUSIVE";
  return { name: provider.name, unattested, signed, verdict, at: clock().toISOString() };
}

/**
 * Dial every MCP server's host and port once, in order. No MCP message is
 * sent, so a finding says a server answered the zone, never that it would
 * serve a tool call.
 */
export async function probeMcp(
  servers: readonly ZoneTarget[],
  options: McpProbeOptions,
): Promise<McpFinding[]> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const findings: McpFinding[] = [];
  for (const server of servers) {
    const target = targetOf(server);
    const { verdict, detail } = verdictFor(await options.dial(target.host, target.port, timeoutMs));
    findings.push({
      name: server.name,
      address: target.address,
      verdict,
      detail: code(detail) ?? UNKNOWN,
      at: now(options),
    });
  }
  return findings;
}

/**
 * Read the cloud metadata endpoint with a bare `GET /`: no header, no token,
 * no path, and a short timeout. Run only when the plan names it. A metadata
 * service that answers at all is reported as `REACHABLE`, since the headers
 * it would need to hand out credentials are the zone's to send.
 */
export async function probeMetadata(options: MetadataProbeOptions): Promise<MetadataFinding> {
  const target = targetOf({ name: "metadata", url: options.url ?? METADATA_URL });
  const read = await directRead(target, options, options.timeoutMs ?? METADATA_TIMEOUT_MS);
  return {
    address: target.address,
    status: read.status,
    detail: read.detail,
    verdict: read.verdict,
    at: now(options),
  };
}

export interface CredentialScanOptions {
  readonly env: Readonly<Record<string, string | undefined>>;
  /** The home directory the `~/` paths are read under. */
  readonly home: string;
  /** Whether a path exists. Files are never opened. */
  readonly exists?: (path: string) => boolean;
  /** The run's own credentials, by finding name: an environment variable, a file, or `$VARIABLE`. */
  readonly own?: readonly string[];
}

/** Variables whose name says what they hold. */
const NAMED_KINDS: ReadonlyMap<string, CredentialKind> = new Map<string, CredentialKind>([
  ["AWS_ACCESS_KEY_ID", "aws-access-key"],
  ["AWS_SECRET_ACCESS_KEY", "aws-secret-key"],
  ["AWS_SESSION_TOKEN", "aws-session-token"],
  ["AZURE_CLIENT_SECRET", "azure-client-secret"],
  ["GITHUB_TOKEN", "github-token"],
  ["GH_TOKEN", "github-token"],
  ["GOOGLE_APPLICATION_CREDENTIALS", "credential-file-path"],
  ["AWS_SHARED_CREDENTIALS_FILE", "credential-file-path"],
  ["AWS_WEB_IDENTITY_TOKEN_FILE", "credential-file-path"],
  ["AZURE_FEDERATED_TOKEN_FILE", "credential-file-path"],
]);

/**
 * What a variable's name ends a word with when it holds a credential, the
 * name split into words at anything not a letter and where a lower case
 * letter meets a capital. A term matches the end of a word, so `AUTHTOKEN`
 * and `TOKEN2` match and `TOKENIZERS` does not; `TOKENS` is left out because
 * `MAX_TOKENS` is a model setting, not a secret.
 */
const NAME_TERMS = [
  "TOKEN",
  "SECRET",
  "SECRETS",
  "PASSWORD",
  "PASSWORDS",
  "PASSWD",
  "CREDENTIAL",
  "CREDENTIALS",
  "APIKEY",
  "API_KEY",
  "ACCESSKEY",
  "ACCESS_KEY",
  "PRIVATEKEY",
  "PRIVATE_KEY",
  "SESSION_KEY",
  "COOKIE",
  "COOKIES",
  "AUTH",
  "AUTHORIZATION",
];

function credentialName(name: string): boolean {
  const words = `${name
    .replace(/([a-z])([A-Z])/g, "$1_$2")
    .toUpperCase()
    .split(/[^A-Z]+/)
    .join("_")}_`;
  // A session is a credential when it ends the name (`APP_SESSION`), not when
  // it qualifies something else (`TERM_SESSION_ID`).
  return NAME_TERMS.some((term) => words.includes(`${term}_`)) || words.endsWith("SESSION_");
}

const JWT = /^eyJ[\w-]+\.[\w-]+\.[\w-]*$/;
const AWS_KEY_ID = /^(?:AKIA|ASIA)[A-Z0-9]{16}$/;

/** What a value's shape says it is, or null. Only the kind leaves this function. */
function shapeOf(value: string): CredentialKind | null {
  if (JWT.test(value)) return "jwt";
  if (value.includes("-----BEGIN ") && value.includes("PRIVATE KEY-----")) return "pem-private-key";
  if (AWS_KEY_ID.test(value)) return "aws-access-key";
  const url = URL.parse(value);
  return url !== null && (url.username !== "" || url.password !== "") ? "url-with-userinfo" : null;
}

/** Files that hold a credential wherever they exist. */
const WELL_KNOWN_FILES: readonly {
  readonly path: string;
  readonly home: boolean;
  readonly kind: CredentialKind;
}[] = [
  {
    path: "/var/run/secrets/kubernetes.io/serviceaccount/token",
    home: false,
    kind: "service-account-token",
  },
  { path: ".aws/credentials", home: true, kind: "aws-credentials" },
  {
    path: ".config/gcloud/application_default_credentials.json",
    home: true,
    kind: "gcp-credentials",
  },
  { path: ".azure/msal_token_cache.json", home: true, kind: "azure-cli-credentials" },
  { path: ".azure/accessTokens.json", home: true, kind: "azure-cli-credentials" },
  { path: ".azure/service_principal_entries.json", home: true, kind: "azure-cli-credentials" },
  { path: ".kube/config", home: true, kind: "kubeconfig" },
  { path: ".docker/config.json", home: true, kind: "docker-config" },
  { path: ".netrc", home: true, kind: "netrc" },
  { path: ".npmrc", home: true, kind: "npmrc" },
];

/** Variables that name a credential file, or a list of them. */
const NAMED_FILES: readonly (readonly [string, CredentialKind])[] = [
  ["GOOGLE_APPLICATION_CREDENTIALS", "gcp-credentials"],
  ["AWS_SHARED_CREDENTIALS_FILE", "aws-credentials"],
  ["AWS_WEB_IDENTITY_TOKEN_FILE", "web-identity-token"],
  ["AZURE_FEDERATED_TOKEN_FILE", "web-identity-token"],
  ["KUBECONFIG", "kubeconfig"],
];

/**
 * List the credentials the zone holds, by name and kind, environment first in
 * name order, then files in a fixed order.
 *
 * An environment variable is reported when its value is shaped like a JWT, a
 * PEM private key, an AWS access key id or a URL with userinfo, when its name
 * is one whose meaning is known, when its name reads as a credential's, or
 * when the caller names it as the run's own. A variable with an empty value is
 * not. The kind is the value's shape when it has one, then the known name's,
 * then `secret-like`.
 *
 * A file is reported when it exists at a path where a credential is kept: the
 * Kubernetes service-account token, the AWS, gcloud and Azure CLI stores,
 * `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, and the
 * files `GOOGLE_APPLICATION_CREDENTIALS` and its kin name. Files are never
 * opened, so a file that holds no credential is reported too; and a variable
 * that names a file is reported as `$VARIABLE`, since its value could be the
 * credential itself rather than a path.
 *
 * It establishes what the zone holds at those names. It does not establish
 * that the zone holds nothing else: a credential under an ordinary name, in an
 * ordinary file, or in a process's memory is not seen.
 */
export function scanCredentials(options: CredentialScanOptions): CredentialFinding[] {
  const own = new Set(options.own);
  const exists = options.exists ?? existsSync;
  const findings: CredentialFinding[] = [];
  for (const name of Object.keys(options.env).sort()) {
    const value = options.env[name];
    if (value === undefined || value === "") continue;
    const kind =
      shapeOf(value) ??
      NAMED_KINDS.get(name) ??
      (credentialName(name) || own.has(name) ? "secret-like" : null);
    if (kind !== null) findings.push({ source: "environment", name, kind, own: own.has(name) });
  }
  for (const file of WELL_KNOWN_FILES) {
    const name = file.home ? `~/${file.path}` : file.path;
    if (exists(file.home ? join(options.home, file.path) : file.path)) {
      findings.push({ source: "file", name, kind: file.kind, own: own.has(name) });
    }
  }
  for (const [variable, kind] of NAMED_FILES) {
    const value = options.env[variable];
    if (value === undefined) continue;
    const name = `$${variable}`;
    if (value.split(delimiter).some((path) => exists(path))) {
      findings.push({ source: "file", name, kind, own: own.has(name) });
    }
  }
  return findings;
}

const zoneName = z.string().min(1).max(ZONE_LIMITS.name);
const zoneAddress = z.string().min(1).max(ZONE_LIMITS.address);
const zoneCode = z.string().regex(CODE);
const zoneStatus = z.int().min(100).max(999).nullable();
const zoneVerdict = z.enum(["REACHABLE", "CONTAINED", "INCONCLUSIVE"]);
const zoneAt = z.iso.datetime();
const zoneExchange = z.strictObject({ status: zoneStatus, detail: zoneCode });
const providerAttempt = {
  status: zoneStatus,
  reason_code: zoneCode.nullable(),
  detail: zoneCode,
};

/**
 * The zone's findings, as the gateway parses them when a run closes. Closed
 * at every level, bounded in every array and string, and with no field that
 * can carry a credential's value: a kind is one of `CREDENTIAL_KINDS`, a
 * detail and a reason are codes. It checks the form of what the zone said,
 * not its truth.
 */
export const zoneFindingsSchema = z.strictObject({
  origins: z
    .array(
      z.strictObject({
        name: zoneName,
        address: zoneAddress,
        direct: zoneExchange,
        control: zoneExchange,
        verdict: zoneVerdict,
        at: zoneAt,
      }),
    )
    .max(ZONE_LIMITS.targets),
  providers: z
    .array(
      z.strictObject({
        name: zoneName,
        unattested: z.strictObject(providerAttempt),
        signed: z.strictObject({ ...providerAttempt, key_id: z.string().regex(KEY_ID) }).nullable(),
        verdict: z.enum(["REFUSED", "ACCEPTED", "INCONCLUSIVE"]),
        at: zoneAt,
      }),
    )
    .max(ZONE_LIMITS.targets),
  mcp: z
    .array(
      z.strictObject({
        name: zoneName,
        address: zoneAddress,
        verdict: zoneVerdict,
        detail: zoneCode,
        at: zoneAt,
      }),
    )
    .max(ZONE_LIMITS.targets),
  credentials: z
    .array(
      z.strictObject({
        source: z.enum(["environment", "file"]),
        name: z.string().min(1).max(ZONE_LIMITS.credentialName),
        kind: z.enum(CREDENTIAL_KINDS),
        own: z.boolean(),
      }),
    )
    .max(ZONE_LIMITS.credentials),
  metadata: z
    .strictObject({
      address: zoneAddress,
      status: zoneStatus,
      detail: zoneCode,
      verdict: zoneVerdict,
      at: zoneAt,
    })
    .nullable(),
});
