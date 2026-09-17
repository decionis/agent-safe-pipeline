import { createRequire } from "node:module";

/** Where a hosted call came from, for the authority's own accounting. Never decision input. */
export interface ClientSource {
  /** The repository the integration was taken from, as `owner/name`. */
  readonly repo?: string;
  /** The example or integration name within it. */
  readonly example?: string;
}

const PRODUCT = "agent-safe-pipeline";
/** A product token or comment value: what a `User-Agent` may carry without escaping. */
const TOKEN = /^[\w.\-/@]{1,120}$/;

let cachedVersion: string | undefined;

/** Defined at bundle time by a single-executable build of a consumer; absent everywhere else. */
declare const __AGENT_SAFE_PIPELINE_VERSION__: string | undefined;

/** This package's own version, read once from its manifest; `unknown` if it cannot be. */
export function packageVersion(): string {
  if (cachedVersion === undefined) {
    if (
      typeof __AGENT_SAFE_PIPELINE_VERSION__ === "string" &&
      TOKEN.test(__AGENT_SAFE_PIPELINE_VERSION__)
    ) {
      cachedVersion = __AGENT_SAFE_PIPELINE_VERSION__;
      return cachedVersion;
    }
    try {
      const manifest = createRequire(import.meta.url)("../../package.json") as {
        readonly version?: unknown;
      };
      cachedVersion =
        typeof manifest.version === "string" && TOKEN.test(manifest.version)
          ? manifest.version
          : "unknown";
    } catch {
      cachedVersion = "unknown";
    }
  }
  return cachedVersion;
}

/**
 * The `User-Agent` a hosted call carries: the package and its version, and
 * when the caller says where the integration came from, that too. A value
 * the header could not carry verbatim is left out rather than escaped.
 */
export function userAgent(source: ClientSource = {}): string {
  const product = `${PRODUCT}/${packageVersion()}`;
  const comment = [
    ["repo", source.repo],
    ["example", source.example],
  ]
    .filter(
      (entry): entry is [string, string] => typeof entry[1] === "string" && TOKEN.test(entry[1]),
    )
    .map(([key, value]) => `${key}=${value}`)
    .join("; ");
  return comment === "" ? product : `${product} (${comment})`;
}
