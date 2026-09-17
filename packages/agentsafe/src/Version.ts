import { createRequire } from "node:module";

const TOKEN = /^[\w.-]{1,64}$/;

/** Defined at bundle time by the single-executable build; absent everywhere else. */
declare const __AGENTSAFE_VERSION__: string | undefined;

/**
 * This package's own version: the one the bundler defined, else the one
 * in the manifest beside the code, else `0.0.0` if neither can be read.
 */
export function packageVersion(): string {
  if (typeof __AGENTSAFE_VERSION__ === "string" && TOKEN.test(__AGENTSAFE_VERSION__)) {
    return __AGENTSAFE_VERSION__;
  }
  try {
    const manifest = createRequire(import.meta.url)("../package.json") as {
      readonly version?: unknown;
    };
    return typeof manifest.version === "string" && TOKEN.test(manifest.version)
      ? manifest.version
      : "0.0.0";
  } catch {
    return "0.0.0";
  }
}
