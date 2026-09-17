import { createRequire } from "node:module";

const TOKEN = /^[\w.-]{1,64}$/;

/** This package's own version, from its manifest; `0.0.0` if the manifest cannot be read. */
export function packageVersion(): string {
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
