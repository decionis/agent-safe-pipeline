import { readFileSync } from "node:fs";
import type {
  StripeBridgeConfig,
  StripeBridgeMode,
  StripeUndecidedRule,
} from "./StripeIssuingBridge.js";

/** Stripe waits two seconds; the bridge's budget must leave it room to answer. */
const DEADLINE_BOUNDS = { min: 100, max: 1_800, default: 1_500 } as const;
const STRIPE_VERSION = /^\d{4}-\d{2}-\d{2}(?:\.[a-z]+)?$/;

export class StripeBridgeConfigError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "StripeBridgeConfigError";
  }
}

export interface StripeBridgeSettings extends StripeBridgeConfig {
  readonly host: string;
  readonly port: number;
  readonly executorUrl: string;
  readonly executorTokenFile: string;
}

/**
 * The bridge's settings from the environment. Secrets are files, never values in the
 * environment: `STRIPE_BRIDGE_WEBHOOK_SECRETS_FILE` (one signing secret per line, so a rolled
 * secret and its successor can both be live) and `STRIPE_BRIDGE_EXECUTOR_TOKEN_FILE`.
 */
export function stripeBridgeSettingsFromEnv(
  env: Readonly<Record<string, string | undefined>>,
  read: (path: string) => string = (path) => readFileSync(path, "utf8"),
): StripeBridgeSettings {
  const required = (name: string): string => {
    const value = env[name];
    if (value === undefined || value.trim() === "") {
      throw new StripeBridgeConfigError(`${name}_REQUIRED`);
    }
    return value.trim();
  };
  const mode = (env.STRIPE_BRIDGE_MODE ?? "shadow").trim();
  if (mode !== "shadow" && mode !== "enforce") {
    throw new StripeBridgeConfigError("STRIPE_BRIDGE_MODE_INVALID");
  }
  const livemode = required("STRIPE_BRIDGE_LIVEMODE");
  if (livemode !== "true" && livemode !== "false") {
    throw new StripeBridgeConfigError("STRIPE_BRIDGE_LIVEMODE_INVALID");
  }
  const stripeVersion = required("STRIPE_BRIDGE_STRIPE_VERSION");
  if (!STRIPE_VERSION.test(stripeVersion)) {
    throw new StripeBridgeConfigError("STRIPE_BRIDGE_STRIPE_VERSION_INVALID");
  }
  const deadlineMs = Number(env.STRIPE_BRIDGE_DEADLINE_MS ?? DEADLINE_BOUNDS.default);
  if (
    !Number.isInteger(deadlineMs) ||
    deadlineMs < DEADLINE_BOUNDS.min ||
    deadlineMs > DEADLINE_BOUNDS.max
  ) {
    throw new StripeBridgeConfigError("STRIPE_BRIDGE_DEADLINE_MS_INVALID");
  }
  const onUndecided = (env.STRIPE_BRIDGE_ON_UNDECIDED ?? "stand_in").trim();
  if (onUndecided !== "stand_in" && onUndecided !== "decline") {
    throw new StripeBridgeConfigError("STRIPE_BRIDGE_ON_UNDECIDED_INVALID");
  }
  const secrets = read(required("STRIPE_BRIDGE_WEBHOOK_SECRETS_FILE"))
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (secrets.length === 0 || secrets.some((secret) => !/^whsec_\S{8,}$/.test(secret))) {
    throw new StripeBridgeConfigError("STRIPE_BRIDGE_WEBHOOK_SECRETS_INVALID");
  }
  const port = Number(env.STRIPE_BRIDGE_PORT ?? 8790);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new StripeBridgeConfigError("STRIPE_BRIDGE_PORT_INVALID");
  }
  return {
    mode: mode as StripeBridgeMode,
    livemode: livemode === "true",
    stripeVersion,
    secrets,
    deadlineMs,
    onUndecided: onUndecided as StripeUndecidedRule,
    host: (env.STRIPE_BRIDGE_HOST ?? "127.0.0.1").trim(),
    port,
    executorUrl: required("STRIPE_BRIDGE_EXECUTOR_URL"),
    executorTokenFile: required("STRIPE_BRIDGE_EXECUTOR_TOKEN_FILE"),
  };
}
