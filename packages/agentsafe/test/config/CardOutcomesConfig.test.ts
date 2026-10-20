import { describe, expect, it } from "vitest";
import { CONFIG_KEYS, SECRET_KEYS } from "../../src/config/ConfigKeys.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { offlineEnvironment } from "../support/Environment.js";
import { ORG_ID, PRODUCER_TOKEN } from "../support/CardOutcomeFacts.js";

const refusal = (env: Record<string, string>): string => {
  try {
    ExecutorConfigLoader.load(env);
  } catch (error) {
    return (error as Error).message;
  }
  throw new Error("expected a refusal");
};

const DIR = "/var/lib/agent-safe/card-outcomes";

describe("the card outcome evidence configuration", () => {
  it("is off unless the deployment names a mode, and off takes none of its settings", () => {
    const base = offlineEnvironment();
    const config = ExecutorConfigLoader.load(base);
    expect(config.cards.outcomes).toEqual({ mode: "off" });
    expect(config.secrets.required).not.toContain("DECIONIS_PRODUCER_TOKEN");
    expect(
      refusal({
        ...base,
        EXECUTOR_CARD_OUTCOMES_DIR: DIR,
        DECIONIS_PRODUCER_TOKEN: PRODUCER_TOKEN,
      }),
    ).toBe(
      "CONFIG_INVALID: EXECUTOR_CARD_OUTCOMES (off with EXECUTOR_CARD_OUTCOMES_DIR, DECIONIS_PRODUCER_TOKEN)",
    );
    expect(refusal({ ...base, EXECUTOR_CARD_OUTCOMES: "on" })).toBe(
      "CONFIG_INVALID: EXECUTOR_CARD_OUTCOMES",
    );
  });

  it("records into a directory, and takes nothing that only publishing needs", () => {
    const base = { ...offlineEnvironment(), EXECUTOR_CARD_OUTCOMES: "record" };
    expect(refusal(base)).toBe(
      "CONFIG_INVALID: EXECUTOR_CARD_OUTCOMES_DIR (required to record card outcomes)",
    );
    const config = ExecutorConfigLoader.load({ ...base, EXECUTOR_CARD_OUTCOMES_DIR: DIR });
    expect(config.cards.outcomes).toEqual({ mode: "record", dir: DIR });
    expect(config.secrets.required).not.toContain("DECIONIS_PRODUCER_TOKEN");
    expect(
      refusal({
        ...base,
        EXECUTOR_CARD_OUTCOMES_DIR: DIR,
        EXECUTOR_CARD_OUTCOMES_ORG_ID: ORG_ID,
        DECIONIS_PRODUCER_TOKEN_FILE: "/var/run/agent-safe/secrets/producer",
      }),
    ).toBe(
      "CONFIG_INVALID: EXECUTOR_CARD_OUTCOMES (record with EXECUTOR_CARD_OUTCOMES_ORG_ID, DECIONIS_PRODUCER_TOKEN_FILE)",
    );
    expect(refusal({ ...base, EXECUTOR_CARD_OUTCOMES_DIR: "relative/dir" })).toBe(
      "CONFIG_INVALID: EXECUTOR_CARD_OUTCOMES_DIR",
    );
  });

  it("publishes with a directory, the organization and the producer token, hourly by default", () => {
    const base = {
      ...offlineEnvironment(),
      EXECUTOR_CARD_OUTCOMES: "publish",
      EXECUTOR_CARD_OUTCOMES_DIR: DIR,
    };
    expect(refusal(base)).toBe(
      "CONFIG_INVALID: EXECUTOR_CARD_OUTCOMES_ORG_ID (required to publish card outcomes)",
    );
    expect(refusal({ ...base, EXECUTOR_CARD_OUTCOMES_ORG_ID: ORG_ID })).toBe(
      "CONFIG_SECRET_MISSING: DECIONIS_PRODUCER_TOKEN",
    );
    const env = {
      ...base,
      EXECUTOR_CARD_OUTCOMES_ORG_ID: ORG_ID,
      DECIONIS_PRODUCER_TOKEN: PRODUCER_TOKEN,
    };
    const config = ExecutorConfigLoader.load(env);
    expect(config.cards.outcomes).toEqual({
      mode: "publish",
      dir: DIR,
      orgId: ORG_ID,
      intervalSeconds: 3_600,
    });
    expect(config.secrets.required).toContain("DECIONIS_PRODUCER_TOKEN");
    expect(
      ExecutorConfigLoader.load({ ...env, EXECUTOR_CARD_OUTCOMES_INTERVAL_SECONDS: "900" }).cards
        .outcomes,
    ).toMatchObject({ intervalSeconds: 900 });
    for (const interval of ["59", "86401", "hourly"]) {
      expect(refusal({ ...env, EXECUTOR_CARD_OUTCOMES_INTERVAL_SECONDS: interval })).toBe(
        "CONFIG_INVALID: EXECUTOR_CARD_OUTCOMES_INTERVAL_SECONDS",
      );
    }
    expect(refusal({ ...env, EXECUTOR_CARD_OUTCOMES_ORG_ID: "not-an-organization" })).toBe(
      "CONFIG_INVALID: EXECUTOR_CARD_OUTCOMES_ORG_ID",
    );
    expect(
      refusal({ ...env, DECIONIS_PRODUCER_TOKEN_FILE: "/var/run/agent-safe/secrets/producer" }),
    ).toBe("CONFIG_SECRET_AMBIGUOUS: DECIONIS_PRODUCER_TOKEN");
  });

  it("lists every outcome variable and the producer token as configuration", () => {
    for (const key of [
      "EXECUTOR_CARD_OUTCOMES",
      "EXECUTOR_CARD_OUTCOMES_DIR",
      "EXECUTOR_CARD_OUTCOMES_ORG_ID",
      "EXECUTOR_CARD_OUTCOMES_INTERVAL_SECONDS",
      "DECIONIS_PRODUCER_TOKEN",
    ]) {
      expect(CONFIG_KEYS).toContain(key);
    }
    expect(SECRET_KEYS).toContain("DECIONIS_PRODUCER_TOKEN");
  });
});
