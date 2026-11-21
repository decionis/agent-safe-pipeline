import { describe, expect, it } from "vitest";
import { CARDS_COMMANDS, runCards } from "../../src/cli/Cards.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const lastJson = (lines: readonly string[]): Record<string, unknown> =>
  JSON.parse(lines.at(-1) ?? "null") as Record<string, unknown>;

describe("agentsafe cards holds-schema", () => {
  it("prints the DDL for the shared hold store, under the default prefix or the operator's", async () => {
    const io = fakeProcess();
    await runCards(io, ["holds-schema"]);
    expect(io.exits).toEqual([0]);
    const ddl = io.out.join("");
    expect(ddl).toContain("CREATE TABLE IF NOT EXISTS agentsafe_card_holds (");
    expect(ddl).toContain("CREATE TABLE IF NOT EXISTS agentsafe_card_claims (");
    expect(ddl).toContain("CREATE TABLE IF NOT EXISTS agentsafe_card_activity (");
    const named = fakeProcess();
    await runCards(named, ["holds-schema", "--table", "bank.cards"]);
    expect(named.exits).toEqual([0]);
    expect(named.out.join("")).toContain("CREATE TABLE IF NOT EXISTS bank.cards_holds (");
  });

  it("refuses a prefix it would have to escape, an unknown option, and an unknown command", async () => {
    const bad = fakeProcess();
    await runCards(bad, ["holds-schema", "--table", "Cards;drop"]);
    expect(bad.exits).toEqual([2]);
    expect(lastJson(bad.err)).toEqual({
      event: "CARDS_USAGE",
      command: "holds-schema",
      code: "TABLE_INVALID",
    });
    const option = fakeProcess();
    await runCards(option, ["holds-schema", "--schema", "x"]);
    expect(option.exits).toEqual([2]);
    expect(lastJson(option.err)).toMatchObject({
      event: "CARDS_USAGE",
      code: "UNKNOWN_OPTION: schema",
    });
    const unknown = fakeProcess();
    await runCards(unknown, ["replay-schema"]);
    expect(unknown.exits).toEqual([2]);
    expect(lastJson(unknown.err)).toEqual({
      event: "CARDS_COMMAND_REQUIRED",
      commands: [...CARDS_COMMANDS],
    });
    const none = fakeProcess();
    await runCards(none, []);
    expect(none.exits).toEqual([2]);
  });
});

describe("agentsafe cards stripe-bridge", () => {
  const env = {
    STRIPE_BRIDGE_LIVEMODE: "false",
    STRIPE_BRIDGE_STRIPE_VERSION: "2025-03-31.basil",
    STRIPE_BRIDGE_WEBHOOK_SECRETS_FILE: "/secrets/stripe",
    STRIPE_BRIDGE_EXECUTOR_URL: "https://executor.example",
    STRIPE_BRIDGE_EXECUTOR_TOKEN_FILE: "/secrets/operator",
  };

  it("refuses to start without its settings, naming the one that is missing", async () => {
    const io = fakeProcess({ env: { ...env, STRIPE_BRIDGE_LIVEMODE: undefined } });
    await runCards(io, ["stripe-bridge"]);
    expect(io.exits).toEqual([2]);
    expect(lastJson(io.err)).toEqual({
      event: "STRIPE_BRIDGE_CONFIG",
      code: "STRIPE_BRIDGE_LIVEMODE_REQUIRED",
    });
  });

  it("refuses a secrets file it cannot read, and never prints a secret", async () => {
    const io = fakeProcess({ env, files: { "/secrets/operator": "operator-token" } });
    await runCards(io, ["stripe-bridge"]);
    expect(io.exits).toEqual([2]);
    expect(lastJson(io.err)).toEqual({
      event: "STRIPE_BRIDGE_CONFIG",
      code: "STRIPE_BRIDGE_FILE_UNREADABLE",
    });
    expect(io.err.join("")).not.toContain("operator-token");
  });
});
