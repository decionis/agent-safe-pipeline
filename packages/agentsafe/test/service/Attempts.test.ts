import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { forwardRequestHandlers } from "../../src/handlers/ForwardRequestHandler.js";
import type { HandlerRegistration } from "../../src/handlers/HandlerRegistration.js";
import { HaltSwitch } from "../../src/incident/HaltSwitch.js";
import { FileExecutionJournal } from "../../src/journal/FileExecutionJournal.js";
import { InMemoryExecutionJournal } from "../../src/journal/InMemoryExecutionJournal.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import {
  collectedEvents,
  loopbackEnvironment,
  openSecrets,
  proposal,
} from "../support/Environment.js";
import { ProviderDouble } from "../support/ProviderDouble.js";

const authority = new LocalAuthority();
const provider = new ProviderDouble();
const root = mkdtempSync(join(tmpdir(), "agentsafe-service-attempts-"));

beforeAll(async () => {
  await authority.start();
  await provider.start();
});

afterAll(async () => {
  await provider.stop();
  await authority.stop();
  rmSync(root, { recursive: true, force: true });
});

interface Built {
  readonly service: TrustedExecutorService;
  readonly journal: InMemoryExecutionJournal;
  readonly halt: HaltSwitch;
  readonly lines: string[];
  readonly securityLines: string[];
}

function build(
  options: {
    readonly env?: Record<string, string | undefined>;
    readonly handlers?: HandlerRegistration;
    readonly journal?: InMemoryExecutionJournal;
  } = {},
): Built {
  const env: Record<string, string> = loopbackEnvironment(
    { authority, providerBaseUrl: provider.baseUrl },
    "ENFORCEMENT",
  );
  for (const [key, value] of Object.entries(options.env ?? {})) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  const config = ExecutorConfigLoader.load(env);
  const lines: string[] = [];
  const securityLines: string[] = [];
  const events = collectedEvents(securityLines);
  const journal = options.journal ?? new InMemoryExecutionJournal();
  const halt = new HaltSwitch({
    events,
    authFailures: config.halt.authFailures,
    egressRefusals: config.halt.egressRefusals,
  });
  const service = TrustedExecutorService.create(
    config,
    openSecrets(env, config, events),
    options.handlers ?? forwardRequestHandlers(),
    { emit: (line) => lines.push(line), security: events, journal, halt },
  );
  return { service, journal, halt, lines, securityLines };
}

async function refusal(work: Promise<unknown>): Promise<ServiceError> {
  try {
    await work;
  } catch (error) {
    if (error instanceof ServiceError) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

const events = (lines: string[]): Record<string, unknown>[] =>
  lines.map((line) => JSON.parse(line) as Record<string, unknown>);

describe("the attempt journal around an execution", () => {
  it("opens the attempt, records the claim before the provider is touched, and closes it", async () => {
    const { service, journal } = build();
    const dispatches = provider.dispatches;
    const answer = await service.propose(proposal(25_00).body);
    expect(answer).toMatchObject({ outcome: "COMPLETED", executed: true });
    expect(provider.dispatches).toBe(dispatches + 1);
    const kinds = journal.all.map((record) => record.record);
    expect(kinds).toEqual(["ATTEMPT_OPENED", "GRANT_CLAIMED", "ATTEMPT_CLOSED"]);
    const [opened, claimed, closed] = journal.all;
    expect(opened).toMatchObject({
      intent_id: answer.intent_id,
      intent_hash: answer.intent_hash,
      decision_id: answer.decision_id,
      dossier_id: answer.dossier_id,
      caller_principal: "legacy-caller",
    });
    expect(claimed).toMatchObject({
      intent_id: answer.intent_id,
      grant_id: answer.authorization?.grant_id,
      expires_at: answer.authorization?.expires_at,
    });
    expect(String((claimed as { request_digest: string }).request_digest)).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    expect(closed).toMatchObject({
      outcome: "COMPLETED",
      executed: true,
      finalization: "RECORDED",
    });
    expect(await journal.openAttempts()).toEqual([]);
    service.close();
  });

  it("never dispatches when the claim cannot be journaled, and tells the authority the attempt failed", async () => {
    const { service, journal } = build();
    const dispatches = provider.dispatches;
    // The claim is the record that must never be lost: without it on disk,
    // an execution would leave nothing for a later process to reconcile.
    journal.failEvery("GRANT_CLAIMED");
    const answer = await service.propose(proposal(26_00).body);
    expect(answer.verdict).toBe("ALLOW");
    expect(answer.outcome).toBe("FAILED_BEFORE_DISPATCH");
    expect(answer.executed).toBe(false);
    expect(answer.reason_codes).toContain("HANDLER_FAILED_BEFORE_DISPATCH");
    expect(answer.finalization).toBe("RECORDED");
    expect(provider.dispatches).toBe(dispatches);
    expect(journal.all.map((record) => record.record)).toEqual([
      "ATTEMPT_OPENED",
      "ATTEMPT_CLOSED",
    ]);
    expect(journal.all.at(-1)).toMatchObject({
      outcome: "FAILED_BEFORE_DISPATCH",
      executed: false,
    });
    journal.failEvery(null);
    expect((await service.propose(proposal(26_00).body)).outcome).toBe("COMPLETED");
    service.close();
  });

  it("refuses the proposal outright when the attempt cannot be opened and a journal is required", async () => {
    const { service, journal, securityLines } = build({
      env: { EXECUTOR_JOURNAL_REQUIRED: undefined, EXECUTOR_JOURNAL_DIR: join(root, "required") },
    });
    const dispatches = provider.dispatches;
    journal.failNextAppend();
    const refused = await refusal(service.propose(proposal(27_00).body));
    expect([refused.status, refused.code]).toEqual([503, "JOURNAL_UNAVAILABLE"]);
    expect(provider.dispatches).toBe(dispatches);
    expect(events(securityLines)).toContainEqual(
      expect.objectContaining({ event: "JOURNAL_WRITE_FAILED", record: "ATTEMPT_OPENED" }),
    );
    service.close();
  });

  it("keeps the attempt open when a lost response leaves the outcome unknown, and closes it on reconciliation", async () => {
    const { service, journal } = build();
    provider.loseNext();
    const lost = await service.propose(proposal(28_00).body);
    expect(lost.outcome).toBe("UNKNOWN_AFTER_DISPATCH");
    // The attempt stays open: an outcome nobody knows is the one thing that
    // must survive into the next process.
    expect(journal.all.map((record) => record.record)).toEqual(["ATTEMPT_OPENED", "GRANT_CLAIMED"]);
    expect((await journal.openAttempts()).map((attempt) => attempt.state)).toEqual(["CLAIMED"]);
    const recovery = lost.recovery as { intent: Record<string, unknown>; reference: unknown };
    const reconciled = await service.reconcile(recovery);
    expect(reconciled.outcome).toBe("COMPLETED");
    expect(journal.all.at(-1)).toMatchObject({
      record: "RECONCILED",
      status: "COMPLETED",
      source: "CALLER",
    });
    expect(await journal.openAttempts()).toEqual([]);
    service.close();
  });

  it("writes to the file journal a second process can read back, and recovers from it read-only", async () => {
    const directory = join(root, "shared");
    const writing = new FileExecutionJournal(directory);
    const { service, journal } = build({ journal: new InMemoryExecutionJournal() });
    provider.loseNext();
    const lost = await service.propose(proposal(29_00).body);
    expect(lost.outcome).toBe("UNKNOWN_AFTER_DISPATCH");
    for (const record of journal.all) await writing.append(record);
    writing.close();
    service.close();
    // A second process over the same directory finds the attempt still open,
    // because an unknown outcome is exactly what must not be closed, and
    // resolves it by reading the provider rather than sending again.
    const reading = new FileExecutionJournal(directory);
    expect((await reading.openAttempts()).map((attempt) => attempt.state)).toEqual(["CLAIMED"]);
    const dispatches = provider.dispatches;
    const restarted = build({ journal: new InMemoryExecutionJournal() });
    const second = TrustedExecutorService.create(
      ExecutorConfigLoader.load(
        loopbackEnvironment({ authority, providerBaseUrl: provider.baseUrl }, "ENFORCEMENT"),
      ),
      openSecrets(
        loopbackEnvironment({ authority, providerBaseUrl: provider.baseUrl }, "ENFORCEMENT"),
        ExecutorConfigLoader.load(
          loopbackEnvironment({ authority, providerBaseUrl: provider.baseUrl }, "ENFORCEMENT"),
        ),
      ),
      forwardRequestHandlers(),
      { emit: () => undefined, security: collectedEvents(), journal: reading },
    );
    const report = await second.recover();
    expect(report.attempts.map((attempt) => attempt.resolution)).toEqual(["RECONCILED_COMPLETED"]);
    expect(report.unknown).toBe(0);
    expect(provider.dispatches).toBe(dispatches);
    expect(await reading.openAttempts()).toEqual([]);
    second.close();
    reading.close();
    restarted.service.close();
  });
});

describe("the halt", () => {
  it("refuses new work with the answer the caller already parses, and asks nothing of the authority", async () => {
    const { service, halt, lines, securityLines } = build();
    const grants = authority.grants.size;
    halt.halt("OPERATOR", "the treasury team asked us to stop");
    const refused = await refusal(service.propose(proposal(30_00).body));
    expect(refused.status).toBe(503);
    expect(refused.code).toBe("EXECUTOR_HALTED");
    expect(refused.retryAfterSeconds).toBe(30);
    expect(refused.body).toMatchObject({
      verdict: "BLOCK",
      outcome: "BLOCKED",
      executed: false,
      fail_closed: true,
      reason_codes: ["EXECUTOR_HALTED"],
      authorization: null,
    });
    expect(authority.grants.size).toBe(grants);
    // The refusal is evidence: the same shape the executor uses for a block.
    expect(events(lines).at(-1)).toMatchObject({
      event: "EXECUTION_BLOCKED",
      reason_codes: ["EXECUTOR_HALTED"],
    });
    expect(events(securityLines).some((event) => event["event"] === "HALTED")).toBe(true);
    service.close();
  });

  it("lets work through again once an operator resumes, and shadow observes either way", async () => {
    const { service, halt } = build();
    halt.halt("OPERATOR", "stopping to look at something");
    await refusal(service.propose(proposal(31_00).body));
    expect(halt.resume("we looked; it was nothing").resumed).toBe(true);
    const answer = await service.propose(proposal(31_00).body);
    expect(answer.outcome).toBe("COMPLETED");
    const shadow = build({ env: { EXECUTOR_MODE: "SHADOW" } });
    shadow.halt.halt("OPERATOR", "halted, but nothing executes in shadow anyway");
    const observed = await shadow.service.propose(proposal(32_00).body);
    expect(observed).toMatchObject({ mode: "SHADOW", executed: false });
    shadow.service.close();
    service.close();
  });

  it("halts on a spike of refusals at the door, and on a posture drift, without anyone wiring it up", async () => {
    const { service, securityLines } = build({
      env: { EXECUTOR_HALT_ON_AUTH_FAILURES: "2/60" },
    });
    // The service subscribes to its own security stream: an event the door
    // or the posture emits reaches the halt switch by itself.
    service.events.emit({
      event: "AUTH_FAILED",
      method: "bearer",
      code: "CALLER_NOT_AUTHENTICATED",
    });
    expect(service.haltSwitch.halted).toBe(false);
    service.events.emit({
      event: "AUTH_FAILED",
      method: "bearer",
      code: "CALLER_NOT_AUTHENTICATED",
    });
    expect(service.haltSwitch.current).toMatchObject({ trigger: "AUTH_FAILURE_SPIKE" });
    expect(events(securityLines).map((event) => event["event"])).toContain("HALTED");
    const refused = await refusal(service.propose(proposal(33_00).body));
    expect(refused.code).toBe("EXECUTOR_HALTED");
    expect(service.metrics.halts.get({ trigger: "AUTH_FAILURE_SPIKE" })).toBe(1);
    service.close();
    const drift = build();
    drift.service.events.emit({ event: "POSTURE_DRIFT", check: "PROXY_ENV" });
    expect(drift.service.haltSwitch.current).toMatchObject({
      trigger: "POSTURE_DRIFT",
      reason: "check PROXY_ENV",
    });
    expect(drift.service.metrics.halts.get({ trigger: "POSTURE_DRIFT" })).toBe(1);
    drift.service.close();
  });
});

describe("the host's own ceilings", () => {
  const limited = (overrides: Record<string, string | undefined> = {}): Built =>
    build({
      env: {
        EXECUTOR_HARD_LIMIT_SINGLE_MINOR: "USD:500000",
        EXECUTOR_HARD_LIMIT_WINDOW_SECONDS: "60",
        EXECUTOR_HARD_LIMIT_WINDOW_COUNT: "2",
        ...overrides,
      },
    });

  it("refuses an amount above the ceiling before the authority is asked at all", async () => {
    const { service, journal, lines, securityLines } = limited();
    const grants = authority.grants.size;
    const refused = await refusal(service.propose(proposal(500_001).body));
    expect([refused.status, refused.code]).toEqual([422, "HARD_LIMIT_EXCEEDED"]);
    expect(authority.grants.size).toBe(grants);
    expect(journal.all).toEqual([]);
    expect(events(lines).at(-1)).toMatchObject({
      event: "EXECUTION_BLOCKED",
      reason_codes: ["HARD_LIMIT_EXCEEDED"],
    });
    expect(events(securityLines)).toContainEqual(
      expect.objectContaining({
        event: "HARD_LIMIT_REFUSED",
        code: "HARD_LIMIT_EXCEEDED",
        currency: "USD",
      }),
    );
    expect(service.metrics.hardLimitRefusals.get({ code: "HARD_LIMIT_EXCEEDED" })).toBe(1);
    service.close();
  });

  it("refuses a currency it was never given, and counts only what it let through", async () => {
    const { service } = limited();
    const unlisted = await refusal(
      service.propose({
        ...proposal(100).body,
        proposal: {
          action: "forward_request",
          target: "payout:synthetic-beneficiary-x",
          parameters: { amountMinor: 100, currency: "CHF" },
        },
      }),
    );
    expect(unlisted.code).toBe("HARD_LIMIT_CURRENCY_UNKNOWN");
    expect((await service.propose(proposal(1_000).body)).outcome).toBe("COMPLETED");
    expect((await service.propose(proposal(1_000).body)).outcome).toBe("COMPLETED");
    const full = await refusal(service.propose(proposal(1_000).body));
    expect(full.code).toBe("HARD_LIMIT_WINDOW_COUNT_EXCEEDED");
    service.close();
  });
});
