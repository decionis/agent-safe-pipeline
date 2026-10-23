/**
 * The target's state version, end to end over a real authority stack: an
 * executor whose profile names a version-bearing read reads the target
 * before asking, the runner binds what it read into the intent, the policy
 * decides the transition on it, the authority carries the version into the
 * claim's attestation, and a verifying provider holds the write to it. The
 * target, the items API and every identifier are synthetic.
 */
import { generateKeyPairSync } from "node:crypto";
import {
  ApiProfile,
  DecionisGate,
  DecionisGrantVerifier,
  GovernedExecutionRunner,
  IntentCapture,
  ProviderRefusal,
  preconditionOf,
  type ClaimedExecution,
  type EffectObservation,
  type ExecutionCapability,
  type ExecutionEffect,
  type ExecutorScope,
  type JsonObject,
  type NativeExecutor,
  type PreparedAction,
  type ReconcileResult,
  type TargetPrecondition,
} from "@decionis/agent-safe-pipeline";
import {
  LOCAL_AUTHORITY_API_KEY,
  LOCAL_AUTHORITY_ISSUER,
  LocalAuthority,
} from "@decionis/agent-safe-pipeline/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SignedRequestCredential } from "../../src/credential/SignedRequestCredential.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";
import {
  MemoryReplayStore,
  refusalBody,
  verifyProviderRequest,
  type ProviderVerdict,
  type VerifyingProviderOptions,
} from "../../src/verify/VerifyingProvider.js";

const TENANT = "00000000-0000-4000-8000-000000000009";
const ACTOR = { id: "synthetic-change-agent", type: "AI_AGENT" };
const SCOPE: ExecutorScope = {
  orgId: TENANT,
  workspaceId: "synthetic-workspace",
  connectionId: "synthetic-connection",
  connectionRevision: "1",
  environment: "sandbox",
};
const PROVIDER_URL = "https://provider.invalid";

/** The items API: a change to an item, and the read that states its version and stage. */
const PROFILE = ApiProfile.parse({
  profile: "agent-safe.profile.api/1",
  id: "example/items/v1",
  platform: "example",
  title: "Synthetic items API",
  prefixes: [""],
  operations: [
    {
      id: "items.promote",
      method: "POST",
      path: "/items/{itemId}",
      action: "change.promote",
      summary: "Move an item to another stage.",
      facts: { item_id: "/path/itemId", stage: "/body/stage" },
      policy_projection: null,
      precondition: { read: "items.get", version: "/headers/etag", state: "/body/stage" },
    },
    {
      id: "items.get",
      method: "GET",
      path: "/items/{itemId}",
      action: "item.read",
      summary: "Read one item.",
      facts: {},
      policy_projection: null,
      subject: { response: "/body/owner" },
    },
  ],
});

/** The stages an item may move between, as the organisation's policy states them. */
const ALLOWED = new Set(["staged>live", "live>staged"]);

/** The system of record: one item, whose entity tag changes with every write. */
class Target {
  public stage = "staged";
  public revision = 17;
  public writes = 0;

  public get etag(): string {
    return `"${String(this.revision)}"`;
  }

  /** Someone else's write, between the grant and the commit. */
  public changeElsewhere(stage: string): void {
    this.stage = stage;
    this.revision += 1;
  }

  public read(path: string): { headers: Record<string, string>; body: JsonObject } {
    expect(path).toBe("/items/item-1");
    return {
      headers: { etag: this.etag },
      body: { owner: "synthetic-owner", stage: this.stage },
    };
  }
}

interface Promotion {
  readonly itemId: string;
  readonly stage: string;
}

const executorKey = generateKeyPairSync("ed25519");
const executorPem = executorKey.privateKey.export({ type: "pkcs8", format: "pem" }) as string;

/**
 * A dispatch-style executor over the profile: its read is the profile's
 * precondition read, and its write is signed for, and presented to, a
 * verifying provider that checks the target's version as it effects.
 */
class ItemExecutor implements NativeExecutor<Promotion, JsonObject, JsonObject> {
  public readonly platform = "example";
  public readonly version = "1.0.0";
  public readonly style = "dispatch";
  public readonly actionTypes = ["change.promote"];
  public readonly verdicts: ProviderVerdict[] = [];
  private readonly credential = new SignedRequestCredential(
    { algorithm: "ed25519", keyId: "synthetic-executor-1" },
    () => SecretHandle.fromString("DOWNSTREAM_SIGNING_KEY", executorPem),
  );

  public constructor(
    private readonly target: Target,
    private readonly provider: () => VerifyingProviderOptions,
    /** What happens to the target after the grant is decided and before the write. */
    private readonly meanwhile: () => void = () => undefined,
  ) {}

  public async capabilities(): Promise<readonly ExecutionCapability[]> {
    return [
      {
        platform: this.platform,
        actionType: "change.promote",
        enabled: true,
        scopeGranted: true,
        connected: true,
        requirement: "",
      },
    ];
  }

  public async prepare(action: Promotion): Promise<PreparedAction> {
    return {
      actionType: "change.promote",
      proposal: {
        action: "change.promote",
        target: `items/${action.itemId}`,
        parameters: { stage: action.stage },
      },
      downstreamTarget: { system: "example-items", operation: "items.promote" },
      idempotencyKey: `synthetic-promote-${action.itemId}-${action.stage}`,
      expectedEffectDigest: null,
      requestDigest: `sha256:${"2".repeat(64)}`,
      facts: { item_id: action.itemId },
    };
  }

  public async readState(action: Promotion): Promise<TargetPrecondition | null> {
    const read = PROFILE.stateRead({
      method: "POST",
      path: `/items/${action.itemId}`,
      body: { stage: action.stage },
    });
    return PROFILE.precondition("items.promote", this.target.read(read!.path), new Date());
  }

  public async execute(run: ClaimedExecution<Promotion>): Promise<ExecutionEffect<JsonObject>> {
    this.meanwhile();
    const body = JSON.stringify({ stage: run.action.stage });
    const path = `/items/${run.action.itemId}`;
    const headers = await this.credential.headersFor({
      method: "POST",
      url: `${PROVIDER_URL}${path}`,
      body,
      idempotencyKey: run.idempotencyKey,
      intentHash: run.intent.intentHash,
      grant: {
        id: run.authorization.grantId,
        decisionId: run.authorization.decisionId,
        claimAttestation: run.authorization.claimAttestation!,
      },
    });
    return await run.dispatch.run(async () => {
      // The provider reads its own item's version under the lock its write
      // takes, here the single thread, and hands it to the procedure.
      const verdict = verifyProviderRequest(
        { method: "POST", path, body, headers },
        this.provider(),
        { version: this.target.etag },
      );
      this.verdicts.push(verdict);
      if (!verdict.accepted) throw new ProviderRefusal(verdict.reasonCode);
      this.target.stage = run.action.stage;
      this.target.revision += 1;
      this.target.writes += 1;
      return { kind: "DISPATCHED", receipt: { ok: true } };
    });
  }

  public async observe(
    effect: ExecutionEffect<JsonObject>,
  ): Promise<EffectObservation<JsonObject>> {
    return effect.kind === "DISPATCHED" && effect.receipt?.["ok"] === true
      ? { status: "COMMITTED", reason: null, result: effect.receipt }
      : { status: "INDETERMINATE", reason: null, result: null };
  }

  public async reconcile(): Promise<ReconcileResult<JsonObject>> {
    return { status: "UNKNOWN" };
  }
}

/**
 * The policy the authority double runs: a promotion is allowed only between
 * the stages the organisation allows, from the stage the runtime read. This
 * is what a bundle's `allowed_transitions` states for the hosted engine.
 */
const authority = new LocalAuthority({
  policy: (request) => {
    const namespace = request.context["agent_safe"] as { precondition?: { state?: unknown } };
    const from = namespace?.precondition?.state;
    const to = request.action.parameters["stage"];
    if (typeof from !== "string" || typeof to !== "string") return "ESCALATE";
    return from === to || ALLOWED.has(`${from}>${to}`) ? "ALLOW" : "BLOCK";
  },
});

beforeAll(async () => {
  await authority.start();
});

afterAll(async () => {
  await authority.stop();
});

function provider(): VerifyingProviderOptions {
  return {
    effects: true,
    executorKeys: [
      {
        keyId: "synthetic-executor-1",
        algorithm: "ed25519",
        publicKeyPem: executorKey.publicKey.export({ type: "spki", format: "pem" }) as string,
      },
    ],
    authorityJwks: authority.jwks,
    authorityIssuer: LOCAL_AUTHORITY_ISSUER,
    clockWindowSeconds: 300,
    replay: new MemoryReplayStore(),
  };
}

function runner(): GovernedExecutionRunner {
  const connection = {
    baseUrl: authority.baseUrl,
    apiKey: LOCAL_AUTHORITY_API_KEY,
    allowInsecureLoopback: true,
  };
  return new GovernedExecutionRunner({
    verifier: new DecionisGrantVerifier(connection),
    authority: new DecionisGate(connection),
    capture: new IntentCapture({ ttlSeconds: 120 }),
  });
}

describe("the target's state version, from the read to the provider", () => {
  it("binds the version read before asking, and the provider effects while the target is still at it", async () => {
    const target = new Target();
    const executor = new ItemExecutor(target, provider);
    const { captured, decision, result } = await runner().submit(executor, {
      action: { itemId: "item-1", stage: "live" },
      scope: SCOPE,
      actor: ACTOR,
    });

    expect(decision.verdict).toBe("ALLOW");
    expect(result).toMatchObject({ outcome: "COMPLETED", executed: true });
    expect(preconditionOf(captured.intent.context)).toMatchObject({
      version: '"17"',
      state: "staged",
      source: "example/items/v1#items.get",
    });
    const [verdict] = executor.verdicts;
    expect(verdict?.attestation?.binding.expected_state_version).toBe('"17"');
    expect(target).toMatchObject({ stage: "live", writes: 1, etag: '"18"' });
  });

  it("refuses at the provider, effecting nothing, when the target changed between the grant and the commit", async () => {
    const target = new Target();
    // Someone else moves the item, and its version with it, after the
    // decision and before the write: the policy that allowed staged to live
    // never saw this state.
    const executor = new ItemExecutor(target, provider, () => target.changeElsewhere("staged"));
    const { decision, result } = await runner().submit(executor, {
      action: { itemId: "item-1", stage: "live" },
      scope: SCOPE,
      actor: ACTOR,
    });

    expect(decision.verdict).toBe("ALLOW");
    expect(result).toMatchObject({ outcome: "DEFINITELY_NOT_EXECUTED", executed: false });
    expect(executor.verdicts).toEqual([
      expect.objectContaining({ accepted: false, reasonCode: "TARGET_STATE_CHANGED" }),
    ]);
    expect(refusalBody("TARGET_STATE_CHANGED")).toBe(
      '{"status":"REJECTED","reason_code":"TARGET_STATE_CHANGED"}',
    );
    expect(target).toMatchObject({ stage: "staged", writes: 0, etag: '"18"' });
  });

  it("refuses a transition the policy does not allow from the state the runtime read", async () => {
    const target = new Target();
    target.stage = "retired";
    const executor = new ItemExecutor(target, provider);
    const { captured, decision, result } = await runner().submit(executor, {
      action: { itemId: "item-1", stage: "live" },
      scope: SCOPE,
      actor: ACTOR,
    });

    expect(decision.verdict).toBe("BLOCK");
    expect(result).toMatchObject({ outcome: "BLOCKED" });
    expect(preconditionOf(captured.intent.context)?.state).toBe("retired");
    expect(executor.verdicts).toEqual([]);
    expect(target.writes).toBe(0);
  });
});
