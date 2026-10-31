import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { Gateway, GATEWAY_STREAM } from "../../src/gateway/Gateway.js";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import {
  collectedIo,
  testConfig,
  UpstreamDouble,
  type CollectedIo,
} from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const CREDENTIAL = "synthetic-upstream-credential-7f3a";
const TOKEN = "synthetic-gateway-token-91c2";
const OTHER = `sha256:${"e".repeat(64)}`;
const ANOTHER = `sha256:${"f".repeat(64)}`;

function payment(): InterceptedRequest {
  return {
    method: "POST",
    path: "/payments",
    search: "",
    headers: { host: "gateway.example", "content-type": "application/json" },
    body: Buffer.from(JSON.stringify({ amount: 500 }), "utf8"),
    remoteAddress: "127.0.0.1",
    encrypted: false,
  };
}

/** Every chained line on the gateway's own stream, in order. */
const gatewayLines = (io: CollectedIo): Record<string, unknown>[] =>
  [...io.out, ...io.err]
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => line["stream"] === GATEWAY_STREAM);
const events = (io: CollectedIo, event: string) =>
  gatewayLines(io).filter((line) => line["event"] === event);
const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 50));

describe("a gateway's fingerprint and the action space it loaded", () => {
  const upstream = new UpstreamDouble();
  const authority = new LocalAuthority({ policy: () => "ALLOW" });
  const secrets = mkdtempSync(join(tmpdir(), "agentsafe-fingerprint-"));
  const credentialFile = join(secrets, "upstream");
  const tokenFile = join(secrets, "gateway-token");

  beforeAll(async () => {
    writeFileSync(credentialFile, CREDENTIAL);
    writeFileSync(tokenFile, TOKEN);
    await upstream.start();
    await authority.start();
  });
  afterAll(async () => {
    await authority.stop();
    await upstream.stop();
    rmSync(secrets, { recursive: true, force: true });
  });

  async function gateway(mode: "enforcement" | "shadow", io: CollectedIo): Promise<Gateway> {
    const env = {
      DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
      DECIONIS_TENANT_ID: TENANT_ID,
      DECIONIS_API_URL: authority.baseUrl,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      AGENTSAFE_MODE: mode,
      AGENTSAFE_UPSTREAM_CREDENTIAL_HEADER: "authorization",
      AGENTSAFE_UPSTREAM_CREDENTIAL_FILE: credentialFile,
      AGENTSAFE_GATEWAY_TOKEN_FILE: tokenFile,
      AGENTSAFE_CONTAINMENT_TARGETS: "ledger=10.0.0.5:5432",
    };
    const file = {
      version: 1,
      interception: {
        routes: [{ path: "/payments", action: "payment.create", methods: ["POST"] }],
      },
    };
    return await Gateway.create(testConfig(upstream.baseUrl, { env, file }), {
      env,
      io,
      version: "0.0.0-test",
    });
  }

  it("records what it is when it starts, the same on every start, and never a secret", async () => {
    const io = collectedIo();
    const first = await gateway("enforcement", io);
    const again = await gateway("enforcement", collectedIo());
    try {
      first.started("http://127.0.0.1:1");
      const status = first.status();
      expect(status.fingerprint?.digest).toBe(first.fingerprint.digest);
      expect(again.fingerprint).toEqual(first.fingerprint);
      expect(status.fingerprint?.document).toMatchObject({
        upstream_identity: {
          mode: "GATEWAY_CREDENTIAL",
          header: "authorization",
          gateway_token: true,
        },
        authority: { kind: "DECIONIS", endpoint: authority.baseUrl, tenant: TENANT_ID },
        containment: ["ledger=10.0.0.5:5432"],
        routes: expect.arrayContaining([
          {
            methods: ["POST"],
            path: "/payments",
            action: "payment.create",
            mode: "ENFORCEMENT",
            failure_policy: "FAIL_CLOSED",
          },
        ]),
      });
      expect(status.action_space).toEqual({
        loaded: first.fingerprint.document.action_manifest_digest,
        release: null,
        state: "UNCHECKED",
        drifted: [],
      });
      const recorded = events(io, "DEPLOYMENT_FINGERPRINT");
      expect(recorded).toHaveLength(1);
      expect(recorded[0]).toMatchObject({
        digest: first.fingerprint.digest,
        document: JSON.parse(JSON.stringify(first.fingerprint.document)) as unknown,
      });
      expect(events(io, "GATEWAY_STARTED")[0]!["seq"]).toBe((recorded[0]!["seq"] as number) - 1);
      const metrics = first.metricsText();
      expect(metrics).toContain(
        `agentsafe_deployment_fingerprint{digest="${first.fingerprint.digest}"} 1`,
      );
      expect(metrics).toContain("agentsafe_action_space_drift 0");
      const everything = [JSON.stringify(status), metrics, ...io.out, ...io.err].join("\n");
      for (const secret of [CREDENTIAL, TOKEN, LOCAL_AUTHORITY_API_KEY]) {
        expect(everything).not.toContain(secret);
      }
    } finally {
      await first.close();
      await again.close();
    }
  });

  it("reports a release checked against another action space once per release, and decides as before", async () => {
    const io = collectedIo();
    const subject = await gateway("enforcement", io);
    const loaded = subject.fingerprint.document.action_manifest_digest;
    try {
      authority.releaseActionManifest = loaded;
      expect((await subject.govern(payment(), "payment.create")).status).toBe(201);
      expect(subject.status().action_space).toMatchObject({ release: loaded, state: "MATCH" });
      expect(events(io, "ACTION_SPACE_DRIFT")).toEqual([]);

      authority.releaseActionManifest = OTHER;
      for (let attempt = 0; attempt < 2; attempt += 1) {
        expect((await subject.govern(payment(), "payment.create")).status).toBe(201);
      }
      authority.releaseActionManifest = ANOTHER;
      expect((await subject.govern(payment(), "payment.create")).status).toBe(201);
      // A decision that names no release leaves the last answer standing.
      authority.releaseActionManifest = null;
      expect((await subject.govern(payment(), "payment.create")).status).toBe(201);

      const drifts = events(io, "ACTION_SPACE_DRIFT");
      expect(drifts.map((line) => line["release"])).toEqual([OTHER, ANOTHER]);
      expect(drifts[0]).toMatchObject({
        fingerprint: subject.fingerprint.digest,
        loaded,
        decision_id: expect.any(String),
      });
      expect(subject.status().action_space).toEqual({
        loaded,
        release: ANOTHER,
        state: "DRIFT",
        drifted: [OTHER, ANOTHER],
      });
      expect(subject.metricsText()).toContain("agentsafe_action_space_drift 1");
    } finally {
      authority.releaseActionManifest = undefined;
      await subject.close();
    }
  });

  it("compares what a shadow gateway observes, and forwards unchanged", async () => {
    const io = collectedIo();
    const shadow = await gateway("shadow", io);
    try {
      authority.releaseActionManifest = OTHER;
      expect((await shadow.govern(payment(), "payment.create")).status).toBe(201);
      await settle();
      expect(events(io, "ACTION_SPACE_DRIFT").map((line) => line["release"])).toEqual([OTHER]);
      expect(shadow.status().action_space?.state).toBe("DRIFT");
    } finally {
      authority.releaseActionManifest = undefined;
      await shadow.close();
    }
  });
});
