import { describe, expect, it } from "vitest";
import * as surface from "../src/Index.js";

describe("public surface", () => {
  it("exports exactly the documented names", () => {
    const expected = [
      "AuthorityClients",
      "CONFIG_KEYS",
      "CompositeSecretStore",
      "DRIFT_CHECKS",
      "EnvSecretStore",
      "EscalationHandoffSchema",
      "EscalationResolver",
      "ExecutorConfigLoader",
      "ExecutorHttpServer",
      "FORWARD_REQUEST_ACTION",
      "FileSecretStore",
      "HostPosture",
      "INSPECTED_ENVIRONMENT",
      "LineAuditSink",
      "LineEmitter",
      "MAX_BODY_BYTES",
      "MAX_LINE_BYTES",
      "MAX_SECRET_BYTES",
      "PostureError",
      "ProposalRequestSchema",
      "REGISTERED_ACTIONS",
      "RESPONSE_HEADERS",
      "ROUTES",
      "ReconciliationRequestSchema",
      "Redactor",
      "SECRET_KEYS",
      "SECURITY_STREAM",
      "SERVICE_ACCOUNT_TOKEN",
      "SecretError",
      "SecretHandle",
      "SecurityEventSchema",
      "SecurityEvents",
      "ServiceError",
      "StaticHeaderCredential",
      "TrustedExecutorService",
      "WAIVABLE_CHECKS",
      "createTrustedExecutor",
      "forwardRequestHandlers",
      "nodeProcess",
      "processFacts",
      "registerHandlers",
      "serve",
    ];
    expect(Object.keys(surface).sort()).toEqual([...expected].sort());
  });
});
