import { describe, expect, it } from "vitest";
import * as surface from "../src/Index.js";

describe("public surface", () => {
  it("exports exactly the documented names", () => {
    expect(Object.keys(surface).sort()).toEqual([
      "CONFIG_KEYS",
      "EscalationHandoffSchema",
      "EscalationResolver",
      "ExecutorConfigLoader",
      "ExecutorHttpServer",
      "FORWARD_REQUEST_ACTION",
      "LineAuditSink",
      "MAX_BODY_BYTES",
      "ProposalRequestSchema",
      "REGISTERED_ACTIONS",
      "RESPONSE_HEADERS",
      "ROUTES",
      "ReconciliationRequestSchema",
      "SECRET_KEYS",
      "SecretStore",
      "ServiceError",
      "TrustedExecutorService",
      "createTrustedExecutor",
      "forwardRequestHandlers",
      "nodeProcess",
      "registerHandlers",
      "serve",
    ]);
  });
});
