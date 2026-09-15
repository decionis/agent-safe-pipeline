import type { AuditEventV1, AuditSink } from "@decionis/agent-safe-pipeline";
import { RequestContext, type RequestScope } from "../http/RequestContext.js";
import type { HashChain } from "./HashChain.js";
import { LineAuditSink, type LineWriter } from "./LineAuditSink.js";

/** The executor's evidence stream: the pipeline's audit fields, the caller, and the chain. */
export const EVIDENCE_STREAM = "agent-safe.executor-evidence/1";

/**
 * The audit sink the executor runs: every lifecycle event as one line, with
 * the principal the request was authenticated as, linked on the evidence
 * chain. `agent-safe.audit/1` is the recorder's contract and is unchanged;
 * this is the executor's envelope around it, `agent-safe.executor-evidence/1`.
 * Writing is synchronous, so the recorder's timeout can never interleave two
 * lines' sequence numbers.
 */
export class HashChainedAuditSink implements AuditSink {
  public constructor(
    private readonly emit: LineWriter,
    private readonly chain: HashChain,
    private readonly scope: () => RequestScope | null = () => RequestContext.current(),
  ) {}

  public write(event: AuditEventV1): void {
    this.chain.link(
      { ...LineAuditSink.fields(event), caller_principal: this.scope()?.principal ?? null },
      this.emit,
    );
  }
}
