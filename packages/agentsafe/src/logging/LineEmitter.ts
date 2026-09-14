import type { LineWriter } from "../audit/LineAuditSink.js";
import type { Redactor } from "../secrets/Redactor.js";

export interface LineSinks {
  readonly stdout: LineWriter;
  readonly stderr: LineWriter;
}

/**
 * The one way a line leaves the process. Audit and process lines go to
 * stdout, security lines to stderr, every one of them through the redactor
 * first. A redaction is reported through `onRedaction` so the security stream
 * can say that something was caught; it never stops the line, because a
 * caller-shaped correlation id that looks like a token must not be a way to
 * silence the evidence stream.
 */
export class LineEmitter {
  private onRedaction: ((patterns: readonly string[]) => void) | null = null;

  public constructor(
    private readonly sinks: LineSinks,
    private readonly redactor: Redactor,
  ) {}

  public reportRedactions(listener: (patterns: readonly string[]) => void): void {
    this.onRedaction = listener;
  }

  public readonly audit: LineWriter = (line) => {
    this.sinks.stdout(this.redacted(line));
  };

  public readonly process: LineWriter = (line) => {
    this.sinks.stdout(this.redacted(line));
  };

  public readonly security: LineWriter = (line) => {
    this.sinks.stderr(this.redacted(line));
  };

  private redacted(line: string): string {
    const redaction = this.redactor.redact(line);
    if (redaction.patterns.length > 0) this.onRedaction?.(redaction.patterns);
    return redaction.line;
  }
}
