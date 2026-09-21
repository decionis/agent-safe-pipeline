import type { CommerceGateConfiguration } from "./Configuration.js";
import { CommerceGateError } from "./Errors.js";
import {
  HISTORICAL_API_PATH,
  HISTORICAL_RESPONSE_BYTES,
  historicalAssessmentResponse,
  historicalSourcesResponse,
  type HistoricalAssessment,
  type HistoricalSources,
  type HistoricalStart,
} from "./HistoricalContract.js";
import { MCP_SERVER_VERSION } from "./Version.js";

export interface HistoricalApi {
  sources(): Promise<HistoricalSources>;
  start(input: HistoricalStart): Promise<HistoricalAssessment>;
  assessment(id: string): Promise<HistoricalAssessment>;
}

/** The managed AWS contract has no generic request, Protocol or ERP operation. */
export class HistoricalClient implements HistoricalApi {
  constructor(
    private readonly configuration: CommerceGateConfiguration,
    private readonly doFetch: typeof fetch = fetch,
    private readonly timeoutMs: number = 10_000,
  ) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
      throw new TypeError("Historical timeout must be between 1 and 30000 milliseconds.");
    }
  }

  async sources(): Promise<HistoricalSources> {
    return historicalSourcesResponse(await this.request("/sources"));
  }
  async start(input: HistoricalStart): Promise<HistoricalAssessment> {
    const assessment = historicalAssessmentResponse(await this.request("/assessments", input));
    if (
      assessment.provenance.kind !== input.source.kind ||
      (input.source.kind === "connected_store" &&
        (assessment.provenance.kind !== "connected_store" ||
          assessment.provenance.connection_id !== input.source.connection_id))
    ) {
      throw new CommerceGateError(
        "INVALID_UPSTREAM_RESPONSE",
        "Commerce Gate returned an assessment for a different historical source.",
      );
    }
    return assessment;
  }
  async assessment(id: string): Promise<HistoricalAssessment> {
    return historicalAssessmentResponse(
      await this.request(`/assessments/${encodeURIComponent(id)}`),
      id,
    );
  }

  private async request(path: string, body?: HistoricalStart): Promise<unknown> {
    // Read-purpose resolution cannot mint local access. The server authenticates
    // the key and rechecks its grant; no organization or expiry is client-derived.
    await this.configuration.resolveAccess("read");
    const connection = this.configuration.requireApiConnection();
    if (new URL(connection.apiBaseUrl).pathname !== "/aws") {
      throw new CommerceGateError(
        "CONFIGURATION_INVALID",
        "AgentOps HTTP requires the exact /aws Commerce Gate gateway. No alternate API was called.",
      );
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.doFetch(`${connection.apiBaseUrl}${HISTORICAL_API_PATH}${path}`, {
        method: body ? "POST" : "GET",
        redirect: "error",
        signal: controller.signal,
        headers: {
          accept: "application/json",
          authorization: `Bearer ${connection.apiKey}`,
          "user-agent": `agentops-history/${MCP_SERVER_VERSION}`,
          ...(body
            ? { "content-type": "application/json", "idempotency-key": body.idempotency_key }
            : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok) {
        await response.body?.cancel();
        const code =
          response.status === 401
            ? "AUTHENTICATION_FAILED"
            : response.status === 403
              ? "AUTHORIZATION_FAILED"
              : response.status === 404
                ? "NOT_FOUND"
                : response.status === 409
                  ? "CONFLICT"
                  : response.status === 429
                    ? "RATE_LIMITED"
                    : response.status >= 500
                      ? "UPSTREAM_UNAVAILABLE"
                      : "REQUEST_REJECTED";
        throw new CommerceGateError(
          code,
          "Commerce Gate rejected the historical request. No assessment result was accepted.",
          { status: response.status, retryable: response.status === 429 || response.status >= 500 },
        );
      }
      const declared = Number(response.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > HISTORICAL_RESPONSE_BYTES) {
        await response.body?.cancel();
        throw new CommerceGateError(
          "INVALID_UPSTREAM_RESPONSE",
          "The historical response exceeded the 100 KiB safety limit.",
        );
      }
      const reader = response.body?.getReader();
      if (!reader)
        throw new CommerceGateError(
          "INVALID_UPSTREAM_RESPONSE",
          "The historical response was empty.",
        );
      const chunks: Uint8Array[] = [];
      let length = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          length += value.byteLength;
          if (length > HISTORICAL_RESPONSE_BYTES) {
            await reader.cancel();
            throw new CommerceGateError(
              "INVALID_UPSTREAM_RESPONSE",
              "The historical response exceeded the 100 KiB safety limit.",
            );
          }
          chunks.push(value);
        }
      } finally {
        reader.releaseLock();
      }
      try {
        return JSON.parse(Buffer.concat(chunks, length).toString("utf8")) as unknown;
      } catch {
        throw new CommerceGateError(
          "INVALID_UPSTREAM_RESPONSE",
          "Commerce Gate returned invalid historical JSON.",
        );
      }
    } catch (error) {
      if (error instanceof CommerceGateError) throw error;
      if (controller.signal.aborted)
        throw new CommerceGateError("UPSTREAM_TIMEOUT", "The historical request timed out.", {
          retryable: true,
        });
      throw new CommerceGateError(
        "UPSTREAM_UNREACHABLE",
        "The historical service could not be reached.",
        { retryable: true },
      );
    } finally {
      clearTimeout(timeout);
    }
  }
}
