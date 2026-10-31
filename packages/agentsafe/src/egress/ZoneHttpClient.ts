/**
 * The HTTP client an acceptance run's zone probes send with: straight to the
 * URL's own host, never through a proxy the environment names, following no
 * redirect, sending only the headers it is given, and reading at most the
 * bytes it is told to. A failure rejects with the socket's own `code`, and
 * `ETIMEDOUT` when the time runs out, so the probe can tell a drop from an
 * answer the way the containment probe does.
 */
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import type { ZoneHttp, ZoneResponse } from "../acceptance/ZoneProbes.js";

/** A failure with the code a probe reads. */
function failure(code: string): Error & { code: string } {
  return Object.assign(new Error(code), { code });
}

export const zoneHttp: ZoneHttp = (request) =>
  new Promise<ZoneResponse>((resolve, reject) => {
    const url = new URL(request.url);
    const send = url.protocol === "https:" ? httpsRequest : httpRequest;
    let settled = false;
    const settle = (outcome: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      outcome();
    };
    const outgoing = send(
      url,
      {
        method: request.method,
        headers: {
          ...request.headers,
          ...(request.body === null ? {} : { "content-length": Buffer.byteLength(request.body) }),
        },
        // No agent: no pooled socket, no proxy, nothing kept after the answer.
        agent: false,
      },
      (response: IncomingMessage) => {
        const chunks: Buffer[] = [];
        let size = 0;
        const answered = (): void => {
          settle(() =>
            resolve({
              status: response.statusCode ?? 0,
              body: Buffer.concat(chunks).toString("utf8"),
            }),
          );
        };
        // Enough of the body read, the rest is not waited for.
        if (request.maxBodyBytes === 0) {
          answered();
          response.destroy();
          return;
        }
        response.on("data", (chunk: Buffer) => {
          chunks.push(chunk.subarray(0, request.maxBodyBytes - size));
          size += chunk.length;
          if (size >= request.maxBodyBytes) {
            answered();
            response.destroy();
          }
        });
        response.on("end", answered);
        response.on("error", (error: Error & { code?: string }) => {
          settle(() => reject(failure(error.code ?? "ERESPONSE")));
        });
      },
    );
    const timer = setTimeout(() => {
      settle(() => reject(failure("ETIMEDOUT")));
      outgoing.destroy();
    }, request.timeoutMs);
    timer.unref();
    outgoing.on("error", (error: Error & { code?: string }) => {
      settle(() => reject(failure(error.code ?? "EREQUEST")));
    });
    outgoing.end(request.body ?? undefined);
  });
