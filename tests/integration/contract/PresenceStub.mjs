/**
 * Loopback stand-in for the two Presence routes the `@decionis/presence-node`
 * human-approval gate uses: creating an intent-bound verification request and
 * polling its outcome. Receipts it issues can be verified by the authority stub
 * against the exact intent hash that was displayed to the approver, which is
 * what makes approval swapping detectable end to end.
 *
 * All identities are synthetic.
 */
import { createServer } from "node:http";

export const PRESENCE_API_KEY = "test-key";

const LOOPBACK_ORIGIN = "http://127.0.0.1";
const MAX_REQUEST_BYTES = 64 * 1024;
const SOCKET_TIMEOUT_MS = 10_000;
const INVITATION_TTL_MS = 120_000;

export class PresenceStub {
  /** Every request seen, oldest first. */
  requests = [];
  /** Receipts issued, keyed by receipt dossier id. */
  receipts = new Map();
  #verifications = new Map();
  #sequence = 0;
  #server = null;
  #port = 0;
  #pendingLookups;
  #nextStatus = "ALLOWED";

  /** @param {{ pendingLookups?: number }} options how many outcome lookups stay pending first */
  constructor(options = {}) {
    this.#pendingLookups = options.pendingLookups ?? 1;
  }

  get baseUrl() {
    return `${LOOPBACK_ORIGIN}:${this.#port}`;
  }

  async start() {
    this.#server = createServer((req, res) => {
      void this.#handle(req, res);
    });
    this.#server.setTimeout(SOCKET_TIMEOUT_MS);
    await new Promise((resolve) => this.#server.listen(0, "127.0.0.1", resolve));
    this.#port = this.#server.address().port;
  }

  async stop() {
    if (this.#server === null) return;
    this.#server.closeAllConnections();
    await new Promise((resolve) => this.#server.close(() => resolve()));
    this.#server = null;
  }

  /** Terminal status the next verification request resolves to. */
  scriptNextStatus(status) {
    this.#nextStatus = status;
  }

  /** Authority-side receipt verification: request, receipt, and displayed intent hash must all match. */
  verifyReceipt(approval, intentHash) {
    const receipt = this.receipts.get(approval.receiptDossierId);
    return (
      receipt !== undefined &&
      receipt.requestId === approval.requestId &&
      receipt.intentHash === intentHash
    );
  }

  async #handle(req, res) {
    const url = new URL(req.url ?? "/", this.baseUrl);
    const record = {
      method: req.method,
      path: url.pathname,
      headers: {
        authorization: req.headers.authorization ?? null,
        "idempotency-key": req.headers["idempotency-key"] ?? null,
      },
      body: null,
      response: null,
      at: new Date().toISOString(),
    };
    this.requests.push(record);

    const raw = await this.#readBody(req);
    if (raw === null) return this.#send(res, record, 413, { reason: "REQUEST_TOO_LARGE" });
    try {
      record.body = raw.length === 0 ? null : JSON.parse(raw);
    } catch {
      return this.#send(res, record, 400, { reason: "REQUEST_MALFORMED" });
    }
    if (req.headers.authorization !== `Bearer ${PRESENCE_API_KEY}`) {
      return this.#send(res, record, 401, { reason: "UNAUTHORIZED" });
    }

    if (req.method === "POST" && url.pathname === "/v1/verification-requests") {
      return this.#createVerificationRequest(res, record);
    }
    const lookup = url.pathname.match(/^\/v1\/verification-requests\/([^/]+)$/);
    if (req.method === "GET" && lookup !== null) {
      return this.#getVerificationRequest(res, record, decodeURIComponent(lookup[1]));
    }
    return this.#send(res, record, 404, { reason: "NOT_FOUND" });
  }

  #createVerificationRequest(res, record) {
    const body = record.body;
    const fields = body?.presentation?.display_fields;
    if (
      typeof record.headers["idempotency-key"] !== "string" ||
      typeof body?.action_context?.intent !== "string" ||
      typeof body?.originator?.actor_id !== "string" ||
      !Array.isArray(fields)
    ) {
      return this.#send(res, record, 400, { reason: "REQUEST_INVALID" });
    }
    this.#sequence += 1;
    const requestId = `synthetic-presence-request-${this.#sequence}`;
    const intentHash = fields.find((field) => field?.key === "intent_hash")?.value ?? null;
    this.#verifications.set(requestId, {
      requestId,
      intentHash,
      lookups: 0,
      terminalStatus: this.#nextStatus,
    });
    this.#nextStatus = "ALLOWED";
    return this.#send(res, record, 200, {
      request_id: requestId,
      invitation_url: `https://presence.example.invalid/approve/${requestId}`,
      invitation_expires_at: new Date(Date.now() + INVITATION_TTL_MS).toISOString(),
    });
  }

  #getVerificationRequest(res, record, requestId) {
    const verification = this.#verifications.get(requestId);
    if (verification === undefined) return this.#send(res, record, 404, { reason: "NOT_FOUND" });
    verification.lookups += 1;
    if (verification.lookups <= this.#pendingLookups) {
      return this.#send(res, record, 200, { request_id: requestId, status: "PENDING" });
    }
    if (verification.terminalStatus !== "ALLOWED") {
      return this.#send(res, record, 200, {
        request_id: requestId,
        status: verification.terminalStatus,
      });
    }
    const receiptDossierId = `synthetic-presence-receipt-${requestId.split("-").at(-1)}`;
    this.receipts.set(receiptDossierId, { requestId, intentHash: verification.intentHash });
    return this.#send(res, record, 200, {
      request_id: requestId,
      status: "ALLOWED",
      receipt_dossier_id: receiptDossierId,
    });
  }

  #send(res, record, status, body) {
    record.response = { status, body };
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  }

  async #readBody(req) {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      if (total > MAX_REQUEST_BYTES) return null;
      chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
  }
}
