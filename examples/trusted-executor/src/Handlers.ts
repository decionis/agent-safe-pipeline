import { forwardRequestHandlers, type HandlerRegistration } from "@decionis/agentsafe";

/**
 * The seam an adopter edits. Everything registered through it runs only
 * behind a claimed single-use grant, with the parameters the authority
 * evaluated and nothing the agent could add afterwards. The reference
 * registration from the package forwards the verified parameters to the
 * configured downstream endpoint, carrying the downstream credential the
 * executor holds and the intent-bound idempotency key. Replace it with a
 * registration for your own provider, keeping the shape the package README
 * describes: a strict parameter schema, the side effect inside
 * `dispatch.run`, and a read-only `reconcile`.
 */
export const handlers: HandlerRegistration = forwardRequestHandlers();
