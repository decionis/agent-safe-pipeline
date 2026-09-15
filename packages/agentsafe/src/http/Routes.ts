/** The payload limit on every route, in bytes. */
export const MAX_BODY_BYTES = 100 * 1024;

export interface RouteDefinition {
  readonly method: "GET" | "POST";
  readonly path: string;
  /** Public routes answer without the caller token; they carry no state. */
  readonly public: boolean;
  /** A route only an operator may reach; until principals exist, nobody is one. */
  readonly role?: "OPERATOR";
}

/** The whole surface. The README's table is checked against this list. */
export const ROUTES = [
  { method: "GET", path: "/health", public: true },
  { method: "GET", path: "/ready", public: true },
  { method: "POST", path: "/v1/actions", public: false },
  { method: "POST", path: "/v1/reconciliations", public: false },
  { method: "POST", path: "/v1/escalations", public: false },
  { method: "GET", path: "/metrics", public: false, role: "OPERATOR" },
] as const satisfies readonly RouteDefinition[];

/** Every response, success or refusal, carries the same protective headers. */
export const RESPONSE_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
} as const;
