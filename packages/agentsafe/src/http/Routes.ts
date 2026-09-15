import type { OperatorScope } from "../identity/PrincipalsFile.js";
import type { Role } from "../identity/PrincipalRegistry.js";

/** The payload limit on every route, in bytes. */
export const MAX_BODY_BYTES = 100 * 1024;

export interface RouteDefinition {
  readonly method: "GET" | "POST";
  readonly path: string;
  /** Public routes answer without a principal; they carry no state. */
  readonly public: boolean;
  /** The role a principal must hold to reach the route; absent on public routes. */
  readonly role?: Role;
  /** The scope an operator must hold, on control routes. */
  readonly scope?: OperatorScope;
}

/** The whole surface. The README's table is checked against this list. */
export const ROUTES = [
  { method: "GET", path: "/health", public: true },
  { method: "GET", path: "/ready", public: true },
  { method: "POST", path: "/v1/actions", public: false, role: "PROPOSER" },
  { method: "POST", path: "/v1/reconciliations", public: false, role: "PROPOSER" },
  { method: "POST", path: "/v1/escalations", public: false, role: "PROPOSER" },
  { method: "GET", path: "/v1/control/status", public: false, role: "OPERATOR", scope: "status" },
  {
    method: "POST",
    path: "/v1/control/secrets/reload",
    public: false,
    role: "OPERATOR",
    scope: "secrets.reload",
  },
  { method: "GET", path: "/metrics", public: false, role: "OPERATOR", scope: "metrics" },
] as const satisfies readonly RouteDefinition[];

export type RoutePath = (typeof ROUTES)[number]["path"];

/** The exposition's content type; every other response is JSON. */
export const METRICS_CONTENT_TYPE = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/** Every response, success or refusal, carries the same protective headers. */
export const RESPONSE_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
} as const;
