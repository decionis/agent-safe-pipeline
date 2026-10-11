import { request } from "node:https";
import { z } from "zod";
import { TCP_TICKET, TCP_UUID } from "../http/TcpRelayStreams.js";

export type TcpRole = "connector" | "client";
export interface TcpBinding {
  route_id: string;
  tenant_host: string;
  role: TcpRole;
}
const grantSchema = z.strictObject({
  lease_id: z.string().regex(TCP_UUID),
  lease_token: z.string().regex(TCP_TICKET),
  org_id: z.string().regex(TCP_UUID),
  route_id: z.string().regex(TCP_UUID),
  generation: z.number().int().positive(),
  tenant_host: z.string().max(253),
  role: z.enum(["connector", "client"]),
  resource_hash: z.string().regex(/^[a-f0-9]{64}$/),
  expires_at: z.string().datetime(),
});
export type TcpGrant = z.infer<typeof grantSchema>;
export interface TcpControl {
  redeem(ticket: string, binding: TcpBinding): Promise<TcpGrant>;
  refresh(grant: TcpGrant, phase: "waiting" | "active"): Promise<TcpGrant>;
  close(grant: TcpGrant): Promise<void>;
  ready(): Promise<boolean>;
}
class TcpControlError extends Error {
  public constructor(public readonly status: number) {
    super("TCP_CONTROL_REFUSED");
  }
}

export function validGrant(value: unknown, binding: TcpBinding, previous?: TcpGrant): TcpGrant {
  const grant = grantSchema.parse(value);
  for (const key of ["route_id", "tenant_host", "role"] as const) {
    if (grant[key] !== binding[key]) throw new Error("TCP_GRANT_BINDING_INVALID");
  }
  if (previous) {
    for (const key of [
      "lease_id",
      "lease_token",
      "org_id",
      "generation",
      "resource_hash",
    ] as const) {
      if (grant[key] !== previous[key]) throw new Error("TCP_GRANT_BINDING_INVALID");
    }
  }
  const remaining = Date.parse(grant.expires_at) - Date.now();
  if (remaining <= 250 || remaining > 35_000) throw new Error("TCP_GRANT_EXPIRY_INVALID");
  return grant;
}

/** The only broker egress: fixed HTTPS control paths, with no redirects or peer destinations. */
export class TcpControlClient implements TcpControl {
  private readonly origin: URL;
  private healthChecked = 0;
  private healthVerified = 0;
  private healthToken: string | null = null;
  private healthPending: Promise<boolean> | null = null;
  private pending = 0;
  public constructor(
    origin: string,
    private readonly token: () => string,
    private readonly ca?: string,
  ) {
    this.origin = new URL(origin);
    if (
      this.origin.protocol !== "https:" ||
      this.origin.username ||
      this.origin.password ||
      this.origin.pathname !== "/" ||
      this.origin.search ||
      this.origin.hash
    )
      throw new Error("TCP_CONTROL_API_INVALID");
  }
  public async ready(): Promise<boolean> {
    let token: string;
    try {
      token = this.serviceToken();
    } catch {
      return false;
    }
    if (token === this.healthToken && Date.now() - this.healthChecked < 10_000)
      return Date.now() - this.healthVerified < 30_000;
    if (this.healthPending) {
      await this.healthPending;
      return await this.ready();
    }
    this.healthPending = (async () => {
      try {
        const value = await this.post("health", {});
        if (
          typeof value !== "object" ||
          value === null ||
          !("transport" in value) ||
          value.transport !== "agentsafe-tcp-relay/1" ||
          !("ready" in value) ||
          value.ready !== true
        )
          throw new Error("TCP_CONTROL_UNAVAILABLE");
        this.healthVerified = Date.now();
        this.healthToken = token;
      } catch (error) {
        if (error instanceof TcpControlError && (error.status === 401 || error.status === 403))
          this.healthVerified = 0;
        // Only a still-valid prior successful proof can survive a transient outage.
      } finally {
        this.healthChecked = Date.now();
        this.healthPending = null;
      }
      return (
        this.serviceToken() === this.healthToken &&
        token === this.healthToken &&
        Date.now() - this.healthVerified < 30_000
      );
    })();
    return await this.healthPending;
  }
  public async redeem(ticket: string, binding: TcpBinding): Promise<TcpGrant> {
    return validGrant(await this.post("redeem", { ticket, ...binding }), binding);
  }
  public async refresh(grant: TcpGrant, phase: "waiting" | "active"): Promise<TcpGrant> {
    return validGrant(
      await this.post("leases/refresh", {
        lease_id: grant.lease_id,
        lease_token: grant.lease_token,
        phase,
      }),
      grant,
      grant,
    );
  }
  public async close(grant: TcpGrant): Promise<void> {
    await this.post("leases/close", { lease_id: grant.lease_id, lease_token: grant.lease_token });
  }
  private serviceToken(): string {
    const token = this.token().trim();
    if (
      token.length < 48 ||
      token.length > 512 ||
      [...token].some((char) => char.charCodeAt(0) < 33 || char.charCodeAt(0) > 126)
    )
      throw new Error("TCP_BROKER_TOKEN_INVALID");
    return token;
  }
  private async post(path: string, body: unknown): Promise<unknown> {
    const token = this.serviceToken();
    if (this.pending >= 128) throw new Error("TCP_CONTROL_CAPACITY_REACHED");
    this.pending++;
    try {
      return await new Promise((resolve, reject) => {
        const data = JSON.stringify(body);
        const req = request(
          new URL(`/v1/internal/gateway/tcp/${path}`, this.origin),
          {
            method: "POST",
            rejectUnauthorized: true,
            minVersion: "TLSv1.2",
            ...(this.ca ? { ca: this.ca } : {}),
            headers: {
              authorization: `Bearer ${token}`,
              "content-type": "application/json",
              "content-length": Buffer.byteLength(data),
            },
            agent: false,
          },
          (response) => {
            let size = 0;
            const chunks: Buffer[] = [];
            response.on("data", (chunk: Buffer) => {
              size += chunk.length;
              if (size > 16_384) req.destroy(new Error("TCP_CONTROL_RESPONSE_TOO_LARGE"));
              else chunks.push(chunk);
            });
            response.on("error", () => reject(new Error("TCP_CONTROL_UNAVAILABLE")));
            response.on("end", () => {
              clearTimeout(timer);
              if (response.statusCode !== 200)
                return reject(new TcpControlError(response.statusCode ?? 0));
              try {
                resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown);
              } catch {
                reject(new Error("TCP_CONTROL_RESPONSE_INVALID"));
              }
            });
          },
        );
        const timer = setTimeout(() => req.destroy(new Error("TCP_CONTROL_TIMEOUT")), 5_000);
        timer.unref();
        req.once("error", () => {
          clearTimeout(timer);
          reject(new Error("TCP_CONTROL_UNAVAILABLE"));
        });
        req.end(data);
      });
    } finally {
      this.pending--;
    }
  }
}
