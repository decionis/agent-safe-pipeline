import { randomBytes, randomUUID } from "node:crypto";
import { request } from "node:https";
import type { Duplex } from "node:stream";
import type { TcpBinding, TcpControl, TcpGrant } from "../../src/egress/TcpControlClient.js";
import { TlsListener } from "../../src/http/TlsListener.js";
import { SecurityEvents } from "../../src/incident/SecurityEvents.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";
import type { TestCertificateAuthority } from "./TestCertificateAuthority.js";

export const ROUTE = "00000000-0000-4000-8000-000000000001";
export const ORG = "00000000-0000-4000-8000-000000000002";
export const TENANT = "acme.decionisedge.com";
export const token = (): string => randomBytes(32).toString("base64url");
export class TestTcpControl implements TcpControl {
  public readonly tickets = new Map<string, TcpGrant>();
  public readonly redeemed: TcpBinding[] = [];
  public readonly released: TcpGrant[] = [];
  public refreshRefused = false;
  public readiness = true;
  public ttl = 30_000;
  public refreshOverride: Partial<TcpGrant> = {};
  public issue(role: "connector" | "client", overrides: Partial<TcpGrant> = {}): string {
    const key = token();
    this.tickets.set(key, {
      lease_id: randomUUID(),
      lease_token: token(),
      org_id: ORG,
      route_id: ROUTE,
      tenant_host: TENANT,
      role,
      resource_hash: "a".repeat(64),
      generation: 1,
      expires_at: new Date(Date.now() + this.ttl).toISOString(),
      ...overrides,
    });
    return key;
  }
  public async redeem(key: string, binding: TcpBinding): Promise<TcpGrant> {
    this.redeemed.push(binding);
    const grant = this.tickets.get(key);
    this.tickets.delete(key);
    if (!grant) throw new Error("refused");
    return grant;
  }
  public async refresh(grant: TcpGrant): Promise<TcpGrant> {
    if (this.refreshRefused) throw new Error("revoked");
    return {
      ...grant,
      expires_at: new Date(Date.now() + this.ttl).toISOString(),
      ...this.refreshOverride,
    };
  }
  public async close(grant: TcpGrant): Promise<void> {
    this.released.push(grant);
  }
  public async ready(): Promise<boolean> {
    return this.readiness;
  }
}
export function testTls(ca: TestCertificateAuthority, dns = ["*.decionisedge.com"]): TlsListener {
  const cert = ca.issueServer(dns);
  const key = SecretHandle.fromString("test-key", cert.key);
  return new TlsListener({
    minVersion: "TLSv1.2",
    events: new SecurityEvents(() => undefined),
    material: () => ({ cert: cert.cert, key, clientCa: null }),
  });
}
export function connectLeg(
  port: number,
  ca: TestCertificateAuthority,
  key: string,
  role: "connector" | "client",
  options: {
    host?: string;
    servername?: string;
    authority?: string;
    headers?: Record<string, string>;
  } = {},
): Promise<{ status: number; socket: Duplex; head: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: "127.0.0.1",
      port,
      ca: ca.certificate,
      servername: options.servername ?? "tcp-broker.decionisedge.com",
      method: "CONNECT",
      path: options.authority ?? `${ROUTE}:443`,
      agent: false,
      headers: {
        host: options.host ?? TENANT,
        authorization: `Bearer ${key}`,
        "agentsafe-tcp-role": role,
        ...options.headers,
      },
    });
    req.on("error", reject);
    req.on("connect", (response, socket, head) => {
      socket.pause();
      socket.allowHalfOpen = true;
      socket.on("error", () => undefined);
      resolve({ status: response.statusCode ?? 0, socket, head });
      if (response.statusCode !== 200) socket.destroy();
    });
    req.end();
  });
}
export function readBytes(socket: Duplex, initial: Buffer, amount: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let bytes: Buffer = initial;
    const finish = (): void => {
      clearTimeout(timer);
      socket.pause();
      socket.off("data", data);
      socket.off("close", close);
    };
    const data = (chunk: Buffer): void => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length >= amount) {
        finish();
        resolve(bytes);
      }
    };
    const close = (): void => {
      finish();
      reject(new Error("closed before data"));
    };
    const timer = setTimeout(() => {
      finish();
      reject(new Error("data timeout"));
    }, 2_000);
    socket.on("data", data);
    socket.once("close", close);
    if (bytes.length >= amount) {
      finish();
      resolve(bytes);
    } else socket.resume();
  });
}
