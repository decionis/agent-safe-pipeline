import type { PeerCertificate } from "node:tls";

/** What a client certificate asserts, as the door reads it off the socket. */
export interface PeerIdentity {
  /** Whether the certificate chains to the configured client CA. */
  readonly authorized: boolean;
  readonly sanUris: readonly string[];
  /** SHA-256 fingerprint, lower-case hex without separators. */
  readonly fingerprint: string;
}

/** The parts of a socket the door looks at; a plain socket has neither. */
export interface PeerSocket {
  readonly authorized?: boolean;
  getPeerCertificate?(): PeerCertificate | object;
}

/** Normalises a Node fingerprint, `AB:CD:…`, to the form the principals file holds. */
export function normaliseFingerprint(value: string): string {
  return value.replace(/:/g, "").toLowerCase();
}

/**
 * Reads the client certificate a connection presented, or null when it
 * presented none (a plain socket, or a TLS socket the kubelet's probe
 * opened). The SAN URIs are the names a workload identity travels under;
 * the fingerprint pins one certificate when the file asks for that.
 */
export function peerIdentity(socket: PeerSocket): PeerIdentity | null {
  if (socket.getPeerCertificate === undefined) return null;
  const certificate = socket.getPeerCertificate() as Partial<PeerCertificate>;
  if (typeof certificate.fingerprint256 !== "string") return null;
  const names = certificate.subjectaltname ?? "";
  const sanUris = names
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith("URI:"))
    .map((entry) => entry.slice("URI:".length));
  return {
    authorized: socket.authorized === true,
    sanUris,
    fingerprint: normaliseFingerprint(certificate.fingerprint256),
  };
}
