import { describe, expect, it } from "vitest";
import { normaliseFingerprint, peerIdentity } from "../../src/identity/PeerIdentity.js";

describe("peerIdentity", () => {
  it("reads nothing from a plain socket or a TLS socket that presented no certificate", () => {
    expect(peerIdentity({})).toBeNull();
    expect(peerIdentity({ authorized: false, getPeerCertificate: () => ({}) })).toBeNull();
  });

  it("reads the URI names, the fingerprint, and whether the chain was authorized", () => {
    const socket = {
      authorized: true,
      getPeerCertificate: () => ({
        subjectaltname:
          "URI:spiffe://synthetic.example/ns/agents/sa/workflow, DNS:workflow.agents.svc, URI:https://second.example/id",
        fingerprint256: "AB:CD:EF:01",
      }),
    };
    expect(peerIdentity(socket)).toEqual({
      authorized: true,
      sanUris: ["spiffe://synthetic.example/ns/agents/sa/workflow", "https://second.example/id"],
      fingerprint: "abcdef01",
    });
    expect(peerIdentity({ ...socket, authorized: false })?.authorized).toBe(false);
    expect(
      peerIdentity({ authorized: true, getPeerCertificate: () => ({ fingerprint256: "00" }) }),
    ).toEqual({
      authorized: true,
      sanUris: [],
      fingerprint: "00",
    });
    expect(normaliseFingerprint("A1:B2")).toBe("a1b2");
  });
});
