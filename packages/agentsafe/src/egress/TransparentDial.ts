/**
 * The interceptor's egress: a plain TCP connection to the destination a
 * redirected client named in its own first bytes. This is the one place the
 * process opens an outbound socket that `EgressPolicy` does not seal, and it
 * is so on purpose: in the observe phase the interceptor forwards a connection
 * to exactly what the client asked for, or to nothing, and decides nothing
 * about the destination itself. What it reaches is therefore what the
 * workload reaches, which is the point of observing; the ledger is the record.
 * The governor, which terminates TLS and asks the authority, leaves this dial
 * to the destinations it does not govern; a governed destination is reached
 * by its gateway's own upstream client, and the authority by the sealed
 * egress.
 */
import { connect, type Socket } from "node:net";

/** Opens a connection to a destination, or rejects within the timeout with a coded error. */
export type Dial = (host: string, port: number, timeoutMs: number) => Promise<Socket>;

export const transparentDial: Dial = (host, port, timeoutMs) =>
  new Promise((resolve, reject) => {
    const socket = connect({ host, port, allowHalfOpen: true });
    const fail = (error: Error): void => {
      clearTimeout(timer);
      reject(error);
    };
    const timer = setTimeout(() => {
      socket.removeListener("error", fail);
      socket.destroy();
      reject(Object.assign(new Error("CONNECT_TIMEOUT"), { code: "CONNECT_TIMEOUT" }));
    }, timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.removeListener("error", fail);
      resolve(socket);
    });
    socket.once("error", fail);
  });
