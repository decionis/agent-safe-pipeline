/**
 * A credential a client reads at the moment of use.
 *
 * A deployment whose Decionis credential rotates has two choices. It can
 * rebuild every client that holds the old value, which means a request in
 * flight and the next request can disagree about which client they belong
 * to; or it can hand each client a function and let the value be read per
 * request. The second is what this type is for: the client holds no string,
 * so nothing has to be torn down when the file behind it changes.
 *
 * A plain string is still accepted, and is the right answer for a credential
 * that does not rotate inside a process's life.
 */
export type Credential = string | (() => string);

/** The reader a client keeps: a constant for a value, the caller's own for a function. */
export function credentialReader(credential: Credential): () => string {
  return typeof credential === "function" ? credential : (): string => credential;
}
