import type { SecretHandle } from "../secrets/SecretHandle.js";
import type { DownstreamCredential } from "./DownstreamCredential.js";

/**
 * The downstream expects one header carrying a static value, prefix included,
 * as the reference deployment does. The value is read from the current
 * handle at each dispatch, so a rotated credential is used from the next
 * request on, and the string exists only for the request that carries it.
 */
export class StaticHeaderCredential implements DownstreamCredential {
  public readonly kind = "STATIC_HEADER";

  public constructor(
    private readonly headerName: string,
    private readonly secret: () => SecretHandle,
  ) {}

  public headersFor(): Promise<Readonly<Record<string, string>>> {
    return Promise.resolve({
      [this.headerName]: this.secret().use((value) => value.toString("utf8")),
    });
  }
}
