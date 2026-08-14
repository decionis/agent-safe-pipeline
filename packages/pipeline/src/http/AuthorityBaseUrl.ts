export class AuthorityBaseUrl {
  public static normalize(value: string, allowInsecureLoopback = false): string {
    const url = new URL(value);
    const loopback =
      url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]";

    if (url.username || url.password) {
      throw new Error("DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS");
    }
    if (url.protocol !== "https:" && !(allowInsecureLoopback && loopback)) {
      throw new Error("DECIONIS_URL_MUST_USE_HTTPS");
    }

    let end = value.length;
    while (end > 0 && value.charCodeAt(end - 1) === 47) {
      end -= 1;
    }
    return value.slice(0, end);
  }
}
