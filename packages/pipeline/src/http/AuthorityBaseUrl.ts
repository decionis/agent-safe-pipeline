export class AuthorityBaseUrl {
  public static normalize(value: string, allowInsecureLoopback = false): string {
    const normalizedValue = value.trim();
    const url = new URL(normalizedValue);
    const loopback =
      url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]";

    if (url.username || url.password) {
      throw new Error("DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS");
    }
    if (url.search || url.hash) {
      throw new Error("DECIONIS_URL_MUST_NOT_CONTAIN_QUERY_OR_FRAGMENT");
    }
    if (url.protocol !== "https:" && !(allowInsecureLoopback && loopback)) {
      throw new Error("DECIONIS_URL_MUST_USE_HTTPS");
    }

    let end = normalizedValue.length;
    while (end > 0 && normalizedValue.charCodeAt(end - 1) === 47) {
      end -= 1;
    }
    return normalizedValue.slice(0, end);
  }
}
