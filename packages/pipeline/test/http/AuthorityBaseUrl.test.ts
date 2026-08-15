import { describe, expect, it } from "vitest";
import { AuthorityBaseUrl } from "../../src/http/AuthorityBaseUrl.js";

describe("AuthorityBaseUrl", () => {
  it("removes trailing path separators without changing internal path separators", () => {
    expect(AuthorityBaseUrl.normalize("https://authority.example/v1////")).toBe(
      "https://authority.example/v1",
    );
    expect(AuthorityBaseUrl.normalize("https://authority.example//v1")).toBe(
      "https://authority.example//v1",
    );
  });

  it("allows insecure transport only for explicitly enabled loopback URLs", () => {
    expect(AuthorityBaseUrl.normalize("http://localhost:3001/", true)).toBe(
      "http://localhost:3001",
    );
    expect(() => AuthorityBaseUrl.normalize("http://authority.example")).toThrow(
      "DECIONIS_URL_MUST_USE_HTTPS",
    );
  });

  it("rejects credentials embedded in authority URLs", () => {
    expect(() => AuthorityBaseUrl.normalize("https://user:secret@authority.example")).toThrow(
      "DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS",
    );
  });

  it("rejects query strings and fragments and trims surrounding whitespace", () => {
    expect(AuthorityBaseUrl.normalize("  https://authority.example/v1/  ")).toBe(
      "https://authority.example/v1",
    );
    expect(() => AuthorityBaseUrl.normalize("https://authority.example?api_key=secret")).toThrow(
      "DECIONIS_URL_MUST_NOT_CONTAIN_QUERY_OR_FRAGMENT",
    );
    expect(() => AuthorityBaseUrl.normalize("https://authority.example#token")).toThrow(
      "DECIONIS_URL_MUST_NOT_CONTAIN_QUERY_OR_FRAGMENT",
    );
  });
});
