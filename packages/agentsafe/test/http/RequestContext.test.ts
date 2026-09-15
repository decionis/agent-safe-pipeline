import { describe, expect, it } from "vitest";
import { LEGACY_CALLER_PRINCIPAL, RequestContext } from "../../src/http/RequestContext.js";

describe("RequestContext", () => {
  it("carries the scope through every await of a request and nowhere else", async () => {
    expect(RequestContext.current()).toBeNull();
    const seen = await RequestContext.run({ principal: LEGACY_CALLER_PRINCIPAL }, async () => {
      await new Promise((resolve) => setTimeout(resolve, 1));
      const inner = await Promise.resolve(RequestContext.current());
      return [RequestContext.current(), inner];
    });
    expect(seen).toEqual([{ principal: "legacy-caller" }, { principal: "legacy-caller" }]);
    expect(RequestContext.current()).toBeNull();
    const nested = RequestContext.run({ principal: "outer" }, () =>
      RequestContext.run({ principal: "inner" }, () => RequestContext.current()?.principal),
    );
    expect(nested).toBe("inner");
  });
});
