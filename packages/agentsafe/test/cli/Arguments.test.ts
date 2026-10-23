import { describe, expect, it } from "vitest";
import {
  ArgumentError,
  optionPort,
  optionValue,
  optionValues,
  parseArguments,
} from "../../src/cli/Arguments.js";

const spec = { valued: ["upstream", "port"], flags: ["verbose"] };

describe("the argument parser", () => {
  it("reads valued options in both spellings, flags, positionals, and the rest after --", () => {
    const parsed = parseArguments(
      [
        "--upstream",
        "http://localhost:1",
        "--port=8080",
        "--verbose",
        "chain",
        "--",
        "--not-an-option",
      ],
      spec,
    );
    expect(optionValue(parsed, "upstream")).toBe("http://localhost:1");
    expect(optionPort(parsed, "port")).toBe(8080);
    expect(parsed.options.get("verbose")).toBe(true);
    expect(parsed.positionals).toEqual(["chain", "--not-an-option"]);
    expect(optionValue(parsed, "verbose")).toBeUndefined();
    expect(optionPort(parsed, "missing")).toBeUndefined();
  });

  it("keeps every value of an option given more than once, in order, and the last as its value", () => {
    const parsed = parseArguments(["--upstream", "a", "--upstream=b", "--port", "1"], spec);
    expect(optionValues(parsed, "upstream")).toEqual(["a", "b"]);
    expect(optionValue(parsed, "upstream")).toBe("b");
    expect(optionValues(parsed, "port")).toEqual(["1"]);
    expect(optionValues(parsed, "verbose")).toEqual([]);
  });

  it("refuses unknown options, a valued option without a value, a flag with one, and a port that is not one", () => {
    expect(() => parseArguments(["--colour"], spec)).toThrow(
      new ArgumentError("UNKNOWN_OPTION", "colour").message,
    );
    expect(() => parseArguments(["--upstream"], spec)).toThrow("VALUE_REQUIRED: upstream");
    expect(() => parseArguments(["--upstream", "--verbose"], spec)).toThrow(
      "VALUE_REQUIRED: upstream",
    );
    expect(() => parseArguments(["--verbose=yes"], spec)).toThrow("VALUE_INVALID: verbose");
    for (const port of ["0", "70000", "eight", "80.5"]) {
      expect(() => optionPort(parseArguments(["--port", port], spec), "port")).toThrow(
        "VALUE_INVALID: port",
      );
    }
  });
});
