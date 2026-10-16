import { describe, expect, it } from "vitest";
import { validateSource } from "./validation";

describe("source validation", () => {
  it("accepts Python and Java source filenames", () => {
    expect(() => validateSource("print('ok')", "check.py")).not.toThrow();
    expect(() => validateSource("class Check {}", "Check.java")).not.toThrow();
  });

  it("rejects unsupported files and empty code", () => {
    expect(() => validateSource("echo unsafe", "script.sh")).toThrow();
    expect(() => validateSource("", "check.py")).toThrow();
  });
});