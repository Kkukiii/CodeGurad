import { describe, expect, it } from "vitest";
import { ConfigurationError, loadConfig } from "./config";

describe("browser configuration", () => {
  it("fails clearly when Supabase configuration is missing", () => {
    expect(() => loadConfig({})).toThrow(ConfigurationError);
    expect(() => loadConfig({})).toThrow("Missing VITE_SUPABASE_URL");
  });

  it("loads configuration without exposing values in errors", () => {
    const result = loadConfig({ VITE_SUPABASE_URL: "https://example.supabase.co", VITE_SUPABASE_PUBLISHABLE_KEY: "public-key", VITE_API_BASE_URL: "https://api.example.test/" });
    expect(result.apiBaseUrl).toBe("https://api.example.test");
  });
});