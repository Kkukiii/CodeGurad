export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

type BrowserEnv = Partial<Record<"VITE_SUPABASE_URL" | "VITE_SUPABASE_PUBLISHABLE_KEY" | "VITE_API_BASE_URL", string>>;

function required(name: "VITE_SUPABASE_URL" | "VITE_SUPABASE_PUBLISHABLE_KEY", env: BrowserEnv): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new ConfigurationError(`Missing ${name}. Add it to the frontend environment configuration.`);
  }
  return value;
}

export function loadConfig(env: BrowserEnv): { supabaseUrl: string; supabasePublishableKey: string; apiBaseUrl: string } {
  return {
    supabaseUrl: required("VITE_SUPABASE_URL", env),
    supabasePublishableKey: required("VITE_SUPABASE_PUBLISHABLE_KEY", env),
    apiBaseUrl: (env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, ""),
  };
}

export function getConfig() {
  return loadConfig(import.meta.env);
}
