import { createClient } from "@supabase/supabase-js";
import { getConfig } from "./config";

const config = getConfig();

export const supabase = createClient(config.supabaseUrl, config.supabasePublishableKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
});
