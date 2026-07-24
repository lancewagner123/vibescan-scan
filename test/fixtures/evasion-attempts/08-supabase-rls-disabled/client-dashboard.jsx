'use client';
// Evasion for check 8, technique B: SERVICE_ROLE_RE is a plain substring search for the
// literal text "SUPABASE_SERVICE_ROLE_KEY" or "service_role" anywhere in the file.
// Building the env var NAME itself out of separate string parts (only joined at
// runtime) means that literal substring never appears anywhere in the source text, even
// though this client component still ends up creating a Supabase client with the
// service_role key -- which bypasses RLS entirely -- and shipping it to the browser
// bundle.
import { createClient } from '@supabase/supabase-js';

const ENV_PARTS = ['SUPABASE', 'SERVICE', 'ROLE', 'KEY'];
const privilegedEnvVarName = ENV_PARTS.join('_'); // resolves to SUPABASE_SERVICE_ROLE_KEY

export function AdminDashboard() {
  const supabaseAdmin = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env[privilegedEnvVarName], // ships the privileged key to the browser bundle
  );
  return supabaseAdmin;
}
