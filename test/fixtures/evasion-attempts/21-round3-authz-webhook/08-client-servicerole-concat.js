// CHECK 8 -- FALSE NEGATIVE via split-literal concatenation inside the bracket key
// (`process.env['SUPABASE_' + 'SERVICE_ROLE_KEY']`). The contiguous literal
// "SUPABASE_SERVICE_ROLE_KEY" never appears, so SERVICE_ROLE_RE misses it; and the bracket
// content starts with a quote, so COMPUTED_ENV_ACCESS_RE (which requires a bare-identifier
// key) misses it too. Same class of split-literal evasion the secrets checks already
// handle via findStringConcatChains, never applied here. Expected (correct): FLAGGED.
'use client';

const key = process.env['SUPABASE_' + 'SERVICE_ROLE_KEY'];

export function makeAdminClient() {
  return createClient('https://x.supabase.co', key);
}
