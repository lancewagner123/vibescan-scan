// CHECK 8 positive control -- client-side file reading an env var via a computed key that
// is a bare IDENTIFIER (process.env[keyVar]). This IS what COMPUTED_ENV_ACCESS_RE catches,
// so it SHOULD be flagged. Establishes that the computed-env defense works for the
// identifier shape, isolating the gap the next two fixtures demonstrate.
'use client';

const keyName = 'SUPABASE_SERVICE_ROLE_KEY';
const key = process.env[keyName];

export function makeAdminClient() {
  return createClient('https://x.supabase.co', key);
}
