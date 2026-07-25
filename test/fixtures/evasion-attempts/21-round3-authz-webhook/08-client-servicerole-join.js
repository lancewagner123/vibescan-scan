// CHECK 8 -- FALSE NEGATIVE. This is the EXACT evasion check 8's own source comment claims
// to defend against: assembling the env var name at runtime via
// ['SUPABASE','SERVICE','ROLE','KEY'].join('_') so the literal string never appears
// contiguously. SERVICE_ROLE_RE (contiguous-literal search) misses it, AND
// COMPUTED_ENV_ACCESS_RE misses it too -- that regex only matches a bracket whose content
// is a bare identifier/member chain ([A-Za-z_$][\w.$]*), not an array-literal `.join()`
// call. So the very evasion the comment cites goes undetected. Expected (correct): FLAGGED.
'use client';

const parts = ['SUPABASE', 'SERVICE', 'ROLE', 'KEY'];
const key = process.env[parts.join('_')];

export function makeAdminClient() {
  return createClient('https://x.supabase.co', key);
}
