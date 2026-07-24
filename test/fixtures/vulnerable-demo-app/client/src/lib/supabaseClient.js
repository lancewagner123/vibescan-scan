// VibeScan test fixture -- written to look like real frontend/browser code (the kind
// bundled by Vite/webpack into a shipped JS bundle), because that's exactly the shape
// this check targets.
//
// VULNERABLE (check 8: supabase-rls-disabled, "service_role key referenced from
// client-side code" variant) -- this file exports a createClient() call meant to be
// imported by browser components, but it's initialized with the Supabase *service_role*
// key. That key bypasses row level security entirely and must never leave a trusted
// server; putting it here means it ends up in the public browser bundle for anyone to
// read via devtools.
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://vibescan-demo-fake-ref.supabase.co';

// Fake JWT -- correct three-part shape/header for a Supabase service_role token, but the
// payload and signature are fabricated filler, not a real credential.
const SUPABASE_SERVICE_ROLE_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwicmVmIjoidmliZXNjYW4tZGVtby1mYWtlLXJlZiJ9.FAKESIGNATUREdoNotUse00000000';

export const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
