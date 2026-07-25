// Positive control -- NOT a false positive. Overcorrection guard: a genuine Supabase
// service_role key (bypasses Row Level Security entirely -- a real leaked credential,
// unlike the anon/publishable key reconstructed elsewhere in this folder) must still be
// flagged by secret-hardcoded-generic at full severity. Prefixed with an underscore so
// it sorts away from the actual false-positive fixtures and is unmistakably a control.

import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://abcdefghijklmnop.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.FAKESIGNATUREFAKESIGNATUREFAKESIGNATURE1234567890';

// Deliberately unsafe (server-side admin client using the service_role key) -- this is
// exactly the pattern that must keep getting flagged.
export const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
