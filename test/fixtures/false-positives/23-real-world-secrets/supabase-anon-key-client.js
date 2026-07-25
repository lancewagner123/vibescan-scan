// Reconstructed (anonymized/generic) from the real-world false-positive validation
// exercise (docs/REAL_WORLD_VALIDATION.md, §5.1) -- the single largest source of real
// false positives (~14 of 45). Multiple independently-sourced Lovable/Bolt/Supabase-stack
// repos hardcode the Supabase client's "publishable"/anon key exactly like this. This is
// the SAFE, by-design pattern: Supabase's own documented architecture ships this key in
// client bundles and enforces access control server-side via Row Level Security, not by
// keeping the string secret. Decoding the JWT payload confirms "role":"anon" -- it must
// NOT be flagged as a leaked credential.

import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://abcdefghijklmnop.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.FAKESIGNATUREFAKESIGNATUREFAKESIGNATURE1234567890';

export const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);

// Same key, passed inline with no intervening keyname-bearing variable at all -- just
// jwt-shaped-token matching on the literal itself.
export const supabaseInline = createClient(
  SUPABASE_URL,
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.FAKESIGNATUREFAKESIGNATUREFAKESIGNATURE1234567890',
);
