'use strict';

// VULNERABLE (check 8: supabase-rls-disabled) -- row level security explicitly turned
// off for the tables this config manages. In a real Supabase project this means any
// client holding a valid API key (anon or otherwise, depending on which key leaks -- see
// client/src/lib/supabaseClient.js in this same fixture) can read/write every row in
// these tables with no per-row ownership check at all.
module.exports = {
  projectRef: 'vibescan-demo-fake-ref',
  tables: {
    users: { rowLevelSecurity: false },
    orders: { rowLevelSecurity: false },
  },
};
