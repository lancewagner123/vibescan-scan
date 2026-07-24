'use strict';
// Evasion for check 8 (supabase-rls-disabled), technique A: RLS is disabled through a
// differently-shaped/nested config key that none of RLS_DISABLED_PATTERNS recognizes.
// Every pattern in that list looks for the exact literal key names
// "row_level_security" / "rowLevelSecurity" / "enable_row_level_security" (or the exact
// SQL phrase "DISABLE ROW LEVEL SECURITY"). A hand-rolled or third-party migration
// config that expresses the identical toggle under a nested/abbreviated key name --
// here, `security.rls.enabled` -- is functionally identical but textually invisible to
// every regex in the list.
const tableSecurityPolicy = {
  users: {
    security: {
      rls: { enabled: false }, // <-- disables RLS; matches none of RLS_DISABLED_PATTERNS
    },
  },
};

module.exports = { tableSecurityPolicy };
