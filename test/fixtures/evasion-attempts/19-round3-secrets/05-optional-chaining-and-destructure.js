'use strict';
// Round-3 evasion for check 1 (secret-hardcoded-generic), SECONDARY technique cluster:
// optional-chaining / nullish-coalescing routing, and destructure-rename. Each keeps the
// high-entropy literal on the line but ensures no key/secret-ish NAME sits immediately
// adjacent (via `:` or `=`) to that literal, which is the one shape GENERIC_ENTROPY_RE can
// match. These are facets of the documented "innocuous name / non-adjacent literal"
// limitation, made concrete with the requested syntax forms; reported honestly as such,
// not as a wholly independent mechanism.

// Nullish-coalescing fallback: the literal follows `??`, not `=`. GENERIC_ENTROPY_RE needs
// `<name> = "<literal>"` with the quote right after the `=`; here `getKey() ?? ` sits in
// between, so it never fires -- even though `apiKey` is a textbook secret-ish name.
const apiKey = getKey() ?? 'aB3kZ9mQ2xW7pL4nR8tYcV5dE6fG7hI8j';

// Destructure-rename: the literal is adjacent to the INNOCUOUS source key `data:`, while the
// secret-ish name `apiSecret` appears only on the destructuring pattern's LHS, far from any
// literal. Neither position gives the regex a keyword-adjacent quoted literal.
const { data: apiSecret } = { data: 'Zx9Kq2Mw7Pl4Nr8Ty1Cv5Bd3Gf6Hj0' };

// Template-literal-wrapped generic value WITH interpolation: the value char class
// [A-Za-z0-9+/_=-] excludes `$`, `{`, `}`, so any `${...}` inside the backticks breaks the
// generic-entropy match outright.
const sessionToken = `${''}Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lz9Xc`;

function getKey() { return process.env.KEY; }

module.exports = { apiKey, apiSecret, sessionToken };
