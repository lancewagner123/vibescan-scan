'use strict';
// Round-3 evasion for check 1 (secret-hardcoded-generic), technique: BRACKET-NOTATION /
// COMPUTED MEMBER ACCESS for the object key holding the secret.
//
// GENERIC_ENTROPY_RE's name portion is built from `[\w.$]*` -- it does not include `[`,
// `]`, `'` or `"`. So when the key/secret-ish NAME lives inside a bracket-notation key,
// the keyword is fenced off from the `=` by the closing `']` and the regex can't join them:
//
//     config['apiSecret'] = 'literal'
//            ^^^^^^^^^^^  keyword is inside quotes+brackets; `']` sits between it and `=`
//
// The identical `config.apiSecret = 'literal'` (dot notation) IS caught. This exactly
// mirrors the bracket-notation gap that WAS closed for check 11 (insecure-random-token)
// via checkInsecureRandomTokenBracket, but that fix was never mirrored onto checks 1/3.
const config = {};
config['apiSecret'] = 'aB3kZ9mQ2xW7pL4nR8tYcV5dE6fG7hI8j';

// Computed key built from concatenated string literals -- an even stronger form of the same
// technique (mirrors check 11's `user['session' + 'Id']` handling, also absent here).
const store = {};
store['api' + 'Token'] = 'Zx9Kq2Mw7Pl4Nr8Ty1Cv5Bd3Gf6Hj0';

module.exports = { config, store };
