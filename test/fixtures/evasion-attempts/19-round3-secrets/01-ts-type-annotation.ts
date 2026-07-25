// Round-3 evasion for check 1 (secret-hardcoded-generic), technique: TypeScript
// return/variable TYPE ANNOTATION breaking a regex that assumed plain JS.
//
// GENERIC_ENTROPY_RE is: [\w.$]*(?:key|secret|token|password|passwd|pwd)[\w]*\s*[:=]\s*["'`](...)
// It expects the key/secret-ish NAME to be immediately followed by `:` or `=` and then a
// quoted literal. In a TypeScript typed declaration the FIRST `:` after the name is the
// TYPE ANNOTATION colon, not the value separator:
//
//     const apiSecret : string = 'literal'
//                     ^-- regex's [:=] binds here, then demands a quote, sees `string` -> fails
//
// The `[\w]*\s*[:=]` in the regex can only reach the type-annotation `:`; it can never skip
// past `: string ` to the real `=`, so the whole assignment is invisible. The identical line
// WITHOUT the `: string` annotation IS caught (see _control-caught.js). This is ordinary,
// mainstream TypeScript, not deliberate obfuscation.
const apiSecret: string = 'aB3kZ9mQ2xW7pL4nR8tYcV5dE6fG7hI8j';

// Same gap inside a class static field with a TS annotation (`static X: T = '...'`); the
// un-annotated `static apiSecret = '...'` form IS caught, so it is specifically the type
// annotation that breaks detection here, not the class-static shape.
class Config {
  static readonly serviceToken: string = 'Zx9Kq2Mw7Pl4Nr8Ty1Cv5Bd3Gf6Hj0';
}

export { apiSecret, Config };
