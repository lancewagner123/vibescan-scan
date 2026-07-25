'use strict';
// Round-3 evasion for check 1 (secret-hardcoded-generic), technique: TEMPLATE-LITERAL
// wrapping used to SPLIT a known-format secret with an interpolation, defeating the
// SINGLE_LINE_PATTERNS regexes the same way plus-concatenation used to before
// scanLineConcatChains was added.
//
// scanLineConcatChains (the existing split-literal defense) only understands quoted
// literals joined with a plus sign. It has no branch for template-literal interpolation.
// A known secret whose contiguous shape is broken by a placeholder expression therefore
// never appears whole to the AWS / Stripe regexes and is never reassembled. The equivalent
// plus-joined form (found in 01-secret-hardcoded-generic/split-literal-secrets.js) IS
// caught. Template-literal string building is ordinary modern JS, not exotic obfuscation.
//
// NOTE: no reassembled/contiguous secret text appears anywhere in THIS comment on purpose --
// secrets.js deliberately does not strip comments, so a comment containing the plus-joined
// form would itself be flagged and mask what the code below is actually testing.
const awsAccessKeyId = `AKIA${''}Q3FAKE7EXAMPLE9Z`;
const stripeSecretKey = `sk_live_${''}51H8xJ2eZvKYlo2Cabcdefghijklmnop`;

module.exports = { awsAccessKeyId, stripeSecretKey };
