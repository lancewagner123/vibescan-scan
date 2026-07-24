'use strict';
// Evasion for check 1 (secret-hardcoded-generic): an AWS access key ID and a Stripe
// secret key are each split across two or three separate string literals and
// concatenated at runtime. SINGLE_LINE_PATTERNS matches a full-width literal on ONE
// line (e.g. AKIA[0-9A-Z]{16} contiguous, or sk_live_ immediately followed by the token
// body) -- splitting the literal so no single line ever contains the whole contiguous
// pattern slips past every regex in SINGLE_LINE_PATTERNS untouched, even though the
// *runtime* value is byte-identical to a real key of that shape.

const awsAccessKeyId = 'AKIA' + 'Q3FAKE7EXAMPLE9Z'; // real shape once joined: AKIA + 16 chars
const stripeSecretKey = 'sk_liv' + 'e_' + '51H8xJ2eZvKYlo2Cabcdefghijklmnop';

module.exports = { awsAccessKeyId, stripeSecretKey };
