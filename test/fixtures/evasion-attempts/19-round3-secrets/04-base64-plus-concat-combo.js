'use strict';
// Round-3 evasion for check 1 (secret-hardcoded-generic), technique: COMBINATION of two
// already-known-and-individually-defended techniques -- base64 encoding AND split-literal
// `+` concatenation -- stacked so neither existing defense fires.
//
// Why each defense misses when combined:
//  * scanLineBase64Encoded decodes each quoted literal INDIVIDUALLY and requires a clean
//    base64 round-trip. The split point below is NOT on a 4-char base64 group boundary, so
//    neither fragment is independently valid base64 (re-encode != original) -> both are
//    rejected before any decode/known-format test.
//  * scanLineConcatChains joins the `'a' + 'b'` fragments back together, but then only
//    re-tests the RAW joined value against SINGLE_LINE_PATTERNS (AWS/Stripe/etc.). It never
//    base64-decodes the joined result, so the reassembled base64 blob matches nothing.
//
// Net: the full secret (base64 of a real `sk_live_...` Stripe key) is present in source and
// decodable at runtime, but slips through both passes. The non-split base64 form (see
// 01-secret-hardcoded-generic/base64-runtime-decode.js) IS caught.
const blob = 'c2tfbGl2ZV81MUg4eEoyZ' + 'Vp2S1lsbzJDYWJjZGVmZ2hpamtsbW5vcA==';

function getBillingCredential() {
  return Buffer.from(blob, 'base64').toString('utf8');
}

module.exports = { getBillingCredential };
