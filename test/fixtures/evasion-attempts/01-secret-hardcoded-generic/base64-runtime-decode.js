'use strict';
// Evasion for check 1 (secret-hardcoded-generic): the secret is stored base64-encoded
// and decoded at runtime, AND the variable holding the encoded blob is deliberately
// named something that does NOT contain "key/secret/token/password/passwd/pwd" so the
// generic high-entropy heuristic (GENERIC_ENTROPY_RE), which only fires on a quoted
// literal assigned to a key/secret/token/password-ish NAME, never even inspects this
// literal's entropy. Base64 encoding also defeats the known-format regexes (Stripe/AWS/
// Google/Slack/JWT) since the encoded text no longer contains the recognizable prefix.
//
// (decoded value intentionally not shown in this comment -- a plaintext secret in a
// comment is still a real leak and *would* be caught, since secrets.js deliberately does
// not strip comments before scanning; keeping this comment silent on the decoded value
// keeps this sample an honest test of the base64+innocuous-name technique itself)
const configData = 'c2tfbGl2ZV81MUg4eEoyZVp2S1lsbzJDYWJjZGVmZ2hpamtsbW5vcA==';

function getBillingCredential() {
  return Buffer.from(configData, 'base64').toString('utf8');
}

module.exports = { getBillingCredential };
