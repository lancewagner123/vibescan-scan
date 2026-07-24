'use strict';
// FALSE POSITIVE for check 12 (weak-password-hashing).
//
// Rate-limiter / response-cache key generator. Hashes the client IP plus the
// request path with md5 purely to build a short, fixed-length dedup key for an
// in-memory Map -- collisions are not a security concern here (worst case: two
// distinct clients briefly share a rate-limit bucket), so md5's speed is exactly
// what's wanted. This is NOT password hashing; the word "password" only appears
// because one of the *routes* being rate-limited happens to be the reset-password
// page, and that literal sits in the same statement as the createHash() call,
// which is enough to trip the check's "nearby password-ish word" heuristic.
const crypto = require('crypto');

function buildRateLimitKey(ip) {
  const rateLimitKey = crypto.createHash('md5').update(ip + ':' + '/reset-password').digest('hex');
  return rateLimitKey;
}

module.exports = { buildRateLimitKey };
