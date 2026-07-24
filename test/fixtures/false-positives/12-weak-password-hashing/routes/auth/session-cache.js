'use strict';
// FALSE POSITIVE for check 12 (weak-password-hashing) -- path-heuristic variant.
//
// Lives under routes/auth/ because it's part of the auth module's route set, but
// this particular function has nothing to do with password hashing: it builds an
// ETag for the (already-authenticated) user's session-status JSON response so
// browsers can skip re-downloading it when nothing changed. md5 is a fine choice
// for an ETag -- it just needs to be fast and collision-unlikely for change
// detection, not cryptographically unbreakable. Flagged solely because the check's
// "does this file look like an auth/login/signup/register module" fallback
// heuristic fires on ANY md5/sha1 call anywhere in a file under an auth/-named
// path, regardless of what that specific call is hashing.
const crypto = require('crypto');

function buildSessionStatusEtag(sessionStatusPayload) {
  const hash = crypto.createHash('md5').update(JSON.stringify(sessionStatusPayload)).digest('hex');
  return `"session-status-${hash}"`;
}

module.exports = { buildSessionStatusEtag };
