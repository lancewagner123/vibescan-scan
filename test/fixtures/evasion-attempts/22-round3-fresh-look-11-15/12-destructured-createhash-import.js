'use strict';

// Check 12 candidate: createHash pulled off the crypto module by destructuring at import
// time -- an extremely common idiom -- so the call site is a bare `createHash('md5')`
// with no literal `crypto.` / `crypto[...]` object prefix. CREATE_HASH_CALL_RE hard-codes
// the `crypto` receiver, so the whole call is invisible.

const { createHash } = require('crypto');

function storePassword(user, password) {
  const passwordHash = createHash('md5').update(password).digest('hex');
  return { id: user.id, passwordHash };
}

module.exports = { storePassword };
