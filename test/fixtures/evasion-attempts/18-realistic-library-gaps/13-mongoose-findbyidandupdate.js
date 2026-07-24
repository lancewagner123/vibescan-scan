'use strict';
// NEW gap for check 13 (mass-assignment), found by a realistic-library-code audit
// (round 2, 2026-07-24) -- not an adversarial evasion trick, just ordinary Mongoose code.
// MODEL_METHOD_CALL_RE used to be a fixed `/\.(create|update|save)\s*\(/g` -- it required
// the method name to be EXACTLY one of those three, so `findByIdAndUpdate` (arguably the
// single most common Mongoose write method for exactly this bug shape) never matched at
// all, even though the arg-extraction logic downstream already handles multi-arg calls
// (the tainted value is the 2nd argument here, not the 1st) just fine once the callee is
// recognized.
const User = require('./models/user');

async function updateProfile(req, res) {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(user);
}

module.exports = { updateProfile };
