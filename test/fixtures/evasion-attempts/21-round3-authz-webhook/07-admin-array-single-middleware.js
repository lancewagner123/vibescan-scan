// CHECK 7 -- edge-case FALSE POSITIVE candidate. Auth middleware present but wired as a
// SINGLE-element array (`[requireAuth]`). Here the auth identifier is followed by "]" not
// ",", so AUTH_KEYWORD_AS_ARG_RE never matches and (with no 401/403/throw in the body) the
// correctly-secured route is reported as missing auth. Less common than the multi-element
// form, but valid Express.
const express = require('express');
const router = express.Router();
const requireAuth = require('./middleware/requireAuth');

router.get('/admin/audit-log', [requireAuth], (req, res) => {
  res.json(db.getAuditLog());
});

module.exports = router;
