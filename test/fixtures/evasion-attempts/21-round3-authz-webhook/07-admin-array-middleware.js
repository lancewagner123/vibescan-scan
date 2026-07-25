// CHECK 7 positive control -- auth middleware wired as a MULTI-element array
// (`[requireAuth, requireAdmin]`). Tested and correctly NOT flagged: the first element is
// followed by the array's internal comma, so AUTH_KEYWORD_AS_ARG_RE ("...auth...,") still
// matches. (A SINGLE-element array `[requireAuth]` is the edge case -- see
// 07-admin-array-single-middleware.js -- because there is no trailing comma there.)
const express = require('express');
const router = express.Router();
const requireAuth = require('./middleware/requireAuth');
const requireAdmin = require('./middleware/requireAdmin');

router.get('/admin/reports', [requireAuth, requireAdmin], (req, res) => {
  res.json(db.getReports());
});

module.exports = router;
