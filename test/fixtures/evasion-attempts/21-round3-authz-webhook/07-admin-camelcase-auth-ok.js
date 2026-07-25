// CHECK 7 positive control for the camelCase fix -- middleware named `requireAuth`
// (camelCase, "Auth" starting mid-identifier) passed inline. The AUTH_KEYWORD_VOCAB
// unanchoring fix should recognize this as real auth and NOT flag it.
const express = require('express');
const router = express.Router();
const requireAuth = require('./middleware/requireAuth');

router.get('/admin/settings', requireAuth, (req, res) => {
  res.json({ ok: true });
});

module.exports = router;
