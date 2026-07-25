// CHECK 7 positive control -- auth middleware imported under a DIFFERENT local name than
// its module, but the local name still contains an auth-vocab word ("auth"). Task asked
// to verify this specific shape: `const auth = require('./middleware/requireAuth')`.
// Should NOT be flagged (the local identifier `auth` matches AUTH_KEYWORD_AS_ARG_RE).
const express = require('express');
const router = express.Router();
const auth = require('./middleware/requireAuth');

router.post('/admin/delete-user', auth, (req, res) => {
  db.deleteUser(req.body.id);
  res.json({ ok: true });
});

module.exports = router;
