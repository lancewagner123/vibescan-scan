// CHECK 7 sanity control -- a genuinely unauthenticated /admin route with NO auth of any
// kind. This SHOULD be flagged (missing-auth-middleware). If this one doesn't fire, the
// check is broken outright and the other check-7 fixtures below prove nothing.
const express = require('express');
const router = express.Router();

router.get('/admin/dashboard', (req, res) => {
  const stats = db.getStats();
  res.json(stats);
});

module.exports = router;
