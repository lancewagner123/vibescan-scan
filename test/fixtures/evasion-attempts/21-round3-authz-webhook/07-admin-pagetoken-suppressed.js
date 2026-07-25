// CHECK 7 -- FALSE NEGATIVE introduced/widened by the AUTH_KEYWORD_VOCAB unanchoring fix.
// This admin route has NO auth whatsoever. But the handler body declares a `pageToken`
// pagination cursor variable, and the unanchored AUTH_KEYWORD_AS_ARG_RE matches the
// substring "Token," inside "pageToken," -- suppressing the finding as if real auth were
// present. Before the \b anchor was removed, `\btoken` would NOT have matched "Token" in
// the middle of "pageToken" (no word boundary between "page" and "Token"), so this route
// would have been correctly flagged. The fix that closed the requireAuth camelCase gap
// therefore WIDENED this substring-collision false negative. Expected (correct): FLAGGED.
const express = require('express');
const router = express.Router();

router.get('/admin/users', (req, res) => {
  const pageToken = req.query.pageToken,
        pageSize = 50;
  const users = db.listUsers(pageToken, pageSize);
  res.json(users);
});

module.exports = router;
