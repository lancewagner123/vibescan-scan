'use strict';

// Check 15 candidate: the redirect target reads the query object via bracket notation
// (`req['query']`) instead of dot notation. Check 13 explicitly added `req['body']`
// bracket support, but open-redirect's REQ_SOURCE_PROP_RE and REQ_SOURCE_PROP_ANYWHERE_RE
// are both dot-only (`req.query`), so `req['query'].next` matches nothing and the redirect
// is never flagged.

function handleRedirect(req, res) {
  const next = req['query'].next;
  res.redirect(next);
}

function handleRedirectInline(req, res) {
  res.redirect(req['query'].returnTo);
}

module.exports = { handleRedirect, handleRedirectInline };
