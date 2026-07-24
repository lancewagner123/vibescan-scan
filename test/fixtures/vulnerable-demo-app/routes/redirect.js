'use strict';

const express = require('express');
const router = express.Router();

// VULNERABLE (check 15: open-redirect) -- the redirect target flows one variable hop from
// req.query.url with no allowlist/validation against a fixed set of internal paths. An
// attacker can send a victim a link on this site's own trusted domain (e.g.
// /go?url=https://evil.example.com/phishing) that silently forwards them somewhere
// attacker-controlled -- a common phishing vector precisely because the link looks safe.
router.get('/go', (req, res) => {
  const target = req.query.url;
  res.redirect(target);
});

module.exports = router;
