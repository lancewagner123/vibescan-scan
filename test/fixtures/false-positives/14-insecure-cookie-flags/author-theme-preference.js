'use strict';
// FALSE POSITIVE for check 14 (insecure-cookie-flags).
//
// Blog "author theme" preference cookie -- lets a signed-in author pick a color
// scheme for their own posts. Purely cosmetic: client-side JS needs to read it to
// render the right theme before the page finishes loading, and neither leaking nor
// tampering with it has any security consequence, so omitting httpOnly/secure is
// fine. Flagged solely because the cookie name/value are built from the word
// "author", which contains the substring "auth" that the check's sensitive-name
// heuristic looks for.
const express = require('express');
const app = express();

app.post('/authorTheme', (req, res) => {
  const authorThemePreference = req.body.theme;
  res.cookie('authorTheme', authorThemePreference);
  res.json({ ok: true });
});

module.exports = app;
