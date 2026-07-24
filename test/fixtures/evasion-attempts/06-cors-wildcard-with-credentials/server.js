'use strict';
// Evasion for check 6 (cors-wildcard-with-credentials): CORS_WILDCARD_RE only matches
// the literal character '*' sitting directly inside quotes next to `origin:` or
// `Access-Control-Allow-Origin`. Routing the wildcard through a variable/env-var default
// means that literal '*' next to either keyword never appears anywhere in this file --
// even though, in the extremely common case where CORS_ALLOWED_ORIGIN is unset (e.g.
// forgotten in a deploy config), this resolves to '*' at runtime and is combined with
// credentials:true, exactly the dangerous combination the check exists to catch.
const cors = require('cors');
const express = require('express');

const app = express();

// If CORS_ALLOWED_ORIGIN is unset, this silently falls back to the wildcard at runtime.
const resolvedOrigin = process.env.CORS_ALLOWED_ORIGIN || '*';

app.use(cors({
  origin: resolvedOrigin,
  credentials: true,
}));

module.exports = { app };
