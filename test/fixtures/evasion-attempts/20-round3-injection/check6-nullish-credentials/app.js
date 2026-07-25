'use strict';

// EVASION (round 3): check 6 (cors-wildcard-with-credentials) where `credentials` is set
// through a NULLISH-COALESCING default rather than a literal `true`. CORS_CREDENTIALS_RE
// only recognizes a literal `credentials: true` (or the ACAC header form), so
// `credentials: options.withCredentials ?? true` fails the credentials gate and the ENTIRE
// check short-circuits to [] -- even though a literal wildcard origin sits right beside it.
const express = require('express');
const cors = require('cors');
const app = express();

const options = {};

app.use(
  cors({
    origin: '*',
    credentials: options.withCredentials ?? true,
  }),
);

module.exports = app;
