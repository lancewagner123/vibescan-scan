'use strict';

// EVASION (round 3): check 6 (cors-wildcard-with-credentials) where the wildcard origin is
// held in a CLASS STATIC FIELD. CORS_ORIGIN_VAR_RE captures the member expression
// `CorsConfig.origin`, but findVarAssignmentContainingWildcard only looks for a
// `const/let/var CorsConfig.origin = ...` declaration -- it has no class-static-field
// resolution (the exact capability round 2 added to resolveConcatExpression for check 12,
// but check 6 rolls its own resolver and never got it). So the '*' is never resolved and
// the dangerous wildcard+credentials combo is missed.
const express = require('express');
const cors = require('cors');
const app = express();

class CorsConfig {
  static origin = '*';
}

app.use(
  cors({
    origin: CorsConfig.origin,
    credentials: true,
  }),
);

module.exports = app;
