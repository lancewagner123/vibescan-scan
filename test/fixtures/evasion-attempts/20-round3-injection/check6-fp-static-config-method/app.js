'use strict';

// FALSE-POSITIVE PROBE (round 3): a SAFE CORS origin resolved through a CLASS STATIC CONFIG
// METHOD. The origin is a specific trusted domain, not a wildcard, and credentials are on.
// This must NOT be flagged by check 6.
const express = require('express');
const cors = require('cors');
const app = express();

class CorsConfig {
  static getOrigin() {
    return 'https://app.example.com';
  }
}

app.use(
  cors({
    origin: CorsConfig.getOrigin(),
    credentials: true,
  }),
);

module.exports = app;
