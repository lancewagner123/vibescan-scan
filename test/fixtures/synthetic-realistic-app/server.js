'use strict';

// Billsy -- a small subscription-billing SaaS backend (Express + Postgres + Stripe).
// Entry point: wires up CORS, the three route groups, and starts the server.

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const webhookRoutes = require('./routes/webhook');

const app = express();

// VULNERABLE (check 6: cors-wildcard-with-credentials) -- origin is the literal wildcard
// '*' in the same config object that also sets credentials:true. Browsers reject this
// specific combination outright, but some proxies/older HTTP clients won't, and it's a
// clear signal the CORS policy here was copy-pasted from a "just make it work" answer
// rather than actually scoped to Billsy's real frontend origin(s).
app.use(cors({ origin: '*', credentials: true }));

app.use(cookieParser());

// The Stripe webhook route needs the raw request body for signature verification, so it
// gets its own body parser wired ahead of the generic json() one -- a very ordinary
// pattern in real Express + Stripe apps.
app.use('/webhooks', express.raw({ type: 'application/json' }), webhookRoutes);

app.use(express.json());
app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'billsy-api' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`billsy-api listening on ${PORT}`);
});

module.exports = app;
