'use strict';

// Stripe webhook receiver for Billsy. Mounted at /webhooks in server.js (ahead of the
// generic express.json() body parser, using express.raw() instead, since real signature
// verification needs the untouched raw body). This file is the fixture's third deliberate
// CROSS-CHECK interaction: the same handler both trusts the payload without verifying it
// AND builds a SQL statement from that same untrusted payload via string concatenation --
// two independently-detected bugs that compound into one another in a real attack.

const express = require('express');
const router = express.Router();
const db = require('../db');

// The stripe SDK is required here so a real implementation *could* call
// stripe.webhooks.constructEvent(rawBody, sig, webhookSecret) to verify the signature --
// but nobody actually wired that up below.
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// VULNERABLE (check 9: stripe-webhook-unverified) -- parses req.body directly as the
// trusted Stripe event, with no call to stripe.webhooks.constructEvent() to check the
// `stripe-signature` header first. Anyone who can reach this endpoint can POST a forged
// event (e.g. a fake "invoice.payment_succeeded") and Billsy will act on it as if Stripe
// itself sent it -- granting paid-plan access, marking invoices settled, etc.
router.post('/stripe', async (req, res) => {
  const event = JSON.parse(req.body);

  // VULNERABLE (check 4: sql-string-concatenation, SAME HANDLER) -- the raw Stripe event
  // fields are concatenated directly into an INSERT statement instead of using a
  // parameterized query. Because the event itself is unverified (see above), an attacker
  // who forges event.id/event.type/event.data controls this SQL too -- the two bugs
  // compound rather than being independent of each other.
  const sql = "INSERT INTO webhook_events (id, type, payload) VALUES ('" + event.id + "', '" + event.type + "', '" + JSON.stringify(event.data) + "')";
  await db.query(sql);

  if (event.type === 'invoice.payment_succeeded') {
    await db.query('UPDATE invoices SET status = $1 WHERE stripe_invoice_id = $2', ['paid', event.data.object.id]);
  }

  res.json({ received: true });
});

module.exports = router;
