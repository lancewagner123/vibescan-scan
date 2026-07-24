'use strict';

const express = require('express');
const router = express.Router();

// VULNERABLE (check 9: stripe-webhook-unverified) -- this handler trusts req.body
// directly and never calls stripe.webhooks.constructEvent() to verify the
// Stripe-Signature header. Anyone who finds this URL can POST a fabricated event and
// have it treated as a real one (e.g. a fake "checkout.session.completed").
router.post('/stripe', (req, res) => {
  const event = req.body;

  if (event && event.type === 'checkout.session.completed') {
    const obj = event.data && event.data.object;
    console.log('Order fulfilled for', obj && obj.id);
  }

  res.json({ received: true });
});

module.exports = router;
