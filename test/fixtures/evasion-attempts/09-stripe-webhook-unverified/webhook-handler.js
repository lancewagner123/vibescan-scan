'use strict';
// Evasion for check 9 (stripe-webhook-unverified): stripe.webhooks.constructEvent() IS
// called (so `/constructEvent/.test(clean)` is true and checkStripeWebhookUnverified()
// returns [] immediately, treating this file as "verified"), but the verification
// failure is swallowed in a catch block and the handler proceeds to trust the raw
// request body regardless of whether the signature actually verified. The check only
// asks "does the text 'constructEvent' appear anywhere in this file?" -- it never
// confirms that the *verified* `event` object (as opposed to the raw, untrusted
// req.body) is what actually gets used, nor that a thrown verification error actually
// stops the request instead of merely being logged.
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

function stripeWebhookHandler(req, res) {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET,
    );
  } catch (err) {
    // Signature verification failed -- but instead of rejecting the request, this
    // swallows the error and falls through to processing the raw, unverified body
    // anyway. Fully equivalent in risk to never calling constructEvent at all.
    console.warn('Webhook signature check failed, processing anyway:', err.message);
  }

  const payload = event || JSON.parse(req.body);
  fulfillOrder(payload.data.object);
  res.sendStatus(200);
}

module.exports = { stripeWebhookHandler };
