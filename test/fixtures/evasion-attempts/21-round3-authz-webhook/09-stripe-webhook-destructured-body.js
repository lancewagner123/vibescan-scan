// CHECK 9 -- FALSE NEGATIVE via DESTRUCTURING (a core catalog technique). A Stripe webhook
// that reads the raw request body through `const { body } = req` and trusts it without ever
// calling stripe.webhooks.constructEvent(). The no-constructEvent branch anchors solely on
// the literal `req.body`/`request.body`, so destructuring the body out of `req` hides it
// and no finding is produced. This is the same destructuring blind spot check 13 was fixed
// for (resolveDestructuredReqSource) but which was never retrofitted onto check 9.
// Expected (correct): FLAGGED (trusts body without signature verification).
const express = require('express');
const router = express.Router();

// Stripe webhook receiver
router.post('/webhook/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const { body } = req;
  const event = body;
  fulfillOrder(event.data.object);
  res.json({ received: true });
});

module.exports = router;
