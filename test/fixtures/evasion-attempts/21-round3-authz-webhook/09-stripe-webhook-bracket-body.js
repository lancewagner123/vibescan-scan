// CHECK 9 -- FALSE NEGATIVE via BRACKET/COMPUTED member access (a core catalog technique).
// A Stripe webhook that reads the raw body as `req['body']` and trusts it, with no
// constructEvent call. `/req\.body|request\.body/` is dot-notation only, so the bracket
// form is invisible and no finding is produced -- exactly the bracket-access gap check 13's
// isReqBodyOrQueryExpr was fixed for (`req['body']`) but which was never applied to check 9.
// Expected (correct): FLAGGED (trusts body without signature verification).
const express = require('express');
const router = express.Router();

// Stripe webhook handler
router.post('/webhook/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const event = req['body'];
  fulfillOrder(event.data.object);
  res.json({ received: true });
});

module.exports = router;
