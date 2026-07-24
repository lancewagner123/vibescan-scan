'use strict';

// VULNERABLE (check 1: secret-hardcoded-generic) -- a Stripe-live-key-format secret
// literal committed directly to source. This is a FAKE key (everything after sk_live_
// is filler, not a real Stripe account) but it matches Stripe's published key format
// exactly, which is what pattern-based secret scanners key off of.
const STRIPE_SECRET_KEY = 'sk_live_51NfakeVibeScanDemoKeyDoNotUse00000000000000000000000000';

module.exports = { STRIPE_SECRET_KEY };
