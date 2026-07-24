'use strict';

// Config module for Billsy's backup/report exports. In theory everything here should come
// from process.env (see .env) -- in practice, someone hardcoded fallback values during a
// hurried incident fix and never came back to remove them once .env was working again.
// Realistic, and exactly the kind of thing that lands in a "config" file rather than a
// route handler, so it's worth its own file in this fixture.
//
// VULNERABLE (check 1: secret-hardcoded-generic) -- a live Stripe secret key and an AWS
// access key ID are hardcoded directly in source, committed alongside the app that also
// (correctly, elsewhere) reads STRIPE_SECRET_KEY from the environment. Whichever one
// actually gets used at runtime, both are now permanently in this repo's history.
const FALLBACK_STRIPE_KEY = 'sk_live_51Hh2xJKzT9xU3mP8qRvN7dGY4wLk6bXcZaFj0iVn2oQ';
const BACKUP_EXPORT_AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const BACKUP_EXPORT_AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

module.exports = {
  stripeSecretKey: process.env.STRIPE_SECRET_KEY || FALLBACK_STRIPE_KEY,
  awsAccessKeyId: BACKUP_EXPORT_AWS_ACCESS_KEY_ID,
  awsSecretAccessKey: BACKUP_EXPORT_AWS_SECRET_ACCESS_KEY,
};
