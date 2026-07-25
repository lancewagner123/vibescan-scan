'use strict';
// CONTROL for the round-3 secrets evasion set. Every line here is the PLAIN, un-evaded
// form of a secret that checks 1/3 already catch. Running scanRepo() on this folder should
// report findings for THIS file (proving detection works at all) while reporting NONE for
// the sibling 01-05 evasion files (proving those specific techniques currently bypass the
// check). If a future fix closes a gap, the corresponding evasion file will start matching
// this control's behaviour.
const apiSecret = 'aB3kZ9mQ2xW7pL4nR8tYcV5dE6fG7hI8j';        // plain generic high-entropy -> caught
const awsAccessKeyId = 'AKIAQ3FAKE7EXAMPLE9Z';               // plain AWS known-format    -> caught
const stripeSecretKey = 'sk_live_51H8xJ2eZvKYlo2Cabcdefghijklmnop'; // plain Stripe        -> caught

module.exports = { apiSecret, awsAccessKeyId, stripeSecretKey };
