// Positive control -- NOT a false positive. Overcorrection guard: an ordinary hardcoded
// high-entropy literal secret (no JWT structure, no env-var reference -- an actual literal
// value sitting in source) must still be flagged by secret-hardcoded-generic. Prefixed
// with an underscore so it sorts away from the actual false-positive fixtures and is
// unmistakably a control.

const apiSecret = 'Zx9kLm2pQrT8vWyB4nC6hJ0sD3fG7aE1';
const config = {
  paymentApiKey: 'sk_live_51H8gT3KqZmR7bNcXpLwYvJdAeFuGhKoP',
};
