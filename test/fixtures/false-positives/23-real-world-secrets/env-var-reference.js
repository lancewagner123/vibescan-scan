// Reconstructed (anonymized/generic) from the real-world false-positive validation
// exercise (docs/REAL_WORLD_VALIDATION.md, §5.2). These lines reference an environment
// variable by NAME -- there is no literal secret VALUE on the line at all, just a
// property-access chain reading from the environment. This is the SAFE pattern (the
// actual secret lives only in the environment, never in source) and must not be flagged
// as a hardcoded secret.

// Vite/browser env-var access, no `const`/`let`/`var` prefix (module-scope reassignment
// shape), matching the real "const KEY = import.meta.env.VITE_SUPABASE_KEY"-style finding.
SUPABASE_KEY = import.meta.env.VITE_SUPABASE_KEY;
STRIPE_SECRET = import.meta.env.VITE_STRIPE_SECRET;

// Node-style process.env reference, same shape.
PINECONE_API_KEY = process.env.PINECONE_API_KEY;
AUTH_TOKEN = process.env.AUTH_TOKEN;
