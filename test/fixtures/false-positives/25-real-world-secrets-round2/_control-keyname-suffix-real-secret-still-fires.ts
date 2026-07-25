// Positive control -- NOT a false positive. Round-6 adversarial fix (2026-07-25): Bug A's
// KeyName/ConstraintName/IndexName property-name suffix signal used to suppress
// unconditionally, with no check on the VALUE at all -- so a real secret hand-assigned to a
// `*KeyName`-suffixed variable in ordinary, hand-written source (no auto-generated header in
// sight) went completely invisible. isKnownSafeKeyDescriptorName now also requires the value
// to look like a snake_case DB identifier (looksLikeGeneratedDbIdentifier) -- these two
// values are ordinary base62 secrets with no underscores at all, so they must still fire.

const secretKeyName = "xK2mQ9pL4vR8tY1wZ3aB5cD7eF9gH1iJ3kL5m";
const primaryKeyName = "aB5cD7eF9gH1iJ3kL5mN7oP9qR1sT3uV5wX7";
