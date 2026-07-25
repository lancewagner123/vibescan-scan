// Reconstructed (anonymized/generic) from the real-world false-positive re-validation
// pass (docs/REAL_WORLD_VALIDATION.md, "Re-validation (post-fix)" section, §1 --
// career-ops). A bare, standalone `key` property name in a plain state-machine/lookup
// config array -- the same idiom as a React list `key` prop or a dictionary key --
// completely unrelated to API keys/secrets. The value itself is an ordinary camelCase
// English phrase, not a real secret, even though its per-character Shannon entropy
// happens to clear the GENERAL entropy threshold (natural-language phrases can look
// deceptively "diverse" per character at 20+ characters).

const applicationStages = [
  { key: 'respondedToInterview', label: 'Responded to Interview' },
  { key: 'offerExtended', label: 'Offer Extended' },
  { key: 'backgroundCheckInProgress', label: 'Background Check In Progress' },
];

module.exports = { applicationStages };
