// Positive control -- NOT a false positive. A BARE `key` property name is not immune from
// detection: if the value genuinely looks like a random secret (the stronger signal this
// fix requires for the ambiguous bare-`key` name -- high entropy AND at least one digit),
// it must still be flagged. Prefixed with an underscore so it sorts away from the actual
// false-positive fixtures and is unmistakably a control.

const cache = {
  key: 'aB3xQ9mZ7pL2vN8jT1cR6wY3bH5fD0sU4',
};

module.exports = { cache };
