'use strict';

const express = require('express');
const router = express.Router();

// Fake ORM-style model so the call shape below looks like a real Sequelize/Mongoose
// `Model.create()` call without this fixture needing a real ORM dependency installed.
const User = {
  create(data) {
    return Promise.resolve({ id: 42, ...data });
  },
};

// VULNERABLE (check 13: mass-assignment) -- the entire req.body is passed straight
// through to Model.create() with no destructuring/allowlist of specific fields first. An
// attacker can set any field the model recognizes, including ones that were never meant
// to be user-settable, e.g. POST { "email": "x@example.com", "isAdmin": true }.
router.post('/users', async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});

module.exports = router;
