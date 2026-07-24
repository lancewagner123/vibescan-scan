'use strict';
// FALSE POSITIVE (design-limitation, not a bug) for check 13 (mass-assignment).
//
// Public, unauthenticated contact-form submission. The Message model only ever has
// name/email/message fields -- there is no isAdmin/role/balance/verified field on
// this model for an attacker to smuggle in, so passing req.body straight through
// carries no actual privilege-escalation risk here. (Model schema, for reference:
//   const MessageSchema = new Schema({ name: String, email: String, message: String });
// -- no privileged fields exist on this model at all.)
//
// This check has NO way to know that, since it never looks at the model's actual
// schema/field list -- it flags Model.create(req.body) purely on the call shape.
// That's an accepted precision/recall tradeoff for a regex-based scanner (see
// report), not something a fixture-level fix can address without schema awareness.
const express = require('express');
const router = express.Router();
const Message = require('../models/Message');

router.post('/contact', async (req, res) => {
  const saved = await Message.create(req.body);
  res.json({ ok: true, id: saved.id });
});

module.exports = router;
