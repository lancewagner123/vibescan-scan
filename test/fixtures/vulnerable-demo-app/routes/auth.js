'use strict';

const crypto = require('crypto');
const express = require('express');
const router = express.Router();

// Fake in-memory "users table" so the signup/login shapes below look like real app code
// without this fixture needing an actual database connection.
const users = [];

// VULNERABLE (check 12: weak-password-hashing) -- password hashing done with a fast,
// unsalted, general-purpose digest (SHA-1) instead of a slow, salted password hash
// (bcrypt/scrypt/argon2). A breached copy of `users` is fully crackable via rainbow
// tables/GPU brute force, not just partially.
router.post('/signup', (req, res) => {
  const { email, password } = req.body || {};
  const passwordHash = crypto.createHash('sha1').update(password || '').digest('hex');
  users.push({ email, passwordHash });
  res.json({ ok: true });
});

router.post('/login', (req, res) => {
  const { email, password } = req.body || {};
  const passwordHash = crypto.createHash('sha1').update(password || '').digest('hex');
  const user = users.find((u) => u.email === email && u.passwordHash === passwordHash);
  if (!user) {
    res.status(401).json({ error: 'invalid credentials' });
    return;
  }

  // VULNERABLE (check 11: insecure-random-token) -- the session token is generated with
  // Math.random().toString(36), which is not cryptographically secure: Math.random()'s
  // internal PRNG state is small and its output predictable, so an attacker who observes
  // a handful of issued session tokens can often predict future ones and hijack another
  // user's session.
  const sessionId = Math.random().toString(36).slice(2);

  // VULNERABLE (check 14: insecure-cookie-flags) -- the session cookie is set with no
  // options object at all, so it gets neither httpOnly (readable/stealable via any XSS
  // elsewhere on the page) nor secure (happily sent in the clear over plain HTTP) nor a
  // SameSite policy.
  res.cookie('sessionId', sessionId);

  res.json({ ok: true });
});

module.exports = router;
