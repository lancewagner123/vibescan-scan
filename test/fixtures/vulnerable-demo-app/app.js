'use strict';

// VibeScan test fixture -- intentionally vulnerable demo app. DO NOT DEPLOY.
// See ./README.md for the full map of which file seeds which of the 10 v1 checks.

const express = require('express');
const cors = require('cors');

const adminRoutes = require('./routes/admin');
const debugRoutes = require('./routes/debug');
const userRoutes = require('./routes/users');
const webhookRoutes = require('./routes/webhooks');

const app = express();

// VULNERABLE (check 6: cors-wildcard-with-credentials) -- wildcard origin combined with
// credentials:true. Real browsers reject this combination for actual credentialed
// requests, but it's exactly the "just make the CORS error go away" shape that shows up
// in vibe-coded apps, and it's still a config mistake worth flagging on its own.
app.use(cors({ origin: '*', credentials: true }));

app.use(express.json());

app.use('/admin', adminRoutes);
app.use('/_debug', debugRoutes);
app.use('/users', userRoutes);
app.use('/webhooks', webhookRoutes);

app.get('/', (req, res) => {
  res.send('vulnerable-demo-app: VibeScan test fixture, do not deploy.');
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`vulnerable-demo-app listening on ${PORT}`);
  });
}

module.exports = app;
