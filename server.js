const express = require('express');
const { verifyWebhookSignature } = require('./verifier');

const app = express();
const PORT = process.env.PORT || 3000;

// Shared secret key (In production, load this from process.env)
const WEBHOOK_SECRET = 'super_secret_key_123';

// Express body parser configured to preserve the raw Buffer for HMAC checks
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf; // Save raw buffer for cryptographic signature checking
  }
}));

// The Webhook Ingestion Route
app.post(
  '/api/v1/webhooks/ingest',
  verifyWebhookSignature(WEBHOOK_SECRET),
  (req, res) => {
    // If execution reaches here, signature validation succeeded!
    console.log('Valid Webhook Received:', req.body);

    // Immediate 202 Accepted response. 
    // We don't process heavy tasks here; we just acknowledge receipt!
    return res.status(202).json({
      status: 'accepted',
      message: 'Webhook received and authenticated successfully.'
    });
  }
);

app.listen(PORT, () => {
  console.log(`HookPulse Ingestion API running on http://localhost:${PORT}`);
});