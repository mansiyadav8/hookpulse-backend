const crypto = require('crypto');

/**
 * Middleware to verify inbound Webhook signatures using HMAC-SHA256
 */
function verifyWebhookSignature(secretKey) {
  return (req, res, next) => {
    // 1. Extract the incoming signature sent by the caller from headers
    const incomingSignature = req.headers['x-hookpulse-signature'];

    if (!incomingSignature) {
      return res.status(401).json({ 
        error: 'Unauthorized: Missing x-hookpulse-signature header' 
      });
    }

    // 2. req.rawBody must be the raw unparsed Buffer/String of the request body
    if (!req.rawBody) {
      return res.status(500).json({ 
        error: 'Server Error: Raw body parser not configured properly' 
      });
    }

    // 3. Compute the expected hash using HMAC-SHA256
    const expectedSignature = crypto
      .createHmac('sha256', secretKey)
      .update(req.rawBody)
      .digest('hex');

    // 4. Timing-safe comparison to prevent timing attack vulnerabilities
    const isValid = crypto.timingSafeEqual(
      Buffer.from(incomingSignature, 'utf-8'),
      Buffer.from(expectedSignature, 'utf-8')
    );

    if (!isValid) {
      return res.status(403).json({ 
        error: 'Forbidden: HMAC signature mismatch. Payload tampered or invalid secret.' 
      });
    }

    // Signature verified! Pass control to the next middleware/route
    next();
  };
}

module.exports = { verifyWebhookSignature };