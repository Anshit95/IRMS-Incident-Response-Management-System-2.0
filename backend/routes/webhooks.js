const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const { authenticate, authorize } = require('../middleware/auth');
const webhookController = require('../controllers/webhookController');

// Ingestion rate limiter: max 120 alerts per minute per IP
const ingestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  message: { error: 'Inbound alert rate limit exceeded. Please throttle telemetry forwarder.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Public ingestion endpoint authenticated by api_key in URL with rate limiting
router.post('/ingest/:apiKey', ingestLimiter, webhookController.ingestAlert);

// Protected configuration endpoints (Admin Only)
router.get('/', authenticate, authorize('admin'), webhookController.listWebhooks);
router.post('/', authenticate, authorize('admin'), webhookController.createWebhook);

module.exports = router;
