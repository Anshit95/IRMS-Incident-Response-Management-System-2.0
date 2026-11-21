const path = require('path'); 
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const { initializeSchema } = require('./database/schema');
const { inputSanitizer } = require('./middleware/sanitize');

// Initialize database schema
initializeSchema();

const app = express();

// Disable X-Powered-By to prevent framework fingerprinting
app.disable('x-powered-by');

// Hardened Security Headers via Helmet
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginEmbedderPolicy: false,
  xFrameOptions: { action: 'deny' },
  xContentTypeOptions: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://generativelanguage.googleapis.com', 'https://api.openai.com', 'https://www.virustotal.com']
    }
  }
}));

// Restrict CORS to configured origins
const allowedOrigin = process.env.FRONTEND_URL || 'http://localhost:5173';
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl, server-to-server) or matching frontend
    if (!origin || origin === allowedOrigin || origin === 'http://localhost:5173' || origin === 'http://127.0.0.1:5173') {
      callback(null, true);
    } else {
      callback(new Error('CORS access denied by enterprise security policy'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Logging (sanitized)
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
}

// Request size limits to prevent buffer overflow and memory exhaustion DoS
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

// Global Input Sanitizer (Anti-XSS, Anti-Prototype-Pollution, Anti-Null-Byte)
app.use(inputSanitizer);

// Global API Rate Limiter: max 600 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 600,
  message: { error: 'API rate limit exceeded. Please throttle automated requests.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', globalLimiter);

// Enterprise Core Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/dashboard', require('./routes/dashboard'));
app.use('/api/incidents', require('./routes/incidents'));
app.use('/api/playbooks', require('./routes/playbooks'));
app.use('/api/threat-intel', require('./routes/threatIntel'));
app.use('/api/compliance', require('./routes/compliance'));
app.use('/api/billing', require('./routes/billing'));
app.use('/api/webhooks', require('./routes/webhooks'));
app.use('/api', require('./routes/misc'));

// Health check
app.get('/api/health', (req, res) => res.json({
  status: 'ok',
  system: 'IRMS Enterprise SOC Platform',
  version: '2.0.0',
  tier: 'Enterprise SOAR Edition',
  security_mode: 'Hardened (Zero-Trust & HMAC Chained)',
  timestamp: new Date().toISOString()
}));
// ==================================================
// SERVE REACT FRONTEND
// ==================================================

const frontendDist = path.resolve(
  __dirname,
  '../frontend/dist'
);

// Serve Vite static assets
app.use(express.static(frontendDist));

// React Router fallback
app.use((req, res, next) => {

  if (req.method !== 'GET') {
    return next();
  }

  if (req.path === '/api' || req.path.startsWith('/api/')) {
    return next();
  }

  res.sendFile(
    path.join(frontendDist, 'index.html'),
    (err) => {
      if (err) next(err);
    }
  );
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Requested resource not found' }));

// Hardened Global Error Handler (Suppresses internal SQL errors and stack traces from client exposure)
app.use((err, req, res, next) => {
  // Log full stack trace securely to server log only
  console.error('[SECURITY LOG - UNCAUGHT ERROR]', err);

  const statusCode = err.status || err.statusCode || 500;
  // Never leak database engine errors or internal paths to external clients
  const clientMessage = statusCode === 500
    ? 'An internal security exception occurred. The incident has been recorded in the audit log.'
    : err.message || 'An error occurred processing the request.';

  res.status(statusCode).json({ error: clientMessage });
});

module.exports = app;
