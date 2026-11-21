const bcrypt = require('bcryptjs');
const { getDb } = require('../database/schema');
const { generateToken } = require('../middleware/auth');
const { recordAuditEntry } = require('../services/complianceService');

// In-memory brute force & account lockout state
const FAILED_ATTEMPTS = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '127.0.0.1';
}

function login(req, res) {
  const { email, password } = req.body;
  const clientIp = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown Client';
  const db = getDb();

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const cleanEmail = email.toLowerCase().trim();

  // Check account lockout status
  const attemptInfo = FAILED_ATTEMPTS.get(cleanEmail);
  if (attemptInfo && attemptInfo.attempts >= MAX_FAILED_ATTEMPTS) {
    const elapsed = Date.now() - attemptInfo.lastAttempt;
    if (elapsed < LOCKOUT_DURATION_MS) {
      const minutesRemaining = Math.ceil((LOCKOUT_DURATION_MS - elapsed) / 60000);
      recordAuditEntry(db, null, 'auth_lockout_blocked', 'auth', null, `Blocked login attempt on locked account ${cleanEmail}`, clientIp, userAgent);
      return res.status(429).json({
        error: `Account temporarily locked due to repeated authentication failures. Please try again in ${minutesRemaining} minute(s).`
      });
    } else {
      // Lockout expired, reset counter
      FAILED_ATTEMPTS.delete(cleanEmail);
    }
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);

  // Check user existence and active status
  if (!user || user.is_active !== 1 || !bcrypt.compareSync(password, user.password_hash)) {
    // Record failed attempt
    const current = FAILED_ATTEMPTS.get(cleanEmail) || { attempts: 0, lastAttempt: Date.now() };
    current.attempts += 1;
    current.lastAttempt = Date.now();
    FAILED_ATTEMPTS.set(cleanEmail, current);

    // Record security audit event
    recordAuditEntry(
      db,
      user ? user.id : null,
      'auth_failed',
      'auth',
      user ? user.id : null,
      `Failed authentication attempt for ${cleanEmail} (Attempt ${current.attempts}/${MAX_FAILED_ATTEMPTS})`,
      clientIp,
      userAgent
    );

    if (current.attempts >= MAX_FAILED_ATTEMPTS) {
      recordAuditEntry(
        db,
        user ? user.id : null,
        'auth_lockout',
        'auth',
        user ? user.id : null,
        `Account ${cleanEmail} locked for 15 minutes due to 5 consecutive failed logins`,
        clientIp,
        userAgent
      );
      return res.status(429).json({
        error: 'Too many failed login attempts. Account is locked for 15 minutes to prevent unauthorized access.'
      });
    }

    return res.status(401).json({
      error: `Invalid email or password. Warning: ${MAX_FAILED_ATTEMPTS - current.attempts} attempt(s) remaining before temporary lockout.`
    });
  }

  // Authentication succeeded — reset failed attempts
  FAILED_ATTEMPTS.delete(cleanEmail);

  const token = generateToken(user);

  // Cryptographically chained audit entry
  recordAuditEntry(
    db,
    user.id,
    'login_success',
    'user',
    user.id,
    `Analyst ${user.name} logged in successfully`,
    clientIp,
    userAgent
  );

  return res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      title: user.title || 'Security Analyst'
    },
  });
}

function logout(req, res) {
  if (req.user) {
    const db = getDb();
    const clientIp = getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'Unknown Client';
    recordAuditEntry(
      db,
      req.user.id,
      'logout',
      'user',
      req.user.id,
      `User ${req.user.name || req.user.email} logged out`,
      clientIp,
      userAgent
    );
  }
  return res.json({ message: 'Logged out successfully' });
}

function me(req, res) {
  const db = getDb();
  const user = db.prepare('SELECT id, name, email, role, title, is_active, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json(user);
}

module.exports = { login, logout, me };
