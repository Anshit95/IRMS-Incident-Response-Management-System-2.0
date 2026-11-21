const bcrypt = require('bcryptjs');
const { getDb } = require('../database/schema');
const { recordAuditEntry } = require('../services/complianceService');

const VALID_ROLES = ['admin', 'analyst', 'viewer'];

// Enterprise Password Complexity Policy (NIST SP 800-63B standard)
function validatePasswordStrength(pwd) {
  if (!pwd || typeof pwd !== 'string') return 'Password is required';
  if (pwd.length < 10) return 'Password must be at least 10 characters long';
  if (!/[A-Z]/.test(pwd)) return 'Password must contain at least one uppercase letter (A-Z)';
  if (!/[a-z]/.test(pwd)) return 'Password must contain at least one lowercase letter (a-z)';
  if (!/[0-9]/.test(pwd)) return 'Password must contain at least one numeric digit (0-9)';
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd)) return 'Password must contain at least one special character (!@#$%^&*...)';

  const commonWeak = ['password123', 'admin12345', 'qwerty1234', 'welcome123'];
  if (commonWeak.includes(pwd.toLowerCase())) {
    return 'Password is too common and easily guessable. Please choose a stronger passphrase.';
  }
  return null;
}

function listUsers(req, res) {
  const db = getDb();
  const users = db.prepare('SELECT id, name, email, role, title, phone, is_active, created_at FROM users ORDER BY created_at DESC').all();
  return res.json(users);
}

function createUser(req, res) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Only admins can create users' });
  const db = getDb();
  const { name, email, password, role, title, phone } = req.body;

  if (!name?.trim()) return res.status(400).json({ error: 'Full name is required' });
  if (!email?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'A valid corporate email address is required' });

  // Enforce strong password policy
  const pwdError = validatePasswordStrength(password);
  if (pwdError) return res.status(400).json({ error: pwdError });

  if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role specified' });

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (exists) return res.status(409).json({ error: 'Email address is already registered in organization' });

  // Use 12 bcrypt salt rounds for enterprise hardening
  const hash = bcrypt.hashSync(password, 12);
  const result = db.prepare(`
    INSERT INTO users (organization_id, name, email, password_hash, role, title, phone)
    VALUES (1, ?, ?, ?, ?, ?, ?)
  `).run(name.trim(), email.toLowerCase().trim(), hash, role, title?.trim() || 'Security Analyst', phone?.trim() || null);

  recordAuditEntry(db, req.user.id, 'create_user', 'user', result.lastInsertRowid, `Created user ${email.toLowerCase().trim()} with role ${role}`);

  const user = db.prepare('SELECT id, name, email, role, title, phone, is_active, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
  return res.status(201).json(user);
}

function updateUser(req, res) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Only admins can update users' });
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { name, role, is_active, title, phone, password } = req.body;

  // Prevent removing last active admin
  if (role && role !== 'admin' && user.role === 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin' AND is_active = 1").get().c;
    if (adminCount <= 1) return res.status(400).json({ error: 'Cannot demote the last active administrator' });
  }
  if (is_active === 0 && user.role === 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin' AND is_active = 1").get().c;
    if (adminCount <= 1) return res.status(400).json({ error: 'Cannot deactivate the last active administrator' });
  }

  const newName = name?.trim() || user.name;
  const newRole = VALID_ROLES.includes(role) ? role : user.role;
  const newActive = is_active !== undefined ? (is_active ? 1 : 0) : user.is_active;
  const newTitle = title !== undefined ? title?.trim() : user.title;
  const newPhone = phone !== undefined ? phone?.trim() : user.phone;

  // Optional password update
  let newHash = user.password_hash;
  if (password && password.trim()) {
    const pwdError = validatePasswordStrength(password);
    if (pwdError) return res.status(400).json({ error: pwdError });
    newHash = bcrypt.hashSync(password, 12);
  }

  db.prepare(`
    UPDATE users SET name=?, role=?, is_active=?, title=?, phone=?, password_hash=?
    WHERE id=?
  `).run(newName, newRole, newActive, newTitle, newPhone, newHash, user.id);

  recordAuditEntry(db, req.user.id, 'update_user', 'user', user.id, `Updated profile/role for user #${user.id}`);

  const updated = db.prepare('SELECT id, name, email, role, title, phone, is_active, created_at FROM users WHERE id = ?').get(user.id);
  return res.json(updated);
}

function getAnalysts(req, res) {
  const db = getDb();
  const analysts = db.prepare("SELECT id, name, email, role, title FROM users WHERE role IN ('admin','analyst') AND is_active = 1 ORDER BY name").all();
  return res.json(analysts);
}

module.exports = { listUsers, createUser, updateUser, getAnalysts };
