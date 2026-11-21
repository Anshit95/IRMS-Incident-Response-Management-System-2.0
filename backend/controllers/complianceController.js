const { getDb } = require('../database/schema');
const { generateComplianceReport, verifyAuditChain, exportStixBundle } = require('../services/complianceService');

// GET /api/compliance/report
function getReport(req, res) {
  const standard = req.query.standard || 'SOC2_TYPE2';
  const report = generateComplianceReport(standard);
  return res.json(report);
}

// GET /api/compliance/verify-chain
function verifyChain(req, res) {
  const result = verifyAuditChain();
  return res.json(result);
}

// GET /api/compliance/export-stix/:incidentId
function exportStix(req, res) {
  try {
    const bundle = exportStixBundle(req.params.incidentId);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="stix21_incident_${req.params.incidentId}.json"`);
    return res.json(bundle);
  } catch (err) {
    return res.status(404).json({ error: err.message });
  }
}

// GET /api/compliance/audit-logs
function getAuditLogs(req, res) {
  const db = getDb();
  const { limit = 50, page = 1 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  const total = db.prepare('SELECT COUNT(*) as c FROM audit_logs').get().c;
  const logs = db.prepare(`
    SELECT a.*, u.name as actor_name, u.email as actor_email
    FROM audit_logs a
    LEFT JOIN users u ON a.actor_id = u.id
    ORDER BY a.id DESC
    LIMIT ? OFFSET ?
  `).all(parseInt(limit), offset);

  return res.json({
    logs,
    total,
    page: parseInt(page),
    limit: parseInt(limit),
    pages: Math.ceil(total / parseInt(limit))
  });
}

module.exports = {
  getReport,
  verifyChain,
  exportStix,
  getAuditLogs
};
