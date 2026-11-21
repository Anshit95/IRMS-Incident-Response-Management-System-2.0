const crypto = require('crypto');
const { getDb } = require('../database/schema');
const { calculateRiskScore } = require('../services/riskScoring');
const { recordAuditEntry } = require('../services/complianceService');

function generateIncidentCode(db) {
  const year = new Date().getFullYear();
  const result = db.prepare(`
    INSERT INTO incident_sequence (year, last_seq) VALUES (?, 1)
    ON CONFLICT(year) DO UPDATE SET last_seq = last_seq + 1
    RETURNING last_seq
  `).get(year);
  return `INC-${year}-${String(result.last_seq).padStart(4, '0')}`;
}

// GET /api/webhooks
function listWebhooks(req, res) {
  const db = getDb();
  const endpoints = db.prepare('SELECT * FROM webhook_endpoints ORDER BY id DESC').all();
  return res.json(endpoints);
}

// POST /api/webhooks
function createWebhook(req, res) {
  const db = getDb();
  const { name, source_type } = req.body;

  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only admins can register webhook ingestion endpoints.' });
  }

  if (!name?.trim()) return res.status(400).json({ error: 'Endpoint name is required' });
  const validSources = ['guardduty', 'crowdstrike', 'splunk', 'sentinel', 'generic_json'];
  if (!validSources.includes(source_type)) {
    return res.status(400).json({ error: 'Invalid source_type. Supported: ' + validSources.join(', ') });
  }

  const apiKey = `irms_wh_${crypto.randomBytes(24).toString('hex')}`;

  const result = db.prepare(`
    INSERT INTO webhook_endpoints (organization_id, name, source_type, api_key)
    VALUES (1, ?, ?, ?)
  `).run(name.trim(), source_type, apiKey);

  recordAuditEntry(db, req.user.id, 'create_webhook', 'webhook_endpoint', result.lastInsertRowid, `Created ${source_type} webhook: ${name.trim()}`);

  const created = db.prepare('SELECT * FROM webhook_endpoints WHERE id = ?').get(result.lastInsertRowid);
  return res.status(201).json(created);
}

// POST /api/webhooks/ingest/:apiKey (Public Ingest Endpoint)
function ingestAlert(req, res) {
  const db = getDb();
  const apiKey = req.params.apiKey;

  if (!apiKey || !/^irms_wh_[a-zA-Z0-9_-]{10,80}$/.test(apiKey)) {
    return res.status(401).json({ error: 'Invalid or inactive webhook API key' });
  }

  const endpoint = db.prepare('SELECT * FROM webhook_endpoints WHERE api_key = ? AND is_active = 1').get(apiKey);
  if (!endpoint) {
    return res.status(401).json({ error: 'Invalid or inactive webhook API key' });
  }

  const payload = req.body || {};
  let title = 'Inbound SIEM Alert';
  let description = 'Automated alert ingested via SIEM webhook.';
  let severity = 'Medium';
  let incident_type = 'Other';
  let affected_asset = 'Unknown Asset';
  let affected_user = null;
  let source = `${endpoint.source_type.toUpperCase()} Ingestion Pipeline`;

  // Parse according to source type
  if (endpoint.source_type === 'guardduty') {
    title = payload.title || payload.detail?.title || 'AWS GuardDuty Finding';
    description = payload.description || payload.detail?.description || JSON.stringify(payload);
    const sevNum = payload.detail?.severity || 5;
    severity = sevNum >= 7 ? 'Critical' : sevNum >= 4 ? 'High' : 'Medium';
    incident_type = 'Unauthorized Access';
    affected_asset = payload.detail?.resource?.instanceDetails?.instanceId || 'AWS EC2 / IAM';
  } else if (endpoint.source_type === 'crowdstrike') {
    title = payload.detect_description || payload.title || 'CrowdStrike Falcon Detection';
    description = payload.tactic || payload.technique || 'Malware activity blocked by Falcon Sensor.';
    severity = payload.severity === 'Critical' ? 'Critical' : 'High';
    incident_type = 'Malware';
    affected_asset = payload.computer_name || 'Windows Endpoint';
  } else {
    title = payload.title || payload.alert_name || 'Generic Alert ' + new Date().toISOString();
    description = payload.description || payload.message || JSON.stringify(payload);
    severity = ['Low', 'Medium', 'High', 'Critical'].includes(payload.severity) ? payload.severity : 'Medium';
    incident_type = ['Phishing', 'Malware', 'Brute Force', 'Suspicious Login', 'Data Breach', 'Unauthorized Access', 'Ransomware', 'Other'].includes(payload.incident_type) ? payload.incident_type : 'Other';
    affected_asset = payload.affected_asset || payload.host || 'Corporate Network';
  }

  const riskScore = calculateRiskScore({
    severity,
    asset_importance: 'High',
    potential_impact: severity === 'Critical' ? 'Critical' : 'High',
    threat_confidence: 'High'
  });

  const incidentCode = generateIncidentCode(db);

  // Assign to first available active analyst
  const analyst = db.prepare('SELECT id FROM users WHERE role = "analyst" AND is_active = 1 LIMIT 1').get();
  const analystId = analyst ? analyst.id : 1;

  const result = db.prepare(`
    INSERT INTO incidents (incident_code, title, description, incident_type, severity, source, affected_asset, affected_user, asset_importance, potential_impact, threat_confidence, risk_score, assigned_analyst_id, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'High', ?, 'High', ?, ?, ?)
  `).run(
    incidentCode,
    title,
    description,
    incident_type,
    severity,
    source,
    affected_asset,
    affected_user,
    severity === 'Critical' ? 'Critical' : 'High',
    riskScore,
    analystId,
    1
  );

  const incId = result.lastInsertRowid;

  // Add timeline entry
  db.prepare(`
    INSERT INTO timeline_events (incident_id, actor_id, event_type, description)
    VALUES (?, ?, 'webhook_ingested', ?)
  `).run(incId, 1, `Ingested automatically from ${endpoint.name} (${endpoint.source_type}). Incident code: ${incidentCode}`);

  // Update webhook stats
  db.prepare(`
    UPDATE webhook_endpoints
    SET total_received = total_received + 1, last_received_at = datetime('now'), last_payload_preview = ?
    WHERE id = ?
  `).run(JSON.stringify(payload).substring(0, 500), endpoint.id);

  return res.status(201).json({
    success: true,
    incident_id: incId,
    incident_code: incidentCode,
    message: 'Alert ingested and incident created successfully'
  });
}

module.exports = {
  listWebhooks,
  createWebhook,
  ingestAlert
};
