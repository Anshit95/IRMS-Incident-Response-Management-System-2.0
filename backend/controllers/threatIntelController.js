const { getDb } = require('../database/schema');
const { enrichIndicator, detectIocType } = require('../services/threatIntelService');
const { recordAuditEntry } = require('../services/complianceService');

// POST /api/threat-intel/lookup
async function lookupIndicator(req, res) {
  const { indicator } = req.body;
  if (!indicator || !indicator.trim()) {
    return res.status(400).json({ error: 'Indicator (IP, domain, hash, or CVE) is required' });
  }

  try {
    const enriched = await enrichIndicator(indicator);
    return res.json(enriched);
  } catch (err) {
    return res.status(500).json({ error: 'Threat lookup error: ' + err.message });
  }
}

// GET /api/threat-intel/indicators
function listIndicators(req, res) {
  const db = getDb();
  const { incident_id, type, reputation, limit = 50 } = req.query;

  let where = ['1=1'];
  const params = [];

  if (incident_id) {
    where.push('incident_id = ?');
    params.push(incident_id);
  }
  if (type) {
    where.push('ioc_type = ?');
    params.push(type);
  }
  if (reputation) {
    where.push('reputation = ?');
    params.push(reputation);
  }

  const iocs = db.prepare(`
    SELECT i.*, inc.incident_code, inc.title as incident_title, u.name as added_by_name
    FROM indicators_of_compromise i
    LEFT JOIN incidents inc ON i.incident_id = inc.id
    LEFT JOIN users u ON i.created_by = u.id
    WHERE ${where.join(' AND ')}
    ORDER BY i.id DESC
    LIMIT ?
  `).all(...params, parseInt(limit));

  return res.json(iocs.map(ioc => ({
    ...ioc,
    enrichment: JSON.parse(ioc.enrichment_json || '{}')
  })));
}

// POST /api/threat-intel/indicators
async function addIndicator(req, res) {
  const db = getDb();
  const { incident_id, value, ioc_type, threat_score, reputation, malware_family, threat_actor } = req.body;

  if (!value?.trim()) return res.status(400).json({ error: 'Indicator value is required' });
  if (req.user.role === 'viewer') return res.status(403).json({ error: 'Insufficient permissions' });

  // Auto-enrich if fields not supplied
  const enriched = await enrichIndicator(value);

  const finalType = ioc_type || enriched.ioc_type || detectIocType(value);
  const finalScore = threat_score !== undefined ? threat_score : enriched.threat_score;
  const finalRep = reputation || enriched.reputation;
  const finalFamily = malware_family || enriched.malware_family;
  const finalActor = threat_actor || enriched.threat_actor;

  const result = db.prepare(`
    INSERT INTO indicators_of_compromise (incident_id, organization_id, ioc_type, value, threat_score, reputation, malware_family, threat_actor, asn, country, enrichment_json, created_by)
    VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    incident_id || null,
    finalType,
    value.trim(),
    finalScore,
    finalRep,
    finalFamily || null,
    finalActor || null,
    enriched.asn || null,
    enriched.country || null,
    JSON.stringify(enriched.enrichment || {}),
    req.user.id
  );

  recordAuditEntry(db, req.user.id, 'add_ioc', 'ioc', result.lastInsertRowid, `Added IOC ${value} (${finalType}) with score ${finalScore}`);

  if (incident_id) {
    db.prepare(`
      INSERT INTO timeline_events (incident_id, actor_id, event_type, description)
      VALUES (?, ?, 'ioc_added', ?)
    `).run(incident_id, req.user.id, `Threat indicator added: ${value} [${finalType.toUpperCase()}] - Reputation: ${finalRep.toUpperCase()}`);
  }

  const created = db.prepare('SELECT * FROM indicators_of_compromise WHERE id = ?').get(result.lastInsertRowid);
  return res.status(201).json({
    ...created,
    enrichment: JSON.parse(created.enrichment_json || '{}')
  });
}

// GET /api/threat-intel/stats
function getThreatStats(req, res) {
  const db = getDb();
  const total = db.prepare('SELECT COUNT(*) as c FROM indicators_of_compromise').get().c;
  const malicious = db.prepare("SELECT COUNT(*) as c FROM indicators_of_compromise WHERE reputation = 'malicious'").get().c;
  const suspicious = db.prepare("SELECT COUNT(*) as c FROM indicators_of_compromise WHERE reputation = 'suspicious'").get().c;
  const clean = db.prepare("SELECT COUNT(*) as c FROM indicators_of_compromise WHERE reputation = 'clean'").get().c;

  const byType = db.prepare(`
    SELECT ioc_type, COUNT(*) as count
    FROM indicators_of_compromise
    GROUP BY ioc_type
  `).all();

  return res.json({
    total,
    malicious,
    suspicious,
    clean,
    byType
  });
}

module.exports = {
  lookupIndicator,
  listIndicators,
  addIndicator,
  getThreatStats
};
