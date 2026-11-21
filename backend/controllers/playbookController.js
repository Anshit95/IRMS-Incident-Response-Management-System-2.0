const { getDb } = require('../database/schema');
const { runPlaybook, DEFAULT_PLAYBOOKS } = require('../services/playbookEngine');
const { recordAuditEntry } = require('../services/complianceService');

// GET /api/playbooks
function listPlaybooks(req, res) {
  const db = getDb();
  const playbooks = db.prepare('SELECT * FROM playbooks ORDER BY id ASC').all();
  return res.json(playbooks.map(p => ({
    ...p,
    steps: JSON.parse(p.steps_json)
  })));
}

// GET /api/playbooks/:id
function getPlaybook(req, res) {
  const db = getDb();
  const playbook = db.prepare('SELECT * FROM playbooks WHERE id = ?').get(req.params.id);
  if (!playbook) return res.status(404).json({ error: 'Playbook not found' });
  return res.json({
    ...playbook,
    steps: JSON.parse(playbook.steps_json)
  });
}

// POST /api/playbooks/:id/run
function executePlaybook(req, res) {
  const { incident_id } = req.body;
  if (!incident_id) return res.status(400).json({ error: 'incident_id is required' });

  if (req.user.role === 'viewer') {
    return res.status(403).json({ error: 'Viewers cannot trigger automated response playbooks.' });
  }

  try {
    const result = runPlaybook(req.params.id, incident_id, req.user.id);
    const db = getDb();
    recordAuditEntry(db, req.user.id, 'execute_playbook', 'playbook', req.params.id, `Triggered playbook "${result.playbook_name}" on incident #${incident_id}`);
    return res.json(result);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
}

// GET /api/playbooks/runs/incident/:incidentId
function getIncidentPlaybookRuns(req, res) {
  const db = getDb();
  const runs = db.prepare(`
    SELECT r.*, p.name as playbook_name, p.category, u.name as executed_by_name
    FROM playbook_runs r
    JOIN playbooks p ON r.playbook_id = p.id
    LEFT JOIN users u ON r.executed_by = u.id
    WHERE r.incident_id = ?
    ORDER BY r.id DESC
  `).all(req.params.incidentId);

  return res.json(runs.map(r => ({
    ...r,
    logs: JSON.parse(r.logs_json || '[]')
  })));
}

module.exports = {
  listPlaybooks,
  getPlaybook,
  executePlaybook,
  getIncidentPlaybookRuns
};
