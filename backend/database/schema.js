const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const dbPath = process.env.DB_PATH || './data/irms.db';
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'irms.db');

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
  }
  return db;
}

function initializeSchema() {
  const database = getDb();

  database.exec(`
    -- Multi-tenant Organizations & Subscriptions
    CREATE TABLE IF NOT EXISTS organizations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      tier TEXT NOT NULL DEFAULT 'enterprise' CHECK(tier IN ('starter', 'professional', 'enterprise')),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'trial', 'past_due', 'cancelled')),
      max_seats INTEGER NOT NULL DEFAULT 25,
      incident_quota_monthly INTEGER NOT NULL DEFAULT 5000,
      threat_intel_quota_monthly INTEGER NOT NULL DEFAULT 10000,
      features_json TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER NOT NULL REFERENCES organizations(id),
      plan_id TEXT NOT NULL,
      plan_name TEXT NOT NULL,
      billing_cycle TEXT NOT NULL DEFAULT 'annual' CHECK(billing_cycle IN ('monthly', 'annual')),
      price_usd INTEGER NOT NULL DEFAULT 1999,
      current_period_start TEXT NOT NULL DEFAULT (datetime('now')),
      current_period_end TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      payment_method_last4 TEXT DEFAULT '4242',
      payment_brand TEXT DEFAULT 'Visa',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Users with Organization FK
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER DEFAULT 1 REFERENCES organizations(id),
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')),
      title TEXT DEFAULT 'Security Operations Specialist',
      phone TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Incidents with Enterprise Metrics (SLA, MITRE, CVE, Threat Actor)
    CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER DEFAULT 1 REFERENCES organizations(id),
      incident_code TEXT NOT NULL UNIQUE,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      incident_type TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
      status TEXT NOT NULL DEFAULT 'New' CHECK(status IN ('New', 'Investigating', 'Contained', 'Resolved', 'Closed', 'False Positive')),
      source TEXT,
      affected_asset TEXT,
      affected_user TEXT,
      cve_id TEXT,
      threat_actor TEXT,
      asset_importance TEXT DEFAULT 'Medium' CHECK(asset_importance IN ('Low', 'Medium', 'High', 'Critical')),
      potential_impact TEXT DEFAULT 'Medium' CHECK(potential_impact IN ('Low', 'Medium', 'High', 'Critical')),
      threat_confidence TEXT DEFAULT 'Medium' CHECK(threat_confidence IN ('Low', 'Medium', 'High')),
      risk_score INTEGER NOT NULL DEFAULT 0,
      assigned_analyst_id INTEGER REFERENCES users(id),
      created_by INTEGER NOT NULL REFERENCES users(id),
      sla_target_hours INTEGER DEFAULT 4,
      sla_breached INTEGER DEFAULT 0,
      acknowledged_at TEXT,
      contained_at TEXT,
      resolved_at TEXT,
      closed_at TEXT,
      resolution_summary TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      deleted_at TEXT
    );

    -- Investigation Notes
    CREATE TABLE IF NOT EXISTS investigation_notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER NOT NULL REFERENCES incidents(id),
      author_id INTEGER NOT NULL REFERENCES users(id),
      note TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Evidence Records
    CREATE TABLE IF NOT EXISTS evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER NOT NULL REFERENCES incidents(id),
      name TEXT NOT NULL,
      evidence_type TEXT NOT NULL,
      description TEXT,
      reference TEXT,
      file_hash TEXT,
      file_size_bytes INTEGER DEFAULT 0,
      added_by INTEGER NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Response & Containment Actions
    CREATE TABLE IF NOT EXISTS response_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER NOT NULL REFERENCES incidents(id),
      action_type TEXT NOT NULL,
      description TEXT NOT NULL,
      result TEXT,
      status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Completed', 'Failed')),
      performed_by INTEGER NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Incident Timeline
    CREATE TABLE IF NOT EXISTS timeline_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER NOT NULL REFERENCES incidents(id),
      actor_id INTEGER REFERENCES users(id),
      event_type TEXT NOT NULL,
      description TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- AI Forensic & Threat Intelligence Analyses
    CREATE TABLE IF NOT EXISTS ai_analyses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER NOT NULL REFERENCES incidents(id),
      provider_mode TEXT NOT NULL DEFAULT 'enterprise_cognitive',
      summary TEXT,
      attack_type TEXT,
      ciso_briefing TEXT,
      regulatory_impact TEXT,
      mitre_mapping_json TEXT,
      risk_explanation TEXT,
      findings_json TEXT,
      recommendations_json TEXT,
      evidence_recommendations_json TEXT,
      confidence_notes TEXT,
      created_by INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Indicators of Compromise (Threat Intelligence)
    CREATE TABLE IF NOT EXISTS indicators_of_compromise (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER REFERENCES incidents(id),
      organization_id INTEGER DEFAULT 1 REFERENCES organizations(id),
      ioc_type TEXT NOT NULL CHECK(ioc_type IN ('ip', 'domain', 'url', 'sha256', 'md5', 'cve', 'email')),
      value TEXT NOT NULL,
      threat_score INTEGER DEFAULT 0,
      reputation TEXT NOT NULL DEFAULT 'suspicious' CHECK(reputation IN ('malicious', 'suspicious', 'clean', 'unknown')),
      malware_family TEXT,
      threat_actor TEXT,
      asn TEXT,
      country TEXT,
      enrichment_json TEXT,
      created_by INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- MITRE ATT&CK Matrix Mapping
    CREATE TABLE IF NOT EXISTS incident_mitre_tactics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER NOT NULL REFERENCES incidents(id),
      tactic_id TEXT NOT NULL,
      tactic_name TEXT NOT NULL,
      technique_id TEXT NOT NULL,
      technique_name TEXT NOT NULL,
      details TEXT,
      confidence TEXT DEFAULT 'High' CHECK(confidence IN ('Low', 'Medium', 'High')),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- SOAR Playbooks
    CREATE TABLE IF NOT EXISTS playbooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER DEFAULT 1 REFERENCES organizations(id),
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      severity_trigger TEXT DEFAULT 'All',
      steps_json TEXT NOT NULL,
      tier_required TEXT NOT NULL DEFAULT 'professional' CHECK(tier_required IN ('starter', 'professional', 'enterprise')),
      is_active INTEGER NOT NULL DEFAULT 1,
      total_runs INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- SOAR Playbook Execution Runs
    CREATE TABLE IF NOT EXISTS playbook_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      playbook_id INTEGER NOT NULL REFERENCES playbooks(id),
      incident_id INTEGER NOT NULL REFERENCES incidents(id),
      status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running', 'completed', 'failed', 'paused')),
      current_step_index INTEGER NOT NULL DEFAULT 0,
      executed_by INTEGER REFERENCES users(id),
      logs_json TEXT,
      started_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT
    );

    -- SIEM & Inbound Webhooks
    CREATE TABLE IF NOT EXISTS webhook_endpoints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER DEFAULT 1 REFERENCES organizations(id),
      name TEXT NOT NULL,
      source_type TEXT NOT NULL CHECK(source_type IN ('guardduty', 'crowdstrike', 'splunk', 'sentinel', 'generic_json')),
      api_key TEXT NOT NULL UNIQUE,
      is_active INTEGER NOT NULL DEFAULT 1,
      total_received INTEGER NOT NULL DEFAULT 0,
      last_payload_preview TEXT,
      last_received_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Compliance Audits (SOC 2, ISO 27001, HIPAA)
    CREATE TABLE IF NOT EXISTS compliance_audits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER DEFAULT 1 REFERENCES organizations(id),
      standard TEXT NOT NULL CHECK(standard IN ('SOC2_TYPE2', 'ISO27001', 'HIPAA_SECURITY', 'NIST_CSF')),
      audit_name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'compliant' CHECK(status IN ('compliant', 'needs_review', 'non_compliant')),
      score_percent INTEGER NOT NULL DEFAULT 98,
      controls_json TEXT NOT NULL,
      generated_by INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Tamper-Evident HMAC Chained Audit Logs (SOC 2 Type II Compliant)
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER DEFAULT 1 REFERENCES organizations(id),
      actor_id INTEGER REFERENCES users(id),
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id INTEGER,
      details TEXT,
      ip_address TEXT DEFAULT '127.0.0.1',
      user_agent TEXT,
      prev_hash TEXT,
      entry_hash TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Incident code sequence counter
    CREATE TABLE IF NOT EXISTS incident_sequence (
      year INTEGER PRIMARY KEY,
      last_seq INTEGER NOT NULL DEFAULT 0
    );

    -- Performance Indexes
    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
    CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
    CREATE INDEX IF NOT EXISTS idx_incidents_assigned_analyst ON incidents(assigned_analyst_id);
    CREATE INDEX IF NOT EXISTS idx_incidents_sla ON incidents(sla_breached, status);
    CREATE INDEX IF NOT EXISTS idx_notes_incident ON investigation_notes(incident_id);
    CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);
    CREATE INDEX IF NOT EXISTS idx_actions_incident ON response_actions(incident_id);
    CREATE INDEX IF NOT EXISTS idx_timeline_incident ON timeline_events(incident_id);
    CREATE INDEX IF NOT EXISTS idx_ai_analyses_incident ON ai_analyses(incident_id);
    CREATE INDEX IF NOT EXISTS idx_iocs_incident ON indicators_of_compromise(incident_id);
    CREATE INDEX IF NOT EXISTS idx_iocs_value ON indicators_of_compromise(value);
    CREATE INDEX IF NOT EXISTS idx_mitre_incident ON incident_mitre_tactics(incident_id);
    CREATE INDEX IF NOT EXISTS idx_playbook_runs_incident ON playbook_runs(incident_id);
  `);

  console.log('Enterprise schema initialized successfully.');
  return database;
}

module.exports = { getDb, initializeSchema, DB_PATH };
