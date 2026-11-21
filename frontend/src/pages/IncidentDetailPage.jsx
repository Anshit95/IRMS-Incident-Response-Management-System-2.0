import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Edit2, ArrowLeft, RefreshCw, BrainCircuit, Plus, Clock,
  FileSearch, ShieldCheck, Zap, MessageSquare, AlertTriangle, Search,
  Globe, FileCode, Play, CheckCircle2, Shield, ExternalLink, Hash
} from 'lucide-react';
import api from '../services/api.js';
import { useAuth } from '../context/AuthContext.jsx';
import toast from 'react-hot-toast';
import {
  severityBadge, statusBadge, riskClass, riskCategory,
  formatDate, formatDateTime, timelineIcon, apiError,
  STATUS_OPTIONS, ACTION_TYPES, EVIDENCE_TYPES, SEVERITY_OPTIONS
} from '../utils/helpers.js';

// ── Sub-components ─────────────────────────────────────────────────────────────

function RiskBar({ score }) {
  return (
    <div className="risk-bar-wrapper" style={{ minWidth: 160 }}>
      <div className="risk-bar-track" style={{ flex: 1 }}>
        <div className={`risk-bar-fill ${riskClass(score)}`} style={{ width: `${score}%` }} />
      </div>
      <span style={{ fontSize: 13, fontWeight: 600, minWidth: 40 }}>
        {score}<span style={{ fontSize: 11, fontWeight: 400, color: 'var(--text-secondary)' }}>/100</span>
      </span>
    </div>
  );
}

function DetailField({ label, children }) {
  return (
    <div className="detail-item">
      <div className="detail-label">{label}</div>
      <div className="detail-value">{children || '—'}</div>
    </div>
  );
}

// ── Overview Tab ───────────────────────────────────────────────────────────────

function OverviewTab({ incident, onStatusChange, analysts, user }) {
  const navigate = useNavigate();
  const [statusModal, setStatusModal] = useState(false);
  const [statusForm, setStatusForm] = useState({ status: incident.status, resolution_summary: incident.resolution_summary || '' });
  const [saving, setSaving] = useState(false);

  const handleStatusSave = async () => {
    setSaving(true);
    try {
      await api.patch(`/incidents/${incident.id}/status`, statusForm);
      toast.success('Status updated');
      setStatusModal(false);
      onStatusChange();
    } catch (err) {
      toast.error(apiError(err));
    } finally {
      setSaving(false);
    }
  };

  const handleExportStix = () => {
    window.open(`/api/compliance/export-stix/${incident.id}`, '_blank');
  };

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      {/* Header bar */}
      <div className="card">
        <div className="card-body" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
              <span className="incident-id" style={{ fontSize: 14 }}>{incident.incident_code}</span>
              <span className={`badge ${severityBadge(incident.severity)}`}>{incident.severity}</span>
              <span className={`badge ${statusBadge(incident.status)}`}>{incident.status}</span>
              {incident.cve_id && (
                <span className="badge badge-neutral" style={{ background: '#F1F5F9', color: '#0F172A', fontWeight: 700 }}>
                  {incident.cve_id}
                </span>
              )}
              {incident.threat_actor && (
                <span className="badge badge-neutral" style={{ background: '#FEF3C7', color: '#92400E', fontWeight: 600 }}>
                  Actor: {incident.threat_actor}
                </span>
              )}
            </div>
            <h2 style={{ fontSize: 17, fontWeight: 700, margin: 0, color: 'var(--text-primary)', lineHeight: 1.4 }}>
              {incident.title}
            </h2>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn btn-secondary btn-sm" onClick={handleExportStix}>
              <FileCode size={13} /> Export STIX 2.1
            </button>
            {['admin', 'analyst'].includes(user?.role) && (
              <>
                <button className="btn btn-secondary btn-sm" onClick={() => setStatusModal(true)}>
                  <RefreshCw size={13} /> Change Status
                </button>
                <button className="btn btn-secondary btn-sm" onClick={() => navigate(`/incidents/${incident.id}/edit`)}>
                  <Edit2 size={13} /> Edit
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix Tactics Strip */}
      {incident.mitre && incident.mitre.length > 0 && (
        <div className="card" style={{ borderLeft: '4px solid #2563EB' }}>
          <div className="card-header" style={{ paddingBottom: 6 }}>
            <span className="card-title" style={{ fontSize: 13 }}>MITRE ATT&CK Matrix Mapping</span>
          </div>
          <div className="card-body" style={{ paddingTop: 6 }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {incident.mitre.map(m => (
                <div key={m.id} style={{
                  background: '#EFF6FF',
                  border: '1px solid #BFDBFE',
                  padding: '6px 12px',
                  borderRadius: 6,
                  fontSize: 12
                }}>
                  <div style={{ color: '#1E40AF', fontWeight: 700 }}>
                    {m.tactic_name} ({m.tactic_id})
                  </div>
                  <div style={{ color: '#1E293B', fontWeight: 500 }}>
                    {m.technique_id}: {m.technique_name}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SLA & Risk Score Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Risk Score */}
        <div className="card">
          <div className="card-header"><span className="card-title">Risk Score Assessment</span></div>
          <div className="card-body">
            <RiskBar score={incident.risk_score} />
            <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-secondary)' }}>
              Category: <strong style={{ color: incident.risk_score >= 81 ? '#DC2626' : incident.risk_score >= 61 ? '#EA580C' : incident.risk_score >= 31 ? '#CA8A04' : '#16A34A' }}>
                {riskCategory(incident.risk_score)}
              </strong> • Threat Confidence: <strong>{incident.threat_confidence}</strong>
            </div>
          </div>
        </div>

        {/* SLA Telemetry */}
        <div className="card">
          <div className="card-header"><span className="card-title">Enterprise SLA Management</span></div>
          <div className="card-body">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ fontSize: 12, color: '#64748B' }}>Target SLA Window:</span>
              <span style={{ fontWeight: 700, fontSize: 13, color: '#0F172A' }}>
                {incident.sla_target_hours || 4} Hours ({incident.severity})
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: '#64748B' }}>SLA Performance:</span>
              {incident.status === 'Resolved' || incident.status === 'Closed' ? (
                <span className="badge badge-low">MET & RESOLVED</span>
              ) : incident.sla_breached ? (
                <span className="badge badge-critical">SLA BREACHED</span>
              ) : (
                <span className="badge badge-low">ON TARGET</span>
              )}
            </div>
            <div style={{ fontSize: 11, color: '#64748B', marginTop: 8 }}>
              Acknowledged: {incident.acknowledged_at ? formatDateTime(incident.acknowledged_at) : 'Pending'} • Contained: {incident.contained_at ? formatDateTime(incident.contained_at) : 'Pending'}
            </div>
          </div>
        </div>
      </div>

      {/* Details grid */}
      <div className="card">
        <div className="card-header"><span className="card-title">Incident Details</span></div>
        <div className="card-body">
          <div className="detail-grid" style={{ marginBottom: 16 }}>
            <DetailField label="Incident Type">{incident.incident_type}</DetailField>
            <DetailField label="Assigned Analyst">{incident.analyst_name || 'Unassigned'}</DetailField>
            <DetailField label="Affected Asset">{incident.affected_asset}</DetailField>
            <DetailField label="Affected User">{incident.affected_user}</DetailField>
            <DetailField label="Alert Source">{incident.source}</DetailField>
            <DetailField label="Asset Importance">{incident.asset_importance}</DetailField>
            <DetailField label="Potential Impact">{incident.potential_impact}</DetailField>
            <DetailField label="Threat Confidence">{incident.threat_confidence}</DetailField>
            <DetailField label="Created">{formatDateTime(incident.created_at)}</DetailField>
            <DetailField label="Last Updated">{formatDateTime(incident.updated_at)}</DetailField>
            {incident.resolved_at && <DetailField label="Resolved At">{formatDateTime(incident.resolved_at)}</DetailField>}
            {incident.closed_at && <DetailField label="Closed At">{formatDateTime(incident.closed_at)}</DetailField>}
          </div>

          <div>
            <div className="detail-label">Description</div>
            <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.6, whiteSpace: 'pre-wrap', marginTop: 4 }}>
              {incident.description}
            </div>
          </div>
          {incident.resolution_summary && (
            <div style={{ marginTop: 14 }}>
              <div className="detail-label">Resolution Summary</div>
              <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.6, whiteSpace: 'pre-wrap', marginTop: 4 }}>
                {incident.resolution_summary}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Status Modal */}
      {statusModal && (
        <div className="modal-overlay" onClick={() => setStatusModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 420 }}>
            <div className="modal-header">
              <span className="modal-title">Update Incident Status</span>
              <button className="btn btn-ghost btn-icon btn-sm" onClick={() => setStatusModal(false)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label className="form-label">New Status</label>
                <select className="form-select" value={statusForm.status} onChange={e => setStatusForm(f => ({ ...f, status: e.target.value }))}>
                  {STATUS_OPTIONS.map(s => <option key={s}>{s}</option>)}
                </select>
              </div>
              {['Resolved', 'Closed', 'False Positive'].includes(statusForm.status) && (
                <div className="form-group">
                  <label className="form-label">Resolution / Explanation<span className="form-required">*</span></label>
                  <textarea className="form-textarea" rows={3} value={statusForm.resolution_summary} onChange={e => setStatusForm(f => ({ ...f, resolution_summary: e.target.value }))} placeholder="Document the resolution steps or reason for this status..." />
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setStatusModal(false)}>Cancel</button>
              <button className="btn btn-primary" disabled={saving} onClick={handleStatusSave}>
                {saving ? <><span className="spinner" /> Saving…</> : 'Update Status'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── SOAR Playbooks Tab ────────────────────────────────────────────────────────

function SOARPlaybooksTab({ incident, user, onStatusChange }) {
  const [playbooks, setPlaybooks] = useState([]);
  const [runs, setRuns] = useState(incident.playbook_runs || []);
  const [executingId, setExecutingId] = useState(null);

  useEffect(() => {
    api.get('/playbooks').then(r => setPlaybooks(r.data)).catch(() => {});
    api.get(`/playbooks/runs/incident/${incident.id}`).then(r => setRuns(r.data)).catch(() => {});
  }, [incident.id]);

  const runPlaybook = async (pb) => {
    try {
      setExecutingId(pb.id);
      const res = await api.post(`/playbooks/${pb.id}/run`, { incident_id: incident.id });
      toast.success(`Playbook "${pb.name}" executed!`);
      // Reload runs and incident
      const runsRes = await api.get(`/playbooks/runs/incident/${incident.id}`);
      setRuns(runsRes.data);
      onStatusChange();
    } catch (err) {
      toast.error(apiError(err));
    } finally {
      setExecutingId(null);
    }
  };

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      {/* Available Automated Playbooks */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Available Automated Containment Playbooks</span>
        </div>
        <div className="card-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 14 }}>
            {playbooks.map(pb => (
              <div key={pb.id} style={{
                background: '#F8FAFC',
                border: '1px solid #E2E8F0',
                borderRadius: 8,
                padding: 16,
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between'
              }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: '#2563EB' }}>
                      {pb.category}
                    </span>
                    <span style={{ fontSize: 11, color: '#64748B' }}>
                      {pb.steps?.length || 0} Steps
                    </span>
                  </div>
                  <h4 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 6px 0', color: '#0F172A' }}>
                    {pb.name}
                  </h4>
                  <p style={{ fontSize: 12, color: '#475569', margin: '0 0 12px 0' }}>
                    {pb.description}
                  </p>
                </div>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => runPlaybook(pb)}
                  disabled={executingId !== null || user?.role === 'viewer'}
                  style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}
                >
                  {executingId === pb.id ? (
                    <><span className="spinner" /> Orchestrating...</>
                  ) : (
                    <><Play size={13} /> Trigger Automated Run</>
                  )}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Completed Runs History */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Completed Containment Runs ({runs.length})</span>
        </div>
        <div className="card-body">
          {runs.length === 0 ? (
            <div className="empty-state">
              <Zap size={28} />
              <p className="empty-state-title">No playbooks executed yet</p>
              <p className="empty-state-desc">Trigger a containment playbook above to automate host isolation, WAF rules, and credential revocation.</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {runs.map(run => (
                <div key={run.id} style={{
                  background: '#0F172A',
                  color: '#F8FAFC',
                  borderRadius: 6,
                  padding: 14,
                  fontFamily: 'Consolas, monospace',
                  fontSize: 12
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: '#38BDF8', marginBottom: 8, fontWeight: 700 }}>
                    <span>PLAYBOOK: {run.playbook_name} [STATUS: {run.status.toUpperCase()}]</span>
                    <span>{run.completed_at || run.started_at}</span>
                  </div>
                  {run.logs?.map((step, idx) => (
                    <div key={idx} style={{ marginBottom: 6 }}>
                      <div style={{ color: '#4ADE80' }}>✓ {step.title || step.step} [{step.status}]</div>
                      <div style={{ color: '#94A3B8', paddingLeft: 14 }}>{step.output}</div>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Threat Intel & IOCs Tab ───────────────────────────────────────────────────

function ThreatIntelTab({ incident, user, onStatusChange }) {
  const [iocs, setIocs] = useState(incident.iocs || []);
  const [val, setVal] = useState('');
  const [type, setType] = useState('ip');
  const [adding, setAdding] = useState(false);

  const addIoc = async (e) => {
    e.preventDefault();
    if (!val.trim()) return;
    setAdding(true);
    try {
      const res = await api.post('/threat-intel/indicators', {
        incident_id: incident.id,
        value: val.trim(),
        ioc_type: type
      });
      toast.success('Indicator added & enriched!');
      setIocs([res.data, ...iocs]);
      setVal('');
      onStatusChange();
    } catch (err) {
      toast.error(apiError(err));
    } finally {
      setAdding(false);
    }
  };

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      {/* Add IOC Form */}
      {['admin', 'analyst'].includes(user?.role) && (
        <div className="card">
          <div className="card-header"><span className="card-title">Add & Correlate Indicator of Compromise (IOC)</span></div>
          <div className="card-body">
            <form onSubmit={addIoc} style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <select className="form-select" value={type} onChange={e => setType(e.target.value)} style={{ width: 140 }}>
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="sha256">SHA-256 Hash</option>
                <option value="cve">CVE ID</option>
              </select>
              <input
                type="text"
                className="form-input"
                placeholder="Enter IP, domain, hash, or CVE..."
                value={val}
                onChange={e => setVal(e.target.value)}
                style={{ flex: 1, minWidth: 240 }}
                required
              />
              <button type="submit" className="btn btn-primary btn-sm" disabled={adding}>
                {adding ? 'Enriching...' : 'Add Indicator'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Linked IOCs Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Linked Threat Indicators ({iocs.length})</span>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <table className="table">
            <thead>
              <tr>
                <th>Indicator Value</th>
                <th>Type</th>
                <th>Reputation</th>
                <th>Threat Score</th>
                <th>Malware Family / Actor</th>
                <th>ASN / Location</th>
              </tr>
            </thead>
            <tbody>
              {iocs.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: 30, color: '#94A3B8' }}>
                    No threat indicators linked to this incident yet.
                  </td>
                </tr>
              ) : (
                iocs.map(ioc => (
                  <tr key={ioc.id}>
                    <td>
                      <span style={{ fontFamily: 'Consolas, monospace', fontSize: 12, fontWeight: 700 }}>
                        {ioc.value}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-neutral" style={{ textTransform: 'uppercase', fontSize: 10 }}>
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td>
                      <span className={`badge badge-${ioc.reputation === 'malicious' ? 'critical' : ioc.reputation === 'suspicious' ? 'high' : 'low'}`} style={{ textTransform: 'uppercase' }}>
                        {ioc.reputation}
                      </span>
                    </td>
                    <td>
                      <strong>{ioc.threat_score}</strong> / 100
                    </td>
                    <td>
                      {ioc.malware_family || ioc.threat_actor || '—'}
                    </td>
                    <td style={{ fontSize: 11.5, color: '#64748B' }}>
                      {ioc.asn || ioc.country || 'Global'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Investigation Tab ─────────────────────────────────────────────────────────

function InvestigationTab({ incidentId, user }) {
  const [notes, setNotes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [noteText, setNoteText] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    api.get(`/incidents/${incidentId}/notes`).then(r => setNotes(r.data)).finally(() => setLoading(false));
  }, [incidentId]);

  useEffect(() => { load(); }, [load]);

  const addNote = async () => {
    if (!noteText.trim()) return;
    setSaving(true);
    try {
      await api.post(`/incidents/${incidentId}/notes`, { note: noteText.trim() });
      toast.success('Note added');
      setNoteText('');
      load();
    } catch (err) {
      toast.error(apiError(err));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="loading-center"><span className="spinner" /> Loading notes…</div>;

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {['admin', 'analyst'].includes(user?.role) && (
        <div className="card">
          <div className="card-header"><span className="card-title">Add Investigation Note</span></div>
          <div className="card-body">
            <textarea
              className="form-textarea"
              rows={4}
              value={noteText}
              onChange={e => setNoteText(e.target.value)}
              placeholder="Document your findings, observations, or investigative steps…"
              maxLength={5000}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{noteText.length}/5000</span>
              <button className="btn btn-primary btn-sm" disabled={saving || !noteText.trim()} onClick={addNote}>
                {saving ? <><span className="spinner" /> Saving…</> : <><Plus size={13} /> Add Note</>}
              </button>
            </div>
          </div>
        </div>
      )}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Investigation Notes</span>
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{notes.length} note{notes.length !== 1 ? 's' : ''}</span>
        </div>
        {notes.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon"><MessageSquare size={28} /></div>
            <p className="empty-state-title">No notes yet</p>
            <p className="empty-state-desc">Add an investigation note to document your findings.</p>
          </div>
        ) : (
          <div style={{ padding: '0 0 8px' }}>
            {notes.map((note, i) => (
              <div key={note.id} style={{ padding: '14px 16px', borderBottom: i < notes.length - 1 ? '1px solid var(--border)' : 'none' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{note.author_name || 'Unknown'}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{formatDateTime(note.created_at)}</span>
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{note.note}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Evidence Tab ──────────────────────────────────────────────────────────────

function EvidenceTab({ incidentId, user }) {
  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(false);
  const [form, setForm] = useState({ name: '', evidence_type: 'Log', description: '', reference: '', file_hash: '' });
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    api.get(`/incidents/${incidentId}/evidence`).then(r => setEvidence(r.data)).finally(() => setLoading(false));
  }, [incidentId]);

  useEffect(() => { load(); }, [load]);

  const addEv = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.post(`/incidents/${incidentId}/evidence`, form);
      toast.success('Evidence added');
      setModal(false);
      setForm({ name: '', evidence_type: 'Log', description: '', reference: '', file_hash: '' });
      load();
    } catch (err) {
      toast.error(apiError(err));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="loading-center"><span className="spinner" /> Loading evidence…</div>;

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="card">
        <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="card-title">Collected Evidence Artifacts</span>
          {['admin', 'analyst'].includes(user?.role) && (
            <button className="btn btn-primary btn-sm" onClick={() => setModal(true)}>
              <Plus size={13} /> Add Evidence
            </button>
          )}
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {evidence.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon"><FileSearch size={28} /></div>
              <p className="empty-state-title">No evidence recorded</p>
              <p className="empty-state-desc">Collect logs, screenshots, and file hashes to build an evidentiary audit trail.</p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Description</th>
                  <th>File Hash</th>
                  <th>Added By</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {evidence.map(ev => (
                  <tr key={ev.id}>
                    <td style={{ fontWeight: 600 }}>{ev.name}</td>
                    <td><span className="badge badge-neutral">{ev.evidence_type}</span></td>
                    <td style={{ fontSize: 12, maxWidth: 260 }}>{ev.description || '—'}</td>
                    <td>
                      {ev.file_hash ? (
                        <span style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: '#2563EB' }}>
                          {ev.file_hash.substring(0, 16)}...
                        </span>
                      ) : '—'}
                    </td>
                    <td style={{ fontSize: 12 }}>{ev.added_by_name || '—'}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{formatDate(ev.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {modal && (
        <div className="modal-overlay" onClick={() => setModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 460 }}>
            <div className="modal-header">
              <span className="modal-title">Record Evidence Artifact</span>
              <button className="btn btn-ghost btn-icon btn-sm" onClick={() => setModal(false)}>✕</button>
            </div>
            <form onSubmit={addEv}>
              <div className="modal-body">
                <div className="form-group">
                  <label className="form-label">Evidence Name<span className="form-required">*</span></label>
                  <input className="form-input" required value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Memory Dump / Winlogon Hook" />
                </div>
                <div className="form-group">
                  <label className="form-label">Type</label>
                  <select className="form-select" value={form.evidence_type} onChange={e => setForm(f => ({ ...f, evidence_type: e.target.value }))}>
                    {EVIDENCE_TYPES.map(t => <option key={t}>{t}</option>)}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">SHA-256 Hash</label>
                  <input className="form-input" value={form.file_hash} onChange={e => setForm(f => ({ ...f, file_hash: e.target.value }))} placeholder="64-character hash..." />
                </div>
                <div className="form-group">
                  <label className="form-label">Description</label>
                  <textarea className="form-textarea" rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={saving}>
                  {saving ? 'Recording…' : 'Record Evidence'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Response Actions Tab ──────────────────────────────────────────────────────

function ActionsTab({ incidentId, user }) {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(false);
  const [form, setForm] = useState({ action_type: 'Block IP', description: '', result: '', status: 'Completed' });
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    api.get(`/incidents/${incidentId}/actions`).then(r => setActions(r.data)).finally(() => setLoading(false));
  }, [incidentId]);

  useEffect(() => { load(); }, [load]);

  const addAct = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.post(`/incidents/${incidentId}/actions`, form);
      toast.success('Response action recorded');
      setModal(false);
      setForm({ action_type: 'Block IP', description: '', result: '', status: 'Completed' });
      load();
    } catch (err) {
      toast.error(apiError(err));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="loading-center"><span className="spinner" /> Loading response actions…</div>;

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="card">
        <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="card-title">Manual & Simulated Containment Actions</span>
          {['admin', 'analyst'].includes(user?.role) && (
            <button className="btn btn-primary btn-sm" onClick={() => setModal(true)}>
              <Plus size={13} /> Record Action
            </button>
          )}
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {actions.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon"><Zap size={28} /></div>
              <p className="empty-state-title">No actions recorded</p>
              <p className="empty-state-desc">Record firewall blocks, account suspensions, and endpoint isolations.</p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Action Type</th>
                  <th>Description</th>
                  <th>Execution Result</th>
                  <th>Status</th>
                  <th>Operator</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {actions.map(act => (
                  <tr key={act.id}>
                    <td><span className="badge badge-neutral" style={{ fontWeight: 600 }}>{act.action_type}</span></td>
                    <td style={{ fontSize: 12.5 }}>{act.description}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{act.result || '—'}</td>
                    <td><span className="badge badge-low">{act.status}</span></td>
                    <td style={{ fontSize: 12 }}>{act.performed_by_name || 'Automation'}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{formatDateTime(act.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {modal && (
        <div className="modal-overlay" onClick={() => setModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 440 }}>
            <div className="modal-header">
              <span className="modal-title">Record Response Action</span>
              <button className="btn btn-ghost btn-icon btn-sm" onClick={() => setModal(false)}>✕</button>
            </div>
            <form onSubmit={addAct}>
              <div className="modal-body">
                <div className="form-group">
                  <label className="form-label">Action Type</label>
                  <select className="form-select" value={form.action_type} onChange={e => setForm(f => ({ ...f, action_type: e.target.value }))}>
                    {ACTION_TYPES.map(t => <option key={t}>{t}</option>)}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Description<span className="form-required">*</span></label>
                  <textarea className="form-textarea" required rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Details of the containment action executed..." />
                </div>
                <div className="form-group">
                  <label className="form-label">Result</label>
                  <input className="form-input" value={form.result} onChange={e => setForm(f => ({ ...f, result: e.target.value }))} placeholder="e.g. Success, IP blocked for 48 hours" />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={saving}>
                  {saving ? 'Recording…' : 'Record Action'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Timeline Tab ──────────────────────────────────────────────────────────────

function TimelineTab({ incidentId }) {
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get(`/incidents/${incidentId}/timeline`).then(r => setTimeline(r.data)).finally(() => setLoading(false));
  }, [incidentId]);

  if (loading) return <div className="loading-center"><span className="spinner" /> Loading timeline…</div>;

  return (
    <div className="card">
      <div className="card-header"><span className="card-title">Incident Forensic Audit Timeline</span></div>
      <div className="card-body">
        {timeline.length === 0 ? (
          <div className="empty-state">
            <Clock size={28} />
            <p className="empty-state-title">No timeline events recorded</p>
          </div>
        ) : (
          <div className="timeline">
            {timeline.map((ev, i) => (
              <div key={ev.id || i} className="timeline-item">
                <div className="timeline-dot" />
                <div className="timeline-header">
                  <span className="timeline-label" style={{ fontWeight: 600 }}>{ev.description}</span>
                  <span className="timeline-time">{formatDateTime(ev.created_at)}</span>
                </div>
                {ev.actor_name && <div className="timeline-actor" style={{ fontSize: 11, color: '#64748B' }}>By {ev.actor_name}</div>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── AI Analysis Tab ───────────────────────────────────────────────────────────

function AIAnalysisTab({ incidentId, user }) {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [activeIdx, setActiveIdx] = useState(0);

  const load = useCallback(() => {
    api.get(`/incidents/${incidentId}/ai-analysis`)
      .then(r => {
        const data = Array.isArray(r.data) ? r.data : r.data.analyses || [];
        setAnalyses(data);
        setActiveIdx(0);
      })
      .finally(() => setLoading(false));
  }, [incidentId]);

  useEffect(() => { load(); }, [load]);

  const runAnalysis = async () => {
    setRunning(true);
    try {
      await api.post(`/incidents/${incidentId}/ai-analysis`);
      toast.success('Cognitive Defense AI analysis complete');
      load();
    } catch (err) {
      toast.error(apiError(err));
    } finally {
      setRunning(false);
    }
  };

  if (loading) return <div className="loading-center"><span className="spinner" /> Loading AI analyses…</div>;

  const current = analyses[activeIdx];

  const safeJson = (val) => {
    if (!val) return [];
    if (Array.isArray(val)) return val;
    try { return JSON.parse(val); } catch { return [val]; }
  };

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {/* Controls */}
      <div className="card">
        <div className="card-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <BrainCircuit size={22} color="#4F46E5" />
            <div>
              <div style={{ fontSize: 14, fontWeight: 700 }}>Cognitive Defense AI Copilot</div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                {analyses.length === 0 ? 'No analyses run yet' : `${analyses.length} analysis reports generated`}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {current && (
              <span className="badge badge-neutral" style={{ background: '#EEF2FF', color: '#4338CA', fontWeight: 600 }}>
                ⚡ Mode: {current.provider_mode}
              </span>
            )}
            {['admin', 'analyst'].includes(user?.role) && (
              <button className="btn btn-primary btn-sm" disabled={running} onClick={runAnalysis}>
                {running ? <><span className="spinner" /> Analysing...</> : <><BrainCircuit size={13} /> Run Cognitive Analysis</>}
              </button>
            )}
          </div>
        </div>
      </div>

      {!current ? (
        <div className="card">
          <div className="empty-state" style={{ padding: 48 }}>
            <div className="empty-state-icon"><BrainCircuit size={36} /></div>
            <p className="empty-state-title">No AI analysis yet</p>
            <p className="empty-state-desc">Click "Run Cognitive Analysis" to generate executive briefings, MITRE ATT&CK correlation, and containment recommendations.</p>
          </div>
        </div>
      ) : (
        <>
          {/* CISO Executive Briefing */}
          {current.ciso_briefing && (
            <div className="card" style={{ borderLeft: '4px solid #7C3AED' }}>
              <div className="card-header"><span className="card-title">CISO & Board Executive Briefing</span></div>
              <div className="card-body">
                <div style={{ fontSize: 13, lineHeight: 1.6, color: '#1E293B', fontWeight: 500 }}>
                  {current.ciso_briefing}
                </div>
              </div>
            </div>
          )}

          {/* Regulatory Advisory */}
          {current.regulatory_impact && (
            <div className="card" style={{ borderLeft: '4px solid #DC2626' }}>
              <div className="card-header"><span className="card-title">Regulatory Notification Advisory</span></div>
              <div className="card-body">
                <div style={{ fontSize: 12.5, lineHeight: 1.6, color: '#991B1B' }}>
                  {current.regulatory_impact}
                </div>
              </div>
            </div>
          )}

          {/* Technical Summary */}
          <div className="card">
            <div className="card-header"><span className="card-title">Technical Incident Summary</span></div>
            <div className="card-body">
              <div style={{ fontSize: 13, lineHeight: 1.7, color: 'var(--text-primary)' }}>
                {current.summary}
              </div>
            </div>
          </div>

          {/* Findings */}
          {safeJson(current.findings_json).length > 0 && (
            <div className="card">
              <div className="card-header"><span className="card-title">Forensic Technical Findings</span></div>
              <div className="card-body">
                <ul className="ai-finding-list">
                  {safeJson(current.findings_json).map((f, i) => <li key={i}>{f}</li>)}
                </ul>
              </div>
            </div>
          )}

          {/* Recommendations */}
          {safeJson(current.recommendations_json).length > 0 && (
            <div className="card">
              <div className="card-header"><span className="card-title">Recommended Containment Actions</span></div>
              <div className="card-body">
                <ol className="ai-rec-list">
                  {safeJson(current.recommendations_json).map((r, i) => <li key={i}>{r}</li>)}
                </ol>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

const TABS = [
  { key: 'overview', label: 'Overview', icon: ShieldCheck },
  { key: 'playbooks', label: 'SOAR Playbooks', icon: Zap },
  { key: 'iocs', label: 'Threat Intel & IOCs', icon: Globe },
  { key: 'investigate', label: 'Investigation', icon: Search },
  { key: 'evidence', label: 'Evidence', icon: FileSearch },
  { key: 'actions', label: 'Response Actions', icon: Zap },
  { key: 'timeline', label: 'Timeline', icon: Clock },
  { key: 'ai', label: 'AI Analysis', icon: BrainCircuit },
];

export default function IncidentDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('overview');
  const [analysts, setAnalysts] = useState([]);

  const loadIncident = useCallback(() => {
    api.get(`/incidents/${id}`).then(r => setIncident(r.data)).catch(err => {
      toast.error(apiError(err));
      navigate('/incidents');
    }).finally(() => setLoading(false));
  }, [id]);

  useEffect(() => { loadIncident(); }, [loadIncident]);
  useEffect(() => { api.get('/analysts').then(r => setAnalysts(r.data)).catch(() => { }); }, []);

  if (loading) return <div className="loading-center"><span className="spinner-lg spinner" /> Loading incident…</div>;
  if (!incident) return null;

  return (
    <div>
      {/* Back link */}
      <div style={{ marginBottom: 16 }}>
        <button className="btn btn-ghost btn-sm" onClick={() => navigate('/incidents')}>
          <ArrowLeft size={14} /> Back to Incidents
        </button>
      </div>

      {/* Tabs */}
      <div className="tabs" style={{ overflowX: 'auto', flexWrap: 'nowrap' }}>
        {TABS.map(t => (
          <button key={t.key} className={`tab${tab === t.key ? ' active' : ''}`} onClick={() => setTab(t.key)}>
            <t.icon size={13} style={{ marginRight: 5, verticalAlign: 'middle' }} />
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'overview' && (
        <OverviewTab incident={incident} onStatusChange={loadIncident} analysts={analysts} user={user} />
      )}
      {tab === 'playbooks' && (
        <SOARPlaybooksTab incident={incident} user={user} onStatusChange={loadIncident} />
      )}
      {tab === 'iocs' && (
        <ThreatIntelTab incident={incident} user={user} onStatusChange={loadIncident} />
      )}
      {tab === 'investigate' && <InvestigationTab incidentId={id} user={user} />}
      {tab === 'evidence' && <EvidenceTab incidentId={id} user={user} />}
      {tab === 'actions' && <ActionsTab incidentId={id} user={user} />}
      {tab === 'timeline' && <TimelineTab incidentId={id} />}
      {tab === 'ai' && <AIAnalysisTab incidentId={id} user={user} />}
    </div>
  );
}
