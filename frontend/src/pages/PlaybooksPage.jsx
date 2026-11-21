import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Zap, Play, ShieldAlert, CheckCircle2, Clock, AlertTriangle,
  Terminal, ArrowRight, RefreshCw, Layers, Check, X
} from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';

export default function PlaybooksPage() {
  const navigate = useNavigate();
  const [playbooks, setPlaybooks] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  // Execution modal state
  const [activePlaybook, setActivePlaybook] = useState(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState('');
  const [executing, setExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);

  const fetchPlaybooks = async () => {
    try {
      setLoading(true);
      const [pbRes, incRes] = await Promise.all([
        api.get('/playbooks'),
        api.get('/incidents?limit=50&status=New,Investigating')
      ]);
      setPlaybooks(pbRes.data);
      setIncidents(incRes.data.incidents || []);
      if (incRes.data.incidents?.length > 0) {
        setSelectedIncidentId(String(incRes.data.incidents[0].id));
      }
    } catch (err) {
      toast.error('Failed to load playbooks: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPlaybooks();
  }, []);

  const handleExecute = async () => {
    if (!selectedIncidentId) {
      toast.error('Please select an active incident to apply this playbook to.');
      return;
    }

    try {
      setExecuting(true);
      setExecutionResult(null);
      const res = await api.post(`/playbooks/${activePlaybook.id}/run`, {
        incident_id: parseInt(selectedIncidentId)
      });
      setExecutionResult(res.data);
      toast.success(`Playbook "${activePlaybook.name}" executed successfully!`);
      fetchPlaybooks();
    } catch (err) {
      toast.error('Playbook execution failed: ' + (err.response?.data?.error || err.message));
    } finally {
      setExecuting(false);
    }
  };

  if (loading) {
    return (
      <div className="loading-center">
        <span className="spinner-lg spinner" />
        <span>Loading SOAR Playbooks engine...</span>
      </div>
    );
  }

  return (
    <div>
      {/* Top Banner */}
      <div style={{
        background: 'linear-gradient(135deg, #0F172A 0%, #1E293B 100%)',
        color: '#F8FAFC',
        padding: '20px 24px',
        borderRadius: 8,
        marginBottom: 20,
        boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <Zap size={22} color="#38BDF8" />
              <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0, color: '#FFFFFF' }}>
                SOAR Security Orchestration & Automated Playbooks
              </h2>
              <span style={{
                background: '#2563EB',
                color: '#FFF',
                fontSize: 11,
                padding: '2px 8px',
                borderRadius: 4,
                fontWeight: 600,
                textTransform: 'uppercase'
              }}>
                Enterprise Tier Active
              </span>
            </div>
            <p style={{ margin: 0, fontSize: 13, color: '#94A3B8', maxWidth: 760 }}>
              Automate multi-tier containment across EDR agents, perimeter WAF/firewalls, cloud IAM identity providers, and email gateways. One-click and event-triggered execution with forensic audit logging.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              className="btn btn-secondary"
              onClick={fetchPlaybooks}
              style={{ background: '#334155', color: '#F8FAFC', borderColor: '#475569' }}
            >
              <RefreshCw size={14} /> Refresh Engine
            </button>
          </div>
        </div>
      </div>

      {/* Playbooks Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(420px, 1fr))', gap: 16 }}>
        {playbooks.map(pb => (
          <div
            key={pb.id}
            className="card"
            style={{
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              border: '1px solid #E2E8F0',
              borderRadius: 8,
              transition: 'transform 0.15s, box-shadow 0.15s'
            }}
          >
            <div className="card-body" style={{ padding: 18 }}>
              {/* Category & Badge */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <span style={{
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  padding: '3px 8px',
                  borderRadius: 4,
                  background: pb.category === 'Ransomware' ? '#FEE2E2' : pb.category === 'Phishing' ? '#E0F2FE' : '#FEF3C7',
                  color: pb.category === 'Ransomware' ? '#DC2626' : pb.category === 'Phishing' ? '#0284C7' : '#D97706'
                }}>
                  {pb.category}
                </span>

                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
                  <Clock size={13} />
                  <span>{pb.total_runs || 0} Executions</span>
                </div>
              </div>

              {/* Title & Description */}
              <h3 style={{ fontSize: 15, fontWeight: 600, margin: '0 0 8px 0', color: '#0F172A' }}>
                {pb.name}
              </h3>
              <p style={{ fontSize: 12.5, color: '#475569', lineHeight: 1.5, margin: '0 0 16px 0', minHeight: 38 }}>
                {pb.description}
              </p>

              {/* Steps Checklist */}
              <div style={{ background: '#F8FAFC', borderRadius: 6, padding: '10px 12px', border: '1px solid #E2E8F0' }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#64748B', textTransform: 'uppercase', marginBottom: 6 }}>
                  Orchestrated Sequence ({pb.steps?.length || 0} Steps)
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {pb.steps?.map((step, idx) => (
                    <div key={step.id || idx} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#334155' }}>
                      <span style={{
                        width: 18,
                        height: 18,
                        borderRadius: '50%',
                        background: '#E2E8F0',
                        fontSize: 10,
                        fontWeight: 700,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: '#475569'
                      }}>
                        {idx + 1}
                      </span>
                      <span style={{ flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {step.title}
                      </span>
                      {step.auto_execute ? (
                        <span style={{ fontSize: 10, color: '#16A34A', background: '#DCFCE7', padding: '1px 6px', borderRadius: 3 }}>
                          AUTO
                        </span>
                      ) : (
                        <span style={{ fontSize: 10, color: '#CA8A04', background: '#FEF9C3', padding: '1px 6px', borderRadius: 3 }}>
                          APPROVAL
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Card Footer */}
            <div style={{
              padding: '12px 18px',
              borderTop: '1px solid #F1F5F9',
              background: '#FAFAFA',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <span style={{ fontSize: 11, color: '#64748B' }}>
                Target: <strong>{pb.severity_trigger} Severities</strong>
              </span>
              <button
                className="btn btn-primary btn-sm"
                onClick={() => {
                  setActivePlaybook(pb);
                  setExecutionResult(null);
                }}
                style={{ display: 'flex', alignItems: 'center', gap: 6 }}
              >
                <Play size={13} />
                <span>Run Playbook</span>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Execution Modal */}
      {activePlaybook && (
        <div className="modal-backdrop">
          <div className="modal-card" style={{ maxWidth: 640 }}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Zap size={18} color="#2563EB" />
                <span className="modal-title">Execute Playbook: {activePlaybook.name}</span>
              </div>
              <button
                className="btn-icon"
                onClick={() => {
                  setActivePlaybook(null);
                  setExecutionResult(null);
                }}
              >
                <X size={16} />
              </button>
            </div>

            <div className="modal-body" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
              {!executionResult ? (
                <>
                  <div style={{ marginBottom: 16 }}>
                    <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                      Target Incident for Containment
                    </label>
                    <select
                      className="form-select"
                      value={selectedIncidentId}
                      onChange={e => setSelectedIncidentId(e.target.value)}
                      style={{ width: '100%', fontSize: 13 }}
                    >
                      {incidents.length === 0 ? (
                        <option value="">No open incidents available</option>
                      ) : (
                        incidents.map(inc => (
                          <option key={inc.id} value={inc.id}>
                            [{inc.incident_code}] {inc.title} ({inc.severity} - {inc.status})
                          </option>
                        ))
                      )}
                    </select>
                    <div style={{ fontSize: 11, color: '#64748B', marginTop: 4 }}>
                      Executing this SOAR playbook will automatically update the incident state to <strong>Contained</strong> and dispatch containment API calls.
                    </div>
                  </div>

                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: 6, padding: 12 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#334155', marginBottom: 8 }}>
                      Actions To Be Executed in Sequence:
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {activePlaybook.steps?.map((step, idx) => (
                        <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                          <CheckCircle2 size={14} color="#16A34A" />
                          <span>{step.title}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              ) : (
                /* Execution Output Terminal */
                <div>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    background: '#DCFCE7',
                    border: '1px solid #86EFAC',
                    color: '#166534',
                    padding: '10px 14px',
                    borderRadius: 6,
                    marginBottom: 16,
                    fontSize: 13,
                    fontWeight: 600
                  }}>
                    <Check size={16} />
                    <span>SOAR Automation Run Completed ({executionResult.steps_executed} of {executionResult.steps_executed} steps executed successfully)</span>
                  </div>

                  <div style={{
                    background: '#0F172A',
                    color: '#38BDF8',
                    fontFamily: 'Consolas, monospace',
                    fontSize: 11.5,
                    padding: 14,
                    borderRadius: 6,
                    maxHeight: 260,
                    overflowY: 'auto'
                  }}>
                    <div style={{ color: '#94A3B8', marginBottom: 8 }}>
                      [SOAR ENGINE] Initializing execution session for Incident #{selectedIncidentId}...
                    </div>
                    {executionResult.logs?.map((l, idx) => (
                      <div key={idx} style={{ marginBottom: 8 }}>
                        <div style={{ color: '#4ADE80' }}>
                          ✓ STEP {idx + 1}: {l.title} [{l.status}]
                        </div>
                        <div style={{ color: '#E2E8F0', paddingLeft: 14 }}>
                          {l.output}
                        </div>
                      </div>
                    ))}
                    <div style={{ color: '#94A3B8', marginTop: 8 }}>
                      [SOAR ENGINE] State transition: Incident status updated to Contained. Incident Timeline logged.
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="modal-footer" style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              {!executionResult ? (
                <>
                  <button
                    className="btn btn-secondary"
                    onClick={() => setActivePlaybook(null)}
                    disabled={executing}
                  >
                    Cancel
                  </button>
                  <button
                    className="btn btn-primary"
                    onClick={handleExecute}
                    disabled={executing || !selectedIncidentId}
                    style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                  >
                    {executing ? (
                      <>
                        <span className="spinner" />
                        <span>Orchestrating...</span>
                      </>
                    ) : (
                      <>
                        <Play size={14} />
                        <span>Confirm & Execute</span>
                      </>
                    )}
                  </button>
                </>
              ) : (
                <>
                  <button
                    className="btn btn-secondary"
                    onClick={() => {
                      setActivePlaybook(null);
                      setExecutionResult(null);
                    }}
                  >
                    Close
                  </button>
                  <button
                    className="btn btn-primary"
                    onClick={() => navigate(`/incidents/${selectedIncidentId}`)}
                  >
                    View Updated Incident →
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
