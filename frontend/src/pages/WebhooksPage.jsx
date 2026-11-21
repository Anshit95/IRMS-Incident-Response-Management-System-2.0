import { useState, useEffect } from 'react';
import {
  Radio, Copy, Check, Plus, RefreshCw, Send,
  Shield, Server, Terminal, ArrowRight, ExternalLink
} from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [copiedId, setCopiedId] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newName, setNewName] = useState('');
  const [newSource, setNewSource] = useState('crowdstrike');

  const fetchWebhooks = async () => {
    try {
      setLoading(true);
      const res = await api.get('/webhooks');
      setWebhooks(res.data);
    } catch (err) {
      toast.error('Failed to load webhook endpoints: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWebhooks();
  }, []);

  const handleCopy = (key, id) => {
    const url = `${window.location.origin}/api/webhooks/ingest/${key}`;
    navigator.clipboard.writeText(url);
    setCopiedId(id);
    toast.success('Ingestion Webhook URL copied to clipboard');
    setTimeout(() => setCopiedId(null), 2500);
  };

  const handleSimulateAlert = async (wh, sampleType) => {
    try {
      setSimulating(true);
      let payload = {};

      if (sampleType === 'crowdstrike') {
        payload = {
          title: 'CrowdStrike Falcon: Emotet Trojan Loader Blocked on WS-088',
          detect_description: 'Suspicious DLL injected into winlogon.exe by Word macro.',
          severity: 'Critical',
          computer_name: 'WS-FINANCE-088.corp.local',
          tactic: 'Execution (T1059.001)',
          technique: 'Command and Scripting Interpreter'
        };
      } else if (sampleType === 'guardduty') {
        payload = {
          title: 'GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration',
          description: 'Credentials from EC2 instance i-08a9fbc1 leaked and queried from external IP.',
          severity: 'Critical',
          detail: {
            severity: 8.5,
            resource: { instanceDetails: { instanceId: 'i-08a9fbc147a2' } }
          }
        };
      } else {
        payload = {
          title: 'Splunk SIEM: Anomalous Egress Spike (4.8 GB over HTTPS)',
          description: 'Unusual outbound data transfer to cloud file locker Mega.nz detected from host SQL-PROD-01.',
          severity: 'High',
          incident_type: 'Data Breach',
          affected_asset: 'SQL-PROD-01.corp'
        };
      }

      const res = await api.post(`/webhooks/ingest/${wh.api_key}`, payload);
      toast.success(`Inbound alert ingested! Created ${res.data.incident_code}`);
      fetchWebhooks();
    } catch (err) {
      toast.error('Simulation failed: ' + (err.response?.data?.error || err.message));
    } finally {
      setSimulating(false);
    }
  };

  const handleCreateWebhook = async (e) => {
    e.preventDefault();
    if (!newName.trim()) return;

    try {
      await api.post('/webhooks', {
        name: newName.trim(),
        source_type: newSource
      });
      toast.success('Webhook ingestion endpoint registered');
      setShowAddModal(false);
      setNewName('');
      fetchWebhooks();
    } catch (err) {
      toast.error('Failed to create webhook: ' + (err.response?.data?.error || err.message));
    }
  };

  if (loading) {
    return (
      <div className="loading-center">
        <span className="spinner-lg spinner" />
        <span>Loading SIEM Ingestion Pipelines...</span>
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
        marginBottom: 20
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <Radio size={22} color="#38BDF8" />
              <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0, color: '#FFFFFF' }}>
                SIEM, EDR & Cloud Telemetry Ingestion Hub
              </h2>
              <span style={{
                background: '#2563EB',
                color: '#FFF',
                fontSize: 11,
                padding: '2px 8px',
                borderRadius: 4,
                fontWeight: 600
              }}>
                Universal Ingest API
              </span>
            </div>
            <p style={{ margin: 0, fontSize: 13, color: '#94A3B8', maxWidth: 740 }}>
              Ingest real-time cybersecurity telemetry from CrowdStrike Falcon, AWS GuardDuty, Splunk Enterprise, and Microsoft Defender. Alerts are automatically deduplicated, risk-scored, and enriched.
            </p>
          </div>

          <button
            className="btn btn-primary"
            onClick={() => setShowAddModal(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Plus size={15} /> Add Ingest Endpoint
          </button>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Registered Ingestion Webhook Pipelines ({webhooks.length})</span>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <table className="table">
            <thead>
              <tr>
                <th>Pipeline Name</th>
                <th>Source Integration</th>
                <th>Ingest URL / API Key</th>
                <th>Status</th>
                <th>Total Ingested</th>
                <th>Last Ingestion</th>
                <th>Test Simulator</th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map(wh => (
                <tr key={wh.id}>
                  <td>
                    <div style={{ fontWeight: 600, color: '#0F172A', fontSize: 13 }}>
                      {wh.name}
                    </div>
                  </td>
                  <td>
                    <span className="badge badge-neutral" style={{ textTransform: 'uppercase', fontSize: 10.5 }}>
                      {wh.source_type}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{
                        fontFamily: 'Consolas, monospace',
                        fontSize: 11,
                        background: '#F1F5F9',
                        padding: '3px 8px',
                        borderRadius: 4,
                        maxWidth: 240,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}>
                        /api/webhooks/ingest/{wh.api_key.substring(0, 16)}...
                      </span>
                      <button
                        className="btn-icon"
                        onClick={() => handleCopy(wh.api_key, wh.id)}
                        title="Copy full webhook URL"
                      >
                        {copiedId === wh.id ? <Check size={14} color="#16A34A" /> : <Copy size={14} />}
                      </button>
                    </div>
                  </td>
                  <td>
                    <span className="badge badge-low" style={{ fontSize: 10.5 }}>
                      ● ACTIVE
                    </span>
                  </td>
                  <td style={{ fontWeight: 700, fontSize: 13 }}>
                    {wh.total_received.toLocaleString()} alerts
                  </td>
                  <td style={{ fontSize: 11.5, color: '#64748B' }}>
                    {wh.last_received_at || 'Awaiting telemetry'}
                  </td>
                  <td>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => handleSimulateAlert(wh, wh.source_type)}
                      disabled={simulating}
                      style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}
                    >
                      <Send size={12} />
                      <span>Dispatch Test Alert</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Webhook Modal */}
      {showAddModal && (
        <div className="modal-backdrop">
          <div className="modal-card" style={{ maxWidth: 480 }}>
            <div className="modal-header">
              <span className="modal-title">Register SIEM Ingest Pipeline</span>
              <button className="btn-icon" onClick={() => setShowAddModal(false)}>✕</button>
            </div>
            <form onSubmit={handleCreateWebhook}>
              <div className="modal-body">
                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                    Endpoint Name
                  </label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. Corporate Splunk Forwarder"
                    value={newName}
                    onChange={e => setNewName(e.target.value)}
                    required
                    style={{ width: '100%', fontSize: 13 }}
                  />
                </div>

                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                    Source Integration Platform
                  </label>
                  <select
                    className="form-select"
                    value={newSource}
                    onChange={e => setNewSource(e.target.value)}
                    style={{ width: '100%', fontSize: 13 }}
                  >
                    <option value="crowdstrike">CrowdStrike Falcon Sensor EDR</option>
                    <option value="guardduty">AWS GuardDuty CloudTrail Stream</option>
                    <option value="splunk">Splunk Enterprise / Cloud SIEM</option>
                    <option value="sentinel">Microsoft Sentinel / Defender</option>
                    <option value="generic_json">Generic SIEM Syslog JSON</option>
                  </select>
                </div>
              </div>

              <div className="modal-footer" style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Create Webhook Pipeline
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
