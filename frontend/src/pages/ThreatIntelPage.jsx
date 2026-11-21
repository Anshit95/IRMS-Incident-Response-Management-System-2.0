import { useState, useEffect } from 'react';
import {
  Search, ShieldAlert, ShieldCheck, AlertTriangle, Globe,
  Hash, ExternalLink, Plus, RefreshCw, Filter, Server, MapPin
} from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';

export default function ThreatIntelPage() {
  const [indicators, setIndicators] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('');
  const [filterRep, setFilterRep] = useState('');

  // Live lookup state
  const [lookupQuery, setLookupQuery] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [lookingUp, setLookingUp] = useState(false);

  // Add IOC modal state
  const [showAddModal, setShowAddModal] = useState(false);
  const [newVal, setNewVal] = useState('');
  const [newType, setNewType] = useState('ip');
  const [adding, setAdding] = useState(false);

  const fetchThreatData = async () => {
    try {
      setLoading(true);
      const [iocsRes, statsRes] = await Promise.all([
        api.get(`/threat-intel/indicators?type=${filterType}&reputation=${filterRep}`),
        api.get('/threat-intel/stats')
      ]);
      setIndicators(iocsRes.data);
      setStats(statsRes.data);
    } catch (err) {
      toast.error('Failed to load threat intelligence: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatData();
  }, [filterType, filterRep]);

  const handleLookup = async (e) => {
    e?.preventDefault();
    if (!lookupQuery.trim()) return;

    try {
      setLookingUp(true);
      setLookupResult(null);
      const res = await api.post('/threat-intel/lookup', { indicator: lookupQuery.trim() });
      setLookupResult(res.data);
      toast.success('Indicator enriched via Threat Intelligence Engine');
    } catch (err) {
      toast.error('Threat lookup failed: ' + (err.response?.data?.error || err.message));
    } finally {
      setLookingUp(false);
    }
  };

  const handleAddIoc = async (e) => {
    e.preventDefault();
    if (!newVal.trim()) return;

    try {
      setAdding(true);
      await api.post('/threat-intel/indicators', {
        value: newVal.trim(),
        ioc_type: newType
      });
      toast.success('Indicator of Compromise added & enriched!');
      setShowAddModal(false);
      setNewVal('');
      fetchThreatData();
    } catch (err) {
      toast.error('Failed to add IOC: ' + (err.response?.data?.error || err.message));
    } finally {
      setAdding(false);
    }
  };

  const repBadge = (rep) => {
    switch (rep?.toLowerCase()) {
      case 'malicious':
        return <span className="badge badge-critical" style={{ textTransform: 'uppercase' }}>Malicious</span>;
      case 'suspicious':
        return <span className="badge badge-high" style={{ textTransform: 'uppercase' }}>Suspicious</span>;
      case 'clean':
        return <span className="badge badge-low" style={{ textTransform: 'uppercase' }}>Clean</span>;
      default:
        return <span className="badge badge-neutral" style={{ textTransform: 'uppercase' }}>Unknown</span>;
    }
  };

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
              <Globe size={22} color="#38BDF8" />
              <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0, color: '#FFFFFF' }}>
                Global Threat Intelligence & IOC Sandbox
              </h2>
              <span style={{
                background: '#059669',
                color: '#FFF',
                fontSize: 11,
                padding: '2px 8px',
                borderRadius: 4,
                fontWeight: 600
              }}>
                Live Feed Connected
              </span>
            </div>
            <p style={{ margin: 0, fontSize: 13, color: '#94A3B8', maxWidth: 740 }}>
              Live telemetry correlation across VirusTotal, AlienVault OTX, AbuseIPDB, and NIST NVD CVE databases. Real-time indicator enrichment, ASN attribution, and malware family classification.
            </p>
          </div>

          <button
            className="btn btn-primary"
            onClick={() => setShowAddModal(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Plus size={15} /> Add Indicator
          </button>
        </div>
      </div>

      {/* Live Sandbox Search Bar */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-body" style={{ padding: 18 }}>
          <form onSubmit={handleLookup} style={{ display: 'flex', gap: 10 }}>
            <div style={{ position: 'relative', flex: 1 }}>
              <input
                type="text"
                className="form-input"
                placeholder="Enter IP Address (e.g. 185.234.219.44), Domain, SHA-256 Hash, or CVE ID..."
                value={lookupQuery}
                onChange={e => setLookupQuery(e.target.value)}
                style={{ width: '100%', paddingLeft: 36, fontSize: 13.5 }}
              />
              <Search size={16} color="#94A3B8" style={{ position: 'absolute', left: 12, top: 11 }} />
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={lookingUp || !lookupQuery.trim()}
              style={{ minWidth: 120 }}
            >
              {lookingUp ? <span className="spinner" /> : 'Enrich & Scan'}
            </button>
          </form>

          {/* Live Lookup Result Panel */}
          {lookupResult && (
            <div style={{
              marginTop: 16,
              background: '#F8FAFC',
              border: '1px solid #E2E8F0',
              borderRadius: 8,
              padding: 16
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12, marginBottom: 12 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 15, fontWeight: 700, fontFamily: 'monospace', color: '#0F172A' }}>
                      {lookupResult.value}
                    </span>
                    <span className="badge badge-neutral" style={{ textTransform: 'uppercase' }}>
                      {lookupResult.ioc_type}
                    </span>
                    {repBadge(lookupResult.reputation)}
                  </div>
                  <div style={{ fontSize: 12, color: '#64748B', marginTop: 4 }}>
                    Source: {lookupResult.source} • Country: {lookupResult.country} • ASN: {lookupResult.asn}
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 11, color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                    Threat Score
                  </div>
                  <div style={{
                    fontSize: 22,
                    fontWeight: 800,
                    color: lookupResult.threat_score >= 80 ? '#DC2626' : lookupResult.threat_score >= 40 ? '#D97706' : '#16A34A'
                  }}>
                    {lookupResult.threat_score} <span style={{ fontSize: 13, fontWeight: 500, color: '#94A3B8' }}>/ 100</span>
                  </div>
                </div>
              </div>

              {/* Enrichment Details */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, fontSize: 12 }}>
                <div style={{ background: '#FFF', padding: 10, borderRadius: 6, border: '1px solid #E2E8F0' }}>
                  <div style={{ color: '#64748B', marginBottom: 2 }}>Malware Attribution</div>
                  <div style={{ fontWeight: 600, color: '#0F172A' }}>{lookupResult.malware_family || 'None Classified'}</div>
                </div>
                <div style={{ background: '#FFF', padding: 10, borderRadius: 6, border: '1px solid #E2E8F0' }}>
                  <div style={{ color: '#64748B', marginBottom: 2 }}>Threat Actor</div>
                  <div style={{ fontWeight: 600, color: '#0F172A' }}>{lookupResult.threat_actor || 'Unknown Group'}</div>
                </div>
                <div style={{ background: '#FFF', padding: 10, borderRadius: 6, border: '1px solid #E2E8F0' }}>
                  <div style={{ color: '#64748B', marginBottom: 2 }}>VirusTotal / Multi-Engine</div>
                  <div style={{ fontWeight: 600, color: '#0F172A' }}>{lookupResult.enrichment?.vt_ratio || 'N/A'} Detections</div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Stats Summary Cards */}
      {stats && (
        <div className="stat-cards-grid" style={{ marginBottom: 20 }}>
          <div className="stat-card">
            <div className="stat-card-label">Total Tracked Indicators</div>
            <div className="stat-card-value">{stats.total}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Confirmed Malicious</div>
            <div className="stat-card-value" style={{ color: '#DC2626' }}>{stats.malicious}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Suspicious / Under Review</div>
            <div className="stat-card-value" style={{ color: '#D97706' }}>{stats.suspicious}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Clean / Whitelisted</div>
            <div className="stat-card-value" style={{ color: '#16A34A' }}>{stats.clean}</div>
          </div>
        </div>
      )}

      {/* Filter Row */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'center' }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: '#475569', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Filter size={15} /> Filters:
        </div>
        <select
          className="form-select"
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          style={{ width: 140, fontSize: 12 }}
        >
          <option value="">All Types</option>
          <option value="ip">IP Addresses</option>
          <option value="domain">Domains</option>
          <option value="sha256">SHA-256 Hashes</option>
          <option value="cve">CVE Vulnerabilities</option>
        </select>

        <select
          className="form-select"
          value={filterRep}
          onChange={e => setFilterRep(e.target.value)}
          style={{ width: 140, fontSize: 12 }}
        >
          <option value="">All Reputations</option>
          <option value="malicious">Malicious</option>
          <option value="suspicious">Suspicious</option>
          <option value="clean">Clean</option>
        </select>
      </div>

      {/* Indicators Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Tracked Indicators of Compromise ({indicators.length})</span>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <table className="table">
            <thead>
              <tr>
                <th>Indicator Value</th>
                <th>Type</th>
                <th>Reputation</th>
                <th>Threat Score</th>
                <th>Malware Attribution</th>
                <th>Linked Incident</th>
                <th>ASN / Location</th>
              </tr>
            </thead>
            <tbody>
              {indicators.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: 30, color: '#94A3B8' }}>
                    No threat indicators match the selected criteria.
                  </td>
                </tr>
              ) : (
                indicators.map(ioc => (
                  <tr key={ioc.id}>
                    <td>
                      <span style={{ fontFamily: 'Consolas, monospace', fontSize: 12, fontWeight: 600 }}>
                        {ioc.value}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-neutral" style={{ textTransform: 'uppercase', fontSize: 10 }}>
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td>{repBadge(ioc.reputation)}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{
                          width: 40,
                          height: 6,
                          borderRadius: 3,
                          background: '#E2E8F0',
                          overflow: 'hidden'
                        }}>
                          <div style={{
                            width: `${ioc.threat_score}%`,
                            height: '100%',
                            background: ioc.threat_score >= 80 ? '#DC2626' : ioc.threat_score >= 40 ? '#D97706' : '#16A34A'
                          }} />
                        </div>
                        <span style={{ fontSize: 11, fontWeight: 700 }}>{ioc.threat_score}</span>
                      </div>
                    </td>
                    <td>
                      <div style={{ fontSize: 12, fontWeight: 500 }}>
                        {ioc.malware_family || ioc.threat_actor || <span style={{ color: '#94A3B8' }}>—</span>}
                      </div>
                    </td>
                    <td>
                      {ioc.incident_code ? (
                        <a href={`/incidents/${ioc.incident_id}`} style={{ color: '#2563EB', fontWeight: 600, fontSize: 12 }}>
                          {ioc.incident_code}
                        </a>
                      ) : (
                        <span style={{ color: '#94A3B8', fontSize: 12 }}>Global Feed</span>
                      )}
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

      {/* Add IOC Modal */}
      {showAddModal && (
        <div className="modal-backdrop">
          <div className="modal-card" style={{ maxWidth: 480 }}>
            <div className="modal-header">
              <span className="modal-title">Add Threat Indicator (IOC)</span>
              <button className="btn-icon" onClick={() => setShowAddModal(false)}>✕</button>
            </div>
            <form onSubmit={handleAddIoc}>
              <div className="modal-body">
                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                    Indicator Type
                  </label>
                  <select
                    className="form-select"
                    value={newType}
                    onChange={e => setNewType(e.target.value)}
                    style={{ width: '100%', fontSize: 13 }}
                  >
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain Name</option>
                    <option value="sha256">SHA-256 Hash</option>
                    <option value="cve">CVE ID</option>
                  </select>
                </div>

                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                    Indicator Value
                  </label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. 194.26.29.112 or evil-domain.com"
                    value={newVal}
                    onChange={e => setNewVal(e.target.value)}
                    required
                    style={{ width: '100%', fontSize: 13 }}
                  />
                  <div style={{ fontSize: 11, color: '#64748B', marginTop: 4 }}>
                    Automated background enrichment will calculate the reputation score, ASN, and geo-ip upon submission.
                  </div>
                </div>
              </div>

              <div className="modal-footer" style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={adding}>
                  {adding ? 'Enriching...' : 'Add Indicator'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
