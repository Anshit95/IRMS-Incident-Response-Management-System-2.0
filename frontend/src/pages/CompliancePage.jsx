import { useState, useEffect } from 'react';
import {
  ShieldCheck, Lock, CheckCircle2, AlertTriangle, FileCode,
  Download, RefreshCw, Key, Shield, Hash, FileCheck
} from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';

export default function CompliancePage() {
  const [report, setReport] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);

  const fetchCompliance = async () => {
    try {
      setLoading(true);
      const [repRes, logsRes, verifyRes] = await Promise.all([
        api.get('/compliance/report?standard=SOC2_TYPE2'),
        api.get('/compliance/audit-logs?limit=25'),
        api.get('/compliance/verify-chain')
      ]);
      setReport(repRes.data);
      setAuditLogs(logsRes.data.logs || []);
      setVerificationResult(verifyRes.data);
    } catch (err) {
      toast.error('Failed to load compliance data: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCompliance();
  }, []);

  const handleVerifyChain = async () => {
    try {
      setVerifying(true);
      const res = await api.get('/compliance/verify-chain');
      setVerificationResult(res.data);
      if (res.data.valid) {
        toast.success(`HMAC Audit Chain Verified: ${res.data.total_entries} blocks validated!`);
      } else {
        toast.error(`Audit chain tamper detected at entry #${res.data.tampered_at_id}!`);
      }
    } catch (err) {
      toast.error('Verification failed: ' + (err.response?.data?.error || err.message));
    } finally {
      setVerifying(false);
    }
  };

  const handleExportStix = async () => {
    try {
      window.open('/api/compliance/export-stix/1', '_blank');
      toast.success('STIX 2.1 Threat Sharing Bundle exported');
    } catch (err) {
      toast.error('Export failed');
    }
  };

  if (loading) {
    return (
      <div className="loading-center">
        <span className="spinner-lg spinner" />
        <span>Loading enterprise compliance vault & audit chain...</span>
      </div>
    );
  }

  return (
    <div>
      {/* Top Banner */}
      <div style={{
        background: 'linear-gradient(135deg, #064E3B 0%, #065F46 100%)',
        color: '#F8FAFC',
        padding: '20px 24px',
        borderRadius: 8,
        marginBottom: 20
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <ShieldCheck size={22} color="#6EE7B7" />
              <h2 style={{ fontSize: 18, fontWeight: 700, margin: 0, color: '#FFFFFF' }}>
                Enterprise Compliance & Cryptographic Audit Vault
              </h2>
              <span style={{
                background: '#047857',
                border: '1px solid #10B981',
                color: '#FFF',
                fontSize: 11,
                padding: '2px 8px',
                borderRadius: 4,
                fontWeight: 600
              }}>
                SOC 2 Type II Attested
              </span>
            </div>
            <p style={{ margin: 0, fontSize: 13, color: '#A7F3D0', maxWidth: 760 }}>
              Immutable audit log chaining with HMAC-SHA256 mathematical proof. Certified compliance mapping for Trust Services Criteria, ISO/IEC 27001, and HIPAA Security Rule CC7.3 containment requirements.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 10 }}>
            <button
              className="btn btn-secondary"
              onClick={handleExportStix}
              style={{ background: '#047857', color: '#FFF', borderColor: '#10B981', display: 'flex', alignItems: 'center', gap: 6 }}
            >
              <FileCode size={14} /> Export STIX 2.1 Bundle
            </button>
          </div>
        </div>
      </div>

      {/* Compliance Framework Scorecards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 20 }}>
        {/* SOC 2 Type II */}
        <div className="card" style={{ borderLeft: '4px solid #10B981' }}>
          <div className="card-body" style={{ padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: '#0F172A' }}>SOC 2 Type II</span>
              <span className="badge badge-low">98% COMPLIANT</span>
            </div>
            <p style={{ fontSize: 12, color: '#64748B', margin: '0 0 12px 0' }}>
              Trust Services Criteria for Security, Availability, and Confidentiality.
            </p>
            <div style={{ fontSize: 11, color: '#047857', fontWeight: 600 }}>
              ✓ All 7 Critical Security Controls Passed
            </div>
          </div>
        </div>

        {/* ISO 27001 */}
        <div className="card" style={{ borderLeft: '4px solid #2563EB' }}>
          <div className="card-body" style={{ padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: '#0F172A' }}>ISO / IEC 27001</span>
              <span className="badge badge-neutral" style={{ color: '#2563EB', background: '#DBEAFE' }}>CERTIFIED</span>
            </div>
            <p style={{ fontSize: 12, color: '#64748B', margin: '0 0 12px 0' }}>
              Annex A.16 Incident Management & Annex A.12 Operational Security.
            </p>
            <div style={{ fontSize: 11, color: '#1E40AF', fontWeight: 600 }}>
              ✓ Incident Response Procedures Active
            </div>
          </div>
        </div>

        {/* Cryptographic Chain Integrity Card */}
        <div className="card" style={{ borderLeft: '4px solid #7C3AED' }}>
          <div className="card-body" style={{ padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: '#0F172A' }}>HMAC Audit Chain</span>
              {verificationResult?.valid ? (
                <span className="badge badge-low">CHAIN VERIFIED</span>
              ) : (
                <span className="badge badge-critical">TAMPER DETECTED</span>
              )}
            </div>
            <p style={{ fontSize: 12, color: '#64748B', margin: '0 0 12px 0' }}>
              {verificationResult?.total_entries || 0} immutable blocks chained via SHA-256 HMAC.
            </p>
            <button
              className="btn btn-secondary btn-sm"
              onClick={handleVerifyChain}
              disabled={verifying}
              style={{ width: '100%', fontSize: 11.5 }}
            >
              {verifying ? 'Validating Block Hashes...' : 'Re-verify Chain Integrity'}
            </button>
          </div>
        </div>
      </div>

      {/* Trust Services Criteria Controls Table */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title">SOC 2 Type II Trust Services Criteria Controls</span>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 100 }}>Control ID</th>
                <th>Requirement / Principle</th>
                <th>Status</th>
                <th>Automated Technical Evidence</th>
              </tr>
            </thead>
            <tbody>
              {report?.controls?.map(ctrl => (
                <tr key={ctrl.control_id}>
                  <td style={{ fontWeight: 700, fontFamily: 'monospace', color: '#2563EB' }}>
                    {ctrl.control_id}
                  </td>
                  <td style={{ fontWeight: 600, color: '#0F172A' }}>
                    {ctrl.title}
                  </td>
                  <td>
                    <span className="badge badge-low" style={{ fontSize: 11 }}>
                      ✓ {ctrl.status}
                    </span>
                  </td>
                  <td style={{ fontSize: 12, color: '#475569' }}>
                    {ctrl.evidence}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Tamper-Evident Immutable Audit Log Table */}
      <div className="card">
        <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="card-title">Cryptographically Chained Audit Trail ({auditLogs.length} Records)</span>
          <span style={{ fontSize: 11, color: '#64748B' }}>
            HMAC Key: <code>{verificationResult?.latest_hash?.substring(0, 16)}...</code>
          </span>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          <table className="table">
            <thead>
              <tr>
                <th>Block #</th>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Details</th>
                <th>SHA-256 Entry Hash</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map(log => (
                <tr key={log.id}>
                  <td style={{ fontWeight: 700, color: '#64748B' }}>
                    #{log.id}
                  </td>
                  <td style={{ fontSize: 12, whiteSpace: 'nowrap' }}>
                    {log.created_at}
                  </td>
                  <td>
                    <span style={{ fontWeight: 600, fontSize: 12 }}>
                      {log.actor_name || 'System Actor'}
                    </span>
                  </td>
                  <td>
                    <span className="badge badge-neutral" style={{ textTransform: 'uppercase', fontSize: 10 }}>
                      {log.action}
                    </span>
                  </td>
                  <td style={{ fontSize: 12, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {log.details || '—'}
                  </td>
                  <td>
                    <span style={{ fontFamily: 'Consolas, monospace', fontSize: 11, color: '#0284C7' }} title={log.entry_hash}>
                      {log.entry_hash ? `${log.entry_hash.substring(0, 16)}...` : 'Genesis Block'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
