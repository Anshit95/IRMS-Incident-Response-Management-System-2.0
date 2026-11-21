import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import {
  FileWarning, Activity, AlertTriangle, CheckCircle, Clock,
  Zap, Globe, ShieldCheck, Plus, Radio, ArrowUpRight, Shield
} from 'lucide-react';
import api from '../services/api';
import { severityBadge, statusBadge, formatDate, formatDateTime, riskClass, riskCategory } from '../utils/helpers';

const SEVERITY_COLORS = { Critical: '#DC2626', High: '#EA580C', Medium: '#CA8A04', Low: '#16A34A' };
const STATUS_COLORS = {
  New: '#2563EB', Investigating: '#EA580C', Contained: '#CA8A04',
  Resolved: '#16A34A', Closed: '#64748B', 'False Positive': '#7C3AED',
};

export default function DashboardPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [activity, setActivity] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.get('/dashboard/stats'),
      api.get('/dashboard/recent-incidents'),
      api.get('/dashboard/activity'),
    ]).then(([s, r, a]) => {
      setStats(s.data);
      setRecent(r.data);
      setActivity(a.data);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="loading-center">
        <span className="spinner-lg spinner" />
        <span>Loading SOC telemetry & command center...</span>
      </div>
    );
  }

  const statCards = [
    { label: 'Total Incidents', value: stats?.total || 0, icon: FileWarning, filter: {} },
    { label: 'Open Incidents', value: stats?.open || 0, icon: Clock, filter: { status: 'New' } },
    { label: 'Critical Severity', value: stats?.critical || 0, icon: AlertTriangle, filter: { severity: 'Critical' }, color: '#DC2626' },
    { label: 'Investigating', value: stats?.investigating || 0, icon: Activity, filter: { status: 'Investigating' } },
    { label: 'Contained (SOAR)', value: stats?.contained || 0, icon: Zap, filter: { status: 'Contained' }, color: '#D97706' },
    { label: 'Resolved', value: stats?.resolved || 0, icon: CheckCircle, filter: { status: 'Resolved' }, color: '#16A34A' },
  ];

  return (
    <div>
      {/* Enterprise Executive SOC KPI Strip */}
      <div style={{
        background: '#FFFFFF',
        border: '1px solid #E2E8F0',
        borderRadius: 8,
        padding: '16px 20px',
        marginBottom: 20,
        boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 14 }}>
          {/* MTTA */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: 8, background: '#EFF6FF', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Clock size={18} color="#2563EB" />
            </div>
            <div>
              <div style={{ fontSize: 11, color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>MTTA (Triage)</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#0F172A' }}>{stats?.kpis?.mtta_minutes || 12} mins</div>
            </div>
          </div>

          <div style={{ width: 1, height: 30, background: '#E2E8F0' }} />

          {/* MTTC */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: 8, background: '#FEF3C7', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Zap size={18} color="#D97706" />
            </div>
            <div>
              <div style={{ fontSize: 11, color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>MTTC (Contain)</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#0F172A' }}>{stats?.kpis?.mttc_hours || 1.8} hrs</div>
            </div>
          </div>

          <div style={{ width: 1, height: 30, background: '#E2E8F0' }} />

          {/* MTTR */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: 8, background: '#DCFCE7', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <CheckCircle size={18} color="#16A34A" />
            </div>
            <div>
              <div style={{ fontSize: 11, color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>MTTR (Resolution)</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#0F172A' }}>{stats?.kpis?.mttr_hours || 4.2} hrs</div>
            </div>
          </div>

          <div style={{ width: 1, height: 30, background: '#E2E8F0' }} />

          {/* SLA Compliance */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: 8, background: '#F1F5F9', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ShieldCheck size={18} color="#059669" />
            </div>
            <div>
              <div style={{ fontSize: 11, color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>SLA Compliance</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#059669' }}>{stats?.kpis?.sla_compliance_percent || 94}% on-target</div>
            </div>
          </div>

          <div style={{ width: 1, height: 30, background: '#E2E8F0' }} />

          {/* Quick Action Buttons */}
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn btn-primary btn-sm"
              onClick={() => navigate('/incidents/new')}
              style={{ display: 'flex', alignItems: 'center', gap: 4 }}
            >
              <Plus size={14} /> New Incident
            </button>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => navigate('/playbooks')}
              style={{ display: 'flex', alignItems: 'center', gap: 4 }}
            >
              <Zap size={14} color="#2563EB" /> Run Playbook
            </button>
          </div>
        </div>
      </div>

      {/* Stat Cards Grid */}
      <div className="stat-cards-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', marginBottom: 20 }}>
        {statCards.map(card => (
          <div
            key={card.label}
            className="stat-card"
            onClick={() => navigate('/incidents', { state: card.filter })}
            style={{ cursor: 'pointer' }}
          >
            <div className="stat-card-label">
              {card.label}
              <span className="stat-card-icon"><card.icon size={16} /></span>
            </div>
            <div className="stat-card-value" style={{ color: card.color || '#0F172A' }}>
              {card.value}
            </div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        {/* Incident Trends */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Security Incident Velocity (12-Month Ingest)</span>
          </div>
          <div className="card-body" style={{ padding: '14px 10px' }}>
            {stats?.trend?.length > 0 ? (
              <ResponsiveContainer width="100%" height={210}>
                <LineChart data={stats.trend} margin={{ left: 0, right: 16, top: 4, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
                  <XAxis dataKey="month" tick={{ fontSize: 11 }} />
                  <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 6, border: '1px solid #E2E8F0' }} />
                  <Line type="monotone" dataKey="count" stroke="#2563EB" strokeWidth={2.5} dot={{ r: 4 }} name="Incidents Ingested" />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state"><p className="empty-state-desc">No trend telemetry.</p></div>
            )}
          </div>
        </div>

        {/* By Severity */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Threat Severity Distribution</span>
          </div>
          <div className="card-body" style={{ padding: '14px 10px' }}>
            {stats?.bySeverity?.length > 0 ? (
              <ResponsiveContainer width="100%" height={210}>
                <PieChart>
                  <Pie
                    data={stats.bySeverity}
                    dataKey="count"
                    nameKey="severity"
                    cx="50%"
                    cy="50%"
                    outerRadius={75}
                    innerRadius={35}
                    paddingAngle={3}
                    label={({ severity, count }) => `${severity}: ${count}`}
                    fontSize={11}
                  >
                    {stats.bySeverity.map(entry => (
                      <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] || '#64748B'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 6 }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state"><p className="empty-state-desc">No severity data.</p></div>
            )}
          </div>
        </div>
      </div>

      {/* Incident Types & Status Breakdown Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        {/* By Incident Type */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">MITRE / Attack Vector Breakdown</span>
          </div>
          <div className="card-body" style={{ padding: '14px 10px' }}>
            {stats?.byType?.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={stats.byType} margin={{ left: -10, right: 10, top: 4, bottom: 25 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
                  <XAxis dataKey="incident_type" tick={{ fontSize: 10 }} angle={-25} textAnchor="end" interval={0} />
                  <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 6 }} />
                  <Bar dataKey="count" fill="#4F46E5" radius={[4, 4, 0, 0]} name="Incidents" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state"><p className="empty-state-desc">No attack vector data.</p></div>
            )}
          </div>
        </div>

        {/* By Status */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Investigation Pipeline Lifecycle</span>
          </div>
          <div className="card-body" style={{ padding: '14px 10px' }}>
            {stats?.byStatus?.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={stats.byStatus} margin={{ left: -10, right: 10, top: 4, bottom: 25 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
                  <XAxis dataKey="status" tick={{ fontSize: 10 }} angle={-25} textAnchor="end" interval={0} />
                  <YAxis tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 6 }} />
                  <Bar dataKey="count" fill="#059669" radius={[4, 4, 0, 0]} name="Incidents" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state"><p className="empty-state-desc">No pipeline status data.</p></div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Incidents Table & Real-time Activity Stream */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
        {/* Recent Incidents Table */}
        <div className="card">
          <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="card-title">Live SOC Priority Incidents</span>
            <button className="btn btn-secondary btn-sm" onClick={() => navigate('/incidents')}>
              View All →
            </button>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Code</th>
                  <th>Title & Asset</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Analyst</th>
                </tr>
              </thead>
              <tbody>
                {recent.map(inc => (
                  <tr
                    key={inc.id}
                    onClick={() => navigate(`/incidents/${inc.id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <span style={{ fontWeight: 700, color: '#2563EB', fontSize: 12 }}>
                        {inc.incident_code}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, fontSize: 12.5, color: '#0F172A' }}>
                        {inc.title}
                      </div>
                      <div style={{ fontSize: 11, color: '#64748B' }}>
                        Asset: {inc.affected_asset || 'N/A'} {inc.threat_actor ? `• Actor: ${inc.threat_actor}` : ''}
                      </div>
                    </td>
                    <td>{severityBadge(inc.severity)}</td>
                    <td>{statusBadge(inc.status)}</td>
                    <td>
                      <span className={`badge ${riskClass(inc.risk_score)}`} style={{ fontWeight: 700 }}>
                        {inc.risk_score}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: '#475569' }}>
                      {inc.analyst_name || <span style={{ color: '#94A3B8' }}>Unassigned</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Real-time Activity Stream */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">SOC Telemetry Stream</span>
          </div>
          <div className="card-body" style={{ maxHeight: 420, overflowY: 'auto', padding: '12px 16px' }}>
            {activity.length === 0 ? (
              <p style={{ color: '#94A3B8', fontSize: 12 }}>No activity logged.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {activity.map(act => (
                  <div key={act.id} style={{ fontSize: 12, borderBottom: '1px solid #F1F5F9', paddingBottom: 8 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748B', fontSize: 11, marginBottom: 2 }}>
                      <span style={{ fontWeight: 600, color: '#2563EB' }}>{act.incident_code || 'SOC SYSTEM'}</span>
                      <span>{formatDateTime(act.created_at)}</span>
                    </div>
                    <div style={{ color: '#1E293B', fontWeight: 500 }}>
                      {act.description}
                    </div>
                    <div style={{ fontSize: 11, color: '#94A3B8', marginTop: 2 }}>
                      By: {act.actor_name || 'System Automation'}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
