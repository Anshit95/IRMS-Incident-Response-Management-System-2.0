import { useAuth } from '../../context/AuthContext.jsx';
import { getInitials } from '../../utils/helpers.js';
import { Shield, Sparkles, Radio } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Header({ title, subtitle }) {
  const { user } = useAuth();
  const navigate = useNavigate();

  return (
    <header className="top-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <div>
        <div className="header-title" style={{ fontSize: 18, fontWeight: 700, color: '#0F172A' }}>
          {title}
        </div>
        {subtitle && (
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
            {subtitle}
          </div>
        )}
      </div>

      <div className="header-right" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        {/* Live SOC Feed indicator */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          background: '#F0FDF4',
          border: '1px solid #BBF7D0',
          color: '#166534',
          fontSize: 11,
          fontWeight: 600,
          padding: '4px 10px',
          borderRadius: 20
        }}>
          <span style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: '#22C55E',
            display: 'inline-block',
            boxShadow: '0 0 6px #22C55E'
          }} />
          <span>SOC Telemetry Active</span>
        </div>

        {/* Enterprise Tier Pill */}
        <div
          onClick={() => navigate('/billing')}
          style={{
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            background: '#EEF2FF',
            border: '1px solid #C7D2FE',
            color: '#4338CA',
            fontSize: 11,
            fontWeight: 700,
            padding: '4px 10px',
            borderRadius: 6,
            transition: 'background 0.15s'
          }}
          title="Click to view subscription & tier quotas"
        >
          <Shield size={13} color="#4F46E5" />
          <span>ENTERPRISE SOAR</span>
        </div>

        {/* User Badge */}
        <div className="user-badge" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="user-avatar" style={{
            background: user?.role === 'admin' ? '#1E293B' : '#2563EB',
            color: '#FFF',
            fontWeight: 700,
            fontSize: 12,
            width: 32,
            height: 32,
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            {getInitials(user?.name)}
          </div>
          <div className="user-info" style={{ display: 'flex', flexDirection: 'column' }}>
            <span className="user-name" style={{ fontSize: 12.5, fontWeight: 600, color: '#0F172A' }}>
              {user?.name}
            </span>
            <span className="user-role" style={{ fontSize: 11, color: '#64748B', textTransform: 'uppercase' }}>
              {user?.role}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
