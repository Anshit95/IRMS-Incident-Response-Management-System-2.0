import { useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, FileWarning, PlusCircle, Search,
  Activity, BarChart2, Users, FileText, BrainCircuit,
  Settings, LogOut, ShieldCheck, Menu, Zap, Globe,
  ShieldAlert, Radio, CreditCard, Lock
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext.jsx';
import toast from 'react-hot-toast';

const mainNavItems = [
  { label: 'SOC Dashboard',     path: '/dashboard',     icon: LayoutDashboard, roles: ['admin','analyst','viewer'] },
  { label: 'Incidents',         path: '/incidents',     icon: FileWarning,     roles: ['admin','analyst','viewer'] },
  { label: 'SOAR Playbooks',    path: '/playbooks',     icon: Zap,             roles: ['admin','analyst'], badge: 'PRO' },
  { label: 'Threat Intel & IOCs', path: '/threat-intel', icon: Globe,           roles: ['admin','analyst','viewer'], badge: 'PRO' },
  { label: 'Investigation Hub', path: '/investigation', icon: Search,          roles: ['admin','analyst'] },
  { label: 'AI Defense Copilot', path: '/ai-assistant',  icon: BrainCircuit,    roles: ['admin','analyst'], badge: 'AI' },
];

const enterpriseNavItems = [
  { label: 'SIEM Ingest Pipelines', path: '/webhooks', icon: Radio,        roles: ['admin','analyst'] },
  { label: 'Compliance & Audit Vault', path: '/compliance', icon: ShieldCheck, roles: ['admin','analyst','viewer'], badge: 'SOC2' },
  { label: 'Reports & STIX 2.1', path: '/reports',       icon: FileText,   roles: ['admin','analyst','viewer'] },
  { label: 'Analytics & MTTR',   path: '/analytics',     icon: BarChart2,  roles: ['admin','analyst','viewer'] },
];

const adminNavItems = [
  { label: 'Commercial Billing', path: '/billing',       icon: CreditCard, roles: ['admin','analyst','viewer'], badge: 'TIER' },
  { label: 'SOC Personnel',     path: '/users',         icon: Users,      roles: ['admin'] },
  { label: 'Settings',          path: '/settings',      icon: Settings,   roles: ['admin','analyst','viewer'] },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  const handleLogout = async () => {
    await logout();
    toast.success('Logged out successfully');
    navigate('/login');
  };

  const filterRole = (items) => items.filter(n => n.roles.includes(user?.role));

  return (
    <>
      {open && (
        <div
          className="sidebar-overlay"
          style={{ display: 'block' }}
          onClick={() => setOpen(false)}
        />
      )}

      <aside className={`sidebar${open ? ' open' : ''}`}>
        {/* Logo */}
        <div className="sidebar-logo">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{
              width: 28,
              height: 28,
              borderRadius: 6,
              background: 'linear-gradient(135deg, #2563EB 0%, #1D4ED8 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 2px 4px rgba(37,99,235,0.3)'
            }}>
              <ShieldCheck size={18} color="#FFFFFF" />
            </div>
            <div>
              <span className="sidebar-logo-title" style={{ letterSpacing: 0.5 }}>IRMS SOAR</span>
              <span style={{
                marginLeft: 6,
                fontSize: 9.5,
                background: '#1E293B',
                color: '#38BDF8',
                padding: '1px 5px',
                borderRadius: 3,
                fontWeight: 700,
                border: '1px solid #334155'
              }}>
                v2.0 ENTERPRISE
              </span>
            </div>
          </div>
          <div className="sidebar-logo-sub" style={{ marginTop: 4, color: '#94A3B8' }}>
            Cyber Defense & Incident Response
          </div>
        </div>

        {/* Navigation */}
        <nav className="sidebar-nav" style={{ paddingBottom: 20 }}>
          <div className="nav-section-label">Operations</div>
          {filterRole(mainNavItems).map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
              onClick={() => setOpen(false)}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <item.icon size={15} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span style={{
                  fontSize: 9,
                  fontWeight: 700,
                  padding: '1px 5px',
                  borderRadius: 3,
                  background: item.badge === 'PRO' ? '#38BDF8' : item.badge === 'AI' ? '#818CF8' : '#334155',
                  color: item.badge === 'PRO' ? '#0F172A' : '#FFF'
                }}>
                  {item.badge}
                </span>
              )}
            </NavLink>
          ))}

          <div className="nav-section-label" style={{ marginTop: 14 }}>Security Telemetry & Compliance</div>
          {filterRole(enterpriseNavItems).map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
              onClick={() => setOpen(false)}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <item.icon size={15} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span style={{
                  fontSize: 9,
                  fontWeight: 700,
                  padding: '1px 5px',
                  borderRadius: 3,
                  background: '#059669',
                  color: '#FFF'
                }}>
                  {item.badge}
                </span>
              )}
            </NavLink>
          ))}

          <div className="nav-section-label" style={{ marginTop: 14 }}>SaaS & Administration</div>
          {filterRole(adminNavItems).map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
              onClick={() => setOpen(false)}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <item.icon size={15} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span style={{
                  fontSize: 9,
                  fontWeight: 700,
                  padding: '1px 5px',
                  borderRadius: 3,
                  background: '#4F46E5',
                  color: '#FFF'
                }}>
                  {item.badge}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="sidebar-footer">
          <button className="nav-item" onClick={handleLogout} style={{ width: '100%' }}>
            <LogOut size={15} />
            Logout Session
          </button>
        </div>
      </aside>

      {/* Mobile trigger */}
      <button
        id="mobile-sidebar-toggle"
        className="mobile-menu-btn"
        style={{ display: 'none', position: 'fixed', top: 12, left: 12, zIndex: 300 }}
        onClick={() => setOpen(v => !v)}
        aria-label="Toggle navigation"
      >
        <Menu size={18} />
      </button>
    </>
  );
}
