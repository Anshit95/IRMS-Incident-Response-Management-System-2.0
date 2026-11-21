import { useState, useEffect } from 'react';
import {
  CreditCard, Check, ShieldCheck, Zap, ArrowUpRight,
  TrendingUp, Users, AlertCircle, Sparkles, CheckCircle2
} from 'lucide-react';
import api from '../services/api';
import toast from 'react-hot-toast';

export default function BillingPage() {
  const [subData, setSubData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [billingCycle, setBillingCycle] = useState('annual');
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [upgrading, setUpgrading] = useState(false);

  const fetchSubscription = async () => {
    try {
      setLoading(true);
      const res = await api.get('/billing/subscription');
      setSubData(res.data);
    } catch (err) {
      toast.error('Failed to load subscription: ' + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSubscription();
  }, []);

  const handleUpgrade = async (planId) => {
    try {
      setUpgrading(true);
      const res = await api.post('/billing/upgrade', {
        plan_id: planId,
        billing_cycle: billingCycle,
        payment_method: { last4: '8842', brand: 'Visa Enterprise' }
      });
      toast.success(res.data.message || 'Subscription upgraded successfully!');
      setSelectedPlan(null);
      fetchSubscription();
    } catch (err) {
      toast.error('Upgrade failed: ' + (err.response?.data?.error || err.message));
    } finally {
      setUpgrading(false);
    }
  };

  if (loading) {
    return (
      <div className="loading-center">
        <span className="spinner-lg spinner" />
        <span>Loading commercial subscription & enterprise tier...</span>
      </div>
    );
  }

  const { organization, plan, subscription, usage, available_plans } = subData;

  return (
    <div>
      {/* Top Banner */}
      <div style={{
        background: 'linear-gradient(135deg, #1E1B4B 0%, #312E81 100%)',
        color: '#F8FAFC',
        padding: '24px 28px',
        borderRadius: 8,
        marginBottom: 20
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <CreditCard size={22} color="#A5B4FC" />
              <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: '#FFFFFF' }}>
                Subscription, Quotas & Commercial Tiers
              </h2>
              <span style={{
                background: '#4F46E5',
                color: '#FFF',
                fontSize: 11,
                padding: '3px 10px',
                borderRadius: 4,
                fontWeight: 700
              }}>
                {plan.badge} EDITION
              </span>
            </div>
            <p style={{ margin: 0, fontSize: 13, color: '#C7D2FE', maxWidth: 740 }}>
              Organization: <strong>{organization.name}</strong> • Account Status: <strong style={{ color: '#4ADE80' }}>Active (Paid)</strong> • Managed by CyberShield Commercial B2B SaaS Engine.
            </p>
          </div>

          <div style={{ background: 'rgba(255,255,255,0.1)', padding: '10px 16px', borderRadius: 8, textAlign: 'right' }}>
            <div style={{ fontSize: 11, color: '#C7D2FE', textTransform: 'uppercase' }}>Next Billing Renewal</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#FFF' }}>
              ${subscription.price_usd?.toLocaleString()} / {subscription.billing_cycle}
            </div>
            <div style={{ fontSize: 11, color: '#A5B4FC' }}>
              Card: {subscription.payment_brand} ending in •••• {subscription.payment_method_last4}
            </div>
          </div>
        </div>
      </div>

      {/* Live Resource Usage Meters */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 24 }}>
        {/* Seats Usage */}
        <div className="card">
          <div className="card-body" style={{ padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 12 }}>
              <span style={{ fontWeight: 600, color: '#475569' }}>Active Analyst Seats</span>
              <span style={{ fontWeight: 700, color: '#0F172A' }}>{usage.seats.used} / {usage.seats.limit}</span>
            </div>
            <div style={{ width: '100%', height: 8, background: '#E2E8F0', borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ width: `${Math.min(100, usage.seats.percent)}%`, height: '100%', background: '#2563EB' }} />
            </div>
            <div style={{ fontSize: 11, color: '#64748B', marginTop: 6 }}>
              {usage.seats.limit - usage.seats.used} seats remaining on current plan
            </div>
          </div>
        </div>

        {/* Incidents Quota */}
        <div className="card">
          <div className="card-body" style={{ padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 12 }}>
              <span style={{ fontWeight: 600, color: '#475569' }}>Monthly Incident Ingest</span>
              <span style={{ fontWeight: 700, color: '#0F172A' }}>{usage.incidents_this_month.used} / {usage.incidents_this_month.limit.toLocaleString()}</span>
            </div>
            <div style={{ width: '100%', height: 8, background: '#E2E8F0', borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ width: `${Math.max(2, Math.min(100, usage.incidents_this_month.percent))}%`, height: '100%', background: '#10B981' }} />
            </div>
            <div style={{ fontSize: 11, color: '#64748B', marginTop: 6 }}>
              Resets on 1st of next calendar month
            </div>
          </div>
        </div>

        {/* Threat Intel Queries */}
        <div className="card">
          <div className="card-body" style={{ padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 12 }}>
              <span style={{ fontWeight: 600, color: '#475569' }}>Threat Intel API Enriched</span>
              <span style={{ fontWeight: 700, color: '#0F172A' }}>{usage.threat_intel_queries.used} / {usage.threat_intel_queries.limit.toLocaleString()}</span>
            </div>
            <div style={{ width: '100%', height: 8, background: '#E2E8F0', borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ width: `${Math.max(2, Math.min(100, usage.threat_intel_queries.percent))}%`, height: '100%', background: '#8B5CF6' }} />
            </div>
            <div style={{ fontSize: 11, color: '#64748B', marginTop: 6 }}>
              VirusTotal, AbuseIPDB & AlienVault queries
            </div>
          </div>
        </div>
      </div>

      {/* Billing Cycle Toggle */}
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: billingCycle === 'monthly' ? '#0F172A' : '#64748B' }}>
          Monthly Billing
        </span>
        <button
          onClick={() => setBillingCycle(c => c === 'monthly' ? 'annual' : 'monthly')}
          style={{
            width: 48,
            height: 24,
            borderRadius: 12,
            background: '#2563EB',
            border: 'none',
            cursor: 'pointer',
            position: 'relative',
            padding: 2
          }}
        >
          <div style={{
            width: 20,
            height: 20,
            borderRadius: '50%',
            background: '#FFF',
            transform: billingCycle === 'annual' ? 'translateX(24px)' : 'translateX(0)',
            transition: 'transform 0.2s'
          }} />
        </button>
        <span style={{ fontSize: 13, fontWeight: 600, color: billingCycle === 'annual' ? '#0F172A' : '#64748B' }}>
          Annual Billing <span style={{ color: '#16A34A', fontSize: 11, background: '#DCFCE7', padding: '1px 6px', borderRadius: 4 }}>Save 20%</span>
        </span>
      </div>

      {/* Pricing Plans Comparison Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(310px, 1fr))', gap: 20, marginBottom: 30 }}>
        {available_plans.map(p => {
          const isCurrent = p.id === plan.id;
          const price = billingCycle === 'annual' ? p.price_annual : p.price_monthly;

          return (
            <div
              key={p.id}
              className="card"
              style={{
                borderRadius: 8,
                border: isCurrent ? '2px solid #2563EB' : '1px solid #E2E8F0',
                position: 'relative',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between'
              }}
            >
              {isCurrent && (
                <div style={{
                  position: 'absolute',
                  top: -11,
                  left: '50%',
                  transform: 'translateX(-50%)',
                  background: '#2563EB',
                  color: '#FFF',
                  fontSize: 10,
                  fontWeight: 700,
                  padding: '2px 12px',
                  borderRadius: 12,
                  letterSpacing: 0.5,
                  textTransform: 'uppercase'
                }}>
                  Current Active Plan
                </div>
              )}

              <div className="card-body" style={{ padding: 24 }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#0F172A', marginBottom: 4 }}>
                  {p.name}
                </div>
                <p style={{ fontSize: 12, color: '#64748B', margin: '0 0 16px 0', minHeight: 34 }}>
                  {p.description}
                </p>

                <div style={{ marginBottom: 20 }}>
                  <span style={{ fontSize: 32, fontWeight: 800, color: '#0F172A' }}>
                    ${price === 0 ? '0' : price.toLocaleString()}
                  </span>
                  <span style={{ fontSize: 12, color: '#64748B' }}>
                    {price === 0 ? ' forever' : billingCycle === 'annual' ? ' / year' : ' / month'}
                  </span>
                </div>

                <div style={{ fontSize: 12, fontWeight: 600, color: '#334155', marginBottom: 12 }}>
                  Plan Inclusions:
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 12.5 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Check size={15} color="#16A34A" />
                    <span><strong>{p.max_seats}</strong> SOC Analyst Seats</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Check size={15} color="#16A34A" />
                    <span><strong>{p.incident_quota_monthly.toLocaleString()}</strong> Incidents / Month</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Check size={15} color="#16A34A" />
                    <span><strong>{p.threat_intel_quota_monthly.toLocaleString()}</strong> Threat Intel Queries</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Check size={15} color={p.features.playbooks ? '#16A34A' : '#CBD5E1'} />
                    <span style={{ color: p.features.playbooks ? '#0F172A' : '#94A3B8' }}>
                      SOAR Automated Playbooks
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Check size={15} color={p.features.webhook_ingest ? '#16A34A' : '#CBD5E1'} />
                    <span style={{ color: p.features.webhook_ingest ? '#0F172A' : '#94A3B8' }}>
                      SIEM & EDR Webhook Ingestion
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Check size={15} color={p.features.compliance_vault ? '#16A34A' : '#CBD5E1'} />
                    <span style={{ color: p.features.compliance_vault ? '#0F172A' : '#94A3B8' }}>
                      SOC 2 / ISO 27001 Cryptographic Vault
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Check size={15} color={p.features.sla_tracking ? '#16A34A' : '#CBD5E1'} />
                    <span style={{ color: p.features.sla_tracking ? '#0F172A' : '#94A3B8' }}>
                      Enterprise SLA Tracking & Breach Alerter
                    </span>
                  </div>
                </div>
              </div>

              <div style={{ padding: '16px 24px', borderTop: '1px solid #F1F5F9', background: '#FAFAFA' }}>
                {isCurrent ? (
                  <button className="btn btn-secondary" disabled style={{ width: '100%', background: '#F1F5F9' }}>
                    Current Active Tier
                  </button>
                ) : (
                  <button
                    className="btn btn-primary"
                    onClick={() => handleUpgrade(p.id)}
                    disabled={upgrading}
                    style={{ width: '100%' }}
                  >
                    {upgrading ? 'Processing...' : `Switch to ${p.name}`}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
