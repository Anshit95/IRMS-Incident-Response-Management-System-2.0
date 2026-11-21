/**
 * Enterprise Billing & Subscription Management (IRMS v2.0)
 *
 * Monetization & Commercial Tier Gating:
 * - Community Starter ($0/mo)
 * - Professional SOC ($499/mo)
 * - Enterprise SOAR ($1,999/mo)
 */

const { getDb } = require('../database/schema');

const PLANS = {
  tier_starter: {
    id: 'tier_starter',
    name: 'Community Starter',
    badge: 'FREE',
    price_monthly: 0,
    price_annual: 0,
    max_seats: 3,
    incident_quota_monthly: 50,
    threat_intel_quota_monthly: 100,
    features: {
      playbooks: false,
      live_intel: false,
      webhook_ingest: false,
      compliance_vault: false,
      stix_export: false,
      ai_copilot: 'basic',
      sla_tracking: false,
      audit_retention_days: 7
    },
    description: 'Essential incident tracking for individual researchers and small home labs.'
  },
  tier_pro: {
    id: 'tier_pro',
    name: 'Professional SOC',
    badge: 'PRO',
    price_monthly: 499,
    price_annual: 4790,
    max_seats: 15,
    incident_quota_monthly: 1000,
    threat_intel_quota_monthly: 5000,
    features: {
      playbooks: true,
      live_intel: true,
      webhook_ingest: true,
      compliance_vault: false,
      stix_export: true,
      ai_copilot: 'full',
      sla_tracking: true,
      audit_retention_days: 90
    },
    description: 'Full-featured Incident Response & Threat Intel platform for mid-market SOC teams.'
  },
  tier_enterprise: {
    id: 'tier_enterprise',
    name: 'Enterprise SOAR & Compliance',
    badge: 'ENTERPRISE',
    price_monthly: 1999,
    price_annual: 19190,
    max_seats: 999,
    incident_quota_monthly: 50000,
    threat_intel_quota_monthly: 100000,
    features: {
      playbooks: true,
      live_intel: true,
      webhook_ingest: true,
      compliance_vault: true,
      stix_export: true,
      ai_copilot: 'unlimited',
      sla_tracking: true,
      audit_retention_days: 365,
      tamper_evident_audit: true,
      custom_playbooks: true,
      dedicated_sla: true
    },
    description: 'Advanced SOAR automation, multi-tenancy, SOC 2/ISO 27001 audit vault, and dedicated SLAs.'
  }
};

/**
 * Get current organization subscription & usage
 */
function getSubscriptionDetails(orgId = 1) {
  const db = getDb();
  let org = db.prepare('SELECT * FROM organizations WHERE id = ?').get(orgId);

  if (!org) {
    // If not found, use default enterprise
    org = {
      id: 1,
      name: 'CyberShield Global SOC',
      tier: 'enterprise',
      status: 'active',
      max_seats: 25,
      incident_quota_monthly: 5000,
      threat_intel_quota_monthly: 10000
    };
  }

  const sub = db.prepare('SELECT * FROM subscriptions WHERE organization_id = ? ORDER BY id DESC LIMIT 1').get(orgId);

  // Compute live usage metrics
  const activeSeats = db.prepare('SELECT COUNT(*) as c FROM users WHERE is_active = 1').get().c;
  const currentMonthIncidents = db.prepare("SELECT COUNT(*) as c FROM incidents WHERE created_at >= date('now', 'start of month')").get().c;
  const iocsEnriched = db.prepare('SELECT COUNT(*) as c FROM indicators_of_compromise').get().c;

  const currentPlan = PLANS[`tier_${org.tier}`] || PLANS.tier_enterprise;

  return {
    organization: org,
    plan: currentPlan,
    subscription: sub || {
      plan_id: currentPlan.id,
      plan_name: currentPlan.name,
      billing_cycle: 'annual',
      price_usd: currentPlan.price_annual,
      current_period_end: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
      status: 'active',
      payment_method_last4: '4242',
      payment_brand: 'Visa'
    },
    usage: {
      seats: { used: activeSeats, limit: currentPlan.max_seats, percent: Math.round((activeSeats / currentPlan.max_seats) * 100) },
      incidents_this_month: { used: currentMonthIncidents, limit: currentPlan.incident_quota_monthly, percent: Math.round((currentMonthIncidents / currentPlan.incident_quota_monthly) * 100) },
      threat_intel_queries: { used: iocsEnriched, limit: currentPlan.threat_intel_quota_monthly, percent: Math.round((iocsEnriched / currentPlan.threat_intel_quota_monthly) * 100) }
    },
    available_plans: Object.values(PLANS)
  };
}

/**
 * Upgrade or change plan (SaaS Checkout Simulation)
 */
function upgradePlan(orgId, planId, billingCycle = 'annual', paymentMethod = { last4: '4242', brand: 'Mastercard' }) {
  const db = getDb();
  const targetPlan = PLANS[planId];
  if (!targetPlan) throw new Error('Invalid plan selected.');

  const tierKey = planId.replace('tier_', '');
  const price = billingCycle === 'annual' ? targetPlan.price_annual : targetPlan.price_monthly;
  const periodEnd = new Date(Date.now() + (billingCycle === 'annual' ? 365 : 30) * 24 * 3600 * 1000).toISOString();

  db.prepare(`
    UPDATE organizations
    SET tier = ?, max_seats = ?, incident_quota_monthly = ?, threat_intel_quota_monthly = ?, features_json = ?
    WHERE id = ?
  `).run(
    tierKey,
    targetPlan.max_seats,
    targetPlan.incident_quota_monthly,
    targetPlan.threat_intel_quota_monthly,
    JSON.stringify(targetPlan.features),
    orgId
  );

  const subResult = db.prepare(`
    INSERT INTO subscriptions (organization_id, plan_id, plan_name, billing_cycle, price_usd, current_period_end, status, payment_method_last4, payment_brand)
    VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
  `).run(
    orgId,
    targetPlan.id,
    targetPlan.name,
    billingCycle,
    price,
    periodEnd,
    paymentMethod.last4 || '4242',
    paymentMethod.brand || 'Visa'
  );

  return {
    success: true,
    message: `Successfully upgraded to ${targetPlan.name} (${billingCycle.toUpperCase()})`,
    plan: targetPlan
  };
}

module.exports = {
  PLANS,
  getSubscriptionDetails,
  upgradePlan
};
