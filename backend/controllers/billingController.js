const { getSubscriptionDetails, upgradePlan } = require('../services/billingService');
const { getDb } = require('../database/schema');
const { recordAuditEntry } = require('../services/complianceService');

// GET /api/billing/subscription
function getSubscription(req, res) {
  const details = getSubscriptionDetails(1);
  return res.json(details);
}

// POST /api/billing/upgrade
function handleUpgrade(req, res) {
  const { plan_id, billing_cycle, payment_method } = req.body;

  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only Organization Administrators can modify subscriptions and billing.' });
  }

  if (!plan_id) {
    return res.status(400).json({ error: 'plan_id is required' });
  }

  try {
    const result = upgradePlan(1, plan_id, billing_cycle, payment_method);
    const db = getDb();
    recordAuditEntry(db, req.user.id, 'upgrade_plan', 'organization', 1, `Organization upgraded to ${plan_id} (${billing_cycle})`);
    return res.json(result);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
}

module.exports = {
  getSubscription,
  handleUpgrade
};
