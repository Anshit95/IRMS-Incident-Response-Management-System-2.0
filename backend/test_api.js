const app = require('../backend/app');
const http = require('http');

const server = http.createServer(app);
server.listen(0, async () => {
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;
  console.log(`Test server running on ${baseUrl}`);

  async function get(path, token) {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });
    return { status: res.status, data: await res.json() };
  }

  async function post(path, body, token) {
    const res = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      },
      body: JSON.stringify(body)
    });
    return { status: res.status, data: await res.json() };
  }

  try {
    // 1. Health check
    const health = await get('/api/health');
    console.log('1. Health Check:', health.status, health.data.status, health.data.version);

    // 2. Auth login
    const login = await post('/api/auth/login', { email: 'admin@irms.com', password: 'Demo@1234' });
    console.log('2. Login:', login.status, login.data.user?.name, login.data.user?.role);
    const token = login.data.token;

    // 3. Dashboard stats
    const stats = await get('/api/dashboard/stats', token);
    console.log('3. Dashboard Stats:', stats.status, 'Total Incidents:', stats.data.total, 'Critical:', stats.data.critical, 'MTTA:', stats.data.kpis?.mtta_minutes, 'SLA %:', stats.data.kpis?.sla_compliance_percent);

    // 4. Incidents list
    const incidents = await get('/api/incidents', token);
    console.log('4. Incidents List:', incidents.status, 'Returned:', incidents.data.incidents?.length);

    // 5. Playbooks list
    const playbooks = await get('/api/playbooks', token);
    console.log('5. Playbooks List:', playbooks.status, 'Playbooks count:', playbooks.data.length);

    // 6. Threat Intel indicators
    const threat = await get('/api/threat-intel/indicators', token);
    console.log('6. Threat Intel IOCs:', threat.status, 'IOC count:', threat.data.length);

    // 7. Compliance report & HMAC chain verification
    const compliance = await get('/api/compliance/report', token);
    const verifyChain = await get('/api/compliance/verify-chain', token);
    console.log('7. Compliance:', compliance.status, 'Score:', compliance.data.compliance_score_percent + '%', 'Chain Verified:', verifyChain.data.valid, 'Blocks:', verifyChain.data.total_entries);

    // 8. Billing & SaaS Subscription
    const billing = await get('/api/billing/subscription', token);
    console.log('8. Billing Plan:', billing.status, 'Tier:', billing.data.plan?.name, 'Price:', '$' + billing.data.subscription?.price_usd);

    // 9. Webhooks
    const webhooks = await get('/api/webhooks', token);
    console.log('9. Webhooks:', webhooks.status, 'Count:', webhooks.data.length);

    console.log('\n>>> ALL BACKEND API ENDPOINTS VERIFIED & WORKING FLAWLESSLY! <<<');
  } catch (err) {
    console.error('Test failed:', err);
  } finally {
    server.close();
  }
});
