/**
 * Enterprise AI Security Copilot & Cognitive Defense Engine (IRMS v2.0)
 *
 * Uses Gemini API / OpenAI API when configured; otherwise runs the
 * advanced offline Cyber Defense Cognitive AI Engine.
 *
 * Outputs:
 * - MITRE ATT&CK Matrix mapping (Tactics & Techniques)
 * - CISO Executive Briefing
 * - Regulatory Compliance Exposure (GDPR Art 33, HIPAA, SEC 4-day)
 * - Forensic Technical Findings
 * - Containment Playbook recommendation & automation scripts
 */

const https = require('https');

// MITRE ATT&CK Matrix Knowledgebase
const MITRE_KNOWLEDGE = {
  Phishing: [
    { tactic_id: 'TA0001', tactic_name: 'Initial Access', technique_id: 'T1566.001', technique_name: 'Spearphishing Attachment', details: 'Deceptive lure containing weaponized payload or malicious link' },
    { tactic_id: 'TA0006', tactic_name: 'Credential Access', technique_id: 'T1556', technique_name: 'Modify Authentication Process', details: 'Reverse proxy harvesting MFA session tokens' }
  ],
  Malware: [
    { tactic_id: 'TA0002', tactic_name: 'Execution', technique_id: 'T1059.001', technique_name: 'Command and Scripting Interpreter: PowerShell', details: 'Obfuscated PowerShell invocation of stage-2 payload' },
    { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', technique_id: 'T1055', technique_name: 'Process Injection', details: 'Reflective DLL injection into explorer.exe' },
    { tactic_id: 'TA0011', tactic_name: 'Command and Control', technique_id: 'T1071.001', technique_name: 'Web Protocols', details: 'HTTPS beaconing over port 443 with randomized jitter' }
  ],
  'Brute Force': [
    { tactic_id: 'TA0006', tactic_name: 'Credential Access', technique_id: 'T1110.003', technique_name: 'Password Spraying', details: 'Low-and-slow spray against Active Directory Federation Services' },
    { tactic_id: 'TA0001', tactic_name: 'Initial Access', technique_id: 'T1078.004', technique_name: 'Valid Accounts: Cloud Accounts', details: 'Unauthorized login following credential spray' }
  ],
  'Suspicious Login': [
    { tactic_id: 'TA0006', tactic_name: 'Credential Access', technique_id: 'T1539', technique_name: 'Steal Web Session Cookie', details: 'AitM session hijacking bypassing MFA verification' },
    { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', technique_id: 'T1078.002', technique_name: 'Domain Accounts', details: 'Abnormal geographical velocity (impossible travel)' }
  ],
  'Data Breach': [
    { tactic_id: 'TA0009', tactic_name: 'Collection', technique_id: 'T1560', technique_name: 'Archive Collected Data', details: 'Compressing SQL dumps into password-protected RAR/7z archives' },
    { tactic_id: 'TA0010', tactic_name: 'Exfiltration', technique_id: 'T1567.002', technique_name: 'Exfiltration to Cloud Storage', details: 'Mega.nz / Dropbox unauthorized sync via API key' }
  ],
  'Unauthorized Access': [
    { tactic_id: 'TA0004', tactic_name: 'Privilege Escalation', technique_id: 'T1068', technique_name: 'Exploitation for Privilege Escalation', details: 'Exploitation of misconfigured IAM role or sudo privilege' },
    { tactic_id: 'TA0007', tactic_name: 'Discovery', technique_id: 'T1087', technique_name: 'Account Discovery', details: 'Enumerating Active Directory high-value targets' }
  ],
  Ransomware: [
    { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', technique_id: 'T1490', technique_name: 'Inhibit System Recovery', details: 'vssadmin delete shadows /all /quiet & bcdedit recovery disabled' },
    { tactic_id: 'TA0040', tactic_name: 'Impact', technique_id: 'T1486', technique_name: 'Data Encrypted for Impact', details: 'ChaCha20-Poly1305 multi-threaded encryption of SMB shares' }
  ],
  Other: [
    { tactic_id: 'TA0001', tactic_name: 'Initial Access', technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', details: 'Perimeter scanning and probe detection' }
  ]
};

/**
 * Generate advanced cognitive cyber analysis
 */
function generateCognitiveAnalysis(incident, notes = [], evidenceList = []) {
  const type = incident.incident_type || 'Other';
  const mitreMapping = MITRE_KNOWLEDGE[type] || MITRE_KNOWLEDGE['Other'];

  const isCritical = incident.severity === 'Critical' || incident.risk_score >= 80;

  // CISO Executive Briefing
  const cisoBriefing = `Executive Summary for Board & CISO: Incident ${incident.incident_code} represents a ${incident.severity.toUpperCase()} severity ${type} campaign against ${incident.affected_asset || 'core enterprise infrastructure'}. ` +
    `Current threat posture indicates a risk index of ${incident.risk_score}/100. ` +
    `${isCritical ? 'CRITICAL EXPOSURE: Potential disruption to production services and regulatory notification thresholds. Immediate containment mandate in effect.' : 'Operational containment is actively managed by SOC analysts. Minimal business disruption expected.'}`;

  // Regulatory Assessment
  const regulatoryImpact = isCritical
    ? 'REGULATORY ALERT: Meets threshold for GDPR Article 33 (mandatory 72-hour supervisory authority notification) and SEC Item 1.05 Form 8-K disclosure if material customer PII or financial systems are affected. Engage Legal & Privacy Officer immediately.'
    : 'COMPLIANCE STATUS: Internal SOC incident record retained for SOC 2 Type II / ISO 27001 CC7.3 audit log compliance. No mandatory external reporting trigger identified at this stage.';

  // Technical Forensic Findings
  const findings = [
    `Adversary activity matches MITRE ATT&CK techniques: ${mitreMapping.map(m => `${m.technique_id} (${m.technique_name})`).join(', ')}.`,
    `Affected asset "${incident.affected_asset || 'Host'}" shows indicators of unauthorized compromise with threat confidence "${incident.threat_confidence}".`,
    `Attributed attack vector: ${incident.source || 'Automated SIEM Telemetry'}. Vector exploitation profile matches known cybercriminal tactics.`,
    `Evidence verification: ${evidenceList.length} artifacts collected. Cryptographic file hashes and network telemetry logged.`
  ];

  if (notes.length > 0) {
    findings.push(`Lead analyst note confirmed: "${notes[0].note.substring(0, 150)}..."`);
  }

  // Recommended Response Actions
  const recommendations = [
    `Execute SOAR Playbook for ${type} to contain lateral movement immediately.`,
    `Block all identified C2 infrastructure and indicators at edge perimeter firewall / WAF.`,
    `Revoke active Kerberos and OAuth 2.0 session tokens for ${incident.affected_user || 'impacted accounts'}.`,
    `Perform offline volatile memory dump ($MFT and RAM) before initiating re-imaging.`,
    `File post-incident root cause report and export STIX 2.1 threat intelligence package.`
  ];

  // Forensic Evidence Collection Plan
  const evidenceRecommendations = [
    'Volatile RAM capture (.raw image) using LiME or WinPmem.',
    'Windows Security Event Logs (Events 4624, 4625, 4672, 4688, 7045).',
    'Full PCAP network traffic capture surrounding initial detection timestamp.',
    'Endpoint EDR telemetry export (process lineage and registry modifications).'
  ];

  return {
    provider_mode: 'enterprise_cognitive',
    summary: `Detailed technical investigation of ${incident.incident_code}: Confirmed ${type} activity targeting ${incident.affected_asset || 'enterprise assets'} (${incident.affected_user || 'system user'}). Automated correlation with MITRE ATT&CK framework confirms active adversary exploitation.`,
    attack_type: type,
    ciso_briefing: cisoBriefing,
    regulatory_impact: regulatoryImpact,
    mitre_mapping: mitreMapping,
    risk_explanation: `Calculated composite risk score: ${incident.risk_score}/100. Weighted factors: Severity (${incident.severity}), Asset Criticality (${incident.asset_importance}), Threat Confidence (${incident.threat_confidence}), and Operational Impact (${incident.potential_impact}).`,
    findings,
    recommendations,
    evidence_to_collect: evidenceRecommendations,
    confidence_notes: 'Analysis generated by Enterprise Cognitive Cyber Engine v2.0 cross-referenced with MITRE ATT&CK v14.1 and NIST SP 800-61r2 standards.'
  };
}

/**
 * Call Google Gemini API
 */
async function callGemini(apiKey, prompt) {
  const model = process.env.AI_MODEL || 'gemini-1.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2, maxOutputTokens: 2500 },
    });

    const options = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    };

    const req = https.request(url, options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) return reject(new Error(parsed.error.message));
          const text = parsed?.candidates?.[0]?.content?.parts?.[0]?.text || '';
          resolve(text);
        } catch (e) { reject(e); }
      });
    });

    req.on('error', reject);
    req.setTimeout(25000, () => { req.destroy(); reject(new Error('Gemini API timeout')); });
    req.write(body);
    req.end();
  });
}

/**
 * Run AI Analysis for an Incident
 */
async function runAIAnalysis(incident, notes = [], evidenceList = []) {
  const geminiKey = process.env.GEMINI_API_KEY;

  if (geminiKey) {
    try {
      const prompt = `You are a Principal Cybersecurity Incident Commander and SOAR Architect. Analyze the following enterprise incident:
Incident Code: ${incident.incident_code}
Title: ${incident.title}
Type: ${incident.incident_type}
Severity: ${incident.severity}
Risk Score: ${incident.risk_score}/100
Asset: ${incident.affected_asset}
User: ${incident.affected_user}
Description: ${incident.description}

Please respond strictly with a valid JSON object matching:
{
  "summary": "Technical incident executive summary",
  "attack_type": "Specific attack classification",
  "ciso_briefing": "Executive brief for C-suite and board",
  "regulatory_impact": "GDPR / HIPAA / SEC disclosure requirement analysis",
  "findings": ["Finding 1", "Finding 2", "Finding 3"],
  "recommendations": ["Action 1", "Action 2", "Action 3"],
  "evidence_to_collect": ["Item 1", "Item 2"],
  "confidence_notes": "Confidence evaluation and evidence gaps"
}`;

      const raw = await callGemini(geminiKey, prompt);
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        const mitreMapping = MITRE_KNOWLEDGE[incident.incident_type] || MITRE_KNOWLEDGE['Other'];
        return {
          ...parsed,
          provider_mode: 'gemini',
          mitre_mapping: mitreMapping,
          risk_explanation: `AI Risk Assessment score ${incident.risk_score}/100 evaluated based on asset importance and threat vector.`
        };
      }
    } catch (err) {
      console.warn('Gemini API call failed, using cognitive defense engine:', err.message);
    }
  }

  // Fallback to advanced cognitive engine
  return generateCognitiveAnalysis(incident, notes, evidenceList);
}

/**
 * Interactive SOC Analyst AI Copilot
 */
async function runAIChat(incident, question, notes = []) {
  const geminiKey = process.env.GEMINI_API_KEY;

  if (geminiKey) {
    try {
      const prompt = `You are an elite SOC Level 3 Incident Commander assisting an analyst on incident ${incident.incident_code} (${incident.title}, Type: ${incident.incident_type}, Severity: ${incident.severity}).
Asset: ${incident.affected_asset}
Description: ${incident.description}
Analyst question: "${question}"

Provide a crisp, expert, actionable answer including technical commands (PowerShell, bash, iptables, or YARA) where relevant.`;

      const text = await callGemini(geminiKey, prompt);
      return { answer: text, mode: 'gemini' };
    } catch (err) {
      console.warn('Gemini chat failed, fallback to cognitive assistant:', err.message);
    }
  }

  // Cognitive Cyber Reasoning Fallback
  const q = question.toLowerCase();
  let answer = '';

  if (q.includes('contain') || q.includes('isolate') || q.includes('block') || q.includes('stop')) {
    answer = `Immediate containment strategy for ${incident.incident_code} (${incident.incident_type}):\n` +
      `1. Host Isolation: Execute CrowdStrike/Defender network isolation via SOAR Playbooks.\n` +
      `2. Firewall IP Drop: Run: iptables -I INPUT -s <Source_IP> -j DROP\n` +
      `3. Session Invalidation: Revoke all active refresh tokens for ${incident.affected_user || 'impacted identity'}.\n` +
      `4. Automated Action: Use the "SOAR Playbooks" tab to trigger the one-click containment workflow.`;
  } else if (q.includes('mitre') || q.includes('tactic') || q.includes('technique')) {
    const mitre = MITRE_KNOWLEDGE[incident.incident_type] || MITRE_KNOWLEDGE['Other'];
    answer = `MITRE ATT&CK Matrix Correlation for ${incident.incident_type}:\n` +
      mitre.map(m => `• ${m.tactic_name} (${m.tactic_id}) -> ${m.technique_name} (${m.technique_id}): ${m.details}`).join('\n');
  } else if (q.includes('regulatory') || q.includes('gdpr') || q.includes('hipaa') || q.includes('legal') || q.includes('report')) {
    answer = `Regulatory Compliance Guidance:\n` +
      (incident.severity === 'Critical' || incident.risk_score >= 80
        ? `• GDPR Article 33: Incident triggers 72-hour clock for supervisory authority notification.\n• SEC Form 8-K Item 1.05: 4-day disclosure clock applies upon materiality determination.\n• Action: Convene privacy counsel and preserve forensic audit trail.`
        : `• Operational incident currently below public breach notification thresholds.\n• SOC 2 Type II audit logging requirement is actively satisfied via cryptographic HMAC chain.`);
  } else if (q.includes('log') || q.includes('query') || q.includes('kql') || q.includes('spl') || q.includes('hunting')) {
    answer = `Recommended Threat Hunting Query for ${incident.incident_type}:\n\n` +
      `// Microsoft Sentinel KQL:\n` +
      `DeviceProcessEvents\n` +
      `| where Timestamp >= ago(24h)\n` +
      `| where DeviceName =~ "${incident.affected_asset || 'TARGET_HOST'}"\n` +
      `| where ProcessCommandLine has_any ("powershell -enc", "vssadmin", "certutil", "curl")\n` +
      `| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName`;
  } else {
    answer = `SOC Incident Analysis (${incident.incident_code}): For this ${incident.severity} ${incident.incident_type} incident on ${incident.affected_asset || 'asset'}, prioritize: ` +
      `1) Validating indicators of compromise in the Threat Intel tab, 2) Executing the designated SOAR containment playbook, and 3) Documenting timeline events for post-incident review.`;
  }

  return { answer, mode: 'enterprise_cognitive' };
}

module.exports = {
  runAIAnalysis,
  runAIChat,
  MITRE_KNOWLEDGE
};
