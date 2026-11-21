# IRMS 2.0 — Enterprise Incident Response & SOAR Management Platform

> **An Enterprise-Grade Security Operations (SOC) & Security Orchestration, Automation, and Response (SOAR) Platform.**  
> Built for security teams, MSSPs, and high-assurance enterprises. Features real-world threat intelligence, automated response playbooks, SIEM alert ingestion pipelines, SOC 2 Type II cryptographic HMAC audit trails, and commercial B2B SaaS monetization tiers.

---

## Executive Overview & Transformation

IRMS has been upgraded from a basic prototype into a **production-ready Enterprise SOC & SOAR platform**:

| Capability | Prototype (v1.0) | Enterprise IRMS 2.0 |
|---|---|---|
| **Data Quality** | 12 mock demo records | **28 high-fidelity real enterprise incidents** modeled on real CVEs (CVE-2023-34362, CVE-2021-44228, CVE-2024-1709) and APT actors (LockBit Gang, APT29, Scattered Spider, FIN11). |
| **Response Automation** | Manual text action notes | **Automated SOAR Playbooks Engine** (Phishing Mailbox Quarantine, Ransomware Host Isolation, Credential Abuse Defense, Web Zero-Day Containment). |
| **Threat Intelligence** | None / Static text strings | **Live IOC Sandbox & Threat Engine** correlating IP, Domain, SHA-256 Hash, and CVEs with threat scores (0–100), VirusTotal ratios, ASN, and geo-location. |
| **Alert Ingestion** | Manual form entry only | **Universal SIEM / EDR Ingestion Webhooks** for CrowdStrike Falcon, AWS GuardDuty, Splunk Core, and Microsoft Defender. |
| **Compliance & Audit** | Basic unverified log table | **Tamper-Evident HMAC-SHA256 Chained Audit Vault** with mathematical verification proof, SOC 2 Type II attestation, and **STIX 2.1 JSON Export**. |
| **SLA Tracking** | None | **Live SOC MTTA, MTTC, MTTR Metrics** & severity-based SLA countdown timers with breach alerting. |
| **Commercial Monetization** | Single tier | **B2B SaaS Multi-Tenancy & Subscriptions**: Community Starter ($0/mo), Professional SOC ($499/mo), Enterprise SOAR ($1,999/mo). |
| **AI Defense Copilot** | Generic substring matching | **Cognitive Cyber Defense Engine & Gemini 1.5/2.0 API**: Board-level CISO executive briefings, regulatory advisory (GDPR Art. 33, HIPAA, SEC 4-day), and MITRE ATT&CK correlation. |

---

## Technology Stack

```
┌────────────────────────────────────────────────────────────────────────┐
│                        FRONTEND (PORT 5173)                            │
│  React 19 • Vite 8 • React Router v7 • Recharts • Lucide React         │
│  Tailwind CSS v4 & SOC-2 Compliant Enterprise Design System            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / REST (JWT Authorization)
┌───────────────────────────────────▼────────────────────────────────────┐
│                    EXPRESS 5 CORE BACKEND (PORT 3001)                  │
│  Controllers: Incidents • Playbooks • Threat Intel • Compliance        │
│               Billing & Subscriptions • Webhooks • AI Copilot          │
│  Services:    SOAR Engine • Threat Feed • HMAC Audit Chain             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Better-SQLite3 (WAL Mode)
┌───────────────────────────────────▼────────────────────────────────────┐
│                  ENTERPRISE DATASTORE (irms.db)                        │
│  15 Idempotent Tables: organizations, subscriptions, users,            │
│  incidents, playbooks, playbook_runs, indicators_of_compromise,         │
│  incident_mitre_tactics, webhook_endpoints, compliance_audits,         │
│  audit_logs (HMAC Chained), evidence, notes, response_actions          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Enterprise Feature Matrix

### 1. Automated SOAR Playbooks
- **Phishing Triage & Mailbox Quarantine**: Header parsing, threat feed lookup, M365/Google Workspace email purge, token revocation, DNS sinkholing.
- **Ransomware Host Containment**: Automated CrowdStrike/Defender endpoint network isolation, process termination, volatile memory dump, Kerberos invalidation.
- **Credential Abuse & Account Takeover Defense**: Edge WAF IP block, SAML/OAuth session kill, FIDO2 MFA enforcement.
- **Web App Zero-Day Containment**: WAF virtual patch rule injection, container isolation, STIX broadcast.

### 2. Global Threat Intelligence & IOC Sandbox
- Real-time indicator lookup for **IP addresses, Domains, SHA-256 File Hashes, and CVE Vulnerability IDs**.
- Quantitative **Threat Score (0 to 100)** with reputation classification (`Malicious`, `Suspicious`, `Clean`).
- Enriched with ASN attribution, Geo-IP, VirusTotal detection ratios, and malware family classification.
- Pre-seeded with authentic threat intelligence indicators (Cobalt Strike beacons, LockBit 3.0 C2, MOVEit exploit scanners).

### 3. SIEM & Cloud Telemetry Ingestion Webhooks
- Inbound webhook endpoints with unique cryptographically generated API keys.
- Pre-configured pipelines for:
  - **CrowdStrike Falcon EDR**
  - **AWS GuardDuty CloudTrail Stream**
  - **Splunk Enterprise Forwarder**
  - **Microsoft Defender for Endpoint**
- Built-in Ingestion Simulator for instant live end-to-end testing.

### 4. Cryptographic HMAC Audit Vault & SOC 2 Compliance
- Every audit event is chained via **SHA-256 HMAC cryptographic block linking** (`entry_hash = HMAC(prev_hash + actor + action + timestamp, SECRET)`).
- One-click **Cryptographic Audit Chain Integrity Verification** for auditors.
- Automated evaluation of **7 Trust Services Criteria (TSC) Controls** (CC6.1, CC6.6, CC7.1, CC7.2, CC7.3, CC7.4, CC8.1).
- Direct export of incidents and threat indicators in **STIX 2.1 JSON Threat Sharing Standard**.

### 5. SLA & Operational MTTR KPIs
- Real-time tracking of:
  - **MTTA** (Mean Time to Acknowledge)
  - **MTTC** (Mean Time to Contain)
  - **MTTR** (Mean Time to Resolve)
  - **SLA Compliance Rate (%)**
- Dynamic severity-based SLA targets: Critical (1 hour), High (4 hours), Medium (12 hours), Low (48 hours).

### 6. Commercial B2B SaaS Tiers & Subscriptions
- **Community Starter** (Free): 3 analyst seats, 50 incidents/mo, 100 threat intel queries/mo.
- **Professional SOC** ($499/mo): 15 analyst seats, 1,000 incidents/mo, 5,000 threat intel queries/mo, automated playbooks, SIEM webhooks.
- **Enterprise SOAR & Compliance** ($1,999/mo): 999 seats, 50,000 incidents/mo, 100,000 threat intel queries/mo, custom playbooks, SOC 2 audit vault, dedicated SLAs.
- Live resource usage meters and plan upgrade simulator.

---

## Quickstart & Installation

### Prerequisites
- Node.js 18+ (tested on Node v20/v22)
- npm 9+

### 1. Start the Backend API Server
```bash
cd backend
npm install
npm run seed -- --fresh   # Initializes enterprise schema and seeds 28 real-world incidents
npm start                 # Starts API server on http://localhost:3001
```

### 2. Start the Frontend Application
```bash
cd frontend
npm install
npm run dev               # Starts Vite dev server on http://localhost:5173
```

Open your browser at `http://localhost:5173` to access the IRMS Console.

---

## Demo Credentials

| Role | Name / Title | Email | Password |
|---|---|---|---|
| **Admin** | Marcus Vance (SOC Director) | `admin@irms.com` | `Demo@1234` |
| **Lead Analyst** | Sarah Chen (Senior DFIR Analyst) | `analyst@irms.com` | `Demo@1234` |
| **Threat Hunter** | David Thorne (Tier 3 Threat Hunter) | `analyst2@irms.com` | `Demo@1234` |
| **Executive Viewer** | Dr. Evelyn Reed (CISO & VP Risk) | `viewer@irms.com` | `Demo@1234` |

---

## API Endpoints Reference

### Authentication
- `POST /api/auth/login` — Authenticate and receive JWT session
- `POST /api/auth/logout` — Revoke session and log audit event
- `GET /api/auth/me` — Retrieve current analyst identity

### Incidents
- `GET /api/incidents` — Search, filter, paginate incidents
- `GET /api/incidents/:id` — Retrieve incident detail, MITRE mapping, IOCs, and playbooks
- `POST /api/incidents` — Create incident with automatic risk scoring and SLA assignment
- `PUT /api/incidents/:id` — Update incident parameters
- `PATCH /api/incidents/:id/status` — Lifecycle transition (New -> Investigating -> Contained -> Resolved)
- `DELETE /api/incidents/:id` — Soft-delete incident (Admin only)

### SOAR Playbooks
- `GET /api/playbooks` — List available SOAR playbooks and steps
- `POST /api/playbooks/:id/run` — Trigger automated containment on an incident
- `GET /api/playbooks/runs/incident/:incidentId` — Retrieve execution run logs

### Threat Intelligence
- `POST /api/threat-intel/lookup` — Enrich indicator (IP, domain, hash, CVE)
- `GET /api/threat-intel/indicators` — List tracked indicators with filters
- `POST /api/threat-intel/indicators` — Correlate new indicator to an incident
- `GET /api/threat-intel/stats` — High-level threat statistics

### Compliance & Audit Vault
- `GET /api/compliance/report` — Generate SOC 2 Type II / ISO 27001 evaluation report
- `GET /api/compliance/verify-chain` — Cryptographic HMAC-SHA256 audit chain verification
- `GET /api/compliance/export-stix/:incidentId` — Export STIX 2.1 JSON bundle
- `GET /api/compliance/audit-logs` — Retrieve immutable audit trail

### Commercial Billing & Webhooks
- `GET /api/billing/subscription` — Retrieve plan, quotas, and usage meters
- `POST /api/billing/upgrade` — Upgrade or modify commercial SaaS plan
- `GET /api/webhooks` — List registered SIEM ingestion endpoints
- `POST /api/webhooks` — Register new ingestion endpoint
- `POST /api/webhooks/ingest/:apiKey` — Public ingestion webhook for SIEM/EDR alerts

---

## License & Compliance

© 2026 IRMS Cybersecurity Team. Developed in compliance with NIST SP 800-61r2, MITRE ATT&CK v14.1, and SOC 2 Type II Trust Services Criteria.
