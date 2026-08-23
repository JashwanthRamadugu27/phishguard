# 🛡️ Phishing Sentinel AI Agent — Complete Project & Architecture Explainer

> **Autonomous Tier-3 AI Phishing Threat Intelligence & Incident Response System**

---

## 📌 1. Executive Summary & Problem Solved

Traditional email security filters rely on static blocklists that miss brand-new, zero-day phishing attacks. **Phishing Sentinel** is an autonomous AI agent designed to sit between incoming emails and Security Operations Centers (SOC). 

It continuously monitors mailboxes 24/7, extracts suspicious links, gathers real-time threat intelligence from global security databases, uses a Large Language Model (Groq Llama-3.3-70B) to reason through forensic evidence, clusters recurring attack waves against brands, and alerts security teams instantly on Discord with actionable indicators of compromise (IOCs).

---

## ⚡ 2. What the Project Does (Core Capabilities)

1. **Autonomous 24/7 IMAP Email Interception**:
   - Continuously monitors unread inbox messages (`INBOX` polling loop every 10s).
   - Parses raw MIME RFC-822 headers for SPF, DKIM, and DMARC verification.
   - Detects display-name spoofing (e.g., Sender: `"Bank of America Security" <attacker@evil-domain.xyz>`).
2. **Deep Obfuscated Link Extraction**:
   - Extracts standard HTTP/HTTPS links, HTML anchor tags, defanged strings (`hxxp://`), and URL-encoded redirects (`%3A%2F%2F`).
3. **Multi-Source External Threat Telemetry**:
   - **VirusTotal v3 API**: Checks URLs against 70+ antivirus engines with a token-bucket rate limiter.
   - **urlscan.io Sandbox API**: Submits targets to a headless browser sandbox to capture DOM structure, risk scores, and screenshots.
4. **LLM Forensic Reasoning & Fallback Engine**:
   - Evaluates technical signals using Groq Llama-3.3-70B to generate explicit threat verdicts (`SAFE` vs `MALICIOUS`), confidence scores, and remediation steps.
   - Includes a deterministic fallback rules engine if external APIs or LLMs experience downtime.
5. **Persistent Memory & Threat Campaign Clustering**:
   - Saves every scanned link instance into SQLite (`sentinel_memory.db`).
   - Automatically groups multi-domain attacks targeting the same brand into **Threat Campaigns** (e.g. tracking PayPal attack counts across multiple domains).
6. **Defanged SecOps Alerting**:
   - Dispatches rich red/orange embeds to Discord webhooks with defanged URLs (`hxxps://evil[.]com`) to prevent accidental clicks by security analysts.

---

## 🏗️ 3. How It Works (The 5-Step Investigation Lifecycle)

```text
                  Incoming Email / URL Target
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 1: 🧠 Memory Recall                                   │
│  • Checks SQLite 'scans' table for previous domain memory.   │
│  • Verifies organizational baseline whitelist (Microsoft,   │
│    Google, Apple, PayPal, GitHub).                          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: 📡 Multi-Source Telemetry                          │
│  • VirusTotal API: 70+ antivirus engine detection tally.    │
│  • urlscan.io: Headless sandbox render, score, & screenshot.│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: 🤖 AI Analyst Synthesis (Groq Llama-3.3-70B)       │
│  • Combines email headers + VT + urlscan + memory context.  │
│  • Produces structured verdict: SAFE or MALICIOUS,          │
│    confidence score (0-100), and targeted brand name.       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 4: 🗄️ Database Persistence & Campaign Clustering       │
│  • 'scans': Logs individual scan record instance.           │
│  • 'campaigns': Clusters repeat attacks by brand name.      │
│  • 'traces': Logs 5-step agent execution audit trajectory.  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 5: 🚨 SecOps Webhook Dispatch                         │
│  • If MALICIOUS: Sends rich defanged card to Discord.       │
│  • If SAFE: Persisted silently to DB (zero Discord spam).   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🗄️ 4. SQLite Database Architecture (`sentinel_memory.db`)

Adheres strictly to the [`DATABASE_SPEC.md`](file:///e:/Hackathon%20Snit/DATABASE_SPEC.md) specification:

### A. `scans` Table (Primary Instance Ledger)
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER` | Auto-increment primary key |
| `url` | `TEXT` | Original raw URL |
| `defanged_url` | `TEXT` | Non-clickable safe format (`hxxps://evil[.]com`) |
| `domain` | `TEXT` | Extracted hostname (`evil.com`) |
| `verdict` | `TEXT` | Binary threat verdict (`SAFE` or `MALICIOUS`) |
| `confidence` | `INTEGER` | AI confidence score (`0`–`100`) |
| `summary` | `TEXT` | Technical reasoning summary |
| `brand` | `TEXT` | Targeted brand name (e.g. `"Bank of America"`) |
| `email_subject`| `TEXT` | Email subject line (if from email) |
| `email_sender` | `TEXT` | Sender address (if from email) |
| `created_at` | `TEXT` | ISO-8601 UTC timestamp |

### B. `campaigns` Table (Correlated Attack Waves)
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `INTEGER` | Auto-increment primary key |
| `brand` | `TEXT` | Targeted brand (e.g. `"PayPal"`) |
| `domains` | `TEXT` | JSON array of associated attack domains |
| `attack_count` | `INTEGER` | Total number of attacks intercepted against this brand |
| `first_seen` | `TEXT` | Timestamp of initial discovery |
| `last_seen` | `TEXT` | Timestamp of latest attack |

### C. `traces` Table (Multi-Step Audit Trajectory)
Stores step-by-step reasoning logs (`MEMORY_CHECK`, `BASELINE_CHECK`, `TELEMETRY`, `LLM_SYNTHESIS`, `PERSIST_ALERT`) for auditability.

---

## 🛠️ 5. How to Run & Operate the System

### Option A: Local CLI Execution
```powershell
# 1. Scan a standalone URL
python -m app.main --url "https://secure-login.bankofamerica.update-auth-now.top/signin"

# 2. Scan an email file (.eml)
python -m app.main --file "sample_phish.eml"

# 3. Start 24/7 background IMAP email watcher
python -m app.main --watch

# 4. View SQLite Database Audit Terminal
python view_memory.py

# 5. Run full test suite (55 tests)
python -m pytest tests/ -v
```

### Option B: Production Container (Docker)
```powershell
# Boot container background daemon
docker compose up -d

# View live polling and scanning logs
docker compose logs -f

# Run DB viewer inside Docker container
docker compose exec phishing-sentinel python view_memory.py --db /app/data/sentinel_memory.db
```

---

## 🎙️ 6. Presentation & Jury Script (How to Demo It)

During your presentation, follow this 30-second live demo flow:

1. **Point to Docker / IMAP Watcher Logs**:
   *"Judges, our agent is running 24/7 in the background monitoring our corporate email inbox."*
2. **Send a Test Email / Scan a Phishing Link**:
   Send an email containing a credential harvester link (e.g. Bank of America phishing domain).
3. **Show Real-Time Interception & Discord Alert**:
   *"Within 8 seconds, the agent intercepts the message, checks VirusTotal & urlscan, passes forensic telemetry to Groq LLM, and dispatches a defanged critical alert to our Discord SecOps channel."*
4. **Show SQLite Memory Audit (`view_memory.py`)**:
   *"Notice how our database automatically logs the instance and correlates this attack under the Bank of America threat campaign, keeping track of how many times this brand has been targeted."*
