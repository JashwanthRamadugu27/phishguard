# PhisGuard

Autonomous Tier-3 AI Phishing Threat Intelligence and Incident Response System.
Integrates Multi-Source Telemetry (VirusTotal, urlscan.io), Deep Forensic Email Parsing (SPF/DKIM/DMARC), LLM Reasoning (Groq), SQLite Memory, and Webhook Dispatch.

---

## Quickstart for Evaluators and Developers

### 1. Docker Setup (Recommended)

1. Create your environment file from the template:
   ```bash
   cp .env.example .env
   ```

2. Start the application:
   ```bash
   docker compose up --build
   ```

3. Open in your browser:
   - Web Console: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/api/health

---

### 2. Local Setup

#### Windows 1-Click:
Run `run.bat`:
```cmd
run.bat
```

#### Manual Start:
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start the API server:
   ```bash
   python -m uvicorn app.api:app --host 0.0.0.0 --port 8000 --reload
   ```

---

## Configuration (.env)

Copy `.env.example` to `.env` and fill in your keys:

- `LLM_API_KEY`: Groq Cloud API key (https://console.groq.com/keys)
- `VIRUSTOTAL_API_KEY`: VirusTotal API key (https://www.virustotal.com/gui/my-apikey)
- `URLSCAN_API_KEY`: urlscan.io API key (https://urlscan.io/user/signup)
- `DISCORD_WEBHOOK_URL`: Discord webhook URL for alerts
- `IMAP_USER` / `IMAP_PASSWORD`: Optional live Gmail / Outlook mailbox watcher

---

## Core Features

1. Live URL and Domain Scanner: Analyzes suspect URLs using multi-engine telemetry.
2. Threat Simulator: Pre-built phishing attack templates (Bank of America, Microsoft 365, PayPal, DocuSign, Safe Google) to test the pipeline without live threats.
3. Email Forensics: Drag-and-drop `.eml` parser checking SPF/DKIM/DMARC and display name spoofing.
4. SQLite Memory: Tracks attack campaigns, domain history, and reasoning traces.

---

## CLI Usage and Tests

- Scan a URL:
  ```bash
  python -m app.main --url "https://example-phish-domain.com"
  ```

- Scan an email file:
  ```bash
  python -m app.main --file "sample_phish.eml"
  ```

- Run tests:
  ```bash
  python -m pytest tests/ -v
  ```

- View memory database:
  ```bash
  python view_memory.py
  ```

---

## Team & Contributors

- [Utkarsh Pandey](https://github.com/UTKARSHPANDEY0)
- [Mohith](https://github.com/mohith-505)
- [Jashwanth Ramadugu](https://github.com/JashwanthRamadugu27)
- [Nikhilesh](https://github.com/Nikhilesh091)


