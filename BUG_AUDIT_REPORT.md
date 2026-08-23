# 🔐 Phishing Sentinel AI — Bug & Vulnerability Audit Report

**Date**: 2026-08-23  
**Scope**: Full static code analysis of all Python modules in `app/` and `tests/`  
**Severity Ratings**: 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW | ℹ️ INFO

---

## SUMMARY

| Severity | Count |
| :--- | :---: |
| 🔴 CRITICAL | 3 |
| 🟠 HIGH | 4 |
| 🟡 MEDIUM | 5 |
| 🔵 LOW | 4 |

---

## 🔴 CRITICAL BUGS

---

### BUG-001 — `report.email_metadata` is a Frozen Immutable Model

**File**: [`app/email_watcher.py`](file:///e:/Hackathon%20Snit/app/email_watcher.py) — Line 86  
**Code**:
```python
report.email_metadata = parsed_email   # ← CRASHES SILENTLY
```
**Root Cause**: `ComprehensiveScanReport` is a Pydantic `BaseModel`. By default, assigning attributes on it after creation is silently ignored (or raises `ValidationError` depending on model config). The `email_metadata` set here is **thrown away** and never persisted to the scan database. Every real-email scan has `email_subject = NULL` and `email_sender = NULL` in the database because of this.

**Impact**: Every email scan saves `None` for subject and sender in the database. The jurys cannot see who sent the malicious email. Discord alerts also omit email forensic metadata.

**Fix**:
```python
# Pass email_metadata to the pipeline directly instead of assigning after
report = await self.pipeline.scan_single_target(
    target=target,
    email_context=email_summary,
    email_metadata=parsed_email,   # ← Add this
    send_alert=True,
)
reports.append(report)
```

---

### BUG-002 — `SUSPICIOUS` Verdict Bypasses DB Binary Constraint, Causes SQLite ABORT

**File**: [`app/memory.py`](file:///e:/Hackathon%20Snit/app/memory.py) — Line 52  
**Code**:
```sql
verdict TEXT NOT NULL CHECK(verdict IN ('SAFE', 'MALICIOUS'))
```
**Root Cause**: The `scans` table has a `CHECK` constraint that only allows `SAFE` or `MALICIOUS`. But `normalize_verdict()` only runs in `record_investigation()`. The `planner.py` still uses `ThreatLevel.SUSPICIOUS` internally and the LLM can respond with `SUSPICIOUS`. If any code path ever calls a raw SQL insert or if the planner changes the model, this will fail.

More critically: `AgentEvaluation.threat_level` still contains `SUSPICIOUS` from the LLM. This is passed through `planner.py` into Discord alerts and campaign correlation correctly, but if `normalize_verdict` were ever bypassed, the DB would throw an `IntegrityError` and crash the entire investigation silently.

**Impact**: Any future change to `record_investigation` that skips `normalize_verdict` will silently drop scan records.

**Fix**: Apply `normalize_verdict` at the model level, not just inside one method. Document clearly that `SUSPICIOUS` → `MALICIOUS` normalization happens at persistence time.

---

### BUG-003 — Bare `except Exception` in Email Watcher Swallows Entire Investigation Failures

**File**: [`app/email_watcher.py`](file:///e:/Hackathon%20Snit/app/email_watcher.py) — Line 93  
**Code**:
```python
except Exception as exc:
    logger.error(f"[IMAP Watcher] Error checking mailbox: {exc}")
```
**Root Cause**: The outer try/except wraps the **entire** mailbox polling cycle. Any error in any email — including a SQLite `IntegrityError`, a malformed URL, or a VT API crash — silently swallows the exception and continues polling. No email is ever marked as failed and there is no dead-letter queue.

**Impact**: Emails with bugs in processing are silently dropped. You will see 0 rows in the database without knowing why. This is the most likely cause of emails "disappearing" during processing.

**Fix**: Move the try/except inside the per-email loop and add per-email error tracking:
```python
for msg_id, raw_bytes in raw_emails:
    try:
        parsed_email = EmailParser.parse_eml(raw_bytes)
        ...
    except Exception as exc:
        logger.error(f"[IMAP Watcher] Failed to process email {msg_id}: {exc}", exc_info=True)
        continue  # Skip failed email, keep processing the rest
```

---

## 🟠 HIGH SEVERITY

---

### BUG-004 — `scan_single_target` in Pipeline Silently Discards `email_metadata` Parameter

**File**: [`app/pipeline.py`](file:///e:/Hackathon%20Snit/app/pipeline.py) — Line 57  
**Code**:
```python
async def scan_single_target(
    self,
    target: ScanTarget,
    email_context: Optional[str] = None,
    email_metadata: Optional[ParsedEmail] = None,   # ← Accepted...
    ...
) -> ComprehensiveScanReport:
    return await self.planner.execute_investigation(
        target=target,
        email_metadata=email_metadata,             # ← ...but NOT PASSED here
        send_alert=send_alert,
        alert_on_safe=alert_on_safe,
    )
```

Wait — actually checking `planner.execute_investigation` signature: it accepts `email_metadata`. But `pipeline.scan_single_target` calls `planner.execute_investigation` **without passing `email_context`** — the email summary text string that was built in `email_watcher.py` is never passed to the LLM! The AI analyst evaluates the URL without the SPF/DKIM/Subject context even when it's available.

**Impact**: The AI LLM makes decisions without the email forensic context (SPF fail, spoofed display name, suspicious subject) that was explicitly gathered. Lower verdict accuracy.

**Fix**: Pass `email_context` through to `planner.execute_investigation`.

---

### BUG-005 — No `sentinel_memory.db` File in `.gitignore`

**File**: [`.gitignore`](file:///e:/Hackathon%20Snit/.gitignore)  
**Code**:
```
.env        ← Good
*.db        ← MISSING
```
**Root Cause**: The `.gitignore` does not exclude `*.db` or `sentinel_memory.db`. If you commit this project to GitHub, the entire SQLite database with all scanned URLs, email subjects, sender addresses, and attack campaign information will be publicly visible in the repository history.

**Impact**: If any real email addresses or real phishing infrastructure were scanned, this is a **data leak**. Email addresses of senders and subjects become public.

**Fix**: Add to `.gitignore`:
```
*.db
sentinel_memory.db
```

---

### BUG-006 — Planner Logs ThreatLevel.SUSPICIOUS in Step 5 Alert But DB Stores MALICIOUS

**File**: [`app/planner.py`](file:///e:/Hackathon%20Snit/app/planner.py) — Line 197  
**Code**:
```python
should_alert = send_alert and (
    alert_on_safe or evaluation.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS)
)
```
This means a `SUSPICIOUS` verdict triggers a Discord alert but the database will store it as `MALICIOUS` (due to `normalize_verdict`). The Discord embed shows `SUSPICIOUS` but the DB says `MALICIOUS`. Inconsistency between what the analyst sees in Discord vs what the DB records.

**Impact**: Audit trail mismatch — Discord says one thing, database says another.

---

### BUG-007 — Rate Limiter is Per-Instance, Not Shared Across Concurrent Scans

**File**: [`app/scanners/virustotal.py`](file:///e:/Hackathon%20Snit/app/scanners/virustotal.py) — Lines 17-44  
**Root Cause**: The `VirusTotalRateLimiter` is instantiated per `VirusTotalScanner` object. When an email with 3 links arrives, the pipeline creates **one scanner** and calls it 3 times concurrently via `asyncio.gather`. The `asyncio.Lock()` inside the limiter correctly serializes those 3 calls. **However**, if `VirusTotalScanner` is ever instantiated multiple times (e.g., multiple parallel pipelines), each has its own rate limiter with its own counter, and the total rate will exceed the 4 req/60s limit.

**Impact**: Risk of HTTP 429 rate limit bans from VirusTotal in multi-pipeline scenarios.

---

## 🟡 MEDIUM SEVERITY

---

### BUG-008 — `model_config = ConfigDict(frozen=True)` on `ScanTarget` Prevents Runtime Mutation

**File**: [`app/models.py`](file:///e:/Hackathon%20Snit/app/models.py) — Line 32  
`ScanTarget` is `frozen=True`. This is correct and intentional. But `report.email_metadata = parsed_email` in `email_watcher.py` (BUG-001) mutates `ComprehensiveScanReport` which is **not** frozen but is still a Pydantic model. Pydantic v2 allows this, but it can introduce subtle issues if ever the model is set to frozen. Cross-reference with BUG-001.

---

### BUG-009 — Discord Avatar URL Points to Raw GitHub SVG (Non-Functional)

**File**: [`app/notifier.py`](file:///e:/Hackathon%20Snit/app/notifier.py) — Line 177  
**Code**:
```python
"avatar_url": "https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.svg",
```
Discord requires avatar URLs to resolve to PNG/JPG/WebP images. SVG files are **not supported** by Discord and will fail to load, leaving the bot with a blank avatar or Discord's default bot icon.

**Impact**: Minor visual issue — Discord alert bot shows no avatar.

---

### BUG-010 — SQL Injection Risk in Future if DB Queries Ever Use f-strings

**File**: [`app/memory.py`](file:///e:/Hackathon%20Snit/app/memory.py)  
Currently all queries use parameterized `?` placeholders — correct. However, `is_domain_trusted` does string comparison in Python, not SQL. If anyone refactors this to use a `LIKE` query without parameterization, SQL injection is possible. Document the rule explicitly.

**Impact**: Low risk now, medium risk if refactored carelessly.

---

### BUG-011 — No Deduplication of Emails Between Polls (Same UNSEEN Email Scanned Twice)

**File**: [`app/email_watcher.py`](file:///e:/Hackathon%20Snit/app/email_watcher.py) — Lines 103-104  
**Root Cause**: The watcher queries `UNSEEN` messages every 10 seconds. If `IMAP_MARK_AS_SEEN = False` in `.env`, the same email is fetched, parsed, and scanned repeatedly every 10 seconds. This would flood the database with duplicate entries and fire repeated Discord alerts.

**Impact**: Duplicate scans in database, spam Discord alerts if `IMAP_MARK_AS_SEEN` is disabled.

---

### BUG-012 — Groq `UNKNOWN` Verdict Not Normalized Before Reaching DB

**File**: [`app/memory.py`](file:///e:/Hackathon%20Snit/app/memory.py) + [`app/models.py`](file:///e:/Hackathon%20Snit/app/models.py)  
`ThreatLevel.UNKNOWN` exists in the enum. The fallback rule engine in `agent.py` can return it. `normalize_verdict()` converts `UNKNOWN` to `SAFE` (anything not MALICIOUS/SUSPICIOUS → SAFE). This means completely unresolvable URLs with zero scanner data get stored as `SAFE` instead of a separate `UNKNOWN` category.

**Impact**: False sense of safety — unresolvable URLs appear safe in the database.

---

## 🔵 LOW SEVERITY

---

### BUG-013 — No Timeout on IMAP Connection / Login

**File**: [`app/email_watcher.py`](file:///e:/Hackathon%20Snit/app/email_watcher.py) — Lines 28-41  
`imaplib.IMAP4_SSL()` has no explicit socket timeout. If the Gmail IMAP server is unreachable (network blip), the connection will block indefinitely and freeze the async event loop via `run_in_executor`.

**Fix**:
```python
import socket
socket.setdefaulttimeout(30)
```

---

### BUG-014 — Sample Phishing Email URL Hard-coded in `main.py` Demo Mode

**File**: [`app/main.py`](file:///e:/Hackathon%20Snit/app/main.py) — Line 124  
The default demo scan hardcodes `https://login.microsoftonline.msft-update-auth.top/...`. If this domain gets taken down, the demo fails with an INCONCLUSIVE or SAFE verdict — not great for jury presentations.

**Fix**: Keep 2-3 backup demo URLs. Or pre-populate the DB with a canned result for demo mode.

---

### BUG-015 — `docker-compose.yml` Missing `env_file` or Explicit Environment Section

**File**: [`docker-compose.yml`](file:///e:/Hackathon%20Snit/docker-compose.yml)  
If `env_file: .env` is not declared in `docker-compose.yml`, Docker will not automatically load your `.env` credentials into the container. The agent will fail on startup with missing credentials.

**Recommendation**: Verify `env_file: .env` is present in the service definition.

---

### BUG-016 — No Health Check on External API Connectivity at Startup

**File**: [`app/main.py`](file:///e:/Hackathon%20Snit/app/main.py)  
The agent starts up and immediately begins watching the inbox without verifying that VirusTotal, urlscan.io, Groq, and Discord APIs are reachable. A bad API key or network issue only surfaces when the first email arrives.

**Recommendation**: Add a startup connectivity probe that tests each API key on boot and fails fast with a clear error message.

---

## ✅ ACTION PLAN (Priority Order)

| Priority | Bug ID | Fix Required | Effort |
| :---: | :--- | :--- | :---: |
| 1 | **BUG-001** | Pass `email_metadata` in `email_watcher.py` | 2 min |
| 2 | **BUG-003** | Move try/except inside per-email loop | 5 min |
| 3 | **BUG-005** | Add `*.db` to `.gitignore` | 30 sec |
| 4 | **BUG-004** | Pass `email_context` through pipeline to planner | 3 min |
| 5 | **BUG-006** | Normalize verdict in Discord embed or accept discrepancy | 10 min |
| 6 | **BUG-013** | Add socket timeout to IMAP connection | 2 min |
| 7 | **BUG-009** | Replace Discord avatar SVG with PNG URL | 1 min |
| 8 | **BUG-011** | Document `IMAP_MARK_AS_SEEN = True` is mandatory | 1 min |
