# 🗄️ Sentinel Memory Database Specification & Rules (`DATABASE_SPEC.md`)

This document defines the strict, simplified architecture, table schema, and operational rules for the Phishing Sentinel persistent database (`sentinel_memory.db`). 

---

## 📌 Core Operational Rules (Memory Directives)

1. **Clean & Fresh Slate**:
   - Zero dummy, fake, or synthetic records.
   - The database initializes completely empty upon deployment.
   - Tables are strictly defined with only necessary, essential columns.

2. **Per-Link Instance Logging**:
   - Every single unique link detected in an email or passed via CLI/API is treated as an individual scan instance.
   - Every instance is recorded immediately in the database with full timestamp and forensic metadata.

3. **Strict Binary Threat Categorization**:
   - Every record has a simplified verdict: **`SAFE`** or **`MALICIOUS`**.
   - If an evaluation contains high/medium risk signals or brand spoofing, it is classified as **`MALICIOUS`**.
   - If clean with no threat indicators, it is classified as **`SAFE`**.

4. **Discord Alerting Policy**:
   - **`MALICIOUS`** $\to$ Immediately format and dispatch a rich alert embed to the configured Discord webhook.
   - **`SAFE`** $\to$ Persist to database silently for historical audit without triggering Discord notifications.

---

## 🏗️ Simplified Database Schema (`sentinel_memory.db`)

### 1. `scans` Table (Primary Instance Ledger)
Stores every scanned link instance cleanly with zero clutter.

| Column Name | Data Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY` | Auto-incrementing unique scan identifier. |
| `url` | `TEXT` | `NOT NULL` | The original raw URL scanned. |
| `domain` | `TEXT` | `NOT NULL` | Normalized domain/hostname (e.g., `evil-login.com`). |
| `verdict` | `TEXT` | `NOT NULL` | Strict verdict: **`MALICIOUS`** or **`SAFE`**. |
| `confidence` | `INTEGER` | `NOT NULL` | Confidence percentage (`0` to `100`). |
| `summary` | `TEXT` | `NOT NULL` | Concise technical explanation for the verdict. |
| `brand` | `TEXT` | `NULL` | Targeted/impersonated brand name (e.g., `PayPal`), or `NULL`. |
| `email_subject`| `TEXT` | `NULL` | Email subject line if extracted from an email. |
| `email_sender` | `TEXT` | `NULL` | Sender address if extracted from an email. |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp when scan occurred. |

---

### 2. `campaigns` Table (Correlated Attack Clusters)
Tracks repeating attack campaigns against brands across different domains.

| Column Name | Data Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY` | Auto-incrementing campaign identifier. |
| `brand` | `TEXT` | `NOT NULL` | Targeted brand (e.g. `Microsoft`, `PayPal`, `Bank of America`). |
| `domains` | `TEXT` | `NOT NULL` | JSON array of associated attack domains. |
| `attack_count` | `INTEGER` | `NOT NULL` | Count of times this campaign was intercepted. |
| `first_seen` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp of initial discovery. |
| `last_seen` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp of latest attack. |

---

## ⚡ Direct SQL Querying Guide (Easy to Read)

```sql
-- 1. View all Malicious Threat Detections
SELECT id, domain, verdict, confidence, brand, summary, created_at 
FROM scans 
WHERE verdict = 'MALICIOUS' 
ORDER BY id DESC;

-- 2. View all Clean / Safe Scans
SELECT id, domain, verdict, confidence, created_at 
FROM scans 
WHERE verdict = 'SAFE' 
ORDER BY id DESC;

-- 3. View Repeat Attack Campaigns
SELECT brand, attack_count, domains, last_seen 
FROM campaigns 
ORDER BY attack_count DESC;
```
