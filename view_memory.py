"""CLI Viewer for Sentinel Memory SQLite database with clean formatted views."""

import argparse
import json
import sqlite3
import sys

# Fix Windows terminal encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def inspect_db(db_path: str = "sentinel_memory.db"):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    print("\n" + "=" * 90)
    print("SENTINEL MEMORY DATABASE - AUDIT DASHBOARD")
    print(f"Source: {db_path}")
    print("=" * 90)

    # 1. Active Threats
    cursor.execute("""
        SELECT * FROM scans 
        WHERE verdict = 'MALICIOUS'
        ORDER BY id DESC LIMIT 20
    """)
    threats = cursor.fetchall()
    print(f"\n[MALICIOUS THREATS] — {len(threats)} record(s)")
    print("-" * 90)
    if not threats:
        print("  No malicious threats recorded yet.")
    else:
        for t in threats:
            print(f"  Scan #   : {t['id']}")
            print(f"  Verdict  : MALICIOUS  |  Confidence: {t['confidence']}%")
            print(f"  URL      : {t['url']}")
            print(f"  Domain   : {t['domain']}")
            if t['brand']:
                print(f"  Brand    : {t['brand']}")
            if t['email_subject']:
                print(f"  Subject  : {t['email_subject']}")
                print(f"  Sender   : {t['email_sender']}")
            print(f"  Summary  : {t['summary']}")
            print(f"  Logged   : {t['created_at']}")
            print()

    # 2. Safe Traffic
    cursor.execute("""
        SELECT * FROM scans 
        WHERE verdict = 'SAFE'
        ORDER BY id DESC LIMIT 20
    """)
    safe = cursor.fetchall()
    print(f"\n[SAFE TRAFFIC] — {len(safe)} record(s)")
    print("-" * 90)
    if not safe:
        print("  No safe traffic logged yet.")
    else:
        for s in safe:
            print(f"  Scan #   : {s['id']}")
            print(f"  Verdict  : SAFE  |  Confidence: {s['confidence']}%")
            print(f"  URL      : {s['url']}")
            print(f"  Domain   : {s['domain']}")
            if s['email_subject']:
                print(f"  Subject  : {s['email_subject']}")
                print(f"  Sender   : {s['email_sender']}")
            print(f"  Logged   : {s['created_at']}")
            print()

    # 3. Campaigns
    cursor.execute("SELECT * FROM campaigns ORDER BY attack_count DESC")
    campaigns = cursor.fetchall()
    print(f"\n[ATTACK CAMPAIGNS] — {len(campaigns)} active")
    print("-" * 90)
    if not campaigns:
        print("  No persistent attack campaigns tracked yet.")
    else:
        for c in campaigns:
            domains = json.loads(c["domains"])
            print(f"  Campaign : #{c['id']} targeting {c['brand']}")
            print(f"  Attacks  : {c['attack_count']}")
            print(f"  Domains  : {', '.join(domains)}")
            print(f"  First    : {c['first_seen']}  |  Last: {c['last_seen']}")
            print()

    # 4. Summary counts
    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict='MALICIOUS'")
    m_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict='SAFE'")
    s_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM campaigns")
    c_count = cursor.fetchone()[0]

    print("=" * 90)
    print(f"TOTALS  ->  Malicious: {m_count}  |  Safe: {s_count}  |  Campaigns: {c_count}")
    print("=" * 90 + "\n")
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Memory Inspector")
    parser.add_argument("--db", default="sentinel_memory.db", help="Path to SQLite database")
    args = parser.parse_args()
    inspect_db(args.db)
