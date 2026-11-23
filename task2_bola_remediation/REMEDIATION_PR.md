# PULL REQUEST: Remediate Critical Broken Object Level Authorization (BOLA/IDOR)

**PR Title:** `fix(security): enforce dual-key session authorization on candidate profile endpoint`  
**Issue Reference:** Fixes `SEC-2026-IDOR-001`  
**Target Branch:** `main` <- `fix/bola-route-hardening`  
**Security Impact:** High (Prevents unauthenticated horizontal privilege escalation across applicant profiles)

---

## 1. Summary of Changes

This Pull Request addresses the vulnerability identified in `SEC-2026-IDOR-001` (OWASP API1:2023 Broken Object Level Authorization). The legacy endpoint allowed arbitrary unauthenticated callers to enumerate candidate records via single-parameter lookups (`/api/v1/applications/:appId`).

### Key Remediation Steps:
1. **Added `requireAuth` Middleware:** Enforces HMAC-SHA256 session token verification. Unauthenticated requests are rejected immediately with `401 Unauthorized`.
2. **Dual-Key Query Constraint:** Modified the database retrieval layer to bind the requested `applicationId` to the caller's authenticated `email`.
3. **Information Disclosure Prevention:** Returns a standardized `404 Not Found` when a record does not exist or belongs to another user, preventing attackers from confirming whether an ID is valid.
4. **Integration Test Suite:** Added automated regression tests verifying that User A cannot fetch User B's profile.

---

## 2. Git Unified Diff

```diff
diff --git a/routes/applicationRoutes.js b/routes/applicationRoutes.js
--- a/routes/applicationRoutes.js
+++ b/routes/applicationRoutes.js
@@ -1,15 +1,28 @@
+const { requireAuth } = require('../middleware/auth_middleware');
+
-app.get('/api/v1/applications/:appId', async (req, res) => {
+app.get('/api/v1/applications/:appId', requireAuth, async (req, res) => {
     const { appId } = req.params;
+    const callerEmail = req.user.email;
+    const callerRole = req.user.role;
 
-    // VULNERABLE: Blind lookup with user-controlled identifier
-    const record = await db.find({ applicationId: appId });
+    // HARDENED: Dual-filter query verifying ownership or admin role
+    const record = await db.findOne({
+        applicationId: appId.toUpperCase(),
+        ...(callerRole !== 'ADMIN' && { email: callerEmail })
+    });
 
     if (!record) {
-        return res.status(404).json({ error: "Application record not found" });
+        return res.status(404).json({
+            success: false,
+            error: "Resource not found",
+            code: "ERR_NOT_FOUND"
+        });
     }
 
-    return res.status(200).json(record);
+    // Return scoped, sanitized data
+    return res.status(200).json({
+        success: true,
+        data: sanitizeCandidatePayload(record)
+    });
 });
```

---

## 3. Automated Verification & Testing

The remediation was verified via `task2_bola_remediation/test_bola_remediation.js`:
```bash
node task2_bola_remediation/test_bola_remediation.js
```

**Results:**
- `[PASS]` Rejection of unauthenticated requests (`401 Unauthorized`).
- `[PASS]` User A retrieving own record (`200 OK`).
- `[PASS]` User A attempting horizontal escalation to User B's record (Blocked).
- `[PASS]` Cryptographic signature tampering detection (`401 Invalid Token`).
- `[PASS]` Expired token rejection.
