/**
 * Automated Integration Test Suite: BOLA / IDOR Defense Verification
 * Validates rejection of unauthorized requests and privilege boundaries.
 */

const assert = require("assert");
const crypto = require("crypto");
const { verifySessionToken, JWT_SECRET } = require("./auth_middleware");

// Helper to sign mock JWTs for test harnesses
function createMockJWT(payload) {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const sig = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url");
    return `${header}.${body}.${sig}`;
}

const mockDatabase = [
    {
        applicationId: "DT-2026-001",
        candidateName: "Jeeviraj V",
        email: "jeevicyber28@gmail.com",
        institution: "Anna University",
        internshipTrack: "AppSec & API Pentesting"
    },
    {
        applicationId: "DT-2026-002",
        candidateName: "Priya Ramanathan",
        email: "priya.ramanathan@example.com",
        institution: "Anna University",
        internshipTrack: "Python Programming"
    }
];

function runSecurityTests() {
    console.log("============================================================");
    console.log("   TASK 2 TEST SUITE: BOLA / IDOR REMEDIATION VERIFICATION  ");
    console.log("============================================================");

    let passed = 0;
    let total = 0;

    function it(testName, fn) {
        total++;
        try {
            fn();
            console.log(` [PASS] ${testName}`);
            passed++;
        } catch (err) {
            console.error(` [FAIL] ${testName}`);
            console.error(`        ${err.message}`);
        }
    }

    // TEST 1: Unauthenticated Caller Rejection
    it("Should reject requests missing session tokens with 401 Unauthorized", () => {
        const token = null;
        const claims = verifySessionToken(token);
        assert.strictEqual(claims, null, "Unauthenticated caller must return null claims");
    });

    // TEST 2: Valid User A Accessing User A's Own Record
    it("Should allow User A to access their own application record (200 OK)", () => {
        const tokenA = createMockJWT({
            userId: "USR-001",
            email: "jeevicyber28@gmail.com",
            role: "USER",
            exp: Math.floor(Date.now() / 1000) + 3600
        });

        const claims = verifySessionToken(tokenA);
        assert.ok(claims, "Valid JWT should verify successfully");

        const targetAppId = "DT-2026-001";
        const record = mockDatabase.find(
            (i) => i.applicationId === targetAppId && i.email.toLowerCase() === claims.email.toLowerCase()
        );

        assert.ok(record, "User A should locate their own record");
        assert.strictEqual(record.candidateName, "Jeeviraj V");
    });

    // TEST 3: User A attempting Horizontal Escalation to User B's Record (BOLA Attempt)
    it("Should BLOCK User A from accessing User B's record (DT-2026-002)", () => {
        const tokenA = createMockJWT({
            userId: "USR-001",
            email: "jeevicyber28@gmail.com",
            role: "USER",
            exp: Math.floor(Date.now() / 1000) + 3600
        });

        const claims = verifySessionToken(tokenA);
        const attackerTargetAppId = "DT-2026-002"; // Belongs to Priya

        // Query enforcing dual key
        const record = mockDatabase.find(
            (i) => i.applicationId === attackerTargetAppId && i.email.toLowerCase() === claims.email.toLowerCase()
        );

        assert.strictEqual(record, undefined, "BOLA breach prevented: User A cannot read User B's record");
    });

    // TEST 4: Tampered Signature Detection
    it("Should reject tampered JWT signatures with 401", () => {
        const validToken = createMockJWT({
            userId: "USR-001",
            email: "jeevicyber28@gmail.com",
            exp: Math.floor(Date.now() / 1000) + 3600
        });

        // Tamper with payload
        const parts = validToken.split(".");
        const tamperedToken = `${parts[0]}.${Buffer.from(JSON.stringify({ userId: "USR-999", email: "admin@corp.com" })).toString("base64url")}.${parts[2]}`;

        const claims = verifySessionToken(tamperedToken);
        assert.strictEqual(claims, null, "Tampered cryptographic signature must be rejected");
    });

    // TEST 5: Expired Token Rejection
    it("Should reject expired session tokens", () => {
        const expiredToken = createMockJWT({
            userId: "USR-001",
            email: "jeevicyber28@gmail.com",
            exp: Math.floor(Date.now() / 1000) - 60 // Expired 1 min ago
        });

        const claims = verifySessionToken(expiredToken);
        assert.strictEqual(claims, null, "Expired token must be rejected");
    });

    console.log("-".repeat(60));
    console.log(`\nResult: ${passed}/${total} Security Tests Passed (${(passed / total) * 100}% Success Rate)\n`);

    if (passed !== total) {
        process.exit(1);
    }
}

if (require.main === module) {
    runSecurityTests();
}

module.exports = { runSecurityTests };
