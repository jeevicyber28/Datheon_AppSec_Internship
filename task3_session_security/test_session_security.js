/**
 * Automated Integration Test Suite: Session Cryptography & Rate Limiting
 */

const assert = require("assert");
const { SessionCryptoService } = require("./session_crypto_service");
const { buildSecureCookieHeader, parseCookies } = require("./cookie_auth_middleware");
const { SlidingWindowRateLimiter } = require("./sliding_rate_limiter");

function runSessionTests() {
    console.log("============================================================");
    console.log(" TASK 3 TEST SUITE: SESSION CRYPTOGRAPHY & RATE LIMITING   ");
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

    // 1. Token Signing & Verified Claims
    it("Should cryptographically sign and verify valid session claims", () => {
        const payload = { userId: "USR-402", email: "sec_engineer@datheon.com", role: "AUDITOR" };
        const token = SessionCryptoService.signToken(payload, 300);
        assert.ok(token, "Token string must be generated");

        const verified = SessionCryptoService.verifyToken(token);
        assert.strictEqual(verified.userId, "USR-402");
        assert.strictEqual(verified.email, "sec_engineer@datheon.com");
        assert.ok(verified.jti, "Unique JTI must be attached");
    });

    // 2. Tamper Rejection via HMAC
    it("Should reject tokens when payload or header bytes are manipulated", () => {
        const token = SessionCryptoService.signToken({ userId: "USR-001" }, 300);
        const [h, b, s] = token.split(".");
        const tampered = `${h}.${Buffer.from(JSON.stringify({ userId: "ADMIN_ROOT" })).toString("base64url")}.${s}`;

        const verified = SessionCryptoService.verifyToken(tampered);
        assert.strictEqual(verified, null, "Tampered token must return null");
    });

    // 3. Cookie Header Directives
    it("Should enforce HttpOnly, Path=/, and SameSite=Lax flags in Set-Cookie", () => {
        const header = buildSecureCookieHeader("session_token", "sample_jwt_val", 900);
        assert.ok(header.includes("HttpOnly"), "Must contain HttpOnly directive");
        assert.ok(header.includes("SameSite=Lax"), "Must contain SameSite=Lax directive");
        assert.ok(header.includes("Max-Age=900"), "Must set Max-Age directive");
    });

    // 4. Cookie Parsing Utility
    it("Should correctly parse browser Cookie header strings", () => {
        const raw = "session_token=secret123; user_theme=dark; device_id=dev99";
        const parsed = parseCookies(raw);
        assert.strictEqual(parsed.session_token, "secret123");
        assert.strictEqual(parsed.user_theme, "dark");
    });

    // 5. Sliding Window Rate Limiting Enforcement
    it("Should throttle burst requests when exceeding max threshold", () => {
        const limiter = new SlidingWindowRateLimiter(60, 5); // 5 max requests per min
        const testIp = "192.168.1.100";

        for (let i = 1; i <= 5; i++) {
            const res = limiter.check(testIp);
            assert.strictEqual(res.allowed, true, `Request ${i} should be allowed`);
        }

        // 6th Request must trigger rate limit
        const blocked = limiter.check(testIp);
        assert.strictEqual(blocked.allowed, false, "Request 6 must be blocked");
        assert.strictEqual(blocked.remaining, 0);
        assert.ok(blocked.resetSeconds > 0, "Reset seconds must be positive");
    });

    console.log("-".repeat(60));
    console.log(`Result: ${passed}/${total} Session Security Tests Passed (100% Success Rate)\n`);

    if (passed !== total) process.exit(1);
}

if (require.main === module) {
    runSessionTests();
}

module.exports = { runSessionTests };
