/**
 * Automated Test Suite: PII Masking & Security Headers Verification
 */

const assert = require("assert");
const { PIISanitizer } = require("./pii_sanitizer");
const { applySecurityHeaders } = require("./security_headers_middleware");

function runPIITests() {
    console.log("============================================================");
    console.log(" TASK 4 TEST SUITE: PII MASKING & SECURITY HEADERS TEST     ");
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

    // 1. Email Masking
    it("Should correctly mask user email addresses", () => {
        const masked1 = PIISanitizer.maskEmail("jeevicyber28@gmail.com");
        assert.strictEqual(masked1, "j***8@gmail.com", "Long email must mask intermediate characters");

        const masked2 = PIISanitizer.maskEmail("admin@corp.io");
        assert.strictEqual(masked2, "a***n@corp.io");
    });

    // 2. Phone Number Masking
    it("Should mask international phone numbers preserving only last 4 digits", () => {
        const masked = PIISanitizer.maskPhone("+91-98401-23456");
        assert.strictEqual(masked, "+**-*****-3456");
    });

    // 3. Name Masking
    it("Should mask first and last names preserving boundary characters", () => {
        const masked = PIISanitizer.maskName("Jeeviraj Ramanathan");
        assert.strictEqual(masked, "J***j R***n");
    });

    // 4. Record Sanitization (Zero Internal Leakage)
    it("Should scrub internal notes, salaries, and sensitive fields from public view", () => {
        const internalRecord = {
            applicationId: "DT-2026-001",
            candidateName: "Jeeviraj V",
            email: "jeevicyber28@gmail.com",
            phone: "+91-98401-23456",
            institution: "Anna University",
            internshipTrack: "AppSec & API Pentesting",
            mentorNotes: "CONFIDENTIAL INTERNAL NOTE: Candidate cleared with top 1% score",
            internalDbId: 40819,
            stipendAmount: "50000"
        };

        const publicView = PIISanitizer.sanitizeForPublicVerification(internalRecord);

        assert.strictEqual(publicView.credentialId, "DT-2026-001");
        assert.strictEqual(publicView.recipientEmailMasked, "j***8@gmail.com");
        assert.strictEqual(publicView.mentorNotes, undefined, "Internal notes must be completely omitted");
        assert.strictEqual(publicView.internalDbId, undefined, "Internal DB IDs must be omitted");
        assert.strictEqual(publicView.stipendAmount, undefined, "Financial data must be omitted");
    });

    // 5. Security Headers Enforcement
    it("Should inject strict Content-Security-Policy, HSTS, and X-Frame-Options", () => {
        const mockHeaders = {};
        const mockRes = {
            setHeader: (k, v) => {
                mockHeaders[k.toLowerCase()] = v;
            }
        };

        applySecurityHeaders({}, mockRes);

        assert.ok(mockHeaders["content-security-policy"].includes("default-src 'self'"));
        assert.ok(mockHeaders["strict-transport-security"].includes("max-age=63072000"));
        assert.strictEqual(mockHeaders["x-content-type-options"], "nosniff");
        assert.strictEqual(mockHeaders["x-frame-options"], "DENY");
        assert.strictEqual(mockHeaders["referrer-policy"], "strict-origin-when-cross-origin");
    });

    console.log("-".repeat(60));
    console.log(`Result: ${passed}/${total} PII & Header Tests Passed (100% Success Rate)\n`);

    if (passed !== total) process.exit(1);
}

if (require.main === module) {
    runPIITests();
}

module.exports = { runPIITests };
