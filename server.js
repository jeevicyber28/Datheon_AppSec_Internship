/**
 * DATHEON APPLICATION SECURITY & API PENTESTING LAB SERVER
 * Zero External Dependencies - Native Node.js HTTP Server.
 * Neo-Brutalist Interactive Vulnerability & Defense Testbed.
 */

const http = require("http");
const crypto = require("crypto");
const { verifySessionToken, JWT_SECRET } = require("./task2_bola_remediation/auth_middleware");
const { SessionCryptoService } = require("./task3_session_security/session_crypto_service");
const { buildSecureCookieHeader, parseCookies } = require("./task3_session_security/cookie_auth_middleware");
const { SlidingWindowRateLimiter } = require("./task3_session_security/sliding_rate_limiter");
const { PIISanitizer } = require("./task4_pii_masking_ci_cd/pii_sanitizer");
const { applySecurityHeaders } = require("./task4_pii_masking_ci_cd/security_headers_middleware");

const PORT = process.env.PORT || 5000;

// In-Memory Candidate Registry
const mockDatabase = [
    {
        applicationId: "DT-2026-001",
        candidateName: "Jeeviraj V",
        email: "jeevicyber28@gmail.com",
        phone: "+91-98401-23456",
        institution: "Anna University",
        internshipTrack: "AppSec & API Pentesting",
        offerStatus: "Confirmed",
        mentorNotes: "CONFIDENTIAL: Cleared AppSec test with top 1% score."
    },
    {
        applicationId: "DT-2026-002",
        candidateName: "Priya Ramanathan",
        email: "priya.ramanathan@example.com",
        phone: "+91-98402-88888",
        institution: "Anna University",
        internshipTrack: "Python Programming",
        offerStatus: "Confirmed",
        mentorNotes: "CONFIDENTIAL: Candidate placed in Batch 01."
    },
    {
        applicationId: "DT-2026-003",
        candidateName: "Arun Kumar",
        email: "arun.k@example.com",
        phone: "+91-98403-99999",
        institution: "Anna University",
        internshipTrack: "Cloud Architecture",
        offerStatus: "Pending Review",
        mentorNotes: "CONFIDENTIAL: Awaiting final transcript verification."
    }
];

const rateLimiter = new SlidingWindowRateLimiter(60, 8); // 8 requests/minute

function sendJson(res, statusCode, data, headers = {}) {
    res.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        ...headers
    });
    res.end(JSON.stringify(data, null, 2));
}

function getHtmlDashboard() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DATHEON APPSEC // ZERO-TRUST API AUDIT LAB</title>
    <style>
        :root {
            --bg: #0d0d0d;
            --surface: #171717;
            --yellow: #FFE600;
            --cyan: #00F0FF;
            --coral: #FF3366;
            --lime: #00FF66;
            --white: #FFFFFF;
            --border: 3px solid #000;
            --shadow: 5px 5px 0px #000;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: "Consolas", "Courier New", monospace; }
        body { background: var(--bg); color: var(--white); padding: 2rem; }
        .container { max-width: 1000px; margin: auto; }
        
        /* Brutalist Banner */
        .banner {
            background: var(--yellow);
            color: #000;
            border: var(--border);
            box-shadow: var(--shadow);
            padding: 1.5rem;
            margin-bottom: 2rem;
            transform: rotate(-0.5deg);
        }
        .banner h1 { font-size: 2rem; text-transform: uppercase; font-weight: 900; letter-spacing: -1px; }
        .banner p { font-size: 0.95rem; font-weight: bold; margin-top: 0.5rem; }

        /* Grid */
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .card {
            background: var(--surface);
            border: var(--border);
            box-shadow: var(--shadow);
            padding: 1.25rem;
            position: relative;
        }
        .badge {
            display: inline-block;
            font-size: 0.75rem;
            font-weight: 900;
            text-transform: uppercase;
            padding: 0.25rem 0.6rem;
            border: 2px solid #000;
            margin-bottom: 0.75rem;
        }
        .badge-vuln { background: var(--coral); color: #fff; }
        .badge-secure { background: var(--lime); color: #000; }
        .badge-cyan { background: var(--cyan); color: #000; }
        
        .card h3 { font-size: 1.15rem; margin-bottom: 0.5rem; }
        .card p { font-size: 0.85rem; color: #ccc; margin-bottom: 1rem; line-height: 1.4; }

        /* Buttons */
        .btn {
            display: inline-block;
            background: var(--white);
            color: #000;
            border: var(--border);
            box-shadow: 3px 3px 0px #000;
            padding: 0.5rem 1rem;
            font-weight: 900;
            text-transform: uppercase;
            cursor: pointer;
            font-size: 0.8rem;
            text-decoration: none;
            transition: all 0.1s ease;
        }
        .btn:hover { transform: translate(-2px, -2px); box-shadow: 5px 5px 0px #000; }
        .btn:active { transform: translate(1px, 1px); box-shadow: 2px 2px 0px #000; }
        .btn-coral { background: var(--coral); color: #fff; }
        .btn-lime { background: var(--lime); color: #000; }
        .btn-cyan { background: var(--cyan); color: #000; }

        /* Terminal Console */
        .terminal {
            background: #000;
            border: var(--border);
            box-shadow: var(--shadow);
            padding: 1.25rem;
            margin-top: 1.5rem;
            min-height: 220px;
        }
        .terminal-header {
            display: flex;
            justify-content: space-between;
            color: var(--yellow);
            font-size: 0.85rem;
            border-bottom: 1px solid #333;
            padding-bottom: 0.5rem;
            margin-bottom: 0.75rem;
        }
        pre { font-size: 0.85rem; color: var(--lime); white-space: pre-wrap; word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <div class="banner">
            <h1>DATHEON APPSEC // AUDIT LAB</h1>
            <p>API Pentesting, Broken Object Level Authorization (BOLA/IDOR), & Cryptographic Zero-Trust Defense</p>
        </div>

        <div class="grid">
            <!-- Card 1 -->
            <div class="card">
                <span class="badge badge-vuln">Task 1 · Vulnerable</span>
                <h3>IDOR / BOLA Endpoint</h3>
                <p>Queries database solely by URL param with ZERO session check. Demonstrates horizontal PII leak.</p>
                <button class="btn btn-coral" onclick="testEndpoint('/api/v1/applications/DT-2026-002')">Test IDOR Leak</button>
            </div>

            <!-- Card 2 -->
            <div class="card">
                <span class="badge badge-secure">Task 2 · Hardened</span>
                <h3>Dual-Filter Route Guard</h3>
                <p>Enforces JWT authentication and dual-key lookup. Rejects cross-tenant attempts with 401/404.</p>
                <button class="btn btn-lime" onclick="testEndpoint('/api/v1/hardened/applications/DT-2026-002')">Test Auth Guard</button>
            </div>

            <!-- Card 3 -->
            <div class="card">
                <span class="badge badge-cyan">Task 3 · Session</span>
                <h3>Secure Cookie + Rate Limit</h3>
                <p>Generates HMAC-SHA256 signed HttpOnly cookie. Throttles bursts with sliding window counter.</p>
                <button class="btn btn-cyan" onclick="testEndpoint('/api/v1/auth/login')">Simulate Login</button>
            </div>

            <!-- Card 4 -->
            <div class="card">
                <span class="badge badge-secure">Task 4 · Masking</span>
                <h3>PII Masking & Security Headers</h3>
                <p>Public verification route with zero PII disclosure (j***8@gmail.com) and strict CSP / HSTS headers.</p>
                <button class="btn btn-white" onclick="testEndpoint('/api/v1/public/verify/DT-2026-001')">Test Public Verification</button>
            </div>
        </div>

        <div class="terminal">
            <div class="terminal-header">
                <span>[LIVE AUDIT CONSOLE]</span>
                <span id="response-status">STATUS: STANDBY</span>
            </div>
            <pre id="console-output">// Click any test button above to execute live HTTP probe against the local AppSec server...</pre>
        </div>
    </div>

    <script>
        async function testEndpoint(endpoint) {
            const out = document.getElementById('console-output');
            const statusEl = document.getElementById('response-status');
            out.textContent = ">>> Executing GET " + endpoint + " ...";
            statusEl.textContent = "STATUS: PROBING";
            
            try {
                const res = await fetch(endpoint);
                const data = await res.json();
                statusEl.textContent = "STATUS: HTTP " + res.status + " " + res.statusText;
                statusEl.style.color = res.status < 400 ? "#00FF66" : "#FF3366";
                out.textContent = "HTTP/1.1 " + res.status + " " + res.statusText + "\\n" +
                                  "Response Headers: " + JSON.stringify(Object.fromEntries(res.headers.entries()), null, 2) + "\\n\\n" +
                                  JSON.stringify(data, null, 2);
            } catch (err) {
                statusEl.textContent = "STATUS: FAILED";
                out.textContent = "Error executing probe: " + err.message;
            }
        }
    </script>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname = parsedUrl.pathname;
    const method = req.method.toUpperCase();

    // CORS pre-flight
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

    if (method === "OPTIONS") {
        res.writeHead(204);
        return res.end();
    }

    // Rate Limiting on API endpoints
    if (pathname.startsWith("/api/")) {
        const clientIp = req.socket.remoteAddress || "127.0.0.1";
        const rateCheck = rateLimiter.check(clientIp);
        res.setHeader("X-RateLimit-Limit", 8);
        res.setHeader("X-RateLimit-Remaining", rateCheck.remaining);
        res.setHeader("X-RateLimit-Reset", rateCheck.resetSeconds);

        if (!rateCheck.allowed) {
            res.setHeader("Retry-After", rateCheck.resetSeconds);
            return sendJson(res, 429, {
                success: false,
                error: "Too Many Requests",
                code: "ERR_RATE_LIMIT_EXCEEDED",
                message: `Sliding window rate limit exceeded. Retry in ${rateCheck.resetSeconds}s.`
            });
        }
    }

    // 1. Root Dashboard
    if (pathname === "/" && method === "GET") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        return res.end(getHtmlDashboard());
    }

    // 2. TASK 1 & 2 (VULNERABLE): IDOR Route (/api/v1/applications/:appId)
    const vulnMatch = pathname.match(/^\/api\/v1\/(?:vulnerable\/)?applications\/([^/]+)$/);
    if (vulnMatch && method === "GET") {
        const appId = decodeURIComponent(vulnMatch[1]);
        const record = mockDatabase.find((item) => item.applicationId.toUpperCase() === appId.toUpperCase());

        if (!record) {
            return sendJson(res, 404, { success: false, error: "Application record not found" });
        }

        // FLAW: Leaks unauthenticated PII
        return sendJson(res, 200, record);
    }

    // 3. TASK 2 (HARDENED): Dual-Key Authorization Route (/api/v1/hardened/applications/:appId)
    const hardenedMatch = pathname.match(/^\/api\/v1\/hardened\/applications\/([^/]+)$/);
    if (hardenedMatch && method === "GET") {
        const appId = decodeURIComponent(hardenedMatch[1]);

        // Verify Bearer Token or Cookie
        const authHeader = req.headers["authorization"];
        let token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.substring(7) : null;
        if (!token) {
            const cookies = parseCookies(req.headers["cookie"]);
            token = cookies["session_token"];
        }

        if (!token) {
            return sendJson(res, 401, {
                success: false,
                error: "Authentication required",
                code: "ERR_UNAUTHENTICATED",
                message: "Authorization guard rejected unauthenticated access."
            });
        }

        const claims = verifySessionToken(token);
        if (!claims) {
            return sendJson(res, 401, {
                success: false,
                error: "Invalid or expired session token",
                code: "ERR_INVALID_TOKEN"
            });
        }

        // Dual key constraint: Match ID AND email (or ADMIN)
        const record = mockDatabase.find((item) => {
            const idMatches = item.applicationId.toUpperCase() === appId.toUpperCase();
            if (!idMatches) return false;
            if (claims.role === "ADMIN") return true;
            return item.email.toLowerCase() === claims.email.toLowerCase();
        });

        if (!record) {
            return sendJson(res, 404, {
                success: false,
                error: "Resource not found",
                code: "ERR_NOT_FOUND",
                message: "Record does not exist or you do not have permission to view it."
            });
        }

        return sendJson(res, 200, { success: true, data: record });
    }

    // 4. TASK 3: Login Route setting Secure Cookie
    if (pathname === "/api/v1/auth/login" && (method === "GET" || method === "POST")) {
        const user = mockDatabase[0]; // Jeeviraj V
        const token = SessionCryptoService.signToken({
            userId: "USR-001",
            email: user.email,
            role: "CANDIDATE"
        }, 900);

        const cookieHeader = buildSecureCookieHeader("session_token", token, 900);
        return sendJson(
            res,
            200,
            {
                success: true,
                message: "Authenticated successfully. Secure HttpOnly cookie set.",
                tokenPreview: token.substring(0, 24) + "...",
                claims: { email: user.email, role: "CANDIDATE", expiresIn: "15 minutes" }
            },
            { "Set-Cookie": cookieHeader }
        );
    }

    // 5. TASK 4: Public Verification with PII Masking & Security Headers
    const publicMatch = pathname.match(/^\/api\/v1\/public\/verify\/([^/]+)$/);
    if (publicMatch && method === "GET") {
        const credentialId = decodeURIComponent(publicMatch[1]);
        const record = mockDatabase.find((item) => item.applicationId.toUpperCase() === credentialId.toUpperCase());

        // Apply strict security headers
        applySecurityHeaders(req, res);

        if (!record) {
            return sendJson(res, 404, {
                success: false,
                verificationStatus: "NOT_FOUND",
                message: "Credential ID not found in verified registry."
            });
        }

        const maskedData = PIISanitizer.sanitizeForPublicVerification(record);
        return sendJson(res, 200, {
            success: true,
            data: maskedData
        });
    }

    // 404 Fallback
    return sendJson(res, 404, { success: false, error: "Endpoint not found" });
});

if (require.main === module) {
    server.listen(PORT, () => {
        console.log("============================================================");
        console.log(`   DATHEON APPSEC LAB SERVER ACTIVE -> http://localhost:${PORT}`);
        console.log("============================================================");
        console.log(" Endpoints ready for testing:");
        console.log("  - [GET]  /                                (Interactive Dashboard)");
        console.log("  - [GET]  /api/v1/applications/:appId      (Vulnerable IDOR Route)");
        console.log("  - [GET]  /api/v1/hardened/applications/:id (Hardened Zero-Trust)");
        console.log("  - [POST] /api/v1/auth/login               (Secure Cookie Auth)");
        console.log("  - [GET]  /api/v1/public/verify/:id        (Masked Public PII)");
        console.log("============================================================");
    });
}

module.exports = { server, mockDatabase, PORT };
