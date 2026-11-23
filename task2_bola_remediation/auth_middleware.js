/**
 * Defensive Authorization & Session Identity Middleware
 * Verifies caller identity and binds authenticated session context to req.user.
 */

const crypto = require("crypto");

const JWT_SECRET = process.env.JWT_SECRET || "DATHEON_APPSEC_SECURE_HMAC_SECRET_2026";

/**
 * Validates HMAC-SHA256 signature and unpacks verified claims.
 */
function verifySessionToken(token) {
    if (!token || typeof token !== "string") return null;

    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const expectedSig = crypto
        .createHmac("sha256", JWT_SECRET)
        .update(`${headerB64}.${payloadB64}`)
        .digest("base64url");

    // Timing-safe comparison to prevent side-channel timing attacks
    if (!crypto.timingSafeEqual(Buffer.from(signatureB64), Buffer.from(expectedSig))) {
        return null;
    }

    try {
        const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
        // Expiration verification
        if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
            return null; // Token expired
        }
        return payload;
    } catch {
        return null;
    }
}

/**
 * Express / Node.js Authentication Guard Middleware
 */
function requireAuth(req, res, next) {
    let token = null;

    // Check 1: Authorization Header (Bearer <token>)
    const authHeader = req.headers["authorization"];
    if (authHeader && authHeader.startsWith("Bearer ")) {
        token = authHeader.substring(7).trim();
    }

    // Check 2: HTTP-only session cookie fallback
    if (!token && req.cookies && req.cookies.session_token) {
        token = req.cookies.session_token;
    }

    if (!token) {
        return res.status(401).json({
            success: false,
            error: "Authentication required",
            code: "ERR_UNAUTHENTICATED",
            message: "Missing valid session token or authentication header."
        });
    }

    const claims = verifySessionToken(token);
    if (!claims) {
        return res.status(401).json({
            success: false,
            error: "Invalid or expired session token",
            code: "ERR_INVALID_TOKEN",
            message: "Session token signature verification failed or token has expired."
        });
    }

    // Bind trusted session context to the request object
    req.user = {
        userId: claims.userId,
        email: claims.email.toLowerCase(),
        role: claims.role || "USER"
    };

    return next();
}

module.exports = { requireAuth, verifySessionToken, JWT_SECRET };
