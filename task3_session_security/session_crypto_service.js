/**
 * Cryptographic Session Security Service
 * Zero external dependencies - Implemented via Node.js native crypto module.
 */

const crypto = require("crypto");

const SESSION_SECRET = process.env.SESSION_SECRET || "DATHEON_SECURE_HMAC_SHA256_SESSION_SECRET_KEY_2026";
const ACCESS_TOKEN_TTL_SEC = 15 * 60; // 15 Minutes
const REFRESH_TOKEN_TTL_SEC = 7 * 24 * 3600; // 7 Days

class SessionCryptoService {
    /**
     * Creates an HMAC-SHA256 signed JWT
     */
    static signToken(payload, expiresInSeconds = ACCESS_TOKEN_TTL_SEC) {
        const now = Math.floor(Date.now() / 1000);
        const fullPayload = {
            ...payload,
            iat: now,
            exp: now + expiresInSeconds,
            jti: crypto.randomBytes(16).toString("hex") // Unique Token ID
        };

        const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
        const body = Buffer.from(JSON.stringify(fullPayload)).toString("base64url");
        const signature = crypto
            .createHmac("sha256", SESSION_SECRET)
            .update(`${header}.${body}`)
            .digest("base64url");

        return `${header}.${body}.${signature}`;
    }

    /**
     * Verifies token with constant-time equality check to prevent timing attacks
     */
    static verifyToken(token) {
        if (!token || typeof token !== "string") return null;

        const parts = token.split(".");
        if (parts.length !== 3) return null;

        const [headerB64, bodyB64, signatureB64] = parts;
        const expectedSignature = crypto
            .createHmac("sha256", SESSION_SECRET)
            .update(`${headerB64}.${bodyB64}`)
            .digest("base64url");

        const sigBuf = Buffer.from(signatureB64);
        const expBuf = Buffer.from(expectedSignature);

        if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
            return null; // Tampered signature
        }

        try {
            const claims = JSON.parse(Buffer.from(bodyB64, "base64url").toString("utf8"));
            const now = Math.floor(Date.now() / 1000);
            if (claims.exp && now > claims.exp) {
                return null; // Expired
            }
            return claims;
        } catch {
            return null;
        }
    }

    /**
     * Generates a high-entropy cryptographically secure refresh token
     */
    static generateRefreshToken() {
        return crypto.randomBytes(32).toString("hex");
    }
}

module.exports = {
    SessionCryptoService,
    SESSION_SECRET,
    ACCESS_TOKEN_TTL_SEC,
    REFRESH_TOKEN_TTL_SEC
};
