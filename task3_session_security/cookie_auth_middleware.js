/**
 * Secure HTTP-Only Cookie Session Middleware
 * Enforces HttpOnly, Secure, and SameSite=Lax flags to protect against XSS token theft.
 */

const { SessionCryptoService, ACCESS_TOKEN_TTL_SEC } = require("./session_crypto_service");

/**
 * Builds the strict Set-Cookie header string
 */
function buildSecureCookieHeader(tokenName, tokenValue, maxAgeSeconds = ACCESS_TOKEN_TTL_SEC) {
    const isProduction = process.env.NODE_ENV === "production";
    const parts = [
        `${tokenName}=${tokenValue}`,
        `Max-Age=${maxAgeSeconds}`,
        "Path=/",
        "HttpOnly",               // Mitigates XSS exfiltration (JS cannot read document.cookie)
        "SameSite=Lax"            // Mitigates Cross-Site Request Forgery (CSRF)
    ];

    if (isProduction) {
        parts.push("Secure");     // Transmitted strictly over HTTPS
    }

    return parts.join("; ");
}

/**
 * Parses raw Cookie header string into key-value map
 */
function parseCookies(cookieHeader) {
    const cookies = {};
    if (!cookieHeader) return cookies;
    cookieHeader.split(";").forEach((pair) => {
        const [key, ...val] = pair.trim().split("=");
        if (key) {
            cookies[key] = decodeURIComponent(val.join("="));
        }
    });
    return cookies;
}

/**
 * Cookie-based authorization middleware
 */
function requireCookieAuth(req, res, next) {
    const rawCookies = req.headers["cookie"];
    const cookies = parseCookies(rawCookies);
    const token = cookies["session_token"];

    if (!token) {
        return res.status(401).json({
            success: false,
            error: "Authentication required",
            code: "ERR_NO_SESSION_COOKIE",
            message: "Missing secure HttpOnly session cookie."
        });
    }

    const claims = SessionCryptoService.verifyToken(token);
    if (!claims) {
        return res.status(401).json({
            success: false,
            error: "Session expired or invalid",
            code: "ERR_SESSION_TERMINATED"
        });
    }

    req.user = claims;
    return next();
}

module.exports = {
    buildSecureCookieHeader,
    parseCookies,
    requireCookieAuth
};
