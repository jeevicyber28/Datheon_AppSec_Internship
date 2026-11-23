/**
 * HTTP Security Hardening Headers Middleware
 * Enforces strict defense-in-depth headers aligned with OWASP REST Security Cheat Sheet.
 */

function applySecurityHeaders(req, res, next) {
    // 1. Content-Security-Policy (CSP) - Strictly restrict asset origins and prevent XSS
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
    );

    // 2. Strict-Transport-Security (HSTS) - Force HTTPS for 2 years with preloading
    res.setHeader(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload"
    );

    // 3. X-Content-Type-Options - Prevent MIME-sniffing attacks
    res.setHeader("X-Content-Type-Options", "nosniff");

    // 4. X-Frame-Options - Disallow embedding in iframes (Anti-Clickjacking)
    res.setHeader("X-Frame-Options", "DENY");

    // 5. Referrer-Policy - Protect URL privacy on outbound navigations
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

    // 6. Permissions-Policy - Disable invasive hardware browser capabilities
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");

    // 7. X-Permitted-Cross-Domain-Policies - Block Flash/PDF cross-domain leaks
    res.setHeader("X-Permitted-Cross-Domain-Policies", "none");

    // 8. Cache-Control for sensitive APIs
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    if (next) return next();
}

module.exports = { applySecurityHeaders };
