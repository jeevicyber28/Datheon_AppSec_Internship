/**
 * Sliding Window Counter Rate Limiter
 * Mitigates automated brute-force attacks and enumeration fuzzing.
 */

class SlidingWindowRateLimiter {
    /**
     * @param {number} windowSeconds - Duration of window in seconds
     * @param {number} maxRequests - Max requests permitted per window
     */
    constructor(windowSeconds = 60, maxRequests = 10) {
        this.windowMs = windowSeconds * 1000;
        this.maxRequests = maxRequests;
        this.hits = new Map(); // Key: IP or Identifier, Value: Array of timestamps
    }

    /**
     * Checks if request should be throttled
     * @returns {Object} { allowed: boolean, currentCount, remaining, resetTime }
     */
    check(key) {
        const now = Date.now();
        const windowStart = now - this.windowMs;

        let timestamps = this.hits.get(key) || [];
        // Evict expired entries older than the sliding window
        timestamps = timestamps.filter((t) => t > windowStart);

        if (timestamps.length >= this.maxRequests) {
            const oldestInWindow = timestamps[0];
            const resetSeconds = Math.ceil((oldestInWindow + this.windowMs - now) / 1000);

            this.hits.set(key, timestamps);
            return {
                allowed: false,
                currentCount: timestamps.length,
                remaining: 0,
                resetSeconds: Math.max(1, resetSeconds)
            };
        }

        timestamps.push(now);
        this.hits.set(key, timestamps);

        return {
            allowed: true,
            currentCount: timestamps.length,
            remaining: this.maxRequests - timestamps.length,
            resetSeconds: Math.ceil(this.windowSeconds || 60)
        };
    }

    /**
     * Express Middleware Factory
     */
    middleware() {
        return (req, res, next) => {
            const clientIp = req.ip || req.headers["x-forwarded-for"] || req.socket.remoteAddress || "127.0.0.1";
            const result = this.check(clientIp);

            // Standard RFC Rate Limit Headers
            res.setHeader("X-RateLimit-Limit", this.maxRequests);
            res.setHeader("X-RateLimit-Remaining", result.remaining);
            res.setHeader("X-RateLimit-Reset", result.resetSeconds);

            if (!result.allowed) {
                res.setHeader("Retry-After", result.resetSeconds);
                return res.status(429).json({
                    success: false,
                    error: "Too Many Requests",
                    code: "ERR_RATE_LIMIT_EXCEEDED",
                    message: `Rate limit threshold exceeded. Try again in ${result.resetSeconds} seconds.`,
                    retryAfterSeconds: result.resetSeconds
                });
            }

            return next();
        };
    }
}

module.exports = { SlidingWindowRateLimiter };
