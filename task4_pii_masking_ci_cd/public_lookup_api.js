/**
 * Public Verification Lookup API
 * Demonstrates safe public lookup with zero unmasked PII leakage and strict security headers.
 */

const { PIISanitizer } = require("./pii_sanitizer");
const { applySecurityHeaders } = require("./security_headers_middleware");

function setupPublicLookupRoute(app, mockDatabase) {
    /**
     * @route GET /api/v1/public/verify/:credentialId
     * @access Public (Safe for unauthenticated verification, e.g. QR code scanning)
     */
    app.get("/api/v1/public/verify/:credentialId", applySecurityHeaders, (req, res) => {
        const { credentialId } = req.params;

        const record = mockDatabase.find(
            (item) => item.applicationId.toUpperCase() === credentialId.toUpperCase()
        );

        if (!record) {
            return res.status(404).json({
                success: false,
                verificationStatus: "NOT_FOUND",
                message: "Credential or Application ID could not be located in registry."
            });
        }

        // Apply dynamic PII masking and sanitize internal metadata
        const publicPayload = PIISanitizer.sanitizeForPublicVerification(record);

        return res.status(200).json({
            success: true,
            data: publicPayload
        });
    });
}

module.exports = { setupPublicLookupRoute };
