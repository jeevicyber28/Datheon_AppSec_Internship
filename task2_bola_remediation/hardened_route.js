/**
 * HARDENED ROUTE HANDLER (Post-Remediation)
 * Architectural Defense: Zero-Trust Dual-Key Object Authorization
 * Adheres to OWASP API1:2023 Guidelines
 */

const { requireAuth } = require("./auth_middleware");

function setupHardenedRoute(app, mockDatabase) {
    /**
     * @route GET /api/v1/hardened/applications/:appId
     * @access Protected (Requires Authenticated Session + Ownership Binding)
     */
    app.get("/api/v1/hardened/applications/:appId", requireAuth, async (req, res) => {
        const { appId } = req.params;
        const callerEmail = req.user.email;
        const callerRole = req.user.role;

        // DEFENSIVE STEP 1: Query database enforcing Dual-Filter Constraint.
        // The record MUST match both the requested ID AND the caller's verified email.
        const candidateRecord = mockDatabase.find((item) => {
            const idMatches = item.applicationId.toUpperCase() === appId.toUpperCase();
            if (!idMatches) return false;

            // Administrative bypass with strict role check
            if (callerRole === "ADMIN") return true;

            // Strict Tenant / Owner verification
            return item.email.toLowerCase() === callerEmail;
        });

        // DEFENSIVE STEP 2: Return generic 404 / 403 on authorization failure
        // Prevents resource enumeration by revealing whether an unauthorized record exists
        if (!candidateRecord) {
            return res.status(404).json({
                success: false,
                error: "Resource not found",
                code: "ERR_NOT_FOUND",
                message: "The requested application does not exist or you do not have permission to access it."
            });
        }

        // DEFENSIVE STEP 3: Return sanitized, scoped data payload
        return res.status(200).json({
            success: true,
            data: {
                applicationId: candidateRecord.applicationId,
                candidateName: candidateRecord.candidateName,
                email: candidateRecord.email,
                institution: candidateRecord.institution,
                internshipTrack: candidateRecord.internshipTrack,
                offerStatus: candidateRecord.offerStatus
            }
        });
    });
}

module.exports = { setupHardenedRoute };
