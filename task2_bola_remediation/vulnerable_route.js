/**
 * VULNERABLE ROUTE HANDLER (Pre-Remediation)
 * Architectural Flaw: Insecure Direct Object Reference (IDOR / BOLA)
 * CWE-639 / OWASP API1:2023
 */

function setupVulnerableRoute(app, mockDatabase) {
    /**
     * @route GET /api/v1/vulnerable/applications/:appId
     * @desc Blind single-parameter database lookup without authorization verification.
     */
    app.get("/api/v1/vulnerable/applications/:appId", async (req, res) => {
        const { appId } = req.params;

        // FLAW: Blind lookup against persistence layer using attacker-controlled key.
        // No checks on WHO is making the request.
        const candidateRecord = mockDatabase.find(
            (item) => item.applicationId.toUpperCase() === appId.toUpperCase()
        );

        if (!candidateRecord) {
            return res.status(404).json({
                success: false,
                error: "Application record not found"
            });
        }

        // FLAW: Complete PII leakage returned to any unauthenticated caller.
        return res.status(200).json({
            success: true,
            data: candidateRecord
        });
    });
}

module.exports = { setupVulnerableRoute };
