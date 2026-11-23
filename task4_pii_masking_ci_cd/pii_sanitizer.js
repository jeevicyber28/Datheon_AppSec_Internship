/**
 * PII Masking & Data Sanitization Utility
 * Zero-Leakage Public Lookup Sanitization
 */

class PIISanitizer {
    /**
     * Masks an email address: e.g. "jeevicyber28@gmail.com" -> "j***8@gmail.com"
     */
    static maskEmail(email) {
        if (!email || typeof email !== "string" || !email.includes("@")) return "masked@domain.com";

        const [user, domain] = email.split("@");
        if (user.length <= 2) {
            return `${user[0]}*@${domain}`;
        }

        const firstChar = user[0];
        const lastChar = user[user.length - 1];
        return `${firstChar}***${lastChar}@${domain}`;
    }

    /**
     * Masks phone number: e.g. "+91-98401-23456" -> "+91-*****-23456"
     */
    static maskPhone(phone) {
        if (!phone || typeof phone !== "string") return "+**-*****-****";
        const clean = phone.trim();
        // Preserve last 4 digits
        if (clean.length < 5) return "****";
        const suffix = clean.slice(-4);
        return `+**-*****-${suffix}`;
    }

    /**
     * Masks candidate name: e.g. "Jeeviraj Ramanathan" -> "J***j R***n"
     */
    static maskName(name) {
        if (!name || typeof name !== "string") return "Anonymous";
        const words = name.trim().split(/\s+/);
        return words
            .map((w) => {
                if (w.length <= 2) return w;
                return `${w[0]}***${w[w.length - 1]}`;
            })
            .join(" ");
    }

    /**
     * Sanitizes full internal database record for safe public credential/certificate lookup
     */
    static sanitizeForPublicVerification(record) {
        if (!record) return null;

        return {
            credentialId: record.applicationId || record.credentialId,
            verificationStatus: "AUTHENTIC_AND_VERIFIED",
            recipientNameMasked: this.maskName(record.candidateName),
            recipientEmailMasked: this.maskEmail(record.email),
            recipientPhoneMasked: this.maskPhone(record.phone),
            institution: record.institution || "Anna University",
            programTrack: record.internshipTrack || "Application Security",
            issueDate: record.issueDate || "2026-11-22",
            credentialHash: record.credentialHash || "SHA256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
            // NOTICE: Internal fields (mentorNotes, internalId, salary, addresses) are strictly omitted.
        };
    }
}

module.exports = { PIISanitizer };
