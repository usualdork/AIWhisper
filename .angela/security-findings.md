# Angela Security Scan Report

**11 findings** identified in `usualdork/AIWhisper`

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 8 |

## Findings

### 1. [CRITICAL] No Authentication or Authorization on Any Application Route or API
**CWE:** CWE-306
**File:** `src/app/(app)/layout.tsx`

The entire application has NO authentication mechanism. The "user" is hardcoded in the layout, and the only "login" is scanning a WhatsApp QR code to link a device — this does NOT authenticate the dashboard user. Every page (/dashboard, /agents, /inbox, /knowledge-base, /settings) and every API route (/api/agents, /api/whatsapp/send, /api/inbox/*, /api/knowledge, etc.) is publicly accessible to anyone who can reach the server. There is no middleware.ts enforcing access control. Anyone who finds 

**Remediation:** Implement a real authentication layer (e.g., NextAuth/Auth.js or session cookies) and add a Next.js middleware.ts that protects all `(app)` pages and `/api/*` routes, requiring a valid authenticated session. Enforce authorization on each API handler.

---

### 2. [CRITICAL] IDOR — Any User Can Read Arbitrary Conversation Messages
**CWE:** CWE-639
**File:** `src/app/api/inbox/messages/[chatId]/route.ts`

The endpoint returns all messages for any `chatId` with no ownership or authentication check. Because there is no auth and no ownership model, any caller can enumerate chatIds (e.g., phone-number@s.whatsapp.net) and read the full private message history of every conversation. This is a textbook Broken Object Level Authorization (BOLA/IDOR) issue amplified by the missing global auth.

**Remediation:** Require authentication and verify the authenticated user owns/has access to the conversation before returning messages.

---

### 3. [CRITICAL] Unauthenticated WhatsApp Message Sending Endpoint
**CWE:** CWE-862
**File:** `src/app/api/whatsapp/send/route.ts`

The /api/whatsapp/send endpoint accepts a `to` and `text` and sends a WhatsApp message via the linked account with no authentication, no rate limiting, and no validation of the recipient. Combined with the lack of global auth, any external actor can use the victim's connected WhatsApp number to send arbitrary messages (spam, phishing, scams) to any number.

**Remediation:** Require authentication, add rate limiting, validate the `to` JID format, and restrict to allowed recipients/conversations the user owns.

---

### 4. [HIGH] Missing Security Headers and Content-Security-Policy
**CWE:** CWE-693
**File:** `next.config.ts`

The Next.js config sets no security headers. There is no Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, or Strict-Transport-Security. This leaves the app vulnerable to clickjacking, MIME sniffing, and makes XSS exploitation easier (no CSP mitigation).

**Remediation:** Add a `headers()` function returning security headers including a restrictive CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy, and HSTS.

---

### 5. [HIGH] Build-Time Type and Lint Errors Suppressed (Insecure Build Configuration)
**CWE:** CWE-1188
**File:** `next.config.ts`

`typescript.ignoreBuildErrors` and `eslint.ignoreDuringBuilds` are both set to true. This disables type safety and linting in production builds, allowing type errors and security-relevant lint findings (e.g., dangerous patterns) to ship to production. Combined with the heavy use of `as any` casts in API routes, this masks bugs that can become security issues.

**Remediation:** Set both to false and fix the underlying errors; run typecheck and lint in CI as gating steps.

---

### 6. [HIGH] No Authorization/Ownership Checks on Agent CRUD Endpoints
**CWE:** CWE-862
**File:** `src/app/api/agents/[id]/route.ts`

GET/PATCH/DELETE for agents accept any `id` with no authentication or ownership check. Any caller can read, modify, or delete any agent. Because agents store plaintext API keys and control auto-responses to WhatsApp, this enables key theft and hijacking of automated replies. The "Admin" user attribution in logs is hardcoded and meaningless.

**Remediation:** Require authentication and verify the caller owns the agent; never return secrets.

---

### 7. [HIGH] Unauthenticated File Upload with No Size Limit, Content Scanning, or Auth (DoS / Stored Data Risk)
**CWE:** CWE-434
**File:** `src/app/api/knowledge/parse/route.ts`

The knowledge upload endpoint is unauthenticated and accepts PDF/DOCX/TXT files with no size limit and no anti-automation control. Parsing happens server-side (pdfjs/mammoth) on arbitrary attacker-supplied files. There is no upper bound on file size, enabling memory/CPU exhaustion (DoS), and uploaded content is later injected into AI prompts (prompt injection vector). The extracted content is also rendered later; combined with stored data flows it broadens attack surface.

**Remediation:** Require authentication, enforce a maximum file size, validate MIME type (not just extension), run parsing with timeouts/limits, and treat extracted content as untrusted when used in prompts.

---

### 8. [HIGH] Stored XSS via Unsanitized Knowledge File Content / Message Text
**CWE:** CWE-79
**File:** `src/components/knowledge-base-manager.tsx`

Extracted document content and message text are rendered in the UI. While React escapes text by default, the application places untrusted document content (from arbitrary uploads) directly into the DOM and AI prompts. The chart component uses `dangerouslySetInnerHTML` (chart.tsx ChartStyle) with config-derived values. More critically, conversation `name`/`text` and file content originate from external senders/files and flow into many components without sanitization; any future use of dangerously

**Remediation:** Always encodeURIComponent values placed into URLs, sanitize/escape untrusted content, avoid dangerouslySetInnerHTML with untrusted data, and add a strict Content-Security-Policy.

---

### 9. [HIGH] API Keys and Secrets Transmitted/Logged Insecurely (Sensitive Data in Logs)
**CWE:** CWE-532
**File:** `src/lib/ai.ts`

The AI module reads API keys from agent settings or environment and logs extensive request/response payloads to the console. While it logs "API key available" (boolean) here, it logs full request bodies and responses for OpenAI/Gemini/Anthropic which can include knowledge-base content and user PII. Additionally, the Gemini key is placed directly in the URL query string (`?key=...`), which is commonly captured in proxy/server logs.

**Remediation:** Remove verbose payload logging in production, never put API keys in URLs (use headers where supported), and scrub PII before logging.

---

### 10. [HIGH] Server-Side Request Forgery / Untrusted External Calls via User-Controlled API Endpoints and link-preview
**CWE:** CWE-918
**File:** `src/lib/ai.ts`

The AI module makes outbound HTTP requests using user-controlled provider settings. While provider URLs are fixed, the `apiKey` is user-supplied and the system trusts agent-configured data. More broadly, `link-preview-js` is a dependency (used by Baileys/message processing) which fetches arbitrary URLs from incoming messages — a classic SSRF vector if previews are generated for attacker-supplied links, potentially reaching internal services or cloud metadata endpoints. There is no URL allow-list

**Remediation:** Disable automatic link previews for inbound messages or enforce an SSRF guard (resolve DNS, block private/loopback/link-local ranges, allow-list schemes/hosts). Pin and review link-preview-js usage.

---

### 11. [HIGH] Plaintext Storage of Third-Party AI API Keys in File-Based DB
**CWE:** CWE-312
**File:** `src/lib/db.ts`

AI provider API keys (OpenAI, Gemini, Anthropic) entered in the Agent Designer are stored as plaintext in `src/data/agents.json` via addAgent/updateAgent. These keys grant access to paid AI services and are returned verbatim by the unauthenticated GET /api/agents/[id] endpoint. There is no encryption at rest and no masking on read.

**Remediation:** Encrypt secrets at rest with a server-side key (e.g., AES-GCM using a KMS/env-derived key), never return the apiKey in API responses (mask it), and store in a secrets manager rather than a JSON file.

---
