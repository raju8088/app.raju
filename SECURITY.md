# Security Policy & Threat Model

## Reporting Security Issues
If you discover a security vulnerability, please do **NOT** open a public issue. Report it privately to the maintainers or via GitHub Security Advisories.

---

## Threat Model & Security Architecture

OmniDimension Control Center is designed as a local web service and reverse proxy running on the operator's machine. It bridges the local browser UI to the OmniDimension Cloud Voice API without exposing sensitive credentials or enabling unauthorized remote access.

### 1. API Key Protection & Precedence
The OmniDimension API key is sensitive because it permits billable telephone calls, AI agent mutations, and account credit transfers. It is handled with strict storage hierarchy:

1. **`OMNIDIM_API_KEY` Environment Variable (Highest Precedence)**
   - **Protection:** Never written to disk or database. Retained strictly in runtime process memory.
   - **Recommendation:** Best practice for automated environments, developers, and CI/CD.

2. **Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`)**
   - **Protection:** On Windows, API keys saved through the UI are encrypted via the Windows Data Protection API (DPAPI). Keys are tied to the local user's Windows login credentials and hardware-backed keys.
   - **Threat Mitigated:** Other OS user accounts, non-admin processes running under different user contexts, and offline disk dumps cannot decrypt the stored key.

3. **OS Keyring (`keyring` package)**
   - **Protection:** On macOS (Keychain) and Linux (Secret Service / FreeDesktop Secret API), keys are delegated to the OS credential manager when `keyring` is installed.

4. **Refusal to Store in Plaintext**
   - **Protection:** If no OS-backed credential store (Windows DPAPI or OS Keyring) is available, the server explicitly **refuses** to store the API key on disk and returns an instructive error directing the operator to use the `OMNIDIM_API_KEY` environment variable.
   - **Threat Mitigated:** Prevents unencrypted credentials from landing in SQLite files or accidental backups.

---

### 2. Local Server Authentication (`X-Local-Token`)
- **Token Generation:** A cryptographically secure, random 256-bit token (`secrets.token_urlsafe(32)`) is generated in memory each time the server starts.
- **Enforcement:** **All** requests to `/api/*` require authentication via:
  - Header: `X-Local-Token: <token>`
  - Cookie: `local_token=<token>` (`HttpOnly`, `SameSite=Strict`, `Path=/`)
- **Threat Mitigated:** Prevents local unauthenticated processes, untrusted scripts on other ports, or other users on shared multi-user machines from issuing commands to the server.

---

### 3. DNS Rebinding & Cross-Origin Protections
- **Host Header Validation:** The server strictly checks the HTTP `Host` header against `localhost` and `127.0.0.1` (with optional port). External hostnames, DNS rebinding domains (e.g., `127.0.0.1.attacker.com`), and missing headers are blocked with `403 Forbidden`.
- **Origin Validation & CSRF Protection:** Mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) require an allowed local `Origin` header and a matching `X-CSRF-Token` header.
- **No Permissive CORS:** Preflight `OPTIONS` requests receive `405 Method Not Allowed` with no `Access-Control-*` headers.

---

### 4. Server-Side Dangerous Action Enforcement
- Endpoints flagged as `danger` (such as placing live phone calls, releasing phone numbers, starting bulk campaigns, or transferring credits) cannot be bypassed with client-side flags.
- **Single-Use 60-Second Token:** The server requires a cryptographic, single-use confirmation token tied to the exact HTTP method, path, query parameters, and SHA-256 payload hash.
- **Tamper Resistance:** Modifying any request parameter or payload after token issuance invalidates the token. Once used, the token is immediately consumed and cannot be replayed.
- **Read-Only Mode:** The `--read-only` flag unconditionally rejects all mutating HTTP requests (`POST`, `PUT`, `PATCH`, `DELETE`) with `403 Forbidden`.

---

### 5. Secret Redaction in Audit History
- Request and response history stored in SQLite is automatically scrubbed.
- Fields matching `password`, `token`, `secret`, `api_key`, `api_token`, `auth_token`, `sip_password`, `account_sid`, and `authorization` are masked as `[REDACTED]`.
- Large Base64 file payloads are truncated.
- URL query strings containing credentials are sanitized before persistence.
- Local history is capped to a configurable retention limit (default: 500 records) and can be completely cleared via the UI.
