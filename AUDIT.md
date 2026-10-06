# Security & Architectural Audit: OmniDimension Control Center

**Date:** October 6, 2026  
**Repository:** `om-chatgpt` (`omnidim-control-center`)  
**Scope:** Complete codebase audit covering `server.py`, `static/`, `data/`, `tests/`, `pyproject.toml`, `.gitignore`, and git commit history.

---

## 1. Executive Summary

OmniDimension Control Center is a local browser workspace and HTTP backend proxy for the OmniDimension Voice Agent API. It is designed to run locally with zero third-party Python runtime dependencies (Python standard library only).

Prior work in the repository introduced preliminary security controls (CSRF validation, Host header checks, recursive redaction, and an endpoint allowlist with a 428 Precondition Required confirmation flow for dangerous actions). However, critical production-grade security, architectural modularity, testing depth, UI hygiene, and project governance gaps remain.

---

## 2. File-by-File Audit

### `server.py` (1,127 lines)
* **Role:** Monolithic script containing configuration, SQLite database operations, catalog definitions, static file server, local security middleware, and HTTP reverse proxy.
* **Findings:**
  1. **API Key Storage:** `get_api_key()` checks `OMNIDIM_API_KEY` (env), OS keyring, and the SQLite `settings` table. However, keys saved to SQLite are stored in plaintext. It lacks local encryption with a key derived from a `0600` secret file.
  2. **Local Authentication:** Uses a random `CSRF_TOKEN` and checks `X-CSRF-Token` only on mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`). It does not require a local authentication token (`X-Local-Token`) across *all* `/api/*` requests (including `GET`).
  3. **Read-Only Mode:** Missing a `--read-only` flag to enforce read-only operation and reject all mutating API proxy requests.
  4. **Danger Action Enforcement:** Backend currently expects `confirm == endpoint["summary"]`. It needs unified support for `"confirmed": true` and single-use confirmation tokens.
  5. **CORS & Preflight:** `do_OPTIONS` returns HTTP 204. Per security requirements, permissive preflight handling should be removed since cross-origin requests are forbidden.
  6. **Request Body Cap:** `read_json()` reads `Content-Length` bytes without an upper bound limit, presenting a memory exhaustion / DoS risk.
  7. **Redaction Keys:** `REDACT_KEYS` covers `password`, `token`, `secret`, `api_key`, `auth_token`, `sip_password`, `account_sid`, `authorization`. Needs explicit inclusion of `api_token`.
  8. **Database & Concurrency:** Uses `sqlite3.connect()` per request without WAL mode (`PRAGMA journal_mode=WAL;`), and lacks a formal `schema_version` migration table.
  9. **Error Handling & Logging:** Relies on `print()` statements and broad `except Exception:` blocks rather than the standard library `logging` module with log levels and `--verbose` support.
  10. **Monolith:** High coupling between HTTP routing, endpoint schema catalogs, database persistence, and proxying.

### `static/index.html` (173 lines)
* **Role:** Single-page application shell.
* **Findings:**
  1. Clean semantic structure with aside sidebar, topbar, and main workspace.
  2. Missing persistent "Read-Only Mode" indicator badge.
  3. Missing theme toggle button for light/dark mode.
  4. Requires accessibility enhancements (aria-live, improved focus rings, explicit labels).

### `static/app.js` (756 lines)
* **Role:** Vanilla JavaScript front-end application logic.
* **Findings:**
  1. Dependency-free architecture adhering to vanilla standards.
  2. Uses `escapeHtml()` across DOM interpolations, but certain templates should be further hardened.
  3. Missing loading spinners / progress state during API calls to give clear feedback.
  4. Lacks local token bootstrap support (receiving token via URL fragment `#token=...` or cookie and attaching `X-Local-Token`).
  5. Needs copy-as-cURL, JSON linting/validation feedback in runner textareas, and light/dark theme persistence.

### `static/styles.css` (871 lines)
* **Role:** Styling for the UI.
* **Findings:**
  1. Well-structured CSS variables (`--bg`, `--surface`, `--ink`, `--accent`).
  2. Lacks complete dark theme variable palette (`[data-theme="dark"]`).
  3. Needs focus indicator improvements for keyboard accessibility.

### `data/` and Git History Audit
* **Findings:**
  1. Checked full git commit history (`git log --all --full-history -- "*.sqlite3" "*.db"`).
  2. **Result: No SQLite database files (`*.sqlite3` or `*.db`) have EVER been committed to the repository history.**
  3. Only `data/.gitkeep` was committed in commit `61584a6`.
  4. `.gitignore` currently ignores `data/*.sqlite3*`, `*.sqlite3*`, `.env*`, `*.key`, `*.pem`, `.pytest_cache/`, `.ruff_cache/`.

### `tests/` (3 test suites, 20 tests)
* **Role:** Pytest test suite covering phases 1-3.
* **Findings:**
  1. Tests currently pass with 20/20 green tests.
  2. Tests rely on `server.py` being imported directly; requires `pythonpath = ["."]` in `pyproject.toml`.
  3. Lacks comprehensive proxy mocking (fake OmniDimension upstream HTTP server) to test retry logic, upstream network errors, and live proxy simulation.
  4. Test coverage needs expansion to reach >= 85%.

### Project Hygiene & Governance
* **Findings:**
  1. Missing `LICENSE` (MIT).
  2. Minimal `README.md` without screenshots, complete CLI reference, security model, and troubleshooting.
  3. Missing `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `REPO_META.md`, `.editorconfig`.
  4. Missing GitHub Actions CI workflow (`.github/workflows/ci.yml`).

---

## 3. History Cleanup Status
- **Database Committed Check:** **CLEAN.** No database files exist in Git history. No `git filter-repo` or BFG history rewriting is required.
