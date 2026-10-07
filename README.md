# OmniDimension Control Center

A browser console for the OmniDimension API, with an authenticated hosted mode for multiple users and a separate loopback-only local mode.

## Online application

For the requested Vercel deployment, follow [VERCEL.md](VERCEL.md). The hosted application adds named accounts, workspace isolation, viewer/operator/admin roles, encrypted workspace credentials, shared database sessions, single-use action confirmations, durable duplicate protection and workspace request budgets. Production requires PostgreSQL and explicit HTTPS configuration.

Run `python manage.py test portal_core omnidim_portal --settings=omnidim_portal.test_settings` for isolated hosted checks. Use `TEST_DATABASE_URL` against a disposable PostgreSQL database to include concurrent duplicate/budget checks. Run `python tests/check_production.py` to check production defaults with synthetic secrets.

The operational checklist, backups, recovery and alternative container setup are in [DEPLOYMENT.md](DEPLOYMENT.md). Do not publish the original local server for shared access. Deployment evidence and remaining launch gates are recorded in [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md).

## Run

```powershell
py -3 server.py --port 8787
```

Then open:

```text
http://127.0.0.1:8787
```

## What it includes

- A private backend proxy for OmniDimension API calls.
- A SQLite database at `data/omnidim_ui.sqlite3`.
- Local API key storage, request history, and saved payloads.
- Endpoint screens in this sequence: Sessions, Agents, Calls, Bulk Calls, Knowledge Base, Phone Numbers, Providers, Simulation, Reseller/Admin.
- Protected confirmation on actions that can place calls, create cost, delete data, change credits, or alter live campaigns.

## Notes

- The browser never receives the API key. The backend adds it to outgoing OmniDimension requests.
- Base URL defaults to `https://omnidim.io/api/v1`.
- PDF knowledge-base uploads are handled by the UI helper, which converts the selected PDF into the Base64 body expected by the API.

## Workspace interface

- Light and dark appearances, with your preference remembered in the browser.
- Collapsible connection settings, searchable actions, and read/write/protected filters.
- Per-action drafts and responses retained while navigating within the page. Reloading the page resets unsaved drafts.
- Inline JSON validation and formatting, request progress, and protected-action review with keyboard cancellation.
- Clear setup, read-only, loading, empty, and error states. Failed history refreshes preserve the records already displayed.
- Responsive navigation and request forms, accessible editor labels, and reduced-motion support.

## Browser smoke checks

With Node.js, the `playwright` package, and Google Chrome available:

```powershell
node tests/ui_smoke.cjs
```

The test defaults to `http://127.0.0.1:8787`. Set `UI_BASE_URL` for another local port and `UI_BROWSER_CHANNEL` for another installed Chromium browser channel. `UI_OUTPUT_DIR` selects the screenshot/results folder; the default is `omnidim-ui-checks` in the system temporary directory.

The browser checks serve frontend assets and intercept APIs with fixtures. They cover drafts, validation, repeat clicks, protected confirmation, uncertain retry, account roles, workspace switches, expiry, appearance and mobile layout without calling OmniDimension. They do not require a running server.

`node tests/hosted_browser.cjs` also starts a disposable Django server, verifies real login/CSRF/database sessions and durable duplicate replay, and captures desktop/mobile screenshots. Set `HOSTED_PYTHON` to the Python executable containing `requirements-hosted.txt` dependencies; by default it uses `.venv-hosted/Scripts/python.exe` on Windows. Its upstream responses are always synthetic.
