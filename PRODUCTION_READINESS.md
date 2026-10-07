# Production upgrade status — 7 October 2026

Target: an online application for multiple users, hosted on Vercel.

## Assessment

The initial 35/100 assessment described a local application missing shared-user protections. This upgrade implements those foundations and improves the interface substantially. My current estimate is **about 80/100 for online production readiness**. This is a judgment, not a standardized benchmark. **95/100 is an acceptance target, not an achieved score.** Deployment, real PostgreSQL concurrency and operational recovery have not yet been demonstrated.

## Implemented

- Responsive light/dark interface, searchable action library, accessible editor labels, clear setup/error/loading states, protected-action review, cancellation, draft retention and mobile navigation.
- Named Django accounts, database sessions, CSRF protection, secure production cookies, password validation and shared sign-in throttling, including the administration login.
- Workspace memberships with viewer/operator/admin permissions checked on every request. Workspace headers prevent cross-tab changes from silently sending an action to the wrong workspace. Settings/history are workspace scoped; saved requests are additionally private to their owner.
- Encrypted workspace credentials with rotation support. Hosted requests never fall back to the machine's global/local credential. Only the approved OmniDimension HTTPS destination can receive credentials; redirects are refused.
- Durable confirmations bound to user, workspace, request and current credential. Nonexecuting preflight detects protected actions, including body-driven activation/resume actions.
- PostgreSQL transactions and row locks protect mutation reservation, duplicate keys and workspace request budgets. Completed duplicate keys replay a stored result; pending/unknown actions cannot silently repeat. Browser retries retain the key, including after refresh.
- Bounded request/response sizes, strict JSON/method/path validation, read-only mode, no automatic mutation retries, and explicit unknown outcomes after network failures or incomplete responses.
- Durable operations and security events, administrator-change auditing, metadata-only request history, secret redaction, retention maintenance and account/credential provisioning commands.
- Explicit Vercel entrypoint, pinned runtime dependencies, environment template, CI with PostgreSQL concurrency checks, deployment checks, health endpoints, backup/restore guidance and an alternative private container gateway.

## Verified locally

| Check | Result |
|---|---|
| Legacy/proxy regression suite | 116 passed; 89.37% branch/statement coverage; 85% gate retained |
| Hosted identity/API suite | 44 passed; 2 PostgreSQL concurrency tests skipped on SQLite |
| Hosted code coverage | 91% branch/statement coverage; excludes tests, generated migrations, empty modules and WSGI bootstrap |
| Frontend browser checks | 18 passed with isolated API fixtures |
| Hosted browser integration | 8 passed using real Django login, sessions, CSRF and database duplicate replay; upstream mocked |
| Desktop/mobile screenshots | Visually reviewed; mobile overflow check passed |
| Production configuration defaults | Django deployment checks passed with synthetic secrets and PostgreSQL configuration |
| Ruff / legacy strict type checks | Passed |
| Catalog drift | All 72 specification operations registered |
| Dependency audit | No known vulnerabilities in resolved hosted packages on this Windows environment; Linux CI audits the deployment dependency set |
| Migration consistency | No pending model changes |

Automatic checks never placed real calls or used the user's stored API credential. Test databases and browser accounts were isolated from local application data. Added CI jobs are prepared but have not run remotely in this session.

## Remaining gates for 95

1. Connect the actual Vercel project, managed PostgreSQL database and intended hostname. Deploy a separate preview environment with separate credentials/data.
2. Run both PostgreSQL concurrency tests and all CI jobs. Validate provider pooling, connection limits, function duration, forward-header behavior and static assets on Vercel.
3. Verify real HTTPS, sign-in, tenant isolation, access revocation, secure cookies and a safe upstream read on staging. Exercise paid/destructive behavior only with deliberate authorization on a staging account.
4. Load-test expected user counts and establish latency/error targets, alerts, operational ownership and cost limits.
5. Restore an encrypted database backup into an isolated instance; verify credential recovery and record recovery time. Confirm secrets and backups are recoverable if an operator loses access.
6. Complete independent security review. Add MFA/SSO and a tested self-service account-recovery flow if required by the deployment's sensitivity and scale. Current recovery is administrator-assisted.
7. Ship audit events to separately controlled storage if tamper-resistant compliance evidence is required. Application-level append-only protection does not stop a database administrator.

The local environment has no running Docker daemon or PostgreSQL service. The user requested a new Vercel project; the creation page was opened, but account access is pending. Automatic approval review rejected the GitHub authentication/repository flow because GitHub access was not yet authorized. The production database and final domain are still unavailable, so no deployed URL, production load result or restoration result is claimed.

See [VERCEL.md](VERCEL.md) for the selected hosting setup and [DEPLOYMENT.md](DEPLOYMENT.md) for launch/recovery procedures.
