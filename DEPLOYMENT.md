# Online deployment

Use the Django entrypoint for multiple users. The original `server.py` is a loopback-only personal tool. Local users, credentials and history are deliberately not imported into hosted workspaces.

## First deployment

1. Select a Linux host, point your domain to it, and install Docker with Compose. Only ports 80/443 should be public. Use a managed PostgreSQL service for stronger availability if required; require database TLS outside the private Compose network.
2. Copy `.env.example` to `.env`, restrict its permissions, and replace every placeholder. Generate `DJANGO_SECRET_KEY` with `secrets.token_urlsafe(64)` and `OMNIDIM_ENCRYPTION_KEY` with `cryptography.fernet.Fernet.generate_key()`. URL-encode the database password in `DATABASE_URL`. Keep both application secrets in a secret manager and backed up separately from the database. Never commit them.
3. Run `docker compose build`, then `docker compose up -d db` and `docker compose run --rm app python manage.py migrate --noinput`. Migrations run once before starting replicas.
4. Run `docker compose run --rm app python manage.py createsuperuser`. Provision named accounts through `/admin/`. Create the first workspace with `docker compose run --rm app python manage.py create_workspace --name "Your team" --slug your-team --owner YOUR_USERNAME`. Assign viewer/operator/admin memberships through the administration screen. Give staff access only to platform administrators.
5. Run `docker compose up -d`. Caddy obtains HTTPS certificates. The app port and database port are never published. `TRUST_PROXY=1` is safe only with this private gateway, which overwrites forwarded headers.
6. Sign in at your HTTPS domain, select the workspace, and add its API key in Connection settings. The key is encrypted in PostgreSQL. A viewer can read; an operator can run actions and save their own requests; a workspace administrator can change settings and clear shared history. Reseller actions require an administrator.

## Release acceptance

Do not score this deployment as 95/100 before recording evidence of these checks:

- Run all CI checks and build the container. `manage.py check --deploy --fail-level WARNING` must pass with real production configuration.
- Run hosted tests against PostgreSQL, including concurrent requests on separate connections. SQLite tests do not establish production locking behavior.
- Sign in as two users in two workspaces. Verify data and credentials remain isolated, revoked access takes effect, CSRF failures are rejected, and anonymous access redirects to login.
- Verify HTTPS redirect, certificate renewal, secure cookies, forwarded header handling and blocked public database/app ports.
- Exercise a safe upstream read with a real workspace credential. Test one explicitly approved mutation, confirmation and duplicate replay on a staging account. Do not use paid calls for automatic tests.
- Load-test expected concurrent users; define latency/error targets and verify memory, connection counts and upstream quotas.
- Complete and time a backup restoration into a separate database; establish recovery targets, alert delivery, log retention and an incident owner.
- Obtain an independent security review, including administration access and account recovery. Add MFA/SSO before handling sensitive customer data at scale.

## Backups and recovery

Take daily encrypted, off-host PostgreSQL backups with `pg_dump --format=custom`. Back up application encryption keys and Django secret separately. Monitor job success and keep a documented retention policy. Restore a backup into a new empty database with `pg_restore --no-owner --dbname=RESTORE_DATABASE_URL backup.dump`, run migrations, and compare workspace/membership/history counts. Verify a restored workspace credential decrypts and perform a safe upstream read. Record recovery time. Never test a restoration against the active production database.

Before each release, back up the database, test migrations in staging, retain the prior container image and confirm readiness. Roll back the image only if the schema remains compatible; otherwise restore into a new database and switch deliberately. Never automatically reverse migrations that discard data.

## Operations and action outcomes

Monitor `/health/live`, `/health/ready`, request error/latency counts, database storage, backups and certificate expiry. Readiness probes do not make external paid calls. Logs carry request IDs without request bodies or credentials. History stores request metadata, not transcripts or upstream response bodies. Saved requests are private to their owner and sensitive fields are redacted; re-enter omitted credentials before reuse.

Mutation requests require an idempotency key. Completed retries return the retained result. Pending/unknown outcomes block retry with the same key, even after restart. A timeout cannot establish whether upstream accepted the action: inspect the upstream dashboard and the operation ID before making a new action. A new key creates a new action; do not use it to bypass an uncertain result. There is no automatic mutation retry or automatic outcome reconciliation.

Run `python manage.py portal_maintenance` daily. It expires confirmations, rate windows and sessions, marks stale pending operations unknown, and removes old metadata. Operation identity records remain as duplicate-prevention tombstones; old result bodies are cleared. Audit records are append-only through the application but a database administrator can modify them; ship audit records to separately controlled storage for tamper resistance.

Rotate workspace encryption keys with `rotate_workspace_keys --help`: retain the previous key as instructed until all records are re-encrypted and backups are covered. Losing the key makes saved upstream credentials unrecoverable. Revoke departed users' memberships and sessions immediately. Password recovery is administrator-assisted; public registration/email reset is not enabled.

## Current verification limits

The supplied Windows environment does not have a running Docker daemon or a production PostgreSQL instance. Container build, production concurrency, live HTTPS, disaster recovery, monitoring and load targets must be verified on staging before launch. Passing local tests alone does not establish 95/100 production readiness.
