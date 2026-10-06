import datetime as dt
import json
import math
import sqlite3
import sys
from pathlib import Path
from typing import Any

from omnidim_ui import config
from omnidim_ui.config import (
    DB_PATH,
    DEFAULT_BASE_URL,
    HISTORY_RETENTION_LIMIT,
    MAX_LOG_CHARS,
)
from omnidim_ui.logging_config import logger
from omnidim_ui.security import (
    get_api_key,
    migrate_legacy_enc_v1,
    redact_payload,
    sanitize_url,
)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def compact_json(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=True, separators=(",", ":")) if not isinstance(value, str) else value
    if len(text) > MAX_LOG_CHARS:
        return text[:MAX_LOG_CHARS] + "\n... truncated ..."
    return text


def get_db(db_path=None) -> sqlite3.Connection:
    target = db_path or DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    # Production SQLite Pragmas
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


MIGRATIONS = [
    (
        1,
        "Initial core schema: settings, request_history, saved_payloads",
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS request_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id TEXT,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            url TEXT NOT NULL,
            status INTEGER,
            ok INTEGER NOT NULL,
            duration_ms INTEGER NOT NULL,
            request_json TEXT,
            response_json TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS saved_payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id TEXT NOT NULL,
            name TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            query_json TEXT NOT NULL,
            body_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """,
    ),
    (
        2,
        "History search and pagination performance indexes",
        """
        CREATE INDEX IF NOT EXISTS idx_history_created_at ON request_history (created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_history_endpoint_id ON request_history (endpoint_id);
        CREATE INDEX IF NOT EXISTS idx_history_status ON request_history (status);
        CREATE INDEX IF NOT EXISTS idx_history_method ON request_history (method);
        """,
    ),
]


def apply_migrations(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL,
            description TEXT NOT NULL
        );
        """
    )
    rows = conn.execute("SELECT version FROM schema_version").fetchall()
    applied_versions = {row["version"] for row in rows}

    for version, desc, sql in MIGRATIONS:
        if version not in applied_versions:
            logger.info("Applying database migration v%d: %s", version, desc)
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
                (version, now_iso(), desc),
            )
            conn.commit()


def init_db(db_path=None) -> None:
    with get_db(db_path) as conn:
        apply_migrations(conn)
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            ("base_url", DEFAULT_BASE_URL, now_iso()),
        )
        conn.commit()
        migrate_legacy_enc_v1(db_conn=conn)


def save_setting(key: str, value: str, db_conn=None) -> None:
    if db_conn is not None:
        db_conn.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, now_iso()),
        )
    else:
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (key, value, now_iso()),
            )


def delete_setting(key: str, db_conn=None) -> None:
    if db_conn is not None:
        db_conn.execute("DELETE FROM settings WHERE key = ?", (key,))
    else:
        with get_db() as conn:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))


def read_settings(include_secret: bool = False, db_conn=None) -> dict[str, Any]:
    if db_conn is not None:
        rows = db_conn.execute("SELECT key, value FROM settings").fetchall()
    else:
        with get_db() as conn:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()

    raw = {row["key"]: row["value"] for row in rows}
    api_key, source = get_api_key(db_conn=db_conn)

    if source == "env":
        notice = "API key loaded from OMNIDIM_API_KEY environment variable (highest security; never stored on disk)."
    elif source == "dpapi":
        notice = "API key securely stored via Windows DPAPI (tied to your Windows user logon credentials)."
    elif source == "keyring":
        notice = "API key securely stored in OS Keychain via keyring."
    else:
        notice = "No API key configured. Provide OMNIDIM_API_KEY in environment or save via UI."

    read_only = getattr(config, "READ_ONLY_MODE", False)
    if "omnidim_ui" in sys.modules and getattr(sys.modules["omnidim_ui"], "READ_ONLY_MODE", False):
        read_only = True
    elif "server" in sys.modules and getattr(sys.modules["server"], "READ_ONLY_MODE", False):
        read_only = True

    data = {
        "baseUrl": raw.get("base_url", DEFAULT_BASE_URL),
        "hasApiKey": bool(api_key),
        "apiKeySource": source,
        "apiKeyPreview": f"...{api_key[-4:]}" if api_key else "",
        "securityNotice": notice,
        "retentionLimit": HISTORY_RETENTION_LIMIT,
        "readOnly": read_only,
    }
    if include_secret:
        data["apiKey"] = api_key
    return data


def log_history(
    endpoint_id_value: str,
    method: str,
    path: str,
    url: str,
    status: int,
    ok: bool,
    duration_ms: int,
    request_payload: Any,
    response_payload: Any,
    db_conn=None,
) -> None:
    clean_url = sanitize_url(url)
    redacted_req = redact_payload(request_payload)
    redacted_res = redact_payload(response_payload)

    def _execute(conn: sqlite3.Connection):
        conn.execute(
            """
            INSERT INTO request_history
            (endpoint_id, method, path, url, status, ok, duration_ms, request_json, response_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                endpoint_id_value,
                method,
                path,
                clean_url,
                status,
                1 if ok else 0,
                duration_ms,
                compact_json(redacted_req),
                compact_json(redacted_res),
                now_iso(),
            ),
        )
        # Auto-prune beyond retention limit
        conn.execute(
            """
            DELETE FROM request_history
            WHERE id NOT IN (
                SELECT id FROM request_history ORDER BY id DESC LIMIT ?
            )
            """,
            (HISTORY_RETENTION_LIMIT,),
        )

    if db_conn is not None:
        _execute(db_conn)
    else:
        with get_db() as conn:
            _execute(conn)


def get_history(
    page: int = 1,
    limit: int = 50,
    search: str | None = None,
    status: int | None = None,
    method: str | None = None,
    db_conn=None,
) -> dict[str, Any]:
    page = max(1, int(page))
    limit = max(1, min(100, int(limit)))
    offset = (page - 1) * limit

    where_clauses = []
    params = []

    if search:
        search_term = f"%{search.strip().lower()}%"
        where_clauses.append("(LOWER(path) LIKE ? OR LOWER(url) LIKE ? OR LOWER(endpoint_id) LIKE ?)")
        params.extend([search_term, search_term, search_term])

    if status is not None:
        where_clauses.append("status = ?")
        params.append(int(status))

    if method:
        where_clauses.append("method = ?")
        params.append(method.strip().upper())

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    def _query(conn: sqlite3.Connection):
        count_row = conn.execute(f"SELECT COUNT(*) AS total FROM request_history {where_sql}", params).fetchone()
        total = count_row["total"] if count_row else 0

        query_sql = f"""
            SELECT id, endpoint_id, method, path, url, status, ok, duration_ms,
                   request_json, response_json, created_at
            FROM request_history
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(query_sql, params + [limit, offset]).fetchall()

        items = []
        for r in rows:
            items.append(
                {
                    "id": r["id"],
                    "endpoint_id": r["endpoint_id"],
                    "method": r["method"],
                    "path": r["path"],
                    "url": r["url"],
                    "status": r["status"],
                    "ok": bool(r["ok"]),
                    "duration_ms": r["duration_ms"],
                    "request": r["request_json"],
                    "response": r["response_json"],
                    "created_at": r["created_at"],
                }
            )

        total_pages = math.ceil(total / limit) if total > 0 else 1
        return {
            "items": items,
            "total": total,
            "page": page,
            "limit": limit,
            "totalPages": total_pages,
        }

    if db_conn is not None and hasattr(db_conn, "execute"):
        return _query(db_conn)
    target = db_conn if isinstance(db_conn, (str, Path)) else None
    with get_db(target) as conn:
        return _query(conn)


def clear_history(db_conn=None) -> None:
    if db_conn is not None and hasattr(db_conn, "execute"):
        db_conn.execute("DELETE FROM request_history")
    else:
        target = db_conn if isinstance(db_conn, (str, Path)) else None
        with get_db(target) as conn:
            conn.execute("DELETE FROM request_history")
