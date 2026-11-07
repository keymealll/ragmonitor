"""SQLite storage for traces, alerts, documents, policies, scans and connected apps."""
import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS traces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    session TEXT,
    source TEXT NOT NULL DEFAULT 'live',
    question TEXT NOT NULL,
    answer TEXT,
    model TEXT,
    latency_ms REAL,
    retrieved_json TEXT,
    spans_json TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    trace_id INTEGER,
    source TEXT NOT NULL DEFAULT 'live',
    severity TEXT NOT NULL,
    owasp TEXT,
    detector TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    evidence TEXT,
    target TEXT,
    doc TEXT,
    chunk_id TEXT,
    status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS documents (
    name TEXT PRIMARY KEY,
    title TEXT,
    classification TEXT,
    status TEXT NOT NULL,
    added_ts REAL,
    scanned_ts REAL,
    content TEXT NOT NULL,
    findings_json TEXT
);
CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    created_ts REAL NOT NULL,
    last_used_ts REAL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    status TEXT NOT NULL,
    summary_json TEXT,
    results_json TEXT,
    log TEXT
);
"""


@contextmanager
def db():
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init(reset: bool = False):
    if reset and config.DB_PATH.exists():
        config.DB_PATH.unlink()
    with db() as conn:
        conn.executescript(SCHEMA)
        # Databases made before connected apps existed get the column added in place.
        if "app" not in {r["name"] for r in conn.execute("PRAGMA table_info(traces)")}:
            conn.execute("ALTER TABLE traces ADD COLUMN app TEXT")
        # "kb": uploaded to the knowledge base screen. "backend": a data source wired in behind the chatbot
        # (a bookings system export) that the bot reads but the knowledge base screen does not list.
        if "source" not in {r["name"] for r in conn.execute("PRAGMA table_info(documents)")}:
            conn.execute("ALTER TABLE documents ADD COLUMN source TEXT NOT NULL DEFAULT 'kb'")
        if not conn.execute("SELECT 1 FROM policies LIMIT 1").fetchone():
            conn.executemany("INSERT INTO policies(text) VALUES (?)", [(p,) for p in config.DEFAULT_POLICIES])


def rows(sql, params=()):
    with db() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def execute(sql, params=()):
    """Run a write; returns the new row id."""
    with db() as conn:
        return conn.execute(sql, params).lastrowid


def update(sql, params=()):
    """Run a write; returns how many rows changed."""
    with db() as conn:
        return conn.execute(sql, params).rowcount


# ---- traces -----------------------------------------------------------------

def save_trace(*, session, source, question, answer, model, latency_ms, retrieved, spans, ts=None, app=None):
    return execute(
        "INSERT INTO traces(ts, session, source, question, answer, model, latency_ms, retrieved_json, spans_json, app)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (ts or time.time(), session, source, question, answer, model, latency_ms,
         json.dumps(retrieved), json.dumps(spans), app),
    )


def get_trace(trace_id):
    found = rows("SELECT * FROM traces WHERE id=?", (trace_id,))
    if not found:
        return None
    t = found[0]
    t["retrieved"] = json.loads(t.pop("retrieved_json") or "[]")
    t["spans"] = json.loads(t.pop("spans_json") or "[]")
    t["alerts"] = rows("SELECT * FROM alerts WHERE trace_id=? ORDER BY id", (trace_id,))
    return t


def recent_queries(session, seconds):
    return rows("SELECT COUNT(*) AS n FROM traces WHERE session=? AND ts>?", (session, time.time() - seconds))[0]["n"]


# ---- alerts -----------------------------------------------------------------

def save_alert(trace_id, source, f, ts=None):
    return execute(
        "INSERT INTO alerts(ts, trace_id, source, severity, owasp, detector, title, detail, evidence, target, doc, chunk_id)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts or time.time(), trace_id, source, f.severity, f.owasp, f.detector, f.title, f.detail,
         f.evidence, f.target, f.doc, f.chunk_id),
    )


# ---- documents --------------------------------------------------------------

def upsert_document(name, title, classification, status, content, findings=None, scanned=False, source="kb"):
    now = time.time()
    with db() as conn:
        conn.execute(
            "INSERT INTO documents(name, title, classification, status, added_ts, scanned_ts, content, findings_json, source)"
            " VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET title=excluded.title, classification=excluded.classification,"
            " status=excluded.status, scanned_ts=excluded.scanned_ts, content=excluded.content,"
            " findings_json=excluded.findings_json, source=excluded.source",
            (name, title, classification, status, now, now if scanned else None, content,
             json.dumps(findings or []), source),
        )


def documents():
    docs = rows("SELECT * FROM documents ORDER BY name")
    for d in docs:
        d["findings"] = json.loads(d.pop("findings_json") or "[]")
    return docs


def policies(enabled_only=True):
    sql = "SELECT * FROM policies" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY id"
    return rows(sql)


# ---- connected apps (API tokens) --------------------------------------------
# Only a SHA-256 hash of each token is stored; the token itself is shown once, when it is created.

def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_app(name):
    token = "rm_live_" + secrets.token_urlsafe(24)
    app_id = execute("INSERT INTO apps(name, token_hash, token_prefix, created_ts) VALUES (?,?,?,?)",
                     (name, _hash(token), token[:12], time.time()))
    return app_id, token


def app_for_token(token):
    """The app a bearer token belongs to, or None. Marks the token as used."""
    if not token:
        return None
    found = rows("SELECT id, name FROM apps WHERE token_hash=? AND revoked=0", (_hash(token),))
    if not found:
        return None
    execute("UPDATE apps SET last_used_ts=? WHERE id=?", (time.time(), found[0]["id"]))
    return found[0]


def apps():
    return rows("SELECT a.id, a.name, a.token_prefix, a.created_ts, a.last_used_ts, a.revoked,"
                " (SELECT COUNT(*) FROM traces t WHERE t.app=a.name) AS conversations FROM apps a ORDER BY a.id")


def revoke_app(app_id):
    return update("UPDATE apps SET revoked=1 WHERE id=?", (app_id,))
