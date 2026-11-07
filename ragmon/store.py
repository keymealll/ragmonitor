"""SQLite storage for traces, alerts, documents, policies and scans."""
import json
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

def save_trace(*, session, source, question, answer, model, latency_ms, retrieved, spans, ts=None):
    return execute(
        "INSERT INTO traces(ts, session, source, question, answer, model, latency_ms, retrieved_json, spans_json)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (ts or time.time(), session, source, question, answer, model, latency_ms,
         json.dumps(retrieved), json.dumps(spans)),
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

def upsert_document(name, title, classification, status, content, findings=None, scanned=False):
    now = time.time()
    with db() as conn:
        conn.execute(
            "INSERT INTO documents(name, title, classification, status, added_ts, scanned_ts, content, findings_json)"
            " VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET title=excluded.title, classification=excluded.classification,"
            " status=excluded.status, scanned_ts=excluded.scanned_ts, content=excluded.content,"
            " findings_json=excluded.findings_json",
            (name, title, classification, status, now, now if scanned else None, content,
             json.dumps(findings or [])),
        )


def documents():
    docs = rows("SELECT * FROM documents ORDER BY name")
    for d in docs:
        d["findings"] = json.loads(d.pop("findings_json") or "[]")
    return docs


def policies(enabled_only=True):
    sql = "SELECT * FROM policies" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY id"
    return rows(sql)
