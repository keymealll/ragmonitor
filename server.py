"""RagMonitor: demo chatbot API + monitoring API + dashboard, one process.

Run:  uvicorn server:app --port 8000
"""
import json
import threading
import time

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ragmon import config, detectors, kb, llm, monitor, scans, store

app = FastAPI(title="RagMonitor")
DASH = config.ROOT / "dashboard"
SEV_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
# Where each OWASP category is covered. "n/a" = does not apply to this bot (no tools / no third-party models).
COVERAGE = {
    "LLM01": ["live", "scan", "upload"], "LLM02": ["live", "scan"], "LLM03": [], "LLM04": ["upload", "live"],
    "LLM05": ["live", "scan"], "LLM06": ["n/a"], "LLM07": ["live", "scan"], "LLM08": ["live"],
    "LLM09": ["scan"], "LLM10": ["live"],
}


@app.on_event("startup")
def startup():
    store.init()
    if not store.documents():
        kb.load_folder()
    kb.rebuild()
    scans.import_saved_results()


# ---- chatbot ----------------------------------------------------------------

class ChatIn(BaseModel):
    question: str
    session: str = "web"
    source: str = "live"   # "scan" for Promptfoo traffic


@app.post("/chat")
def chat(body: ChatIn):
    if not body.question.strip():
        raise HTTPException(400, "empty question")
    source = "scan" if body.source == "scan" else "live"
    return monitor.ask(body.question, body.session, source)


# ---- overview ---------------------------------------------------------------

def _score(open_alerts):
    counts = {s: sum(a["severity"] == s for a in open_alerts) for s in SEV_WEIGHT}
    if counts["CRITICAL"]:
        return max(5, 39 - 5 * (counts["CRITICAL"] - 1)), "red"
    if counts["HIGH"]:
        return max(40, 69 - 4 * (counts["HIGH"] - 1)), "amber"
    if counts["MEDIUM"] or counts["LOW"]:
        return max(70, 89 - 2 * (counts["MEDIUM"] + counts["LOW"] - 1)), "green"
    return 100, "green"


def _buckets(range_):
    now = time.time()
    step, n = (60, 60) if range_ == "1h" else (1800, 48)
    start = (now // step + 1) * step - step * n
    return start, step, n


@app.get("/api/overview")
def overview(range_: str = Query("1h", alias="range")):
    since = time.time() - 86400
    open_alerts = store.rows("SELECT * FROM alerts WHERE source='live' AND status='open' ORDER BY id DESC")
    score, color = _score(open_alerts)
    top = max(open_alerts, key=lambda a: (SEV_WEIGHT[a["severity"]], a["id"]), default=None)
    convos = store.rows("SELECT COUNT(*) n, AVG(latency_ms) lat FROM traces WHERE source='live' AND ts>?", (since,))[0]
    reason = top["title"] if top else f"No problems found in {convos['n']} conversations in the last 24 hours."

    start, step, n = _buckets(range_)
    series = {"labels": [start + i * step for i in range(n)], "conversations": [0] * n,
              **{s: [0] * n for s in SEV_WEIGHT}}
    for r in store.rows("SELECT ts FROM traces WHERE source='live' AND ts>=?", (start,)):
        series["conversations"][min(n - 1, int((r["ts"] - start) // step))] += 1
    for r in store.rows("SELECT ts, severity FROM alerts WHERE source='live' AND ts>=?", (start,)):
        series[r["severity"]][min(n - 1, int((r["ts"] - start) // step))] += 1

    docs = documents()
    return {
        "score": score, "color": color, "reason": reason, "top_alert_id": top["id"] if top else None,
        "kpis": {
            "conversations_24h": convos["n"], "avg_latency_ms": round(convos["lat"] or 0),
            "open_alerts": len(open_alerts), "critical_open": sum(a["severity"] == "CRITICAL" for a in open_alerts),
            "leaks_24h": store.rows("SELECT COUNT(*) n FROM alerts WHERE source='live' AND owasp='LLM02' AND ts>?",
                                    (since,))[0]["n"],
            "docs_at_risk": sum(d["risk"] >= 3 for d in docs), "docs_total": len(docs),
        },
        "series": series,
        "top_docs": [d for d in docs if d["risk"]][:5],
        "status": status(),
    }


@app.get("/api/status")
def status():
    return {"provider": llm.PROVIDER, "model": llm.model_name(), "company": config.COMPANY,
            "policy_engine": "rule-based fallback" if llm.PROVIDER == "offline" else f"LLM judge ({llm.model_name()})"}


@app.get("/api/owasp")
def owasp():
    live = store.rows("SELECT owasp, severity, COUNT(*) n FROM alerts WHERE source='live' AND status='open'"
                      " AND owasp IS NOT NULL GROUP BY owasp, severity")
    scan = scans.latest()
    out = []
    for code, (name, plain) in detectors.OWASP.items():
        hits = [r for r in live if r["owasp"] == code]
        cat = (scan or {}).get("by_owasp", {}).get(code, {})
        out.append({
            "code": code, "name": name, "plain": plain, "coverage": COVERAGE[code],
            "open_alerts": sum(r["n"] for r in hits),
            "worst": max((r["severity"] for r in hits), key=lambda s: SEV_WEIGHT[s], default=None),
            "scan_passed": cat.get("passed", 0), "scan_failed": cat.get("failed", 0),
        })
    return out


# ---- alerts & traces --------------------------------------------------------

@app.get("/api/alerts")
def alerts(source: str = "live", status: str = "all", limit: int = 200):
    sql, params = "SELECT a.*, t.question FROM alerts a LEFT JOIN traces t ON t.id=a.trace_id WHERE a.source=?", [source]
    if status != "all":
        sql += " AND a.status=?"
        params.append(status)
    return store.rows(sql + " ORDER BY a.id DESC LIMIT ?", (*params, limit))


@app.post("/api/alerts/{alert_id}/resolve")
def resolve(alert_id: int):
    store.execute("UPDATE alerts SET status='resolved' WHERE id=?", (alert_id,))
    return {"ok": True}


@app.get("/api/traces")
def traces(source: str = "live", limit: int = 200):
    out = store.rows(
        "SELECT t.id, t.ts, t.session, t.source, t.question, t.answer, t.latency_ms, t.model, t.retrieved_json,"
        " COUNT(a.id) alerts, MAX(CASE a.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2"
        " WHEN 'LOW' THEN 1 ELSE 0 END) worst FROM traces t LEFT JOIN alerts a ON a.trace_id=t.id"
        " WHERE t.source=? GROUP BY t.id ORDER BY t.id DESC LIMIT ?", (source, limit))
    for t in out:
        t["docs"] = sorted({c["doc"] for c in json.loads(t.pop("retrieved_json") or "[]")})
    return out


@app.get("/api/traces/{trace_id}")
def trace(trace_id: int):
    t = store.get_trace(trace_id)
    if not t:
        raise HTTPException(404)
    return t


# ---- knowledge base ---------------------------------------------------------

@app.get("/api/documents")
def documents():
    counts = {r["doc"]: r for r in store.rows(
        "SELECT doc, COUNT(*) n, MAX(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2"
        " ELSE 1 END) worst FROM alerts WHERE source='live' AND status='open' AND doc IS NOT NULL GROUP BY doc")}
    retrievals = {}
    for r in store.rows("SELECT retrieved_json FROM traces WHERE source='live'"):
        for doc in {c["doc"] for c in json.loads(r["retrieved_json"] or "[]")}:
            retrievals[doc] = retrievals.get(doc, 0) + 1
    docs = store.documents()
    for d in docs:
        live = counts.get(d["name"], {})
        scan_worst = max((SEV_WEIGHT[f["severity"]] for f in d["findings"]), default=0)
        d["open_alerts"] = live.get("n", 0)
        d["risk"] = max(live.get("worst", 0), scan_worst if d["status"] != "approved" else 0)
        d["retrievals"] = retrievals.get(d["name"], 0)
        d["chunks"] = kb.chunk(d["name"], d["content"])
    docs.sort(key=lambda d: (-d["risk"], -d["open_alerts"], d["name"]))
    return docs


class DocIn(BaseModel):
    name: str
    content: str


@app.post("/api/documents")
def upload(body: DocIn):
    name = body.name.strip().replace("/", "_") or "untitled.md"
    status_, findings = kb.add_document(name, body.content, scan=True)
    kb.rebuild()
    return {"name": name, "status": status_, "findings": [f.to_dict() for f in findings]}


@app.post("/api/documents/scan")
def scan_all():
    for d in store.documents():
        if d["status"] not in ("quarantined", "approved"):
            kb.add_document(d["name"], d["content"], scan=True)
    kb.rebuild()
    return documents()


def _set_doc_status(name, status_):
    if not store.rows("SELECT 1 FROM documents WHERE name=?", (name,)):
        raise HTTPException(404)
    store.execute("UPDATE documents SET status=? WHERE name=?", (status_, name))
    kb.rebuild()


@app.post("/api/documents/{name}/quarantine")
def quarantine(name: str):
    _set_doc_status(name, "quarantined")
    # Alerts caused by this document are fixed once it is out of the knowledge base.
    resolved = store.update(
        "UPDATE alerts SET status='resolved' WHERE status='open' AND source='live' AND (doc=? OR trace_id IN"
        " (SELECT id FROM traces WHERE retrieved_json LIKE ?))", (name, f'%"doc": "{name}"%'))
    return {"ok": True, "resolved": resolved}


@app.post("/api/documents/{name}/approve")
def approve(name: str):
    _set_doc_status(name, "approved")
    return {"ok": True}


# ---- policies ---------------------------------------------------------------

class PolicyIn(BaseModel):
    text: str


@app.get("/api/policies")
def policies():
    return store.policies(enabled_only=False)


@app.post("/api/policies")
def add_policy(body: PolicyIn):
    if not body.text.strip():
        raise HTTPException(400, "empty rule")
    store.execute("INSERT INTO policies(text) VALUES (?)", (body.text.strip(),))
    return policies()


@app.delete("/api/policies/{policy_id}")
def delete_policy(policy_id: int):
    store.execute("DELETE FROM policies WHERE id=?", (policy_id,))
    return policies()


# ---- security scans (Promptfoo) --------------------------------------------

@app.get("/api/scans/latest")
def scan_latest():
    return scans.latest() or {}


@app.post("/api/scans/run")
def scan_run():
    if scans.running():
        raise HTTPException(409, "a scan is already running")
    threading.Thread(target=scans.run, daemon=True).start()
    return {"ok": True}


# ---- demo -------------------------------------------------------------------

@app.post("/api/reset")
def reset():
    """Demo reset: wipe customer traffic and alerts, reload the original knowledge base. Keeps scans and their traces."""
    store.execute("DELETE FROM alerts WHERE source='live'")
    store.execute("DELETE FROM traces WHERE source='live'")
    store.execute("DELETE FROM documents")
    kb.load_folder()
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(DASH / "index.html")


@app.get("/shop")
def shop():
    return FileResponse(DASH / "shop.html")


app.mount("/static", StaticFiles(directory=DASH), name="static")
