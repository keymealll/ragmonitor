"""Active security scans powered by Promptfoo: run `promptfoo eval` against the bot, import results.json."""
import json
import os
import subprocess
import time

from . import config, store

PROMPTFOO_VERSION = os.environ.get("PROMPTFOO_VERSION", "0.125.1")
# Promptfoo red-team plugin ids -> OWASP category, for results from `promptfoo redteam run`.
PLUGIN_OWASP = {
    "indirect-prompt-injection": "LLM01", "prompt-injection": "LLM01", "hijacking": "LLM01",
    "pii": "LLM02", "pii:direct": "LLM02", "pii:session": "LLM02", "harmful:privacy": "LLM02",
    "prompt-extraction": "LLM07", "system-prompt-override": "LLM07", "hallucination": "LLM09",
    "excessive-agency": "LLM06", "policy": "POLICY", "ascii-smuggling": "LLM01", "harmful:misinformation-disinformation": "LLM09",
}


def running():
    return bool(store.rows("SELECT 1 FROM scans WHERE status='running' AND ts>?", (time.time() - 600,)))


def run():
    """Run the Promptfoo scan (the bot server must be up on :8000), then import its results."""
    scan_id = store.execute("INSERT INTO scans(ts, status) VALUES (?, 'running')", (time.time(),))
    cmd = ["npx", "-y", f"promptfoo@{PROMPTFOO_VERSION}", "eval", "-c", str(config.PROMPTFOO_DIR / "promptfooconfig.yaml"),
           "-o", str(config.SCAN_RESULTS), "--no-cache", "--no-progress-bar"]
    env = {**os.environ, "PROMPTFOO_DISABLE_TELEMETRY": "1", "PROMPTFOO_DISABLE_UPDATE": "1"}
    try:
        proc = subprocess.run(cmd, cwd=config.ROOT, env=env, capture_output=True, text=True, timeout=600)
        log = (proc.stdout + proc.stderr)[-5000:]
        # promptfoo exits non-zero when tests fail; a missing results file is the real failure.
        if not config.SCAN_RESULTS.exists():
            raise RuntimeError(f"promptfoo exited {proc.returncode} without writing results")
        summary, results = parse(json.loads(config.SCAN_RESULTS.read_text()))
        store.update("UPDATE scans SET status='done', summary_json=?, results_json=?, log=? WHERE id=?",
                     (json.dumps(summary), json.dumps(results), log, scan_id))
    except Exception as e:
        store.update("UPDATE scans SET status='failed', log=? WHERE id=?", (f"{type(e).__name__}: {e}", scan_id))


def parse(data):
    """Turn a promptfoo results.json (eval or redteam) into a summary and a flat result list."""
    raw = data.get("results", {})
    items = raw.get("results", []) if isinstance(raw, dict) else raw
    results = []
    for r in items:
        tc = r.get("testCase") or {}
        meta = {**(tc.get("metadata") or {}), **(r.get("metadata") or {})}
        plugin = meta.get("pluginId") or meta.get("attack") or ""
        owasp = meta.get("owasp") or PLUGIN_OWASP.get(plugin) or PLUGIN_OWASP.get(plugin.split(":")[0], "OTHER")
        grading = r.get("gradingResult") or {}
        failed_checks = [c.get("assertion", {}).get("metric") or c.get("assertion", {}).get("type")
                         for c in grading.get("componentResults", []) if not c.get("pass")]
        try:
            trace_id = json.loads((r.get("response") or {}).get("raw") or "{}").get("trace_id")
        except (ValueError, AttributeError):
            trace_id = None
        results.append({
            "trace_id": trace_id,
            "owasp": owasp, "attack": plugin, "description": tc.get("description") or plugin,
            "prompt": (r.get("vars") or tc.get("vars") or {}).get("question") or (r.get("prompt") or {}).get("raw", ""),
            "output": (r.get("response") or {}).get("output", r.get("error", "")),
            "passed": bool(r.get("success")), "failed_checks": [c for c in failed_checks if c],
            "reason": grading.get("reason") or r.get("failureReason") or "",
        })
    by_owasp = {}
    for x in results:
        c = by_owasp.setdefault(x["owasp"], {"passed": 0, "failed": 0})
        c["passed" if x["passed"] else "failed"] += 1
    passed = sum(x["passed"] for x in results)
    summary = {"total": len(results), "passed": passed, "failed": len(results) - passed,
               "pass_rate": round(100 * passed / len(results)) if results else 0,
               "by_owasp": by_owasp, "eval_id": data.get("evalId"),
               "timestamp": (raw.get("timestamp") if isinstance(raw, dict) else None)}
    return summary, results


def import_saved_results():
    """Load the saved results.json once, so the dashboard has a scan to show without running Promptfoo live."""
    if config.SCAN_RESULTS.exists() and not store.rows("SELECT 1 FROM scans WHERE status='done'"):
        summary, results = parse(json.loads(config.SCAN_RESULTS.read_text()))
        store.execute("INSERT INTO scans(ts, status, summary_json, results_json, log) VALUES (?,?,?,?,?)",
                      (config.SCAN_RESULTS.stat().st_mtime, "done", json.dumps(summary), json.dumps(results),
                       "imported from promptfoo/results.json"))


def latest():
    done = store.rows("SELECT * FROM scans WHERE status='done' ORDER BY id DESC LIMIT 1")
    last = store.rows("SELECT id, ts, status, log FROM scans ORDER BY id DESC LIMIT 1")
    if not done and not last:
        return None
    out = {"running": running(), "last_run": last[0] if last else None}
    if done:
        d = done[0]
        results = json.loads(d["results_json"])
        # Only link to scan traces that still exist in this database.
        known = {r["id"] for r in store.rows("SELECT id FROM traces WHERE source='scan'")}
        for r in results:
            if r.get("trace_id") not in known:
                r["trace_id"] = None
        out.update(id=d["id"], ts=d["ts"], **json.loads(d["summary_json"]), results=results)
    return out
