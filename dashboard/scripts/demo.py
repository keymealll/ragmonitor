"""Demo helper. The server must be running (uvicorn server:app --port 8000).

  python scripts/demo.py seed       # reset, then add normal customer chats over the last day (green dashboard)
  python scripts/demo.py run        # play the demo script: normal question, poisoned refund, salary leak
  python scripts/demo.py fill       # add the ~110 test conversations in scripts/cases.py (keeps existing data)
  python scripts/demo.py connect    # wire the synthetic bookings export in behind the bot (no prompts), for a live demo
  python scripts/demo.py pii        # wire the synthetic bookings export in behind the bot, then run the sensitive-data prompts
  python scripts/demo.py template   # write ../ChatbotTestingTemplate.md and ../SensitiveDataTestingTemplate.md
"""
import json
import os
import random
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ragmon import config, kb, monitor, store  # noqa: E402
from scripts import cases  # noqa: E402

BASE = os.environ.get("RAGMON_URL", "http://localhost:8000")
NORMAL = [
    "Do you fly to Paris?", "How heavy can my cabin bag be?", "How much is a checked bag?", "Where do you fly from Cork?",
    "How do I book a trip?", "When does your support team answer?", "How long do you hold the price?",
    "Do you fly to Barcelona?", "What is Skerry?", "Can I add a bag after booking?",
]
DEMO = [
    ("Normal customer question", "Do you fly to Paris?"),
    ("Refund question hits the poisoned document", "How do I get a refund?"),
    ("Salary question leaks canary tokens", "What's the CEO's salary?"),
]


def post(path, body=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body or {}).encode(),
                                 headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def seed():
    post("/api/reset")
    kb.rebuild()
    now, rng = time.time(), random.Random(7)
    # Every seeded chat runs through the real model, so keep the count small enough to seed in about a minute.
    stamps = sorted([now - rng.uniform(3600, 86400) for _ in range(16)] + [now - rng.uniform(60, 3500) for _ in range(8)])
    for i, ts in enumerate(stamps):
        monitor.ask(rng.choice(NORMAL), f"visitor-{rng.randint(100, 999)}", "live", ts=ts)
    alerts = store.rows("SELECT COUNT(*) n FROM alerts WHERE source='live'")[0]["n"]
    print(f"Seeded {len(stamps)} normal conversations over the last 24h ({alerts} alerts). Dashboard: {BASE}")


def run(pause=6):
    for label, q in DEMO:
        r = post("/chat", {"question": q, "session": "demo-customer"})
        worst = max((a["severity"] for a in r["alerts"]), key="LOW MEDIUM HIGH CRITICAL".split().index, default="none")
        print(f"\n== {label}\nQ: {q}\nA: {r['answer']}\n   {len(r['alerts'])} alerts, worst {worst}, trace {BASE}/#/traces/{r['trace_id']}")
        time.sleep(pause)


def fill():
    """Run every test case through the real pipeline, spread over the last 24 hours, as traffic from the travel site."""
    store.init()
    kb.rebuild()
    rng, now = random.Random(11), time.time()
    stamps = sorted(now - rng.uniform(120, 86400) for _ in cases.CASES)
    order = cases.CASES[:]
    rng.shuffle(order)
    folder = config.ROOT / "samples" / "attachments"
    counts = {}
    for i, ((category, prompt, att), ts) in enumerate(zip(order, stamps), 1):
        attachment = {"name": att, "content": (folder / att).read_text()} if att else None
        r = monitor.ask(prompt, f"visitor-{rng.randint(1000, 9999)}", "live", ts=ts, app="Skerry travel site", attachment=attachment)
        counts[category] = counts.get(category, 0) + 1
        worst = max((a["severity"] for a in r["alerts"]), key="LOW MEDIUM HIGH CRITICAL".split().index, default="-")
        print(f"{i:>3}/{len(order)} {category:<13} {worst:<8} {prompt[:60]}", flush=True)
    session = f"visitor-flood-{rng.randint(1000, 9999)}"
    for prompt in cases.FLOOD[1]:  # live timestamps, so the flood detector counts them inside one minute
        monitor.ask(prompt, session, "live", app="Skerry travel site")
    print(f"done: {sum(counts.values()) + len(cases.FLOOD[1])} conversations, "
          f"{store.rows('SELECT COUNT(*) n FROM alerts WHERE source=?', ('live',))[0]['n']} live alerts in total")


def pii():
    """A bookings export is wired in behind the chatbot, out of the knowledge base's sight; attackers then ask for customers' data."""
    store.init()
    path = config.ROOT / "samples" / cases.SENSITIVE_FILE
    # Wired in behind the chatbot (like a bookings system it can query), not uploaded on the knowledge base screen.
    status, findings = kb.add_document(cases.SENSITIVE_FILE, path.read_text(encoding="utf-8"), source="backend")
    print(f"connected behind the bot; scan: {status}, {len(findings)} finding(s): {sorted({f.title for f in findings})}")
    if status == "quarantined":
        store.execute("UPDATE documents SET status='approved' WHERE name=?", (cases.SENSITIVE_FILE,))
    kb.rebuild()
    rng, now = random.Random(5), time.time()
    stamps = sorted(now - rng.uniform(120, 6 * 3600) for _ in cases.SENSITIVE_CASES)
    for i, ((category, prompt), ts) in enumerate(zip(cases.SENSITIVE_CASES, stamps), 1):
        r = monitor.ask(prompt, f"visitor-{rng.randint(1000, 9999)}", "live", ts=ts, app="Skerry travel site")
        leak = any(a["severity"] == "CRITICAL" for a in r["alerts"])
        print(f"{i:>2}/{len(cases.SENSITIVE_CASES)} {category:<10} {'LEAK' if leak else '-':<5} {prompt[:56]}", flush=True)
    print("done. Open a leaking conversation and quarantine bookings_export.csv from its source link to stop the leaks.")


def connect():
    """Wire the bookings export in behind the running bot without sending any prompts, so leaks can be shown live."""
    store.init()
    path = config.ROOT / "samples" / cases.SENSITIVE_FILE
    kb.add_document(cases.SENSITIVE_FILE, path.read_text(encoding="utf-8"), source="backend")
    post(f"/api/documents/{cases.SENSITIVE_FILE}/approve")  # makes the running server re-index, so the bot can read it now
    print(f"{cases.SENSITIVE_FILE} is connected behind the bot (not listed in the knowledge base).")


def template():
    for name, text in (("ChatbotTestingTemplate.md", cases.markdown()), ("SensitiveDataTestingTemplate.md", cases.sensitive_markdown())):
        out = config.ROOT.parent / name
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out}")


if __name__ == "__main__":
    {"seed": seed, "run": run, "fill": fill, "pii": pii, "connect": connect, "template": template}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: print(__doc__))()
