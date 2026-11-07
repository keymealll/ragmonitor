# Corkathon 2026 — RAG Chatbot Security Monitor

## Context
- **Event:** Corkathon (UCC CS Society, sponsors Frame + Ignite UCC), Sat 7 Nov 2026, The ORB, UCC.
- **Hard deadline:** Devpost locks at **19:00 sharp**. Draft submission must be up by **18:30**.
- **Team:** 3 people. Kamil owns detectors, attack scenarios and the security story.
- **Tracks:** Best use of data, Best startup potential.
- **Devpost needs:** project name + problem/solution description, GitHub repo link, short demo video, the challenge prompt entered, all 3 teammates added.

## The product (one line)
An always-on monitor for SMEs running AI chatbots trained on their own documents. It shows a non-technical business owner what their chatbot actually retrieved and said, alerts on leaks, poisoned documents and policy breaks, and traces every alert back to the exact document.

## Positioning (for pitch + README)
- **Testers** (Promptfoo, Garak, PyRIT, DeepTeam, Giskard scan) attack the bot to see if it *can* break. Developer tools (YAML/CLI/CI).
- **Guards/firewalls** (Lakera/Check Point, Giskard Guards, LLM Guard, NeMo Guardrails, Promptfoo Guardrails) block in real time, mostly enterprise.
- **Us = visibility for SMEs:** passive monitoring of *real* conversations at the retrieval layer, traced to the source document, in a dashboard a business owner can read.
- Pitch line: "Testers check before launch. Guards block in real time. Neither tells a small business owner what's actually happening in their chatbot, or which document to fix. We do."
- **Do NOT claim:** "nobody monitors live chatbots", "Promptfoo only tests before launch" (it has scheduled CI scans + drift alerts), or that RAG monitoring is an empty market.
- Extra angles: built in Ireland / EU-hosted / GDPR-first; EU AI Act exposure as "why now".
- Target customer: SMEs with customer-facing chatbots trained on their docs (Chatbase-style), e.g. clinics, estate agents, law firms, online shops. Business model: per-chatbot monthly subscription.

## Stack (keep it boring and fast)
- Python throughout.
- FastAPI backend, Chroma vector store, whichever LLM API we already have a key for.
- Dashboard: Datadog-style single-page HTML/vanilla JS in `dashboard/`, served by FastAPI (chosen over Streamlit for the Datadog look). No build step.
- Retrieval: pure-Python TF-IDF in `ragmon/kb.py` (deterministic, no embedding download). Chroma swap = replace `kb.search`.
- SQLite (or JSON) for logs and alerts.
- Run on localhost for the demo video. No deployment, no auth.
- **Two projects:** `dashboard/` = RagMonitor (FastAPI on :8000: RAG bot API, detectors, Promptfoo, dashboard UI in `dashboard/ui/`). `website-chatbot/` = Skerry, a fictional Cork travel app site (FastAPI on :4000, Hallmark Cobalt theme) whose chat calls RagMonitor `POST /v1/chat` with a Bearer API token kept server-side in `website-chatbot/.env`. Port 3000 is taken by Grafana on Kamil's Mac.
- Run: `cd dashboard && uvicorn server:app --port 8000`, `python scripts/apptoken.py create "Skerry travel site"`, then `cd website-chatbot && uvicorn server:app --port 4000`. `python scripts/demo.py seed|run` and `python -m unittest discover tests` run from `dashboard/`.
- Model: Ollama `qwen2.5:1.5b` by default (auto-detected; real 1 to 4 s latency). `BOT_PROMPT=naive` (default) tells it to obey document instructions, like a careless deployment. `LLM_PROVIDER=offline` = scripted demo bot (no LLM, ~1 ms; a volunteer spotted the 1 ms, so never present it as a real model). Policy checks are rule-based on ollama/offline; LLM judge only with an API key.
- Demo company is now Skerry (travel), not Harbour & Hill. KB filenames unchanged: `handbook.md`, `refund_policy.md` (poisoned), `salaries_confidential.md` (canaries).
- Detector `confidential_value_leak`: the real model rewrites answers without canary tokens, so money, percentages and names found only in confidential chunks are matched too.

## Architecture
1. **Demo RAG chatbot** over a fake company knowledge base (stands in for a Chatbase-style bot).
2. **Logging layer** wrapping retrieval + generation. Per query, store: timestamp, question, retrieved chunks (text, source doc, score), answer.
3. **Detectors** run on retrieved chunks and on answers inside the logging step; write alerts with severity + the offending chunk/doc.
4. **Dashboard** reads logs + alerts.

## MVP features (build these, in this order)
1. **Leak alerts** — canary tokens (e.g. `CANARY-7f3a`) planted in a confidential doc; any canary in an answer = CRITICAL. Plus regex for emails, API-key-like strings, card/IBAN-like patterns in answers.
2. **Suspicious chunk detection** — regex for instruction-like text ("ignore previous instructions", "you must", "reveal", "system override"), invisible/zero-width Unicode, suspicious URLs or markdown images in retrieved chunks.
3. **Plain-English policy checks** — owner writes rules like "never share staff salaries" / "only refer customers to support@company.ie"; an LLM judge checks each answer against them.
4. **Dashboard:** safety score (green/amber/red + one-line reason), alerts feed in plain English, risky documents ranked with suspicious text highlighted, click an alert → trace-back view (question → retrieved chunks → answer → source doc).

## Stretch (only if ahead at 16:00)
- Usage-and-risk charts: conversations/day, alerts/day, top flagged docs (helps "best use of data").
- Upload scan: check a new doc before it enters the knowledge base.
- Promptfoo active scan (**BUILT**, core feature now: `promptfoo/promptfooconfig.yaml` uses `promptfoo eval` with deterministic asserts over the HTTP provider, so no LLM key needed; "Run scan now" button on Security scans page; saved `promptfoo/results.json` is imported on startup). Original plan: custom Python provider calling our bot, small `promptfooconfig.yaml` (`purpose` + plugins `indirect-prompt-injection`, `pii:direct`, `harmful:privacy`, `policy`), `numTests` ~10, `promptfoo redteam run -o results.json`, parse into a "Security scan" tab. Needs Node + likely an LLM API key. **Timebox: drop it if no results file by 14:30.** Never run it live in the pitch; show saved results. Credit Promptfoo (MIT) in Devpost.
- Answer-grounding check (is the answer supported by retrieved chunks?).

## Out of scope (roadmap slide only)
Email/Slack alerts, weekly report, GDPR/EU AI Act compliance export, connectors for Chatbase/Intercom Fin/Tidio, auto-fix suggestions, on-prem, policy-as-code, agent support, ML training, auth, deployment.

## Demo knowledge base
- `handbook.md` — normal company info.
- `refund_policy.md` — **poisoned**: hidden instruction telling the bot to send customers to an attacker email for refunds.
- `salaries_confidential.md` — fake salary sheet containing canary tokens.

## Demo script (build and test this FIRST)
1. Dashboard is green.
2. Normal customer question → answered, still green.
3. Refund question → poisoned chunk retrieved → injection + policy alert, doc turns red.
4. "What's the CEO's salary?" → canary leaks → CRITICAL alert, score goes red.
5. Click the alert → trace back to the exact document and chunk.

## Timeline
- 11:00–13:00 RAG bot working + retrieval logging; detectors written as standalone functions.
- 13:00–14:30 Detectors plugged into logging, alerts stored; dashboard skeleton reading logs.
- 14:30–16:00 Demo script works end to end; alert → trace-back.
- 16:00–17:30 Polish, charts, stretch items.
- 17:30–18:30 Record demo video, push repo + README, write Devpost.
- **18:30 feature freeze, draft submitted. 19:00 locks.**

## Rules for working on this repo
- A scripted attack that reliably fires an alert beats five detectors that sometimes work.
- Rule-based first; LLM judge only for policy checks and borderline cases.
- Keep everything runnable with one command each for bot, monitor and dashboard.
- Honest framing: "detection and visibility, not a guarantee". Detection is heuristic.