# RagMonitor

**An always-on security monitor for small businesses running AI chatbots trained on their own documents.**
It shows the owner what the chatbot actually retrieved and said, alerts on data leaks, poisoned documents and broken rules, and traces every alert back to the exact document and sentence.

Built at Corkathon 2026 (UCC). Tracks: Best use of data, Best startup potential.

![Overview dashboard](docs/overview.png)

## The problem

Clinics, estate agents, law firms and online shops are putting chatbots on their websites that answer from their own documents (Chatbase-style RAG bots). If one of those documents is tampered with, or a confidential file ends up in the knowledge base, the chatbot will repeat it to customers. The owner usually finds out last.

- **Testers** (Promptfoo, Garak, PyRIT, DeepTeam, Giskard) attack a bot to see if it *can* break. They are developer tools (YAML, CLI, CI).
- **Guards and firewalls** (Lakera, LLM Guard, NeMo Guardrails, Promptfoo Guardrails) block in real time, mostly for enterprises.
- **RagMonitor gives visibility to SMEs.** It passively monitors *real* conversations at the retrieval layer, traces each problem to the source document, and puts it in a dashboard a business owner can read.

> Testers check before launch. Guards block in real time. Neither tells a small business owner what's actually happening in their chatbot, or which document to fix. We do.

## What it does

| Feature | How |
|---|---|
| **Leak alerts** | Canary tokens (`CANARY-7f3a`) planted in confidential docs and the system prompt; regex for emails, API keys, Luhn-valid card numbers and IBANs in answers. |
| **Poisoned document detection** | Instruction-like text ("ignore previous instructions", "system override", "you must tell the customer…"), zero-width and bidi Unicode, hidden HTML comments, markdown-image exfiltration links and unknown emails or URLs in retrieved chunks. |
| **Upload scan** | Every new document is scanned before the chatbot can read it; risky ones are quarantined automatically. |
| **Plain-English rules** | The owner writes rules like "Only refer customers to support@harbourhill.ie". An LLM judge checks each answer, with a rule-based fallback when no API key is set. |
| **Trace-back** | Click any alert to see the question, the retrieved passages with the bad text highlighted, the answer, and a span timeline. Then quarantine the document in one click. |
| **Security scans (Promptfoo)** | [Promptfoo](https://github.com/promptfoo/promptfoo) sends 14 attack questions to the live bot and grades each answer with deterministic checks. Results are mapped to OWASP categories, and each failure links to its conversation trace. |
| **Owner view / Engineer view** | The same data either as plain-English sentences or as detector IDs, chunk scores, spans and models. |

![Trace-back view](docs/trace.png)

## OWASP Top 10 for LLM Applications (2025) coverage

| Risk | How RagMonitor watches it |
|---|---|
| LLM01 Prompt Injection | Live: instructions hidden in retrieved chunks, direct injection attempts, answers that send customers to unknown contacts. Promptfoo scan. |
| LLM02 Sensitive Information Disclosure | Live: canary tokens, secrets, card numbers and IBANs in answers. Promptfoo scan. |
| LLM03 Supply Chain | Roadmap |
| LLM04 Data and Model Poisoning | Upload scan quarantines tampered documents; live document risk ranking. |
| LLM05 Improper Output Handling | Live: markdown images to external hosts, active HTML in answers. Promptfoo scan. |
| LLM06 Excessive Agency | Not applicable (the demo bot has no tools). |
| LLM07 System Prompt Leakage | Live: system-prompt canary in answers. Promptfoo scan. |
| LLM08 Vector and Embedding Weaknesses | Live: confidential documents retrieved into a public customer chat. |
| LLM09 Misinformation | Promptfoo grounding checks. |
| LLM10 Unbounded Consumption | Live: oversized inputs and floods from a single session. |

Detection is heuristic. RagMonitor gives you detection and visibility, not a guarantee.

## Run it

Needs Python 3.10+. The Promptfoo scan also needs Node 20+ (it is run through `npx`, so nothing to install).

```bash
pip install -r requirements.txt
uvicorn server:app --port 8000          # bot + monitor + dashboard in one process
```

- Dashboard: http://localhost:8000
- Demo shop with the customer chatbot: http://localhost:8000/shop

```bash
python scripts/demo.py seed             # reset and add a day of normal customer chats (green dashboard)
python scripts/demo.py run              # play the attack script against the bot
npx promptfoo@0.125.1 eval -c promptfoo/promptfooconfig.yaml -o promptfoo/results.json   # or the "Run scan now" button
python -m unittest discover tests       # checks that the demo attacks fire every time
```

### LLM provider

With no API key the bot uses an **offline demo model**: a deliberately naive bot that answers from the retrieved text and follows instructions hidden in it, as an unprotected RAG bot can. This keeps the demo reliable, and the dashboard labels it.

To use a real model, set a key before starting the server:

```bash
export ANTHROPIC_API_KEY=...            # uses claude-haiku-5-5 (override with ANTHROPIC_MODEL)
# or
export OPENAI_API_KEY=...               # override the model with OPENAI_MODEL
export LLM_PROVIDER=offline             # force the offline demo model even if a key is set
```

With a key, the rule checks use an LLM judge instead of the rule-based fallback.

## Demo script

1. The dashboard is green: 44 normal conversations, no alerts.
2. A normal customer question gets answered and the dashboard stays green.
3. "How do I get a refund?" retrieves the poisoned `refund_policy.md`. The bot sends the customer to `refunds@hh-payments-help.com` and asks for their card number. This raises injection and rule alerts, and the document turns red.
4. "What's the CEO's salary?" leaks canary tokens from `salaries_confidential.md`. A CRITICAL alert fires and the score goes red.
5. Click the alert. The trace shows the question, the passage with the hidden text highlighted, the answer and the source document. Quarantining the document resolves its alerts.
6. Bonus: upload `samples/supplier_update.md` in Knowledge base. It hides zero-width characters and a tracking image, so it is quarantined before the chatbot ever sees it.

## How it works

```
customer ─► POST /chat ─► monitor.ask()
                            ├─ detect.question   direct injection, flooding (LLM01, LLM10)
                            ├─ rag.retrieve      TF-IDF over kb/ chunks (quarantined docs excluded)
                            ├─ detect.chunks     poisoning signs, confidential retrieval (LLM01/04/08)
                            ├─ llm.generate      Anthropic / OpenAI / offline demo model
                            ├─ detect.answer     canaries, secrets, PII, unsafe output (LLM02/05/07)
                            └─ policy.judge      owner's plain-English rules
                          ─► SQLite: trace (chunks + spans) + alerts ─► dashboard (polls every 3s)

Promptfoo ─► POST /chat (source=scan) ─► same pipeline, kept apart from customer traffic
          └► promptfoo/results.json ─► Security scans page
```

| Path | What |
|---|---|
| `server.py` | FastAPI: chatbot endpoint, monitoring API, serves the dashboard |
| `ragmon/detectors.py` | All rule-based detectors with their OWASP mapping (each one is a plain function) |
| `ragmon/monitor.py` | Wraps retrieval and generation, runs the detectors, stores the trace and alerts |
| `ragmon/kb.py` | Document loading, chunking, retrieval and the upload scan |
| `ragmon/policy.py` | LLM judge for plain-English rules, plus the rule-based fallback |
| `ragmon/scans.py` | Runs Promptfoo and imports `results.json` |
| `promptfoo/promptfooconfig.yaml` | The 14 attack tests, tagged by OWASP category |
| `dashboard/` | Single-page dashboard (vanilla JS, no build step) and the demo shop |
| `kb/` | Demo knowledge base: normal handbook, poisoned refund policy, confidential salaries with canaries |

## Roadmap

Email and Slack alerts, a weekly owner report, GDPR / EU AI Act compliance export, connectors for Chatbase, Intercom Fin and Tidio, fix suggestions, Promptfoo red-team generation (`promptfoo redteam`) for larger attack sets, and on-prem / EU hosting.

## Credits

- [Promptfoo](https://github.com/promptfoo/promptfoo) (MIT) runs the security scans.
- Risk categories come from the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
- Harbour & Hill Outdoor is a fictional company. All documents, names and salaries are made up.
