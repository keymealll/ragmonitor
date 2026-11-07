# Cyber Tiger

<img src="dashboard/ui/cybertiger-logo.png" alt="Cyber Tiger: threat detection at full speed" width="440">


**An always-on security monitor for small businesses running AI chatbots trained on their own documents.**
It shows the owner what the chatbot actually retrieved and said, alerts on data leaks, poisoned documents and broken rules, and traces every alert back to the exact document and sentence.

Built at Corkathon 2026 (UCC). The code still uses the working name RagMonitor (`ragmon/`, `RAGMON_*` settings, `rm_live_` tokens). Tracks: Best use of data, Best startup potential.

![Overview dashboard](docs/overview.png)

## The problem

Clinics, estate agents, law firms and online shops are putting chatbots on their websites that answer from their own documents (Chatbase-style RAG bots). If one of those documents is tampered with, or a confidential file ends up in the knowledge base, the chatbot will repeat it to customers. The owner usually finds out last.

- **Testers** (Promptfoo, Garak, PyRIT, DeepTeam, Giskard) attack a bot to see if it *can* break. They are developer tools (YAML, CLI, CI).
- **Guards and firewalls** (Lakera, LLM Guard, NeMo Guardrails, Promptfoo Guardrails) block in real time, mostly for enterprises.
- **Cyber Tiger gives visibility to SMEs.** It passively monitors *real* conversations at the retrieval layer, traces each problem to the source document, and puts it in a dashboard a business owner can read.

> Testers check before launch. Guards block in real time. Neither tells a small business owner what's actually happening in their chatbot, or which document to fix. We do.

## What it does

| Feature | How |
|---|---|
| **Leak alerts** | Canary tokens (`CANARY-7f3a`) planted in confidential docs and the system prompt; regex for emails, API keys, Luhn-valid card numbers and IBANs in answers. |
| **Poisoned document detection** | Instruction-like text ("ignore previous instructions", "system override", "you must tell the customer…"), zero-width and bidi Unicode, hidden HTML comments, markdown-image exfiltration links and unknown emails or URLs in retrieved chunks. |
| **Upload scan** | Every new document is scanned before the chatbot can read it; risky ones are quarantined automatically. |
| **Plain-English rules** | The owner writes rules like "Only refer customers to support@skerry.ie". An LLM judge checks each answer, with a rule-based fallback when no API key is set. |
| **Beyond attacks** | Knowledge gaps (customers ask about things no document covers, shown as insights that never lower the score), answers not backed by the documents (LLM09), and answers that name internal files. |
| **Attachments** | Customers can attach a text file in the travel site's chat. Cyber Tiger scans it like a document before the bot reads it: hidden instructions, invisible text, tracking images, passport and card numbers. |
| **Trace-back** | Click any alert to see the question, the retrieved passages with the bad text highlighted, the answer, and a span timeline. Then quarantine the document in one click. |
| **Security scans (Promptfoo)** | [Promptfoo](https://github.com/promptfoo/promptfoo) sends 14 attack questions to the live bot and grades each answer with deterministic checks. Results are mapped to OWASP categories, and each failure links to its conversation trace. |

![Trace-back view](docs/trace.png)

## OWASP Top 10 for LLM Applications (2025) coverage

| Risk | How Cyber Tiger watches it |
|---|---|
| LLM01 Prompt Injection | Live: instructions hidden in retrieved chunks, direct injection attempts, answers that send customers to unknown contacts. Promptfoo scan. |
| LLM02 Sensitive Information Disclosure | Live: canary tokens, figures and names that exist only in confidential documents, secrets, card numbers and IBANs in answers. Promptfoo scan. |
| LLM03 Supply Chain | Roadmap |
| LLM04 Data and Model Poisoning | Upload scan quarantines tampered documents; live document risk ranking. |
| LLM05 Improper Output Handling | Live: markdown images to external hosts, active HTML in answers. Promptfoo scan. |
| LLM06 Excessive Agency | Not applicable (the demo bot has no tools). |
| LLM07 System Prompt Leakage | Live: system-prompt canary in answers. Promptfoo scan. |
| LLM08 Vector and Embedding Weaknesses | Live: confidential documents retrieved into a public customer chat. |
| LLM09 Misinformation | Promptfoo grounding checks. |
| LLM10 Unbounded Consumption | Live: oversized inputs and floods from a single session. |

Detection is heuristic. Cyber Tiger gives you detection and visibility, not a guarantee.

## Two projects in this repo

| Folder | What it is | Port |
|---|---|---|
| [`dashboard/`](dashboard/) | **Cyber Tiger**: the monitored RAG chatbot API, the detectors, the Promptfoo scans and the dashboard | 8000 |
| [`website-chatbot/`](website-chatbot/) | **Skerry**, a fictional Cork travel app's website. Its chat is a customer app connected to Cyber Tiger with an API token | 4000 |

The travel site never holds the model or the documents. Its server sends each question to Cyber Tiger's `POST /v1/chat` with `Authorization: Bearer <token>`, and Cyber Tiger answers, traces and checks it. The token stays in `website-chatbot/.env` on the server; the browser never sees it.

## Run it

Needs Python 3.10+, [Ollama](https://ollama.com) for the local model, and Node 20+ for the Promptfoo scan (run through `npx`, nothing to install).

```bash
pip install -r dashboard/requirements.txt
ollama pull qwen2.5:1.5b                      # about 1 GB, once

# 1. the monitor
cd dashboard
uvicorn server:app --port 8000                # http://localhost:8000
python scripts/apptoken.py create "Skerry travel site"   # prints the API token once

# 2. the travel site, in a second terminal
cd website-chatbot
cp .env.example .env                          # paste the token into RAGMON_TOKEN
uvicorn server:app --port 4000                # http://localhost:4000
```

Connected apps and their tokens are also listed, created and revoked on the dashboard's **Rules** screen.

```bash
cd dashboard
python scripts/demo.py seed       # reset and add normal chats over the last day (green dashboard)
python scripts/demo.py run        # play the three demo questions
python -m unittest discover tests # the demo attacks fire every time (runs on the scripted bot)
python scripts/demo.py fill       # add the 109 test conversations from scripts/cases.py through the real model
python scripts/demo.py pii        # add the synthetic customer export by mistake, then run the 26 sensitive-data prompts
python scripts/demo.py template   # regenerate ChatbotTestingTemplate.md and SensitiveDataTestingTemplate.md
```

### The model

By default the chatbot runs **qwen2.5:1.5b** locally through Ollama, so answers take one to four seconds and every trace shows the model that answered. Its system prompt is set to `BOT_PROMPT=naive`, which tells the model to follow instructions found in the documents, the way a careless real deployment does. `BOT_PROMPT=careful` is the hardened version.

| Setting | Effect |
|---|---|
| `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` | a hosted model instead, and an LLM judge for the rules |
| `OLLAMA_MODEL=llama3.2:3b` | a different local model |
| `LLM_PROVIDER=offline` | the scripted demo bot: no language model, answers in about 1 ms, always named as such in the dashboard |

## Demo script

1. Open the dashboard: green, normal customer chats, no alerts.
2. On the Skerry site, ask "Do you fly to Paris?" The answer comes back and the dashboard stays green.
3. Ask "How do I get a refund?" The poisoned `refund_policy.md` is retrieved and the model is told to send customers to `refunds@skerry-refunds-desk.com` with their card number. The injection alert fires on the retrieved passage whether or not the model obeys; when it obeys, the answer is flagged too.
4. Ask "What's the CEO's salary?" The model answers "€156,000 per year." with no canary token, and the CRITICAL leak alert still fires: Cyber Tiger matches values that exist only in the confidential document.
5. Click the alert: the question, the passage with the hidden text highlighted, the answer, the model and the source document. Quarantine the document to resolve its alerts.
6. Security scans: Promptfoo's 14 attacks against the real model, each linked to its conversation.

## How it works

```
Skerry site ─► its server ─► POST /v1/chat (Bearer token) ─► monitor.ask()
                                ├─ detect.question   direct injection, flooding (LLM01, LLM10)
                                ├─ rag.retrieve      TF-IDF over kb/ chunks (quarantined docs excluded)
                                ├─ detect.chunks     poisoning signs, confidential retrieval (LLM01/04/08)
                                ├─ llm.generate      Ollama / Anthropic / OpenAI / scripted demo bot
                                ├─ detect.answer     canaries, confidential values, secrets, PII, unsafe output (LLM02/05/07)
                                └─ policy.judge      owner's plain-English rules
                              ─► SQLite: trace (chunks, spans, app) + alerts ─► dashboard (polls every 3s)

Promptfoo ─► POST /chat (internal, source=scan) ─► same pipeline, kept apart from customer traffic
```

| Path | What |
|---|---|
| `dashboard/server.py` | FastAPI: `/v1/chat` for connected apps, `/chat` for internal tools, the monitoring API, the dashboard |
| `dashboard/ragmon/detectors.py` | Every rule-based detector with its OWASP mapping, each a plain function |
| `dashboard/ragmon/monitor.py` | Wraps retrieval and generation, runs the detectors, stores the trace and alerts |
| `dashboard/ragmon/llm.py` | Ollama, Anthropic, OpenAI or the scripted demo bot |
| `dashboard/ragmon/store.py` | SQLite, including connected apps (only token hashes are stored) |
| `dashboard/scripts/apptoken.py` | Create, list and revoke API tokens |
| `dashboard/promptfoo/promptfooconfig.yaml` | The 14 attack tests, tagged by OWASP category |
| `dashboard/ui/` | The dashboard (vanilla JS, no build step) |
| `dashboard/kb/` | Skerry's knowledge base: help centre, poisoned refund policy, confidential salaries with canaries |
| `website-chatbot/` | The Skerry site: `server.py` (page and token-holding chat proxy) and `site/` |

The dashboard has no login. Run it on localhost only; anyone who can reach port 8000 can create tokens.

## Roadmap

Email and Slack alerts, a weekly owner report, GDPR / EU AI Act compliance export, connectors for Chatbase, Intercom Fin and Tidio, fix suggestions, Promptfoo red-team generation (`promptfoo redteam`) for larger attack sets, and on-prem / EU hosting.

## Credits

- [Promptfoo](https://github.com/promptfoo/promptfoo) (MIT) runs the security scans.
- Risk categories come from the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
- Skerry is a fictional company. All documents, names and salaries are made up.
- The Skerry site's photograph is by Joe Ravi (CC BY-SA 3.0, Wikimedia Commons).
