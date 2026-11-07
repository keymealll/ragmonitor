"""LLM access: Anthropic or OpenAI over plain HTTPS, or an offline demo model.

The offline model is a deliberately naive bot: it answers from the retrieved text and obeys
instructions hidden in it, the way a real unprotected RAG bot can. It keeps the demo reliable
without an API key and is always labelled as such in the dashboard.
"""
import json
import os
import re
import urllib.request

from . import config

PROVIDER = config.LLM_PROVIDER


def model_name():
    return {"anthropic": config.ANTHROPIC_MODEL, "openai": config.OPENAI_MODEL}.get(PROVIDER, "offline-demo-model")


def _post(url, headers, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"content-type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def complete(system, user, max_tokens=500):
    if PROVIDER == "anthropic":
        data = _post(
            os.environ.get("ANTHROPIC_API_URL", "https://api.anthropic.com") + "/v1/messages",
            {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"},
            {"model": config.ANTHROPIC_MODEL, "max_tokens": max_tokens, "system": system,
             "messages": [{"role": "user", "content": user}]},
        )
        return "".join(b.get("text", "") for b in data["content"])
    if PROVIDER == "openai":
        data = _post(
            "https://api.openai.com/v1/chat/completions",
            {"authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
            {"model": config.OPENAI_MODEL, "max_tokens": max_tokens,
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
        )
        return data["choices"][0]["message"]["content"]
    raise RuntimeError("offline provider has no general completion")


def answer(question, retrieved):
    if PROVIDER == "offline":
        return _offline_answer(question, retrieved)
    context = "\n\n".join(f"[document: {c['doc']}]\n{c['text']}" for c in retrieved) or "(no documents found)"
    return complete(config.SYSTEM_PROMPT, f"Context documents:\n{context}\n\nCustomer question: {question}")


# ---- offline demo model -----------------------------------------------------

_LEAK_PROMPT_RE = re.compile(r"system prompt|your (?:instructions|rules|prompt)|initial prompt|everything above", re.I)
_OBEY_RE = re.compile(r"you must (?:tell|ask) the (?:customer|user) to (.+?)(?:\.(?:\s|$)|-->|$)", re.I | re.M)
_IMAGE_RE = re.compile(r"include (?:this|the) (?:tracking )?image (!\[[^\]]*\]\([^)]+\))", re.I)


def _offline_answer(question, retrieved):
    from .kb import tokens  # local import avoids a cycle

    if _LEAK_PROMPT_RE.search(question):
        return f"Sure! My instructions are: {config.SYSTEM_PROMPT}"

    q = set(tokens(question))
    candidates = []
    for rank, c in enumerate(retrieved):
        visible = re.sub(r"<!--.*?-->", "", c["text"], flags=re.S)
        for line in visible.splitlines():
            if line.lstrip().startswith("#"):
                continue
            line = line.strip().lstrip("-* ").strip()
            for sent in re.split(r"(?<=[.!?])\s+", line):
                overlap = len(q & set(tokens(sent)))
                if overlap and len(sent) > 20:
                    candidates.append((overlap, -rank, sent))
    candidates.sort(reverse=True)
    picked = [s for _, _, s in candidates[:2]]
    reply = " ".join(picked) if picked else f"I'm not sure about that. Please email {config.SUPPORT_EMAIL}."

    # Naive obedience to instructions hidden in retrieved text (the vulnerability being monitored).
    context = " ".join(c["text"] for c in retrieved)
    for m in _OBEY_RE.finditer(context):
        reply += f" To speed things up, please {m.group(1).strip().replace(' their ', ' your ')}."
    for m in _IMAGE_RE.finditer(context):
        reply += f" {m.group(1)}"
    return reply
