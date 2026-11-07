"""LLM access: Anthropic or OpenAI over plain HTTPS, a local model through Ollama, or an offline demo model.

The offline model is a scripted stand-in, not a language model: it copies sentences from the retrieved
text and obeys instructions hidden in it. It answers in about a millisecond, so it is only a fallback for
when no model is available, and the dashboard always names it.
"""
import json
import os
import re
import urllib.request

from . import config

def _ollama_has_model():
    try:
        with urllib.request.urlopen(config.OLLAMA_URL + "/api/tags", timeout=1) as r:
            names = {m["name"] for m in json.loads(r.read()).get("models", [])}
        return config.OLLAMA_MODEL in names or f"{config.OLLAMA_MODEL}:latest" in names
    except (OSError, ValueError):
        return False


def _detect():
    if config.LLM_PROVIDER:
        return config.LLM_PROVIDER
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "ollama" if _ollama_has_model() else "offline"


PROVIDER = _detect()


def model_name():
    return {"anthropic": config.ANTHROPIC_MODEL, "openai": config.OPENAI_MODEL,
            "ollama": config.OLLAMA_MODEL}.get(PROVIDER, "scripted-demo-bot")


def model_label():
    """How the dashboard names the model in plain words."""
    if PROVIDER == "offline":
        return "scripted demo bot (no language model)"
    return f"{model_name()} via {PROVIDER}"


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
    if PROVIDER == "ollama":
        data = _post(
            config.OLLAMA_URL + "/api/chat", {},
            {"model": config.OLLAMA_MODEL, "stream": False, "options": {"temperature": 0.2, "num_predict": max_tokens},
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
        )
        return data["message"]["content"]
    raise RuntimeError("the scripted demo bot has no general completion")


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
