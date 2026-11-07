"""Plain-English policy checks.

With an LLM key, an LLM judge checks each answer against the owner's rules.
Without one, a small rule-based fallback handles the common rule shapes:
"only refer customers to <email>" and "never share/ask for <topic>".
"""
import json
import re

from . import detectors, llm

JUDGE_PROMPT = """You are a compliance checker for a small business chatbot.
The business owner wrote these rules:
{rules}

Customer question: {question}
Chatbot answer: {answer}

For each rule the ANSWER breaks, return an object. Return ONLY a JSON array, e.g.
[{{"rule": 2, "reason": "one short sentence"}}] or [] if no rule is broken."""

GENERIC = {"any", "all", "staff", "information", "details", "customer", "customers", "people", "number", "numbers",
           "other", "their", "personal", "data", "the", "about", "with", "for"}


def _stem(w):
    w = w.lower()
    return w[:-3] if w.endswith("ies") else w[:-1] if w.endswith("s") else w


def _fallback(rule, answer):
    text = answer.lower()
    allowed = re.findall(detectors.EMAIL_RE, rule)
    if re.search(r"\bonly\b", rule, re.I) and allowed:
        others = [e for e in set(re.findall(detectors.EMAIL_RE, answer)) if e.lower() not in {a.lower() for a in allowed}]
        if others:
            return f"Answer points to {', '.join(sorted(others))} instead of {allowed[0]}"
    m = re.search(r"never (?:share|reveal|mention|give out|disclose|discuss|ask (?:\w+ )?for) (.+?)(?:\.|$)", rule, re.I)
    if m:
        stems = [_stem(w) for w in re.findall(r"[a-zA-Z]+", m.group(1))
                 if w.lower() not in GENERIC and w.lower() not in {"or", "and"} and len(w) > 3]
        words = re.findall(r"[a-z]+", text)
        hits = sorted({s for s in stems if len(s) >= 4 and any(w.startswith(s) for w in words)})
        if hits:
            return f"Answer mentions: {', '.join(hits)}"
    return None


def judge(question, answer, policies):
    """Return (findings, engine)."""
    if not policies or not answer:
        return [], "none"
    violations = []
    if llm.PROVIDER in ("offline", "ollama"):  # a 1-3B local model is too weak to judge its own answers
        engine = "rule-based checks"
        for p in policies:
            reason = _fallback(p["text"], answer)
            if reason:
                violations.append((p, reason))
    else:
        engine = f"LLM judge ({llm.model_name()})"
        rules = "\n".join(f"{i + 1}. {p['text']}" for i, p in enumerate(policies))
        try:
            raw = llm.complete("You output only JSON.", JUDGE_PROMPT.format(rules=rules, question=question, answer=answer), 300)
            for v in json.loads(raw[raw.find("["): raw.rfind("]") + 1] or "[]"):
                idx = int(v.get("rule", 0)) - 1
                if 0 <= idx < len(policies):
                    violations.append((policies[idx], v.get("reason", "")))
        except Exception as e:  # judge failure must never break the chat
            engine = f"rule-based fallback (judge error: {type(e).__name__})"
            violations = [(p, r) for p in policies if (r := _fallback(p["text"], answer))]
    findings = [detectors.Finding(
        "policy_violation", "HIGH", None,
        f"Broke your rule: “{p['text']}”",
        f"{engine}: {reason}", reason, "answer") for p, reason in violations]
    return findings, engine
