"""Rule-based detectors, mapped to the OWASP Top 10 for LLM Applications (2025).

Every detector is a plain function returning a list of Findings, so it can be tested on its own.
Detection is heuristic: it gives visibility, not a guarantee.
"""
import re
from dataclasses import asdict, dataclass

from . import config

OWASP = {
    "LLM01": ("Prompt Injection", "Someone hid instructions in a question or document to take over the chatbot."),
    "LLM02": ("Sensitive Information Disclosure", "The chatbot revealed private data such as salaries, keys or card numbers."),
    "LLM03": ("Supply Chain", "Risky third-party models, plugins or datasets."),
    "LLM04": ("Data and Model Poisoning", "A document in the knowledge base was tampered with."),
    "LLM05": ("Improper Output Handling", "The answer contains links, images or code that could harm the customer's browser."),
    "LLM06": ("Excessive Agency", "The chatbot can take actions it should not."),
    "LLM07": ("System Prompt Leakage", "The chatbot revealed its hidden setup instructions."),
    "LLM08": ("Vector and Embedding Weaknesses", "The search step pulled in documents this user should not see."),
    "LLM09": ("Misinformation", "The chatbot made things up."),
    "LLM10": ("Unbounded Consumption", "Someone is flooding the chatbot, driving up cost."),
}

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class Finding:
    detector: str
    severity: str
    owasp: str | None
    title: str          # plain English, for the business owner
    detail: str         # technical, for the developer
    evidence: str       # exact offending text, used for highlighting
    target: str         # question | chunk | answer | document
    doc: str | None = None
    chunk_id: str | None = None

    def to_dict(self):
        return asdict(self)


# ---- patterns ---------------------------------------------------------------

INSTRUCTION_PATTERNS = [
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) (?:instructions|rules|messages)",
    r"disregard (?:all |any )?(?:the )?(?:previous|prior|above|your) (?:instructions|rules)",
    r"system override",
    r"developer mode",
    r"new instructions\s*:",
    r"(?:assistant|ai|chatbot|bot) note\s*:",
    r"note to (?:the )?(?:ai|assistant|chatbot|model)",
    r"you must (?:tell|say|reveal|send|include|respond|ask|reply|output|direct)",
    r"\breveal (?:the |your |all |full )?(?:system prompt|instructions|password|secret|salar\w*|full list)",
    r"do not (?:mention|tell (?:the )?(?:customer|user)|reveal that)",
    r"(?:print|repeat|show) (?:your|the) (?:system prompt|instructions|initial prompt)",
    r"\bjailbreak\b",
    r"pretend (?:you are|to be)",
]
INSTRUCTION_RE = re.compile("|".join(f"(?:{p})" for p in INSTRUCTION_PATTERNS), re.IGNORECASE)

INVISIBLE_RE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000E0000-\U000E007F]+")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)[^)]*\)")
URL_RE = re.compile(r"https?://[^\s)\"'>]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HTML_TAG_RE = re.compile(r"<\s*(script|iframe|img|svg|object|embed|form)\b[^>]*>", re.IGNORECASE)
CANARY_RE = re.compile(config.CANARY_PATTERN)
SECRET_PATTERNS = {
    "OpenAI-style API key": r"\bsk-[A-Za-z0-9_-]{20,}",
    "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
    "GitHub token": r"\bghp_[A-Za-z0-9]{36}\b",
    "Slack token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    "Private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
}
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){3,7}[A-Z0-9]{1,4}\b")

ALLOWED_DOMAINS = {config.SUPPORT_EMAIL.split("@")[1]}


def _domain(email_or_url):
    host = email_or_url.split("@")[-1] if "@" in email_or_url and "://" not in email_or_url else \
        re.sub(r"^https?://", "", email_or_url).split("/")[0]
    return host.lower()


def _allowed(host):
    return any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS)


def _luhn(digits):
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


# ---- text scanners (used on retrieved chunks and on uploaded documents) ----

def scan_text(text, *, doc, chunk_id, owasp_injection="LLM01", target="chunk"):
    """Look for poisoning signs inside knowledge-base text."""
    findings = []
    where = f"{doc}" + (f" (chunk {chunk_id})" if chunk_id else "")

    for m in INSTRUCTION_RE.finditer(text):
        findings.append(Finding(
            "instruction_in_document", "HIGH", owasp_injection,
            f"Hidden instructions found in '{doc}' that try to control the chatbot",
            f"Instruction-like phrase matched in {where}: {m.group(0)!r}",
            m.group(0), target, doc, chunk_id))

    for m in INVISIBLE_RE.finditer(text):
        codes = " ".join(f"U+{ord(c):04X}" for c in m.group(0)[:6])
        findings.append(Finding(
            "invisible_unicode", "HIGH", owasp_injection,
            f"Invisible characters hidden in '{doc}'",
            f"{len(m.group(0))} zero-width/bidi/tag characters ({codes}) in {where}",
            m.group(0), target, doc, chunk_id))

    for m in HTML_COMMENT_RE.finditer(text):
        findings.append(Finding(
            "hidden_html_comment", "MEDIUM", owasp_injection,
            f"Text in '{doc}' is hidden from human readers but visible to the chatbot",
            f"HTML comment ({len(m.group(1).strip())} chars) in {where}",
            m.group(0), target, doc, chunk_id))

    for m in MD_IMAGE_RE.finditer(text):
        findings.append(Finding(
            "markdown_image_exfil", "HIGH", owasp_injection,
            f"'{doc}' contains an image link that can leak data to {_domain(m.group(1))}",
            f"Markdown image pointing to external host in {where}: {m.group(1)}",
            m.group(0), target, doc, chunk_id))

    image_urls = {m.group(1) for m in MD_IMAGE_RE.finditer(text)}
    for url in URL_RE.findall(text):
        if url not in image_urls and not _allowed(_domain(url)):
            findings.append(Finding(
                "external_url", "LOW", owasp_injection,
                f"'{doc}' links to an unknown website ({_domain(url)})",
                f"External URL in {where}: {url}", url, target, doc, chunk_id))

    for email in set(EMAIL_RE.findall(text)):
        if not _allowed(_domain(email)):
            findings.append(Finding(
                "unknown_email_in_document", "MEDIUM", owasp_injection,
                f"'{doc}' mentions an email address outside your company ({email})",
                f"Non-allowlisted email in {where}: {email}", email, target, doc, chunk_id))
    return findings


def scan_document(name, content, chunks):
    """Upload-time scan of a whole document before it enters the knowledge base (OWASP LLM04)."""
    findings = []
    for chunk in chunks:
        findings += scan_text(chunk["text"], doc=name, chunk_id=chunk["chunk_id"],
                              owasp_injection="LLM04", target="document")
    return _dedupe(findings)


# ---- per-conversation detectors ---------------------------------------------

def check_question(question, session, recent_count):
    findings = []
    for m in INSTRUCTION_RE.finditer(question):
        findings.append(Finding(
            "direct_injection_attempt", "MEDIUM", "LLM01",
            "A user tried to trick the chatbot into breaking its rules",
            f"Instruction-like phrase in user input: {m.group(0)!r}", m.group(0), "question"))
        break
    if len(question) > config.MAX_QUESTION_CHARS:
        findings.append(Finding(
            "oversized_input", "LOW", "LLM10",
            "Someone sent an unusually long message",
            f"Input length {len(question)} > {config.MAX_QUESTION_CHARS} chars", question[:80], "question"))
    if recent_count >= config.MAX_QUERIES_PER_MINUTE:
        findings.append(Finding(
            "query_flood", "MEDIUM", "LLM10",
            "One visitor is flooding the chatbot with messages",
            f"Session {session!r} sent {recent_count + 1} queries in 60s (limit {config.MAX_QUERIES_PER_MINUTE})",
            session or "", "question"))
    return findings


def check_retrieval(retrieved):
    findings, confidential_seen = [], set()
    for c in retrieved:
        findings += scan_text(c["text"], doc=c["doc"], chunk_id=c["chunk_id"])
        if c.get("classification") == "confidential" and c["doc"] not in confidential_seen:
            confidential_seen.add(c["doc"])
            findings.append(Finding(
                "confidential_doc_retrieved", "MEDIUM", "LLM08",
                f"A confidential document ('{c['doc']}') was pulled into a customer chat",
                f"Chunk {c['chunk_id']} with classification=confidential retrieved (score {c['score']:.2f})",
                "", "chunk", c["doc"], c["chunk_id"]))
    return _dedupe(findings)


def _source_of(token, retrieved):
    for c in retrieved:
        if token in c["text"]:
            return c["doc"], c["chunk_id"]
    return None, None


def check_answer(answer, retrieved):
    findings = []

    tokens = sorted(set(CANARY_RE.findall(answer)))
    if tokens:
        doc, chunk_id = _source_of(tokens[0], retrieved)
        findings.append(Finding(
            "canary_leak", "CRITICAL", "LLM02",
            "Confidential data leaked to a customer" + (f" from '{doc}'" if doc else ""),
            f"{len(tokens)} canary token(s) {', '.join(tokens)} present in answer; source chunk {chunk_id or 'unknown'}",
            "\n".join(tokens), "answer", doc, chunk_id))

    if config.SYSTEM_PROMPT_CANARY in answer:
        findings.append(Finding(
            "system_prompt_leak", "CRITICAL", "LLM07",
            "The chatbot revealed its hidden setup instructions",
            f"System prompt canary {config.SYSTEM_PROMPT_CANARY} present in answer",
            config.SYSTEM_PROMPT_CANARY, "answer"))

    for label, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, answer):
            doc, chunk_id = _source_of(m.group(0), retrieved)
            findings.append(Finding(
                "secret_in_answer", "CRITICAL", "LLM02",
                f"The chatbot revealed a secret key ({label})",
                f"{label} pattern in answer", m.group(0), "answer", doc, chunk_id))

    for m in CARD_RE.finditer(answer):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            findings.append(Finding(
                "card_number_in_answer", "HIGH", "LLM02",
                "The chatbot shared something that looks like a payment card number",
                "Luhn-valid 13-19 digit sequence in answer", m.group(0), "answer"))
    for m in IBAN_RE.finditer(answer):
        findings.append(Finding(
            "iban_in_answer", "HIGH", "LLM02",
            "The chatbot shared something that looks like a bank account (IBAN)",
            "IBAN-like pattern in answer", m.group(0), "answer"))

    for email in sorted(set(EMAIL_RE.findall(answer))):
        if not _allowed(_domain(email)):
            doc, chunk_id = _source_of(email, retrieved)
            findings.append(Finding(
                "unknown_contact_in_answer", "HIGH", "LLM01",
                f"The chatbot sent a customer to an unknown email address ({email})",
                "Non-allowlisted email in answer" + (f", copied from {doc} chunk {chunk_id}" if doc else "")
                + " — typical outcome of indirect prompt injection (phishing redirect)",
                email, "answer", doc, chunk_id))

    for m in MD_IMAGE_RE.finditer(answer):
        findings.append(Finding(
            "markdown_image_in_answer", "HIGH", "LLM05",
            f"The answer contains a hidden image that can send data to {_domain(m.group(1))}",
            f"Markdown image to external host in answer: {m.group(1)}", m.group(0), "answer"))
    for m in HTML_TAG_RE.finditer(answer):
        findings.append(Finding(
            "html_in_answer", "MEDIUM", "LLM05",
            "The answer contains web code that could run in the customer's browser",
            f"Active HTML tag <{m.group(1)}> in answer", m.group(0), "answer"))
    return _dedupe(findings)


def _dedupe(findings):
    """One alert per detector per chunk; repeated matches are merged into its evidence (one per line)."""
    groups = {}
    for f in findings:
        key = (f.detector, f.doc, f.chunk_id)
        if key not in groups:
            groups[key] = f
        elif f.evidence not in groups[key].evidence.split("\n"):
            groups[key].evidence += "\n" + f.evidence
            groups[key].detail += "; " + f.detail
    return list(groups.values())


def worst(findings):
    return max((SEVERITY_RANK[f.severity] for f in findings), default=0)
