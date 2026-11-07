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
# Distinctive values in a confidential document: money, percentages, full names. Canaries only catch copy-paste;
# a model that rewrites "CEO salary: €156,000, ref CANARY-7f3a" as "€156,000 per year" still leaks the figure.
SENSITIVE_VALUE_RE = re.compile(r"[€$£]\s?\d[\d,.]*\d|\b\d{1,3}(?:[.,]\d+)?\s?%|\b[A-Z][a-z]{2,} [A-Z][a-z]{2,}\b")
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
        if c.get("classification") == "attachment":
            findings += check_attachment_data(c)
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

    public_text = " ".join(c["text"] for c in retrieved if c.get("classification") != "confidential")
    for c in retrieved:
        if c.get("classification") != "confidential":
            continue
        values = {v for v in SENSITIVE_VALUE_RE.findall(c["text"]) if v not in public_text}
        hits = sorted(v for v in values if v in answer)
        if hits:
            findings.append(Finding(
                "confidential_value_leak", "CRITICAL", "LLM02",
                f"Confidential data leaked to a customer from '{c['doc']}'",
                f"Answer repeats {len(hits)} value(s) found only in confidential chunk {c['chunk_id']}: {', '.join(hits)}",
                "\n".join(hits), "answer", c["doc"], c["chunk_id"]))

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


# ---- attachments, coverage, grounding and internal references -----------------

PASSPORT_RE = re.compile(r"\bpassport\b[^\n]{0,40}?\b([A-Z]{1,2}\d{6,8})\b", re.IGNORECASE)


def check_attachment_data(chunk):
    """Personal data inside a file a customer attached to the chat (it now sits in the bot's logs and context)."""
    text, found = chunk["text"], []
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            found.append(("payment card number", m.group(0)))
    for m in PASSPORT_RE.finditer(text):
        found.append(("passport number", m.group(1)))
    for m in IBAN_RE.finditer(text):
        found.append(("bank account (IBAN)", m.group(0)))
    if not found:
        return []
    kinds = sorted({k for k, _ in found})
    return [Finding(
        "attachment_personal_data", "MEDIUM", "LLM02",
        f"A customer uploaded a file containing a {kinds[0]}" + (f" and {len(kinds) - 1} more kind of personal data" if len(kinds) > 1 else ""),
        f"Attachment {chunk['doc']} holds {', '.join(kinds)}; it is now in the conversation log and the model's context",
        "\n".join(v for _, v in found), "chunk", chunk["doc"], chunk["chunk_id"])]


# Words that carry no topic, so a question made of them is never a knowledge gap.
CHAT_WORDS = set("""hello hey thank thanks please help question want need know tell like would could should will just really
good great okay yes all also which what when where who why how much many there here this that these those about any some
more most other into your you can make give take going have has had been being ask asking said say thing way time today
tomorrow now still sure right well let kind sort ever every even very only does doing done there their they them then than
hi hiya cheer love nice cool fine maybe guys mate bring carry heavy light big small cheap cheapest expensive price cost
pay paid allow allowed possible available option options best fast quick long short soon late early travel trip trips
fly flying flight flights plane airport go visit see find look use earn money detail details reply word words print
mode show list translate french repeat message instruction instructions secret rule rules restriction restrictions above
document documents admin hidden pretend answer link reset password image put work works working""".split())
REFUSAL_RE = re.compile(r"\b(?:don't|do not|not|no|sorry|unfortunately|can't|cannot|unable|isn't|aren't|doesn't|won't)\b", re.IGNORECASE)


def _prefixes(words):
    return {w[:5] for w in words}


def check_coverage(question, retrieved, vocab, tokenize):
    """A customer asked about something no document mentions: a gap the owner can fill (an insight, not an attack).
    Only when retrieval was weak too, so a well-answered question with one stray word is not a gap."""
    if (retrieved and retrieved[0]["score"] >= 0.35) or INSTRUCTION_RE.search(question) or re.search(r"<|\]\(|https?://", question):
        return []  # well answered, or an attack: neither is a content gap
    known = _prefixes(vocab)
    missing = []
    for w in tokenize(question):
        if w.isalpha() and len(w) >= 3 and w not in CHAT_WORDS and w[:5] not in known and w not in missing:
            missing.append(w)
    if not missing:
        return []
    return [Finding(
        "knowledge_gap", "LOW", None,
        f"Customers ask about {', '.join(missing[:3])}, which your documents don't cover",
        f"Question terms with no match anywhere in the knowledge base: {', '.join(missing)}",
        ", ".join(missing[:3]), "question")]


def check_grounding(question, answer, retrieved, tokenize):
    """OWASP LLM09: an answer that asserts things the retrieved passages never said. Refusals are left alone."""
    if not answer or REFUSAL_RE.search(answer):  # no passages at all and a confident answer is the clearest case
        return []
    # The question is not support: an answer that agrees with the customer's premise ("free insurance") is the risk.
    support = _prefixes(tokenize(" ".join(c["text"] for c in retrieved) + " " + config.SYSTEM_PROMPT))
    words = {w for w in tokenize(answer) if w.isalpha() and w not in CHAT_WORDS and len(w) >= 3}
    novel = sorted(w for w in words if w[:5] not in support)
    if len(words) >= 3 and len(novel) >= 2 and len(novel) / len(words) >= 0.3:
        return [Finding(
            "ungrounded_answer", "MEDIUM", "LLM09",
            f"The chatbot said something your documents don't support ({', '.join(novel[:3])})",
            f"{len(novel)} of {len(words)} content words in the answer appear in no retrieved passage: {', '.join(novel)}",
            "\n".join(novel[:6]), "answer")]
    return []


def check_internal_reference(answer, doc_names):
    """The answer names the bot's internal files or machinery to a customer."""
    patterns = [r"context documents?", r"the context( provided)?", r"provided documents?", r"knowledge base", r"system prompt",
                r"my instructions", r"\b[\w-]+\.md\b"]
    for name in doc_names:
        stem = name.rsplit(".", 1)[0]
        patterns.append(re.escape(stem.replace("_", " ")))
        if "_" in stem:
            patterns.append(re.escape(stem))
    hits = sorted({m.group(0) for m in re.finditer("|".join(f"(?:{p})" for p in patterns), answer, re.IGNORECASE)})
    if not hits:
        return []
    return [Finding(
        "internal_reference", "LOW", "LLM02",
        "The chatbot told a customer about its internal documents",
        f"Answer names internal files or machinery: {', '.join(hits)}", "\n".join(hits), "answer")]


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
