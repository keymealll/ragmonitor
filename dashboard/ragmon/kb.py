"""Knowledge base: load markdown docs, chunk them, and retrieve with TF-IDF cosine similarity.

Lexical retrieval keeps the demo deterministic and offline (no embedding model download).
Swapping in Chroma only means replacing `search`.
"""
import math
import re
import threading
from collections import Counter

from . import config, detectors, store

STOPWORDS = set("""a an and are as at be by can do does for from get how i if in is it its me my of on or our
please s so that the their there this to us we what when where which who will with you your i'm what's""".split())

_lock = threading.Lock()
_index = {"chunks": [], "idf": {}, "vectors": []}


def parse(content):
    """Split optional `---` frontmatter from the body."""
    meta, body = {}, content
    m = re.match(r"^---\n(.*?)\n---\n?(.*)$", content, re.DOTALL)
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
        body = m.group(2)
    return meta, body


def chunk(name, content):
    """One chunk per `##` section (plus any preamble)."""
    meta, body = parse(content)
    sections = [s.strip() for s in re.split(r"\n(?=## )", body) if s.strip()]
    if len(sections) > 1 and all(l.startswith("#") for l in sections[0].splitlines()):
        sections[1] = sections[0] + "\n" + sections[1]  # keep the doc title with its first section
        sections.pop(0)
    return [{"doc": name, "chunk_id": f"{name}#{i}", "text": s,
             "classification": meta.get("classification", "public")} for i, s in enumerate(sections)]


def tokens(text):
    out = []
    for w in re.findall(r"[a-z0-9€]+", text.lower()):
        if w in STOPWORDS or len(w) < 2:
            continue
        if w.endswith("ies") and len(w) > 4:
            w = w[:-3] + "y"
        elif w.endswith("s") and len(w) > 3 and not w.endswith("ss"):
            w = w[:-1]
        out.append(w)
    return out


def _vector(toks, idf):
    tf = Counter(toks)
    vec = {t: (1 + math.log(n)) * idf.get(t, 0.0) for t, n in tf.items()}
    norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
    return {t: v / norm for t, v in vec.items()}


def rebuild():
    """Index every document that is not quarantined."""
    chunks = []
    for d in store.documents():
        if d["status"] != "quarantined":
            chunks += chunk(d["name"], d["content"])
    df = Counter(t for c in chunks for t in set(tokens(c["text"])))
    n = len(chunks) or 1
    idf = {t: math.log((n + 1) / (k + 0.5)) for t, k in df.items()}
    with _lock:
        _index.update(chunks=chunks, idf=idf, vectors=[_vector(tokens(c["text"]), idf) for c in chunks])


def vocabulary():
    """Every token the indexed documents contain."""
    with _lock:
        return set(_index["idf"])


def doc_names():
    with _lock:
        return sorted({c["doc"] for c in _index["chunks"]})


def search(question, k=config.TOP_K, min_score=0.08):
    with _lock:
        q = _vector(tokens(question), _index["idf"])
        scored = [(sum(q.get(t, 0) * v for t, v in vec.items()), c)
                  for vec, c in zip(_index["vectors"], _index["chunks"])]
    scored.sort(key=lambda x: -x[0])
    return [{**c, "score": round(s, 3)} for s, c in scored[:k] if s >= min_score]


def load_folder(scan=False):
    """Register the docs in kb/ as the bot's existing knowledge base."""
    for path in sorted(config.KB_DIR.glob("*.md")):
        add_document(path.name, path.read_text(encoding="utf-8"), scan=scan)
    rebuild()


def add_document(name, content, scan=True):
    """Add or replace a document. With scan=True, risky docs are quarantined before they reach the bot."""
    meta, _ = parse(content)
    findings, status = [], "unscanned"
    if scan:
        findings = detectors.scan_document(name, content, chunk(name, content))
        sev = detectors.worst(findings)
        status = "quarantined" if sev >= detectors.SEVERITY_RANK["HIGH"] else "warning" if sev else "clean"
    store.upsert_document(name, meta.get("title", name), meta.get("classification", "public"), status,
                          content, [f.to_dict() for f in findings], scanned=scan)
    return status, findings
