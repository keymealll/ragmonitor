"""The monitoring wrapper: retrieval -> generation, with detectors on every step, stored as a trace."""
import time
from contextlib import contextmanager

from . import config, detectors, kb, llm, policy, store


class Tracer:
    def __init__(self):
        self.t0 = time.perf_counter()
        self.spans = []

    @contextmanager
    def span(self, name, **meta):
        start = time.perf_counter()
        s = {"name": name, "start_ms": round((start - self.t0) * 1000, 2), "meta": meta}
        try:
            yield s["meta"]
        finally:
            s["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
            self.spans.append(s)

    def total_ms(self):
        return round((time.perf_counter() - self.t0) * 1000, 2)


def ask(question, session="anonymous", source="live", ts=None):
    tr = Tracer()
    with tr.span("chat.request", session=session, source=source):
        recent = store.recent_queries(session, 60) if source == "live" else 0
        with tr.span("detect.question") as m:
            findings = detectors.check_question(question, session, recent)
            m["findings"] = len(findings)

        with tr.span("rag.retrieve", top_k=config.TOP_K) as m:
            retrieved = kb.search(question)
            m["chunks"] = len(retrieved)
        with tr.span("detect.chunks") as m:
            chunk_findings = detectors.check_retrieval(retrieved)
            findings += chunk_findings
            m["findings"] = len(chunk_findings)

        with tr.span("llm.generate", provider=llm.PROVIDER, model=llm.model_name()):
            try:
                answer = llm.answer(question, retrieved)
            except Exception as e:
                answer = f"Sorry, I'm having trouble right now. Please email {config.SUPPORT_EMAIL}."
                findings.append(detectors.Finding("llm_error", "LOW", None, "The chatbot failed to answer a customer",
                                                  f"{type(e).__name__}: {e}", "", "answer"))

        with tr.span("detect.answer") as m:
            answer_findings = detectors.check_answer(answer, retrieved)
            findings += answer_findings
            m["findings"] = len(answer_findings)
        with tr.span("policy.judge") as m:
            policy_findings, engine = policy.judge(question, answer, store.policies())
            findings += policy_findings
            m.update(engine=engine, findings=len(policy_findings))

    trace_id = store.save_trace(session=session, source=source, question=question, answer=answer,
                                model=f"{llm.PROVIDER}:{llm.model_name()}", latency_ms=tr.total_ms(),
                                retrieved=retrieved, spans=sorted(tr.spans, key=lambda s: s["start_ms"]), ts=ts)
    for f in findings:
        store.save_alert(trace_id, source, f, ts=ts)
    return {"answer": answer, "trace_id": trace_id, "alerts": [f.to_dict() for f in findings]}
