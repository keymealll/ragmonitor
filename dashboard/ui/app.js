"use strict";
// Cyber Tiger dashboard: vanilla JS, hash router, polls the API every 3s.

const $ = (sel, root = document) => root.querySelector(sel);
const main = $("#main");
// Screen state lives in the URL (#/alerts?status=all&owasp=LLM01), so a filtered view survives a reload or a shared link.
const listParam = (p, k) => new Set((p.get(k) || "").split(",").filter(Boolean));
function alertFilter() {
  const p = route().params;
  return { status: p.get("status") || "open", source: p.get("source") || "live", sev: listParam(p, "sev"), owasp: listParam(p, "owasp") };
}
function alertsHref(f) {
  const q = new URLSearchParams();
  if (f.status !== "open") q.set("status", f.status);
  if (f.source !== "live") q.set("source", f.source);
  if (f.sev.size) q.set("sev", [...f.sev].join(","));
  if (f.owasp.size) q.set("owasp", [...f.owasp].join(","));
  return "#/alerts" + (q.size ? "?" + q : "");
}
/** Swap the query of the current screen without a history entry or a scroll jump, then redraw. */
function setQuery(hash) { history.replaceState(null, "", hash); render(); }
const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_WORD = { 4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW" };
const SEV_LABEL = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", OK: "OK", FAIL: "Failed", PASS: "Passed" };
const SEV_COLOR = { CRITICAL: "var(--sev-critical)", HIGH: "var(--sev-high)", MEDIUM: "var(--sev-medium)", LOW: "var(--sev-low)" };
const OWASP_SHORT = {
  LLM01: "Prompt injection", LLM02: "Sensitive data leak", LLM03: "Supply chain", LLM04: "Data poisoning",
  LLM05: "Unsafe output", LLM06: "Excessive agency", LLM07: "System prompt leak", LLM08: "Retrieval access",
  LLM09: "Misinformation", LLM10: "Unbounded consumption",
};
const STATUS_LABEL = { unscanned: "Not scanned", clean: "Clean", warning: "Warnings", quarantined: "Quarantined", approved: "Approved by owner" };
const COVER_LABEL = { live: "Live monitoring", scan: "Promptfoo scan", upload: "Upload scan", "n/a": "Not applicable" };

// ---------------------------------------------------------------- utilities

const store = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "content-type": "application/json" }, ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `${res.status} ${res.statusText}`);
  return res.json();
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const clip = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1).trimEnd() + "…" : s; };
/** The model that answered a trace, in plain words. "offline:…" is the scripted stand-in, never a language model. */
const modelOf = (m) => String(m || "").startsWith("offline") ? "the scripted demo bot (no language model)" : String(m || "").split(":").slice(1).join(":");
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

function ago(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const sev = (s) => `<span class="sev ${esc(s)}">${esc(SEV_LABEL[s] || s)}</span>`;
const owaspTag = (code, detector) => code
  ? `<span class="tag" title="OWASP Top 10 for LLM Applications"><span class="code">${esc(code)}</span><span> ${esc(OWASP_SHORT[code] || "")}</span></span>`
  : `<span class="tag">${detector === "knowledge_gap" ? "Knowledge gap" : "Your rule"}</span>`;
/** The facet an alert files under: its OWASP code, a knowledge gap, or the owner's rules. */
const catOf = (a) => a.owasp || (a.detector === "knowledge_gap" ? "GAP" : "POLICY");
const CAT_LABEL = { POLICY: "Your rules", GAP: "Knowledge gaps" };
const docStatus = (st) => `<span class="status ${esc(st)}">${esc(STATUS_LABEL[st] || st)}</span>`;
const bySeverity = (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || b.id - a.id;

const INVISIBLE = /[​-‏‪-‮⁠-⁤﻿]|[\u{E0000}-\u{E007F}]/gu;
const showInvisible = (html) => html.replace(INVISIBLE, (c) => `<span class="zw" title="invisible character">U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}</span>`);

/** Escape `text` and wrap every occurrence of each needle in <mark>. Invisible characters are made visible. */
function highlight(text, needles) {
  text = String(text ?? "");
  const ranges = [];
  const lower = text.toLowerCase();
  for (const n of new Set(needles.filter((x) => x && x.length > 0))) {
    const ln = n.toLowerCase();
    for (let i = lower.indexOf(ln); i !== -1; i = lower.indexOf(ln, i + ln.length)) ranges.push([i, i + ln.length]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]); else merged.push([...r]);
  }
  let out = "", pos = 0;
  for (const [a, b] of merged) {
    out += showInvisible(esc(text.slice(pos, a))) + `<mark>${showInvisible(esc(text.slice(a, b)))}</mark>`;
    pos = b;
  }
  return out + showInvisible(esc(text.slice(pos)));
}
const needlesOf = (alerts) => alerts.flatMap((a) => (a.evidence || "").split("\n"));

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 3500);
}

function openModal(html) {
  $("#modal-body").innerHTML = html;
  $("#modal").showModal();
}
function closeModal() { $("#modal").close(); }

// ---------------------------------------------------------------- tooltip + chart

const tip = $("#tooltip");
function showTip(e, html) {
  tip.innerHTML = html; tip.hidden = false;
  const r = tip.getBoundingClientRect();
  let x = e.clientX + 14, y = e.clientY + 14;
  if (x + r.width > innerWidth - 8) x = e.clientX - r.width - 14;
  if (y + r.height > innerHeight - 8) y = e.clientY - r.height - 14;
  tip.style.translate = `${x}px ${y}px`;
}
const hideTip = () => (tip.hidden = true);

/** Stacked bar timeseries. series: [{label, color, values}] */
function barChart(el, labels, series) {
  const W = Math.max(280, el.clientWidth), H = el.clientHeight || 220;
  const padL = 32, padB = 24, padT = 8, n = labels.length, narrow = W < 480;
  const totals = labels.map((_, i) => series.reduce((s, x) => s + x.values[i], 0));
  const rawMax = Math.max(1, ...totals);
  const steps = narrow ? 2 : 4;
  const mag = Math.pow(10, Math.floor(Math.log10(Math.max(1, rawMax / steps))));
  const tick = rawMax <= steps ? 1 : Math.ceil(rawMax / steps / mag) * mag;
  const max = Math.ceil(rawMax / tick) * tick;
  const plotW = W - padL, plotH = H - padB - padT, slot = plotW / n, bw = Math.min(24, Math.max(2, slot - 3));
  const y = (v) => padT + plotH - (v / max) * plotH;
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(series.map((s) => s.label).join(", "))} over time"><g class="axis">`;
  for (let v = tick; v <= max; v += tick) {
    svg += `<line class="gridline" x1="${padL}" x2="${W}" y1="${y(v)}" y2="${y(v)}"/><text x="${padL - 6}" y="${y(v) + 3}" text-anchor="end">${v}</text>`;
  }
  svg += `<line class="baseline" x1="${padL}" x2="${W}" y1="${y(0)}" y2="${y(0)}"/><text x="${padL - 6}" y="${y(0) + 3}" text-anchor="end">0</text>`;
  const every = Math.ceil(n / (narrow ? 3 : 6));
  labels.forEach((ts, i) => {
    if (i % every === 0) {
      const txt = new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      svg += `<text x="${padL + i * slot + slot / 2}" y="${H - 5}" text-anchor="middle">${txt}</text>`;
    }
  });
  svg += `</g>`;
  labels.forEach((_, i) => {
    let base = 0;
    const x = padL + i * slot + (slot - bw) / 2;
    series.forEach((s) => {
      const v = s.values[i];
      if (!v) return;
      const gap = base > 0 ? 2 : 0;
      const top = y(base + v), bottom = y(base) - gap;
      svg += `<rect x="${x}" y="${top}" width="${bw}" height="${Math.max(2, bottom - top)}" rx="1.5" fill="${s.color}"/>`;
      base += v;
    });
    svg += `<rect class="hit" data-i="${i}" x="${padL + i * slot}" y="${padT}" width="${slot}" height="${plotH}" fill="transparent"/>`;
  });
  el.innerHTML = svg + "</svg>";
  el._chart = { labels, series, w: el.clientWidth };
  if (!el._ro && "ResizeObserver" in window) {
    el._ro = new ResizeObserver(() => { if (el._chart && Math.abs(el.clientWidth - el._chart.w) > 4) barChart(el, el._chart.labels, el._chart.series); });
    el._ro.observe(el);
  }
  el.querySelectorAll(".hit").forEach((r) => {
    r.addEventListener("mousemove", (e) => {
      const i = +r.dataset.i, d = new Date(labels[i] * 1000);
      const rows = series.map((s) => `<div class="row"><span><i style="background:${s.color}"></i>${esc(SEV_LABEL[s.label] || s.label)}</span><b>${s.values[i]}</b></div>`).join("");
      showTip(e, `<div class="head">${d.toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" })}</div>${rows}`);
    });
    r.addEventListener("mouseleave", hideTip);
  });
}

// ---------------------------------------------------------------- shared fragments

function alertRow(a, { showQuestion = true } = {}) {
  return `<li class="${a.status === "resolved" ? "resolved" : ""}" data-href="#/traces/${a.trace_id}?alert=${a.id}">
    <div>${sev(a.severity)}</div>
    <div>
      <div class="t">${esc(a.title)}</div>
      ${showQuestion && a.question ? `<div class="d">Customer asked “${esc(a.question)}”</div>` : ""}
      ${a.doc ? `<div class="d">Source: ${esc(a.doc)}</div>` : ""}
    </div>
    <div class="when">${owaspTag(a.owasp, a.detector)}<div>${ago(a.ts)}</div></div>
  </li>`;
}

function bindLinks(root = main) {
  root.querySelectorAll("[data-href]").forEach((el) => el.addEventListener("click", (e) => {
    if (e.target.closest("button, a")) return;
    location.hash = el.dataset.href;
  }));
}

function crumbs(parts) {
  $("#crumbs").innerHTML = parts.map((p, i) => (i ? `<span class="sep" aria-hidden="true">/</span>` : "") + p).join("");
}

const regionHead = (title, right = "") => `<div class="region-head"><h2>${title}</h2>${right ? `<div class="sub">${right}</div>` : ""}</div>`;

/** The incident on paper: the customer's card, the passage that caused it, the answer. */
function incidentPaper(t, focusAlert) {
  const withChunk = t.alerts.filter((a) => a.chunk_id).sort(bySeverity);
  const chunkId = (focusAlert && focusAlert.chunk_id) || withChunk[0]?.chunk_id;
  const chunk = t.retrieved.find((c) => c.chunk_id === chunkId) || t.retrieved[0];
  const chunkAlerts = chunk ? t.alerts.filter((a) => a.chunk_id === chunk.chunk_id) : [];
  const answerAlerts = t.alerts.filter((a) => a.target === "answer");
  return `<div class="incident">
    <div class="stock index-card"><div class="who">A customer asked, ${ago(t.ts)}</div><div class="said">“${esc(t.question)}”</div></div>
    ${chunk ? `<div class="stock sheet ${chunkAlerts.length ? "flagged" : ""}">
      <div class="sheet-head"><a href="#/kb/${encodeURIComponent(chunk.doc)}">${esc(chunk.doc)}</a><span class="muted small">the passage the chatbot read</span></div>
      <pre>${highlight(chunk.text, needlesOf(chunkAlerts))}</pre></div>` : ""}
    <div class="stock sheet"><div class="sheet-head"><b>What the chatbot answered</b></div>
      <p class="answer-text">${highlight(t.answer, needlesOf(answerAlerts))}</p></div>
  </div>`;
}

// ---------------------------------------------------------------- pages

const pages = {};

pages.overview = async () => {
  const range = route().params.get("range") === "24h" ? "24h" : "1h";
  const [o, ow, open, gapList] = await Promise.all([
    api(`/api/overview?range=${range}`), api("/api/owasp"), api("/api/alerts?status=open&limit=200"), api("/api/gaps"),
  ]);
  const top = open.find((a) => a.id === o.top_alert_id);
  const incident = top ? await api(`/api/traces/${top.trace_id}`).catch(() => null) : null;
  crumbs([`<b>Overview</b>`, `<span>${esc(o.status.company)} support chatbot</span>`]);
  const k = o.kpis;
  const word = { green: "All clear", amber: "Needs attention", red: "Action needed now" }[o.color];
  const latest = open.filter((a) => a.detector !== "knowledge_gap").sort(bySeverity).slice(0, 6);
  main.innerHTML = `
  <div class="page-head">
    <div><h1>Is my chatbot safe right now?</h1>
      <p>Every customer conversation is checked for leaks, tampered documents and broken rules.</p></div>
    <div class="seg" role="group" aria-label="Time range">
      <button type="button" data-range="1h" aria-pressed="${range === "1h"}">Past 1 hour</button>
      <button type="button" data-range="24h" aria-pressed="${range === "24h"}">Past 24 hours</button>
    </div>
  </div>

  <section class="verdict" aria-label="Safety">
    <div>
      ${o.color === "green" ? `<span class="pressed">All clear</span>` : `<h2 class="verdict-word"><span class="verdict-mark ${o.color}">${o.color === "red" ? "Red" : "Amber"}</span>${word}</h2>`}
      <div class="score" aria-label="Safety score ${o.score} out of 100">${o.score}<small> / 100 safety score</small></div>
      <p class="reason">${esc(o.reason)}</p>
      ${top ? `<a class="btn primary" href="#/traces/${top.trace_id}?alert=${top.id}">See what happened</a>` : ""}
      <dl class="ledger">
        <div><dt>Conversations, 24h<small>real customer chats</small></dt><dd>${k.conversations_24h}</dd></div>
        <div><dt>Open alerts<small>${k.critical_open} critical</small></dt><dd class="${k.open_alerts ? "bad" : ""}">${k.open_alerts}</dd></div>
        <div><dt>Data leaks, 24h<small>private data in answers</small></dt><dd class="${k.leaks_24h ? "bad" : ""}">${k.leaks_24h}</dd></div>
        <div><dt>Documents at risk<small>in your knowledge base</small></dt><dd class="${k.docs_at_risk ? "bad" : ""}">${k.docs_at_risk}<small> of ${k.docs_total}</small></dd></div>
        <div><dt>Avg response time<small>per answer</small></dt><dd>${k.avg_latency_ms}<small> ms</small></dd></div>
      </dl>
    </div>
    <div>${incident ? incidentPaper(incident, top) : `<div class="empty"><b>Nothing to show right now.</b>When something goes wrong, the exact sentence that caused it appears here, on the document it came from.</div>`}</div>
  </section>


  <div class="cols region">
    <section>${regionHead("Conversations", range === "1h" ? "per minute" : "per 30 minutes")}<div class="chart" id="ch-conv"></div></section>
    <section>${regionHead("Alerts by severity", `<span class="legend">${SEV_ORDER.map((s) => `<span><i style="background:${SEV_COLOR[s]}"></i>${SEV_LABEL[s]}</span>`).join("")}</span>`)}<div class="chart" id="ch-alerts"></div></section>
  </div>

  <div class="cols-21 region">
    <section>${regionHead("Latest open alerts", `<a href="#/alerts">All alerts</a>`)}
      ${latest.length ? `<ul class="list">${latest.map((a) => alertRow(a)).join("")}</ul>` : `<div class="empty"><b>Nothing to worry about.</b>New problems show up here within seconds.</div>`}</section>
    <div><section>${regionHead("Questions your documents miss", `<a href="#/alerts?status=all&owasp=GAP">All gaps</a>`)}
      ${gapList.length ? `<ul class="list">${gapList.map((g) => `
        <li data-href="#/traces/${g.trace_id}" style="grid-template-columns:minmax(0,1fr) auto"><div><div class="t">${esc(g.topic)}</div>
          <div class="d">last asked ${ago(g.last_ts)}</div></div><div class="when"><span class="mono">${g.n}</span> ${g.n === 1 ? "chat" : "chats"}</div></li>`).join("")}</ul>`
        : `<div class="empty"><b>No gaps yet.</b>Topics customers ask about that no document covers show up here.</div>`}</section>
    <section class="region">${regionHead("Riskiest documents", `<a href="#/kb">Knowledge base</a>`)}
      ${o.top_docs.length ? `<ul class="list">${o.top_docs.map((d) => `
        <li data-href="#/kb/${encodeURIComponent(d.name)}" style="grid-template-columns:auto minmax(0,1fr)">
          <div>${sev(SEV_WORD[d.risk])}</div>
          <div><div class="t">${esc(d.title)}</div><div class="d mono">${esc(d.name)}</div><div class="d">${plural(d.open_alerts, "open alert")}, used in ${plural(d.retrievals, "chat")}</div><div class="d">${docStatus(d.status)}</div></div></li>`).join("")}</ul>`
        : `<div class="empty"><b>No risky documents.</b>Documents that cause alerts are ranked here.</div>`}</section>
  <section class="region">${regionHead("OWASP Top 10 for LLM apps", `<a href="#/owasp">Full risk map</a>`)}
    <div class="table-wrap"><table class="resp"><thead><tr><th>Risk</th><th>Right now</th><th>Last scan</th></tr></thead><tbody>
    ${ow.map((c) => `<tr class="click" data-owasp="${c.code}">
      <td data-label=""><span class="mono">${c.code}</span> ${esc(OWASP_SHORT[c.code])}</td>
      <td data-label="Now">${c.open_alerts ? `${sev(c.worst)} ${plural(c.open_alerts, "open alert")}` : `<span class="muted">${c.coverage.length === 0 ? "Not covered yet" : c.coverage.includes("n/a") ? "Not applicable" : "No issues"}</span>`}</td>
      <td data-label="Scan">${c.scan_passed + c.scan_failed ? `<span class="mono">${c.scan_passed}/${c.scan_passed + c.scan_failed}</span> passed` : `<span class="muted">Not scanned</span>`}</td></tr>`).join("")}
    </tbody></table></div></section>
  </div></div>`;

  const s = o.series;
  barChart($("#ch-conv"), s.labels, [{ label: "Conversations", color: "var(--series-1)", values: s.conversations }]);
  barChart($("#ch-alerts"), s.labels, SEV_ORDER.map((k2) => ({ label: k2, color: SEV_COLOR[k2], values: s[k2] })));
  main.querySelectorAll("[data-range]").forEach((b) => b.addEventListener("click", () => setQuery(b.dataset.range === "24h" ? "#/overview?range=24h" : "#/overview")));
  main.querySelectorAll("[data-owasp]").forEach((c) => c.addEventListener("click", () => {
    location.hash = `#/alerts?status=all&owasp=${c.dataset.owasp}`;
  }));
  bindLinks();
};

pages.alerts = async () => {
  const f = alertFilter();
  const all = await api(`/api/alerts?source=${f.source}&status=all&limit=500`);
  crumbs([`<b>Alerts</b>`]);
  const byStatus = all.filter((a) => f.status === "all" || a.status === f.status);
  const shown = byStatus.filter((a) => (!f.sev.size || f.sev.has(a.severity)) && (!f.owasp.size || f.owasp.has(catOf(a))));
  const count = (key, val) => byStatus.filter((a) => (key === "owasp" ? catOf(a) : a[key]) === val).length;
  const owaspKeys = [...Object.keys(OWASP_SHORT), "POLICY", "GAP"].filter((c) => count("owasp", c) || f.owasp.has(c));
  main.innerHTML = `
  <div class="page-head"><div><h1>Alerts</h1>
    <p>Every problem the monitor found. Open one to see the exact document and sentence behind it.</p></div>
    <div class="seg" role="group" aria-label="Traffic">
      <button type="button" data-source="live" aria-pressed="${f.source === "live"}">Customer chats</button>
      <button type="button" data-source="scan" aria-pressed="${f.source === "scan"}">Security scan traffic</button></div></div>
  <div class="cols-side">
    <details class="facets" open><summary>Filters</summary>
      <h3>Status</h3>${["open", "resolved", "all"].map((s) => `<label><input type="radio" name="st" value="${s}" ${f.status === s ? "checked" : ""}> ${s[0].toUpperCase() + s.slice(1)}</label>`).join("")}
      <h3>Severity</h3>${SEV_ORDER.map((s) => `<label><input type="checkbox" data-f="sev" value="${s}" ${f.sev.has(s) ? "checked" : ""}> ${SEV_LABEL[s]}<span class="n">${count("severity", s)}</span></label>`).join("")}
      <h3>Category</h3>${owaspKeys.map((c) => `<label><input type="checkbox" data-f="owasp" value="${c}" ${f.owasp.has(c) ? "checked" : ""}> <span>${CAT_LABEL[c] || `<span class="mono">${c}</span> <span class="muted">${OWASP_SHORT[c]}</span>`}</span><span class="n">${count("owasp", c)}</span></label>`).join("") || `<div class="muted">No alerts</div>`}
      ${f.sev.size || f.owasp.size ? `<button type="button" class="btn quiet small" id="clear-f">Clear filters</button>` : ""}
    </details>
    <section>${regionHead(plural(shown.length, "alert"), shown.some((a) => a.status === "open") ? `<button type="button" class="btn small" id="resolve-all">Mark shown as resolved</button>` : "")}
      ${shown.length ? `<ul class="list">${shown.map((a) => alertRow(a)).join("")}</ul>` : `<div class="empty"><b>No alerts match.</b>Clear a filter to see more.</div>`}</section>
  </div>`;
  main.querySelectorAll("[data-source]").forEach((b) => b.addEventListener("click", () => { f.source = b.dataset.source; setQuery(alertsHref(f)); }));
  main.querySelectorAll("input[name=st]").forEach((r) => r.addEventListener("change", () => { f.status = r.value; setQuery(alertsHref(f)); }));
  main.querySelectorAll("input[data-f]").forEach((c) => c.addEventListener("change", () => {
    const set = f[c.dataset.f]; c.checked ? set.add(c.value) : set.delete(c.value); setQuery(alertsHref(f));
  }));
  $("#clear-f")?.addEventListener("click", () => { f.sev.clear(); f.owasp.clear(); setQuery(alertsHref(f)); });
  $("#resolve-all")?.addEventListener("click", async () => {
    await Promise.all(shown.filter((a) => a.status === "open").map((a) => api(`/api/alerts/${a.id}/resolve`, { method: "POST" })));
    toast("Alerts marked as resolved"); render();
  });
  bindLinks();
};

pages.traces = async () => {
  const source = route().params.get("source") === "scan" ? "scan" : "live";
  const rows = await api(`/api/traces?source=${source}`);
  crumbs([`<b>Conversations</b>`]);
  main.innerHTML = `
  <div class="page-head"><div><h1>Conversations</h1>
    <p>Every question your customers asked, what the chatbot looked up, and what it answered.</p></div>
    <div class="seg" role="group" aria-label="Traffic">
      <button type="button" data-src="live" aria-pressed="${source === "live"}">Customer chats</button>
      <button type="button" data-src="scan" aria-pressed="${source === "scan"}">Security scan traffic</button></div></div>
  ${rows.length ? `<div class="table-wrap"><table class="resp"><thead><tr><th>Time</th><th>Status</th><th>Question</th><th>Answer</th><th>Documents used</th><th class="num">Alerts</th><th class="num">Answered in</th></tr></thead><tbody>
    ${rows.map((t) => `<tr class="click" data-href="#/traces/${t.id}">
      <td class="nowrap muted mono" data-label="">${clock(t.ts)}</td>
      <td data-label="">${t.worst ? sev(SEV_WORD[t.worst]) : sev("OK")}</td>
      <td data-label=""><span class="t">${esc(clip(t.question, 70))}</span></td>
      <td data-label="" class="dim">${esc(clip(t.answer, 110))}</td>
      <td class="dim" data-label="Documents">${t.docs.map(esc).join(", ") || "None"}</td>
      <td class="num" data-label="Alerts">${t.alerts}</td>
      <td class="num" data-label="Answered in">${(t.latency_ms / 1000).toFixed(1)} s</td></tr>`).join("")}</tbody></table></div>`
    : `<div class="empty"><b>No conversations yet.</b>Open the customer chat and ask something.</div>`}`;
  main.querySelectorAll("[data-src]").forEach((b) => b.addEventListener("click", () => setQuery(b.dataset.src === "scan" ? "#/traces?source=scan" : "#/traces")));
  bindLinks();
};

/** An alert title for the story: the story already names the file once, so drop "from 'file'" and "in 'file'". */
const storyLine = (title) => title.replace(/,? (?:copied )?from '[^']+'/, "").replace(/ in '[^']+'/, "").replace(/ \('[^']+'\)/, "")
  .replace(/'[^']+' /, "the file ").replace(/^./, (c) => c.toUpperCase());
const LEAKS = new Set(["canary_leak", "confidential_value_leak", "personal_data_in_answer", "secret_in_answer", "card_number_in_answer", "iban_in_answer"]);

/** Leak alerts become one line that says what was given out; other answer problems keep their own line. */
function answerLines(alerts) {
  const leaks = alerts.filter((a) => LEAKS.has(a.detector));
  const values = [...new Set(leaks.flatMap((a) => (a.evidence || "").split("\n")).filter(Boolean))];
  const lines = values.length ? [`It gave private data to whoever was asking: <b>${values.map(esc).join(", ")}</b>.`] : [];
  for (const a of alerts.filter((x) => !LEAKS.has(x.detector))) lines.push(esc(storyLine(a.title)));
  return [...new Set(lines)].map((l) => `<li>${l}</li>`).join("");
}

const SPAN_COLOR = (name) => name.startsWith("chat") ? "var(--series-1)" : name.startsWith("rag") ? "var(--series-3)"
  : name.startsWith("llm") ? "var(--series-2)" : name.startsWith("policy") ? "var(--series-5)" : "var(--series-4)";

pages.trace = async (id, params) => {
  const t = await api(`/api/traces/${id}`);
  const focus = Number(params.get("alert"));
  crumbs([`<a href="#/traces">Conversations</a>`, `<b>#${t.id}</b>`]);
  const chunkAlerts = (c) => t.alerts.filter((a) => a.chunk_id === c.chunk_id);
  const answerAlerts = t.alerts.filter((a) => a.target === "answer");
  const isPoison = (a) => a.target === "chunk" && a.detector !== "confidential_doc_retrieved";
  const flaggedChunks = t.retrieved.filter((c) => chunkAlerts(c).some(isPoison));
  const confidential = [...new Set(t.retrieved.filter((c) => c.classification === "confidential").map((c) => c.doc))];
  const docs = [...new Set(t.retrieved.filter((c) => c.classification !== "attachment").map((c) => c.doc))];
  const worstDoc = t.alerts.filter((a) => a.doc).sort(bySeverity)[0]?.doc;

  const story = [`<li>A ${t.source === "scan" ? "security scan" : "customer"} asked <b>“${esc(t.question)}”</b></li>`];
  const uploads = t.retrieved.filter((c) => c.classification === "attachment");
  if (uploads.length) story.push(`<li class="${uploads.some((c) => chunkAlerts(c).length) ? "bad" : "warn"}">They attached <b>${esc(uploads.map((c) => c.doc.replace(/^upload: /, "")).join(", "))}</b>, and the chatbot read it like one of your documents.</li>`);
  const docLabel = (d, i) => `<b>${esc(d)}</b>${confidential.includes(d) ? (i < docs.length - 1 ? ", which is confidential," : ", which is confidential") : ""}`;
  story.push(`<li class="${confidential.length ? "warn" : ""}">The chatbot searched your knowledge base and pulled in ${plural(t.retrieved.length - uploads.length, "passage")} from ${docs.map(docLabel).join(" and ") || "no documents"}.</li>`);
  if (flaggedChunks.length) story.push(`<li class="bad">${flaggedChunks.length === 1 ? "One passage" : `${flaggedChunks.length} passages`} contained something suspicious:
    <ul>${[...new Set(t.alerts.filter(isPoison).map((a) => storyLine(a.title)))].map((x) => `<li>${esc(x)}</li>`).join("")}</ul></li>`);
  story.push(`<li class="${answerAlerts.length ? "bad" : ""}">The chatbot, running ${esc(modelOf(t.model))}, answered in ${(t.latency_ms / 1000).toFixed(1)} s.
    ${answerAlerts.length ? `The answer was a problem:<ul>${answerLines(answerAlerts)}</ul>` : ""}</li>`);
  const gapsHere = t.alerts.filter((a) => a.detector === "knowledge_gap");
  if (gapsHere.length) story.push(`<li class="warn">Your documents don't mention <b>${esc(gapsHere.map((a) => a.evidence).join(", "))}</b>.</li>`);
  const realAlerts = t.alerts.filter((a) => a.detector !== "knowledge_gap");
  story.push(!realAlerts.length && gapsHere.length
    ? `<li><b>What to do:</b> nothing is broken. If customers should get an answer about ${esc(gapsHere[0].evidence)}, add it to your <a href="#/kb">knowledge base</a>.</li>`
    : realAlerts.length
    ? `<li class="bad"><b>What to do:</b> ${worstDoc ? `<a href="#/kb/${encodeURIComponent(worstDoc)}">open ${docs.length > 1 ? "the file" : "that file"}</a> and quarantine it, so the chatbot can no longer read it, or remove the highlighted text.` : "review the answer below and tighten your rules."}</li>`
    : `<li>No problems found in this conversation.</li>`);

  const end = Math.max(1, ...t.spans.map((s) => s.start_ms + s.duration_ms));
  main.innerHTML = `
  <div class="page-head"><div><h1>Conversation #${t.id}</h1>
    <div class="meta"><span>${new Date(t.ts * 1000).toLocaleString()}</span><span>${plural(t.alerts.length, "alert")}</span></div></div>
    ${worstDoc ? `<a class="btn primary" href="#/kb/${encodeURIComponent(worstDoc)}">Open source document</a>` : ""}</div>
  <div class="cols-21">
    <div>
      <section>${regionHead("What happened")}<ol class="story">${story.join("")}</ol></section>
      <section class="region">${regionHead("Passages the chatbot read", `${t.retrieved.length} retrieved; highlights show the problem text`)}
        <div class="stack">${t.retrieved.map((c) => {
          const al = chunkAlerts(c);
          return `<article class="stock sheet ${al.some((a) => a.detector !== "confidential_doc_retrieved") ? "flagged" : ""}">
            <div class="sheet-head"><a href="#/kb/${encodeURIComponent(c.doc)}">${esc(c.doc)}</a>
              <span class="row-actions">${c.classification === "confidential" ? `<span class="tag">Confidential</span>` : c.classification === "attachment" ? `<span class="tag">Customer upload</span>` : ""}
              ${al.length ? sev(SEV_WORD[Math.max(...al.map((a) => 4 - SEV_ORDER.indexOf(a.severity)))]) : ""}
              <span class="mono muted small">match ${c.score.toFixed(2)}</span></span></div>
            <pre>${highlight(c.text, needlesOf(al))}</pre></article>`;
        }).join("") || `<div class="empty"><b>Nothing was retrieved.</b>The chatbot answered without your documents.</div>`}</div></section>
      <section class="region">${regionHead("Chatbot answer", esc(modelOf(t.model)))}
        <div class="stock sheet"><p class="answer-text">${highlight(t.answer, needlesOf(answerAlerts))}</p></div></section>
    </div>
    <div>
      <section>${regionHead("Alerts in this conversation")}
        ${t.alerts.length ? `<ul class="list">${t.alerts.slice().sort(bySeverity).map((a) => `
          <li class="${a.id === focus ? "focus" : ""} ${a.status === "resolved" ? "resolved" : ""}" style="grid-template-columns:auto minmax(0,1fr)">
            <div>${sev(a.severity)}</div><div><div class="t">${esc(storyLine(a.title))}</div>
            ${a.evidence ? `<div class="d"><code>${esc(a.detector)}</code> ${esc(clip(a.evidence.split("\n").join(", "), 120))}</div>` : `<div class="d"><code>${esc(a.detector)}</code></div>`}
            <div class="d">${owaspTag(a.owasp, a.detector)}</div>
            <div class="d">${a.status === "open" ? `<button type="button" class="btn small" data-resolve="${a.id}">Resolve</button>` : "Resolved"}</div></div></li>`).join("")}</ul>`
        : `<div class="empty"><b>No alerts.</b>This conversation passed every check.</div>`}</section>
      <section class="region">${regionHead("Timeline", `${Math.round(t.latency_ms)} ms total`)}
        <div class="waterfall">${t.spans.map((s) => `
          <div class="wf-row"><span class="nm" title="${esc(JSON.stringify(s.meta))}">${esc(s.name)}</span>
            <div class="wf-track"><div class="wf-bar" style="left:${(s.start_ms / end) * 100}%;width:${Math.max(0.6, (s.duration_ms / end) * 100)}%;background:${SPAN_COLOR(s.name)}"></div></div>
            <span class="ms">${s.duration_ms < 1 ? s.duration_ms.toFixed(2) : Math.round(s.duration_ms)} ms</span></div>`).join("")}
          <div class="legend region" style="margin-top:var(--space-md)"><span><i style="background:var(--series-1)"></i>Request</span><span><i style="background:var(--series-3)"></i>Retrieval</span><span><i style="background:var(--series-2)"></i>LLM</span><span><i style="background:var(--series-4)"></i>Detectors</span><span><i style="background:var(--series-5)"></i>Rules</span></div></div></section>
      <section class="region">${regionHead("Details")}
        <dl class="kv"><dt>trace_id</dt><dd>${t.id}</dd><dt>session</dt><dd>${esc(t.session)}</dd><dt>source</dt><dd>${esc(t.source)}</dd>
        <dt>app</dt><dd>${esc(t.app || "internal (/chat)")}</dd><dt>model</dt><dd>${esc(t.model)}</dd><dt>timestamp</dt><dd>${new Date(t.ts * 1000).toISOString()}</dd></dl></section>
    </div>
  </div>`;
  main.querySelectorAll("[data-resolve]").forEach((b) => b.addEventListener("click", async () => {
    b.setAttribute("aria-busy", "true"); b.disabled = true;
    await api(`/api/alerts/${b.dataset.resolve}/resolve`, { method: "POST" }); toast("Alert resolved"); render();
  }));
};

pages.kb = async () => {
  const docs = await api("/api/documents");
  crumbs([`<b>Knowledge base</b>`]);
  main.innerHTML = `
  <div class="page-head"><div><h1>Knowledge base</h1>
    <p>The documents your chatbot learns from, riskiest first. New documents are scanned before the chatbot can read them.</p></div>
    <div class="row-actions"><button type="button" class="btn" id="scan-all">Scan all documents</button><button type="button" class="btn primary" id="upload">Add document</button></div></div>
  <div class="table-wrap"><table class="resp"><thead><tr><th>Risk</th><th>Document</th><th>Status</th><th>Access</th><th class="num">Open alerts</th><th class="num">Used in chats</th><th><span class="visually-hidden">Actions</span></th></tr></thead><tbody>
  ${docs.map((d) => `<tr class="click" data-href="#/kb/${encodeURIComponent(d.name)}">
    <td data-label="">${d.risk ? sev(SEV_WORD[d.risk]) : sev("OK")}</td>
    <td data-label=""><div class="t">${esc(d.title)}</div><div class="d mono">${esc(d.name)}</div></td>
    <td data-label="">${docStatus(d.status)}${d.findings.length ? `<div class="d">${plural(d.findings.length, "scan finding")}</div>` : ""}</td>
    <td data-label="">${d.classification === "confidential" ? `<span class="tag">Confidential</span>` : `<span class="dim">Public</span>`}</td>
    <td class="num" data-label="Open alerts">${d.open_alerts}</td><td class="num" data-label="Used in chats">${d.retrievals}</td>
    <td data-label=""><div class="row-actions">${d.status === "quarantined" ? `<button type="button" class="btn small" data-approve="${esc(d.name)}">Restore</button>` : `<button type="button" class="btn small danger" data-quarantine="${esc(d.name)}">Quarantine</button>`}</div></td></tr>`).join("")}
  </tbody></table></div>`;
  bindDocActions();
  $("#scan-all").addEventListener("click", async (e) => {
    e.currentTarget.setAttribute("aria-busy", "true"); e.currentTarget.disabled = true;
    const res = await api("/api/documents/scan", { method: "POST" });
    const q = res.filter((d) => d.status === "quarantined").length;
    toast(q ? `Scan finished: ${plural(q, "document")} quarantined` : "Scan finished: no problems found");
    render();
  });
  $("#upload").addEventListener("click", uploadDialog);
  bindLinks();
};

function bindDocActions() {
  main.querySelectorAll("[data-quarantine]").forEach((b) => b.addEventListener("click", async () => {
    b.setAttribute("aria-busy", "true"); b.disabled = true;
    const r = await api(`/api/documents/${encodeURIComponent(b.dataset.quarantine)}/quarantine`, { method: "POST" });
    toast(`Quarantined. The chatbot can no longer use it.${r.resolved ? ` ${plural(r.resolved, "related alert")} resolved.` : ""}`);
    render();
  }));
  main.querySelectorAll("[data-approve]").forEach((b) => b.addEventListener("click", async () => {
    b.setAttribute("aria-busy", "true"); b.disabled = true;
    await api(`/api/documents/${encodeURIComponent(b.dataset.approve)}/approve`, { method: "POST" });
    toast("Restored: the chatbot can use this document again"); render();
  }));
}

function bindClose() { $("#modal").querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", closeModal)); }

function uploadDialog() {
  openModal(`<div class="dialog-head"><h2>Add a document</h2><button type="button" class="btn quiet icon-btn" data-close aria-label="Close">
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg></button></div>
    <div class="dialog-body">
      <p class="dim">The document is checked for hidden instructions, invisible characters, tracking links and unknown contacts <b>before</b> the chatbot can read it.</p>
      <div><label class="field" for="up-file">File (.md, .txt or .csv)</label><input type="file" id="up-file" accept=".md,.txt,.csv,text/plain,text/markdown,text/csv"></div>
      <div><label class="field" for="up-name">Name</label><input type="text" id="up-name" name="name" autocomplete="off" placeholder="supplier_update.md"></div>
      <div><label class="field" for="up-text">Content</label><textarea id="up-text" name="content" placeholder="Paste text or pick a file"></textarea></div>
      <p class="small" id="up-help" aria-live="polite"></p>
      <div class="row-actions"><button type="button" class="btn quiet" data-close>Cancel</button><button type="button" class="btn primary" id="up-go">Scan and add</button></div>
    </div>`);
  bindClose();
  $("#up-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    $("#up-name").value = file.name; $("#up-text").value = await file.text();
  });
  $("#up-go").addEventListener("click", async () => {
    const name = $("#up-name").value.trim(), content = $("#up-text").value, help = $("#up-help");
    const missing = !name ? $("#up-name") : !content.trim() ? $("#up-text") : null;
    $("#up-name").toggleAttribute("aria-invalid", !name);
    $("#up-text").toggleAttribute("aria-invalid", !!name && !content.trim());
    if (missing) { help.textContent = "Add a name and some content first."; missing.focus(); return; }
    const go = $("#up-go");
    go.disabled = true; go.setAttribute("aria-busy", "true"); help.textContent = "Scanning…";
    try {
      const r = await api("/api/documents", { method: "POST", body: { name, content } });
      const blocked = r.status === "quarantined";
      $("#modal-body").innerHTML = `<div class="dialog-head"><h2>Scan result</h2><button type="button" class="btn quiet icon-btn" data-close aria-label="Close">
          <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg></button></div>
        <div class="dialog-body">
          <p class="mono small">${esc(r.name)}</p>
          ${blocked ? `<span class="pressed">Quarantined</span>` : ""}
          <div class="note ${blocked ? "bad" : r.status === "warning" ? "" : "good"}"><b>${blocked ? "Blocked. This document was quarantined before it reached your chatbot." : r.status === "warning" ? "Added, with warnings to review." : "Clean. The chatbot can now use this document."}</b></div>
          ${r.findings.length ? `<ul class="list">${r.findings.map((f) => `<li style="grid-template-columns:auto minmax(0,1fr)">${sev(f.severity)}<div><div class="t">${esc(f.title)}</div><div class="d">${owaspTag(f.owasp)} <span class="muted">${esc(f.detail)}</span></div></div></li>`).join("")}</ul>
            <h3>Flagged text</h3><pre class="doc-body">${highlight(content, needlesOf(r.findings))}</pre>` : ""}
          <div class="row-actions"><a class="btn" href="#/kb/${encodeURIComponent(r.name)}" data-close>Open document</a><button type="button" class="btn primary" data-close>Done</button></div></div>`;
      bindClose();
      render();
    } catch (err) {
      help.textContent = `That did not go through: ${err.message}. Try again.`;
      go.disabled = false; go.removeAttribute("aria-busy");
    }
  });
}

pages.doc = async (name) => {
  const [docs, alerts] = await Promise.all([api("/api/documents?include_backend=true"), api("/api/alerts?status=all&limit=500")]);
  const d = docs.find((x) => x.name === name);
  if (!d) { main.innerHTML = `<div class="empty"><b>Document not found.</b><a href="#/kb">Back to the knowledge base</a></div>`; return; }
  const related = alerts.filter((a) => a.doc === name);
  crumbs([d.source === "backend" ? `<span>Data source</span>` : `<a href="#/kb">Knowledge base</a>`, `<b>${esc(d.name)}</b>`]);
  const finding = (f) => `<li style="grid-template-columns:auto minmax(0,1fr)">${sev(f.severity)}<div><div class="t">${esc(f.title)}</div><div class="d">${owaspTag(f.owasp)} <span class="muted">${esc(f.detail)}</span></div></div></li>`;
  main.innerHTML = `
  <div class="page-head"><div><h1>${esc(d.title)}</h1>
    <div class="meta"><span class="mono">${esc(d.name)}</span>${docStatus(d.status)}<span>${d.classification === "confidential" ? "Confidential" : "Public"}</span><span>Used in ${plural(d.retrievals, "chat")}</span>${d.source === "backend" ? "<span>Connected behind the chatbot, not in your knowledge base</span>" : ""}</div></div>
    <div class="row-actions">${d.status === "quarantined" ? `<button type="button" class="btn" data-approve="${esc(d.name)}">Restore to chatbot</button>` : `<button type="button" class="btn danger" data-quarantine="${esc(d.name)}">Quarantine document</button>`}</div></div>
  <div class="cols-21">
    <article class="stock sheet">
      <div class="sheet-head"><b>Document text</b>${d.status === "quarantined" ? `<span class="pressed">Quarantined</span>` : `<span class="muted small">Highlights are text flagged by scans or live alerts</span>`}</div>
      <pre class="doc-body">${highlight(d.content, [...needlesOf(d.findings), ...needlesOf(related.filter((a) => a.target === "chunk" || a.target === "document" || a.chunk_id))])}</pre></article>
    <div>
      <section>${regionHead("Live alerts from this document", String(related.length))}
        ${related.length ? `<ul class="list">${related.slice(0, 12).map((a) => alertRow(a)).join("")}</ul>` : `<div class="empty"><b>No live alerts.</b>Customer chats have not been affected by this document.</div>`}</section>
      <section class="region">${regionHead("Upload scan", d.scanned_ts ? `scanned ${ago(d.scanned_ts)}` : "not scanned yet")}
        ${d.findings.length ? `<ul class="list">${d.findings.map(finding).join("")}</ul>`
          : `<div class="empty"><b>${d.scanned_ts ? "Clean." : "Not scanned yet."}</b>${d.scanned_ts ? "The scan found nothing suspicious." : "Use Scan all documents on the knowledge base page."}</div>`}</section>
    </div>
  </div>`;
  bindDocActions();
  bindLinks();
};

pages.scans = async () => {
  const s = await api("/api/scans/latest");
  crumbs([`<b>Security scans</b>`, `<span>Promptfoo</span>`]);
  const running = s.running;
  const head = `<div class="page-head"><div><h1>Security scans</h1>
    <p>Like a mystery shopper: known attack questions go to your chatbot, and every answer is checked.</p></div>
    <div class="row-actions">${running ? `<span class="chip" role="status"><span class="spin" aria-hidden="true"></span>&nbsp;Scan running</span>` : ""}<button type="button" class="btn primary" id="run-scan" ${running ? "disabled aria-busy=\"true\"" : ""}>Run scan now</button></div></div>`;
  if (!s.results) {
    main.innerHTML = head + `<div class="empty"><b>No scan results yet.</b>${s.last_run?.status === "failed" ? `The last run failed: <code>${esc(s.last_run.log)}</code>` : "Run a scan to test your chatbot."}</div>`;
  } else {
    const cats = Object.entries(s.by_owasp).sort();
    main.innerHTML = head + `
    <dl class="figures four">
      <div><dt>Attacks blocked</dt><dd class="${s.pass_rate < 50 ? "bad" : ""}">${s.pass_rate}<small>%, ${s.passed} of ${s.total} tests</small></dd></div>
      <div><dt>Weak spots found</dt><dd class="${s.failed ? "bad" : ""}">${s.failed}</dd></div>
      <div><dt>Last scan</dt><dd class="word">${ago(s.ts)}</dd></div>
      <div><dt>Engine</dt><dd class="word">Promptfoo</dd></div>
    </dl>
    ${s.last_run?.status === "failed" ? `<div class="note bad region">The last run failed: <code>${esc(s.last_run.log)}</code>. Showing the previous results.</div>` : ""}
    <div class="region">
      <section>${regionHead("By OWASP category", `<span class="legend"><span><i style="background:var(--sev-good)"></i>Passed</span><span><i style="background:var(--sev-critical)"></i>Failed</span></span>`)}
        <div class="cat-grid">${cats.map(([code, c]) => `<div>
          <div style="display:flex;justify-content:space-between;gap:var(--space-sm)"><span><span class="mono">${esc(code)}</span> ${esc(OWASP_SHORT[code] || "")}</span><span class="muted"><span class="mono">${c.passed}/${c.passed + c.failed}</span> passed</span></div>
          <div class="bar-h" title="${c.passed} passed, ${c.failed} failed">${c.passed ? `<span style="flex:${c.passed};background:var(--sev-good)"></span>` : ""}${c.failed ? `<span style="flex:${c.failed};background:var(--sev-critical)"></span>` : ""}</div></div>`).join("")}</div>
        <p class="muted small">Scan engine: <a href="https://github.com/promptfoo/promptfoo" target="_blank" rel="noopener">Promptfoo</a> (MIT). Scan traffic is kept apart from customer chats.</p></section>
    </div>
    <div class="region">
      <section>${regionHead("Test results", "open a row to see the conversation")}
        <div class="table-wrap"><table class="resp"><thead><tr><th>Result</th><th>Category</th><th>Attack</th><th>Chatbot answer</th><th>Failed checks</th></tr></thead><tbody>
        ${s.results.slice().sort((a, b) => a.passed - b.passed || a.owasp.localeCompare(b.owasp)).map((r) => `
          <tr class="${r.trace_id ? "click" : ""}" ${r.trace_id ? `data-href="#/traces/${r.trace_id}"` : ""}>
            <td data-label="">${r.passed ? sev("PASS") : sev("FAIL")}</td>
            <td data-label="">${owaspTag(r.owasp === "OTHER" ? null : r.owasp)}</td>
            <td data-label=""><div class="t">${esc(r.description)}</div><div class="d">“${esc(r.prompt)}”</div></td>
            <td class="dim" data-label="">${esc(clip(r.output, 150))}</td>
            <td class="mono" data-label="Failed checks">${r.failed_checks.map(esc).join("<br>")}</td></tr>`).join("")}
        </tbody></table></div></section>
    </div>`;
  }
  $("#run-scan").addEventListener("click", async () => {
    try { await api("/api/scans/run", { method: "POST" }); toast("Scan started. Results appear here in under a minute."); render(); }
    catch (e) { toast(e.message); }
  });
  bindLinks();
};

pages.owasp = async () => {
  const ow = await api("/api/owasp");
  crumbs([`<b>OWASP Top 10</b>`, `<span>risk map</span>`]);
  main.innerHTML = `
  <div class="page-head"><div><h1>OWASP Top 10 for LLM applications</h1>
    <p>The industry list of the ten biggest risks for AI chatbots, and how Cyber Tiger watches each one. Detection is heuristic: it gives visibility, not a guarantee.</p></div></div>
  <div class="table-wrap"><table class="resp"><thead><tr><th>Risk</th><th>What it means for you</th><th>How we watch it</th><th>Open alerts</th><th>Last scan</th></tr></thead><tbody>
  ${ow.map((c) => `<tr class="click" data-owasp="${c.code}">
    <td class="nowrap" data-label=""><span class="mono">${c.code}</span> <b>${esc(c.name)}</b></td>
    <td class="dim" data-label="">${esc(c.plain)}</td>
    <td data-label="">${c.coverage.length ? c.coverage.map((x) => `<span class="tag">${COVER_LABEL[x]}</span>`).join(" ") : `<span class="tag">Roadmap</span>`}</td>
    <td data-label="Open">${c.open_alerts ? `${sev(c.worst)} <span class="mono">${c.open_alerts}</span>` : `<span class="muted">None</span>`}</td>
    <td data-label="Scan">${c.scan_passed + c.scan_failed ? `${c.scan_failed ? sev("FAIL") : sev("PASS")} <span class="mono muted">${c.scan_passed}/${c.scan_passed + c.scan_failed}</span>` : `<span class="muted">Not scanned</span>`}</td></tr>`).join("")}
  </tbody></table></div>
  <p class="muted region">LLM06 does not apply: this chatbot cannot take actions. LLM03 (supply chain) is on the roadmap.</p>`;
  main.querySelectorAll("[data-owasp]").forEach((r) => r.addEventListener("click", () => {
    location.hash = `#/alerts?status=all&owasp=${r.dataset.owasp}`;
  }));
};

pages.policies = async () => {
  const [ps, st, apps] = await Promise.all([api("/api/policies"), api("/api/status"), api("/api/apps")]);
  crumbs([`<b>Rules</b>`]);
  main.innerHTML = `
  <div class="page-head"><div><h1>Your rules</h1>
    <p>Write rules in plain English. Every answer is checked against them, and an answer that breaks one raises an alert.</p></div>
    <span class="chip">Checked by ${esc(st.policy_engine)}</span></div>
  <div class="cols-21">
    <section>${regionHead(plural(ps.length, "rule"))}
      ${ps.length ? `<ul class="list">${ps.map((p) => `
        <li style="grid-template-columns:minmax(0,1fr) auto"><div class="t">“${esc(p.text)}”</div>
        <button type="button" class="btn small danger" data-del="${p.id}">Remove</button></li>`).join("")}</ul>` : `<div class="empty"><b>No rules yet.</b>Add one below, in your own words.</div>`}
      <form id="add-rule" class="region"><label class="field" for="rule-text">New rule</label>
        <div style="display:flex;gap:var(--space-xs)"><input type="text" id="rule-text" autocomplete="off" placeholder="Never promise delivery dates before 20 December">
        <button class="btn primary">Add rule</button></div></form>
    </section>
    <section>${regionHead("Connected apps")}
      <p class="dim small">Each website or app that sends its chatbot traffic here gets its own API token for <code>POST /v1/chat</code>.</p>
      ${apps.length ? `<ul class="list">${apps.map((a) => `
        <li class="${a.revoked ? "resolved" : ""}" style="grid-template-columns:minmax(0,1fr) auto"><div><div class="t">${esc(a.name)}</div>
          <div class="d"><span class="mono">${esc(a.token_prefix)}…</span> ${a.revoked ? "revoked" : a.last_used_ts ? `last used ${ago(a.last_used_ts)}` : "not used yet"}</div>
          <div class="d">${plural(a.conversations, "conversation")}</div></div>
          ${a.revoked ? "" : `<button type="button" class="btn small danger" data-revoke="${a.id}">Revoke</button>`}</li>`).join("")}</ul>`
        : `<div class="empty"><b>No apps connected yet.</b>Create a token and give it to your website.</div>`}
      <form id="add-app" class="region"><label class="field" for="app-name">App name</label>
        <div style="display:flex;gap:var(--space-xs)"><input type="text" id="app-name" autocomplete="off" placeholder="Skerry travel site">
        <button class="btn">Create token</button></div></form>
    </section>
  </div>`;
  main.querySelectorAll("[data-revoke]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm("Revoke this token? The app will stop getting answers until it has a new one.")) return;
    b.setAttribute("aria-busy", "true"); b.disabled = true;
    await api(`/api/apps/${b.dataset.revoke}`, { method: "DELETE" }); toast("Token revoked"); render();
  }));
  $("#add-app").addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = $("#app-name").value.trim();
    if (!name) { $("#app-name").setAttribute("aria-invalid", "true"); $("#app-name").focus(); return; }
    const r = await api("/api/apps", { method: "POST", body: { name } });
    openModal(`<div class="dialog-head"><h2>Token for ${esc(r.name)}</h2><button type="button" class="btn quiet icon-btn" data-close aria-label="Close">
        <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg></button></div>
      <div class="dialog-body"><p>Copy it now: it is shown once and only its hash is stored.</p>
        <pre class="doc-body note">RAGMON_TOKEN=${esc(r.token)}</pre>
        <p class="dim small">Put this line in the app’s server-side <code>.env</code>, never in browser code.</p>
        <div class="row-actions"><button type="button" class="btn primary" data-close>Done</button></div></div>`);
    bindClose();
    render();
  });
  main.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => {
    const rule = b.closest("li").querySelector(".t").textContent;
    if (!confirm(`Remove the rule ${rule}? Answers will no longer be checked against it.`)) return;
    b.setAttribute("aria-busy", "true"); b.disabled = true;
    await api(`/api/policies/${b.dataset.del}`, { method: "DELETE" }); render();
  }));
  $("#add-rule").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = $("#rule-text").value.trim();
    if (!text) { $("#rule-text").setAttribute("aria-invalid", "true"); $("#rule-text").focus(); return; }
    await api("/api/policies", { method: "POST", body: { text } }); toast("Rule added"); render();
  });
};

// ---------------------------------------------------------------- router

function route() {
  const [path, query] = (location.hash.slice(2) || "overview").split("?");
  const [page, arg] = path.split("/");
  return { page, arg: arg && decodeURIComponent(arg), params: new URLSearchParams(query) };
}

const LIVE_PAGES = new Set(["overview", "alerts", "traces", "kb", "scans", "owasp"]);
let rendering = false, skeletonTimer = 0;
const TABLE_PAGES = new Set(["alerts", "traces", "kb", "scans", "owasp", "policies"]);
function skeletonFor(page, arg) {
  if (page === "overview" || (arg && (page === "traces" || page === "kb"))) {
    return `<div class="skeleton" aria-label="Loading"><span class="sk-head"></span><div class="sk-split"><span></span><span></span></div></div>`;
  }
  return `<div class="skeleton" aria-label="Loading"><span class="sk-head"></span>${'<span class="sk-row"></span>'.repeat(TABLE_PAGES.has(page) ? 7 : 3)}</div>`;
}

async function render(silent = false) {
  if (rendering) return;
  rendering = true;
  const { page, arg, params } = route();
  if (!silent) skeletonTimer = setTimeout(() => { main.setAttribute("aria-busy", "true"); main.innerHTML = skeletonFor(page, arg); }, 150);
  document.querySelectorAll(".sidenav [data-route]").forEach((a) => {
    const on = a.dataset.route === page || (page === "trace" && a.dataset.route === "traces");
    a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  try {
    if (page === "traces" && arg) await pages.trace(arg, params);
    else if (page === "kb" && arg) await pages.doc(arg);
    else await (pages[page] || pages.overview)();
    updateBadge();
  } catch (e) {
    if (!silent) main.innerHTML = `<div class="note bad"><b>Could not load this screen.</b> ${esc(e.message)}. Check that the server is running, then reload.</div>`;
  } finally { clearTimeout(skeletonTimer); rendering = false; main.removeAttribute("aria-busy"); }
}

async function updateBadge() {
  const o = await api("/api/overview?range=1h").catch(() => null);
  if (!o) return;
  const b = $("#nav-alerts");
  b.hidden = !o.kpis.open_alerts; b.textContent = o.kpis.open_alerts;
  b.setAttribute("aria-label", `${o.kpis.open_alerts} open`);
  $("#model-chip").textContent = `${o.status.model_label}, ${o.status.bot_prompt} prompt`;
  $("#chat-site-link").href = o.status.chat_site_url;
}


function setTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  store.set("ragmon-theme", t || "");
}

$("#theme-btn").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  setTheme(dark ? "light" : "dark");
});
$("#reset-btn").addEventListener("click", async () => {
  if (!confirm("Reset the demo? This clears all conversations and alerts and reloads the original knowledge base.")) return;
  await api("/api/reset", { method: "POST" }); toast("Demo reset"); location.hash = "#/overview"; render();
});
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });

setTheme(store.get("ragmon-theme", "") || null);
addEventListener("hashchange", () => { hideTip(); render(); main.focus(); scrollTo(0, 0); });
setInterval(() => {
  const busy = $("#modal").open || document.activeElement?.matches("input, textarea, select") || !tip.hidden;
  if (!busy && document.visibilityState === "visible" && LIVE_PAGES.has(route().page) && !route().arg) render(true);
}, 3000);
render();
