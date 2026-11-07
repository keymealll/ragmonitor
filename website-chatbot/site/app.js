"use strict";
// Skerry site: the live assistant, the route field behind the hero, and the bag calculator.

const $ = (s, r = document) => r.querySelector(s);
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

// ---------------------------------------------------------------- the assistant

const session = "site-" + Math.random().toString(36).slice(2, 10);
const log = $("#chat-log"), form = $("#chat-form"), input = $("#chat-input"), send = $("#chat-send");
const fileInput = $("#chat-file"), fileName = $("#chat-file-name");
let attachment = null;  // { name, content }: a text file the customer attached, sent with the next question

function clearAttachment() {
  attachment = null; fileInput.value = ""; fileName.hidden = true; fileName.textContent = "";
}
fileInput?.addEventListener("change", async () => {
  const file = fileInput.files[0];
  if (!file) return clearAttachment();
  if (file.size > 20000) { clearAttachment(); say("That file is too long. Attach a text file under 20 KB.", "msg--bot msg--error"); return; }
  attachment = { name: file.name, content: await file.text() };
  fileName.hidden = false;
  fileName.innerHTML = "";
  const label = document.createElement("span"); label.textContent = `Attached: ${file.name}`;
  const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove";
  remove.addEventListener("click", clearAttachment);
  fileName.append(label, remove);
  input.focus();
});

function say(text, kind) {
  const li = document.createElement("li");
  li.className = `msg ${kind}`;
  li.textContent = text;
  log.append(li);
  log.scrollTop = log.scrollHeight;
  return li;
}

function busy(on) {
  send.disabled = on;
  send.toggleAttribute("aria-busy", on);
  input.disabled = on;
}

async function ask(question) {
  const q = question.trim();
  if (!q || send.disabled) return;
  const sent = attachment;
  say(sent ? `${q}\n(attached ${sent.name})` : q, "msg--me");
  input.value = "";
  clearAttachment();
  busy(true);
  let waiting = null;
  const slow = setTimeout(() => { waiting = say("Looking that up…", "msg--bot msg--wait"); }, 200);
  try {
    const res = await fetch("/api/chat", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ question: q, session, ...(sent ? { attachment: sent } : {}) }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || "The assistant could not answer that. Try again in a moment.");
    clearTimeout(slow);
    const li = waiting || say("", "msg--bot");
    li.className = "msg msg--bot";
    li.textContent = data.answer || "I don't have an answer for that. Email support@skerry.ie and the team will help.";
  } catch (err) {
    clearTimeout(slow);
    const li = waiting || say("", "msg--bot");
    li.className = "msg msg--bot msg--error";
    li.textContent = err.message;
  } finally {
    busy(false);
    log.scrollTop = log.scrollHeight;
    input.focus({ preventScroll: true });
  }
}

form.addEventListener("submit", (e) => { e.preventDefault(); ask(input.value); });
log.scrollTop = log.scrollHeight;

// The trip picker hands the trip to the assistant; booking itself happens in the Skerry app.
$("#trip-form")?.addEventListener("submit", (e) => {
  e.preventDefault();
  const f = new FormData(e.currentTarget);
  $("#ask").scrollIntoView({ block: "center", behavior: reduced ? "auto" : "smooth" });
  ask(`I want to book a trip from ${f.get("from")} to ${f.get("to")}. How do I do it, and when are the flights?`);
});

// Any [data-ask] button on the page sends its question to the assistant in the hero.
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-ask]");
  if (!b) return;
  $("#ask").scrollIntoView({ block: "center", behavior: reduced ? "auto" : "smooth" });
  ask(b.dataset.ask);
});
document.querySelectorAll('a[href="#ask"]').forEach((a) => a.addEventListener("click", () => {
  setTimeout(() => input.focus({ preventScroll: true }), reduced ? 0 : 400);
}));

// ---------------------------------------------------------------- bags

const calc = $("#bag-calc");
if (calc) {
  const PRICE = 35; // a 20 kg checked bag, each way (help centre)
  const update = () => {
    const bags = Number(calc.querySelector("input[name=bags]:checked")?.value || 0);
    const legs = Number(calc.querySelector("input[name=trip]:checked")?.value || 2);
    $("#bag-total").value = `€${bags * PRICE * legs}`;
    $("#bag-line").textContent = bags ? `${bags} ${bags === 1 ? "bag" : "bags"}, ${legs === 2 ? "there and back" : "one way"}.` : "Cabin bag only.";
  };
  calc.addEventListener("change", update);
  update();
}

// ---------------------------------------------------------------- the route field
// An ASCII field on an 8 by 16 cell: Skerry's routes from Cork and Dublin, faint where they leave
// and resolved where they land, with a pulse travelling each route. One composed still under reduced motion.

const canvas = $(".field");
if (canvas && canvas.getContext) {
  const ctx = canvas.getContext("2d");
  const css = getComputedStyle(document.documentElement);
  const tint = ["--color-glyph-1", "--color-glyph-2", "--color-glyph-3", "--color-glyph-4", "--color-accent-deep"].map((v) => css.getPropertyValue(v).trim());
  const label = css.getPropertyValue("--color-muted").trim();
  const mono = css.getPropertyValue("--font-outlier").trim();
  const RAMP = " .:-=+*#%@";
  const CW = 8, CH = 16;
  // Rough map order (west to east, south low), squeezed into the band under the chat panel so no city is covered.
  const ORIGINS = { ORK: [0.04, 0.93], DUB: [0.08, 0.87] };
  const DEST = { LIS: [0.47, 0.97], OPO: [0.53, 0.92], BCN: [0.68, 0.96], PAR: [0.74, 0.89], AMS: [0.84, 0.87], KRK: [0.95, 0.91] };
  let W = 0, H = 0, cols = 0, rows = 0, base = null, arcs = [], running = false, last = 0, left = 0, span = 1;
  const X = (f) => left + f * span;

  const bez = (a, c, b, t) => [(1 - t) ** 2 * a[0] + 2 * (1 - t) * t * c[0] + t * t * b[0], (1 - t) ** 2 * a[1] + 2 * (1 - t) * t * c[1] + t * t * b[1]];
  const noise = (x, y) => { const s = Math.sin(x * 12.9898 + y * 78.233) * 43758.5453; return s - Math.floor(s); };

  function layout() {
    const dpr = Math.min(2, devicePixelRatio || 1);
    W = canvas.clientWidth; H = canvas.clientHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    cols = Math.ceil(W / CW); rows = Math.ceil(H / CH);
    // Map the route coordinates onto the page container (capped at --container, inside the gutters).
    const cap = parseFloat(css.getPropertyValue("--container")) || 1440, gut = parseFloat(css.getPropertyValue("--gutter")) || 64;
    left = Math.max(0, (W - cap) / 2) + gut; span = Math.min(W, cap) - 2 * gut;
    arcs = [];
    for (const o of Object.values(ORIGINS)) {
      for (const d of Object.values(DEST)) {
        const a = [X(o[0]), o[1] * H], b = [X(d[0]), d[1] * H];
        const c = [(a[0] + b[0]) / 2, Math.min(a[1], b[1]) - 0.05 * H];
        arcs.push({ pts: Array.from({ length: 64 }, (_, i) => [...bez(a, c, b, i / 63), i / 63]), a, c, b, phase: noise(a[1], b[0]) });
      }
    }
    base = new Float32Array(cols * rows);
    for (let r = 0; r < rows; r++) for (let q = 0; q < cols; q++) {
      const x = q * CW + CW / 2, y = r * CH + CH / 2;
      const v = 0;
      // Each cell takes its strongest route, so overlapping routes stay lines instead of piling into a wall.
      let line = 0;
      for (const arc of arcs) for (const [px, py, t] of arc.pts) {
        const d2 = ((x - px) ** 2 + (y - py) ** 2) / 40;
        if (d2 < 5) line = Math.max(line, (0.16 + 0.4 * t * t) * Math.exp(-d2));
      }
      base[r * cols + q] = v + line;
    }
  }

  function draw(time) {
    ctx.clearRect(0, 0, W, H);
    ctx.font = `12px ${mono}`;
    ctx.textBaseline = "middle";
    const pulses = arcs.map((arc) => bez(arc.a, arc.c, arc.b, (time / 9000 + arc.phase) % 1));
    for (let r = 0; r < rows; r++) for (let q = 0; q < cols; q++) {
      const x = q * CW + CW / 2, y = r * CH + CH / 2;
      let v = base[r * cols + q];
      if (v < 0.06 && r < rows * 0.7) continue;
      for (const [px, py] of pulses) {
        const d2 = ((x - px) ** 2 + ((y - py) * 0.8) ** 2) / 260;
        if (d2 < 5) v += 0.7 * Math.exp(-d2) * (v > 0.12 ? 1 : 0.2);
      }
      if (v < 0.06) continue;
      const i = Math.min(RAMP.length - 1, Math.floor(v * 9));
      ctx.fillStyle = tint[Math.min(4, Math.floor(i / 2))];
      ctx.fillText(RAMP[i], q * CW, y);
    }
    ctx.fillStyle = label;
    ctx.font = `500 11px ${mono}`;
    for (const [code, [px, py]] of Object.entries({ ...ORIGINS, ...DEST })) ctx.fillText(code, Math.min(left + span - 24, X(px) + 6), py * H - 10);
  }

  function frame(t) {
    if (!running) return;
    if (t - last > 33) { draw(t); last = t; }
    requestAnimationFrame(frame);
  }
  function start() { if (!running && !reduced) { running = true; requestAnimationFrame(frame); } }
  function stop() { running = false; }

  layout();
  draw(4000);
  canvas.classList.add("is-live");
  new ResizeObserver(() => { layout(); draw(last || 4000); }).observe(canvas);
  if (!reduced) {
    new IntersectionObserver(([e]) => (e.isIntersecting ? start() : stop())).observe(canvas);
    document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
  }
}
