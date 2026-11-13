"use strict";
// External, CSP-'self' script (no inline anything). The token is injected into the page as a data
// attribute on <body> (unreadable cross-origin); this reads it and uses it for every request.
const TOKEN = document.body.dataset.token || "";
const H = { headers: { "X-SIGIL-Token": TOKEN } };
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const api = (p) => fetch(p, H).then((r) => r.json());

async function refresh() {
  const s = await api("/api/snapshot");
  const k = $("#kill");
  k.textContent = "kill: " + s.kill_switch;
  k.className = s.kill_switch === "ENGAGED" ? "kill-on" : "kill-off";
  const q = $("#queue");
  if (!s.pending_approvals || !s.pending_approvals.length) {
    q.innerHTML = '<span class="empty">nothing awaiting approval</span>';
  } else {
    q.innerHTML = s.pending_approvals.map((a) => `<div class="item">
      <div class="meta">seq ${a.seq} · ${esc(a.tier)} · ${esc(a.kind)} · ${esc(a.agent || "")}</div>
      <div class="subj">${esc(a.subject || "(no subject)")}</div>
      <button class="approve" data-act="approve" data-seq="${a.seq}">Approve</button>
      <button class="deny" data-act="deny" data-seq="${a.seq}">Deny</button></div>`).join("");
  }
  $("#activity").innerHTML = kv(s.recent_by_agent) || '<span class="empty">quiet</span>';
  $("#budget").innerHTML = Object.entries(s.budget_today || {})
    .map(([a, v]) => `<b>${esc(a)}</b><span>${v.actions} actions · ${v.interrupts} interrupts</span>`).join("")
    || '<span class="empty">none</span>';
  const l = s.ingest_lag || {};
  $("#lag").innerHTML = `<b>head</b><span>${l.head_seq}</span><b>since checkpoint</b><span>${l.records_since_checkpoint}</span>`;
  renderCaps(s.capabilities || {});
  loadMargin();
}

// EC-6 operator margin panel. minor-units -> display money; a null cost/margin is "not configured" (never a
// fabricated 0). The /api/billing/margin route is owner-tier + flag-gated: it 404s (flag off) or 403s
// (non-owner). On that first negative the panel LATCHES OFF (marginOff=true) and never polls again, so an
// off-flag / non-owner cockpit issues exactly ONE probe at load, then is byte-identical in steady state (the
// server route itself is byte-identical — 404 — when off). A transient network/parse error does NOT latch.
let marginOff = false;   // latched true after a deterministic 404/403: stop re-polling /api/billing/margin
function money(v, cur) {
  if (v === null || v === undefined) return '<span class="nc">not configured</span>';
  const sym = cur === "USD" ? "$" : "";
  const s = (Math.abs(v) / 100).toFixed(2);
  const tail = cur && cur !== "USD" ? " " + esc(cur) : "";
  return `${v < 0 ? "-" : ""}${sym}${s}${tail}`;
}
async function loadMargin() {
  if (marginOff) return;                 // latched off (flag off / non-owner): no further polling
  const panel = $("#margin-panel");
  let m = null;
  try {
    const r = await fetch("/api/billing/margin", H);
    if (r.status === 404 || r.status === 403) { marginOff = true; panel.style.display = "none"; return; }
    if (r.ok) m = await r.json();
  } catch (_) { /* transient network/parse error -> try again next cycle (do NOT latch) */ }
  if (!m || !Array.isArray(m.tenants)) { panel.style.display = "none"; return; }  // unavailable -> hidden
  const cur = m.currency || "USD";
  $("#margin-note").textContent = m.rate_configured
    ? `cost rate ${m.cost_rate_micro_minor_per_token} micro-minor/token` + (m.target_margin_set
      ? " · target = cost ÷ (1 − target margin). The target margin is over metered AI cost; until per-run metered"
        + " cost is recorded, this cost column is the per-token rate estimate"
      : (m.target_margin_issue ? ` · no target line: ${m.target_margin_issue}` : ""))
    : "cost rate NOT CONFIGURED — committed tokens + billed revenue shown; no margin is fabricated.";
  const t = m.totals || {};
  $("#margin-totals").innerHTML =
    `<b>tenants</b><span>${t.tenant_count || 0}</span>` +
    `<b>committed tokens</b><span>${t.committed_tokens || 0}</span>` +
    `<b>cost in flight (tok)</b><span>${t.in_flight_tokens || 0}</span>` +
    `<b>billed revenue</b><span>${money(t.billed_revenue_minor, cur)}</span>` +
    `<b>collected</b><span>${money(t.collected_minor, cur)}</span>` +
    `<b>cost</b><span>${money(t.cost_minor, cur)}</span>` +
    `<b>margin</b><span>${money(t.margin_minor, cur)}</span>`;
  const head = `<tr><th>tenant</th><th>tokens</th><th>in flight</th><th>billed</th><th>cost</th><th>margin</th><th>margin %</th><th>target</th></tr>`;
  const body = m.tenants.map((x) => `<tr><td>${esc(x.name || x.org_id)}</td>
    <td>${x.committed_tokens}</td><td>${x.in_flight_tokens}</td>
    <td>${money(x.billed_revenue_minor, x.currency || cur)}</td>
    <td>${money(x.cost_minor, x.currency || cur)}</td>
    <td>${money(x.margin_minor, x.currency || cur)}</td>
    <td>${x.margin_pct === null || x.margin_pct === undefined ? '<span class="nc">—</span>' : esc(x.margin_pct) + "%"}</td>
    <td>${x.target_revenue_minor === null || x.target_revenue_minor === undefined ? '<span class="nc">—</span>' : money(x.target_revenue_minor, x.currency || cur)}</td></tr>`).join("");
  $("#margin-table").innerHTML = head + (body || '<tr><td colspan="8" class="nc">no tenant activity</td></tr>');
  panel.style.display = "block";
}
const kv = (o) => Object.entries(o || {}).map(([a, n]) => `<b>${esc(a)}</b><span>${n}</span>`).join("");

// Capabilities panel: a state chip + a toggle button per capability whose data-act flips with state
// (enabled → "Disable x", disabled → "Enable x"), reusing the delegated button[data-act] → act() path.
function capRow(name, state) {
  const on = state === "enabled";
  const act = (on ? "disable_" : "enable_") + name;
  return `<div class="cap-row"><b>${esc(name)}</b>
    <span class="chip ${on ? "ok" : "broken"}">${esc(state)}</span>
    <button data-act="${act}">${on ? "Disable" : "Enable"} ${esc(name)}</button></div>`;
}
function renderCaps(caps) {
  const rows = ["gesture", "voice"].map((n) => capRow(n, caps[n] || "enabled")).join("");
  $("#capabilities").innerHTML = rows +
    `<div class="cap-row both"><button data-act="disable_both">Disable both</button>
       <button data-act="enable_both">Enable both</button></div>`;
}

async function act(action, seq) {
  // capability actions carry no seq (the button has no data-seq → NaN); omit it rather than send null.
  const body = Number.isNaN(seq) ? { action } : { action, seq };
  const r = await fetch("/api/action", {
    method: "POST",
    headers: { "X-SIGIL-Token": TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await r.json();
  if (!r.ok) alert("action refused: " + (j.error || r.status));
  refresh();
}

async function showRecord(seq) {
  const r = await api("/api/record/" + seq);
  const badge = r.integrity_ok === false
    ? '<span class="chip broken">INTEGRITY BROKEN</span>'
    : '<span class="chip ok">verified</span>';
  $("#detail-body").innerHTML =
    `<div class="prov">record <b>seq ${r.seq}</b> · ${esc(r.kind)} · entry_hash <b>${esc((r.entry_hash || "").slice(0, 24))}</b> ${badge}</div>
     <div class="prov">${esc(r.integrity_reason || "")}</div><pre>${esc(JSON.stringify(r.payload, null, 2))}</pre>`;
  $("#detail").style.display = "block";
}

function feedRow(ev) {
  const anc = ev.integrity_ok === false ? '<span class="chip broken">broken</span>'
    : ev.anchored ? '<span class="chip anchored">anchored</span>' : '<span class="chip tail">tail</span>';
  const el = document.createElement("div");
  el.className = "row";
  el.dataset.seq = ev.seq;
  el.innerHTML = `<span class="seq">#${ev.seq}</span><span class="kind">${esc(ev.kind)}</span><span class="actor">${esc(ev.actor)}</span><span class="txt">${esc((ev.text || "").slice(0, 140))}</span>${anc}`;
  return el;
}
function startStream() {
  const es = new EventSource("/api/stream?token=" + encodeURIComponent(TOKEN));
  const feed = $("#feed");
  es.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    feed.prepend(feedRow(ev));
    while (feed.children.length > 300) feed.lastChild.remove();
  };
}

// event delegation (no inline handlers — CSP-safe)
document.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-act]");
  if (btn) return act(btn.dataset.act, Number(btn.dataset.seq));
  const row = e.target.closest(".row[data-seq]");
  if (row) return showRecord(Number(row.dataset.seq));
  if (e.target.closest("#detail-close")) $("#detail").style.display = "none";
});

refresh();
setInterval(refresh, 4000);
startStream();
