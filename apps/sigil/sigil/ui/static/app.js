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
}
const kv = (o) => Object.entries(o || {}).map(([a, n]) => `<b>${esc(a)}</b><span>${n}</span>`).join("");

async function act(action, seq) {
  const r = await fetch("/api/action", {
    method: "POST",
    headers: { "X-SIGIL-Token": TOKEN, "Content-Type": "application/json" },
    body: JSON.stringify({ action, seq }),
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
