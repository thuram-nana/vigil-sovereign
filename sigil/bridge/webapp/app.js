"use strict";
/* SIGIL Companion (Phase 9 W1-C) — the owner's phone PWA for the WireGuard bridge.
 *
 * It holds the phone's OWN Ed25519 device key (WebCrypto, NON-EXTRACTABLE, in IndexedDB) and signs
 * EVERY request locally; the desktop bridge (sigil/bridge/server.py) only VERIFIES. There is no wire
 * bearer secret — authentication IS the signature over the canonical envelope core, checked against
 * the owner-minted authorized-device set (sigil/mesh :: authorized_devices).
 *
 * CRYPTO REQUIREMENTS — WebCrypto Ed25519 is REQUIRED (no vendored/downloaded fallback: the sandbox
 * is offline and we will NOT silently drop to weak crypto). Minimum browsers with Ed25519 in
 * crypto.subtle:  Chrome/Edge 137+ · Safari 17+ · Firefox 129+ · Node 22 (for the parity test).
 * If crypto.subtle lacks Ed25519 the app says so honestly and refuses to operate.
 *
 * ENCODING PARITY with sigil (sigil/reuse/crypto.py):
 *   - device PUBLIC key (raw 32 bytes, exportKey("raw")) and SIGNATURES (raw 64 bytes) are STANDARD
 *     base64 WITH padding (b64std) — because verify_one() -> _b64decode_exact() does
 *     base64.b64decode(value, validate=True), which only accepts the standard alphabet (+ / =).
 *   - the WHOLE envelope JSON that rides in X-SIGIL-Envelope / ?env= is base64URL (b64url), because
 *     the server decodes it with base64.urlsafe_b64decode (padding re-added server-side).
 *   - canonical signing bytes come from SigilCanonical.canonicalJson (see canonical.js — the parity
 *     contract). ts is floored to INTEGER seconds and nonces/seqs are integers so the JS and Python
 *     canonical bytes are byte-identical (floats are never signed).
 *   - the human fingerprint = grouped SHA-256(pubkey-base64-STRING) first 8 bytes as xxxx-xxxx-xxxx-
 *     xxxx, matching sigil/cli.py :: _device_fingerprint (which hashes pubkey.encode(), i.e. the
 *     base64 STRING, NOT the raw key bytes).
 *
 * CSP: default-src 'self'. No inline scripts, no inline event handlers, no external origins. All
 * behaviour is wired by ONE delegated click listener + a few input handlers.
 */

/* ----------------------------------------------------------------------------- tiny DOM helpers */
var $ = function (s) { return document.querySelector(s); };
var esc = function (s) {
  return String(s == null ? "" : s).replace(/[&<>]/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c];
  });
};
var enc = new TextEncoder();
function banner(kind, html) {
  var b = $("#banner");
  b.className = "banner " + kind;
  b.innerHTML = html;
}
function clearBanner() { $("#banner").className = "banner info hidden"; }

/* ----------------------------------------------------------------------------------- base64 */
function bytesToB64std(bytes) {                       // standard base64, WITH padding (pubkey / sig)
  var s = "";
  for (var i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
  return btoa(s);
}
function strToB64url(str) {                           // base64URL, no padding (the envelope wrapper)
  return bytesToB64std(enc.encode(str)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function toHex(buf) {
  var v = new Uint8Array(buf), out = "";
  for (var i = 0; i < v.length; i++) { out += v[i].toString(16).padStart(2, "0"); }
  return out;
}
async function sha256Hex(bytes) {                     // == sigil.reuse.sha256_hex
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

/* -------------------------------------------------------------------------------- IndexedDB */
/* One DB, two stores: "kv" (device key material + the monotonic nonce) and "outbox" (POSTs queued
 * while offline, flushed on reconnect). CryptoKey objects are structured-cloneable, so the
 * NON-EXTRACTABLE private key persists here without ever exposing its bytes. */
var DB = null;
function openDB() {
  return new Promise(function (resolve, reject) {
    var req = indexedDB.open("sigil-companion", 1);
    req.onupgradeneeded = function () {
      var db = req.result;
      if (!db.objectStoreNames.contains("kv")) { db.createObjectStore("kv", { keyPath: "k" }); }
      if (!db.objectStoreNames.contains("outbox")) { db.createObjectStore("outbox", { keyPath: "id", autoIncrement: true }); }
    };
    req.onsuccess = function () { resolve(req.result); };
    req.onerror = function () { reject(req.error); };
  });
}
function tx(store, mode) { return DB.transaction(store, mode).objectStore(store); }
function idbGet(store, key) {
  return new Promise(function (resolve, reject) {
    var r = tx(store, "readonly").get(key);
    r.onsuccess = function () { resolve(r.result); };
    r.onerror = function () { reject(r.error); };
  });
}
function idbPut(store, val) {
  return new Promise(function (resolve, reject) {
    var r = tx(store, "readwrite").put(val);
    r.onsuccess = function () { resolve(r.result); };
    r.onerror = function () { reject(r.error); };
  });
}
function idbDel(store, key) {
  return new Promise(function (resolve, reject) {
    var r = tx(store, "readwrite").delete(key);
    r.onsuccess = function () { resolve(); };
    r.onerror = function () { reject(r.error); };
  });
}
function idbAll(store) {
  return new Promise(function (resolve, reject) {
    var r = tx(store, "readonly").getAll();
    r.onsuccess = function () { resolve(r.result || []); };
    r.onerror = function () { reject(r.error); };
  });
}

/* ------------------------------------------------------------------------ device key + identity */
var DEVICE = null;   // { privateKey: CryptoKey (non-extractable), pubB64: string, deviceId: string, fingerprint: string }

async function ed25519Available() {
  if (!(window.crypto && crypto.subtle && crypto.subtle.generateKey)) { return false; }
  try {
    var k = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    return !!(k && k.privateKey && k.publicKey);
  } catch (e) { return false; }
}

function randomDeviceId() {
  var b = new Uint8Array(4);
  crypto.getRandomValues(b);
  return "phone-" + toHex(b.buffer);
}

async function loadOrCreateDevice() {
  var rec = await idbGet("kv", "device");
  if (rec && rec.privateKey && rec.pubB64) {
    DEVICE = { privateKey: rec.privateKey, pubB64: rec.pubB64, deviceId: rec.deviceId, fingerprint: rec.fingerprint };
    return DEVICE;
  }
  // First run on this device: mint a fresh NON-EXTRACTABLE key. ["sign","verify"] so the (always-
  // extractable) public key carries a valid usage; the private key stays extractable=false. We only
  // ever exportKey("raw") the PUBLIC key.
  var pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  var raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));  // 32 bytes
  var pubB64 = bytesToB64std(raw);
  var short = (await sha256Hex(enc.encode(pubB64))).slice(0, 16);
  var fingerprint = [short.slice(0, 4), short.slice(4, 8), short.slice(8, 12), short.slice(12, 16)].join("-");
  var deviceId = randomDeviceId();
  DEVICE = { privateKey: pair.privateKey, pubB64: pubB64, deviceId: deviceId, fingerprint: fingerprint };
  await idbPut("kv", { k: "device", privateKey: pair.privateKey, pubB64: pubB64, deviceId: deviceId, fingerprint: fingerprint });
  await idbPut("kv", { k: "nonce", v: 0 });
  return DEVICE;
}

async function nextNonce() {                          // monotonic, per-device, persisted (replay gate)
  var rec = await idbGet("kv", "nonce");
  var n = (rec && typeof rec.v === "number" ? rec.v : 0) + 1;
  await idbPut("kv", { k: "nonce", v: n });
  return n;
}

async function signBytes(msgBytes) {                  // -> standard-base64 signature
  var sig = await crypto.subtle.sign("Ed25519", DEVICE.privateKey, msgBytes);
  return bytesToB64std(new Uint8Array(sig));
}

/* --------------------------------------------------------------------------- envelope builder */
/* core = {v,device,action,args,nonce,ts}; sign canonicalJson(core); wrapper = base64url(JSON). */
async function buildEnvelope(action, args, nonce) {
  var core = {
    v: 1,
    device: DEVICE.pubB64,
    action: action,
    args: args || {},
    nonce: nonce,
    ts: Math.floor(Date.now() / 1000)   // INTEGER seconds — byte-parity with Python; server window is +/-120s
  };
  var sig = await signBytes(enc.encode(SigilCanonical.canonicalJson(core)));
  var wrapper = {};
  for (var kk in core) { if (Object.prototype.hasOwnProperty.call(core, kk)) { wrapper[kk] = core[kk]; } }
  wrapper.sig = sig;
  return strToB64url(JSON.stringify(wrapper));
}

/* ------------------------------------------------------------------------------- networking */
function on401(status) {                              // a read/action was refused as unauthenticated
  if (status === 401 || status === 403) {
    banner("warn", "This device is not authorized yet (or its signature was refused). Pair it on the PC "
      + "(see the Pairing panel), then it will connect.");
  }
}

async function authedGet(path, action, extraQuery) {  // a signed READ (envelope in the header)
  var env = await buildEnvelope(action, {}, await nextNonce());
  var url = path + (extraQuery ? ("?" + extraQuery) : "");
  var r = await fetch(url, { headers: { "X-SIGIL-Envelope": env }, cache: "no-store" });
  if (!r.ok) { on401(r.status); throw new Error("GET " + path + " -> " + r.status); }
  clearBanner();
  return r.json();
}

async function effectfulPost(path, action, args) {    // panic / relay — signed, replay-gated
  var env = await buildEnvelope(action, args || {}, await nextNonce());
  var req = { path: path, headers: { "X-SIGIL-Envelope": env }, body: "" };
  return deliver(req);
}

async function postApproval(seq, decision) {          // device-signed governor.approval -> /api/action
  var approver = "device";
  var msgBytes = enc.encode(SigilCanonical.canonicalJson({ approver: approver, decision: decision, target: seq }));
  var sig = await signBytes(msgBytes);
  var payload = {
    signal: "governor.approval", approval: decision, target_seq: seq,
    approver: approver, reason: "", pubkey: DEVICE.pubB64, sig: sig,
    msg_digest: await sha256Hex(msgBytes), device: true
  };
  var req = { path: "/api/action", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) };
  return deliver(req);
}

/* deliver: try now; if the network is unreachable, QUEUE it (already signed) and flush on reconnect.
 * If the server RESPONDS (any HTTP status) the item is considered delivered — the server adjudicated. */
async function deliver(req) {
  try {
    var r = await fetch(req.path, {
      method: "POST", headers: req.headers, body: req.body, cache: "no-store"
    });
    var j = await r.json().catch(function () { return {}; });
    return { ok: r.ok, status: r.status, body: j };
  } catch (netErr) {
    await idbPut("outbox", { req: req, at: Date.now() });
    return { ok: false, queued: true, status: 0, body: { error: "offline — signed and queued; will flush on reconnect" } };
  }
}

async function flushOutbox() {
  if (!DB) { return; }
  var items = await idbAll("outbox");
  for (var i = 0; i < items.length; i++) {
    var it = items[i];
    try {
      await fetch(it.req.path, { method: "POST", headers: it.req.headers, body: it.req.body, cache: "no-store" });
      await idbDel("outbox", it.id);                 // server responded (any status) -> stop retrying
    } catch (e) {
      /* still offline — keep it queued */
    }
  }
  renderOutbox();
}

/* --------------------------------------------------------------------------------- renderers */
async function renderPairing() {
  var host = $("#pair-body");
  host.innerHTML =
    '<div class="mono">device id</div><code class="sel">' + esc(DEVICE.deviceId) + '</code>'
    + '<div class="mono mt">device public key (base64)</div><code class="sel" id="pubkey">' + esc(DEVICE.pubB64) + '</code>'
    + '<div class="mono mt">fingerprint (eyeball-match this on the PC)</div><div class="fp">' + esc(DEVICE.fingerprint) + '</div>'
    + '<div class="acts mt"><button data-act="copy-pub">Copy public key</button>'
    + '<button data-act="copy-cmd">Copy authorize command</button></div>'
    + '<div class="instr">On the PC, run:<br><code id="authcmd">sigil mesh authorize ' + esc(DEVICE.deviceId) + ' ' + esc(DEVICE.pubB64)
    + '</code><br>Confirm the printed fingerprint equals <b>' + esc(DEVICE.fingerprint) + '</b> before you accept it.</div>';
}

async function refreshPending() {
  var q = $("#queue");
  var data;
  try { data = await authedGet("/api/pending", "read:pending"); }
  catch (e) { q.innerHTML = '<span class="empty">unavailable (not authorized, or offline)</span>'; return; }
  var items = data.pending || [];
  if (!items.length) { q.innerHTML = '<span class="empty">nothing awaiting approval</span>'; return; }
  q.innerHTML = items.map(function (a) {
    return '<div class="item"><div class="meta">seq ' + esc(a.seq) + ' &middot; ' + esc(a.tier) + ' &middot; ' + esc(a.kind) + '</div>'
      + '<div class="acts"><button class="approve" data-act="approve" data-seq="' + esc(a.seq) + '">Approve</button>'
      + '<button class="deny" data-act="deny" data-seq="' + esc(a.seq) + '">Deny</button></div></div>';
  }).join("");
}

var kv = function (o) {
  return Object.keys(o || {}).map(function (a) {
    return '<b>' + esc(a) + '</b><span>' + esc(o[a]) + '</span>';
  }).join("");
};

async function refreshCockpit() {
  var s;
  try { s = await authedGet("/api/snapshot", "read:snapshot"); }
  catch (e) { return; }
  var k = $("#kill");
  k.textContent = "kill: " + s.kill_switch;
  k.className = s.kill_switch === "ENGAGED" ? "kill-on" : "kill-off";
  $("#cockpit").innerHTML =
    '<b>head seq</b><span>' + esc(s.head_seq) + '</span>'
    + '<b>kill switch</b><span>' + esc(s.kill_switch) + '</span>'
    + '<b>pending</b><span>' + esc((s.pending_approvals || []).length) + '</span>';
  $("#budget").innerHTML = Object.keys(s.budget_today || {}).map(function (a) {
    var v = s.budget_today[a];
    return '<b>' + esc(a) + '</b><span>' + esc(v.actions) + ' actions &middot; ' + esc(v.interrupts) + ' interrupts</span>';
  }).join("") || '<span class="empty">none</span>';
  $("#activity").innerHTML = kv(s.recent_by_agent) || '<span class="empty">quiet</span>';
  var l = s.ingest_lag || {};
  $("#lag").innerHTML = '<b>head</b><span>' + esc(l.head_seq) + '</span>'
    + '<b>since checkpoint</b><span>' + esc(l.records_since_checkpoint) + '</span>';
}

async function showRecord(seq) {
  var r;
  try { r = await authedGet("/api/record/" + seq, "read:record"); }
  catch (e) { return; }
  // HONEST integrity badge — mirror sigil/ui/static/app.js: only integrity_ok===false is "broken".
  var badge = r.integrity_ok === false
    ? '<span class="chip broken">INTEGRITY BROKEN</span>'
    : '<span class="chip ok">verified</span>';
  $("#detail-body").innerHTML =
    '<div class="prov">record <b>seq ' + esc(r.seq) + '</b> &middot; ' + esc(r.kind)
    + ' &middot; entry_hash <b>' + esc((r.entry_hash || "").slice(0, 24)) + '</b> ' + badge + '</div>'
    + '<div class="prov">' + esc(r.integrity_reason || "") + '</div>'
    + '<pre>' + esc(JSON.stringify(r.payload, null, 2)) + '</pre>';
  $("#detail").style.display = "block";
}

async function doRecall() {
  var subject = ($("#recall-input").value || "").trim();
  var out = $("#recall-out");
  if (!subject) { out.textContent = "enter a subject"; return; }
  out.textContent = "recalling…";
  var r;
  try { r = await authedGet("/api/recall", "read:recall", "subject=" + encodeURIComponent(subject)); }
  catch (e) { out.textContent = "unavailable"; return; }
  var rc = r.recall;
  if (!rc) { out.innerHTML = '<span class="empty">no grounded record for ' + esc(subject) + ' — not fabricated</span>'; return; }
  out.innerHTML = '<div class="prov">seq <b>' + esc(rc.seq) + '</b> &middot; ' + esc(rc.when || "") + '</div>'
    + '<pre>' + esc(rc.quote || "(no quote)") + '</pre>';
}

/* ---------------------------------------------------------------------------------- live feed */
var STREAM = null;
var STREAM_SINCE = -1;
function feedRow(ev) {
  var el = document.createElement("div");
  el.className = "row";
  el.dataset.seq = ev.seq;
  el.innerHTML = '<span class="seq">#' + esc(ev.seq) + '</span>'
    + '<span class="kind">' + esc(ev.kind) + '</span>'
    + '<span class="actor">' + esc(ev.tier) + '</span>';
  return el;
}
async function restartStream() {
  if (STREAM) { try { STREAM.close(); } catch (e) { /* noop */ } STREAM = null; }
  var env;
  try { env = await buildEnvelope("read:stream", {}, await nextNonce()); }
  catch (e) { return; }
  var url = "/api/stream?env=" + encodeURIComponent(env) + "&since=" + encodeURIComponent(STREAM_SINCE);
  var es = new EventSource(url);
  var feed = $("#feed");
  es.onopen = function () {
    if (feed.querySelector(".empty")) { feed.innerHTML = ""; }
  };
  es.onmessage = function (e) {
    var ev;
    try { ev = JSON.parse(e.data); } catch (x) { return; }
    if (typeof ev.seq === "number") { STREAM_SINCE = ev.seq; }
    if (feed.querySelector(".empty")) { feed.innerHTML = ""; }
    feed.prepend(feedRow(ev));
    while (feed.children.length > 300) { feed.lastChild.remove(); }
  };
  es.onerror = function () {
    // the envelope ts ages out of the +/-120s window; rebuild with a FRESH signed env on error.
    try { es.close(); } catch (x) { /* noop */ }
    if (STREAM === es) { STREAM = null; setTimeout(restartStream, 3000); }
  };
  STREAM = es;
}

function renderOutbox() {
  idbAll("outbox").then(function (items) {
    var el = $("#panic-msg");   // reuse a nearby line for the queued indicator on the action plane
    if (!items.length) { return; }
    el.innerHTML = '<span class="outbox">' + items.length + ' signed action(s) queued offline — will flush on reconnect</span>';
  });
}

/* --------------------------------------------------------------------------------- actions */
async function copyText(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) { await navigator.clipboard.writeText(text); return true; }
  } catch (e) { /* fall through — plain HTTP has no secure-context clipboard */ }
  return false;
}

async function onApprove(seq, decision) {
  var res = await postApproval(seq, decision);
  if (res.queued) { banner("warn", "Offline — the " + decision + " for seq " + seq + " is signed and queued."); }
  else if (!res.ok) { banner("err", "Approval refused: " + esc((res.body && res.body.error) || res.status)); }
  else { clearBanner(); }
  renderOutbox();
  refreshPending();
  refreshCockpit();
}

async function onPanic() {
  var btn = $("#panic-btn");
  btn.disabled = true;
  var res = await effectfulPost("/api/panic", "panic", {});
  btn.disabled = false;
  var m = $("#panic-msg");
  if (res.queued) { m.innerHTML = '<span class="outbox">PANIC signed &amp; queued offline (note: a panic is freshness-bound; if reconnect &gt; 120s it will be refused as stale — re-tap when online).</span>'; }
  else if (res.ok) { m.innerHTML = '<span style="color:var(--red)">PANIC engaged — mesh halted (seq ' + esc(res.body.seq) + ').</span>'; }
  else { m.innerHTML = '<span style="color:var(--red)">panic refused: ' + esc((res.body && res.body.error) || res.status) + '</span>'; }
  refreshCockpit();
}

async function onRelay() {
  var text = ($("#relay-input").value || "").trim();
  var m = $("#relay-msg");
  if (!text) { m.textContent = "enter a command"; return; }
  var btn = $("#relay-btn");
  btn.disabled = true;
  var res = await effectfulPost("/api/relay", "relay", { text: text });
  btn.disabled = false;
  if (res.queued) { m.innerHTML = '<span class="outbox">relay signed &amp; queued offline (freshness-bound — may be refused if reconnect &gt; 120s).</span>'; }
  else if (res.ok) { m.innerHTML = '<div class="prov">reply</div><pre>' + esc(res.body.reply) + '</pre>'; }
  else { m.textContent = "relay refused: " + ((res.body && res.body.error) || res.status); }
}

/* ------------------------------------------------------------------- event delegation (CSP-safe) */
document.addEventListener("click", function (e) {
  var btn = e.target.closest("button[data-act]");
  if (btn) {
    var act = btn.dataset.act;
    if (act === "approve") { return onApprove(Number(btn.dataset.seq), "approved"); }
    if (act === "deny") { return onApprove(Number(btn.dataset.seq), "denied"); }
    if (act === "panic") { return onPanic(); }
    if (act === "relay") { return onRelay(); }
    if (act === "recall") { return doRecall(); }
    if (act === "copy-pub") { return copyText(DEVICE.pubB64).then(function (ok) { btn.textContent = ok ? "Copied" : "Select above to copy"; }); }
    if (act === "copy-cmd") {
      var cmd = "sigil mesh authorize " + DEVICE.deviceId + " " + DEVICE.pubB64;
      return copyText(cmd).then(function (ok) { btn.textContent = ok ? "Copied" : "Select above to copy"; });
    }
    return;
  }
  var row = e.target.closest(".row[data-seq]");
  if (row) { return showRecord(Number(row.dataset.seq)); }
  if (e.target.closest("#detail-close")) { $("#detail").style.display = "none"; }
});
document.addEventListener("keydown", function (e) {
  if (e.key !== "Enter") { return; }
  if (e.target && e.target.id === "relay-input") { onRelay(); }
  if (e.target && e.target.id === "recall-input") { doRecall(); }
});

/* ------------------------------------------------------------------------------------- init */
async function init() {
  // Register the offline-shell service worker (scope /static/ — the only scope the bridge can serve
  // it from; the app's installed start_url lives under /static/ to match). Best-effort.
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/static/service-worker.js", { scope: "/static/" }).catch(function () { /* noop */ });
  }
  if (!(await ed25519Available())) {
    banner("err", "This browser can't hold a device key: crypto.subtle has no Ed25519. Use Chrome/Edge 137+, "
      + "Safari 17+, or Firefox 129+. The app will NOT fall back to weaker crypto.");
    return;
  }
  try { DB = await openDB(); }
  catch (e) { banner("err", "Local storage (IndexedDB) is unavailable — the device key cannot be held. " + esc(String(e))); return; }
  try { await loadOrCreateDevice(); }
  catch (e) { banner("err", "Could not create the device key: " + esc(String(e))); return; }

  await renderPairing();
  renderOutbox();
  flushOutbox();
  refreshPending();
  refreshCockpit();
  restartStream();

  setInterval(refreshPending, 5000);
  setInterval(refreshCockpit, 5000);
  setInterval(restartStream, 90000);   // re-sign the SSE envelope before it ages out of the freshness window
  window.addEventListener("online", function () { flushOutbox(); refreshPending(); refreshCockpit(); restartStream(); });
}
init();
