/* ==========================================================================
   CRUCIBLE Ops Console — app core (vanilla, no framework, no build).
   Router + nav registry + safety header + live SSE feed + screen renderers.
   Screens are added phase by phase; each is a function that fills #main.
   ========================================================================== */
'use strict';

const Console = (() => {
  // ---- tiny helpers ------------------------------------------------------
  const $ = (sel) => document.querySelector(sel);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const dash = (v) => (v == null || v === '' ? '<span class="dash">—</span>' : esc(v));
  const num = (v) => (v == null ? '<span class="dash">—</span>' : Number(v).toLocaleString());
  async function getJSON(url) {
    const r = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error(`${r.status} ${url}`);
    return r.json();
  }

  // ---- state -------------------------------------------------------------
  const state = { status: null, engagements: [], activeSlug: null, feed: [], evtSource: null, live: false };
  const FEED_CAP = 600;

  // ---- screen registry (one per part + cross-cutting) --------------------
  const SCREENS = [
    { id: 'overview',   label: 'Overview',      group: 'OPERATIONS',  glyph: '◎', render: renderOverview },
    { id: 'live',       label: 'Live Run',      group: 'OPERATIONS',  glyph: '⏵', render: renderLive },
    { id: 'engagements',label: 'Engagements',   group: 'OPERATIONS',  glyph: '▤', render: renderEngagements },
    { id: 'findings',   label: 'Findings',      group: 'OPERATIONS',  glyph: '◈', render: renderFindings },
    { id: 'graph',      label: 'Attack Graph',  group: 'OPERATIONS',  glyph: '⧉', render: (m) => stub(m, 'Attack Graph', 'The world-model: typed nodes, belief-weighted edges, attacker→crown-jewel paths, choke-points. (Phase 2)') },
    { id: 'coverage',   label: 'Coverage',      group: 'OPERATIONS',  glyph: '▦', render: (m) => stub(m, 'Coverage', 'Fingerprint, library checks, discovered endpoints, passive hygiene, DOM-XSS leads. (Phase 2)') },

    { id: 'reasoning',  label: 'Reasoning Brain', group: 'INTELLIGENCE', glyph: '❋', render: (m) => stub(m, 'Reasoning Brain', 'Bandit rankings, WAF-evasion attempts, grammar-fuzz coverage, inferred filter predicates. (Phase 3)') },
    { id: 'planner',    label: 'Planner',       group: 'INTELLIGENCE', glyph: '⌘', render: (m) => stub(m, 'Planner', 'The goal tree: status/score/cost, the claimed leaf, VOI/EIG, halt reasons. (Phase 3)') },
    { id: 'memory',     label: 'Memory',        group: 'INTELLIGENCE', glyph: '❒', render: (m) => stub(m, 'Memory', 'Priors, winning hypotheses, best payloads, dead-ends, postmortems — with provenance. (Phase 3)') },
    { id: 'kernel',     label: 'Kernel',        group: 'INTELLIGENCE', glyph: '◆', render: (m) => stub(m, 'Kernel (Cognition)', 'LLM backends + CallTrace, hypotheses, self-critique, CVSS decisions, threat-model tree. (Phase 3)') },

    { id: 'benchmark',  label: 'Benchmark',     group: 'ASSURANCE',   glyph: '▲', render: (m) => stub(m, 'Benchmark', 'CRUCIBLE vs incumbents, precision/recall/FP, performance, the regression gate, calibration. (Phase 2)') },
    { id: 'analysis',   label: 'Analysis',      group: 'ASSURANCE',   glyph: '⊟', render: (m) => stub(m, 'Analysis (SAST)', 'Analyzers run/skipped, findings by path/rule/CWE, severity histogram. (Phase 4)') },
    { id: 'improve',    label: 'Improve',       group: 'ASSURANCE',   glyph: '↗', render: (m) => stub(m, 'Improve (SIL)', 'Capability-gap backlog, proposals + diffs, the merge gate, horizon items. (Phase 4)') },

    { id: 'authority',  label: 'Authority & Safety', group: 'GOVERNANCE', glyph: '⛨', render: (m) => stub(m, 'Authority & Safety', 'Kill-switch, authority window, budget/gate counters, posture, entitlement tier. (Phase 4)') },
    { id: 'defender',   label: 'Defender',      group: 'GOVERNANCE',  glyph: '◇', render: (m) => stub(m, 'Defender (DEL)', 'Detectability self-assessment: which rules fire on which channel, loudest channel. (Phase 4)') },
    { id: 'socialdef',  label: 'Social Defense',group: 'GOVERNANCE',  glyph: '✉', render: (m) => stub(m, 'Social Defense', 'Inbound-message phishing risk: band, score, indicators, recommendation. (Phase 4)') },
    { id: 'reports',    label: 'Reports',       group: 'GOVERNANCE',  glyph: '▣', render: (m) => stub(m, 'Reports', 'Browse/export executive/technical/remediation, SARIF, HTML. (Phase 4)') },
    { id: 'status',     label: 'System Status', group: 'GOVERNANCE',  glyph: '●', render: renderStatus },
  ];

  // ---- boot --------------------------------------------------------------
  function init() {
    initTheme();
    $('#themeToggle').addEventListener('click', toggleTheme);
    $('#engSelect').addEventListener('change', (e) => setActive(e.target.value || null));
    window.addEventListener('hashchange', route);
    renderNav();
    refresh().then(route);
    setInterval(refreshSafety, 8000); // keep the safety header honest without touching the engine
  }

  async function refresh() {
    try { state.status = await getJSON('/api/status'); } catch { state.status = null; }
    try { state.engagements = (await getJSON('/api/engagements')).engagements || []; } catch { state.engagements = []; }
    if (!state.activeSlug && state.engagements.length) state.activeSlug = state.engagements[0].slug;
    renderEngSelect();
    renderSafety();
    connectSSE();
  }
  async function refreshSafety() {
    try { state.engagements = (await getJSON('/api/engagements')).engagements || []; renderSafety(); } catch {}
  }

  // ---- theme -------------------------------------------------------------
  function initTheme() {
    const t = localStorage.getItem('crucible.theme');
    if (t) document.documentElement.setAttribute('data-theme', t);
  }
  function toggleTheme() {
    const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', cur);
    localStorage.setItem('crucible.theme', cur);
  }

  // ---- nav + routing -----------------------------------------------------
  function renderNav() {
    const nav = $('#nav'); const groups = {};
    SCREENS.forEach((s) => { (groups[s.group] = groups[s.group] || []).push(s); });
    nav.innerHTML = Object.entries(groups).map(([g, items]) =>
      `<div class="nav-group">${esc(g)}</div>` + items.map((s) =>
        `<div class="nav-item" data-id="${s.id}" onclick="location.hash='#${s.id}'">
           <span class="glyph">${s.glyph}</span><span>${esc(s.label)}</span>
           <span class="badge-count" id="nc-${s.id}" style="display:none"></span>
         </div>`).join('')).join('');
  }
  function currentId() { return (location.hash || '#overview').slice(1); }
  function route() {
    const id = currentId();
    document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.id === id));
    const screen = SCREENS.find((s) => s.id === id) || SCREENS[0];
    const main = $('#main'); main.innerHTML = '';
    try { screen.render(main); } catch (e) { main.innerHTML = `<div class="empty">screen error: ${esc(e.message)}</div>`; }
  }

  // ---- engagement selector + safety header -------------------------------
  function renderEngSelect() {
    const sel = $('#engSelect');
    if (!state.engagements.length) { sel.innerHTML = '<option value="">no engagements</option>'; return; }
    sel.innerHTML = state.engagements.map((e) =>
      `<option value="${esc(e.slug)}" ${e.slug === state.activeSlug ? 'selected' : ''}>${esc(e.slug)}</option>`).join('');
  }
  function setActive(slug) { state.activeSlug = slug; renderSafety(); connectSSE(); route(); }
  function activeEng() { return state.engagements.find((e) => e.slug === state.activeSlug) || null; }

  function renderSafety() {
    const e = activeEng();
    const pills = [];
    if (e) {
      const ks = e.killswitch || {};
      pills.push(ks.tripped
        ? `<span class="pill danger" title="${esc(ks.reason || '')}"><span class="dot"></span>KILL-SWITCH</span>`
        : `<span class="pill ok"><span class="dot"></span>armed</span>`);
      const env = e.authority && e.authority.environment;
      if (env) pills.push(`<span class="pill"><span class="dot"></span>${esc(env)}</span>`);
      else pills.push(`<span class="pill warn"><span class="dot"></span>no authority</span>`);
      pills.push(e.has_charter ? `<span class="pill ok"><span class="dot"></span>charter</span>`
                               : `<span class="pill warn"><span class="dot"></span>no charter</span>`);
    }
    pills.push(state.live ? `<span class="pill live"><span class="dot"></span>LIVE</span>`
                          : `<span class="pill"><span class="dot"></span>idle</span>`);
    $('#safety').innerHTML = pills.join('');
  }

  // ---- live SSE feed -----------------------------------------------------
  function connectSSE() {
    if (state.evtSource) { state.evtSource.close(); state.evtSource = null; }
    const qs = state.activeSlug ? `?slug=${encodeURIComponent(state.activeSlug)}` : '';
    const es = new EventSource('/api/events' + qs);
    es.onmessage = (m) => {
      let ev; try { ev = JSON.parse(m.data); } catch { return; }
      state.feed.unshift(ev);
      if (state.feed.length > FEED_CAP) state.feed.length = FEED_CAP;
      state.live = true; renderSafety();
      if (currentId() === 'overview') prependFeedRow(ev);
    };
    es.onerror = () => { /* EventSource auto-reconnects; nothing to do */ };
    state.evtSource = es;
  }
  function eventClass(name) {
    if (/refus|halt|reject|denied|violation/i.test(name)) return 'refuse';
    if (/scope|authority|budget|destructive|egress|rate/i.test(name)) return 'gate';
    if (/finding|confirm/i.test(name)) return 'finding';
    return '';
  }
  function feedRowHTML(ev) {
    const ts = (ev.timestamp || '').slice(11, 19) || '';
    const name = ev.event || ev.kind || '(event)';
    const msg = ev.url || ev.reason || ev.bug_class || ev.subcommand || ev.note || ev.denial_code || '';
    return `<div class="row"><span class="t">${esc(ts)}</span>
      <span class="ev ${eventClass(name)}">${esc(name)}</span>
      <span class="msg">${esc(msg)}</span></div>`;
  }
  function prependFeedRow(ev) {
    const f = document.getElementById('liveFeed'); if (!f) return;
    f.insertAdjacentHTML('afterbegin', feedRowHTML(ev));
    while (f.children.length > 200) f.removeChild(f.lastChild);
  }

  // ---- screens: Overview -------------------------------------------------
  function renderOverview(main) {
    const engs = state.engagements;
    const tripped = engs.filter((e) => e.killswitch && e.killswitch.tripped).length;
    const backends = (state.status && state.status.backends) || [];
    const up = backends.filter((b) => b.available).length;
    main.innerHTML = `
      <div class="screen-head"><h1>Mission Control</h1>
        <span class="sub">a read-only cockpit over what the framework is doing</span></div>
      <div class="grid cols-4" style="margin-bottom:var(--sp-4)">
        <div class="tile"><div class="k">Engagements</div><div class="v">${engs.length}</div>
          <div class="foot">${tripped ? tripped + ' kill-switch tripped' : 'all armed'}</div></div>
        <div class="tile"><div class="k">Active</div><div class="v sm mono">${dash(state.activeSlug)}</div>
          <div class="foot">${activeEng() && activeEng().authority ? esc(activeEng().authority.environment || '') : 'no authority'}</div></div>
        <div class="tile"><div class="k">LLM backends</div><div class="v">${up}<span class="muted" style="font-size:var(--fs-md)">/${backends.length}</span></div>
          <div class="foot">reachable</div></div>
        <div class="tile"><div class="k">Live feed</div><div class="v">${state.feed.length}</div>
          <div class="foot">events buffered</div></div>
      </div>
      <div class="grid cols-2">
        <div class="card"><h3>Live activity</h3>
          <div class="feed" id="liveFeed">${state.feed.length
            ? state.feed.slice(0, 200).map(feedRowHTML).join('')
            : '<div class="muted" style="padding:var(--sp-3)">no events yet — run <code>engage &lt;slug&gt; &lt;url&gt;</code> (or a console-launched scan) to stream here</div>'}</div>
        </div>
        <div class="card"><h3>Engagements</h3>
          ${engs.length ? engagementTable(engs.slice(0, 8)) : '<div class="muted">none yet — <code>intake</code> / <code>engage</code> create one under <code>targets/</code></div>'}
        </div>
      </div>`;
  }

  // ---- screens: Engagements ---------------------------------------------
  function engagementTable(engs) {
    return `<div class="scroll-x"><table class="tbl"><thead><tr>
        <th>slug</th><th>env</th><th>charter</th><th>kill-switch</th><th>evidence</th><th>log</th></tr></thead><tbody>
      ${engs.map((e) => {
        const ks = e.killswitch || {}; const au = e.authority || {};
        return `<tr class="click" onclick="location.hash='#engagements'; Console.openEngagement('${esc(e.slug)}')">
          <td class="mono">${esc(e.slug)}</td>
          <td>${au.environment ? `<span class="badge">${esc(au.environment)}</span>` : dash()}</td>
          <td>${e.has_charter ? '<span class="badge ok">yes</span>' : '<span class="badge warn">no</span>'}</td>
          <td>${ks.tripped ? '<span class="badge danger">tripped</span>' : '<span class="badge ok">armed</span>'}</td>
          <td>${num(e.evidence_count)}</td>
          <td>${e.log_exists ? '<span class="badge ok">yes</span>' : dash()}</td>
        </tr>`;
      }).join('')}</tbody></table></div>`;
  }
  function renderEngagements(main) {
    main.innerHTML = `<div class="screen-head"><h1>Engagements</h1>
      <span class="sub">${state.engagements.length} target(s) under <code>targets/</code></span></div>
      <div class="card">${state.engagements.length ? engagementTable(state.engagements) : '<div class="empty">no engagements yet</div>'}</div>`;
  }
  function openEngagement(slug) {
    setActive(slug);
    getJSON('/api/engagement/' + encodeURIComponent(slug)).then((d) => {
      const au = d.authority || {}; const ks = d.killswitch || {};
      drawer(slug, `<div class="kv">
        <div class="k">environment</div><div class="v">${dash(au.environment)}</div>
        <div class="k">scope</div><div class="v mono">${au.scope && au.scope.length ? au.scope.map(esc).join('<br>') : dash()}</div>
        <div class="k">validity</div><div class="v mono">${dash(au.not_before)} → ${dash(au.not_after)}</div>
        <div class="k">destructive</div><div class="v">${au.allow_destructive == null ? dash() : (au.allow_destructive ? 'allowed' : 'denied')}</div>
        <div class="k">max actions</div><div class="v">${num(au.max_actions)}</div>
        <div class="k">kill-switch</div><div class="v">${ks.tripped ? '<span class="badge danger">tripped</span> ' + esc(ks.reason || '') : '<span class="badge ok">armed</span>'}</div>
        <div class="k">charter</div><div class="v">${d.has_charter ? 'present' : 'missing'}</div>
        <div class="k">evidence files</div><div class="v">${num(d.evidence_count)}</div>
      </div>`);
    }).catch((e) => drawer(slug, `<div class="empty">${esc(e.message)}</div>`));
  }

  // ---- screens: Status ---------------------------------------------------
  function renderStatus(main) {
    const s = state.status || {}; const paths = s.paths || {}; const backends = s.backends || [];
    main.innerHTML = `<div class="screen-head"><h1>System Status</h1>
      <span class="sub">environment + backend health (the <code>status</code> command, live)</span></div>
      <div class="grid cols-2">
        <div class="card"><h3>Paths</h3><div class="kv">
          ${Object.entries(paths).map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v mono">${dash(v)}</div>`).join('')}
        </div></div>
        <div class="card"><h3>LLM backends</h3><table class="tbl"><tbody>
          ${backends.length ? backends.map((b) => `<tr><td>${b.available ? '<span class="badge ok">up</span>' : '<span class="badge">·</span>'}</td>
            <td class="mono">${esc(b.name)}</td><td class="muted">${esc(b.note)}</td></tr>`).join('')
            : '<tr><td class="muted">no backends probed</td></tr>'}
        </tbody></table></div>
      </div>`;
  }

  // ---- screens: Live Run -------------------------------------------------
  let liveES = null;
  const liveCounters = { phase: '—', pages: 0, discovered: 0, surface: 0, findings: 0, requests: 0 };
  function renderLive(main) {
    main.innerHTML = `
      <div class="screen-head"><h1>Live Run</h1>
        <span class="sub">watch a scan/engage as it happens — decoupled, tailing the log</span></div>
      <div class="card" style="margin-bottom:var(--sp-4)">
        <h3>Launch a loopback scan</h3>
        <div class="row-flex">
          <input id="launchTarget" class="eng-select" style="flex:1;font-family:var(--font-mono)"
                 placeholder="http://127.0.0.1:PORT/  (loopback only — remote uses engage)" />
          <button class="btn primary" onclick="Console.launchScan()">▶ Launch scan</button>
        </div>
        <div class="muted" style="font-size:var(--fs-xs);margin-top:6px">
          Spawns the gated CLI (<code>scan --format json --progress-log</code>); the scan is unchanged, this only tails it.
        </div>
        <div id="launchMsg" style="margin-top:8px"></div>
      </div>
      <div class="grid cols-4" id="liveTiles"></div>
      <div class="grid cols-2" style="margin-top:var(--sp-4)">
        <div class="card"><h3>Findings confirming <span id="livePhase" class="badge">idle</span></h3>
          <div class="feed" id="liveFindings"><div class="muted" style="padding:var(--sp-3)">no run streaming — launch a scan, or pick an engagement to tail its gate stream</div></div></div>
        <div class="card"><h3>Event stream</h3>
          <div class="feed" id="liveStream"></div></div>
      </div>`;
    renderLiveTiles();
    // if an engagement is active, tail its log by default
    if (state.activeSlug) startLive({ slug: state.activeSlug });
  }
  function renderLiveTiles() {
    const t = document.getElementById('liveTiles'); if (!t) return;
    const c = liveCounters;
    t.innerHTML = [
      ['Phase', c.phase], ['Pages', c.pages], ['Surface', c.surface],
      ['Findings', c.findings], ['Requests', c.requests],
    ].slice(0, 4).map(([k, v]) => `<div class="tile"><div class="k">${k}</div><div class="v sm">${esc(v)}</div></div>`).join('');
  }
  function startLive(opts) {
    if (liveES) { liveES.close(); liveES = null; }
    Object.assign(liveCounters, { phase: '—', pages: 0, discovered: 0, surface: 0, findings: 0, requests: 0 });
    const qs = opts.run ? `?run=${encodeURIComponent(opts.run)}` : (opts.slug ? `?slug=${encodeURIComponent(opts.slug)}` : '');
    const es = new EventSource('/api/events' + qs);
    es.onmessage = (m) => { let ev; try { ev = JSON.parse(m.data); } catch { return; } onLiveEvent(ev, opts); };
    liveES = es;
  }
  function onLiveEvent(ev, opts) {
    const name = ev.event || ev.kind || '';
    const stream = document.getElementById('liveStream');
    if (stream) { stream.insertAdjacentHTML('afterbegin', feedRowHTML(ev)); while (stream.children.length > 250) stream.removeChild(stream.lastChild); }
    if (name === 'scan.phase') { liveCounters.phase = ev.phase; liveCounters.pages = ev.pages ?? liveCounters.pages;
      liveCounters.surface = ev.surface ?? liveCounters.surface; const b = document.getElementById('livePhase'); if (b) b.textContent = ev.phase; }
    if (name === 'scan.finding' || /finding|confirm/i.test(name)) {
      liveCounters.findings += 1;
      const ff = document.getElementById('liveFindings');
      if (ff) { if (ff.querySelector('.muted')) ff.innerHTML = '';
        ff.insertAdjacentHTML('afterbegin', `<div class="row"><span class="t">${esc((ev.timestamp||'').slice(11,19))}</span>
          <span class="ev finding">${esc(ev.bug_class || 'finding')}</span>
          <span class="msg">${esc(ev.confirmed_by || '')} · ${esc(ev.endpoint || ev.param || '')}</span></div>`); }
    }
    if (/http\.request/.test(name)) liveCounters.requests += 1;
    if (name === 'scan.done') { liveCounters.findings = ev.findings ?? liveCounters.findings; liveCounters.requests = ev.requests_sent ?? liveCounters.requests;
      const b = document.getElementById('livePhase'); if (b) b.textContent = 'done';
      if (opts.run) document.getElementById('launchMsg').innerHTML =
        `<span class="badge ok">done</span> ${liveCounters.findings} findings — <a href="#findings" onclick="Console.selectRun('${esc(opts.run)}')">view in Findings →</a>`; }
    renderLiveTiles();
  }
  async function launchScan() {
    const target = (document.getElementById('launchTarget').value || '').trim();
    const msg = document.getElementById('launchMsg');
    if (!target) { msg.innerHTML = '<span class="badge warn">enter a loopback target</span>'; return; }
    msg.innerHTML = '<span class="muted">launching…</span>';
    try {
      const r = await fetch('/api/launch/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }) });
      const d = await r.json();
      if (d.error) { msg.innerHTML = `<span class="badge danger">${esc(d.error)}</span>`; return; }
      msg.innerHTML = `<span class="badge ok">running</span> <span class="mono">${esc(d.run_id)}</span>`;
      state.live = true; renderSafety();
      startLive({ run: d.run_id });
    } catch (e) { msg.innerHTML = `<span class="badge danger">${esc(e.message)}</span>`; }
  }

  // ---- screens: Findings -------------------------------------------------
  let currentRun = null;
  function renderFindings(main) {
    main.innerHTML = `<div class="screen-head"><h1>Findings</h1>
      <span class="sub">oracle-confirmed findings with re-verifiable certificates</span>
      <div class="actions"><select class="eng-select" id="runSelect" onchange="Console.selectRun(this.value)"></select></div></div>
      <div id="findingsBody"><div class="empty">loading runs…</div></div>`;
    getJSON('/api/runs').then((d) => {
      const runs = d.runs || [];
      const sel = document.getElementById('runSelect');
      sel.innerHTML = runs.length
        ? runs.map((r) => `<option value="${esc(r.run_id)}">${esc(r.run_id)} · ${esc(r.target || '')} · ${r.findings==null?'…':r.findings+' findings'}</option>`).join('')
        : '<option value="">no console runs yet</option>';
      const pick = currentRun || (runs[0] && runs[0].run_id);
      if (pick) { sel.value = pick; selectRun(pick); }
      else document.getElementById('findingsBody').innerHTML =
        '<div class="empty">no runs yet — launch a scan from <a href="#live">Live Run</a></div>';
    }).catch((e) => { document.getElementById('findingsBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
  }
  function selectRun(runId) {
    if (!runId) return; currentRun = runId;
    if (currentId() !== 'findings') { location.hash = '#findings'; return; }
    const body = document.getElementById('findingsBody');
    if (body) body.innerHTML = '<div class="muted">loading report…</div>';
    getJSON('/api/report/' + encodeURIComponent(runId)).then((doc) => renderReport(doc, runId));
  }
  window.__findings = {};
  function renderReport(doc, runId) {
    const body = document.getElementById('findingsBody'); if (!body) return;
    if (doc.pending) { body.innerHTML = `<div class="stub">run <b>${esc(runId)}</b> is <b>${esc(doc.status)}</b> — findings appear when it finishes. Watch it in <a href="#live">Live Run</a>.</div>`; return; }
    const s = doc.summary || {}; const findings = doc.findings || []; const paths = doc.attack_paths || [];
    window.__findings[runId] = findings;
    const sev = s.by_severity || {};
    body.innerHTML = `
      <div class="grid cols-4" style="margin-bottom:var(--sp-4)">
        <div class="tile"><div class="k">Confirmed</div><div class="v">${num(s.confirmed)}</div><div class="foot">${esc(doc.target||'')}</div></div>
        <div class="tile"><div class="k">Pages crawled</div><div class="v">${num(s.pages_crawled)}</div></div>
        <div class="tile"><div class="k">Requests audited</div><div class="v">${num(s.requests_audited)}</div></div>
        <div class="tile"><div class="k">Attack paths</div><div class="v">${num(paths.length)}</div><div class="foot">exploit chains</div></div>
      </div>
      <div class="card" style="margin-bottom:var(--sp-4)"><h3>Confirmed findings</h3>
      ${findings.length ? `<div class="scroll-x"><table class="tbl"><thead><tr>
        <th>severity</th><th>bug class</th><th>location</th><th>oracle</th><th>conf</th><th>cert</th></tr></thead><tbody>
        ${findings.map((f, i) => `<tr class="click" onclick="Console.openFinding('${esc(runId)}',${i})">
          <td><span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
          <td class="mono">${esc(f.bug_class)}</td>
          <td class="mono muted">${esc(f.location)}</td>
          <td><span class="badge oracle">${esc(f.confirmed_by)}</span></td>
          <td>${esc(f.confidence)}</td>
          <td>${f.re_verifiable ? '<span class="badge ok">✓</span>' : dash()}</td>
        </tr>`).join('')}</tbody></table></div>` : '<div class="empty">no confirmed findings</div>'}
      </div>
      ${paths.length ? `<div class="card"><h3>Exploit chains (attack paths)</h3>
        ${paths.map((p) => `<div style="padding:6px 0;border-bottom:1px solid var(--border)">
          <span class="badge ${p.detection_cost < .5 ? 'ok' : p.detection_cost < .8 ? 'warn' : 'danger'}">${Number(p.detection_cost).toFixed(2)} detect</span>
          <span class="mono" style="margin-left:8px">${esc(p.description)}</span></div>`).join('')}</div>` : ''}
      <div style="margin-top:var(--sp-4)"><button class="btn" onclick="Console.reverify('${esc(runId)}')">↻ Re-verify certificates</button>
        <span id="reverifyMsg" style="margin-left:10px"></span></div>`;
  }
  function openFinding(runId, i) {
    const f = (window.__findings[runId] || [])[i]; if (!f) return;
    drawer(`${f.bug_class}`, `<div class="kv">
      <div class="k">severity</div><div class="v"><span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span></div>
      <div class="k">location</div><div class="v mono">${esc(f.location)}</div>
      <div class="k">confirmed by</div><div class="v"><span class="badge oracle">${esc(f.confirmed_by)}</span> ${f.re_verifiable ? '<span class="badge ok">re-verifiable</span>' : ''}</div>
      <div class="k">confidence</div><div class="v">${esc(f.confidence)}</div>
      <div class="k">evidence</div><div class="v">${esc(f.evidence)}</div>
      <div class="k">remediation</div><div class="v">${esc(f.remediation)}</div>
      <div class="k">references</div><div class="v mono">${(f.references||[]).map(esc).join(', ') || dash()}</div>
    </div>
    <h3 style="margin-top:var(--sp-4);font-size:var(--fs-sm);color:var(--text-2)">ORACLE CERTIFICATE</h3>
    <pre class="cert">${esc(JSON.stringify(f, null, 2))}</pre>`);
  }
  async function reverify(runId) {
    const msg = document.getElementById('reverifyMsg'); msg.innerHTML = '<span class="muted">re-verifying…</span>';
    try {
      const r = await fetch('/api/reverify/' + encodeURIComponent(runId), { method: 'POST' });
      const d = await r.json();
      msg.innerHTML = d.error ? `<span class="badge danger">${esc(d.error)}</span>`
        : `<span class="badge ${d.reproduced === d.total ? 'ok' : 'warn'}">${d.reproduced}/${d.total} certificates reproduced</span>`;
    } catch (e) { msg.innerHTML = `<span class="badge danger">${esc(e.message)}</span>`; }
  }

  // ---- stub + drawer -----------------------------------------------------
  function stub(main, title, desc) {
    main.innerHTML = `<div class="screen-head"><h1>${esc(title)}</h1></div>
      <div class="stub">${esc(desc)}</div>`;
  }
  function drawer(title, html) {
    $('#drawerTitle').textContent = title;
    $('#drawerBody').innerHTML = html;
    $('#drawer').classList.add('open');
  }
  function closeDrawer() { $('#drawer').classList.remove('open'); }

  return { init, openEngagement, closeDrawer, launchScan, selectRun, openFinding, reverify };
})();

document.addEventListener('DOMContentLoaded', Console.init);
