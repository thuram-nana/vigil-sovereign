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
    { id: 'graph',      label: 'Attack Graph',  group: 'OPERATIONS',  glyph: '⧉', render: renderGraph },
    { id: 'evidence',   label: 'Evidence',      group: 'OPERATIONS',  glyph: '⚿', render: renderEvidence },
    { id: 'timeline',   label: 'Timeline',      group: 'OPERATIONS',  glyph: '⏱', render: renderTimeline },
    { id: 'coverage',   label: 'Coverage',      group: 'OPERATIONS',  glyph: '▦', render: renderCoverage },

    { id: 'reasoning',  label: 'Reasoning Brain', group: 'INTELLIGENCE', glyph: '❋', render: renderReasoning },
    { id: 'intel',      label: 'Intelligence',  group: 'INTELLIGENCE', glyph: '❂', render: renderIntel },
    { id: 'planner',    label: 'Planner',       group: 'INTELLIGENCE', glyph: '⌘', render: renderPlanner },
    { id: 'memory',     label: 'Memory',        group: 'INTELLIGENCE', glyph: '❒', render: renderMemory },
    { id: 'kernel',     label: 'Kernel',        group: 'INTELLIGENCE', glyph: '◆', render: renderKernel },

    { id: 'benchmark',  label: 'Benchmark',     group: 'ASSURANCE',   glyph: '▲', render: renderBenchmark },
    { id: 'analysis',   label: 'Analysis',      group: 'ASSURANCE',   glyph: '⊟', render: (m) => subsystem(m, 'analysis') },
    { id: 'improve',    label: 'Improve',       group: 'ASSURANCE',   glyph: '↗', render: (m) => subsystem(m, 'improve') },
    { id: 'intake',     label: 'Intake',        group: 'ASSURANCE',   glyph: '⊕', render: (m) => subsystem(m, 'intake') },

    { id: 'authority',  label: 'Authority & Safety', group: 'GOVERNANCE', glyph: '⛨', render: renderAuthority },
    { id: 'defender',   label: 'Defender',      group: 'GOVERNANCE',  glyph: '◇', render: (m) => subsystem(m, 'defender') },
    { id: 'socialdef',  label: 'Social Defense',group: 'GOVERNANCE',  glyph: '✉', render: (m) => subsystem(m, 'socialdefense') },
    { id: 'reports',    label: 'Reports',       group: 'GOVERNANCE',  glyph: '▣', render: renderReports },
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

  // ---- shared run picker (Graph / Coverage reuse Findings' run selection) --
  function withRun(main, title, sub, cb) {
    main.innerHTML = `<div class="screen-head"><h1>${esc(title)}</h1><span class="sub">${esc(sub)}</span>
      <div class="actions"><select class="eng-select" id="runSelect2"></select></div></div>
      <div id="runBody"><div class="muted">loading runs…</div></div>`;
    getJSON('/api/runs').then((d) => {
      const runs = (d.runs || []).filter((r) => r.has_report);
      const sel = document.getElementById('runSelect2');
      sel.innerHTML = runs.length ? runs.map((r) => `<option value="${esc(r.run_id)}">${esc(r.run_id)} · ${esc(r.target || '')}</option>`).join('')
        : '<option value="">no completed runs</option>';
      sel.onchange = () => { currentRun = sel.value; cb(sel.value); };
      const pick = (currentRun && runs.some((r) => r.run_id === currentRun)) ? currentRun : (runs[0] && runs[0].run_id);
      if (pick) { sel.value = pick; currentRun = pick; cb(pick); }
      else document.getElementById('runBody').innerHTML = '<div class="empty">no completed runs — launch a scan from <a href="#live">Live Run</a></div>';
    }).catch((e) => { document.getElementById('runBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
  }

  // ---- screens: Attack Graph --------------------------------------------
  function renderGraph(main) {
    withRun(main, 'Attack Graph', 'the world-model — belief-weighted, attacker→crown-jewel paths, choke-points', (run) => {
      const body = document.getElementById('runBody'); body.innerHTML = '<div class="muted">reconstructing world-model…</div>';
      getJSON('/api/worldmodel/' + encodeURIComponent(run)).then((d) => {
        if (d.pending) { body.innerHTML = '<div class="stub">run still in progress</div>'; return; }
        body.innerHTML = `
          <div class="grid cols-4" style="margin-bottom:var(--sp-4)">
            <div class="tile"><div class="k">Nodes</div><div class="v">${num(d.node_count)}</div></div>
            <div class="tile"><div class="k">Edges</div><div class="v">${num(d.edge_count)}</div></div>
            <div class="tile"><div class="k">Attack paths</div><div class="v">${num((d.paths||[]).length)}</div><div class="foot">attacker→crown jewel</div></div>
            <div class="tile"><div class="k">Choke-points</div><div class="v">${num((d.chokes||[]).length)}</div><div class="foot">remediation levers</div></div>
          </div>
          <div class="card" style="margin-bottom:var(--sp-4)"><h3>World-model</h3><div id="graphCanvas"></div></div>
          <div class="grid cols-2">
            <div class="card"><h3>Attack paths <span class="muted" style="font-weight:400">(mission-ranked)</span></h3>${(d.paths||[]).length ?
              d.paths.slice().sort((a,b)=>(b.value||1)-(a.value||1)).map((p) =>
              `<div style="padding:6px 0;border-bottom:1px solid var(--border)"><span class="badge oracle" title="business impact of the crown jewel reached">◆ ${Number(p.value||1).toFixed(1)}</span>
                <span class="badge ${p.detection_cost<.5?'ok':p.detection_cost<.8?'warn':'danger'}" style="margin-left:4px">${Number(p.detection_cost).toFixed(2)} detect</span>
                <span class="mono" style="margin-left:8px;font-size:var(--fs-xs)">${esc(p.description)}</span></div>`).join('') : '<div class="muted">no attacker→crown-jewel path (findings not chainable to a crown jewel)</div>'}</div>
            <div class="card"><h3>Choke-points <span class="muted" style="font-weight:400">(cut these to disconnect — impact-ranked)</span></h3>
              ${(d.chokes||[]).length ? `<table class="tbl"><thead><tr><th>edge</th><th>impact</th><th>betw.</th><th>bridge</th><th>disc.</th></tr></thead><tbody>
                ${d.chokes.map((c) => `<tr><td class="mono" style="font-size:var(--fs-xs)">${esc(c.src)} →<br>${esc(c.dst)}</td>
                  <td><span class="badge ${(c.impact_disconnected||0)>0?'warn':''}">${Number(c.impact_disconnected||0).toFixed(1)}</span></td>
                  <td>${c.betweenness}</td><td>${c.is_bridge?'<span class="badge danger">yes</span>':dash()}</td>
                  <td>${num((c.disconnects||[]).length)}</td></tr>`).join('')}</tbody></table>` : '<div class="muted">none computed</div>'}</div>
          </div>`;
        Graph.render(document.getElementById('graphCanvas'), d, (n) => drawer(n.id, `<div class="kv">
          <div class="k">kind</div><div class="v"><span class="badge" style="color:${Graph.color(n.kind)}">${esc(n.kind)}</span></div>
          <div class="k">belief (mean)</div><div class="v">${esc(n.belief)}</div>
          <div class="k">confidence</div><div class="v">${esc(n.confidence)}</div>
          <div class="k">provenance</div><div class="v mono">${esc(n.provenance)}</div>
          <div class="k">detail</div><div class="v">${dash(n.detail)}</div></div>`));
      }).catch((e) => { body.innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
    });
  }

  // ---- screens: Evidence Browser ----------------------------------------
  function renderEvidence(main) {
    withRun(main, 'Evidence', 'provable findings — every certificate re-verified offline (prove-don’t-guess)', (run) => {
      const body = document.getElementById('runBody'); body.innerHTML = '<div class="muted">re-verifying certificates…</div>';
      getJSON('/api/evidence/' + encodeURIComponent(run)).then((d) => {
        if (d.pending) { body.innerHTML = '<div class="stub">run still in progress</div>'; return; }
        const fs = d.findings || [];
        const soundBadge = (f) => f.sound ? '<span class="badge ok">sound</span>'
          : (f.has_certificate ? '<span class="badge danger">FAILED</span>' : '<span class="badge">no cert</span>');
        body.innerHTML = `
          <div class="grid cols-4" style="margin-bottom:var(--sp-4)">
            <div class="tile"><div class="k">Findings</div><div class="v">${num(fs.length)}</div></div>
            <div class="tile"><div class="k">Re-verified</div><div class="v">${num(d.reproduced)}</div><div class="foot">reproduced offline</div></div>
            <div class="tile"><div class="k">With certificate</div><div class="v">${num(fs.filter((f)=>f.has_certificate).length)}</div></div>
            <div class="tile"><div class="k">Tampered / spurious</div><div class="v">${num(fs.filter((f)=>f.has_certificate && !f.sound).length)}</div></div>
          </div>
          <div class="card"><h3>Certificates <span class="muted" style="font-weight:400">— each re-runs with no target and no trust in the producing tool</span></h3>
          ${fs.length ? `<div class="scroll-x"><table class="tbl"><thead><tr><th>finding</th><th>bug class</th><th>surface</th><th>confirmed by</th><th>conf</th><th>status</th></tr></thead><tbody>
            ${fs.map((f) => `<tr><td class="mono">${esc(f.ref)}</td><td class="mono">${esc(f.bug_class)}</td>
              <td class="muted">${dash(f.surface)}</td><td>${dash(f.confirmed_by)}</td><td>${esc(f.confidence)}</td>
              <td>${soundBadge(f)}${f.matches_claim===false?' <span class="badge danger" title="'+esc(f.note)+'">claim-mismatch</span>':''}</td></tr>`).join('')}</tbody></table></div>`
            : '<div class="muted">no findings to re-verify</div>'}
          <div class="muted" style="font-size:var(--fs-xs);margin-top:10px">${esc(d.doctrine||'')}</div></div>`;
      }).catch((e) => { body.innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
    });
  }

  // ---- screens: Timeline ------------------------------------------------
  function renderTimeline(main) {
    withRun(main, 'Timeline', 'how the world-model was built — scrub the monotonic sequence to replay graph growth', (run) => {
      const body = document.getElementById('runBody'); body.innerHTML = '<div class="muted">reconstructing…</div>';
      getJSON('/api/worldmodel/' + encodeURIComponent(run)).then((d) => {
        if (d.pending) { body.innerHTML = '<div class="stub">run still in progress</div>'; return; }
        const nodes = d.nodes || [], edges = d.edges || [];
        const maxSeq = Math.max(1, ...nodes.map((n)=>n.last_seen||0), ...edges.map((e)=>e.last_seen||0));
        body.innerHTML = `
          <div class="card" style="margin-bottom:var(--sp-4)">
            <h3>Replay <span class="muted" style="font-weight:400">seq <span id="tlSeq">${maxSeq}</span> / ${maxSeq}</span></h3>
            <input id="tlSlider" type="range" min="1" max="${maxSeq}" value="${maxSeq}" style="width:100%">
            <div class="grid cols-3" style="margin-top:var(--sp-3)">
              <div class="tile"><div class="k">Nodes present</div><div class="v" id="tlNodes">${nodes.length}</div></div>
              <div class="tile"><div class="k">Edges present</div><div class="v" id="tlEdges">${edges.length}</div></div>
              <div class="tile"><div class="k">Newest</div><div class="v" id="tlNew" style="font-size:var(--fs-sm)">—</div></div>
            </div>
          </div>
          <div class="card"><h3>Appearance order</h3><div id="tlLog" class="feed" style="max-height:340px"></div></div>`;
        const rows = [
          ...nodes.map((n)=>({seq:n.first_seen||1, kind:'node', label:n.id, tag:n.kind})),
          ...edges.map((e)=>({seq:e.first_seen||1, kind:'edge', label:`${e.src} --${e.kind}--> ${e.dst}`, tag:e.technique})),
        ].sort((a,b)=>a.seq-b.seq);
        const slider = document.getElementById('tlSlider');
        const apply = (t) => {
          document.getElementById('tlSeq').textContent = t;
          document.getElementById('tlNodes').textContent = nodes.filter((n)=>(n.first_seen||1)<=t).length;
          document.getElementById('tlEdges').textContent = edges.filter((e)=>(e.first_seen||1)<=t).length;
          const shown = rows.filter((r)=>r.seq<=t);
          document.getElementById('tlNew').textContent = shown.length ? ('seq '+shown[shown.length-1].seq) : '—';
          document.getElementById('tlLog').innerHTML = shown.map((r)=>`<div class="row"><span class="t">${r.seq}</span>
            <span class="ev ${r.kind==='edge'?'gate':''}">${r.kind}</span><span class="msg mono">${esc(r.label)}</span>
            <span class="muted" style="font-size:var(--fs-xs)">${esc(r.tag||'')}</span></div>`).join('') || '<div class="muted" style="padding:var(--sp-3)">nothing yet</div>';
        };
        slider.addEventListener('input', () => apply(Number(slider.value)));
        apply(maxSeq);
      }).catch((e) => { body.innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
    });
  }

  // ---- screens: Coverage -------------------------------------------------
  function renderCoverage(main) {
    withRun(main, 'Coverage', 'surface coverage — stack, discovered endpoints, passive hygiene, DOM-XSS leads', (run) => {
      const body = document.getElementById('runBody');
      getJSON('/api/coverage/' + encodeURIComponent(run)).then((d) => {
        if (d.pending) { body.innerHTML = '<div class="stub">run still in progress</div>'; return; }
        const s = d.summary || {};
        body.innerHTML = `
          <div class="grid cols-4" style="margin-bottom:var(--sp-4)">
            <div class="tile"><div class="k">Pages crawled</div><div class="v">${num(s.pages_crawled)}</div></div>
            <div class="tile"><div class="k">Endpoints found</div><div class="v">${num((d.discovered_endpoints||[]).length + (s.discovered_endpoints||0))}</div></div>
            <div class="tile"><div class="k">Passive</div><div class="v">${num((d.passive||[]).length)}</div><div class="foot">hygiene</div></div>
            <div class="tile"><div class="k">DOM-XSS leads</div><div class="v">${num((d.dom_xss||[]).length)}</div><div class="foot">candidates</div></div>
          </div>
          <div class="card" style="margin-bottom:var(--sp-4)"><h3>Detected stack (fingerprint)</h3>
            <div class="row-flex" style="flex-wrap:wrap">${(d.fingerprint||[]).length ? d.fingerprint.map((t) => `<span class="badge">${esc(t)}</span>`).join(' ') : '<span class="muted">no stack tokens</span>'}</div></div>
          <div class="grid cols-2">
            <div class="card"><h3>Passive findings</h3>${(d.passive||[]).length ? `<table class="tbl"><tbody>
              ${d.passive.map((f) => `<tr><td><span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span></td><td class="mono">${esc(f.bug_class)}</td><td class="muted">${esc(f.title)}</td></tr>`).join('')}</tbody></table>` : '<div class="muted">none</div>'}</div>
            <div class="card"><h3>Discovered endpoints</h3><div class="feed" style="max-height:300px">${(d.discovered_endpoints||[]).length ? d.discovered_endpoints.map((e) => `<div class="row"><span class="msg mono">${esc(e)}</span></div>`).join('') : '<div class="muted" style="padding:var(--sp-3)">none (SPA crawl off / static target)</div>'}</div></div>
          </div>`;
      }).catch((e) => { body.innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
    });
  }

  // ---- screens: Benchmark ------------------------------------------------
  function renderBenchmark(main) {
    main.innerHTML = `<div class="screen-head"><h1>Benchmark</h1><span class="sub">CRUCIBLE vs incumbents + the regression gate</span></div>
      <div id="benchBody"><div class="muted">loading…</div></div>`;
    getJSON('/api/benchmark').then((d) => {
      const body = document.getElementById('benchBody');
      const res = d.results; if (!res) { body.innerHTML = '<div class="empty">no committed benchmark-results.json — run <code>make bench</code></div>'; return; }
      const rows = res.results || [];
      const crucible = rows.find((r) => r.tool === 'crucible') || {};
      const base = (d.baseline && d.baseline.scores && d.baseline.scores['benchmark-app'] && d.baseline.scores['benchmark-app'].crucible) || null;
      let gate = 'no baseline';
      if (base) { const reg = (crucible.fp > base.fp) || (crucible.tp < base.tp); gate = reg ? 'REGRESSION' : 'PASS'; }
      body.innerHTML = `
        <div class="grid cols-4" style="margin-bottom:var(--sp-4)">
          <div class="tile"><div class="k">CRUCIBLE precision</div><div class="v">${crucible.precision!=null?Number(crucible.precision).toFixed(3):dash()}</div><div class="foot">${num(crucible.tp)} tp · ${num(crucible.fp)} fp</div></div>
          <div class="tile"><div class="k">Recall</div><div class="v">${crucible.recall!=null?Number(crucible.recall).toFixed(3):dash()}</div></div>
          <div class="tile"><div class="k">Gate</div><div class="v sm"><span class="badge ${gate==='PASS'?'ok':gate==='REGRESSION'?'danger':'warn'}">${esc(gate)}</span></div><div class="foot">vs committed baseline</div></div>
          <div class="tile"><div class="k">Requests</div><div class="v">${num(crucible.requests_sent)}</div><div class="foot">${crucible.elapsed_s!=null?crucible.elapsed_s+'s':''}</div></div>
        </div>
        <div class="card" style="margin-bottom:var(--sp-4)"><h3>Scoreboard <span class="muted" style="font-weight:400">— ${esc(res.corpus||'')}</span></h3>
          <div class="scroll-x"><table class="tbl"><thead><tr><th>tool</th><th>tp</th><th>fp</th><th>fn</th><th>precision</th><th>recall</th><th>f1</th><th>time_s</th><th>reqs</th><th>rss_mb</th></tr></thead><tbody>
          ${rows.map((r) => `<tr><td class="mono ${r.tool==='crucible'?'':''}">${esc(r.tool)}</td>
            <td>${num(r.tp)}</td><td>${r.fp>0?`<span class="badge danger">${r.fp}</span>`:num(r.fp)}</td><td>${num(r.fn)}</td>
            <td>${Number(r.precision).toFixed(3)}</td><td>${Number(r.recall).toFixed(3)}</td><td>${Number(r.f1).toFixed(3)}</td>
            <td>${r.elapsed_s!=null?Number(r.elapsed_s).toFixed(1):dash()}</td><td>${r.requests_sent==null?dash():num(r.requests_sent)}</td><td>${r.peak_rss_mb==null?dash():r.peak_rss_mb}</td></tr>`).join('')}</tbody></table></div>
          <div class="muted" style="font-size:var(--fs-xs);margin-top:8px">The <b>fp</b> column is the differentiator — CRUCIBLE reports only oracle-confirmed findings. <code>-</code> = the tool does not report that number.</div></div>
        <div class="card"><h3>Incumbent versions + invocations</h3><div class="kv">
          ${Object.entries(res.incumbent_versions||{}).map(([k,v]) => `<div class="k">${esc(k)}</div><div class="v mono">${esc(v)} — <span class="muted">${esc((res.incumbent_invocations||{})[k]||'')}</span></div>`).join('')}</div></div>`;
    }).catch((e) => { document.getElementById('benchBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
  }

  // ---- screens: Intelligence --------------------------------------------
  function renderIntel(main) {
    const slug = state.activeSlug;
    main.innerHTML = `<div class="screen-head"><h1>Intelligence</h1><span class="sub">reason over recon — resolved entities, source-yield learning, gated predictions</span></div><div id="intelBody"><div class="muted">${slug ? 'loading…' : 'select an engagement'}</div></div>`;
    if (!slug) return;
    getJSON('/api/intel/' + encodeURIComponent(slug)).then((d) => {
      const ents = d.entities || [], ys = d.source_yield || [], preds = d.predictions || [];
      const entRows = ents.map((e) => `
        <tr><td class="mono">${esc(e.id)}</td>
          <td><span class="badge ${e.confidence>=.9?'ok':e.confidence>=.7?'warn':''}">${e.confidence}</span></td>
          <td class="muted">${e.members.map(esc).join('<br>')}</td>
          <td class="mono">${(e.owned_by||[]).map(esc).join(', ') || '<span class="muted">—</span>'}</td>
          <td class="muted" style="font-size:var(--fs-xs)">${(e.why||[]).map(esc).join('<br>') || '<span class="muted">single reference</span>'}</td></tr>`).join('');
      const yRows = ys.map((y) => `
        <tr><td class="mono">${esc(y.source_kind)}</td><td class="muted">${dash(y.archetype)}</td>
          <td>${num(y.queries)}</td><td>${num(y.observations_yielded)}</td><td>${num(y.entities_yielded)}</td>
          <td>${num(y.findings_downstream)}</td>
          <td><span class="badge ${y.calibrated_prior>=.6?'ok':y.calibrated_prior>=.4?'warn':''}">${y.calibrated_prior}</span></td></tr>`).join('');
      const predRows = preds.map((p) => `
        <tr><td class="mono">${esc(p.predicted)}</td><td class="muted">${esc(p.pattern)}</td>
          <td>${p.prior}</td><td><span class="badge oracle">${p.posterior}</span></td>
          <td class="muted" style="font-size:var(--fs-xs)">${esc(p.decisive_test)}</td>
          <td><span class="badge warn">gated</span></td></tr>`).join('');
      document.getElementById('intelBody').innerHTML = `
        <div class="grid cols-4" style="margin-bottom:var(--sp-4)">
          <div class="tile"><div class="k">observations</div><div class="v">${num(d.observations)}</div></div>
          <div class="tile"><div class="k">entities</div><div class="v">${num(ents.length)}</div></div>
          <div class="tile"><div class="k">owned assets</div><div class="v">${num(ents.filter((e)=>(e.owned_by||[]).length).length)}</div></div>
          <div class="tile"><div class="k">predictions</div><div class="v">${num(preds.length)}</div></div>
        </div>
        <div class="card"><h3>Resolved entities <span class="muted" style="font-weight:400">— many references, one asset, explainably</span></h3>
        ${ents.length ? `<div class="scroll-x"><table class="tbl"><thead><tr><th>entity</th><th>conf</th><th>members</th><th>owned by</th><th>why (merge signals)</th></tr></thead><tbody>${entRows}</tbody></table></div>`
          : '<div class="muted">no entities yet — run <span class="mono">intel ingest --seed &lt;apex&gt; --slug '+esc(slug)+'</span></div>'}</div>
        <div class="card"><h3>Source-yield learning <span class="muted" style="font-weight:400">— which recon source pays off, calibrated priors feed the planner</span></h3>
        ${ys.length ? `<div class="scroll-x"><table class="tbl"><thead><tr><th>source</th><th>archetype</th><th>queries</th><th>obs</th><th>entities</th><th>findings</th><th>prior</th></tr></thead><tbody>${yRows}</tbody></table></div>`
          : '<div class="muted">no yield recorded yet — accrues as sources are queried across engagements</div>'}</div>
        <div class="card"><h3>Prediction queue <span class="muted" style="font-weight:400">— gated hypotheses, never facts, never auto-scanned</span></h3>
        ${preds.length ? `<div class="scroll-x"><table class="tbl"><thead><tr><th>predicted asset</th><th>pattern</th><th>prior</th><th>posterior</th><th>decisive test</th><th>status</th></tr></thead><tbody>${predRows}</tbody></table></div>`
          : '<div class="muted">no predictions — they derive from observed assets</div>'}
        <div class="muted" style="font-size:var(--fs-xs);margin-top:10px">${esc(d.doctrine||'')}</div></div>`;
    }).catch((e) => { document.getElementById('intelBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
  }

  // ---- screens: Memory ---------------------------------------------------
  function renderMemory(main) {
    main.innerHTML = `<div class="screen-head"><h1>Memory</h1><span class="sub">cross-engagement learning — Beta priors with provenance</span></div><div id="memBody"><div class="muted">loading…</div></div>`;
    getJSON('/api/memory').then((d) => {
      const s = d.summary || {}; const pr = d.priors || [];
      document.getElementById('memBody').innerHTML = `
        <div class="grid cols-4" style="margin-bottom:var(--sp-4)">
          ${['engagements','findings','hypotheses','payloads','dead_ends','priors'].filter((k)=>k in s).slice(0,4).map((k)=>`<div class="tile"><div class="k">${esc(k.replace('_',' '))}</div><div class="v">${num(s[k])}</div></div>`).join('')}
        </div>
        <div class="card"><h3>Archetype priors <span class="muted" style="font-weight:400">— what paid off, by bug class</span></h3>
        ${pr.length ? `<div class="scroll-x"><table class="tbl"><thead><tr><th>archetype</th><th>bug class</th><th>surface</th><th>successes</th><th>attempts</th><th>mean</th><th>Wilson LB</th></tr></thead><tbody>
          ${pr.map((p)=>`<tr><td class="mono">${esc(p.archetype)}</td><td class="mono">${esc(p.bug_class)}</td><td class="muted">${dash(p.surface)}</td>
            <td>${num(p.successes)}</td><td>${num(p.attempts)}</td>
            <td><span class="badge ${p.mean>=.6?'ok':p.mean>=.3?'warn':''}">${p.mean}</span></td><td>${p.lower_bound}</td></tr>`).join('')}</tbody></table></div>`
          : '<div class="muted">no priors yet — they accumulate as engagements complete (mean = Laplace, LB = Wilson 95%)</div>'}</div>`;
    }).catch((e)=>{ document.getElementById('memBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
  }

  // ---- screens: Kernel ---------------------------------------------------
  function renderKernel(main) {
    main.innerHTML = `<div class="screen-head"><h1>Kernel (Cognition)</h1><span class="sub">the URK layer — structured LLM outputs, type-checked</span></div><div id="kBody"><div class="muted">loading…</div></div>`;
    getJSON('/api/kernel').then((d)=>{
      document.getElementById('kBody').innerHTML = `
        <div class="grid cols-2">
          <div class="card"><h3>LLM backends</h3><table class="tbl"><tbody>
            ${(d.backends||[]).map((b)=>`<tr><td>${b.available?'<span class="badge ok">up</span>':'<span class="badge">·</span>'}</td><td class="mono">${esc(b.name)}</td><td class="muted">${esc(b.note)}</td></tr>`).join('')}</tbody></table>
            <div class="muted" style="font-size:var(--fs-xs);margin-top:8px">${esc(d.note||'')}</div></div>
          <div class="card"><h3>Cognitive outputs</h3><div class="row-flex" style="flex-wrap:wrap">
            ${(d.cognitive_docs||[]).map((c)=>`<span class="badge oracle">${esc(c)}</span>`).join(' ')}</div>
            <div class="muted" style="font-size:var(--fs-xs);margin-top:10px">Each returns a typed result + a CallTrace (backend, dryrun, tokens_in/out, latency_ms). DryRun by default (no network/GPU).</div></div>
        </div>`;
    }).catch((e)=>{ document.getElementById('kBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
  }

  // ---- screens: Authority & Safety --------------------------------------
  function renderAuthority(main) {
    const slug = state.activeSlug;
    main.innerHTML = `<div class="screen-head"><h1>Authority &amp; Safety</h1><span class="sub">fail-closed governance for <code class="mono">${esc(slug||'—')}</code></span></div><div id="auBody"></div>`;
    if (!slug) { document.getElementById('auBody').innerHTML = '<div class="empty">select an engagement</div>'; return; }
    getJSON('/api/authority/'+encodeURIComponent(slug)).then((d)=>{
      const ks=d.killswitch||{}; const au=d.authority||{};
      document.getElementById('auBody').innerHTML = `
        <div class="grid cols-3" style="margin-bottom:var(--sp-4)">
          <div class="tile"><div class="k">Kill-switch</div><div class="v sm">${ks.tripped?'<span class="badge danger">TRIPPED</span>':'<span class="badge ok">armed</span>'}</div><div class="foot">${esc(ks.reason||'')}</div></div>
          <div class="tile"><div class="k">Environment</div><div class="v sm">${au.environment?`<span class="badge">${esc(au.environment)}</span>`:dash()}</div></div>
          <div class="tile"><div class="k">Charter</div><div class="v sm">${d.charter_present?'<span class="badge ok">signed</span>':'<span class="badge warn">missing</span>'}</div></div>
        </div>
        <div class="grid cols-2">
          <div class="card"><h3>Authority window</h3><div class="kv">
            <div class="k">scope</div><div class="v mono">${au.scope&&au.scope.length?au.scope.map(esc).join('<br>'):dash()}</div>
            <div class="k">valid</div><div class="v mono">${dash(au.not_before)} → ${dash(au.not_after)}</div>
            <div class="k">destructive</div><div class="v">${au.allow_destructive==null?dash():(au.allow_destructive?'allowed':'denied')}</div>
            <div class="k">max actions</div><div class="v">${num(au.max_actions)}</div>
            <div class="k">issued by</div><div class="v mono">${dash(au.issued_by)}</div></div></div>
          <div class="card"><h3>The six-gate stack <span class="muted" style="font-weight:400">(every request)</span></h3>
            <div style="display:flex;flex-direction:column;gap:6px">
            ${(d.gates||[]).map((g,i)=>`<div class="row-flex"><span class="badge">${i+1}</span><span class="mono">${esc(g)}</span></div>`).join('')}</div>
            <div style="margin-top:var(--sp-4)"><button class="btn danger" onclick="Console.tripKill('${esc(slug)}')">⛔ Trip kill-switch (emergency stop)</button>
              <span id="tripMsg" style="margin-left:10px"></span></div></div>
        </div>`;
    }).catch((e)=>{ document.getElementById('auBody').innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
  }
  async function tripKill(slug) {
    if (!confirm(`Trip the kill-switch for "${slug}"? This is an emergency hard stop.`)) return;
    const msg=document.getElementById('tripMsg'); msg.innerHTML='<span class="muted">tripping…</span>';
    try { const r=await fetch('/api/killswitch/'+encodeURIComponent(slug)+'/trip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason:'tripped from Ops Console'})});
      const d=await r.json(); msg.innerHTML = d.error?`<span class="badge danger">${esc(d.error)}</span>`:'<span class="badge danger">tripped</span>';
      refreshSafety(); setTimeout(()=>route(),400);
    } catch(e){ msg.innerHTML=`<span class="badge danger">${esc(e.message)}</span>`; }
  }

  // ---- screens: Planner --------------------------------------------------
  function renderPlanner(main) {
    const slug = state.activeSlug;
    main.innerHTML = `<div class="screen-head"><h1>Planner</h1><span class="sub">goal tree + best-first / VOI search for <code>${esc(slug||'—')}</code></span></div><div id="plBody"></div>`;
    if (!slug) { document.getElementById('plBody').innerHTML='<div class="empty">select an engagement</div>'; return; }
    getJSON('/api/planner/'+encodeURIComponent(slug)).then((d)=>{
      if (!d.present) { document.getElementById('plBody').innerHTML = `<div class="stub"><b>No planner state</b> for this engagement. The planner drives best-first / value-of-information search over a mutable goal tree; run it via <code>python3 -m framework.v2</code> to populate <code>.planner-state.json</code>.</div>`; return; }
      document.getElementById('plBody').innerHTML = `<div class="card"><h3>Planner state</h3><pre class="cert">${esc(JSON.stringify(d.state, null, 2))}</pre></div>`;
    }).catch((e)=>{ document.getElementById('plBody').innerHTML=`<div class="empty">${esc(e.message)}</div>`; });
  }

  // ---- screens: Reasoning Brain -----------------------------------------
  function renderReasoning(main) {
    withRun(main, 'Reasoning Brain', 'the adaptive scan intelligence — bandit ordering, WAF-evasion, grammar fuzzing', (run) => {
      const body=document.getElementById('runBody');
      getJSON('/api/coverage/'+encodeURIComponent(run)).then((d)=>{
        body.innerHTML = `<div class="grid cols-2">
          <div class="card"><h3>Detected stack (drives gated checks)</h3><div class="row-flex" style="flex-wrap:wrap">${(d.fingerprint||[]).length?d.fingerprint.map((t)=>`<span class="badge">${esc(t)}</span>`).join(' '):'<span class="muted">no fingerprint (library off for this run)</span>'}</div></div>
          <div class="card"><h3>Adaptive modules</h3><div style="display:flex;flex-direction:column;gap:8px">
            <div><span class="badge oracle">contextual bandit</span> <span class="muted">Thompson sampling orders checks per (context, bug_class); persisted with <code>--bandit-file</code>, transferable across engagements.</span></div>
            <div><span class="badge oracle">WAF-evasion</span> <span class="muted">on a filtered probe, synthesize a bypass (evasion ladder → GA) that still fires the oracle (<code>--waf-adaptive</code>).</span></div>
            <div><span class="badge oracle">grammar-fuzz</span> <span class="muted">induce a request grammar from the crawl, synthesize structurally-valid new requests (<code>--grammar-fuzz N</code>).</span></div>
            <div><span class="badge oracle">constraint inference</span> <span class="muted">learn a filter's predicate from black-box membership queries.</span></div>
          </div></div></div>
          <div class="muted" style="font-size:var(--fs-xs);margin-top:var(--sp-3)">Bandit posteriors surface here once a run persists a <code>--bandit-file</code>.</div>`;
      }).catch((e)=>{ body.innerHTML=`<div class="empty">${esc(e.message)}</div>`; });
    });
  }

  // ---- screens: Reports --------------------------------------------------
  function renderReports(main) {
    const slug = state.activeSlug;
    main.innerHTML = `<div class="screen-head"><h1>Reports</h1><span class="sub">generated deliverables for <code>${esc(slug||'—')}</code></span></div><div id="rpBody"></div>`;
    if (!slug) { document.getElementById('rpBody').innerHTML='<div class="empty">select an engagement</div>'; return; }
    getJSON('/api/reports/'+encodeURIComponent(slug)).then((d)=>{
      const rs=d.reports||[];
      document.getElementById('rpBody').innerHTML = `<div class="card"><h3>Report files</h3>
        ${rs.length?`<table class="tbl"><thead><tr><th>file</th><th>size</th></tr></thead><tbody>
          ${rs.map((f)=>`<tr><td class="mono">${esc(f.name)}</td><td>${num(f.size)} b</td></tr>`).join('')}</tbody></table>`
          :`<div class="stub">No report files under <code>targets/${esc(slug)}/reports/</code> yet. CRUCIBLE emits executive / technical / remediation (markdown), and <code>scan --format sarif|html</code> produces SARIF/HTML.</div>`}</div>`;
    }).catch((e)=>{ document.getElementById('rpBody').innerHTML=`<div class="empty">${esc(e.message)}</div>`; });
  }

  // ---- on-demand subsystem info panels (defender/social/analysis/improve/intake) ----
  const SUBSYS = {
    defender: { title: 'Defender (DEL)', role: 'Self-assesses the DETECTABILITY of the framework\'s own actions against Sigma-style rules — it measures footprint, it never generates evasion.',
      produces: ['DetectionScore (detectability, loudest channel/severity)', 'per-rule hits by channel (access-log / waf / auth / netflow / edr / dns)', 'posture annotation + guidance'], cli: 'defender score|annotate|rules' },
    socialdefense: { title: 'Social Defense', role: 'Scores inbound messages for phishing / social-engineering risk (defensive).',
      produces: ['PhishingAssessment (noisy-OR score + risk band)', 'triggered indicators with weights + evidence', 'a recommendation'], cli: 'socialdefense assess' },
    analysis: { title: 'Analysis (SAST)', role: 'Runs built-in + external static analyzers (semgrep / joern-style dataflow, CPG) over a source tree, normalized to one finding shape.',
      produces: ['AnalysisReport (files scanned, analyzers run/skipped + reasons)', 'findings by path:line / rule / CWE / severity + snippet', 'severity histogram'], cli: 'analysis scan|index|analyzers|review' },
    improve: { title: 'Improve (SIL)', role: 'Mines engagements for capability gaps and drafts reviewable improvement proposals — it never self-applies; a merge gate governs.',
      produces: ['CapabilityGap backlog by priority', 'ProposedChange (diff + status draft→eval→approved→merged)', 'MergeDecision (approvals, eval pass, threshold)'], cli: 'improve review|horizon|show' },
    intake: { title: 'Intake', role: 'Passively fingerprints a target from captured HTTP, classifies it to an archetype, and scaffolds the engagement (charter / threat-model / attack-tree drafts).',
      produces: ['Fingerprint (detectors by category + confidence + evidence)', 'Classification (primary archetype + runners-up)', 'scaffold paths'], cli: 'intake run|authorize|fingerprint' },
  };
  function subsystem(main, key) {
    const s = SUBSYS[key];
    main.innerHTML = `<div class="screen-head"><h1>${esc(s.title)}</h1><span class="sub">on-demand subsystem</span></div>
      <div class="grid cols-2">
        <div class="card"><h3>What it does</h3><p style="margin:0;color:var(--text-1)">${esc(s.role)}</p>
          <h3 style="margin-top:var(--sp-4)">Invoke</h3><pre class="cert">python3 -m framework.v2 ${esc(s.cli)}</pre></div>
        <div class="card"><h3>Produces</h3><ul style="margin:0;padding-left:18px;color:var(--text-1)">
          ${s.produces.map((p)=>`<li style="margin-bottom:6px">${esc(p)}</li>`).join('')}</ul></div>
      </div>
      <div class="muted" style="font-size:var(--fs-xs);margin-top:var(--sp-4)">This subsystem produces output on demand (no standing artifact to tail); its results render here once a run persists them. The console reflects the system — it never drives it.</div>`;
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

  return { init, openEngagement, closeDrawer, launchScan, selectRun, openFinding, reverify, tripKill };
})();

document.addEventListener('DOMContentLoaded', Console.init);
