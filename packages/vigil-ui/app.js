"use strict";
/* ==========================================================================
   VIGIL COMMAND — app.js : the unified shell + Home (P1).
   Federates two same-origin backends via a reverse proxy:
     window.VIGIL_CFG = { token, api: { sovereign: "/sovereign", offense: "/offense" } }
   Screens beyond Home are registered as guided stubs in P1; P2+ fill them in.
   CSP-native: built entirely with VUI.h (no inline handlers, no eval).
   ========================================================================== */
(function () {
  const V = window.VUI;
  const h = V.h;
  const CFG = window.VIGIL_CFG || (window.VIGIL_CFG = { token: "", api: { sovereign: "/sovereign", offense: "/offense" } });
  const SOV = function (p) { return CFG.api.sovereign + p; };
  const OFF = function (p) { return CFG.api.offense + p; };

  const app = V.store({ plane: "all", nav: [], counts: { agents: 0, tools: 0, findings: 0 }, live: "idle", waiting: 0, killed: false });

  // -- navigation model (every capability has a home; P1 marks not-yet-built) --
  const NAV = [
    { group: "DO", items: [
      { id: "home", label: "Home", icon: "home", ready: true },
      { id: "assess", label: "New Assessment", icon: "assess", ready: true },
      { id: "live", label: "Live", icon: "live", ready: true },
      { id: "findings", label: "Findings", icon: "find", phase: "P3" },
      { id: "fixes", label: "Fixes", icon: "fixes", phase: "P6" },
      { id: "defense", label: "Defense (AEGIS)", icon: "shield", phase: "P5" },
    ]},
    { group: "MANAGE", items: [
      { id: "safety", label: "Approvals & Safety", icon: "key", owner: true, phase: "P4" },
      { id: "tools", label: "Tools", icon: "bolt", ready: true },
      { id: "brain", label: "Brain", icon: "brain", phase: "P7" },
      { id: "settings", label: "Settings", icon: "gear", owner: true, phase: "P4" },
    ]},
    { group: "LEARN", items: [
      { id: "manual", label: "Manual", icon: "book", ready: true },
    ]},
  ];

  // ---- shell -----------------------------------------------------------------
  function topbar() {
    const seg = h("div.segmented", null, ["all", "offense", "defense"].map(function (p) {
      return h("button" + (app.get().plane === p ? ".on" : ""), { dataset: { plane: p },
        onClick: function () { app.set({ plane: p }); renderNav(); } }, p[0].toUpperCase() + p.slice(1));
    }));
    const cmdk = h("div.cmdk", { title: "Command palette (⌘K)", onClick: openPalette },
      [V.icon("search"), "Search or run a command", h("span.kbd", null, "⌘K")]);
    const s = app.get();
    const live = s.killed ? V.pill("Kill-switch", "danger", null)
      : (s.live === "live" ? V.pill("Live", "live", null) : V.pill("Idle", "idle", null));
    const counts = h("div.counts", null, [
      h("span.count", null, [V.icon("brain"), h("b", null, String(s.counts.agents)), " agents"]),
      h("span.count", null, [V.icon("bolt"), h("b", null, String(s.counts.tools)), " tools"]),
      h("span.count", null, [V.icon("find"), h("b", null, String(s.counts.findings)), " findings"]),
    ]);
    const safety = s.killed
      ? h("button.safety.tripped", { onClick: function () { location.hash = "#/safety"; } }, "KILL-SWITCH TRIPPED")
      : (s.waiting > 0
        ? h("button.safety.waiting", { onClick: function () { location.hash = "#/safety"; } }, [V.icon("key"), s.waiting + " waiting for you"])
        : h("button.safety.clear", { onClick: function () { location.hash = "#/safety"; } }, [V.icon("check"), "Safe · 0 waiting"]));
    const themeBtn = h("button.iconbtn", { title: "Toggle theme", onClick: toggleTheme }, V.icon("dot"));
    const cta = h("button.btn.primary", { onClick: function () { location.hash = "#/assess"; } }, [V.icon("bolt"), "New Assessment"]);
    return h("div#topbar", null, [seg, cmdk, h("div.spacer"), counts, live, safety, themeBtn, cta]);
  }

  function renderNav() {
    const nav = V.$("#nav"); if (!nav) return;
    const plane = app.get().plane;
    const visible = function (it) {
      if (plane === "all") return true;
      if (it.id === "defense") return plane === "defense";
      if (["assess", "live", "findings", "fixes"].indexOf(it.id) >= 0) return plane === "offense";
      return true; // home + manage always
    };
    V.mount(nav, NAV.map(function (grp) {
      return [h("div.nav-group.label", null, grp.group),
        grp.items.filter(visible).map(function (it) { return navItem(it); })];
    }));
  }
  function navItem(it) {
    const active = current() === it.id;
    const badge = it.id === "safety" && app.get().waiting > 0
      ? h("span.badge-count.owner", null, String(app.get().waiting)) : null;
    return h("div.nav-item" + (it.owner ? ".owner" : "") + (active ? ".active" : ""),
      { dataset: { nav: it.id }, onClick: function () { location.hash = "#/" + it.id; } },
      [V.icon(it.icon), h("span.txt", null, it.label), badge]);
  }
  function current() { return (location.hash || "#/home").slice(2).split("?")[0] || "home"; }

  function shell() {
    document.body.appendChild(h("div#app", null, [
      h("div#brand", null, [h("span.logo", null, "V"), h("span.name", null, "VIGIL COMMAND")]),
      topbar(),
      h("div#nav"),
      h("div#main", null, h("div.wrap#screen")),
    ]));
    document.body.appendChild(h("div#drawer", null, [h("div.dh", null, [h("h2#drawer-title", null, "Detail"),
      h("button.iconbtn", { onClick: closeDrawer }, V.icon("x"))]), h("div.db#drawer-body")]));
    renderNav();
  }

  // ---- drawer ----------------------------------------------------------------
  function openDrawer(title, body) {
    V.$("#drawer-title").textContent = title || "Detail";
    V.mount(V.$("#drawer-body"), body);
    V.$("#drawer").classList.add("open");
  }
  function closeDrawer() { V.$("#drawer").classList.remove("open"); }

  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme");
    const next = cur === "light" ? "dark" : (cur === "dark" ? "light" : (matchMedia("(prefers-color-scheme: dark)").matches ? "light" : "dark"));
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("vigil-theme", next); } catch (e) {}
  }
  function openPalette() { V.toast("Command palette is on the roadmap — for now use the sidebar. Start a run from New Assessment."); }

  // ---- Home screen -----------------------------------------------------------
  async function renderHome(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Command"),
        h("span.sub", null, "One place to run, watch, and govern every VIGIL assessment.")]),
      h("div.grid.cols-4#home-tiles"),
      h("div.grid.cols-2", { style: { marginTop: "16px", alignItems: "start" } }, [
        V.card("Quick start", "DO", quickStart(), false),
        V.card("Recent activity", "LIVE", h("div.feed#home-feed", null, h("div.empty", null, "Connecting to the live feed…")), false),
      ]),
    ]);
    // live data from both planes (fail-soft: a plane being down never blanks the page)
    let snap = null, ostat = null;
    try { snap = await V.getJSON(SOV("/api/snapshot")); } catch (e) { /* sovereign offline */ }
    try { ostat = await V.getJSON(OFF("/api/status")); } catch (e) { /* offense offline */ }
    const waiting = (snap && (snap.pending_approvals || []).length) || 0;
    const killed = !!(snap && snap.kill_switch && (snap.kill_switch.engaged || snap.kill_switch === "engaged"));
    const findings = (ostat && (ostat.findings_confirmed != null ? ostat.findings_confirmed : (ostat.findings || 0))) || 0;
    const runs = (ostat && (ostat.active_runs != null ? ostat.active_runs : 0)) || 0;
    app.set({ waiting: waiting, killed: killed, live: runs > 0 ? "live" : "idle",
      counts: { agents: (ostat && ostat.agents) || 0, tools: (ostat && ostat.tools) || 0, findings: findings } });
    refreshTopbar();
    V.mount(V.$("#home-tiles"), [
      V.tile("Active runs", String(runs), runs ? "in progress" : "nothing running"),
      V.tile("Waiting for you", String(waiting), waiting ? "needs approval" : "all clear", waiting ? "down" : "up"),
      V.tile("Confirmed findings", String(findings), "proven by oracle"),
      V.tile("Budget today", (snap && snap.budget_today != null ? "$" + snap.budget_today : "—"), "spend so far"),
    ]);
    // merged recent activity (sovereign spine snapshot has recent_by_agent / recent_decisions)
    const rows = [];
    if (snap && snap.recent_decisions) snap.recent_decisions.slice(0, 8).forEach(function (d) {
      rows.push(feedRow("decision", d.text || d.choice || "decision", d.ts || ""));
    });
    if (!rows.length) rows.push(h("div.empty", null, [h("div.big", null, "Nothing yet"),
      "Run your first assessment and every action shows up here, live."]));
    V.mount(V.$("#home-feed"), rows);
  }
  function quickStart() {
    const items = [
      { t: "Scan a codebase", d: "Point at a path or repo; the AI reads and reasons over it.", go: "#/assess" },
      { t: "Scan a website", d: "Give a URL; VIGIL crawls and safely probes it.", go: "#/assess" },
      { t: "Defend an app", d: "Watch your own app for AI attacks (AEGIS).", go: "#/defense" },
    ];
    return h("div.stack", null, items.map(function (it) {
      return h("button.choice", { onClick: function () { location.hash = it.go; } },
        [h("span.cico", null, V.icon("play")), h("div", null, [h("div.ct", null, it.t), h("div.cd", null, it.d)])]);
    }));
  }
  function feedRow(kind, text, ts) {
    return h("div.trow.kind-" + kind, null, [
      h("div.ico", null, V.icon(kind === "finding" ? "check" : (kind === "refusal" ? "x" : "dot"))),
      h("div.body", null, [h("div.k", null, kind), h("div.m", null, text)]),
      h("div.meta", null, [h("span.t", null, String(ts || ""))]),
    ]);
  }

  function refreshTopbar() {
    const bar = V.$("#topbar"); if (!bar) return;
    const fresh = topbar();
    bar.parentNode.replaceChild(fresh, bar);
    renderNav();
  }

  // ---- Manual (in-app documentation; real content, no runtime data) ---------
  function renderManual(screen) {
    const sections = window.VIGIL_MANUAL || [];
    const index = h("div.card", { style: { position: "sticky", top: "0", alignSelf: "start" } },
      [h("span.label", null, "CONTENTS"),
       h("div.stack", { style: { gap: "2px", marginTop: "8px" } }, sections.map(function (s) {
         return h("a.nav-item", { href: "#/manual", onClick: function (e) {
           e.preventDefault(); const t = document.getElementById("man-" + s.id);
           if (t) t.scrollIntoView({ behavior: "smooth", block: "start" });
         } }, [h("span.txt", null, s.title)]);
       }))]);
    const content = h("div.stack", null, sections.map(function (s) {
      return h("div.card", { id: "man-" + s.id }, [
        h("h3", { style: { fontSize: "var(--fs-xl)", marginBottom: "12px" } }, s.title),
        s.blocks.map(function (b) { return manualBlock(b); }),
      ]);
    }));
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Manual"),
        h("span.sub", null, "How every part of VIGIL works — in plain language.")]),
      h("div", { style: { display: "grid", gridTemplateColumns: "260px 1fr", gap: "24px", alignItems: "start" } },
        [index, content]),
    ]);
  }
  function manualBlock(b) {
    if (b.h) return h("h4", { style: { marginTop: "16px", marginBottom: "6px", fontSize: "var(--fs-lg)" } }, b.h);
    if (b.p) return h("p", { class: "muted", style: { margin: "8px 0", maxWidth: "72ch", lineHeight: "1.6" } }, b.p);
    if (b.note) return h("div.legend", { style: { margin: "12px 0" } }, [V.icon("info"), b.note]);
    if (b.list) return h("div.stack", { style: { gap: "10px", margin: "10px 0" } }, b.list.map(function (row) {
      return h("div", { style: { display: "grid", gridTemplateColumns: "180px 1fr", gap: "14px" } },
        [h("b", null, row[0]), h("span.muted", null, row[1])]);
    }));
    return null;
  }

  // ---- Tools (offense host CLIs, probed LIVE via /offense/api/tools) ---------
  // Status maps onto the shared badge system: installed→confirmed (green), missing→idle,
  // failed→blocked (red), shadowed→blocked (red — a same-named impostor shadows the real tool on PATH),
  // unsupported→refuted. No hardcoded tool data — every row comes from the endpoint, which resolves
  // PATH (+ a version-banner check for name collisions) at request time; status is never invented.
  const TOOL_BADGE = { installed: "confirmed", missing: "idle", failed: "blocked",
                       shadowed: "blocked", unsupported: "refuted" };

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () { V.toast("Copied install command"); },
        function () { V.toast(text); });
    } else {
      V.toast(text);
    }
  }

  function toolBadge(status) {
    // reuse the .st/.st-<state> styling but keep the HONEST status word as the label.
    return h("span.st.st-" + (TOOL_BADGE[status] || "idle"), null, [h("span.dot"), status || "unknown"]);
  }

  function installHint(t) {
    return h("div", { style: { marginTop: "10px", display: "flex", gap: "8px", alignItems: "stretch" } }, [
      h("pre.code", { style: { flex: "1", margin: "0" } }, t.install_hint || "(install manually)"),
      h("button.btn", { title: "Copy the install command",
        onClick: function () { copyText(t.install_hint || ""); } }, "Copy"),
    ]);
  }

  function toolCard(t) {
    const needsAction = t.status === "missing" || t.status === "failed" || t.status === "shadowed";
    return h("div.card", null, [
      h("div", { style: { display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" } }, [
        toolBadge(t.status),
        h("b.mono", null, t.name),
        V.pill(t.optional ? "optional" : "core", t.optional ? "" : "danger", null),
        t.version ? h("span.muted.mono", { style: { marginLeft: "auto", fontSize: "var(--fs-xs)" } }, t.version) : null,
      ]),
      h("div.muted", { style: { marginTop: "6px", maxWidth: "80ch", lineHeight: "1.5" } }, t.purpose || ""),
      // a shadowed tool: be explicit that a same-named binary on PATH is NOT the real tool.
      t.status === "shadowed"
        ? h("div", { style: { marginTop: "6px", color: "var(--st-blocked)", fontSize: "var(--fs-sm)" } },
            "A different '" + t.name + "' on your PATH" + (t.path ? " (" + t.path + ")" : "") +
            " is shadowing the real tool — it is NOT usable. Fix PATH order or install the real one:")
        : (t.path ? h("div.muted.mono", { style: { marginTop: "4px", fontSize: "var(--fs-micro)" } }, t.path) : null),
      needsAction ? installHint(t) : null,
    ]);
  }

  function renderToolsData(d) {
    const s = d.summary || {};
    const plat = d.platform || {};
    const tools = d.tools || [];
    const supported = !!plat.supported;
    const osName = plat.pretty_name || plat.system || "this system";

    V.mount(V.$("#tools-summary"), [
      V.tile("Installed", String(s.installed || 0), "on PATH", "up"),
      V.tile("Missing", String(s.missing || 0), "not installed", s.missing ? "down" : ""),
      V.tile("Failed", String(s.failed || 0), "install failed", s.failed ? "down" : ""),
      V.tile("Required missing", String(s.required_missing || 0), "offense-core", s.required_missing ? "down" : "up"),
    ]);
    if (app.get().counts.tools !== (s.installed || 0)) {
      app.set({ counts: Object.assign({}, app.get().counts, { tools: s.installed || 0 }) });
      refreshTopbar();
    }

    const shadowNote = (s.shadowed || 0) > 0
      ? "  " + s.shadowed + " tool(s) SHADOWED (a same-named binary on PATH is not the real tool)." : "";
    const header = supported
      ? h("div.legend", null, [V.icon("info"),
          (s.installed || 0) + " of " + (s.total || 0) + " offensive tools installed on " + osName +
          " — these are Linux packages, probed live (command -v + a version check)." + shadowNote])
      : h("div.legend", null, [V.icon("info"),
          "Host tools are Linux packages; " + (plat.system || "this OS") +
          " is unsupported — nothing is installed or probed here. Run the offense engine on Linux (Kali/Ubuntu/Debian)."]);

    const body = [header];
    if (d.error) body.push(h("div.empty", null, ["Could not probe tools: " + d.error]));
    body.push(h("div.stack", { style: { marginTop: "12px" } }, tools.map(toolCard)));

    // Strix sandbox — informational, clearly separated (never host-installed).
    const sb = d.sandbox || {};
    const sbTools = sb.tools || [];
    if (sbTools.length) {
      body.push(V.card("Strix sandbox tools", "NOT HOST-INSTALLED",
        h("div", null, [
          h("p.muted", { style: { margin: "0 0 10px", maxWidth: "80ch", lineHeight: "1.5" } },
            "Provided by the " + (sb.image || "strix") + " container image and run inside the sandbox per " +
            "engagement — neither probed nor installed on this host. Listed for reference only."),
          h("div", { style: { display: "flex", flexWrap: "wrap", gap: "6px" } }, sbTools.map(function (st) {
            return h("span.pill", { title: st.purpose || "" }, st.name);
          })),
        ]), false));
    }
    V.mount(V.$("#tools-body"), body);
  }

  function renderTools(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Tools"),
        h("span.sub", null, "External security tools the offense engine runs on this host — installed live.")]),
      h("div.grid.cols-4#tools-summary"),
      h("div#tools-body", { style: { marginTop: "16px" } }, h("div.empty", null, "Probing host tools…")),
    ]);
    V.getJSON(OFF("/api/tools")).then(renderToolsData).catch(function () {
      V.mount(V.$("#tools-body"), h("div.empty", null, [
        h("div.big", null, "Offense engine offline"),
        h("p", null, "Could not reach the offense console to probe host tools. Start it (vigil up / the console server) and reload."),
      ]));
    });
  }

  // ==========================================================================
  // P2 — New Assessment wizard + Live run view
  // ==========================================================================

  function hashQuery() {
    const q = (location.hash || "").split("?")[1] || "";
    const out = {};
    q.split("&").forEach(function (kv) { if (!kv) return; const i = kv.indexOf("=");
      out[decodeURIComponent(i < 0 ? kv : kv.slice(0, i))] = i < 0 ? "" : decodeURIComponent(kv.slice(i + 1)); });
    return out;
  }
  function isURL(s) { return /^https?:\/\/.+/i.test(String(s || "").trim()); }
  function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return ""; } }
  function isLoopbackHost(h) { return h === "127.0.0.1" || h === "localhost" || h === "::1" || /^127\./.test(h); }
  function slugify(s, fb) { const v = String(s || "").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48); return v || fb; }

  // -- the 14 offense event kinds: plain-language label + icon + one-line summary --
  const KIND_META = {
    observation:   { label: "Observed", icon: "find", cat: "observe",
      sum: function (p) { return (p.source ? p.source + ": " : "") + (p.summary || p.surface || ""); } },
    hypothesis:    { label: "Hypothesis", icon: "brain", cat: "orient",
      sum: function (p) { return (p.handle ? p.handle + " · " : "") + (p.bug_class || "") + (p.surface ? " @ " + p.surface : "") + (p.status ? " — " + p.status : ""); } },
    plan:          { label: "Plan", icon: "assess", cat: "plan",
      sum: function (p) { return p.next_action || p.plan_id || ""; } },
    decision:      { label: "Decision", icon: "gear", cat: "plan",
      sum: function (p) { return (p.question || "") + (p.choice ? " → " + p.choice : ""); } },
    action:        { label: "Action", icon: "bolt", cat: "act",
      sum: function (p) { return (p.tool || "") + (p.args_summary ? " · " + p.args_summary : ""); } },
    tool_call:     { label: "Tool call", icon: "bolt", cat: "act",
      sum: function (p) { return (p.tool || "") + (p.target ? " → " + p.target : "") + (p.args_summary ? " · " + p.args_summary : ""); } },
    result:        { label: "Result", icon: function (p) { return p.success ? "check" : "x"; }, cat: "result",
      sum: function (p) { return (p.success ? "ok" : "fail") + (p.status_code ? " · HTTP " + p.status_code : "") + (p.note ? " · " + p.note : ""); } },
    tool_result:   { label: "Tool result", icon: function (p) { return p.refused ? "x" : (p.ok ? "check" : "dot"); }, cat: "result",
      sum: function (p) { return (p.tool || "") + " · " + (p.refused ? "refused by " + (p.gate || "gate") : (p.ok ? "ok" : "no result")) + (p.summary ? " · " + p.summary : (p.note ? " · " + p.note : "")); } },
    finding:       { label: "Finding", icon: "shield", cat: "finding",
      sum: function (p) { return (p.bug_class || "") + (p.title ? " — " + p.title : (p.summary ? " — " + p.summary : "")); } },
    critique:      { label: "Critique", icon: "book", cat: "review",
      sum: function (p) { return (p.decision || "") + ((p.objections || []).length ? " · " + p.objections.join("; ") : ""); } },
    critic_verdict:{ label: "Critic", icon: "book", cat: "review",
      sum: function (p) { return (p.critic || "") + ": " + (p.verdict || "") + (p.severity ? " (" + p.severity + ")" : ""); } },
    reflection:    { label: "Reflection", icon: "brain", cat: "review",
      sum: function (p) { return (p.trigger ? p.trigger + ": " : "") + (p.reorientation || (p.observations || []).join("; ")); } },
    reward:        { label: "Reward", icon: "dot", cat: "review",
      sum: function (p) { return (p.source || "") + (p.signal ? " · " + p.signal : "") + " · r=" + (p.reward != null ? p.reward : "?"); } },
    refusal:       { label: "Refusal", icon: "x", cat: "review",
      sum: function (p) { return (p.gate || "gate") + " refused: " + (p.action_refused || "") + (p.fatal ? " (fatal)" : ""); } },
  };
  function kindIcon(kind, p) { const m = KIND_META[kind]; if (!m) return "dot"; return typeof m.icon === "function" ? m.icon(p || {}) : m.icon; }
  function isFact(p) { return !!(p && p.verified_by_oracle); }

  // ---- New Assessment wizard -------------------------------------------------
  const TARGET_TYPES = [
    { mode: "codebase", icon: "book", t: "Scan a codebase", d: "Point at a local path or repo; the AI reads and reasons over the source (Strix)." },
    { mode: "url", icon: "live", t: "Scan a website / API", d: "Give a URL; VIGIL engages it through the full gate. A 127.0.0.1 target runs a quick loopback scan." },
    { mode: "tool", icon: "bolt", t: "Run one tool", d: "Run a single gated capability pack against a target — the narrow, focused option." },
    { mode: "suite", icon: "brain", t: "Full autonomous suite", d: "The autonomous OODA loop drives the whole arsenal (gated, oracle-adjudicated)." },
    { mode: "aegis", icon: "shield", t: "Defend an app (AEGIS)", d: "Run the defensive dual over your telemetry/logs to detect AI attacks." },
  ];
  const ENGAGE_MODES = { url: true, tool: true, suite: true };  // modes that spawn `engage`/`scan`

  function renderAssess(screen) {
    const W = { step: 1, mode: "", target: "", slug: "", authorized: false, mount: false,
      scope: [], scopeInput: "", objective: "", scan_mode: "standard", aiTools: true,
      tools: [], apply_fixes: false, keyless: false, model: "", aegis_action: "detect",
      caps: null, kernel: null, launching: false };
    // real capability catalog + backend/LLM status (never hardcoded)
    V.getJSON(OFF("/api/capabilities")).then(function (d) { W.caps = d; draw(); }).catch(function () { W.caps = { capabilities: [], scan_modes: [] }; });
    V.getJSON(OFF("/api/kernel")).then(function (d) { W.kernel = d; draw(); }).catch(function () { W.kernel = { backends: [] }; });

    function set(patch) { Object.assign(W, patch); draw(); }
    function isEngage() { return !!ENGAGE_MODES[W.mode]; }
    function isLoopback() { return isLoopbackHost(hostOf(W.target)); }

    function stepValid(n) {
      if (n === 1) return !!W.mode;
      if (n === 2) {
        if (W.mode === "codebase") return !!W.target.trim() && W.authorized;
        if (W.mode === "aegis") return !!W.target.trim();
        return isURL(W.target) && W.authorized;
      }
      if (n === 3) return true;   // scope is optional / validated on launch
      if (n === 4) {
        if (W.mode === "tool") return W.tools.length === 1;
        return true;
      }
      return true;
    }
    function canLaunch() { return stepValid(1) && stepValid(2) && stepValid(3) && stepValid(4) && !W.launching; }

    function goto(n) { if (n > W.step && !stepValid(W.step)) { V.toast("Please complete this step first."); return; } set({ step: Math.max(1, Math.min(5, n)) }); }

    // ---- step bodies ----
    function stepTargetType() {
      return h("div.wizbody", null, [
        h("h2", null, "What do you want to assess?"),
        h("p.helper", null, "Pick the kind of target. Everything after adapts to this choice."),
        h("div.choice-grid", null, TARGET_TYPES.map(function (tt) {
          const sel = W.mode === tt.mode;
          return h("button.choice" + (sel ? ".sel" : "") + (tt.mode === "aegis" ? ".defense" : ""),
            { onClick: function () { set({ mode: tt.mode, step: 2, tools: [], aiTools: tt.mode !== "tool" }); } },
            [h("span.cico", null, V.icon(tt.icon)), h("div", null, [h("div.ct", null, tt.t), h("div.cd", null, tt.d)])]);
        })),
      ]);
    }
    function stepWhere() {
      const rows = [];
      if (W.mode === "codebase") {
        rows.push(field("Codebase path", h("input", { type: "text", value: W.target, placeholder: "/home/you/project  or  https://github.com/org/repo",
          onInput: function (e) { W.target = e.target.value; updateSummary(); refreshFoot(); } }), "A local path (or a git URL Strix can clone). Large trees: use bind-mount below."));
        rows.push(checkbox("Bind-mount instead of copy (large monorepos)", W.mount, function (v) { W.mount = v; }));
      } else if (W.mode === "aegis") {
        rows.push(field("Telemetry / log file", h("input", { type: "text", value: W.target, placeholder: "/path/to/telemetry-envelope.json",
          onInput: function (e) { W.target = e.target.value; updateSummary(); refreshFoot(); } }), "AEGIS detect runs its defensive oracles over one TelemetryEnvelope/log file."));
      } else {
        rows.push(field("Target URL", h("input", { type: "url", value: W.target, placeholder: "https://app.example.com/",
          onInput: function (e) { W.target = e.target.value; if (!W.slug) W.slug = slugify(hostOf(e.target.value), ""); updateSummary(); syncSlug(); refreshFoot(); } }),
          "An absolute URL on an in-scope host. A 127.0.0.1 target runs a quick, loopback-only scan."));
        rows.push(field("Engagement slug", h("input#wiz-slug", { type: "text", value: W.slug, placeholder: slugify(hostOf(W.target), "engagement"),
          onInput: function (e) { W.slug = e.target.value; updateSummary(); } }),
          "Names the charter, scope and reasoning spine. A REMOTE target needs a signed charter under this slug (the console cannot mint it)."));
      }
      if (W.mode !== "aegis") {
        rows.push(h("div.field", null, [
          h("label", { class: "row-flex", style: { cursor: "pointer" } }, [
            h("input", { type: "checkbox", checked: W.authorized, style: { width: "auto" },
              onChange: function (e) { W.authorized = e.target.checked; refreshFoot(); updateSummary(); } }),
            h("span", null, "I am authorized to test this target (I own it or have written permission)."),
          ]),
          h("div.hint", null, "VIGIL is for authorized testing only. This is recorded with the run."),
        ]));
      }
      rows.push(field("Objective (optional)", h("textarea", { placeholder: "e.g. focus on authentication and access control",
        onInput: function (e) { W.objective = e.target.value; updateSummary(); } }, W.objective), "Guides the reasoning; never widens scope."));
      return h("div.wizbody", null, [h("h2", null, "Where is it?"),
        h("p.helper", null, "Tell VIGIL exactly what to point at, and confirm you're allowed to."), h("div", null, rows)]);
    }
    function syncSlug() { const el = V.$("#wiz-slug"); if (el) el.value = W.slug; }
    function stepScope() {
      if (!isEngage()) {
        return h("div.wizbody", null, [h("h2", null, "Scope"),
          h("p.helper", null, W.mode === "codebase"
            ? "A codebase scan reads source only — it sends no traffic, so there is no network scope to set."
            : "AEGIS reads your telemetry defensively — there is no offensive scope to set."),
          h("div.legend", null, [V.icon("info"), "Nothing to configure here for this mode."])]);
      }
      if (isLoopback()) {
        return h("div.wizbody", null, [h("h2", null, "Scope"),
          h("p.helper", null, "This is a loopback target, so scope is fixed to your own machine."),
          h("div.legend", null, [V.icon("check"), "Scope: 127.0.0.1 (loopback-only, self-authorized)."])]);
      }
      const chips = h("div", { style: { display: "flex", flexWrap: "wrap", gap: "8px", marginBottom: "12px" } },
        W.scope.length ? W.scope.map(function (s, i) {
          return h("span.pill", null, [s, h("button.iconbtn", { style: { width: "22px", height: "22px" }, title: "remove",
            onClick: function () { W.scope.splice(i, 1); draw(); } }, V.icon("x"))]);
        }) : [h("span.muted", null, "No hosts yet — the target's host is always in scope.")]);
      return h("div.wizbody", null, [h("h2", null, "Scope"),
        h("p.helper", null, "List the hosts this engagement may touch. Literal hosts or *.wildcards only — no CIDR ranges."),
        chips,
        h("div", { style: { display: "flex", gap: "8px" } }, [
          h("input", { type: "text", value: W.scopeInput, placeholder: "app.example.com  or  *.example.com",
            onInput: function (e) { W.scopeInput = e.target.value; },
            onKeydown: function (e) { if (e.key === "Enter") { e.preventDefault(); addScope(); } } }),
          h("button.btn", { onClick: addScope }, "Add"),
        ]),
        h("div.legend", { style: { marginTop: "12px" } }, [V.icon("info"),
          "Scope is SIGNED into the charter/authority — the console never passes it, so it can't be widened here. A *.wildcard is a deliberately broad grant."]),
      ]);
      function addScope() {
        const v = W.scopeInput.trim(); if (!v) return;
        if (v.indexOf("/") >= 0) { V.toast("No CIDR — use a literal host or a *.wildcard.", true); return; }
        if (W.scope.indexOf(v) < 0) W.scope.push(v);
        W.scopeInput = ""; draw();
      }
    }
    function stepMode() {
      const caps = (W.caps && W.caps.caps) || (W.caps && W.caps.capabilities) || [];
      const modes = (W.caps && W.caps.scan_modes) || [{ id: "quick", label: "Quick" }, { id: "standard", label: "Standard" }, { id: "deep", label: "Deep" }];
      const body = [];
      if (isEngage()) {
        body.push(field("Depth", h("div.choice-grid", null, modes.map(function (m) {
          const sel = W.scan_mode === m.id;
          return h("button.choice" + (sel ? ".sel" : ""), { onClick: function () { set({ scan_mode: m.id }); } },
            [h("div", null, [h("div.ct", null, m.label), h("div.cd", null, m.purpose || "")])]);
        })), null));
        if (W.mode !== "tool") {
          body.push(h("div.field", null, [
            h("label", { class: "row-flex", style: { cursor: "pointer" } }, [
              h("input", { type: "checkbox", checked: W.aiTools, style: { width: "auto" },
                onChange: function (e) { set({ aiTools: e.target.checked }); } }),
              h("span", null, "Let the AI choose the tools (recommended)."),
            ]),
            h("div.hint", null, "Off: pick exactly which gated capability packs run."),
          ]));
        }
        const single = W.mode === "tool";
        if (single || !W.aiTools) {
          body.push(h("div.field", null, [
            h("label", null, single ? "Pick one capability" : "Pick capabilities"),
            caps.length ? h("div", { style: { display: "flex", flexWrap: "wrap", gap: "8px" } }, caps.map(function (c) {
              const on = W.tools.indexOf(c.id) >= 0;
              return h("button.pill" + (on ? ".live" : ""), { title: c.purpose || "",
                onClick: function () {
                  if (single) { W.tools = on ? [] : [c.id]; }
                  else { const i = W.tools.indexOf(c.id); if (i >= 0) W.tools.splice(i, 1); else W.tools.push(c.id); }
                  draw();
                } }, [on ? V.icon("check") : null, c.label, h("span.muted", { style: { fontSize: "var(--fs-micro)" } }, " " + c.tier)]);
            })) : h("div.muted", null, "Capability catalog unavailable (offense engine offline)."),
            h("div.hint", null, "Each pack maps to an already-gated engage flag; nothing here can widen authority."),
          ]));
        }
        body.push(checkbox("Apply fixes after discovery", W.apply_fixes, function (v) { W.apply_fixes = v; },
          "Fixes are PROPOSED and queue for your approval — they never auto-apply."));
      } else {
        body.push(h("div.legend", null, [V.icon("info"),
          W.mode === "codebase" ? "Strix chooses its own analysis passes over the source."
            : "AEGIS runs its full defensive oracle set over the telemetry."]));
        body.push(checkbox("Apply fixes after discovery", W.apply_fixes, function (v) { W.apply_fixes = v; },
          "Fixes are PROPOSED and queue for your approval — they never auto-apply."));
      }
      return h("div.wizbody", null, [h("h2", null, "How should it run?"),
        h("p.helper", null, "Choose depth and which capabilities run."), h("div", null, body)]);
    }
    function stepModel() {
      const backends = (W.kernel && W.kernel.backends) || [];
      const live = backends.filter(function (b) { return b.available; });
      const status = W.kernel == null ? "Checking…"
        : (live.length ? live.map(function (b) { return b.name; }).join(", ") + " available"
          : "No live LLM backend detected — set ANTHROPIC_API_KEY (Settings) or run keyless.");
      const body = [
        h("div.field", null, [h("label", null, "Reasoning backend / API key"),
          h("div.legend", null, [V.icon(live.length ? "check" : "info"), status]),
          h("div.hint", null, "The model + key come from the environment (Settings). Keys are never shown or entered here.")]),
        checkbox("Run keyless (attest, then only do what needs no model)", W.keyless, function (v) { W.keyless = v; },
          "A keyless run still attests first and never fabricates activity."),
      ];
      return h("div.wizbody", null, [h("h2", null, "Model & keys"),
        h("p.helper", null, "VIGIL runs on your machine with your own key — nothing is sent anywhere else."), h("div", null, body)]);
    }

    function field(label, control, hint) {
      return h("div.field", null, [h("label", null, label), control, hint ? h("div.hint", null, hint) : null]);
    }
    function checkbox(label, val, onChange, hint) {
      return h("div.field", null, [
        h("label", { class: "row-flex", style: { cursor: "pointer" } }, [
          h("input", { type: "checkbox", checked: val, style: { width: "auto" }, onChange: function (e) { onChange(e.target.checked); updateSummary(); } }),
          h("span", null, label)]),
        hint ? h("div.hint", null, hint) : null]);
    }

    // ---- summary + rail + foot ----
    function summaryCard() {
      const rows = [];
      const put = function (k, v) { rows.push(h("div.kv", null, [h("div.k", null, k), h("div.v", null, v)])); };
      const tt = TARGET_TYPES.find(function (x) { return x.mode === W.mode; });
      put("Assessment", tt ? tt.t : "—");
      put("Target", W.target || "—");
      if (isEngage()) put("Scope", isLoopback() ? "127.0.0.1 (loopback)" : (W.scope.length ? W.scope.join(", ") : "(host only)"));
      if (isEngage()) put("Slug", W.slug || slugify(hostOf(W.target), "engagement"));
      if (isEngage()) put("Depth", W.scan_mode);
      if (isEngage()) put("Tools", W.mode === "tool" ? (W.tools[0] || "—") : (W.aiTools ? "AI chooses" : (W.tools.join(", ") || "none")));
      put("Fixes", W.apply_fixes ? "propose (queue for approval)" : "off");
      put("Model", W.keyless ? "keyless" : "environment / Settings");
      return V.card("What will happen", "SUMMARY", h("div", null, [
        h("div.stack", { style: { gap: "8px" } }, rows),
        h("div.legend", { style: { marginTop: "14px" } }, [V.icon("key"),
          "Offensive steps QUEUE for your approval — nothing fires automatically."]),
      ]), false);
    }
    function rail() {
      const names = ["Target", "Where", "Scope", "How", "Model"];
      return h("div.steprail", null, names.map(function (nm, i) {
        const n = i + 1; const cls = n === W.step ? ".on" : (n < W.step ? ".done" : "");
        return h("div.step" + cls, { onClick: function () { goto(n); } },
          [h("span.num", null, n < W.step ? "✓" : String(n)), h("span", null, nm)]);
      }));
    }
    function refreshFoot() { const f = V.$("#wiz-foot"); if (f) V.mount(f, footContent()); }
    function updateSummary() { const s = V.$("#wiz-summary"); if (s) V.mount(s, summaryCard()); }
    function footContent() {
      const back = h("button.btn.ghost", { disabled: W.step === 1, onClick: function () { goto(W.step - 1); } }, "Back");
      const note = h("span.safenote", null, [V.icon("key"), "Steps queue for approval — nothing auto-fires"]);
      const grow = h("span.grow");
      let primary;
      if (W.step < 5) primary = h("button.btn.primary", { disabled: !stepValid(W.step), onClick: function () { goto(W.step + 1); } }, ["Next", V.icon("play")]);
      else primary = h("button.btn.primary.lg", { disabled: !canLaunch(), onClick: launch }, [V.icon("bolt"), W.launching ? "Launching…" : "Launch assessment"]);
      return [back, note, grow, primary];
    }

    function launch() {
      if (!canLaunch()) return;
      set({ launching: true });
      const body = {
        mode: W.mode, target: W.target.trim(), slug: W.slug.trim(), scope: W.scope,
        objective: W.objective.trim(), scan_mode: W.scan_mode,
        tools: (W.mode !== "tool" && W.aiTools) ? [] : W.tools,
        apply_fixes: W.apply_fixes, keyless: W.keyless, model: W.model,
        mount: W.mount, aegis_action: W.aegis_action,
      };
      V.postJSON(OFF("/api/launch/assessment"), body).then(function (r) {
        if (r && r.error) { W.launching = false; V.toast(r.error, true); refreshFoot(); return; }
        V.toast("Assessment launched — watching it live.");
        location.hash = "#/live?run=" + encodeURIComponent(r.run_id);
      }).catch(function (e) {
        W.launching = false; V.toast((e && e.message) || "Launch failed", true); refreshFoot();
      });
    }

    function draw() {
      const bodies = [stepTargetType, stepWhere, stepScope, stepMode, stepModel];
      V.mount(screen, [
        h("div.screen-head", null, [h("h1", null, "New Assessment"),
          h("span.sub", null, "Set up a run in five short steps. Everything stays on your machine.")]),
        h("div.wizard", null, [
          rail(),
          h("div", null, [bodies[W.step - 1](), h("div.wizfoot#wiz-foot", null, footContent())]),
          h("div.summary#wiz-summary", null, summaryCard()),
        ]),
      ]);
    }
    draw();
  }

  // ---- Live run view ---------------------------------------------------------
  let liveES = null, liveTimers = [];
  function teardownLive() {
    if (liveES) { try { liveES.close(); } catch (e) {} liveES = null; }
    liveTimers.forEach(function (t) { clearInterval(t); });
    liveTimers = [];
  }

  function renderLive(screen) {
    const L = { run: null, runs: [], events: [], seen: {}, filter: "all", snapshot: null, started: null };
    const want = hashQuery().run || "";

    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Live"),
        h("span.sub", null, "Every action, as it happens — with proof-grade FACT vs LEAD clarity.")]),
      h("div#live-body", null, h("div.empty", null, "Loading runs…")),
    ]);

    V.getJSON(OFF("/api/runs")).then(function (d) {
      L.runs = (d && d.runs) || [];
      L.run = L.runs.find(function (r) { return r.run_id === want; }) || L.runs[0] || null;
      if (L.run) { L.started = L.run.started; attachStream(); }
      drawBody();
    }).catch(function () {
      V.mount(V.$("#live-body"), h("div.empty", null, [h("div.big", null, "Offense engine offline"),
        h("p", null, "Could not reach the offense console. Start it (vigil up) and reload.")]));
    });

    function selectRun(runId) {
      teardownLive();
      L.run = L.runs.find(function (r) { return r.run_id === runId; }) || null;
      L.events = []; L.seen = {}; L.snapshot = null; L.started = L.run && L.run.started;
      history.replaceState(null, "", "#/live?run=" + encodeURIComponent(runId));
      if (L.run) attachStream();
      drawBody();
    }

    function attachStream() {
      const run = L.run; if (!run) return;
      // approvals live on the SOVEREIGN plane — poll its snapshot (read-only) for pending items.
      pollSnapshot();
      liveTimers.push(setInterval(pollSnapshot, 4000));
      liveTimers.push(setInterval(function () { updateHeader(); }, 1000)); // elapsed ticker
      if (run.stream === "blackboard" && run.slug) {
        // the 14-kind reasoning spine. EventSource resumes from Last-Event-ID (durable cursor).
        liveES = V.sse(OFF("/api/blackboard?slug=" + encodeURIComponent(run.slug)), function (ev) {
          if (!ev || !ev.kind) return;
          if (ev.id != null) { if (L.seen[ev.id]) return; L.seen[ev.id] = 1; }  // dedup any reconnect replay
          L.events.push(ev); onEvents();
        }, function () { /* auto-reconnect; the id: cursor prevents gaps/replays */ });
      } else if (run.stream === "progress") {
        // a loopback scan writes a progress log (not the reasoning spine) — render it honestly.
        liveES = V.sse(OFF("/api/events?run=" + encodeURIComponent(run.run_id)), function (ev) {
          const norm = progressToEvent(ev); if (norm) { L.events.push(norm); onEvents(); }
        });
      }
      // strix/aegis (stream 'none'): no live spine — poll run status instead.
      if (run.stream === "none") liveTimers.push(setInterval(refreshRunMeta, 3000));
    }
    function refreshRunMeta() {
      V.getJSON(OFF("/api/runs")).then(function (d) {
        const r = ((d && d.runs) || []).find(function (x) { return x.run_id === L.run.run_id; });
        if (r) { L.run = r; updateHeader(); }
      }).catch(function () {});
    }
    function pollSnapshot() {
      V.getJSON(SOV("/api/snapshot")).then(function (s) {
        L.snapshot = s; drawApprovals();
        const waiting = (s && (s.pending_approvals || []).length) || 0;
        const killed = !!(s && (s.kill_switch === "ENGAGED" || (s.kill_switch && s.kill_switch.engaged)));
        if (app.get().waiting !== waiting || app.get().killed !== killed) { app.set({ waiting: waiting, killed: killed }); refreshTopbar(); }
      }).catch(function () { /* sovereign plane offline — approvals just won't show */ });
    }

    // convert a scan progress-log row into a timeline-shaped event
    function progressToEvent(ev) {
      if (!ev || !ev.event) return null;
      if (ev.event === "scan.phase") return { kind: "observation", payload: { source: "scan", summary: "phase: " + (ev.phase || "") }, _progress: true };
      if (ev.event === "scan.finding") return { kind: "finding", payload: { bug_class: ev.bug_class, title: (ev.param || "") + " @ " + (ev.endpoint || ""),
        confidence: ev.confidence, verified_by_oracle: false, oracle_kind: ev.confirmed_by, severity: "" }, _progress: true };
      if (ev.event === "scan.done") return { kind: "decision", payload: { question: "scan complete", choice: (ev.findings || 0) + " findings · " + (ev.requests_sent || 0) + " requests" }, _progress: true };
      return null;
    }

    function counts() {
      let facts = 0, leads = 0, ref = 0, calls = 0;
      L.events.forEach(function (e) {
        if (e.kind === "finding") { if (isFact(e.payload)) facts++; else leads++; }
        else if (e.kind === "refusal") ref++;
        else if (e.kind === "tool_call") calls++;
      });
      return { facts: facts, leads: leads, refusals: ref, calls: calls, total: L.events.length };
    }
    function phaseLabel() {
      for (let i = L.events.length - 1; i >= 0; i--) {
        const e = L.events[i];
        if (e.kind === "plan") return "planning: " + (KIND_META.plan.sum(e.payload) || "");
        if (e.kind === "observation") return KIND_META.observation.sum(e.payload) || "observing";
      }
      return L.run && L.run.status === "running" ? "starting…" : (L.run ? L.run.status : "");
    }

    function onEvents() { updateHeader(); drawGraph(); drawTimeline(); }

    // ---- header / stop ----
    function updateHeader() {
      const el = V.$("#live-head"); if (!el || !L.run) return;
      V.mount(el, headerContent());
    }
    function headerContent() {
      const run = L.run; const c = counts();
      const running = run.status === "running";
      const statusPill = running ? V.pill("Live", "live", null) : V.pill(run.status || "done", run.status === "error" ? "danger" : "idle", null);
      const elapsed = L.started ? fmtElapsed((Date.now() / 1000) - L.started) : "—";
      const stop = h("button.btn.danger", { disabled: !running || !run.slug, title: "Trip this engagement's kill-switch (offense-side hard stop)",
        onClick: stopRun }, [V.icon("x"), "Stop run"]);
      return [
        h("div", { style: { display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" } }, [
          statusPill,
          h("b.mono", null, run.target || run.slug || run.run_id),
          h("span.pill.sm", null, run.mode || "url"),
          h("span.muted", { style: { marginLeft: "auto" } }, [V.icon("live"), " ", elapsed]),
          stop,
        ]),
        h("div.muted", { style: { marginTop: "8px" } }, "Phase: " + phaseLabel()),
        h("div.grid.cols-4", { style: { marginTop: "12px" } }, [
          V.tile("Actions", String(c.calls), "tool calls"),
          V.tile("Facts", String(c.facts), "oracle-confirmed", c.facts ? "up" : ""),
          V.tile("Leads", String(c.leads), "unconfirmed"),
          V.tile("Refusals", String(c.refusals), "gates fired", c.refusals ? "down" : ""),
        ]),
      ];
    }
    function stopRun() {
      if (!L.run || !L.run.slug) return;
      V.postJSON(OFF("/api/killswitch/" + encodeURIComponent(L.run.slug) + "/trip"), { reason: "stopped from Live view" })
        .then(function (r) { if (r && r.error) { V.toast(r.error, true); return; } V.toast("Kill-switch tripped — the engagement will halt.");
          L.run.status = "stopping"; updateHeader(); })
        .catch(function (e) { V.toast((e && e.message) || "Could not stop the run", true); });
    }

    // ---- approvals (sovereign plane) ----
    function drawApprovals() {
      const host = V.$("#live-approvals"); if (!host) return;
      const pend = (L.snapshot && L.snapshot.pending_approvals) || [];
      if (!pend.length) { V.mount(host, null); return; }
      V.mount(host, V.card("Waiting for your approval", "OWNER", h("div.stack", null, pend.map(approvalCard)), true));
    }
    function approvalCard(a) {
      return h("div.approval", null, [
        h("div.ah", null, [V.icon("key"), h("span.t", null, (a.kind || "action") + " · seq " + a.seq),
          a.tier ? h("span.pill.sm", null, "tier " + a.tier) : null]),
        h("div.why", null, (a.agent ? a.agent + " → " : "") + (a.subject || "requires owner sign-off")),
        h("div.acts", null, [
          h("button.btn.owner", { onClick: function () { act("approve", a.seq); } }, [V.icon("check"), "Approve"]),
          h("button.btn.danger", { onClick: function () { act("deny", a.seq); } }, [V.icon("x"), "Deny"]),
        ]),
      ]);
    }
    function act(action, seq) {
      V.postJSON(SOV("/api/action"), { action: action, seq: seq, reason: action + " from Live view" })
        .then(function (r) { if (r && r.error) { V.toast(r.error, true); return; }
          V.toast(action === "approve" ? "Approved." : "Denied."); pollSnapshot(); })
        .catch(function (e) { V.toast((e && e.message) || "Action failed", true); });
    }

    // ---- graph + timeline ----
    function drawGraph() { const g = V.$("#live-graph"); if (g) liveGraph(g, L.events); }
    function drawTimeline() {
      const host = V.$("#live-timeline"); if (!host) return;
      let rows = L.events;
      if (L.filter === "facts") rows = rows.filter(function (e) { return e.kind === "finding" && isFact(e.payload); });
      else if (L.filter === "leads") rows = rows.filter(function (e) { return e.kind === "finding" && !isFact(e.payload); });
      if (!rows.length) {
        V.mount(host, h("div.empty", null, L.events.length ? "No events match this filter." :
          (L.run && L.run.stream === "none" ? "This run reports in its own sandbox — see Findings for its results." : "Waiting for the first event…")));
        return;
      }
      const out = [];
      for (let i = rows.length - 1; i >= 0; i--) out.push(timelineRow(rows[i]));   // newest first
      V.mount(host, out);
    }
    function timelineRow(e) {
      const m = KIND_META[e.kind] || { label: e.kind, sum: function () { return ""; } };
      const p = e.payload || {};
      const meta = [];
      if (e.kind === "finding") {
        if (p.severity) meta.push(h("span.sev.sev-" + String(p.severity).toLowerCase(), null, p.severity));
        meta.push(isFact(p)
          ? h("span.shield", null, [V.icon("check"), "FACT"])
          : h("span.shield.lead", null, "LEAD"));
      } else if (e.kind === "tool_call") {
        meta.push(h("span.pill.sm", null, "tier " + (p.tier || "?")));
      } else if (e.kind === "tool_result" && p.refused) {
        meta.push(h("span.st.st-blocked", null, [h("span.dot"), "refused"]));
      }
      return h("div.trow.kind-" + e.kind + ".new", { onClick: function () { openEventDrawer(e); } }, [
        h("div.ico", null, V.icon(kindIcon(e.kind, p))),
        h("div.body", null, [h("div.k", null, m.label), h("div.m", null, m.sum(p) || "—")]),
        h("div.meta", null, meta.concat([h("span.t", null, e.posted_at ? String(e.posted_at).slice(11, 19) : (e.id != null ? "#" + e.id : ""))])),
      ]);
    }
    function openEventDrawer(e) {
      const p = e.payload || {};
      const kv = [];
      const put = function (k, v) { kv.push(h("div.kv", null, [h("div.k", null, k), h("div.v", null, String(v))])); };
      put("Kind", (KIND_META[e.kind] || {}).label || e.kind);
      if (e.agent) put("Agent", e.agent);
      if (e.posted_at) put("At", e.posted_at);
      if (e.id != null) put("Event id", e.id);
      if (e.parent_id != null) put("Derives from", "#" + e.parent_id);
      if (e.kind === "finding") { put("Verdict", isFact(p) ? "FACT (oracle-confirmed)" : "LEAD (unconfirmed)");
        if (p.oracle_kind) put("Oracle", p.oracle_kind); if (p.confidence != null) put("Confidence", p.confidence); }
      openDrawer((KIND_META[e.kind] || {}).label || e.kind, [
        h("div.dsection", null, kv),
        h("div.dsection", null, [h("span.label", null, "PROVENANCE / PAYLOAD"),
          h("pre.code", { style: { marginTop: "8px" } }, JSON.stringify(p, null, 2))]),
        e.kind === "finding" && !isFact(p)
          ? h("div.legend", null, [V.icon("info"), "A LEAD is a proposal. It becomes a FACT only when a deterministic oracle re-executes and confirms it."])
          : null,
      ]);
    }

    // ---- body assembly ----
    function drawBody() {
      const body = V.$("#live-body"); if (!body) return;
      if (!L.runs.length) {
        V.mount(body, h("div.empty", null, [h("div.big", null, "No runs yet"),
          h("p", null, "Start one from New Assessment and it appears here, live."),
          h("button.btn.primary", { style: { marginTop: "16px" }, onClick: function () { location.hash = "#/assess"; } }, [V.icon("bolt"), "New Assessment"])]));
        return;
      }
      const picker = h("div.field", { style: { maxWidth: "520px" } }, [
        h("label", null, "Run"),
        h("select", { onChange: function (e) { selectRun(e.target.value); } }, L.runs.map(function (r) {
          return h("option", { value: r.run_id, selected: L.run && r.run_id === L.run.run_id },
            (r.mode || "url") + " · " + (r.target || r.slug || r.run_id) + " · " + r.status);
        })),
      ]);
      const legend = h("div.legend", { style: { marginTop: "12px" } }, [V.icon("shield"),
        "Only a fired ORACLE confirms a finding (FACT). Critics, the LLM, and rewards only advise — they never promote a LEAD to a FACT."]);
      const filterSeg = h("div.segmented", null, [["all", "All"], ["facts", "Facts"], ["leads", "Leads"]].map(function (f) {
        return h("button" + (L.filter === f[0] ? ".on" : ""), { onClick: function () { L.filter = f[0]; drawBody(); } }, f[1]);
      }));
      V.mount(body, [
        picker,
        L.run ? h("div.card#live-head", { style: { marginTop: "12px" } }, headerContent()) : null,
        legend,
        h("div#live-approvals", { style: { marginTop: "12px" } }),
        h("div.grid.cols-2", { style: { marginTop: "12px", alignItems: "start" } }, [
          V.card("Reasoning graph", "LIVE", h("div#live-graph", null, h("div.empty", null, "Waiting for activity…")), false),
          h("div.card", null, [
            h("div.card-h", null, [h("span.label", null, "TIMELINE"), h("h3", null, "Everything, as it happens"), h("span.grow", { style: { flex: 1 } }), filterSeg]),
            h("div.feed#live-timeline", null, h("div.empty", null, "Waiting for the first event…")),
          ]),
        ]),
      ]);
      drawGraph(); drawTimeline(); drawApprovals();
    }
  }

  function fmtElapsed(s) {
    s = Math.max(0, Math.floor(s || 0));
    const h2 = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return (h2 ? h2 + "h " : "") + (h2 || m ? m + "m " : "") + sec + "s";
  }

  // ---- live reasoning graph (CSP-native SVG built with createElementNS) -------
  const GRAPH_LANES = [
    { cat: "observe", label: "Observe" }, { cat: "orient", label: "Orient" },
    { cat: "plan", label: "Plan" }, { cat: "act", label: "Act" },
    { cat: "result", label: "Result" }, { cat: "finding", label: "Finding" },
    { cat: "review", label: "Review" },
  ];
  const CAT_COLOR = { observe: "#4aa3ff", orient: "#c88bff", plan: "#37c8d6", act: "#f5a623",
    result: "#8895a7", finding: "#ff8a3d", review: "#ff5470" };
  function svgEl(tag, attrs) {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const k in attrs) if (attrs[k] != null) el.setAttribute(k, attrs[k]);
    return el;
  }
  function liveGraph(container, events) {
    V.clear(container);
    if (!events.length) { container.appendChild(h("div.empty", null, "Waiting for activity…")); return; }
    const laneIdx = {}; GRAPH_LANES.forEach(function (l, i) { laneIdx[l.cat] = i; });
    const CAP = 22; // per-lane node cap keeps the graph legible and cheap
    const laneItems = GRAPH_LANES.map(function () { return []; });
    const pos = {};
    const recent = events.slice(-140);
    recent.forEach(function (e) {
      e._gx = null; e._gy = null;   // clear any stale position from a prior redraw
      const m = KIND_META[e.kind]; const cat = (m && m.cat) || "review";
      const li = laneIdx[cat]; if (li == null) return;
      laneItems[li].push(e);
    });
    const laneW = 118, rowH = 30, padTop = 26, padL = 14;
    const maxRows = Math.min(CAP, Math.max.apply(null, laneItems.map(function (a) { return a.length; }).concat([1])));
    const W = laneW * GRAPH_LANES.length, H = padTop + maxRows * rowH + 16;
    const svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, width: "100%", height: H,
      style: "background:var(--bg-0);border:1px solid var(--border);border-radius:8px" });
    // lane headers
    GRAPH_LANES.forEach(function (l, i) {
      const t = svgEl("text", { x: padL + i * laneW, y: 16, "font-size": 10, fill: "var(--text-2)",
        "font-family": "var(--font-mono)" }); t.textContent = l.label; svg.appendChild(t);
    });
    // place nodes (last CAP per lane), remember positions by event id
    const nodeEls = [];
    laneItems.forEach(function (items, li) {
      const shown = items.slice(-CAP);
      shown.forEach(function (e, r) {
        const x = padL + li * laneW + 4, y = padTop + r * rowH;
        pos[e.id != null ? e.id : ("k" + li + "_" + r)] = { x: x, y: y };
        if (e.id != null) pos[e.id] = { x: x, y: y };
        e._gx = x; e._gy = y; nodeEls.push(e);
      });
    });
    // edges: parent_id → child (only when both are on-screen)
    recent.forEach(function (e) {
      if (e.parent_id == null || !pos[e.parent_id] || e._gx == null) return;
      const a = pos[e.parent_id], b = { x: e._gx, y: e._gy };
      const mx = (a.x + b.x) / 2;
      svg.appendChild(svgEl("path", { d: "M" + a.x + "," + a.y + " C" + mx + "," + a.y + " " + mx + "," + b.y + " " + b.x + "," + b.y,
        fill: "none", stroke: "var(--border-strong)", "stroke-width": 1, opacity: 0.5 }));
    });
    // nodes
    nodeEls.forEach(function (e) {
      const m = KIND_META[e.kind] || {}; const cat = m.cat || "review";
      const isRef = e.kind === "refusal";
      const isFactFinding = e.kind === "finding" && isFact(e.payload);
      const g = svgEl("g", { style: "cursor:pointer" });
      const dot = svgEl("circle", { cx: e._gx, cy: e._gy, r: e.kind === "finding" ? 6 : 5,
        fill: isRef ? "var(--st-blocked)" : (CAT_COLOR[cat] || "#8895a7"),
        stroke: isFactFinding ? "var(--st-confirmed)" : "var(--bg-0)", "stroke-width": isFactFinding ? 2 : 1.4 });
      const label = svgEl("text", { x: e._gx + 10, y: e._gy + 3.5, "font-size": 9, fill: "var(--text-1)",
        "font-family": "var(--font-mono)" });
      label.textContent = (m.label || e.kind).slice(0, 12);
      g.appendChild(dot); g.appendChild(label);
      g.addEventListener("click", function () { V.toast((m.label || e.kind) + ": " + ((m.sum && m.sum(e.payload)) || "")); });
      svg.appendChild(g);
    });
    container.appendChild(svg);
    // legend
    const leg = h("div.row-flex", { style: { flexWrap: "wrap", gap: "10px", marginTop: "8px" } },
      GRAPH_LANES.map(function (l) {
        return h("span.row-flex", { style: { gap: "5px" } }, [
          h("span", { style: { width: "9px", height: "9px", borderRadius: "50%", background: CAT_COLOR[l.cat], display: "inline-block" } }),
          h("span.muted", { style: { fontSize: "var(--fs-xs)" } }, l.label)]);
      }).concat([h("span.row-flex", { style: { gap: "5px", marginLeft: "auto" } },
        [h("span.shield", { style: { padding: "1px 6px" } }, "FACT"), h("span.muted", { style: { fontSize: "var(--fs-xs)" } }, "= oracle-confirmed")])]));
    container.appendChild(leg);
  }

  // ---- guided stub for not-yet-built screens --------------------------------
  function renderStub(screen, item) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, item.label),
        h("span.sub", null, "This surface is part of the plan.")]),
      h("div.empty", null, [
        h("div.big", null, item.label + " — arriving in " + item.phase),
        h("p", null, "The design system and shell are live now (P1). This screen is wired next; the plan builds it in " + item.phase + "."),
        h("button.btn.primary", { style: { marginTop: "16px" }, onClick: function () { location.hash = "#/home"; } }, "Back to Command"),
      ]),
    ]);
  }

  // ---- boot ------------------------------------------------------------------
  function route() {
    const id = current();
    teardownLive();               // close any live stream/timers when navigating away
    renderNav();
    const screen = V.$("#screen"); if (!screen) return;
    if (id === "home") { renderHome(screen); return; }
    if (id === "manual") { renderManual(screen); return; }
    if (id === "tools") { renderTools(screen); return; }
    if (id === "assess") { renderAssess(screen); return; }
    if (id === "live") { renderLive(screen); return; }
    let item = null;
    NAV.forEach(function (g) { g.items.forEach(function (it) { if (it.id === id) item = it; }); });
    if (item && item.ready) renderHome(screen); else renderStub(screen, item || { label: "Not found", phase: "—" });
  }

  function boot() {
    // config comes from the server-injected <body> data-attributes (CSP-native; no inline script).
    const ds = document.body.dataset;
    if (ds.token && ds.token !== "__VIGIL_TOKEN__") CFG.token = ds.token;
    if (ds.sovereign != null && ds.sovereign !== "__VIGIL_SOVEREIGN__") CFG.api.sovereign = ds.sovereign;
    if (ds.offense != null && ds.offense !== "__VIGIL_OFFENSE__") CFG.api.offense = ds.offense;
    try { const t = localStorage.getItem("vigil-theme"); if (t) document.documentElement.setAttribute("data-theme", t); } catch (e) {}
    shell();
    window.addEventListener("hashchange", route);
    if (!location.hash) location.hash = "#/home";
    route();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
