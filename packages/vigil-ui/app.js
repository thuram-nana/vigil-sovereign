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
      { id: "findings", label: "Findings", icon: "find", ready: true },
      { id: "fixes", label: "Fixes", icon: "fixes", ready: true },
      { id: "defense", label: "Defense (AEGIS)", icon: "shield", ready: true },
    ]},
    { group: "MANAGE", items: [
      { id: "safety", label: "Approvals & Safety", icon: "key", owner: true, ready: true },
      { id: "apikeys", label: "API Keys", icon: "key", owner: true, ready: true },
      { id: "tools", label: "Tools", icon: "bolt", ready: true },
      { id: "brain", label: "Brain", icon: "brain", ready: true },
      { id: "settings", label: "Settings", icon: "gear", owner: true, ready: true },
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
    const themeBtn = h("button.iconbtn", { title: "Toggle theme", "aria-label": "Toggle light/dark theme", onClick: toggleTheme }, V.icon("dot"));
    const cta = h("button.btn.primary", { onClick: function () { location.hash = "#/assess"; } }, [V.icon("bolt"), "New Assessment"]);
    // API-key failure badge — hidden until a live probe reports a failing key (populated by refreshKeysBadge)
    const keysBadge = h("button.safety.tripped#keys-badge", { style: { display: "none" },
      title: "One or more API keys are failing", onClick: function () { location.hash = "#/apikeys"; } }, "");
    return h("div#topbar", null, [seg, cmdk, h("div.spacer"), counts, live, keysBadge, safety, themeBtn, cta]);
  }

  // Poll the redacted settings status for the failing-key count and show/hide the top-bar badge. Cheap +
  // owner-plane; silently no-ops if the sovereign plane is offline (badge stays hidden).
  function refreshKeysBadge() {
    V.getJSON(SOV("/api/settings")).then(function (st) {
      var el = V.$("#keys-badge"); if (!el) return;
      var n = (st && st.keys_failing) || 0;
      if (n > 0) { el.textContent = ""; el.appendChild(V.icon("info"));
        el.appendChild(document.createTextNode(" " + n + " API key" + (n === 1 ? "" : "s") + " failing"));
        el.style.display = ""; }
      else { el.style.display = "none"; }
    }).catch(function () {});
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
    function go() { location.hash = "#/" + it.id; }
    return h("div.nav-item" + (it.owner ? ".owner" : "") + (active ? ".active" : ""),
      { dataset: { nav: it.id }, role: "link", tabindex: "0",
        "aria-current": active ? "page" : null, "aria-label": it.label,
        onClick: go,
        onKeydown: function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } } },
      [V.icon(it.icon), h("span.txt", null, it.label), badge]);
  }
  function current() { return (location.hash || "#/home").slice(2).split("?")[0] || "home"; }

  function shell() {
    document.body.appendChild(h("div#app", null, [
      h("div#brand", null, [h("span.logo", null, "V"), h("span.name", null, "VIGIL COMMAND")]),
      topbar(),
      h("div#nav", { role: "navigation", "aria-label": "Primary" }),
      h("div#main", null, h("div.wrap#screen")),
    ]));
    document.body.appendChild(h("div#drawer", null, [h("div.dh", null, [h("h2#drawer-title", null, "Detail"),
      h("button.iconbtn", { "aria-label": "Close detail panel", onClick: closeDrawer }, V.icon("x"))]), h("div.db#drawer-body")]));
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

  // ==========================================================================
  // P3 — Findings hub: Findings · Attack Graph · Evidence · Coverage · Timeline
  // Every surface reads the offense console's RESILIENT, offline read providers
  // (report / worldmodel / evidence / coverage). Nothing is hardcoded; a finding
  // is only ever shown CONFIRMED (a FACT) when a deterministic oracle actually
  // re-grounds it — otherwise it is an honest LEAD. Re-verify + graph reconstruct
  // are pure re-runs of retained evidence and issue ZERO target traffic.
  // ==========================================================================

  const P3_TABS = [
    { id: "findings", label: "Findings", icon: "find" },
    { id: "graph", label: "Attack Graph", icon: "brain" },
    { id: "evidence", label: "Evidence", icon: "shield" },
    { id: "coverage", label: "Coverage", icon: "assess" },
    { id: "timeline", label: "Timeline", icon: "live" },
  ];

  // The HONEST fact test for a finding as returned by /api/report/<run> (the rendered
  // build_report shape) OR a blackboard FindingPayload. In order of authority:
  //   1. `grounding` — the LIVE veracity-firewall verdict at render time; "fact" ⟺ the
  //      finding's own oracle RE-FIRED over its retained evidence. This is the strongest,
  //      most honest signal (stronger than a mere certificate existing).
  //   2. `verified_by_oracle` — the blackboard provenance flag.
  //   3. fallback: an active finding carrying a real oracle kind (never a passive/DOM lead).
  // A passive/dom_xss lead is NEVER a fact.
  function p3IsFact(f) {
    if (!f) return false;
    if (typeof f.grounding === "string" && f.grounding) return f.grounding === "fact";
    if (f.verified_by_oracle != null) return !!f.verified_by_oracle;
    const ob = f.confirmed_by || f.oracle_kind || "";
    return f.kind === "active" && !!ob && ob !== "passive" && ob !== "static-lead";
  }
  // World-model grounding is a DIFFERENT vocabulary from the report's "fact" (do not confuse them):
  // worldmodel/models.classify_provenance emits "grounded" (the oracle / evidence-cert / confirmed-finding
  // fact tier) vs "intel" / "ungrounded" / "unclassified" (inferred/unproven). Pinned by
  // test_worldmodel_grounding_vocab.py so a backend rename can't silently make this lie.
  function p3WmFact(g) { return g === "grounded"; }
  function p3Surface(f) {
    return f.location || f.surface || f.insertion_point || f.param || f.endpoint || "—";
  }
  function p3Oracle(f) { return f.confirmed_by || f.oracle_kind || "—"; }
  function p3Rationale(f) { return f.oracle_rationale || f.evidence || f.rationale || ""; }
  function p3Sev(f) { return String(f.severity || "").trim(); }
  function p3SevChip(sev) {
    const s = String(sev || "").toLowerCase();
    return s ? h("span.sev.sev-" + s, null, sev) : h("span.muted", null, "—");
  }
  function p3StatusChip(f) {
    if (p3IsFact(f)) return h("span.shield", null, [V.icon("check"), "CONFIRMED"]);
    // a LEAD is explicitly "not proven". If it is an ACTIVE finding whose oracle failed to
    // re-ground (contradicted / ungrounded), say so honestly rather than a bland "lead".
    const g = f.grounding;
    const label = (g === "contradicted") ? "CONTRADICTED"
      : (g === "ungrounded") ? "UNGROUNDED" : "LEAD";
    return h("span.shield.lead", { title: "Not proven by an oracle" }, label);
  }

  // ---- the hub ---------------------------------------------------------------
  function renderFindings(screen) {
    const S = { runs: [], run: null, tab: "findings" };
    const q = hashQuery();
    const want = q.run || "";
    const wantTab = q.tab || "";

    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Findings"),
        h("span.sub", null, "Proven bugs, the attack graph, re-checkable evidence, coverage and replay — all oracle-gated.")]),
      h("div#p3-body", null, h("div.empty", null, "Loading runs…")),
    ]);

    V.getJSON(OFF("/api/runs")).then(function (d) {
      S.runs = (d && d.runs) || [];
      S.run = S.runs.find(function (r) { return r.run_id === want; }) || S.runs[0] || null;
      if (P3_TABS.some(function (t) { return t.id === wantTab; })) S.tab = wantTab;
      drawShell();
    }).catch(function () {
      V.mount(V.$("#p3-body"), h("div.empty", null, [h("div.big", null, "Offense engine offline"),
        h("p", null, "Could not reach the offense console. Start it (vigil up) and reload.")]));
    });

    function syncHash() {
      if (!S.run) return;
      history.replaceState(null, "", "#/findings?run=" + encodeURIComponent(S.run.run_id) + "&tab=" + S.tab);
    }
    function selectRun(runId) {
      S.run = S.runs.find(function (r) { return r.run_id === runId; }) || null;
      syncHash(); drawShell();
    }
    function selectTab(tab) { S.tab = tab; syncHash(); drawTab(); }

    function drawShell() {
      const body = V.$("#p3-body"); if (!body) return;
      if (!S.runs.length) {
        V.mount(body, h("div.empty", null, [h("div.big", null, "No runs yet"),
          h("p", null, "Start an assessment and its findings, attack graph and evidence appear here."),
          h("button.btn.primary", { style: { marginTop: "16px" }, onClick: function () { location.hash = "#/assess"; } },
            [V.icon("bolt"), "New Assessment"])]));
        return;
      }
      const picker = h("div.field", { style: { maxWidth: "560px", marginBottom: "0" } }, [
        h("label", null, "Run"),
        h("select", { onChange: function (e) { selectRun(e.target.value); } }, S.runs.map(function (r) {
          return h("option", { value: r.run_id, selected: S.run && r.run_id === S.run.run_id },
            (r.mode || "url") + " · " + (r.target || r.slug || r.run_id) + " · " + r.status);
        })),
      ]);
      const tabs = h("div.segmented", { style: { marginTop: "12px", flexWrap: "wrap" } }, P3_TABS.map(function (t) {
        return h("button" + (S.tab === t.id ? ".on" : ""), { onClick: function () { selectTab(t.id); } }, t.label);
      }));
      V.mount(body, [picker, tabs, h("div#p3-view", { style: { marginTop: "16px" } })]);
      drawTab();
    }

    function drawTab() {
      const host = V.$("#p3-view"); if (!host || !S.run) return;
      V.mount(host, h("div.empty", null, "Loading…"));
      if (S.tab === "findings") p3Findings(host, S.run);
      else if (S.tab === "graph") p3Graph(host, S.run);
      else if (S.tab === "evidence") p3Evidence(host, S.run);
      else if (S.tab === "coverage") p3Coverage(host, S.run);
      else if (S.tab === "timeline") p3Timeline(host, S.run);
    }
  }

  function p3RunHasNoReport(run) {
    // strix/aegis runs (stream 'none') and live engage runs (stream 'blackboard') don't save a
    // rendered findings report — say so honestly and point to where their results DO live.
    return run.stream === "none" || run.stream === "blackboard";
  }
  function p3NoReportEmpty(run, what) {
    if (run.stream === "blackboard") {
      return h("div.empty", null, [h("div.big", null, "This run reports on the reasoning spine"),
        h("p", null, (what || "Findings") + " for a live engage run stream onto the blackboard — open it in Live to watch every FACT and LEAD as an oracle adjudicates it."),
        h("button.btn", { style: { marginTop: "14px" }, onClick: function () { location.hash = "#/live?run=" + encodeURIComponent(run.run_id); } },
          [V.icon("live"), "Open in Live"])]);
    }
    if (run.stream === "none") {
      return h("div.empty", null, [h("div.big", null, "Runs in its own sandbox"),
        h("p", null, "A codebase (Strix) / AEGIS run reports inside its sandbox — no re-checkable web report is captured here.")]);
    }
    return null;
  }

  // ---- 1) Findings table + detail drawer -------------------------------------
  function p3Findings(host, run) {
    V.getJSON(OFF("/api/report/" + encodeURIComponent(run.run_id))).then(function (rep) {
      if (rep && rep.pending) { V.mount(host, p3NoReportEmpty(run, "Findings") || pendingEmpty(run)); return; }
      const findings = (rep && rep.findings) || [];
      const sum = (rep && rep.summary) || {};
      const st = { filter: "all" };

      function draw() {
        let rows = findings;
        if (st.filter === "facts") rows = rows.filter(p3IsFact);
        else if (st.filter === "leads") rows = rows.filter(function (f) { return !p3IsFact(f); });

        const facts = findings.filter(p3IsFact).length;
        const leads = findings.length - facts;
        const summaryTiles = h("div.grid.cols-4", { style: { marginBottom: "16px" } }, [
          V.tile("Confirmed", String(facts), "oracle-proven FACTs", facts ? "up" : ""),
          V.tile("Leads", String(leads), "not proven"),
          V.tile("Endpoints", String((sum.discovered_endpoints != null ? sum.discovered_endpoints : (rep.discovered_endpoints || []).length)), "surface seen"),
          V.tile("Requests", String(sum.requests_audited || 0), "audited"),
        ]);
        const filterSeg = h("div.segmented", null, [["all", "All"], ["facts", "Facts"], ["leads", "Leads"]].map(function (f) {
          return h("button" + (st.filter === f[0] ? ".on" : ""), { onClick: function () { st.filter = f[0]; draw(); } }, f[1]);
        }));
        const legend = h("div.legend", null, [V.icon("shield"),
          "Only a fired deterministic ORACLE proves a finding (CONFIRMED / FACT). Everything else — passive hygiene, DOM leads, an active finding whose oracle did not re-ground — is an honest LEAD, never shown as fact."]);

        let table;
        if (!rows.length) {
          table = h("div.empty", null, findings.length
            ? "No findings match this filter."
            : "Findings appear here once an oracle proves a bug on this target.");
        } else {
          table = h("div.scroll-x", null, h("table.tbl", null, [
            h("thead", null, h("tr", null, ["Severity", "Bug class", "Surface", "Oracle", "Status"].map(function (c) { return h("th", null, c); }))),
            h("tbody", null, rows.map(function (f) {
              return h("tr.click", { onClick: function () { p3OpenFindingDrawer(run, f); } }, [
                h("td", null, p3SevChip(p3Sev(f))),
                h("td", null, h("b.mono", null, f.bug_class || "—")),
                h("td", null, h("span.mono", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all" } }, p3Surface(f))),
                h("td", null, h("span.mono", { style: { fontSize: "var(--fs-xs)" } }, p3Oracle(f))),
                h("td", null, p3StatusChip(f)),
              ]);
            })),
          ]));
        }
        V.mount(host, [
          summaryTiles,
          h("div.card", null, [
            h("div.card-h", null, [h("span.label", null, "FINDINGS"),
              h("h3", null, (rep.target || run.target || "target")),
              h("span.grow", { style: { flex: 1 } }), filterSeg]),
            legend,
            h("div", { style: { marginTop: "12px" } }, table),
          ]),
        ]);
      }
      draw();
    }).catch(function () { V.mount(host, offlineEmpty()); });
  }

  function p3OpenFindingDrawer(run, f) {
    const kv = [];
    const put = function (k, v) { if (v == null || v === "") return; kv.push(h("div.kv", null, [h("div.k", null, k), h("div.v", null, String(v))])); };
    const fact = p3IsFact(f);
    put("Verdict", fact ? "CONFIRMED — an oracle re-fired over the retained evidence (a FACT)"
      : (f.grounding === "contradicted" ? "CONTRADICTED — the oracle did NOT re-ground this claim"
        : f.grounding === "ungrounded" ? "UNGROUNDED — no live oracle proof"
          : "LEAD — a proposal, not proven"));
    put("Severity", p3Sev(f) || "—");
    put("Bug class", f.bug_class);
    put("Surface", p3Surface(f));
    put("Oracle kind", p3Oracle(f));
    if (f.confidence != null && f.confidence !== "") put("Confidence", f.confidence);
    if (f.cvss_vector) put("CVSS vector", f.cvss_vector);
    if (f.cvss_base != null) put("CVSS base", f.cvss_base);
    if (f.derived_from_hypothesis) put("Derived from", f.derived_from_hypothesis);
    if (f.re_verifiable != null) put("Re-runnable certificate", f.re_verifiable ? "yes" : "no");

    const sections = [h("div.dsection", null, [h("h3", { style: { marginBottom: "6px" } }, f.title || f.bug_class || "Finding"),
      p3IsFact(f) ? h("span.shield", null, [V.icon("check"), "CONFIRMED"]) : h("span.shield.lead", null, "LEAD"),
      h("div", { style: { marginTop: "12px" } }, kv)])];

    if (f.impact) sections.push(h("div.dsection", null, [h("span.label", null, "IMPACT"),
      h("p.muted", { style: { marginTop: "6px", lineHeight: "1.55" } }, f.impact)]));

    const rationale = p3Rationale(f);
    sections.push(h("div.dsection", null, [h("span.label", null, "ORACLE RATIONALE — which signal fired, on what evidence"),
      rationale ? h("pre.code", { style: { marginTop: "8px" } }, rationale)
        : h("p.muted", { style: { marginTop: "6px" } }, fact ? "(no rationale text retained)" : "No oracle fired — this is a lead, not a proven fact.")]));

    if (f.remediation) sections.push(h("div.dsection", null, [h("span.label", null, "REMEDIATION"),
      h("p.muted", { style: { marginTop: "6px", lineHeight: "1.55" } }, f.remediation)]));
    if (f.references && f.references.length) sections.push(h("div.dsection", null, [h("span.label", null, "REFERENCES"),
      h("div.stack", { style: { gap: "4px", marginTop: "6px" } }, f.references.map(function (r) { return h("span.mono.muted", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all" } }, r); }))]));

    // Re-verify: a PURE, offline re-run of this run's retained certificates (no target traffic).
    const rvHost = h("div", { style: { marginTop: "8px" } });
    const rvBtn = h("button.btn", { onClick: function () { p3ReverifyInline(run, rvHost, rvBtn); } },
      [V.icon("check"), "Re-verify this run (offline)"]);
    sections.push(h("div.dsection", null, [h("span.label", null, "RE-VERIFY"),
      h("p.muted", { style: { margin: "6px 0" } }, "Re-runs every retained oracle certificate for this run offline — no request is sent to the target."),
      rvBtn, rvHost]));

    openDrawer(f.title || f.bug_class || "Finding", sections);
  }

  function p3ReverifyInline(run, host, btn) {
    btn.disabled = true;
    V.mount(host, h("div.muted", { style: { marginTop: "10px" } }, "Re-verifying offline…"));
    V.postJSON(OFF("/api/reverify/" + encodeURIComponent(run.run_id)), {}).then(function (r) {
      btn.disabled = false;
      if (!r || r.error) { V.mount(host, h("div.legend", { style: { marginTop: "10px" } }, [V.icon("info"), (r && r.error) || "no re-verifiable artifact for this run"])); return; }
      const all = r.total > 0 && r.reproduced === r.total;
      const badge = h("span.st." + (all ? "st-confirmed" : (r.reproduced ? "st-queued" : "st-blocked")), null,
        [h("span.dot"), r.reproduced + " / " + r.total + " reproduced"]);
      const list = (r.results || []).map(function (x) {
        const okc = x.reproduced ? "st-confirmed" : "st-blocked";
        return h("div.trow", { style: { cursor: "default" } }, [
          h("div.ico", null, V.icon(x.reproduced ? "check" : "x")),
          h("div.body", null, [h("div.k", null, x.confirmed_by || x.finding || "cert"), h("div.m", null, x.note || "")]),
          // "reproduced" (not "sound") — this roll-up exposes only re-fire, not claim-match; the note
          // flags a claim mismatch, and the Evidence tab shows the full sound/tampered/claim-mismatch state.
          h("div.meta", null, h("span.st." + okc, null, [h("span.dot"), x.reproduced ? "reproduced" : "not reproduced"])),
        ]);
      });
      V.mount(host, [h("div", { style: { marginTop: "10px", marginBottom: "8px" } }, badge),
        h("div.feed", null, list)]);
    }).catch(function (e) { btn.disabled = false; V.mount(host, h("div.legend", { style: { marginTop: "10px" } }, [V.icon("info"), (e && e.message) || "re-verify failed"])); });
  }

  // ---- 2) Attack graph (CSP-native SVG; force-directed layout) ---------------
  const P3_KIND_COLOR = {
    endpoint: "#4aa3ff", finding: "#ff8a3d", host: "#ff5470", datastore: "#f5c542",
    credential: "#c88bff", principal: "#37c8d6", cloud_resource: "#35d07f",
    service: "#8895a7", webapp: "#4aa3ff", session: "#c88bff", control: "#8895a7",
    network_segment: "#8895a7", attacker: "#f5a623",
  };
  function p3IsAttacker(id) { return String(id || "").indexOf("attacker") >= 0; }
  function p3NodeColor(n) {
    if (p3IsAttacker(n.id)) return P3_KIND_COLOR.attacker;
    return P3_KIND_COLOR[n.kind] || "#8895a7";
  }
  // Deterministic force-directed layout (ported from the legacy graph.js, math only — no DOM).
  function p3Layout(nodes, edges, W, H) {
    const N = nodes.length; if (!N) return;
    nodes.forEach(function (n, i) {
      const a = (i / N) * Math.PI * 2;
      n.x = W / 2 + Math.cos(a) * Math.min(W, H) * 0.32;
      n.y = H / 2 + Math.sin(a) * Math.min(W, H) * 0.32;
      n.vx = 0; n.vy = 0;
      if (p3IsAttacker(n.id)) { n.x = W / 2; n.y = H - 54; }
    });
    const idx = {}; nodes.forEach(function (n, i) { idx[n.id] = i; });
    const REST = 90, KREP = 5200, KSPR = 0.045, DAMP = 0.85, CENTER = 0.008;
    for (let it = 0; it < 260; it++) {
      for (let i = 0; i < N; i++) {
        let fx = (W / 2 - nodes[i].x) * CENTER, fy = (H / 2 - nodes[i].y) * CENTER;
        for (let j = 0; j < N; j++) {
          if (i === j) continue;
          const dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
          const d2 = dx * dx + dy * dy || 0.01, d = Math.sqrt(d2);
          const f = KREP / d2; fx += (dx / d) * f; fy += (dy / d) * f;
        }
        nodes[i]._fx = fx; nodes[i]._fy = fy;
      }
      for (let k = 0; k < edges.length; k++) {
        const a = nodes[idx[edges[k].src]], b = nodes[idx[edges[k].dst]]; if (!a || !b) continue;
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 0.01;
        const f = (d - REST) * KSPR;
        a._fx += (dx / d) * f; a._fy += (dy / d) * f;
        b._fx -= (dx / d) * f; b._fy -= (dy / d) * f;
      }
      for (let i = 0; i < N; i++) {
        const n = nodes[i]; if (p3IsAttacker(n.id)) continue;
        n.vx = (n.vx + n._fx) * DAMP; n.vy = (n.vy + n._fy) * DAMP;
        n.x += Math.max(-12, Math.min(12, n.vx)); n.y += Math.max(-12, Math.min(12, n.vy));
        n.x = Math.max(30, Math.min(W - 30, n.x)); n.y = Math.max(30, Math.min(H - 30, n.y));
      }
    }
  }
  // Render a world-model graph into `container` (svgEl → CSP-clean: no innerHTML, no inline handlers).
  function p3DrawGraph(container, data, onPick) {
    V.clear(container);
    const nodes = (data.nodes || []).map(function (n) { return Object.assign({}, n); });
    const edges = data.edges || [];
    if (!nodes.length) {
      container.appendChild(h("div.empty", null, "No world-model nodes — a run with chainable findings (IDOR / SSRF / deserialization) populates the graph."));
      return;
    }
    const W = Math.max(680, container.clientWidth || 880), H = 520;
    p3Layout(nodes, edges, W, H);
    const pos = {}; nodes.forEach(function (n) { pos[n.id] = n; });
    const pathEdges = {}; (data.paths || []).forEach(function (p) { (p.steps || []).forEach(function (s) { pathEdges[s.src + ">" + s.dst] = 1; }); });
    const chokeEdges = {}; const chokeNodes = {};
    (data.chokes || []).forEach(function (c) { chokeEdges[c.src + ">" + c.dst] = 1; chokeNodes[c.src] = 1; chokeNodes[c.dst] = 1; });

    const svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, width: "100%", height: H });
    // style via CSSOM (never an inline style ATTRIBUTE) so this stays clean under the bundle's
    // strict same-origin CSP (no 'unsafe-inline' for styles); presentation attrs (fill/stroke) are fine.
    svg.style.background = "var(--bg-0)"; svg.style.border = "1px solid var(--border)"; svg.style.borderRadius = "8px";

    edges.forEach(function (e) {
      const a = pos[e.src], b = pos[e.dst]; if (!a || !b) return;
      const key = e.src + ">" + e.dst;
      const onPath = pathEdges[key], choke = chokeEdges[key];
      const stroke = choke ? "var(--st-blocked)" : (onPath ? "var(--st-running)" : "var(--border-strong)");
      const w = choke ? 2.4 : (onPath ? 2.2 : 1);
      const line = svgEl("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: stroke, "stroke-width": w,
        opacity: (onPath || choke) ? 0.95 : 0.4 });
      if (choke) line.setAttribute("stroke-dasharray", "5 4");
      svg.appendChild(line);
      if (onPath && e.technique) {
        const t = svgEl("text", { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - 3, "font-size": 9,
          fill: "var(--text-2)", "text-anchor": "middle", "font-family": "var(--font-mono)" });
        t.textContent = String(e.technique).slice(0, 22); svg.appendChild(t);
      }
    });

    nodes.forEach(function (n) {
      const isAtt = p3IsAttacker(n.id);
      const r = isAtt ? 11 : (n.kind === "finding" ? 6 : 8);
      const g = svgEl("g"); g.style.cursor = "pointer";
      if (chokeNodes[n.id]) {
        g.appendChild(svgEl("circle", { cx: n.x, cy: n.y, r: r + 5, fill: "none",
          stroke: "var(--st-blocked)", "stroke-width": 1.4, "stroke-dasharray": "3 3", opacity: 0.9 }));
      }
      const dot = svgEl("circle", { cx: n.x, cy: n.y, r: r, fill: p3NodeColor(n), stroke: "var(--bg-0)", "stroke-width": 1.5,
        opacity: 0.55 + 0.45 * (n.belief == null ? 1 : n.belief) });
      const label = svgEl("text", { x: n.x + r + 3, y: n.y + 3, "font-size": 10, fill: "var(--text-1)", "font-family": "var(--font-mono)" });
      label.textContent = String(n.id).replace(/^[a-z_]+:/, "").slice(0, 22);
      g.appendChild(dot); g.appendChild(label);
      g.addEventListener("click", function () { if (onPick) onPick(n); });
      svg.appendChild(g);
    });
    container.appendChild(svg);

    // legend (kinds present) + path / choke keys
    const kinds = {}; nodes.forEach(function (n) { kinds[p3IsAttacker(n.id) ? "attacker" : n.kind] = 1; });
    const leg = h("div.row-flex", { style: { flexWrap: "wrap", gap: "12px", marginTop: "8px" } },
      Object.keys(kinds).map(function (k) {
        return h("span.row-flex", { style: { gap: "5px" } }, [
          h("span", { style: { width: "9px", height: "9px", borderRadius: "50%", background: P3_KIND_COLOR[k] || "#8895a7", display: "inline-block" } }),
          h("span.muted", { style: { fontSize: "var(--fs-xs)" } }, k)]);
      }).concat([
        h("span.row-flex", { style: { gap: "5px", marginLeft: "auto" } }, [
          h("span", { style: { width: "16px", borderTop: "2px solid var(--st-running)", display: "inline-block" } }),
          h("span.muted", { style: { fontSize: "var(--fs-xs)" } }, "attack path")]),
        h("span.row-flex", { style: { gap: "5px" } }, [
          h("span", { style: { width: "16px", borderTop: "2px dashed var(--st-blocked)", display: "inline-block" } }),
          h("span.muted", { style: { fontSize: "var(--fs-xs)" } }, "choke-point")]),
      ]));
    container.appendChild(leg);
  }

  function p3Graph(host, run) {
    V.getJSON(OFF("/api/worldmodel/" + encodeURIComponent(run.run_id))).then(function (wm) {
      if (wm && wm.pending) { V.mount(host, p3NoReportEmpty(run, "The attack graph") || pendingEmpty(run)); return; }
      if (wm && wm.error) { V.mount(host, h("div.empty", null, [h("div.big", null, "Could not reconstruct the world-model"), h("p", null, wm.error)])); return; }
      const tiles = h("div.grid.cols-4", { style: { marginBottom: "16px" } }, [
        V.tile("Nodes", String(wm.node_count != null ? wm.node_count : (wm.nodes || []).length), "world-model"),
        V.tile("Edges", String(wm.edge_count != null ? wm.edge_count : (wm.edges || []).length), "relations"),
        V.tile("Attack paths", String((wm.paths || []).length), "attacker → crown-jewel", (wm.paths || []).length ? "down" : ""),
        V.tile("Choke-points", String((wm.chokes || []).length), "sever to cut paths"),
      ]);
      const graphCard = V.card("Attacker → impact", "ATTACK GRAPH", h("div#p3-graph", null, h("div.empty", null, "Rendering…")), false);
      const pathsCard = V.card("Attack paths", "REACHABILITY",
        (wm.paths || []).length
          ? h("div.stack", { style: { gap: "8px" } }, wm.paths.map(function (p) {
              return h("div.node", null, [
                h("div.node-t", null, p.description || (p.destination || "path")),
                h("div.node-meta", null, [
                  h("span", null, (p.hops != null ? p.hops + " hops" : "")),
                  h("span", null, "detection cost " + (p.detection_cost != null ? p.detection_cost : "?")),
                  h("span", null, "value " + (p.value != null ? Math.round(p.value * 100) / 100 : "?")),
                ]),
              ]);
            }))
          : h("div.empty", null, "No attacker→crown-jewel path — nothing chains to a modelled crown jewel."), false);
      const chokeCard = V.card("Choke-points", "REMEDIATION LEVERS",
        (wm.chokes || []).length
          ? h("div.scroll-x", null, h("table.tbl", null, [
              h("thead", null, h("tr", null, ["Edge", "Kind", "Disconnects", "Impact cut", "Bridge"].map(function (c) { return h("th", null, c); }))),
              h("tbody", null, wm.chokes.map(function (c) {
                return h("tr", null, [
                  h("td", null, h("span.mono", { style: { fontSize: "var(--fs-xs)" } }, (c.src || "") + " → " + (c.dst || ""))),
                  h("td", null, c.kind || "—"),
                  h("td", null, String(c.disconnects != null ? c.disconnects : "—")),
                  h("td", null, String(c.impact_disconnected != null ? Math.round(c.impact_disconnected * 100) / 100 : "—")),
                  h("td", null, c.is_bridge ? h("span.st.st-blocked", null, [h("span.dot"), "bridge"]) : h("span.muted", null, "no")),
                ]);
              })),
            ]))
          : h("div.empty", null, "No choke-points — no single edge severs an attack path here."), false);

      V.mount(host, [tiles, graphCard, h("div.grid.cols-2", { style: { marginTop: "16px", alignItems: "start" } }, [pathsCard, chokeCard])]);
      p3DrawGraph(V.$("#p3-graph"), wm, function (n) { p3OpenNodeDrawer(wm, n); });
    }).catch(function () { V.mount(host, offlineEmpty()); });
  }

  function p3OpenNodeDrawer(wm, n) {
    const kv = [];
    const put = function (k, v) { if (v == null || v === "") return; kv.push(h("div.kv", null, [h("div.k", null, k), h("div.v", null, String(v))])); };
    put("Node", n.id);
    put("Kind", n.kind);
    put("Belief", n.belief);
    put("Confidence", n.confidence);
    put("Grounding", n.grounding);
    put("Provenance", n.provenance);
    put("Detail", n.detail);
    if (n.first_seen != null) put("First seen (seq)", n.first_seen);
    if (n.last_seen != null) put("Last seen (seq)", n.last_seen);
    // the facts/leads that touch this node = the edges incident on it
    const incident = (wm.edges || []).filter(function (e) { return e.src === n.id || e.dst === n.id; });
    const edgeRows = incident.length ? incident.map(function (e) {
      const fact = (typeof e.grounding === "string" && e.grounding) ? p3WmFact(e.grounding) : (e.belief != null && e.belief >= 0.999);
      return h("div.trow", { style: { cursor: "default" } }, [
        h("div.ico", null, V.icon("dot")),
        h("div.body", null, [h("div.k", null, (e.src === n.id ? "→ " + e.dst : e.src + " →")),
          h("div.m", null, (e.kind || "") + (e.technique ? " · " + e.technique : ""))]),
        h("div.meta", null, fact ? h("span.shield", null, [V.icon("check"), "FACT"]) : h("span.shield.lead", null, "LEAD")),
      ]);
    }) : [h("div.empty", null, "No incident edges.")];
    openDrawer(String(n.id).replace(/^[a-z_]+:/, ""), [
      h("div.dsection", null, [h("span.label", null, "NODE"), h("div", { style: { marginTop: "8px" } }, kv)]),
      h("div.dsection", null, [h("span.label", null, "FACTS / LEADS AT THIS NODE"), h("div.feed", { style: { marginTop: "8px" } }, edgeRows)]),
      n.grounding && !p3WmFact(n.grounding)
        ? h("div.legend", null, [V.icon("info"), "This node's grounding is '" + n.grounding + "' — it is inferred/unproven, not an oracle-confirmed fact."]) : null,
    ]);
  }

  // ---- 3) Evidence browser (offline re-verify → sound / tampered / mismatch) --
  function p3EvidenceState(f) {
    if (!f.has_certificate) return { sym: "—", label: "No certificate", cls: "st-idle",
      why: "This finding carries no re-runnable oracle_context — it is a lead, not a certified fact." };
    if (f.sound) return { sym: "✔", label: "Sound", cls: "st-confirmed",
      why: "The pure oracle re-fired over the retained evidence and matches the claimed certificate." };
    if (!f.reproduced) return { sym: "✖", label: "Tampered", cls: "st-blocked",
      why: "The retained evidence no longer re-confirms — it was altered, or never truly confirmed." };
    return { sym: "⚠", label: "Claim mismatch", cls: "st-queued",
      why: "The oracle re-fires, but with a different kind/confidence than the certificate claimed." };
  }
  function p3Evidence(host, run) {
    function load(then) {
      V.getJSON(OFF("/api/evidence/" + encodeURIComponent(run.run_id))).then(then).catch(function () { V.mount(host, offlineEmpty()); });
    }
    load(function (ev) {
      if (ev && ev.pending) { V.mount(host, p3NoReportEmpty(run, "Evidence") || pendingEmpty(run)); return; }
      const findings = (ev && ev.findings) || [];
      const tiles = h("div.grid.cols-4", { style: { marginBottom: "16px" } }, [
        V.tile("Certificates", String(findings.length), "re-checkable"),
        V.tile("Sound", String(ev.reproduced != null ? ev.reproduced : findings.filter(function (f) { return f.sound; }).length), "reproduced offline", "up"),
        V.tile("Not sound", String(findings.filter(function (f) { return f.has_certificate && !f.sound; }).length), "tampered / mismatch", findings.some(function (f) { return f.has_certificate && !f.sound; }) ? "down" : ""),
        V.tile("Traffic sent", "0", "pure re-run", "up"),
      ]);
      const doctrine = h("div.legend", { style: { marginBottom: "12px" } }, [V.icon("shield"),
        (ev.doctrine || "Each certificate re-verifies OFFLINE with no target and no trust in the tool that produced it.")]);
      let cards;
      if (!findings.length) {
        cards = h("div.empty", null, "No evidence certificates — a run with oracle-confirmed findings mints re-checkable certificates here.");
      } else {
        cards = h("div.stack", null, findings.map(function (f) { return p3EvidenceCard(run, f); }));
      }
      V.mount(host, [tiles, doctrine, cards]);
    });
  }
  function p3EvidenceCard(run, f) {
    const state = p3EvidenceState(f);
    const badge = h("span.st." + state.cls, { style: { fontSize: "var(--fs-sm)", padding: "6px 12px" } }, [h("span.dot"), state.sym + " " + state.label]);
    const stateHost = h("div", null, badge);
    const rvBtn = h("button.btn", { title: "Re-run this run's certificates offline (no target traffic)",
      onClick: function () { p3EvidenceReverify(run, f, stateHost, rvBtn); } }, [V.icon("check"), "Offline re-verify"]);
    const meta = [];
    const put = function (k, v) { if (v == null || v === "") return; meta.push(h("div.kv", null, [h("div.k", null, k), h("div.v", null, String(v))])); };
    put("Finding", f.bug_class || f.ref);
    put("Surface", f.surface);
    put("OracleKind", f.confirmed_by);
    put("Confidence", f.confidence);
    put("Cert id (content hash)", f.cert_id || "(no certificate)");
    return h("div.card", null, [
      h("div", { style: { display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap", marginBottom: "10px" } },
        [stateHost, h("b.mono", null, f.bug_class || f.ref), h("span.grow", { style: { flex: 1 } }), rvBtn]),
      h("div", null, meta),
      f.note ? h("div.legend", { style: { marginTop: "10px" } }, [V.icon("info"), f.note]) : null,
      h("p.muted", { style: { marginTop: "8px", fontSize: "var(--fs-xs)" } }, state.why),
    ]);
  }
  function p3EvidenceReverify(run, f, stateHost, btn) {
    btn.disabled = true;
    const prev = stateHost.firstChild;
    V.mount(stateHost, h("span.muted", null, "Re-verifying offline…"));
    // Re-fetch the evidence provider (a pure offline oracle re-run — issues NO target traffic) and
    // resolve THIS certificate's honest state again.
    V.getJSON(OFF("/api/evidence/" + encodeURIComponent(run.run_id))).then(function (ev) {
      btn.disabled = false;
      const fresh = ((ev && ev.findings) || []).find(function (x) { return x.ref === f.ref; }) || f;
      const st = p3EvidenceState(fresh);
      V.mount(stateHost, h("span.st." + st.cls, { style: { fontSize: "var(--fs-sm)", padding: "6px 12px" } }, [h("span.dot"), st.sym + " " + st.label]));
      V.toast(st.label === "Sound" ? "Certificate reproduced offline — sound." : ("Re-verify: " + st.label), st.label !== "Sound");
    }).catch(function () { btn.disabled = false; if (prev) V.mount(stateHost, prev); V.toast("Re-verify failed", true); });
  }

  // ---- 4) Coverage -----------------------------------------------------------
  function p3Coverage(host, run) {
    V.getJSON(OFF("/api/coverage/" + encodeURIComponent(run.run_id))).then(function (cov) {
      if (cov && cov.pending) { V.mount(host, p3NoReportEmpty(run, "Coverage") || pendingEmpty(run)); return; }
      const sum = cov.summary || {};
      const fp = cov.fingerprint || [];
      const eps = cov.discovered_endpoints || [];
      const passive = cov.passive || [];
      const dom = cov.dom_xss || [];
      const tiles = h("div.grid.cols-4", { style: { marginBottom: "16px" } }, [
        V.tile("Pages crawled", String(sum.pages_crawled || 0), "reached"),
        V.tile("Requests audited", String(sum.requests_audited || 0), "probed"),
        V.tile("Endpoints", String(eps.length || sum.discovered_endpoints || 0), "surface mapped"),
        V.tile("Confirmed", String(sum.confirmed || 0), "oracle FACTs", sum.confirmed ? "up" : ""),
      ]);
      const stack = V.card("Detected stack", "FINGERPRINT",
        fp.length ? h("div", { style: { display: "flex", flexWrap: "wrap", gap: "6px" } }, fp.map(function (t) { return h("span.pill", null, t); }))
          : h("div.empty", null, "No technology fingerprinted (library-driven scanning may have been off)."), false);
      const epsCard = V.card("Endpoints seen", "SURFACE",
        eps.length ? h("div.stack", { style: { gap: "2px" } }, eps.slice(0, 200).map(function (e) { return h("div.mono", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all" } }, e); }))
          : h("div.empty", null, "No extra endpoints discovered beyond the seed."), false);
      const passiveCard = V.card("Passive hygiene", "LEADS · not proven",
        passive.length ? h("div.stack", { style: { gap: "8px" } }, passive.map(function (p) {
          return h("div.trow", { style: { cursor: "default" } }, [
            h("div.ico", null, V.icon("info")),
            h("div.body", null, [h("div.k", null, p.title || p.bug_class || "passive"), h("div.m", null, p.url || p.evidence || "")]),
            h("div.meta", null, p3SevChip(p.severity)),
          ]);
        })) : h("div.empty", null, "No passive-hygiene leads."), false);
      const domCard = V.card("DOM-XSS leads", "STATIC · candidates",
        dom.length ? h("div.stack", { style: { gap: "8px" } }, dom.map(function (d) {
          return h("div.trow", { style: { cursor: "default" } }, [
            h("div.ico", null, V.icon("find")),
            h("div.body", null, [h("div.k", null, (d.source || "?") + " → " + (d.sink || "?")), h("div.m", null, d.evidence || "")]),
            h("div.meta", null, h("span.shield.lead", null, "LEAD")),
          ]);
        })) : h("div.empty", null, "No static DOM-XSS candidates."), false);
      const blind = h("div.legend", null, [V.icon("info"),
        "Coverage map: what was reached and probed. A quick loopback scan does not exercise auth-gated classes (access-control, SSO) or the host arsenal unless those packs were explicitly enabled — those remain blind spots for this run."]);
      V.mount(host, [tiles, blind, h("div.grid.cols-2", { style: { marginTop: "16px", alignItems: "start" } }, [stack, epsCard]),
        h("div.grid.cols-2", { style: { marginTop: "16px", alignItems: "start" } }, [passiveCard, domCard])]);
    }).catch(function () { V.mount(host, offlineEmpty()); });
  }

  // ---- 5) Timeline replay (scrub graph growth by monotonic first_seen) --------
  function p3Timeline(host, run) {
    V.getJSON(OFF("/api/worldmodel/" + encodeURIComponent(run.run_id))).then(function (wm) {
      if (wm && wm.pending) { V.mount(host, p3NoReportEmpty(run, "The timeline") || pendingEmpty(run)); return; }
      if (wm && wm.error) { V.mount(host, h("div.empty", null, [h("div.big", null, "No timeline"), h("p", null, wm.error)])); return; }
      const nodes = wm.nodes || [], edges = wm.edges || [];
      // monotonic breakpoints = sorted unique first_seen values across nodes+edges.
      const seqs = {};
      nodes.forEach(function (n) { if (n.first_seen != null) seqs[n.first_seen] = 1; });
      edges.forEach(function (e) { if (e.first_seen != null) seqs[e.first_seen] = 1; });
      const breaks = Object.keys(seqs).map(Number).sort(function (a, b) { return a - b; });
      if (!nodes.length || !breaks.length) {
        V.mount(host, h("div.empty", null, [h("div.big", null, "Nothing to replay"),
          h("p", null, "The world-model carries no timestamped nodes for this run (a run with chainable findings populates the replay).")]));
        return;
      }
      const st = { i: breaks.length - 1 };
      const graphHost = h("div#p3-tl-graph");
      const counter = h("div.muted", { style: { marginTop: "6px" } });
      const slider = h("input", { type: "range", min: "0", max: String(breaks.length - 1), value: String(st.i),
        step: "1", style: { width: "100%" },
        onInput: function (e) { st.i = parseInt(e.target.value, 10) || 0; redraw(); } });

      function redraw() {
        const cut = breaks[st.i];
        const vn = nodes.filter(function (n) { return n.first_seen == null || n.first_seen <= cut; });
        const ids = {}; vn.forEach(function (n) { ids[n.id] = 1; });
        const ve = edges.filter(function (e) { return (e.first_seen == null || e.first_seen <= cut) && ids[e.src] && ids[e.dst]; });
        // paths/chokes only when fully materialised by this cut (honest — no premature path highlight)
        const vp = (wm.paths || []).filter(function (p) { return (p.steps || []).every(function (s) { return ids[s.src] && ids[s.dst]; }); });
        const vc = (wm.chokes || []).filter(function (c) { return ids[c.src] && ids[c.dst]; });
        p3DrawGraph(V.$("#p3-tl-graph"), { nodes: vn, edges: ve, paths: vp, chokes: vc }, function (n) { p3OpenNodeDrawer(wm, n); });
        V.mount(counter, "Step " + (st.i + 1) + " of " + breaks.length + " · seq ≤ " + cut + " · " + vn.length + " nodes · " + ve.length + " edges · " + vp.length + " paths");
      }
      V.mount(host, [
        V.card("Investigation replay", "TIMELINE", h("div", null, [
          h("p.muted", { style: { margin: "0 0 12px" } }, "Scrub to replay how the attack graph grew, in the monotonic order the reasoning discovered it. Pure reconstruction — no traffic."),
          graphHost, counter,
          h("div", { style: { marginTop: "14px" } }, slider),
          h("div.row-flex", { style: { justifyContent: "space-between", marginTop: "4px" } }, [
            h("span.muted", { style: { fontSize: "var(--fs-xs)" } }, "start"),
            h("span.muted", { style: { fontSize: "var(--fs-xs)" } }, "now"),
          ]),
        ]), false),
      ]);
      redraw();
    }).catch(function () { V.mount(host, offlineEmpty()); });
  }

  // ---- shared small empties --------------------------------------------------
  function pendingEmpty(run) {
    return h("div.empty", null, [h("div.big", null, "Still running"),
      h("p", null, "This run has not produced a saved report yet. Watch it in Live, then come back."),
      h("button.btn", { style: { marginTop: "12px" }, onClick: function () { location.hash = "#/live?run=" + encodeURIComponent(run.run_id); } }, [V.icon("live"), "Open in Live"])]);
  }
  function offlineEmpty() {
    return h("div.empty", null, [h("div.big", null, "Offense engine offline"),
      h("p", null, "Could not reach the offense console read plane. Start it (vigil up) and reload.")]);
  }

  // ---- guided stub for not-yet-built screens --------------------------------
  // ---- Settings screen (owner plane: API key + model) ------------------------
  function ownerBanner(text) {
    return h("div.owner-banner", null, [V.icon("key"), h("span", null, text)]);
  }
  function settingsAct(body, okMsg, then) {
    return V.postJSON(SOV("/api/action"), body)
      .then(function (r) {
        if (r && r.error) { V.toast(r.error, true); return; }
        V.toast(okMsg); if (then) then(r);
      })
      .catch(function (e) { V.toast((e && e.message) || "Action failed — check you are on the owner plane", true); });
  }

  function renderSettings(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Settings"),
        h("span.sub", null, "The model the AI reasons with. API keys have moved to their own screen.")]),
      ownerBanner("Owner plane — every change is signed with your key on the server. The browser never holds or receives key material."),
      h("div.grid.cols-2", { style: { alignItems: "start", marginTop: "16px" } }, [
        V.card("Reasoning model", "OWNER", h("div#set-model", null, h("div.empty", null, "Loading…")), true),
        V.card("API keys", "OWNER", [
          h("div.hint", null, "Every key the system uses — Claude/other model providers, cloud credentials, integrations — with a live health check so a bad or expired key always shows as failing."),
          h("div.acts", { style: { marginTop: "12px" } },
            h("button.btn.owner", { onClick: function () { location.hash = "#/apikeys"; } }, [V.icon("key"), "Manage API keys"])),
        ], true),
      ]),
    ]);
    loadSettings();
  }

  function loadSettings() {
    V.getJSON(SOV("/api/settings")).then(drawSettings).catch(function (e) {
      var msg = (e && e.status === 401) ? "The sovereign plane needs the owner token — open the UI via `vigil up`."
        : "Settings are on the sovereign plane, which is offline. Start it with `vigil up`.";
      var box2 = V.$("#set-model"); if (box2) V.mount(box2, h("div.empty", null, msg));
    });
  }

  function drawSettings(st) {
    drawModelCard(st);
  }

  // A live-health chip for a SET secret: ok (green) / fail (red) / can't-verify (grey) / not-tested.
  function healthChip(sec) {
    if (!sec.set) return null;
    var hs = (sec.health && sec.health.status) || "unchecked";
    var reason = (sec.health && sec.health.reason) || "";
    if (hs === "ok") return h("span.pill.sm.ok", { title: reason }, [V.icon("check"), " Working"]);
    if (hs === "fail") return h("span.pill.sm.danger", { title: reason }, [V.icon("info"), " Failing"]);
    if (hs === "unknown") return h("span.pill.sm", { title: reason }, [V.icon("info"), " Can't verify"]);
    return h("span.pill.sm", { title: "Not tested yet — press Test" }, "Not tested");
  }

  // `reload` is the caller's refresh (loadApiKeys or loadSettings); keeps this card usable on either screen.
  function drawSecretCard(sec, st, reload) {
    reload = reload || loadSettings;
    var isKey = sec.name === "ANTHROPIC_API_KEY";
    var statusRow = sec.set
      ? h("div.set-status.ok", null, [V.icon("check"), h("span", null, "Set"),
          h("span.pill.sm", null, sec.backend), h("span.mono.dim", null, sec.fingerprint), healthChip(sec)])
      : h("div.set-status.off", null, [V.icon("info"),
          h("span", null, isKey
            ? "No key set — the system runs keyless (deterministic oracles only) until you add one or pick the local Claude Code model."
            : "Not set — optional until you use the feature it enables.")]);
    // an explicit failure/uncertainty line so a bad key is never silent
    var healthLine = null;
    if (sec.set && sec.health && sec.health.status === "fail") {
      healthLine = h("div.set-status.off", { style: { color: "var(--danger, #e5484d)" } },
        [V.icon("info"), h("span", null, "This key failed its last live check: " + (sec.health.reason || "rejected") + ". Re-seal a valid value.")]);
    } else if (sec.set && sec.health && sec.health.status === "unknown" && sec.health.reason) {
      healthLine = h("div.set-status.off", null, [V.icon("info"), h("span", null, sec.health.reason)]);
    }
    var input = h("input", { type: "password", autocomplete: "off", spellcheck: "false",
      placeholder: sec.set ? "Enter a new value to replace it" : (isKey ? "sk-ant-…" : "paste the key…") });
    var save = h("button.btn.owner", { onClick: function () {
        var v = (input.value || "").trim();
        if (!v) { V.toast("Paste a value first.", true); return; }
        save.disabled = true;
        settingsAct({ action: "set_secret", name: sec.name, value: v, reason: "set " + sec.name + " from API Keys" },
          (sec.label || sec.name) + " sealed on this machine.", function () { input.value = ""; reload(); refreshKeysBadge(); })
          .then(function () { save.disabled = false; });
      } }, [V.icon("key"), "Seal"]);
    // Test = a live probe. Only offered for a SET, probeable secret; a non-probeable secret has no service to check.
    var test = (sec.set && sec.probeable) ? h("button.btn", { onClick: function () {
        test.disabled = true; test.textContent = "Testing…";
        settingsAct({ action: "check_secret", name: sec.name, reason: "test " + sec.name },
          "", function (r) {
            if (r && r.status === "ok") V.toast((sec.label || sec.name) + ": working.");
            else if (r && r.status === "fail") V.toast((sec.label || sec.name) + ": FAILING — " + (r.reason || ""), true);
            else V.toast((sec.label || sec.name) + ": " + (r && r.reason || "can't verify"), true);
            reload(); refreshKeysBadge();
          }).then(function () { test.disabled = false; test.textContent = "Test"; });
      } }, "Test") : null;
    return [
      statusRow,
      healthLine,
      h("div.field", { style: { marginTop: "14px" } }, [
        h("label", null, sec.label || sec.name), input,
        h("div.hint", null, (sec.purpose ? sec.purpose + " " : "")
          + "Sealed to your OS keyring or a TPM-sealed store when available; the value never enters the spine, a log, or any response — only a fingerprint is recorded."),
      ]),
      h("div.acts", null, [save, test]),
    ];
  }

  // ---- API Keys screen (owner plane) — every secret the system uses, grouped, with LIVE health -------
  function renderApiKeys(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "API Keys"),
        h("span.sub", null, "Every key the system uses — sealed on this machine, never shown back to the browser. Press Test to check a key is live; a failing key always shows here.")]),
      ownerBanner("Owner plane — every change is signed with your key on the server. The browser never holds or receives key material."),
      h("div.acts", { style: { marginTop: "12px" } },
        h("button.btn#test-all", { onClick: function () {
          var b = V.$("#test-all"); if (b) { b.disabled = true; b.textContent = "Testing all…"; }
          settingsAct({ action: "check_secrets", reason: "test all keys" }, "", function (r) {
            var f = (r && r.failing) || []; if (f.length) V.toast(f.length + " key(s) failing: " + f.join(", "), true);
            else V.toast("All set keys checked.");
            loadApiKeys(); refreshKeysBadge();
          }).then(function () { var bb = V.$("#test-all"); if (bb) { bb.disabled = false; bb.textContent = "Test all keys"; } });
        } }, [V.icon("bolt"), "Test all keys"])),
      h("div#apikeys-body", { style: { marginTop: "8px" } }, h("div.empty", null, "Loading…")),
    ]);
    loadApiKeys();
  }

  function loadApiKeys() {
    V.getJSON(SOV("/api/settings")).then(drawApiKeys).catch(function (e) {
      var msg = (e && e.status === 401) ? "The sovereign plane needs the owner token — open the UI via `vigil up`."
        : "API keys live on the sovereign plane, which is offline. Start it with `vigil up`.";
      var box = V.$("#apikeys-body"); if (box) V.mount(box, h("div.empty", null, msg));
    });
  }

  function drawApiKeys(st) {
    var host = V.$("#apikeys-body"); if (!host) return;
    var cats = st.secret_categories || [{ id: "integration", label: "Secrets" }];
    var secrets = st.secrets || [];
    var sections = cats.map(function (cat) {
      var inCat = secrets.filter(function (s) { return (s.category || "integration") === cat.id; });
      if (!inCat.length) return null;
      return h("div", { style: { marginTop: "18px" } }, [
        h("div.screen-head", { style: { marginBottom: "6px" } }, h("h2", null, cat.label)),
        h("div.grid.cols-2", { style: { alignItems: "start" } }, inCat.map(function (sec) {
          return V.card(sec.label || sec.name, "OWNER", drawSecretCard(sec, st, loadApiKeys), true);
        })),
      ]);
    }).filter(Boolean);
    var failing = st.keys_failing || 0;
    V.mount(host, [
      failing > 0 ? h("div.set-status.off", { style: { color: "var(--danger, #e5484d)", marginBottom: "8px" } },
        [V.icon("info"), h("span", null, failing + " key" + (failing === 1 ? " is" : "s are") + " failing a live check — see the red 'Failing' cards below.")]) : null,
      sections.length ? sections : h("div.empty", null, "No secrets configured."),
    ]);
  }

  function drawModelCard(st) {
    var host = V.$("#set-model"); if (!host) return;
    var models = st.models || [];
    if (!models.length) { V.mount(host, h("div.empty", null, "No models available from the server.")); return; }
    var chosen = st.selected_model || null;
    function rows() {
      return models.map(function (m) {
        var sel = chosen === m.id;
        var isCurrent = st.selected_model === m.id;
        return h("div.choice" + (sel ? ".sel" : ""), { dataset: { model: m.id },
          onClick: function () { chosen = m.id; V.mount(list, rows()); save.disabled = false; } }, [
          h("div.cico", null, V.icon(m.keyless ? "shield" : "brain")),
          h("div", null, [
            h("div.ct", null, [m.label, isCurrent ? h("span.pill.sm.ok", { style: { marginLeft: "8px" } }, "current") : null,
              m.keyless ? h("span.pill.sm", { style: { marginLeft: "8px" } }, "no key needed") : null]),
            h("div.cd", null, m.note),
          ]),
        ]);
      });
    }
    var list = h("div.stack", null, rows());
    var save = h("button.btn.owner", { disabled: true, onClick: function () {
        if (!chosen) { V.toast("Pick a model first.", true); return; }
        save.disabled = true;
        settingsAct({ action: "set_model", model: chosen, reason: "set model from Settings" },
          "Model set.", function () { loadSettings(); });
      } }, [V.icon("check"), "Use this model"]);
    V.mount(host, [
      st.keyless ? h("div.set-status.off", null, [V.icon("info"),
        h("span", null, "Tip: models other than the local Claude Code session need an API key (set it on the left).")]) : null,
      list,
      h("div.hint", { style: { margin: "10px 2px" } }, "Controls the primary reasoning model — used when the AI reasons over your target (engagements, scans, research). Mechanical helpers (memory extraction) always use a fast model. A running engine picks up a change on the next `vigil up`."),
      h("div.acts", null, save),
    ]);
  }

  // ---- Approvals & Safety screen (owner plane) -------------------------------
  function renderSafety(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Approvals & Safety"),
        h("span.sub", null, "Everything that needs your sign-off, the kill-switch, capabilities, and the live governance feed.")]),
      ownerBanner("Owner plane — approvals, the kill-switch, and capability changes are all signed with your key on the server."),
      h("div.grid.cols-4#safety-tiles", { style: { marginTop: "16px" } }),
      h("div.grid.cols-2", { style: { alignItems: "start", marginTop: "4px" } }, [
        h("div.stack", null, [
          V.card("Waiting for your approval", "OWNER", h("div#safety-approvals", null, h("div.empty", null, "Loading…")), true),
          V.card("Capabilities", "OWNER", h("div#safety-caps", null, h("div.empty", null, "Loading…")), true),
        ]),
        h("div.stack", null, [
          V.card("Kill-switch", "OWNER", h("div#safety-kill", null, h("div.empty", null, "Loading…")), true),
          V.card("Live governance feed", "LIVE", h("div.feed#safety-feed", null, h("div.empty", null, "Connecting to the sovereign spine…")), false),
        ]),
      ]),
    ]);
    loadSafety();
  }

  function loadSafety() {
    function refresh() {
      V.getJSON(SOV("/api/snapshot")).then(drawSafety).catch(function () {
        var box = V.$("#safety-approvals");
        if (box) V.mount(box, h("div.empty", null, "The sovereign plane is offline. Start it with `vigil up`."));
      });
    }
    refresh();
    liveTimers.push(setInterval(refresh, 5000));    // cleaned up by teardownLive() on navigation
    // live spine feed (owner governance events)
    var feed = V.$("#safety-feed");
    try {
      liveES = V.sse(SOV("/api/stream"), function (ev) {
        if (!feed) return;
        var empty = feed.querySelector(".empty"); if (empty) empty.remove();
        feed.insertBefore(safetyFeedRow(ev), feed.firstChild);
        while (feed.childNodes.length > 60) feed.removeChild(feed.lastChild);
      }, function () { /* SSE error — the poll above keeps the rest live */ });
    } catch (e) { /* EventSource unavailable — non-fatal */ }
  }

  function safetyFeedRow(ev) {
    var kind = (ev && (ev.kind || ev.k)) || "event";
    var who = (ev && (ev.actor || ev.source || ev.agent)) || "";
    var seq = (ev && ev.seq != null) ? ("#" + ev.seq) : "";
    var subj = (ev && (ev.subject || (ev.payload && (ev.payload.signal || ev.payload.subject)))) || "";
    return h("div.feed-row", null, [
      h("span.pill.sm", null, kind),
      h("span.fr-t", null, [who ? h("b", null, who) : null, subj ? (" · " + subj) : ""]),
      h("span.fr-seq.mono.dim", null, seq),
    ]);
  }

  function drawSafety(snap) {
    var ks = snap.kill_switch || "released";
    var pend = snap.pending_approvals || [];
    var caps = snap.capabilities || {};
    // tiles
    var tiles = V.$("#safety-tiles");
    if (tiles) V.mount(tiles, [
      V.tile("Kill-switch", ks === "engaged" ? "ENGAGED" : "Released", ks === "engaged" ? "mesh halted" : "mesh live", ks === "engaged" ? "danger" : "ok"),
      V.tile("Waiting", String(pend.length), pend.length ? "need your sign-off" : "all clear", pend.length ? "warn" : "ok"),
      V.tile("Spine head", snap.head_seq != null ? ("#" + snap.head_seq) : "—", "records", null),
      V.tile("Budget today", budgetLabel(snap.budget_today), "spend", null),
    ]);
    // approvals
    var ab = V.$("#safety-approvals");
    if (ab) {
      if (!pend.length) V.mount(ab, h("div.empty", null, "Nothing is waiting. New offensive steps that need sign-off will appear here."));
      else V.mount(ab, h("div.stack", null, pend.map(safetyApprovalCard)));
    }
    // capabilities
    var cb = V.$("#safety-caps");
    if (cb) V.mount(cb, [
      capRow("gesture", caps.gesture),
      capRow("voice", caps.voice),
    ]);
    // kill-switch
    var kb = V.$("#safety-kill");
    if (kb) V.mount(kb, [
      h("div.set-status." + (ks === "engaged" ? "off" : "ok"), null, [
        V.icon(ks === "engaged" ? "info" : "check"),
        h("span", null, ks === "engaged"
          ? "The kill-switch is ENGAGED — the agent mesh is halted (perception and memory-read stay alive)."
          : "The kill-switch is released — the agent mesh runs normally."),
      ]),
      h("div.acts", { style: { marginTop: "12px" } }, ks === "engaged"
        ? h("button.btn.owner", { onClick: function () {
            settingsAct({ action: "release", reason: "release from Safety" }, "Kill-switch released.", loadSafety); } }, [V.icon("play"), "Release"])
        : h("button.btn.danger", { onClick: function () {
            settingsAct({ action: "kill", reason: "engage from Safety" }, "Kill-switch engaged — mesh halted.", loadSafety); } }, [V.icon("x"), "Engage kill-switch"])),
      h("div.hint", { style: { marginTop: "10px" } }, "Halting is always safe and immediate. Releasing requires your signed request."),
    ]);
  }

  function budgetLabel(b) {
    if (!b || typeof b !== "object") return "—";
    if (b.spent != null && b.cap != null) return b.spent + " / " + b.cap;
    if (b.spent != null) return String(b.spent);
    var ks = Object.keys(b); return ks.length ? String(b[ks[0]]) : "—";
  }

  function safetyApprovalCard(a) {
    return h("div.approval", null, [
      h("div.ah", null, [V.icon("key"), h("span.t", null, (a.kind || "action") + " · seq " + a.seq),
        a.tier ? h("span.pill.sm", null, "tier " + a.tier) : null]),
      h("div.why", null, (a.agent ? a.agent + " → " : "") + (a.subject || "requires owner sign-off")),
      h("div.acts", null, [
        h("button.btn.owner", { onClick: function () {
          settingsAct({ action: "approve", seq: a.seq, reason: "approve from Safety" }, "Approved.", loadSafety); } }, [V.icon("check"), "Approve"]),
        h("button.btn.danger", { onClick: function () {
          settingsAct({ action: "deny", seq: a.seq, reason: "deny from Safety" }, "Denied.", loadSafety); } }, [V.icon("x"), "Deny"]),
      ]),
    ]);
  }

  function capRow(name, state) {
    var on = state === "enabled";
    var label = name.charAt(0).toUpperCase() + name.slice(1);
    return h("div.cap-row", null, [
      h("div.cap-l", null, [h("b", null, label),
        h("span.st.st-" + (on ? "confirmed" : "idle"), null, [h("span.dot"), on ? "enabled" : "disabled"])]),
      on
        ? h("button.btn.sm.danger", { onClick: function () {
            settingsAct({ action: "disable_" + name, reason: "disable from Safety" }, label + " disabled.", loadSafety); } }, "Disable")
        : h("button.btn.sm.owner", { onClick: function () {
            settingsAct({ action: "enable_" + name, reason: "enable from Safety" }, label + " enabled.", loadSafety); } }, "Enable"),
    ]);
  }

  // ---- Defense (AEGIS) screen ------------------------------------------------
  // Honesty rules baked in (see the manual): in DEFENSE a CONFIRMED verdict is an ATTACK (danger, NOT
  // the offense green "proven=good"); "clear" is NOT proof of safety; the deployment secret is privacy
  // pseudonymisation, NOT request auth; canary / prompt-injection detection is the in-process SDK path,
  // not this reverse proxy. Every value is live from /offense/api/aegis/* — no placeholder data.
  function defGenSecret() {
    try {
      var a = new Uint8Array(24); (window.crypto || window.msCrypto).getRandomValues(a);
      return Array.prototype.map.call(a, function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    } catch (e) { return ""; }
  }
  function defField(label, node, hint) {
    return h("div.field", null, [h("label", null, label), node, hint ? h("div.hint", null, hint) : null]);
  }

  function renderDefense(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Defense (AEGIS)"),
        h("span.sub", null, "Put VIGIL in front of an app you run and watch it prove AI attacks in real time.")]),
      h("div.legend", null, [V.icon("shield"),
        h("span", null, "A CONFIRMED verdict here is a PROVEN attack on your app (an oracle fired). A “lead” is a suspicion. “Clear” means nothing was proven — it is NOT proof of safety.")]),
      h("div.grid.cols-4#def-tiles", { style: { marginTop: "16px" } }),
      h("div.grid.cols-2", { style: { alignItems: "start", marginTop: "4px" } }, [
        h("div.stack", null, [
          V.card("Set up your defense", "DEFENSE", h("div#def-setup", null, h("div.empty", null, "Loading…")), false),
          V.card("Who is attacking (actor beliefs)", "DEFENSE", h("div#def-actors", null, h("div.empty", null, "Loading…")), false),
        ]),
        V.card("Live verdicts", "LIVE", h("div.feed#def-feed", null, h("div.empty", null, "Connecting to the verdict stream…")), false),
      ]),
    ]);
    loadDefense();
  }

  function loadDefense() {
    function refresh() {
      V.getJSON(OFF("/api/aegis/status")).then(defDrawStatus).catch(function () {
        var b = V.$("#def-setup");
        if (b) V.mount(b, h("div.empty", null, "The offense engine is offline. Start it with `vigil up`."));
      });
    }
    refresh();
    liveTimers.push(setInterval(refresh, 4000));
    var feed = V.$("#def-feed");
    try {
      liveES = V.sse(OFF("/api/aegis/verdicts"), function (v) {
        if (!feed) return;
        var empty = feed.querySelector(".empty"); if (empty) empty.remove();
        feed.insertBefore(defVerdictRow(v), feed.firstChild);
        while (feed.childNodes.length > 80) feed.removeChild(feed.lastChild);
      }, function () { /* no gateway yet / stream ended — the poll keeps status live */ });
    } catch (e) { /* EventSource unavailable — non-fatal */ }
  }

  function defDrawStatus(st) {
    var running = !!st.running;
    var eff = st.effective_mode || null;
    var req = st.requested_mode || "observe";
    var gw = st.gateway || {};
    var actors = st.actors || [];
    var tiles = V.$("#def-tiles");
    if (tiles) V.mount(tiles, [
      V.tile("Gateway", running ? "RUNNING" : "Stopped", running ? (gw.bind || "") : "not started", running ? "ok" : null),
      V.tile("Mode", running ? (eff === "enforce" ? "ENFORCE" : "Observe") : "—",
        running && req === "enforce" && eff !== "enforce" ? "downgraded (no entitlement)" : (eff === "enforce" ? "blocking proven attacks" : "watch-only"),
        eff === "enforce" ? "warn" : null),
      V.tile("Upstream", running ? "protected" : "—", running ? (gw.upstream || "") : "point me at your app", null),
      V.tile("Actors seen", String(st.actor_count || 0), "with a belief", actors.length ? "warn" : null),
    ]);
    var setup = V.$("#def-setup");
    if (setup) { if (running) V.mount(setup, defRunningPanel(gw, eff, req)); else V.mount(setup, defSetupForm()); }
    var ab = V.$("#def-actors");
    if (ab) {
      if (!actors.length) V.mount(ab, h("div.empty", null, running ? "No actors yet — drive some traffic through the gateway." : "Start the gateway to build per-actor beliefs."));
      else V.mount(ab, h("div.stack", null, actors.slice(0, 24).map(defActorRow)));
    }
  }

  function defRunningPanel(gw, eff, req) {
    return [
      h("div.set-status.ok", null, [V.icon("check"),
        h("span", null, "Gateway running — " + (gw.bind || "") + " → " + (gw.upstream || "") + " · mode " + (eff || req))]),
      req === "enforce" && eff !== "enforce"
        ? h("div.set-status.off", null, [V.icon("info"), h("span", null, "You requested ENFORCE but it downgraded to observe (the AEGIS_RESPOND entitlement isn’t available here) — nothing is being blocked.")])
        : null,
      h("div.acts", { style: { marginTop: "12px" } },
        h("button.btn.danger", { onClick: function () {
          V.postJSON(OFF("/api/aegis/stop"), {}).then(function () { V.toast("Gateway stopped."); loadDefense(); })
            .catch(function (e) { V.toast((e && e.message) || "Could not stop the gateway", true); });
        } }, [V.icon("x"), "Stop gateway"])),
      h("div.hint", { style: { marginTop: "10px" } }, "Watch proven attacks in the live verdicts stream. To run this on your real edge, use the production command shown when you started it (bind your routable interface there, never here)."),
    ];
  }

  function defSetupForm() {
    var upstream = h("input", { type: "url", placeholder: "http://127.0.0.1:3000" });
    var host = h("input", { type: "text", value: "127.0.0.1" });
    var port = h("input", { type: "text", value: "8080" });
    var mode = h("select", null, [h("option", { value: "observe" }, "Observe — watch only (default, blocks nothing)"),
      h("option", { value: "enforce" }, "Enforce — block PROVEN attacks (needs entitlement)")]);
    var honey = h("input", { type: "text", placeholder: "/__aegis_hp__/… (optional, comma-separated)" });
    var secretIn = h("input", { type: "text", placeholder: "click Generate", spellcheck: "false", autocomplete: "off" });
    var genBtn = h("button.btn.sm", { onClick: function () { secretIn.value = defGenSecret(); } }, "Generate");
    var slug = h("input", { type: "text", value: "aegis-gateway" });
    var start = h("button.btn.primary", { onClick: function () {
      var host0 = (host.value || "127.0.0.1").trim();
      if (host0 !== "127.0.0.1" && host0 !== "localhost" && host0 !== "::1" &&
          !confirm("Binding " + host0 + " exposes a real data plane to the network. Only do this on an interface you intend to expose. Continue?")) return;
      var body = { upstream: (upstream.value || "").trim(), host: host0, port: (port.value || "8080").trim(),
        mode: mode.value, deployment_secret: (secretIn.value || "").trim(), slug: (slug.value || "").trim(),
        honeypot_paths: (honey.value || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean) };
      start.disabled = true;
      V.postJSON(OFF("/api/aegis/setup"), body).then(function (r) {
        start.disabled = false;
        if (r && r.error) { V.toast(r.error, true); return; }
        V.toast("Defense gateway started.");
        if (r && r.production_command) defShowProdCommand(r.production_command, r.warn_public);
        loadDefense();
      }).catch(function (e) { start.disabled = false; V.toast((e && e.message) || "Could not start", true); });
    } }, [V.icon("shield"), "Start defense"]);
    return [
      defField("Your app’s URL (upstream)", upstream, "The gateway sits in front of this and forwards to it. Required."),
      h("div.grid.cols-2", null, [defField("Bind host", host, "Default 127.0.0.1. A routable bind is warned."), defField("Port", port, "Default 8080.")]),
      defField("Mode", mode, "Observe watches only. Enforce blocks proven attacks and needs the AEGIS_RESPOND entitlement (otherwise it downgrades to observe)."),
      defField("Honeypot paths", honey, "Decoy paths — any fetch proves automated access. Optional."),
      defField("Deployment secret", h("div.row-flex", null, [secretIn, genBtn]),
        "A per-deployment secret AEGIS uses internally (identifier pseudonymisation on the SDK ingest path) — NOT a request password/auth. Required. Note: your live dashboard below shows the real client source of attackers, which is what you need to act."),
      defField("Gateway name (slug)", slug, "Identity for the kill-switch + audit trail."),
      h("div.legend", { style: { marginTop: "4px" } }, [V.icon("info"),
        h("span", null, "This reverse proxy detects honeypot hits, automated access, and injection/SSRF/XXE leads over real traffic. Canary / prompt-injection detection for an LLM app is the in-process SDK path (aegis detect / the Aegis SDK), not this proxy.")]),
      h("div.acts", null, start),
    ];
  }

  function defShowProdCommand(cmd, warnPublic) {
    openDrawer("Run on your edge", [
      h("div.dsection", null, [
        h("p", null, "Your local gateway is running for testing. To protect your real deployment, run this on your own routable edge (bind your public interface there):"),
        h("pre.code", null, cmd),
        h("button.btn.sm", { onClick: function () { copyText(cmd); } }, "Copy command"),
        warnPublic ? h("div.set-status.off", { style: { marginTop: "12px" } }, [V.icon("info"), h("span", null, "You bound a routable interface locally — make sure that is intended.")]) : null,
      ]),
    ]);
  }

  function defVerdictRow(v) {
    var decision = (v && v.decision) || "clear";
    var cls = decision === "confirmed" ? "danger" : (decision === "lead" ? "warn" : "muted");
    var label = decision === "confirmed" ? "ATTACK PROVEN" : (decision === "lead" ? "lead" : "clear");
    var ac = (v && v.attack_class) || "";
    var conf = (v && typeof v.confidence === "number") ? (" · " + Math.round(v.confidence * 100) + "%") : "";
    var act = (v && v.action && v.action !== "observe" && v.action !== "allow") ? (" · " + v.action) : "";
    var row = h("div.feed-row.verdict-" + cls, null, [
      h("span.vbadge." + cls, null, label),
      h("span.fr-t", null, [ac ? h("b", null, ac) : "activity", conf, act]),
      (v && v.certificate) ? h("span.pill.sm", null, "cert") : null,
    ]);
    if (v && v.certificate) {
      row.style.cursor = "pointer";
      row.addEventListener("click", function () {
        openDrawer("Attack certificate", [h("div.dsection", null, [
          h("div.kv", null, [
            h("div.k", null, "attack"), h("div.v", null, ac || "—"),
            h("div.k", null, "confirmed by"), h("div.v", null, (v.certificate.confirmed_by) || "oracle"),
            h("div.k", null, "cert id"), h("div.v.mono", null, (v.certificate.cert_id) || "—"),
            h("div.k", null, "confidence"), h("div.v", null, conf.replace(" · ", "") || "—"),
          ]),
          h("div.legend", { style: { marginTop: "12px" } }, "This verdict is backed by a deterministic oracle that re-fires offline over the evidence. The matched-span detail is kept server-side and not streamed to the browser."),
        ])]);
      });
    }
    return row;
  }

  function defActorRow(a) {
    var mean = (a && typeof a.mean === "number") ? a.mean : 0;
    var pct = Math.max(0, Math.min(100, Math.round(mean * 100)));
    var act = (a && a.action) ? a.action : null;
    // the id is AEGIS's actor key — the client source (an IP), prefixed "session:" internally. Show the
    // source plainly (this is the defender's own view of who is hitting their app).
    var src = String((a && a.id) || "?").replace(/^session:/, "");
    return h("div.actor-row", null, [
      h("div.actor-h", null, [h("span.mono.dim", { title: "client source" }, src),
        act ? h("span.pill.sm.warn", null, act) : null]),
      h("div.bar", null, h("div.bar-fill" + (pct >= 66 ? ".hi" : (pct >= 40 ? ".mid" : "")), { style: { width: pct + "%" } })),
      h("div.actor-meta.dim", null, "belief " + pct + "% · " + ((a && a.n) || 0) + " observations"),
    ]);
  }

  // ---- Fixes screen (remediation) --------------------------------------------
  // HONEST: shows the run's oracle-confirmed FIXABLE findings (with their real remediation guidance) +
  // the gated ladder any auto-fix follows. Live auto-application (clone/build/open-PR) is a separate
  // sovereign-gated capability that must be provisioned + authorized — nothing is cloned/built/opened here.
  function renderFixes(screen) {
    var S = { runs: [], run: null };
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Fixes"),
        h("span.sub", null, "What to fix after discovery, and the gated process an auto-fix follows.")]),
      h("div#fx-body", null, h("div.empty", null, "Loading runs…")),
    ]);
    var want = (hashQuery().run) || "";
    V.getJSON(OFF("/api/runs")).then(function (d) {
      S.runs = (d && d.runs) || [];
      S.run = S.runs.find(function (r) { return r.run_id === want; }) || S.runs[0] || null;
      drawFixes(S);
    }).catch(function () {
      var b = V.$("#fx-body");
      if (b) V.mount(b, h("div.empty", null, "The offense engine is offline. Start it with `vigil up`."));
    });
  }

  function drawFixes(S) {
    var body = V.$("#fx-body"); if (!body) return;
    if (!S.runs.length) {
      V.mount(body, h("div.empty", null, [h("div.big", null, "No runs yet"),
        h("p", null, "Run an assessment first — its confirmed findings become fixable here."),
        h("button.btn.primary", { style: { marginTop: "12px" }, onClick: function () { location.hash = "#/assess"; } }, "New Assessment")]));
      return;
    }
    var picker = h("div.field", { style: { maxWidth: "560px", marginBottom: "0" } }, [
      h("label", null, "Run"),
      h("select", { onChange: function (e) {
          S.run = S.runs.find(function (r) { return r.run_id === e.target.value; }) || null;
          history.replaceState(null, "", "#/fixes?run=" + encodeURIComponent(S.run ? S.run.run_id : ""));
          drawFixes(S);
        } }, S.runs.map(function (r) {
        return h("option", { value: r.run_id, selected: S.run && r.run_id === S.run.run_id },
          (r.mode || "url") + " · " + (r.target || r.slug || r.run_id) + " · " + r.status);
      })),
    ]);
    V.mount(body, [picker, h("div#fx-view", { style: { marginTop: "16px" } }, h("div.empty", null, "Loading fix plan…"))]);
    if (!S.run) return;
    V.getJSON(OFF("/api/remediate/" + encodeURIComponent(S.run.run_id))).then(drawFixPlan)
      .catch(function () { var v = V.$("#fx-view"); if (v) V.mount(v, h("div.empty", null, "Could not load the fix plan for this run.")); });
    // impact-ranked fix points (choke-points) from the world-model — best-effort, non-fatal
    V.getJSON(OFF("/api/worldmodel/" + encodeURIComponent(S.run.run_id))).then(function (wm) {
      var host = V.$("#fx-chokes"); if (!host) return;
      var ch = (wm && wm.chokes) || [];
      if (!ch.length) { V.mount(host, h("div.empty", null, "No single-lever choke-points for this run.")); return; }
      V.mount(host, h("div.stack", null, ch.slice(0, 6).map(function (c) {
        return h("div.kv", null, [
          h("div.k", null, (c.kind || "edge")), h("div.v", null, (c.src || "?") + " → " + (c.dst || "?")),
          h("div.k", null, "severs"), h("div.v", null, (c.disconnects != null ? c.disconnects + " path(s)" : "—") + (c.is_bridge ? " · bridge" : "")),
        ]);
      })));
    }).catch(function () { /* worldmodel optional */ });
  }

  function drawFixPlan(plan) {
    var view = V.$("#fx-view"); if (!view) return;
    if (plan.pending) {
      V.mount(view, h("div.empty", null, "This run has no saved report yet" + (plan.status ? " (" + plan.status + ")" : "") + " — fixes appear once it finishes."));
      return;
    }
    var fixable = plan.fixable || [];
    var nodes = [
      plan.apply_fixes_requested ? h("div.legend", null, [V.icon("check"), h("span", null, "You requested fixes for this run at launch. Here is the plan — nothing is applied without the gated steps below.")]) : null,
      h("div.grid.cols-4", { style: { marginBottom: "4px" } }, [
        V.tile("Fixable", String(plan.fixable_count || 0), "oracle-confirmed", (plan.fixable_count ? "warn" : "ok")),
        V.tile("Unproven", String(plan.lead_count || 0), "leads — not auto-fixable", null),
        V.tile("Live auto-fix", "OFF", "provision + authorize", null),
        V.tile("Verify", "oracle-silent", "proof required", null),
      ]),
      V.card("The gated fix ladder", "PROCESS", fixLadder(plan.ladder || []), false),
      h("div.legend", null, [V.icon("shield"), h("span", null, plan.note || "")]),
    ];
    if (!fixable.length) {
      nodes.push(h("div.empty", null, "No oracle-confirmed findings to fix in this run. Only proven FACTs are eligible — unproven leads are never auto-fixed."));
    } else {
      nodes.push(V.card("Fixable findings", "CONFIRMED", h("div.stack", null, fixable.map(fixFindingCard)), false));
    }
    nodes.push(V.card("Highest-impact fix points", "IMPACT", h("div#fx-chokes", null, h("div.empty", null, "Loading…")), false));
    V.mount(view, nodes);
  }

  function fixLadder(stages) {
    return h("div.ladder.scroll-x", null, stages.map(function (s, i) {
      return h("div.ladder-stage", null, [
        h("div.ls-h", null, [h("span.ls-n", null, String(i + 1)), h("b", null, s.stage),
          s.tier && s.tier !== "—" ? h("span.pill.sm", null, s.tier) : null]),
        h("div.ls-w.dim", null, s.what),
      ]);
    }));
  }

  function sevClass(sev) {
    var s = String(sev || "").toLowerCase();
    if (s === "critical" || s === "high") return "danger";
    if (s === "medium" || s === "moderate") return "warn";
    return "";
  }
  function fixFindingCard(f) {
    return h("div.fix-card", null, [
      h("div.fix-h", null, [
        h("span.vbadge." + (sevClass(f.severity) || "muted"), null, (f.severity || "?").toUpperCase()),
        h("b", null, f.title || f.bug_class || "finding"),
        f.bug_class ? h("span.pill.sm", null, f.bug_class) : null,
      ]),
      f.location ? h("div.mono.dim", { style: { fontSize: "var(--fs-xs)", margin: "4px 0" } }, f.location) : null,
      h("div.fix-rem", null, [h("span.label", null, "Remediation"), h("p", null, f.remediation)]),
      f.confirmed_by ? h("div.dim", { style: { fontSize: "var(--fs-xs)", marginTop: "6px" } }, "confirmed by " + f.confirmed_by) : null,
    ]);
  }

  // ---- Brain screen (Memory / Benchmark / Catalog / Intel / Planner) ---------
  // Every tab is REAL data from an existing read endpoint; honest empty states throughout — no fabricated
  // priors/scores. Reasoning is presented as advisory-only (it never promotes a finding — the oracle does).
  var BRAIN_TABS = [
    { id: "memory", label: "Memory" }, { id: "benchmark", label: "Benchmark" },
    { id: "catalog", label: "Catalog" }, { id: "intel", label: "Intel" }, { id: "planner", label: "Planner" },
  ];
  function renderBrain(screen) {
    var B = { tab: (hashQuery().tab) || "memory", runs: [], run: null, catalogQ: "" };
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Brain"),
        h("span.sub", null, "What the system has learned, how well it scores, and the capabilities it can bring to bear.")]),
      h("div.segmented#brain-tabs", { style: { flexWrap: "wrap" } }),
      h("div#brain-view", { style: { marginTop: "16px" } }),
    ]);
    function drawTabs() {
      V.mount(V.$("#brain-tabs"), BRAIN_TABS.map(function (t) {
        return h("button" + (B.tab === t.id ? ".on" : ""), { onClick: function () {
          B.tab = t.id; history.replaceState(null, "", "#/brain?tab=" + t.id); drawTabs(); drawView(); } }, t.label);
      }));
    }
    function drawView() {
      var v = V.$("#brain-view"); if (!v) return;
      V.mount(v, h("div.empty", null, "Loading…"));
      if (B.tab === "memory") brainMemory(v);
      else if (B.tab === "benchmark") brainBenchmark(v);
      else if (B.tab === "catalog") brainCatalog(v, B);
      else brainRunScoped(v, B, B.tab);   // intel / planner (per-engagement)
    }
    drawTabs(); drawView();
  }

  function brainMemory(v) {
    V.getJSON(OFF("/api/memory")).then(function (m) {
      var s = m.summary || {}; var priors = m.priors || [];
      V.mount(v, [
        h("div.grid.cols-4", null, [
          V.tile("Engagements", String(s.engagements || 0), "learned from", null),
          V.tile("Findings", String(s.findings || 0), "remembered", null),
          V.tile("Priors", String(s.priors || 0), "per-class success", null),
          V.tile("Dead ends", String(s.dead_ends || 0), "won't re-walk", null),
        ]),
        V.card("Learned priors", "MEMORY", priors.length
          ? h("div.stack", null, priors.slice(0, 40).map(function (p) {
              // real prior shape: {archetype, bug_class, surface, successes, attempts, mean, lower_bound}
              var label = [p.bug_class, p.archetype, p.surface].filter(Boolean).join(" · ") || "prior";
              var mean = (typeof p.mean === "number") ? Math.round(p.mean * 100) + "%" : "—";
              var lb = (typeof p.lower_bound === "number") ? " (lcb " + Math.round(p.lower_bound * 100) + "%)" : "";
              var n = (p.attempts != null) ? (" · " + (p.successes != null ? p.successes : "?") + "/" + p.attempts) : "";
              return h("div.kv", null, [h("div.k", null, label),
                h("div.v", null, "success " + mean + lb + n)]); }))
          : h("div.empty", null, "No priors learned yet — the system learns a per-archetype/bug-class success rate as you run assessments; it never fabricates a score."), false),
      ]);
    }).catch(function () { V.mount(v, offlineEmpty()); });
  }

  function brainBenchmark(v) {
    V.getJSON(OFF("/api/benchmark")).then(function (b) {
      var base = b.baseline || {}; var scores = base.scores || {};
      var rows = [];
      Object.keys(scores).forEach(function (appName) {
        var engines = scores[appName] || {};
        Object.keys(engines).forEach(function (eng) {
          var sc = engines[eng] || {};
          rows.push(h("div.kv", null, [h("div.k", null, appName + " · " + eng),
            h("div.v", null, "tp " + (sc.tp != null ? sc.tp : "—") + " · fp " + (sc.fp != null ? sc.fp : "—") + " · fn " + (sc.fn != null ? sc.fn : "—"))]));
        });
      });
      V.mount(v, [
        V.card("Benchmark baseline", "CALIBRATION", [
          h("p.dim", { style: { marginBottom: "10px" } }, base.label || "the in-process benchmark corpus"),
          rows.length ? h("div.stack", null, rows) : h("div.empty", null, "No benchmark scores recorded yet."),
        ], false),
        h("div.legend", null, [V.icon("info"), h("span", null, "tp = planted bugs found · fp = safe controls wrongly flagged · fn = missed bugs. The corpus includes safe controls a precise engine must leave alone.")]),
      ]);
    }).catch(function () { V.mount(v, offlineEmpty()); });
  }

  function brainCatalog(v, b) {
    V.getJSON(OFF("/api/capabilities")).then(function (c) {
      var caps = c.capabilities || [];
      var list = h("div.stack#cap-list");
      function drawCaps() {
        var q = (b.catalogQ || "").toLowerCase();
        var shown = caps.filter(function (x) { return !q || (String(x.label) + x.id + x.purpose).toLowerCase().indexOf(q) >= 0; });
        V.mount(list, shown.length ? shown.map(function (x) {
          return h("div.fix-card", null, [
            h("div.fix-h", null, [h("b", null, x.label || x.id), x.tier ? h("span.pill.sm", null, x.tier) : null]),
            h("div.dim", { style: { fontSize: "var(--fs-sm)", marginTop: "4px" } }, x.purpose || ""),
          ]);
        }) : h("div.empty", null, "No capability matches that filter."));
      }
      var input = h("input", { type: "text", placeholder: "Filter capabilities…", value: b.catalogQ || "",
        onInput: function (e) { b.catalogQ = e.target.value; drawCaps(); } });
      V.mount(v, [
        h("div.field", { style: { maxWidth: "480px" } }, [h("label", null, "Capability catalog"), input]),
        list,
        h("div.legend", { style: { marginTop: "12px" } }, [V.icon("shield"), h("span", null, c.note || "Capabilities map to already-gated engage flags.")]),
        h("div.legend", null, [V.icon("brain"), h("span", null, "Reasoning (critics, learning, reflection) is advisory only — it re-ranks and defers, but never promotes a finding. Only a fired oracle confirms.")]),
      ]);
      drawCaps();
    }).catch(function () { V.mount(v, offlineEmpty()); });
  }

  function brainRunScoped(v, b, tab) {
    var ep = tab === "intel" ? "/api/intel/" : "/api/planner/";
    V.getJSON(OFF("/api/runs")).then(function (d) {
      b.runs = (d && d.runs) || [];
      if (!b.run || !b.runs.find(function (r) { return r.run_id === b.run.run_id; })) b.run = b.runs[0] || null;
      var picker = b.runs.length ? h("div.field", { style: { maxWidth: "560px" } }, [
        h("label", null, "Engagement"),
        h("select", { onChange: function (e) { b.run = b.runs.find(function (r) { return r.run_id === e.target.value; }); brainRunScoped(v, b, tab); } },
          b.runs.map(function (r) { return h("option", { value: r.run_id, selected: b.run && r.run_id === b.run.run_id }, (r.mode || "url") + " · " + (r.target || r.slug || r.run_id)); })),
      ]) : null;
      var slot = h("div#brain-rs", { style: { marginTop: "12px" } }, h("div.empty", null, b.runs.length ? "Loading…" : ("No engagements yet — " + tab + " is per-engagement.")));
      V.mount(v, [picker, slot]);
      if (!b.run) return;
      var slug = b.run.slug || b.run.run_id;
      V.getJSON(OFF(ep + encodeURIComponent(slug))).then(function (data) {
        var host = V.$("#brain-rs"); if (!host) return;
        var note = data.note || (data.present === false ? (tab + " has no data for this engagement yet") : "");
        V.mount(host, [
          note ? h("div.legend", null, [V.icon("info"), h("span", null, note)]) : null,
          h("pre.code.scroll-x", null, JSON.stringify(data, null, 2)),
        ]);
      }).catch(function () { var host = V.$("#brain-rs"); if (host) V.mount(host, h("div.empty", null, "Could not load " + tab + ".")); });
    }).catch(function () { V.mount(v, offlineEmpty()); });
  }

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
    if (id === "findings") { renderFindings(screen); return; }
    if (id === "settings") { renderSettings(screen); return; }
    if (id === "apikeys") { renderApiKeys(screen); return; }
    if (id === "safety") { renderSafety(screen); return; }
    if (id === "defense") { renderDefense(screen); return; }
    if (id === "fixes") { renderFixes(screen); return; }
    if (id === "brain") { renderBrain(screen); return; }
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
    refreshKeysBadge();           // surface any failing API key in the top bar from first paint
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
