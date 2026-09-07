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

  const app = V.store({ plane: "all", nav: [], counts: { agents: 0, tools: 0, findings: 0 }, live: "idle", waiting: 0, killed: false,
    engagement: "", engagementName: "" });

  // ---- the ACTIVE ENGAGEMENT: the job the operator is working on right now ----
  // Every screen lists that job's runs and nothing else, so starting a new job leaves a clean desk
  // without deleting anything. This is PRESENTATION, exactly like the human name a job carries: it
  // scopes what is LISTED, and changes nothing about what is signed, gated, or adjudicated. An empty
  // scope means "all engagements" — byte-identical to the behaviour before scoping existed — so no
  // past job is ever unreachable. Persisted, so it survives a refresh and a restart of the console.
  const ENGAGEMENT_KEY = "vigil.engagement";             // the machine identity (slug) — the scope itself
  const ENGAGEMENT_NAME_KEY = "vigil.engagement.name";   // its human name — for the top-bar chip only

  function activeEngagement() { return app.get().engagement || ""; }
  // What to CALL the active job: its human name if we know one, else its machine identity (which is
  // always honest — it is what the run itself recorded).
  function engagementName() { return app.get().engagementName || activeEngagement(); }

  // Switch (or clear) the scope. This is the ONLY writer, so the store, localStorage and the chip can
  // never disagree. `name` is optional: omit it and a re-scope to the SAME job keeps the name we
  // already have (a caller that knows only the slug must not blank it).
  function setEngagement(slug, name) {
    const next = String(slug || "");
    const s = app.get();
    const nm = !next ? "" : (name == null ? (s.engagement === next ? (s.engagementName || "") : "") : String(name));
    if (s.engagement === next && s.engagementName === nm) return;
    app.set({ engagement: next, engagementName: nm });
    try {
      if (!next) { localStorage.removeItem(ENGAGEMENT_KEY); localStorage.removeItem(ENGAGEMENT_NAME_KEY); }
      else {
        localStorage.setItem(ENGAGEMENT_KEY, next);
        if (nm) localStorage.setItem(ENGAGEMENT_NAME_KEY, nm); else localStorage.removeItem(ENGAGEMENT_NAME_KEY);
      }
    } catch (e) { /* storage disabled (private mode): the scope still holds for this session */ }
    refreshTopbar();
  }
  // A better name for the job ALREADY in scope, learned from a list that carries labels. It never
  // changes WHICH job is active — only what the chip calls it.
  function noteEngagementName(slug, name) {
    const nm = String(name || "");
    if (!nm || !slug || slug !== activeEngagement() || nm === app.get().engagementName) return;
    setEngagement(slug, nm);
  }

  // The runs endpoint, scoped. `?slug=` is a FILTER the server applies against the engagement each run
  // RECORDED IN ITS OWN meta.json: a caller can only ever SELECT among runs that already say they
  // belong to that job — it can never assert one into it.
  function runsURL() {
    const slug = activeEngagement();
    return OFF("/api/runs" + (slug ? ("?slug=" + encodeURIComponent(slug)) : ""));
  }
  // Read the run list out of that response. The server has already filtered; the identical comparison
  // is made here against each run's OWN recorded slug, so a console talking to a backend that does not
  // know the parameter still shows exactly what its chip claims. Narrowing only — this can no more
  // re-home a run than the server filter can.
  function runsOf(d) {
    const list = (d && d.runs) || [];
    const slug = activeEngagement();
    if (!slug) return list;
    const mine = list.filter(function (r) { return r && r.slug === slug; });
    if (mine.length) noteEngagementName(slug, mine[0].engagement_label);
    return mine;
  }

  // ---- honest empty states for a SCOPED screen (never a bare blank panel) ----
  // A clean desk and a broken screen look identical unless the screen says which it is. So: name the
  // scope, say why it is empty, and always offer the way back out to every engagement — an operator
  // who thinks their work was deleted stops trusting the tool.
  function newAssessBtn() {
    return h("button.btn.primary", { onClick: function () { location.hash = "#/assess"; } }, [V.icon("bolt"), "New Assessment"]);
  }
  function widenBtn() {
    return h("button.btn", { onClick: function () { setEngagement(""); route(); } }, [V.icon("book"), "Show all engagements"]);
  }
  function scopedEmpty(noun, why, extra) {
    return h("div.empty", null, [
      h("div.big", null, "No " + noun + " yet in this engagement"),
      h("p", null, (why || "Nothing has been recorded under this job yet.")
        + " You are looking at " + engagementName() + " only — every other job is still on disk, just out of scope."),
      h("div.row-flex", { style: { gap: "8px", marginTop: "16px", flexWrap: "wrap", justifyContent: "center" } },
        (extra || []).concat([widenBtn()])),
    ]);
  }
  // A deep link (a bookmark, a link from the library or a chat) can name a run belonging to a DIFFERENT
  // job than the one in scope. Say so, rather than silently showing a neighbour's run in its place.
  function otherEngagementNote(runId) {
    return h("div.legend", { style: { marginBottom: "12px" } }, [V.icon("info"),
      h("span", null, "The run you opened (" + runId + ") is not part of " + engagementName() + ", so it is not listed here."),
      h("button.btn.sm", { style: { marginLeft: "auto" }, onClick: function () { setEngagement(""); route(); } }, "Show all engagements")]);
  }

  // -- navigation model (every capability has a home; P1 marks not-yet-built) --
  const NAV = [
    { group: "DO", items: [
      { id: "home", label: "Home", icon: "home", ready: true },
      { id: "assess", label: "New Assessment", icon: "assess", ready: true },
      { id: "chat", label: "Chat", icon: "brain", ready: true },
      { id: "terminal", label: "Terminal", icon: "bolt", ready: true },
      { id: "live", label: "Live", icon: "live", ready: true },
      { id: "strix", label: "Strix Control", icon: "bolt", ready: true },
      { id: "findings", label: "Findings", icon: "find", ready: true },
      { id: "proof", label: "Proof Studio", icon: "shield", ready: true },
      { id: "report", label: "Report", icon: "book", ready: true },
      { id: "fixes", label: "Fixes", icon: "fixes", ready: true },
      { id: "defense", label: "Defense (AEGIS)", icon: "shield", ready: true },
      { id: "replay", label: "Replay Proof", icon: "bolt", ready: true },
    ]},
    { group: "MANAGE", items: [
      { id: "library", label: "Engagement Library", icon: "book", ready: true },
      { id: "sessions", label: "Sessions", icon: "book", ready: true },
      { id: "activity", label: "Activity", icon: "live", ready: true },
      { id: "safety", label: "Approvals & Safety", icon: "key", owner: true, perm: "approve_a2", ready: true },
      { id: "charter", label: "Charter & Attestation", icon: "key", owner: true, perm: "manage_users", ready: true },
      { id: "apikeys", label: "API Keys", icon: "key", owner: true, perm: "secrets", ready: true },
      { id: "tools", label: "Tools", icon: "bolt", ready: true },
      { id: "brain", label: "Brain", icon: "brain", ready: true },
      { id: "mcp", label: "MCP Servers", icon: "bolt", ready: true },
      { id: "system", label: "System & Services", icon: "gear", ready: true },
      { id: "durability", label: "Durability", icon: "shield", owner: true, perm: "secrets", ready: true },
      { id: "ceremonies", label: "Ceremonies", icon: "key", owner: true, perm: "config_nonsecret", ready: true },
      { id: "budgets", label: "Token Budgets", icon: "bolt", ready: true },
      { id: "compliance", label: "Compliance", icon: "shield", ready: true },
      { id: "assurance", label: "Assurance", icon: "find", ready: true },
      { id: "settings", label: "Settings", icon: "gear", owner: true, perm: "config_nonsecret", ready: true },
      { id: "users", label: "Users & Roles", icon: "key", owner: true, perm: "manage_users", ready: true },
      { id: "governance", label: "Governance", icon: "shield", ready: true },
    ]},
    { group: "LEARN", items: [
      { id: "trust", label: "Trust Center", icon: "shield", ready: true },
      { id: "posture", label: "Proof of Posture", icon: "check", ready: true },
      { id: "manual", label: "Manual", icon: "book", ready: true },
      { id: "knowledge", label: "Knowledge Engine", icon: "brain", ready: true },
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
    // WHICH JOB every screen is showing. Always visible, always the truth about the scope; clicking it
    // goes to the library to switch job or widen back to all. It shrinks and ellipsises (see
    // components.css) so it can never push the safety state or the primary action off the bar.
    const scopeLabel = s.engagement ? engagementName() : "All engagements";
    // A VIEW FILTER, not a running job. It reads "Viewing: <job>" (never "active"/"live") so a scoped
    // view is never mistaken for an engagement that is running, and it carries an inline × to clear the
    // filter from anywhere — the operator's complaint was a scoped job that looked "active" and could not
    // be cleared from the top bar. The × is a SIBLING button next to the chip (never nested inside it —
    // a button-in-a-button is invalid HTML and mis-announces to assistive tech).
    const scopeChip = h("button.scope-chip" + (s.engagement ? ".on" : ""), {
      title: s.engagement
        ? ("A VIEW FILTER — every screen is showing " + scopeLabel + " only. This is not a running job; "
          + "click to switch job, or use × to show all engagements.")
        : "Every screen is showing all engagements — click to pick a job to view",
      onClick: function () { location.hash = "#/library"; },
    }, [V.icon("book"), h("span.txt", null, s.engagement ? ("Viewing: " + scopeLabel) : scopeLabel)]);
    const scope = s.engagement
      ? h("span.scope-wrap", null, [scopeChip, h("button.scope-clear", {
          title: "Clear this view filter — show all engagements again",
          "aria-label": "Clear view filter, show all engagements",
          onClick: function (e) { e.preventDefault(); e.stopPropagation(); setEngagement(""); route(); },
        }, "×")])
      : scopeChip;
    // The kill-switch state is REAL (the mesh is halted while it is engaged) — but as a bare pill it was
    // an inert readout the operator could click forever with nothing happening. Make it carry its own
    // action: it now takes you to Safety, which is where the signed Release control lives.
    const live = s.killed
      ? h("button.pill.danger.pill-act", { title: "The kill-switch is ENGAGED — the agent mesh is halted. Open Safety to release it.",
          onClick: function () { location.hash = "#/safety"; } }, "Kill-switch")
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
    // offenseChip() is the "start the offense side from the screen" control (see its own comment). It
    // MUST be in this list: it renders itself as `#offense-chip`, and paintOffenseChip() only *replaces*
    // an existing `#offense-chip` — so without a seat here on first render there is nothing for the state
    // poll to update, and the button never appears. It was written and then left out of this array,
    // which is exactly why the screen carried no way to start the offense side without a terminal.
    return h("div#topbar", null, [seg, scope, cmdk, h("div.spacer"), counts, live, offenseChip(), keysBadge, safety, userChip(), themeBtn, cta]);
  }

  // ---- current-user chip (Claim 6) -------------------------------------------
  // Names WHO you are signed in as (username · role). Clicking opens a small account panel to switch user
  // or sign out. Hidden until a principal is known (whoami resolves) so it never flashes a wrong identity.
  function userChip() {
    const p = V.principal();
    if (!p || !p.authenticated) return h("span#user-chip", { style: { display: "none" } }, "");
    return h("button.user-chip#user-chip", {
      title: "Signed in as " + p.username + " (" + p.role + ") — click to switch user or sign out",
      onClick: openUserMenu }, [V.icon("key"), h("span.txt", null, p.username + " · " + p.role)]);
  }
  function openUserMenu() {
    const p = V.principal() || {};
    openDrawer("Account", h("div", null, [
      h("div.hint", null, "Signed in as " + (p.username || "?") + " (" + (p.role || "?") + ")."),
      p.permissions ? h("div.legend", { style: { marginTop: "8px" } },
        [V.icon("info"), h("span", null, "Permissions: " + p.permissions.join(", "))]) : null,
      h("div.acts", { style: { marginTop: "12px", display: "flex", gap: "8px", flexWrap: "wrap" } }, [
        h("button.btn", { onClick: function () { closeDrawer(); renderLoginGate(V.$("#screen")); } },
          [V.icon("key"), "Switch user"]),
        h("button.btn.danger", { onClick: logout }, [V.icon("x"), "Sign out"]),
      ]),
    ]));
  }
  function logout() {
    V.setSessionToken(""); V.setPrincipal(null); closeDrawer();
    loadPrincipal(function (pp, ok) {
      refreshTopbar(); renderNav();
      if (ok && pp && !pp.authenticated) { renderLoginGate(V.$("#screen")); }
      else { location.hash = "#/home"; route(); }
    });
  }

  // ---- login gate + principal load (Claim 6) ---------------------------------
  // Whether the sovereign has the OIDC RP turned ON — learned from the (token-optional) /api/whoami, which
  // is a bootstrap route so this reaches the login gate BEFORE a session exists. Drives whether the login
  // gate offers the SSO button (the OIDC routes are unregistered when this is false, so a button that always
  // showed would dead-end). W17-2 (#536).
  var _oidcEnabled = false;
  function loadPrincipal(cb) {
    V.getJSON(SOV("/api/whoami"))
      .then(function (p) { _oidcEnabled = !!(p && p.oidc); V.setPrincipal(p); if (cb) cb(p, true); })
      .catch(function () { V.setPrincipal(null); if (cb) cb(null, false); });   // plane offline → don't gate
  }

  // SSO: hand the browser to the sovereign's /api/oidc/login, which 302s to the operator's IdP. A TOP-LEVEL
  // navigation (not a fetch) is required so the IdP can drive its own login page and set the session-binding
  // cookie; the IdP returns the browser to redirect_uri (configured to THIS app's origin), where boot()'s
  // completeOidcReturn() finishes the exchange and adopts the minted bearer. Both /api/oidc/login and the
  // callback are proxy-bootstrap routes (reachable without a bearer through `vigil up`).
  function ssoSignIn() { window.location.assign(SOV("/api/oidc/login")); }

  // If this page load is the IdP's return leg (redirect_uri carries ?code&state), finish the OIDC login:
  // the callback (sent WITH same-origin credentials so the session-binding cookie rides along) verifies the
  // id_token + owner-signed mapping and mints a fresh session bearer, which we adopt into the per-user
  // session. code/state are single-use + sensitive, so they are stripped from the address bar immediately.
  // Calls cb(true) on a completed SSO login, cb(false) otherwise (incl. "this was not an SSO return").
  function completeOidcReturn(cb) {
    var qs;
    try { qs = new URLSearchParams(location.search || ""); } catch (e) { cb(false); return; }
    var code = qs.get("code"), state = qs.get("state");
    if (!code || !state) { cb(false); return; }
    try { history.replaceState(null, "", location.pathname + location.hash); } catch (e) {}
    V.getJSON(SOV("/api/oidc/callback") + "?code=" + encodeURIComponent(code) + "&state=" + encodeURIComponent(state))
      .then(function (r) {
        if (r && r.authenticated && r.bearer) {
          V.setSessionToken(r.bearer); V.setPrincipal(r);
          V.toast("Signed in as " + r.username + " (" + r.role + ") via SSO.");
          cb(true);
        } else { V.toast("SSO sign-in did not complete.", true); cb(false); }
      })
      .catch(function (e) { V.toast((e && (e.data && e.data.error || e.message)) || "SSO sign-in failed.", true); cb(false); });
  }
  // ---- WebAuthn / passkey (Slice 1c-iii — production owner login) -------------
  // Feature-detected + graceful: on a browser without WebAuthn the affordances hide. The LIVE ceremony needs
  // a real authenticator + (in production) TLS; the server side is fully unit-tested with synthetic vectors.
  function _bufToB64url(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function _hasWebAuthn() { return !!(window.PublicKeyCredential && navigator.credentials); }
  function passkeySignIn() {
    if (!_hasWebAuthn()) { V.toast("This browser has no passkey support.", true); return; }
    V.postJSON(SOV("/api/login/challenge"), {}).then(function (r) {
      return navigator.credentials.get({ publicKey: {
        challenge: new TextEncoder().encode(r.challenge),
        rpId: location.hostname, userVerification: "preferred", timeout: 60000 } });
    }).then(function (cred) {
      if (!cred) return null;
      return V.postJSON(SOV("/api/webauthn/assert"), {
        credential_id: _bufToB64url(cred.rawId),
        authenticator_data: _bufToB64url(cred.response.authenticatorData),
        client_data_json: _bufToB64url(cred.response.clientDataJSON),
        signature: _bufToB64url(cred.response.signature) });
    }).then(function (r) {
      if (r && r.authenticated) {
        V.setPrincipal(r); V.toast("Signed in with your passkey.");
        refreshTopbar(); renderNav(); location.hash = "#/home"; route();
      } else if (r) { V.toast("Passkey sign-in was not accepted.", true); }
    }).catch(function (e) { V.toast("Passkey sign-in failed: " + ((e && e.message) || e), true); });
  }
  function passkeyEnroll() {
    if (!_hasWebAuthn()) { V.toast("This browser has no passkey support.", true); return; }
    V.postJSON(SOV("/api/login/challenge"), {}).then(function (r) {
      return navigator.credentials.create({ publicKey: {
        challenge: new TextEncoder().encode(r.challenge),
        rp: { name: "VIGIL", id: location.hostname },
        user: { id: new TextEncoder().encode("owner"), name: "owner", displayName: "VIGIL owner" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 },
                           { type: "public-key", alg: -8 }],
        authenticatorSelection: { userVerification: "preferred" }, timeout: 60000 } });
    }).then(function (cred) {
      if (!cred) return;
      var spki = cred.response.getPublicKey && cred.response.getPublicKey();
      var alg = cred.response.getPublicKeyAlgorithm && cred.response.getPublicKeyAlgorithm();
      if (!spki || !alg) { V.toast("This authenticator did not expose a public key (WebAuthn L2 needed).", true); return; }
      settingsAct({ action: "enroll_webauthn", credential_id: _bufToB64url(cred.rawId),
        cose_alg: alg, public_key_spki_b64: _bufToB64url(spki), reason: "enroll owner passkey" },
        "Passkey enrolled — the owner can now sign in with it (production posture).", function () {});
    }).catch(function (e) { V.toast("Passkey enrolment failed: " + ((e && e.message) || e), true); });
  }
  function renderLoginGate(screen) {
    if (!screen) return;
    const input = h("input.input", { type: "password", placeholder: "Paste your VIGIL bearer token",
      autocomplete: "off", style: { minWidth: "320px" } });
    // OPTIONAL TOTP second-factor code (W17-1). A bearer login is NOT gated by an enrolment — leave this
    // blank and the token alone signs you in — but if your account has TOTP enrolled you MAY present the
    // current code and the server will validate it (a wrong code is refused).
    const totpInput = h("input.input", { type: "text", inputMode: "numeric", autocomplete: "one-time-code",
      pattern: "[0-9]*", maxLength: "8", placeholder: "TOTP code (optional)",
      style: { maxWidth: "180px" } });
    function submit() {
      const tok = (input.value || "").trim();
      if (!tok) { V.toast("Enter your bearer token.", true); return; }
      const body = { token: tok };
      const code = (totpInput.value || "").trim();
      if (code) { body.totp = code; }                    // only sent when the user actually typed one
      V.postJSON(SOV("/api/login"), body)
        .then(function (r) {
          if (!r || !r.authenticated) { V.toast("That token was not accepted.", true); return; }
          V.setSessionToken(tok); V.setPrincipal(r);
          V.toast("Signed in as " + r.username + " (" + r.role + ").");
          refreshTopbar(); renderNav(); location.hash = "#/home"; route();
        })
        .catch(function (e) { V.toast((e && e.message) || "Login failed.", true); });
    }
    input.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); submit(); } });
    totpInput.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); submit(); } });
    // SSO card — shown ONLY when the sovereign reports the OIDC RP is enabled (whoami.oidc). The button is a
    // top-level navigation to the sovereign's /api/oidc/login (a bootstrap route reachable without a bearer
    // through `vigil up`); the IdP returns to this app, where completeOidcReturn() adopts the minted bearer.
    var ssoCard = _oidcEnabled ? V.card("Single sign-on (SSO)", null, [
      h("div.hint", null, "Sign in with your organisation's identity provider. Your VIGIL role still comes "
        + "from an owner-signed account — SSO establishes who you are, never what you may do."),
      h("div.acts", { style: { marginTop: "12px", display: "flex", gap: "8px", flexWrap: "wrap" } },
        [h("button.btn.primary", { onClick: ssoSignIn }, [V.icon("key"), "Sign in with SSO"])]),
    ]) : null;
    V.mount(screen, h("div.wrap", null, [
      h("div.screen-head", null, [h("h1", null, "Sign in to VIGIL"),
        h("span.sub", null, "Multi-user access control (Claim 6). The owner uses the token printed by `vigil up`.")]),
      V.card("Bearer sign-in", null, [
        h("div.hint", null, "Enter the bearer token the owner issued you (Users & Roles → Create account). "
          + "Your role decides what you can do; every action is still gated and owner-signed on the server. "
          + "If your account has a TOTP second factor enrolled, you may add the current code (optional)."),
        h("div.acts", { style: { marginTop: "12px", display: "flex", gap: "8px", flexWrap: "wrap" } },
          [input, totpInput, h("button.btn.primary", { onClick: submit }, [V.icon("key"), "Sign in"])]),
      ]),
      _hasWebAuthn() ? V.card("Passkey", null, [
        h("div.hint", null, "Sign in with a registered passkey (WebAuthn) — the production owner login: "
          + "phishing-resistant and cryptographically bound to this site. Enrol one first from "
          + "Users & Roles → Owner session (needs TLS in production)."),
        h("div.acts", { style: { marginTop: "12px", display: "flex", gap: "8px", flexWrap: "wrap" } },
          [h("button.btn.primary", { onClick: passkeySignIn }, [V.icon("shield"), "Sign in with a passkey"])]),
      ]) : null,
      ssoCard,
    ]));
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

  // ==== the offense side: whether it is running, and the ONE named action that starts it ============
  // This whole interface is served by `vigil up`'s reverse proxy, so the page still loads with the two
  // offense backends (console 8787, gated api 8799) dead — and that proxy is the process that already
  // owns their lifecycle. It is therefore the one place that can honestly offer to start them, over two
  // routes of its OWN (they reach neither backend):
  //
  //     GET  /__vigil/plane/status         ->  { running, planes:{…}, starting, can_start }
  //     POST /__vigil/plane/offense/start  ->  { result: "started" | "already_running" | "starting" }
  //                                     a failure is a non-2xx carrying { error: "<reason>" }
  //
  // THE CALLER NAMES NO COMMAND. The POST body is empty: "start the offense plane" is a fixed, named
  // action, and the proxy rebuilds the SAME argv it uses at boot from its own configuration. No path, no
  // argument, no port, no command ever travels in the request — anything else would be remote code
  // execution wearing a button. Both routes are token-gated and loopback/private-bound exactly like every
  // other call on this page (same X-SIGIL-Token; the proxy refuses a public bind), and starting is
  // single-flight on the server, so a second click can never spawn a second copy. None of this touches
  // gating, approvals, the kill-switch, scope, or what counts as a fact: it starts a process the operator
  // was otherwise going to start by hand.
  const OFFENSE_STATUS_URL = "/__vigil/plane/status";
  const OFFENSE_START_URL = "/__vigil/plane/offense/start";
  const OFFENSE_STOP_URL = "/__vigil/plane/offense/stop";
  const OFFENSE_START_WAIT_MS = 30000;   // how long we watch for it to actually answer before saying so
  const OFFENSE_STOP_WAIT_MS = 15000;    // …and how long we watch for it to go quiet after a stop

  // known:    have we observed the offense side at all yet? Before the first probe we show NOTHING —
  //           an indicator that guesses is worse than no indicator.
  // up:       it answered.
  // canStart: this proxy serves the start route. A 404 means an older `vigil up`, and then the honest
  //           thing is to show the command, not a button that cannot work.
  // busy:     a start we asked for is in flight.
  const OFFENSE = { known: false, up: false, starting: false, canStart: true, busy: false, stopping: false };

  function offenseHeaders() {
    const hh = { "X-Requested-With": "vigil-ui" };
    const t = V.token(); if (t) hh["X-SIGIL-Token"] = t;
    return hh;
  }

  // One status read. Never throws, and never invents: if the proxy itself does not answer we keep the
  // last observation rather than claiming either state.
  function probeOffense() {
    return fetch(OFFENSE_STATUS_URL, { headers: offenseHeaders(), credentials: "same-origin", cache: "no-store" })
      .then(function (r) {
        // 404/501: an older proxy with no plane routes. 401/403: a proxy that has them but will not let
        // THIS page drive them (no token embedded, a rebinding host). Either way the honest answer is the
        // same — we cannot offer a button — and the indicator falls back to whether the offense console
        // itself answers. Treating an auth refusal as an unknown would leave the chip silent forever.
        if (r.status === 404 || r.status === 501 || r.status === 401 || r.status === 403) {
          OFFENSE.canStart = false;
          return probeOffenseConsole();               // fall back to the console's own reachability
        }
        if (!r.ok) throw new Error("offense status " + r.status);
        return r.json().then(function (d) { applyOffenseStatus(d || {}); });
      })
      .catch(function () { /* proxy unreachable (stale page / host going down) — assert nothing new */ })
      .then(function () { paintOffenseChip(); });
  }

  // Read the proxy's own report. Tolerant about which key it uses for "is it running", strict about
  // never reading a truthy "your request was accepted" as "the offense side is up".
  function applyOffenseStatus(d) {
    const running = d.running === true || d.up === true
      || (d.console === true && d.api === true)
      || String(d.state || "").toLowerCase() === "running";
    if (d.can_start === false) OFFENSE.canStart = false;
    OFFENSE.starting = d.starting === true;
    noteOffenseUp(running);
  }

  // Fallback signal when the proxy has no plane routes: the offense console's own status endpoint. A 502/
  // 503/504 is the proxy telling us the backend is not there; anything else means it answered.
  function probeOffenseConsole() {
    return fetch(OFF("/api/status"), { headers: offenseHeaders(), credentials: "same-origin", cache: "no-store" })
      .then(function (r) { noteOffenseUp(r.status !== 502 && r.status !== 503 && r.status !== 504); },
        function () { noteOffenseUp(false); });
  }

  function noteOffenseUp(up) {
    const was = OFFENSE.known ? OFFENSE.up : null;
    OFFENSE.known = true;
    OFFENSE.up = !!up;
    // The System screen tells the operator the offense side is offline; the moment it is not, that screen
    // is stale. Re-render exactly that screen, and only when it is the one showing the offline message.
    if (was === false && OFFENSE.up && current() === "system" && V.$("#system-offline")) route();
  }

  // ---- the top-bar indicator -------------------------------------------------
  // Quiet when it is up (a dot and a word). A real, clearly clickable button when it is DOWN, because
  // that is the moment the operator needs a way out that is not a terminal.
  function offenseChip() {
    if (!OFFENSE.known) {                       // nothing observed yet: occupy no space, claim nothing
      return h("span.offense-chip#offense-chip", { style: { display: "none" } }, "");
    }
    if (OFFENSE.stopping) {
      return h("button.offense-chip.working#offense-chip", { disabled: true,
        title: "Stopping the offense console and API." },
        [h("span.dot"), h("span.txt", null, "Stopping offense…")]);
    }
    if (OFFENSE.busy || (OFFENSE.starting && !OFFENSE.up)) {
      return h("button.offense-chip.working#offense-chip", { disabled: true,
        title: "Starting the offense console and API — this takes a few seconds." },
        [h("span.dot"), h("span.txt", null, "Starting offense…")]);
    }
    if (OFFENSE.up) {
      // Up: a quiet indicator, PLUS the STOP that pairs with the start button — so the offense side can
      // be brought DOWN from the screen the same way it is brought up. The proxy serving this page owns
      // the two backends' lifecycle and tears exactly them down (never the cockpit, never itself).
      // `canStart` gates stop too: a proxy that cannot start the plane cannot stop it, so it shows no
      // button rather than one that cannot work.
      const upKids = [h("span.dot"), h("span.txt", null, "Offense up")];
      if (OFFENSE.canStart) {
        upKids.push(h("button.oc-stop", {
          title: "Stop the offense console and API. Findings, reports and proof stay on disk; you can "
            + "start the offense side again here or with `vigil up`.",
          onClick: function (e) { e.preventDefault(); e.stopPropagation(); confirmStopOffense(); },
        }, "Stop"));
      }
      return h("span.offense-chip.up#offense-chip",
        { title: "The offense console and API are answering." }, upKids);
    }
    if (!OFFENSE.canStart) {                    // honest: no button, because this proxy cannot start it
      return h("span.offense-chip.down#offense-chip",
        { title: "The offense side is not answering. Start it in a terminal with `vigil up`, then reload." },
        [h("span.dot"), h("span.txt", null, "Offense down")]);
    }
    return h("button.offense-chip.down.action#offense-chip", {
      title: "The offense side is not answering. Click to start it — the proxy serving this page re-runs "
        + "the same command it uses at boot. You can also run `vigil up` in a terminal.",
      onClick: function () { startOffensePlane(); },
    }, [V.icon("play"), h("span.txt", null, "Start offense side")]);
  }
  function paintOffenseChip() {
    const el = V.$("#offense-chip"); if (!el) return;
    el.parentNode.replaceChild(offenseChip(), el);
  }

  // ---- the named action ------------------------------------------------------
  // Single-flight and idempotent: a second click (or a click while a start is already running) JOINS the
  // start in flight instead of posting again, and starting something already up is a no-op that says so.
  // Resolves to { outcome: "started" | "already_running" | "failed", detail }. Never rejects.
  let offenseStarting = null;
  function startOffensePlane() {
    if (offenseStarting) return offenseStarting;
    OFFENSE.busy = true; paintOffenseChip();
    offenseStarting = V.postJSON(OFFENSE_START_URL, {})   // empty body: no command, no path, no port
      .then(readStartClaim, readStartFailure)
      .then(function (res) {
        OFFENSE.busy = false; offenseStarting = null;
        V.toast(res.detail, res.outcome === "failed");
        paintOffenseChip();
        scheduleOffensePoll();
        return res;
      });
    return offenseStarting;
  }

  function readStartClaim(r) {
    r = r || {};
    if (r.error) return { outcome: "failed", detail: "Could not start the offense side: " + String(r.error) };
    const claim = String(r.result || r.state || (r.already_running ? "already_running" : (r.started ? "started" : ""))).toLowerCase();
    if (claim === "already_running" || claim === "running") {
      return confirmOffenseUp("already_running", "The offense side was already running.");
    }
    // "started" / "starting" / any other 2xx: the POST is a CLAIM, the status route is the OBSERVATION.
    // Report only what can be SEEN, so a child that dies on its first breath is never called a success.
    return confirmOffenseUp("started", "The offense side is up.");
  }

  function readStartFailure(e) {
    const st = e && e.status;
    if (st === 409) {   // the proxy's own single-flight: a start is already in progress. Watch it.
      return confirmOffenseUp("started", "A start was already in progress, and the offense side is up.");
    }
    if (st === 404 || st === 501) {
      OFFENSE.canStart = false;
      return { outcome: "failed",
        detail: "This build of `vigil up` has no start action — start the offense side in a terminal with `vigil up`." };
    }
    if (st === 401 || st === 403) {
      return { outcome: "failed",
        detail: "Not authorized to start the offense side. Reload the page to pick up a current session token." };
    }
    return { outcome: "failed",
      detail: "Could not start the offense side: " + ((e && e.message) || "the proxy did not answer") + "." };
  }

  // Wait for it to actually answer, then report what was observed — including the unhappy case, where a
  // timeout is a FAILURE with somewhere to look, not a quiet success.
  function confirmOffenseUp(outcome, detail) {
    return waitForOffense(OFFENSE_START_WAIT_MS).then(function (up) {
      if (up) return { outcome: outcome, detail: detail };
      return { outcome: "failed",
        detail: "The start was accepted, but the offense side is still not answering after "
          + Math.round(OFFENSE_START_WAIT_MS / 1000) + "s. Look at the log `vigil up` writes for it "
          + "(ui/logs/offense-console.log under your VIGIL live directory), or run `vigil up` in a "
          + "terminal to see the error." };
    });
  }
  function waitForOffense(ms) {
    const deadline = Date.now() + ms;
    function attempt() {
      return probeOffense().then(function () {
        if (OFFENSE.up) return true;
        if (Date.now() >= deadline) return false;
        return new Promise(function (res) { setTimeout(res, 1200); }).then(attempt);
      });
    }
    return attempt();
  }

  // ---- the named STOP action -------------------------------------------------
  // Stopping the offense side shuts down the console + api that serve findings/reports; disruptive enough
  // to confirm first, reversible enough (start again here or `vigil up`) not to need more than that.
  function confirmStopOffense() {
    if (!window.confirm("Stop the offense side?\n\nThe offense console and API will be shut down. Your "
      + "findings, reports and proof stay on disk — start the offense side again from here (or with "
      + "`vigil up`) whenever you want. Any assessment still running will be stopped.")) return;
    stopOffensePlane();
  }
  // Single-flight and idempotent, exactly like the start action. Resolves to
  // { outcome: "stopped" | "already_stopped" | "failed", detail }. Never rejects.
  let offenseStopping = null;
  function stopOffensePlane() {
    if (offenseStopping) return offenseStopping;
    OFFENSE.stopping = true; paintOffenseChip();
    offenseStopping = V.postJSON(OFFENSE_STOP_URL, {})     // empty body: no command, no path, no port
      .then(readStopClaim, readStopFailure)
      .then(function (res) {
        OFFENSE.stopping = false; offenseStopping = null;
        V.toast(res.detail, res.outcome === "failed");
        paintOffenseChip();
        scheduleOffensePoll();
        return res;
      });
    return offenseStopping;
  }
  function readStopClaim(r) {
    r = r || {};
    if (r.error) return { outcome: "failed", detail: "Could not stop the offense side: " + String(r.error) };
    const claim = String(r.result || "").toLowerCase();
    if (claim === "already_stopped") {
      return confirmOffenseDown("already_stopped", "The offense side was already stopped.");
    }
    // "stopped" / any other 2xx: the POST is a CLAIM, the status route is the OBSERVATION — report only
    // what can be SEEN, so a backend that refused to die is never called a clean stop.
    return confirmOffenseDown("stopped", "The offense side was stopped.");
  }
  function readStopFailure(e) {
    const st = e && e.status;
    if (st === 404 || st === 501) {
      return { outcome: "failed",
        detail: "This build of `vigil up` has no stop action — stop the offense side with `vigil down`." };
    }
    if (st === 401 || st === 403) {
      return { outcome: "failed",
        detail: "Not authorized to stop the offense side. Reload the page to pick up a current session token." };
    }
    if (st === 503) {
      return { outcome: "failed",
        detail: "This page's proxy has no plane control — stop the offense side with `vigil down`." };
    }
    return { outcome: "failed",
      detail: "Could not stop the offense side: " + ((e && e.message) || "the proxy did not answer") + "." };
  }
  function confirmOffenseDown(outcome, detail) {
    return waitForOffenseDown(OFFENSE_STOP_WAIT_MS).then(function (down) {
      if (down) return { outcome: outcome, detail: detail };
      return { outcome: "failed",
        detail: "The stop was accepted, but the offense side is still answering after "
          + Math.round(OFFENSE_STOP_WAIT_MS / 1000) + "s. Stop it with `vigil down` in a terminal." };
    });
  }
  function waitForOffenseDown(ms) {
    const deadline = Date.now() + ms;
    function attempt() {
      return probeOffense().then(function () {
        if (!OFFENSE.up) return true;
        if (Date.now() >= deadline) return false;
        return new Promise(function (res) { setTimeout(res, 1000); }).then(attempt);
      });
    }
    return attempt();
  }

  // A start button with in-place feedback, for a screen (the top-bar chip is its own control). Same
  // single-flight action, same three honest outcomes.
  function offenseStartButton(label) {
    const btn = h("button.btn.primary", { onClick: function () {
      if (btn.disabled) return;
      btn.disabled = true;
      V.mount(btn, [V.icon("live"), "Starting…"]);
      startOffensePlane().then(function (res) {
        btn.disabled = false;
        if (res.outcome === "failed") { V.mount(btn, [V.icon("play"), label]); return; }  // the toast carries why
        V.mount(btn, [V.icon("check"), "Offense side is up"]);
        if (current() === "system" && V.$("#system-offline")) route();   // the report can load now
      });
    } }, [V.icon("play"), label]);
    return btn;
  }

  // ---- polling: often enough to notice, rarely enough not to be a nuisance ----
  // Attentive while it is down or coming up (that is when the operator is waiting on it), quiet once it
  // is healthy, and completely silent while the tab is hidden.
  let offenseTimer = null;
  function offensePollDelay() {
    if (OFFENSE.busy || OFFENSE.starting || OFFENSE.stopping) return 2000;
    if (!OFFENSE.known) return 4000;
    return OFFENSE.up ? 20000 : 6000;
  }
  function scheduleOffensePoll() {
    if (offenseTimer) { clearTimeout(offenseTimer); offenseTimer = null; }
    if (document.hidden) return;                       // a hidden tab polls nothing at all
    offenseTimer = setTimeout(function () {
      offenseTimer = null;
      probeOffense().then(scheduleOffensePoll, scheduleOffensePoll);
    }, offensePollDelay());
  }
  function watchOffensePlane() {
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        if (offenseTimer) { clearTimeout(offenseTimer); offenseTimer = null; }
        return;
      }
      probeOffense().then(scheduleOffensePoll, scheduleOffensePoll);   // catch up the moment it is looked at
    });
    probeOffense().then(scheduleOffensePoll, scheduleOffensePoll);
  }

  // ---- new-build notice ------------------------------------------------------
  // If `vigil up` republishes the bundle while this tab is open, the page keeps running the OLD app.js
  // (the browser already parsed it). Notice a new build id from /__vigil/plane/version and tell the
  // operator to reload — the ETag/no-cache + `?v=<build>` cache-busting then serve the fresh bundle. This
  // is exactly the "I updated it but still see the old UI" gap. Checked on load + whenever the tab is
  // looked at again; announced once, never nagged.
  const OFFENSE_VERSION_URL = "/__vigil/plane/version";
  let _buildNotified = false;
  function checkBuildVersion() {
    const mine = (document.body.dataset && document.body.dataset.build) || "";
    if (!mine || mine === "__VIGIL_BUILD__" || _buildNotified) return;   // unsubstituted placeholder → skip
    fetch(OFFENSE_VERSION_URL, { headers: offenseHeaders(), credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.build || d.build === mine) return;
        _buildNotified = true;
        V.toast("A new VIGIL build is available — reload the page to pick it up.", false);
      })
      .catch(function () { /* proxy busy / down — try again next time the tab is looked at */ });
  }
  function watchBuildVersion() {
    document.addEventListener("visibilitychange", function () { if (!document.hidden) checkBuildVersion(); });
    setTimeout(checkBuildVersion, 3000);   // one check shortly after load
  }

  function renderNav() {
    const nav = V.$("#nav"); if (!nav) return;
    const plane = app.get().plane;
    const prin = V.principal();
    const visible = function (it) {
      // (1) plane filter (unchanged)
      var planeOk = (plane === "all") ? true
        : (it.id === "defense") ? (plane === "defense")
        : (["assess", "live", "findings", "fixes"].indexOf(it.id) >= 0) ? (plane === "offense")
        : true; // home + manage always
      if (!planeOk) return false;
      // (2) RBAC gate (Claim 6): once a principal is KNOWN, an owner-flagged screen is shown only if the
      // role carries its permission (default owner-only). Before whoami resolves (prin == null) we don't
      // restrict — the SERVER is the enforcement of record (every mutation is re-checked and 403s); this
      // is the UX layer that stops a teammate seeing owner screens they cannot use.
      if (prin && it.owner && !V.can(it.perm || "manage_users")) return false;
      return true;
    };
    V.mount(nav, NAV.map(function (grp) {
      return [h("div.nav-group.label", null, grp.group),
        grp.items.filter(visible).map(function (it) { return navItem(it); })];
    }));
  }
  function navItem(it) {
    const active = current() === it.id;
    const attn = it.id === "safety" && app.get().waiting > 0;
    const badge = attn ? h("span.badge-count.owner", null, String(app.get().waiting)) : null;
    function go() { location.hash = "#/" + it.id; }
    return h("div.nav-item" + (it.owner ? ".owner" : "") + (active ? ".active" : "") + (attn ? ".needs-approval" : ""),
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
    document.body.appendChild(h("div#drawer", { "aria-hidden": "true" }, [
      h("div.dz#drawer-dz", { role: "separator", "aria-label": "Resize panel (drag)" }),
      h("div.dh", null, [
        h("h2#drawer-title", null, "Detail"),
        h("button.iconbtn#drawer-dock", { "aria-label": "Dock the panel to the bottom or the side", title: "Dock to bottom / side", onClick: cycleDrawerDock }, V.icon("dock-bottom")),
        h("button.iconbtn#drawer-max", { "aria-label": "Maximize or restore the panel", title: "Maximize / restore", onClick: toggleDrawerMax }, V.icon("maximize")),
        h("button.iconbtn", { "aria-label": "Close detail panel", onClick: closeDrawer }, V.icon("x")),
      ]),
      h("div.db#drawer-body"),
    ]));
    installDrawerControls();
    renderNav();
  }

  // ---- drawer ----------------------------------------------------------------
  function openDrawer(title, body) {
    V.$("#drawer-title").textContent = title || "Detail";
    V.mount(V.$("#drawer-body"), body);
    applyDrawerState();                       // honour the operator's remembered dock/size each open
    const d = V.$("#drawer"); d.classList.add("open"); d.setAttribute("aria-hidden", "false");
  }
  function closeDrawer() { const d = V.$("#drawer"); d.classList.remove("open"); d.setAttribute("aria-hidden", "true"); }

  // ---- drawer dock / resize / maximize (the "expand the activity box" controls) --------------------
  // A single detail/activity panel the whole app opens things into. The operator can drag it wider (or,
  // when docked to the bottom, taller), flip it between a right dock and a bottom dock, or maximize it to
  // fill the viewport — and the choice + size PERSIST across opens and reloads (localStorage, per browser).
  const DRAWER_KEY = "vigil.drawer";
  function drawerState() {
    try { return JSON.parse(localStorage.getItem(DRAWER_KEY) || "{}") || {}; } catch (e) { return {}; }
  }
  function saveDrawerState(s) { try { localStorage.setItem(DRAWER_KEY, JSON.stringify(s || {})); } catch (e) { /* private mode / blocked — the panel just won't remember */ } }
  function applyDrawerState() {
    const el = V.$("#drawer"); if (!el) return;
    const s = drawerState();
    const bottom = s.dock === "bottom";
    el.classList.toggle("dock-bottom", bottom);
    el.classList.toggle("max", !!s.max);
    // inline size wins over the CSS default; cleared when maximized so .max fills the viewport
    el.style.width = ""; el.style.height = "";
    if (!s.max) {
      if (bottom) { if (s.height) el.style.height = s.height + "px"; }
      else { if (s.width) el.style.width = s.width + "px"; }
    }
    const maxBtn = V.$("#drawer-max");
    if (maxBtn) { V.mount(maxBtn, V.icon(s.max ? "minimize" : "maximize")); maxBtn.classList.toggle("on", !!s.max);
      maxBtn.title = s.max ? "Restore panel" : "Maximize panel"; }
    const dockBtn = V.$("#drawer-dock");
    if (dockBtn) { V.mount(dockBtn, V.icon(bottom ? "dock-right" : "dock-bottom")); dockBtn.classList.toggle("on", bottom);
      dockBtn.title = bottom ? "Dock to the right" : "Dock to the bottom"; }
  }
  function toggleDrawerMax() { const s = drawerState(); s.max = !s.max; saveDrawerState(s); applyDrawerState(); }
  function cycleDrawerDock() { const s = drawerState(); s.dock = (s.dock === "bottom") ? "right" : "bottom"; s.max = false; saveDrawerState(s); applyDrawerState(); }
  function installDrawerControls() {
    const el = V.$("#drawer"); const dz = V.$("#drawer-dz"); if (!el || !dz) return;
    let drag = null;
    dz.addEventListener("pointerdown", function (e) {
      const s = drawerState(); if (s.max) return;            // nothing to resize while maximized
      e.preventDefault();
      const r = el.getBoundingClientRect();
      drag = { bottom: s.dock === "bottom", startX: e.clientX, startY: e.clientY, startW: r.width, startH: r.height };
      dz.classList.add("active"); el.classList.add("resizing");
      try { dz.setPointerCapture(e.pointerId); } catch (_e) { /* older engines: falls back to window move */ }
    });
    dz.addEventListener("pointermove", function (e) {
      if (!drag) return;
      if (drag.bottom) {
        let hh = drag.startH - (e.clientY - drag.startY);     // drag the top edge UP = taller
        el.style.height = Math.max(160, Math.min(window.innerHeight * 0.94, hh)) + "px";
      } else {
        let ww = drag.startW - (e.clientX - drag.startX);      // panel hugs the right edge: drag LEFT = wider
        el.style.width = Math.max(320, Math.min(window.innerWidth * 0.94, ww)) + "px";
      }
    });
    function endDrag() {
      if (!drag) return;
      // Persist the size we actually APPLIED this drag (the inline style), not a re-measured rect — they
      // agree in a browser, and this is the value the operator dragged to.
      const s = drawerState();
      if (drag.bottom) s.height = parseInt(el.style.height, 10) || Math.round(el.getBoundingClientRect().height);
      else s.width = parseInt(el.style.width, 10) || Math.round(el.getBoundingClientRect().width);
      saveDrawerState(s);
      drag = null; dz.classList.remove("active"); el.classList.remove("resizing");
    }
    dz.addEventListener("pointerup", endDrag);
    dz.addEventListener("pointercancel", endDrag);
    applyDrawerState();                                       // paint the remembered state at boot
  }

  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme");
    const next = cur === "light" ? "dark" : (cur === "dark" ? "light" : (matchMedia("(prefers-color-scheme: dark)").matches ? "light" : "dark"));
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("vigil-theme", next); } catch (e) {}
  }
  // ---- Command palette -------------------------------------------------------
  // The top bar advertises "Search or run a command ⌘K". It used to answer with a toast saying the
  // feature was on the roadmap, and ⌘K was not bound at all — a control that promised search and
  // delivered nothing. This is the real thing: it searches every screen the nav can reach plus every
  // Manual section, and runs a small set of named actions. Pure overlay — it mounts into its own
  // fixed host, steals no layout, and Escape / a backdrop click always closes it.
  var PAL = { host: null, items: [], sel: 0, onKey: null };

  function paletteSources() {
    var out = [];
    (NAV || []).forEach(function (grp) {
      (grp.items || []).forEach(function (it) {
        if (it.ready === false) return;                       // never offer a screen that isn't wired
        out.push({ kind: grp.group || "GO", label: it.label, icon: it.icon || "dot",
                   hint: "screen", run: function () { location.hash = "#/" + it.id; } });
      });
    });
    (window.VIGIL_MANUAL || []).forEach(function (s) {
      out.push({ kind: "MANUAL", label: s.title, icon: "book", hint: "manual section",
                 run: function () {
                   location.hash = "#/manual";
                   setTimeout(function () {
                     var t = document.getElementById("man-" + s.id);
                     if (t) t.scrollIntoView({ behavior: "smooth", block: "start" });
                   }, 60);
                 } });
    });
    out.push({ kind: "DO", label: "New Assessment", icon: "bolt", hint: "start a run",
               run: function () { location.hash = "#/assess"; } });
    out.push({ kind: "DO", label: "Toggle theme (light / dark)", icon: "dot", hint: "appearance",
               run: toggleTheme });
    return out;
  }

  function paletteMatch(all, q) {
    var s = (q || "").trim().toLowerCase();
    if (!s) return all.slice(0, 12);
    var scored = [];
    all.forEach(function (it) {
      var hay = (it.label + " " + it.kind + " " + (it.hint || "")).toLowerCase();
      var i = hay.indexOf(s);
      if (i === -1) {                       // fall back to subsequence, so "prfstd" finds "Proof Studio"
        var pos = 0, ok = true;
        for (var c = 0; c < s.length; c++) {
          pos = hay.indexOf(s[c], pos);
          if (pos === -1) { ok = false; break; }
          pos++;
        }
        if (!ok) return;
        i = 500;                            // rank subsequence hits below substring hits
      }
      scored.push({ it: it, score: i - (it.label.toLowerCase().indexOf(s) === 0 ? 100 : 0) });
    });
    scored.sort(function (a, b) { return a.score - b.score; });
    return scored.slice(0, 12).map(function (x) { return x.it; });
  }

  function paletteDraw(q) {
    var list = V.$("#pal-list"); if (!list) return;
    PAL.items = paletteMatch(PAL.all, q);
    if (PAL.sel >= PAL.items.length) PAL.sel = 0;
    if (!PAL.items.length) {
      V.mount(list, h("div.empty", null, "Nothing matches “" + q + "”."));
      return;
    }
    V.mount(list, PAL.items.map(function (it, i) {
      return h("div.pal-row" + (i === PAL.sel ? ".on" : ""), {
        onClick: function () { paletteRun(i); },
      }, [h("span.pal-ico", null, V.icon(it.icon)),
          h("span.pal-label", null, it.label),
          h("span.pal-kind", null, it.hint || it.kind)]);
    }));
  }

  function paletteRun(i) {
    var it = PAL.items[i];
    closePalette();
    if (it && typeof it.run === "function") it.run();
  }

  function closePalette() {
    if (PAL.onKey) { document.removeEventListener("keydown", PAL.onKey, true); PAL.onKey = null; }
    if (PAL.host && PAL.host.parentNode) PAL.host.parentNode.removeChild(PAL.host);
    PAL.host = null; PAL.items = []; PAL.sel = 0;
  }

  function openPalette() {
    if (PAL.host) { closePalette(); return; }              // toggle
    PAL.all = paletteSources();
    PAL.sel = 0;
    var input = h("input.pal-input", { type: "text", placeholder: "Search screens, manual sections, actions…",
                                       "aria-label": "Search or run a command", autocomplete: "off" });
    PAL.host = h("div.pal-host", { onClick: function (e) { if (e.target === PAL.host) closePalette(); } },
      h("div.pal-box", null, [
        h("div.pal-head", null, [V.icon("search"), input]),
        h("div.pal-list#pal-list"),
        h("div.pal-foot", null, "↑↓ move · ↵ open · esc close"),
      ]));
    document.body.appendChild(PAL.host);
    paletteDraw("");
    input.addEventListener("input", function () { PAL.sel = 0; paletteDraw(input.value); });
    PAL.onKey = function (e) {
      if (e.key === "Escape") { e.preventDefault(); closePalette(); return; }
      if (e.key === "ArrowDown") { e.preventDefault(); PAL.sel = Math.min(PAL.sel + 1, PAL.items.length - 1); paletteDraw(input.value); return; }
      if (e.key === "ArrowUp") { e.preventDefault(); PAL.sel = Math.max(PAL.sel - 1, 0); paletteDraw(input.value); return; }
      if (e.key === "Enter") { e.preventDefault(); paletteRun(PAL.sel); return; }
    };
    document.addEventListener("keydown", PAL.onKey, true);
    input.focus();
  }

  // ⌘K / Ctrl-K — the shortcut the top bar advertises. It was never bound, so the hint was a lie.
  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) { e.preventDefault(); openPalette(); }
  });

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
    // MERGE both planes: sovereign pending + offense pending (renderHome already fetched OFF /api/status,
    // so no extra request — see mergeWaiting for the polling screens).
    const waiting = ((snap && (snap.pending_approvals || []).length) || 0)
                  + ((ostat && ostat.pending_approvals) || 0);
    const killed = !!(snap && snap.kill_switch && (snap.kill_switch.engaged || snap.kill_switch === "ENGAGED"));
    const findings = (ostat && (ostat.findings_confirmed != null ? ostat.findings_confirmed : (ostat.findings || 0))) || 0;
    const runs = (ostat && (ostat.active_runs != null ? ostat.active_runs : 0)) || 0;
    app.set({ waiting: waiting, killed: killed, live: runs > 0 ? "live" : "idle",
      counts: { agents: (ostat && ostat.agents) || 0, tools: (ostat && ostat.tools) || 0, findings: findings } });
    refreshTopbar();
    V.mount(V.$("#home-tiles"), [
      V.tile("Active runs", String(runs), runs ? "in progress" : "nothing running"),
      V.tile("Waiting for you", String(waiting), waiting ? "needs approval" : "all clear", waiting ? "down" : "up"),
      V.tile("Confirmed findings", String(findings), "proven by oracle"),
      V.tile("Budget today", budgetLabel(snap && snap.budget_today), "spend so far"),
    ]);
    // recent activity — the sovereign snapshot exposes recent_events as an ARRAY of recent agent events;
    // recent_by_agent / recent_decisions are COUNTER objects (not arrays), so never call .slice() on those.
    // Array.isArray guards against any shape drift so the feed degrades to the empty state, never a TypeError.
    const rows = [];
    const recentEvents = Array.isArray(snap && snap.recent_events) ? snap.recent_events : [];
    recentEvents.slice(0, 8).forEach(function (d) {
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

  // The "Waiting for you" count MERGES both planes: SOVEREIGN pending (agent-mesh / gesture / learn) plus
  // OFFENSE pending (Strix / engage owner-approvals, from OFF /api/status.pending_approvals). It read the
  // sovereign snapshot only, so a live Strix run's unsigned actions showed as "0 waiting". `done` is called
  // with the summed count; if the offense plane is down we fall back to the sovereign count (honest, never
  // an inflated number). Loopback fetch, cheap.
  function mergeWaiting(sovPending, done) {
    V.getJSON(OFF("/api/status"))
      .then(function (o) { done(sovPending + ((o && o.pending_approvals) || 0)); })
      .catch(function () { done(sovPending); });
  }

  // ---- Manual (in-app documentation; real content, no runtime data) ---------
  function renderManual(screen) {
    const sections = window.VIGIL_MANUAL || [];
    const index = h("div.card", { style: { position: "sticky", top: "0", alignSelf: "start" } },
      [h("span.label", null, "CONTENTS"),
       // .man-toc: this is a table of CONTENTS, not the icon rail — a long section title must WRAP
       // inside the 260px card rather than run out of it (the global .nav-item .txt is nowrap, which
       // is right for the sidebar rail but overflows here). Ellipsis would be worse: the operator
       // needs to read the whole title to navigate by it.
       h("div.stack.man-toc", { style: { gap: "2px", marginTop: "8px" } }, sections.map(function (s) {
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

  // Tool consciousness (Phase B1): each tool joined across its host install-status, its CLI-usage playbook,
  // and whether the engine can build a validated gated argv for it — with the admission verdict (only a
  // globally-recognised tool it can drive via CLI/background is adopted). Advisory; execution stays gated.
  function drawToolProfiles(d) {
    const host = V.$("#tool-consciousness"); if (!host) return;
    const profs = (d && d.profiles) || [];
    const s = (d && d.summary) || {};
    if (d && d.error && !profs.length) {
      V.mount(host, V.card("Tool consciousness", "ADVISORY", h("div.empty", null, "Could not build profiles: " + d.error), false));
      return;
    }
    function row(p) {
      var chip = p.admitted
        ? h("span.pill.sm.ok", { title: p.admit_reason }, [V.icon("check"), " Controllable (" + (p.control_surface || "cli") + ")"])
        : h("span.pill.sm.danger", { title: p.admit_reason }, [V.icon("info"), " Refused"]);
      var signals = [
        p.has_skill_doc ? h("span.pill.sm", { title: "has a CLI-usage playbook the agent reads" }, "playbook ✓") : null,
        p.has_typed_builder ? h("span.pill.sm", { title: "the engine builds a validated, gated argv" }, "typed argv ✓") : null,
        p.installed ? h("span.pill.sm.ok", { title: p.path || "" }, "installed") :
          (p.install_hint ? h("span.pill.sm", { title: p.install_hint }, "installable") : h("span.pill.sm", null, p.status || "—")),
      ];
      // on-demand install (B2): two-step operator consent — the first click reveals the EXACT declared
      // command; confirming runs it. Server-side only an adopted tool + its declared apt/pip may install.
      var installSlot = h("span", { style: { flex: "1 1 100%" } });
      if (p.admitted && !p.installed && p.install_hint) {
        var slot = installSlot;
        var confirm = function (cmd) {
          var run = h("button.btn.sm.owner", { onClick: function () {
              run.disabled = true;
              V.postJSON(OFF("/api/tools/install"), { name: p.name, consent: true }).then(function (r) {
                V.toast(r && r.ok ? (p.name + " installed.") : ((r && r.error) || (p.name + " install failed")), !(r && r.ok));
                renderTools(V.$("#screen") || document.body);   // re-probe + re-render
              }).catch(function (e) { run.disabled = false; V.toast((e && e.message) || "install failed", true); });
            } }, [V.icon("check"), "Run it"]);
          V.mount(slot, [h("span.mono.dim", { style: { fontSize: "var(--fs-xs)", marginRight: "8px" } }, "$ " + cmd), run]);
        };
        var btn = h("button.btn.sm", { onClick: function () {
            btn.disabled = true;
            V.postJSON(OFF("/api/tools/install"), { name: p.name }).then(function (r) {
              btn.disabled = false;
              if (r && r.needs_consent) { confirm(r.command); }
              else if (r && r.ok) { V.toast(p.name + " already installed."); }
              else { V.toast((r && r.error) || "cannot install", true); }
            }).catch(function (e) { btn.disabled = false; V.toast((e && e.message) || "install check failed", true); });
          } }, [V.icon("bolt"), "Install"]);
        V.mount(installSlot, btn);
      }
      // deep-research pointers (B3): fetch the tool's official docs + the canonical research query on demand
      var researchSlot = h("span", { style: { flex: "1 1 100%" } });
      var rbtn = h("button.btn.sm", { onClick: function () {
          rbtn.disabled = true;
          V.getJSON(OFF("/api/toolresearch/" + encodeURIComponent(p.name))).then(function (r) {
            rbtn.disabled = false;
            var kids = [h("div.mono.dim", { style: { fontSize: "var(--fs-xs)" } }, "research query: " + (r.query || "—"))];
            (r.docs || []).forEach(function (u) { kids.push(h("div", { style: { fontSize: "var(--fs-xs)" } }, h("a", { href: u, target: "_blank", rel: "noreferrer" }, u))); });
            if (!r.has_doc) kids.push(h("div.dim", { style: { fontSize: "var(--fs-xs)" } }, r.note || "no playbook — research via the query above"));
            V.mount(researchSlot, kids);
          }).catch(function () { rbtn.disabled = false; V.toast("research lookup failed", true); });
        } }, [V.icon("book"), "Research"]);
      V.mount(researchSlot, rbtn);
      return h("div", { style: { display: "flex", alignItems: "center", gap: "8px", padding: "6px 0", borderBottom: "1px solid var(--border)", flexWrap: "wrap" } }, [
        h("span.mono", { style: { minWidth: "120px", fontWeight: "600" } }, p.name),
        p.in_host_roster ? h("span.pill.sm", { title: "a host security CLI" }, "host CLI")
                         : h("span.pill.sm", { title: "an agent capability skill (not a host security CLI)" }, "agent skill"),
        chip,
        h("span", { style: { display: "flex", gap: "6px", flexWrap: "wrap" } }, signals),
        installSlot,
        researchSlot,
        p.admitted ? null : h("span.dim", { style: { fontSize: "var(--fs-xs)", flex: "1 1 100%" } }, p.admit_reason),
      ]);
    }
    var admitted = profs.filter(function (p) { return p.admitted; });
    var refused = profs.filter(function (p) { return !p.admitted; });
    V.mount(host, V.card("Tool consciousness", "ADVISORY", h("div", null, [
      h("div.grid.cols-4", { style: { marginBottom: "12px" } }, [
        V.tile("Adopted", String(s.admitted || 0), "recognised + controllable", "up"),
        V.tile("Refused", String(s.refused || 0), "not usable/recognised", s.refused ? "" : "up"),
        V.tile("Installed", String(s.installed || 0), "on PATH", ""),
        V.tile("Installable", String(s.installable_missing || 0), "adopted, not yet installed", ""),
      ]),
      h("div.legend", { style: { marginBottom: "8px" } }, [V.icon("info"),
        "The arsenal is curated: a tool is adopted only if it is globally recognised AND the engine can drive it (a CLI playbook or a typed argv builder). Everything here is advisory — a real run still passes the safety gate."]),
      admitted.length ? h("div", null, admitted.map(row)) : h("div.empty", null, "No tools adopted yet."),
      refused.length ? h("details", { style: { marginTop: "12px" } }, [
        h("summary", { style: { cursor: "pointer", color: "var(--text-1)" } }, "Refused / not-yet-usable (" + refused.length + ")"),
        h("div", { style: { marginTop: "8px" } }, refused.map(row)),
      ]) : null,
    ]), false));
  }

  function renderTools(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Tools"),
        h("span.sub", null, "External security tools the offense engine runs on this host — installed live.")]),
      h("div.grid.cols-4#tools-summary"),
      h("div#tools-body", { style: { marginTop: "16px" } }, h("div.empty", null, "Probing host tools…")),
      h("div#tool-consciousness", { style: { marginTop: "16px" } }),
    ]);
    V.getJSON(OFF("/api/tools")).then(renderToolsData).catch(function (e) {
      V.mount(V.$("#tools-body"), offlineEmpty(e, "Could not reach the offense console to probe host tools. Start it (vigil up) and reload."));
    });
    V.getJSON(OFF("/api/toolprofiles")).then(drawToolProfiles).catch(function () { /* panel just stays empty */ });
  }

  // ==========================================================================
  // Trust Center — VIGIL's SIGNED, offline-verifiable certificates AS certificates.
  // Renders each cert's trust root (m-of-n authorizers + threshold), its out-of-band
  // fingerprint pin, the signed digest, and the accuracy numbers — plus a LIVE
  // "Verify offline" button that runs the cert's real offline verifier and shows a
  // PASS/FAIL badge + whether the fingerprint matches the OOB pin. READ/VERIFY-ONLY:
  // no mint, no scope/target, no traffic — the verify POST is a pure re-computation.
  // ==========================================================================

  function trustKv(k, v) { return h("div.kv", null, [h("div.k", null, k), h("div.v", null, v)]); }
  function trustShort(s, head, tail) {
    s = String(s || ""); head = head || 22; tail = tail || 8;
    return s.length > head + tail + 1 ? s.slice(0, head) + "…" + s.slice(-tail) : (s || "—");
  }
  function trustPct(x) { return x == null ? "—" : (Math.round(Number(x) * 1000) / 10) + "%"; }
  function trustCssId(id) { return "trust-verify-" + String(id || "").replace(/[^A-Za-z0-9_-]+/g, "-"); }

  function renderTrust(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Trust Center"),
        h("span.sub", null, "VIGIL's signed, offline-verifiable certificates — rendered as certificates: "
          + "trust root, out-of-band fingerprint pin, and a live offline PASS/FAIL verification.")]),
      h("div#trust-doctrine", { style: { marginBottom: "14px" } }),
      antiRollbackCard(),
      h("div#trust-body", null, h("div.empty", null, "Loading certificates…")),
    ]);
    V.getJSON(OFF("/api/certs")).then(renderTrustData).catch(function (e) {
      V.mount(V.$("#trust-body"), offlineEmpty(e, "Could not reach the offense console to read certificates. Start it (vigil up) and reload."));
    });
  }

  // Wave 8 (parity) — read-only sovereign ANTI-ROLLBACK status: the durable external floor (`sigil floor
  // status`) + the spine's segment-rotation state (`sigil spine status`). Metadata only. The reset / rotate /
  // compact mutations stay CLI/owner-only (deferred).
  function antiRollbackCard() {
    var out = h("div", null, h("div.empty", null, "Loading anti-rollback status…"));
    function draw(floor, spine) {
      function block(title, r) {
        var okv = !!(r && r.ok);
        return h("div", { style: { flex: "1", minWidth: "260px" } }, [
          h("div", { style: { display: "flex", gap: "6px", alignItems: "center", marginBottom: "4px" } }, [V.pill(okv ? "ok" : "check", okv ? "up" : "danger", null), h("strong", null, title)]),
          h("pre.mono", { style: { whiteSpace: "pre-wrap", fontSize: "12px", maxHeight: "220px", overflow: "auto", margin: "0" } }, (r && (r.text || r.error)) || "—"),
        ]);
      }
      V.mount(out, h("div", { style: { display: "flex", gap: "18px", flexWrap: "wrap" } }, [block("Anti-rollback floor", floor), block("Spine segments", spine)]));
    }
    Promise.all([
      V.getJSON(SOV("/api/antirollback/floor")).catch(function (e) { return { ok: false, error: (e && e.message) || "unreachable" }; }),
      V.getJSON(SOV("/api/antirollback/spine")).catch(function (e) { return { ok: false, error: (e && e.message) || "unreachable" }; }),
    ]).then(function (r) { draw(r[0], r[1]); });
    return h("div.card", { style: { marginBottom: "14px" } }, [
      h("div.card-h", null, [h("h3", null, "Anti-rollback status"),
        h("button.btn.sm", { style: { marginLeft: "auto" }, onClick: function () { if (current() === "trust") renderTrust(V.$("#screen") || document.body); } }, [V.icon("live"), "Refresh"])]),
      h("div.hint", null, "The durable external floor + the spine's segment-rotation state — read-only. "
        + "A downward floor RESET or a spine rotate/compact stays a deliberate owner CLI act."),
      h("div", { style: { marginTop: "10px" } }, out),
    ]);
  }

  function renderTrustData(d) {
    var doc = V.$("#trust-doctrine");
    if (doc && d && d.doctrine) {
      V.mount(doc, [h("div.hint", null, d.doctrine),
        d.source_pin_note ? h("div.hint", { style: { marginTop: "6px" } }, d.source_pin_note) : null]);
    }
    var body = V.$("#trust-body"); if (!body) return;
    var certs = (d && d.certs) || [];
    if (!certs.length) { V.mount(body, h("div.empty", null, "No certificates found.")); return; }
    V.mount(body, h("div.grid.cols-2", null, certs.map(trustCertCard)));
  }

  function trustSummary(c) {
    var s = c.summary || {};
    if (c.kind === "recall") {
      var rows = (s.results || []).map(function (r) {
        return trustKv(r.tool, "recall " + trustPct(r.recall) + " · precision " + trustPct(r.precision)
          + " · F1 " + trustPct(r.f1) + " · tp " + r.tp + " / fp " + r.fp + " / fn " + r.fn);
      });
      return h("div", { style: { marginTop: "8px" } }, [
        s.scope ? h("div.hint", null, s.scope) : null,
        s.ground_truth_count != null ? trustKv("Ground truth",
          s.ground_truth_count + " planted bugs across " + ((s.planted_classes || []).length) + " classes") : null,
      ].concat(rows));
    }
    if (c.kind === "coverage" || c.kind === "plan-integrity") {
      var sm = s.summary || {};
      var keys = Object.keys(sm);
      return h("div", { style: { marginTop: "8px" } }, [
        s.scope ? h("div.hint", null, s.scope) : null,
        s.target_host ? trustKv("Target host", s.target_host) : null,
        keys.length ? trustKv("Summary", keys.map(function (k) { return k + " " + sm[k]; }).join(" · ")) : null,
      ]);
    }
    return null;
  }

  function trustCertCard(c) {
    var head = h("div.card-h", null, [
      h("span.label", null, c.kind || "cert"),
      h("h3", null, c.name || c.id),
      c.run_id ? V.pill("run " + c.run_id, null, null) : null,
    ]);
    if (!c.present) {
      return h("div.card", null, [head,
        h("div.empty", { style: { marginTop: "8px" } }, [
          V.statusBadge("idle"),
          h("p", null, c.note || "not yet produced — run a scan / make bench to mint and sign this certificate."),
        ]),
      ]);
    }
    var tr = c.trust_root || {};
    var authz = tr.authorizers || [];
    var body = [
      c.schema ? trustKv("Schema", h("span.mono", null, c.schema)) : null,
      trustKv("Signed digest", h("span.mono", null, trustShort(c.scorecard_digest))),
      trustKv("Trust root", "m-of-n threshold " + (tr.threshold != null ? tr.threshold : "?") + " of " + authz.length),
      h("div.kv", null, [h("div.k", null, "Authorizers"), h("div.v", null,
        authz.length ? authz.map(function (a) {
          return h("div", { style: { marginBottom: "3px" } },
            [V.pill(a.key_id || "?", null, null), " ", h("span.mono", null, trustShort(a.public_key_b64, 14, 6))]);
        }) : "—")]),
      // A SOURCE-pinned cert (recall) shows its out-of-band pin; a per-run cert's .fingerprint.txt is
      // written by the same signer and is NOT a pin — label it honestly so no "out-of-band" claim is implied.
      c.source_pin
        ? trustKv("Fingerprint pin (out-of-band)", h("span.mono", null, trustShort(c.source_pin, 26, 8)))
        : trustKv("Fingerprint (self-asserted, in-bundle — NOT a pin)",
                  h("span.mono", null, trustShort(c.fingerprint, 26, 8))),
      c.source_pin ? h("div.hint", null,
        "This trust root is pinned in SOURCE — a re-sign under a fresh key fails the pin.") : null,
      c.source_pin ? null : h("div.hint", null,
        "No source pin for a per-run cert: this fingerprint is written by the same signer, so it proves "
        + "tamper-after-signing only. To bind the trust ROOT (reject a fresh-key re-sign), paste the "
        + "operator-held out-of-band pin below."),
      trustSummary(c),
    ];
    var resultId = trustCssId(c.id);
    var pinId = c.source_pin ? null : (resultId + "-pin");
    if (pinId) {
      body.push(h("div.kv", { style: { marginTop: "8px" } }, [
        h("div.k", null, "Out-of-band pin (optional)"),
        h("div.v", null, h("input.mono", { id: pinId, type: "text", spellcheck: "false",
          placeholder: "sha256:… (the pin you hold independently)" })),
      ]));
    }
    body.push(h("div.row", { style: { marginTop: "10px", alignItems: "center" } }, [
      h("button.btn.sm.primary", { onClick: function () { doVerifyCert(c, resultId, pinId); } },
        [V.icon("shield"), "Verify offline"]),
      h("span.hint", { style: { marginLeft: "8px" } }, c.source_pin
        ? "Re-derives the digest + checks the signature + the SOURCE pin. Offline, read-only."
        : "Re-derives the digest + checks the signature; binds the trust root only if you supply a pin. Offline, read-only."),
    ]));
    body.push(h("div", { id: resultId, style: { marginTop: "10px" } }));
    return h("div.card", null, [head, h("div", null, body)]);
  }

  function doVerifyCert(c, resultId, pinId) {
    var slot = V.$("#" + resultId);
    if (slot) V.mount(slot, h("div.row", { style: { alignItems: "center" } },
      [V.statusBadge("running"), h("span.hint", { style: { marginLeft: "8px" } }, "verifying offline…")]));
    var pinEl = pinId ? V.$("#" + pinId) : null;
    var oobPin = pinEl ? String(pinEl.value || "").trim() : "";
    V.postJSON(OFF("/api/verify-cert"), { name: c.id, run_id: c.run_id || "", oob_pin: oobPin }).then(function (r) {
      renderVerifyResult(slot, r);
    }).catch(function () {
      if (slot) V.mount(slot, h("div.hint", null, "Verify failed — offense console unreachable."));
    });
  }

  function renderVerifyResult(slot, r) {
    if (!slot) return;
    if (!r || r.error) { V.mount(slot, h("div.hint", null, "Verify error: " + ((r && r.error) || "unknown"))); return; }
    if (r.present === false) {
      V.mount(slot, h("div.hint", null, r.note || "certificate not present — nothing to verify."));
      return;
    }
    var ok = !!r.verified;
    // fingerprint_matches_pin is TRUE / FALSE only when a real out-of-band pin bound the trust root;
    // NULL means the per-run trust root is UNPINNED (no independent pin) — that is NOT a green match.
    var fp = r.fingerprint_matches_pin;
    var fpRow;
    if (fp === true) {
      fpRow = h("span.row", { style: { alignItems: "center" } },
        [V.statusBadge("confirmed"), h("span", { style: { marginLeft: "8px" } }, "matches the out-of-band pin")]);
    } else if (fp === false) {
      fpRow = h("span.row", { style: { alignItems: "center" } },
        [V.statusBadge("refuted"), h("span", { style: { marginLeft: "8px" } }, "does NOT match the pin")]);
    } else {
      // unpinned trust root — neutral, never green. The origin/trust-root guarantee is not established.
      fpRow = h("span.row", { style: { alignItems: "center" } },
        [V.statusBadge("idle"), h("span", { style: { marginLeft: "8px" } },
          "trust root UNPINNED — no out-of-band pin supplied (origin not bound)")]);
    }
    V.mount(slot, [
      h("div.row", { style: { alignItems: "center" } }, [
        V.statusBadge(ok ? "confirmed" : "refuted"),
        h("span", { style: { marginLeft: "8px", fontWeight: "700" } },
          ok ? "PASS — signature re-verified offline" : "FAIL — did not verify"),
      ]),
      h("div.kv", { style: { marginTop: "6px" } }, [
        h("div.k", null, "Trust root vs out-of-band pin"),
        h("div.v", null, fpRow)]),
      (r.which_authorizers && r.which_authorizers.length)
        ? trustKv("Signed by", r.which_authorizers.join(", ")) : null,
      r.digest ? trustKv("Digest", h("span.mono", null, trustShort(r.digest))) : null,
      r.pin_source ? h("div.hint", null, "Pin source: " + r.pin_source) : null,
    ]);
  }

  // ==========================================================================
  // Proof of Posture — the signed, offline-verifiable Certificate of Non-Exploitability.
  // Renders each PostureCertificate AS a certificate: the target + freshness, the CLOSED /
  // OPEN / UNPROVEN posture claims grouped by surface (with the vuln-class, the conclusive
  // oracle(s), and the verification TIER — binding vs re-executable), the PROMINENT coverage
  // DENOMINATOR + the honest RESIDUAL (the boundary is the point — CLOSED is never "secure
  // against everything"), the out-of-band fingerprint PIN, and the exact offline-verify
  // command (copy). READ-ONLY: reads the certificate; the bundle's own verify_offline.py is
  // the offline PASS/FAIL authority. No fabricated numbers — an un-attested tree is EMPTY.
  // ==========================================================================

  var POSTURE_STATE = { CLOSED: "confirmed", OPEN: "blocked", UNPROVEN: "queued" };
  function postureBadge(status) {
    var s = String(status || "").toUpperCase();
    return h("span.st.st-" + (POSTURE_STATE[s] || "idle"), null, [h("span.dot"), s || "—"]);
  }
  function postureTier(v) {
    // "re-executable" = raw bytes embedded + a pinned oracle kernel re-runs them (stronger);
    // "binding" = the offline verifier re-checks the signed coverage verdict + projection, but
    // re-firing the oracle needs VIGIL (the honest residual). Never dress binding up as re-exec.
    var re = String(v || "") === "re-executable";
    return h("span.pill.sm" + (re ? ".ok" : ""), null, [re ? "re-executable" : "binding"]);
  }

  var PST = { data: null };
  function renderPosture(screen) {
    var refreshBtn = h("button.btn.sm", { onClick: function () { loadPosture(); } }, [V.icon("live"), "Refresh"]);
    var dlBtn = h("button.btn.sm", { onClick: function () {
      if (!PST.data || !((PST.data.posture || []).some(function (c) { return c && c.present; }))) {
        V.toast("No posture certificate to export yet.", true); return; }
      downloadJSON("vigil-posture-" + nowStamp() + ".json", PST.data);
    } }, [V.icon("book"), "Download certificate (JSON)"]);
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Proof of Posture"),
        h("span.sub", null, "The Certificate of Non-Exploitability — a signed, coverage-bounded, "
          + "offline-verifiable proof that, over the surface the scanner REACHED, an applicable oracle "
          + "had a live channel and did not fire. The boundary (denominator + residual) is the point.")]),
      h("div.acts", { style: { margin: "0 0 12px", gap: "8px", display: "flex", flexWrap: "wrap" } }, [refreshBtn, dlBtn]),
      postureActionsCard(),
      h("div#posture-doctrine", { style: { marginBottom: "14px" } }),
      h("div#posture-body", null, h("div.empty", null, "Loading posture certificates…")),
    ]);
    loadPosture();
  }

  // Wave 5 (parity) — mint a Certificate of Non-Exploitability (attest) and offline re-verify a bundle,
  // from the browser. Attest DETACHES on the server (it runs a scan, ~1-2 min) → we poll the posture read
  // until the cert appears. Verify is a fast offline re-run of the bundle's own verifier. The bundle NAME is
  // a slug the server validates + resolves strictly under the console posture dir.
  function postureActionsCard() {
    var nameInp = h("input.inp", { type: "text", placeholder: "bundle name (slug, e.g. prod-2026-08)", value: "posture-" + nowStamp().slice(0, 10) });
    var out = h("div", null, "");
    function poll(name, n) {
      loadPosture();
      if (n > 0) setTimeout(function () { if (current() === "posture") poll(name, n - 1); }, 12000);
    }
    return h("div.card", { style: { marginBottom: "14px" } }, [
      h("div.card-h", null, [h("h3", null, "Attest & verify")]),
      h("div.hint", null, "Attest scans the authorized loopback target and mints a signed, offline-verifiable "
        + "certificate (~1-2 min — it appears below when done). Verify re-runs the bundle's own offline verifier."),
      h("div", { style: { display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center", marginTop: "10px" } }, [
        h("div", { style: { minWidth: "260px" } }, nameInp),
        h("button.btn.sm.owner", { onClick: function () {
          var nm = (nameInp.value || "").trim();
          if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(nm)) { V.toast("name must be a slug [A-Za-z0-9_-]", true); return; }
          V.postJSON(OFF("/api/posture/attest"), { name: nm }).then(function (r) {
            if (r && r.ok) { V.mount(out, h("div.set-status.ok", { style: { marginTop: "8px" } }, [V.icon("check"), h("span", null, " " + (r.detail || "attesting…"))])); poll(nm, 12); }
            else { V.mount(out, h("div.set-status.danger", { style: { marginTop: "8px" } }, (r && r.error) || "attest failed")); }
          }).catch(function (e) { V.mount(out, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "attest failed")); });
        } }, [V.icon("shield"), "Attest new certificate"]),
        h("button.btn.sm", { onClick: function () {
          var nm = (nameInp.value || "").trim();
          if (!nm) { V.toast("enter the bundle name to verify", true); return; }
          V.mount(out, h("div.hint", { style: { marginTop: "8px" } }, "Verifying " + nm + "…"));
          V.postJSON(OFF("/api/posture/verify"), { name: nm }).then(function (r) {
            var okv = !!(r && r.ok);
            V.mount(out, h("div.set-status" + (okv ? ".ok" : ".danger"), { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
              h("div", null, [V.icon(okv ? "check" : "x"), h("span", null, " " + nm + ": " + (okv ? "VERIFIED offline" : "NOT verified"))]),
              (r && (r.text || r.error)) ? h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px", maxHeight: "220px", overflow: "auto" } }, r.text || r.error) : null,
            ]));
          }).catch(function (e) { V.mount(out, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "verify failed")); });
        } }, [V.icon("check"), "Verify bundle"]),
      ]),
      out,
    ]);
  }
  function loadPosture() {
    var body = V.$("#posture-body");
    if (body) V.mount(body, h("div.empty", null, "Loading posture certificates…"));
    V.getJSON(OFF("/api/posture")).then(function (d) { PST.data = d; renderPostureData(d); }).catch(function (e) {
      PST.data = null;
      var b = V.$("#posture-body");
      if (b) V.mount(b, offlineEmpty(e, "Could not reach the offense console to read posture certificates. Start it (vigil up) and reload."));
    });
  }

  function renderPostureData(d) {
    var doc = V.$("#posture-doctrine");
    if (doc && d && d.doctrine) V.mount(doc, h("div.hint", null, d.doctrine));
    var body = V.$("#posture-body"); if (!body) return;
    var certs = (d && d.posture) || [];
    var present = certs.filter(function (c) { return c && c.present; });
    if (!present.length) {
      V.mount(body, h("div.empty", null, [
        h("div.big", null, "No posture attested yet"),
        h("p", null, "Nothing here is fabricated. Mint a signed Certificate of Non-Exploitability with:"),
        h("pre.code", { style: { textAlign: "left", maxWidth: "640px", margin: "12px auto 0" } },
          "python -m vigil_integration.posture attest --out <dir>"),
        h("p", { style: { marginTop: "10px" } }, "Attest into the console's posture dir "
          + "(<v2_root>/.console/posture/<name>) or a run dir, then reload."),
      ]));
      return;
    }
    V.mount(body, h("div.stack", null, present.map(postureCard)));
  }

  function postureCard(c) {
    var sum = c.summary || {};
    var tr = c.trust_root || {};
    var authz = tr.authorizers || [];
    var target = (c.target_sample && (c.target_sample.host || c.target_sample.url
      || Object.values(c.target_sample)[0])) || c.engagement || "target";

    var head = h("div.card-h", null, [
      h("span.label", null, "certificate of non-exploitability"),
      h("h3", null, String(target)),
      c.engagement ? V.pill("engagement " + c.engagement, null, null) : null,
      c.run_id ? V.pill("run " + c.run_id, null, null) : null,
    ]);

    // freshness — HONEST: the signed core is deterministic (no wall-clock); the freshness bound is the
    // bundle's external RFC3161 time anchor, applied as a sidecar. Never invent a timestamp.
    var freshness = h("div.hint", { style: { marginTop: "2px" } },
      "Freshness: this proof is only as current as the last coverage scan. The signed certificate core is "
      + "deterministic (no wall-clock); the freshness bound is the bundle's external RFC3161 time anchor "
      + "(a sidecar), not a field of the signed bytes.");

    var tiles = h("div.grid.cols-4", { style: { marginTop: "12px" } }, [
      V.tile("Closed", String(sum.n_closed != null ? sum.n_closed : "—"),
        "oracle had a channel & did NOT fire", "ok"),
      V.tile("Open", String(sum.n_open != null ? sum.n_open : "—"),
        "an oracle FIRED (a finding)", (sum.n_open ? "danger" : "")),
      V.tile("Unproven", String(sum.n_unproven != null ? sum.n_unproven : "—"),
        "payload sent, no oracle adjudicated", (sum.n_unproven ? "warn" : "")),
      V.tile("Re-executable", (sum.n_closed_re_executable != null ? sum.n_closed_re_executable : 0)
        + " / " + (sum.n_closed != null ? sum.n_closed : 0),
        "CLOSED that re-fire offline; the rest are binding-only (need VIGIL)"),
    ]);

    var denom = postureDenominator(c);
    var residual = c.residual ? h("div.legend", { style: { marginTop: "12px", alignItems: "flex-start" } },
      [V.icon("info"), h("span", null, [h("b", null, "Residual (the honest boundary): "), c.residual])]) : null;

    var claims = postureClaims(c.posture_claims || []);
    var trust = postureTrust(c, tr, authz);
    var verify = postureVerify(c);

    return h("div.card", null, [head, freshness, tiles, denom, residual, claims, trust, verify]);
  }

  // The PROMINENT coverage denominator — CLOSED is bounded to the REACHED surface; this panel says so.
  function postureDenominator(c) {
    var dm = c.denominator || {};
    function row(k, v) { return (v == null || v === "") ? null : trustKv(k, String(v)); }
    var known = [
      row("Surfaces reached", dm.surfaces_reached),
      row("Insertion points probed", dm.insertion_points_probed),
      row("Distinct classes probed", dm.distinct_classes_probed),
      row("Crawl bound", (dm.max_pages != null ? dm.max_pages + " pages" : "")
        + (dm.max_depth != null ? " · depth " + dm.max_depth : "")),
      row("Frontier truncated", dm.frontier_truncated != null ? dm.frontier_truncated : null),
      row("Budget exhausted", dm.budget_exhausted != null ? (dm.budget_exhausted ? "yes" : "no") : null),
    ].filter(Boolean);
    return h("div.card", { style: { marginTop: "12px", background: "var(--bg-2)" } }, [
      h("div.card-h", null, [h("span.label", null, "coverage denominator"),
        h("h3", { style: { fontSize: "var(--fs-lg)" } }, "What this proof covers — and what it does NOT")]),
      known.length ? h("div.kv", { style: { marginTop: "8px" } }, known)
        : h("div.hint", null, "denominator not recorded in this certificate."),
      c.scope ? h("div.hint", { style: { marginTop: "10px" } }, c.scope) : null,
      h("div.hint", { style: { marginTop: "6px", color: "var(--st-blocked)" } },
        "CLOSED is bounded to the surface the scanner REACHED (the denominator above). Undiscovered "
        + "endpoints/parameters are discovery/recall — OUT of this denominator, NOT covered. A CLOSED "
        + "certificate is never a claim of security against everything."),
    ]);
  }

  // The claims table, grouped by surface (OPEN first, then UNPROVEN, then CLOSED within a surface).
  function postureClaims(claims) {
    if (!claims.length) return h("div.hint", { style: { marginTop: "12px" } }, "no posture claims recorded.");
    var rank = { OPEN: 0, UNPROVEN: 1, CLOSED: 2 };
    var bySurface = {};
    claims.forEach(function (c) { (bySurface[c.surface || "—"] = bySurface[c.surface || "—"] || []).push(c); });
    var surfaces = Object.keys(bySurface).sort();
    var sections = surfaces.map(function (surf) {
      var rows = bySurface[surf].slice().sort(function (a, b) {
        var r = (rank[String(a.status).toUpperCase()] || 9) - (rank[String(b.status).toUpperCase()] || 9);
        return r !== 0 ? r : String(a.class).localeCompare(String(b.class));
      });
      var counts = { OPEN: 0, CLOSED: 0, UNPROVEN: 0 };
      rows.forEach(function (c) { var s = String(c.status).toUpperCase(); if (counts[s] != null) counts[s]++; });
      var chips = h("span", { style: { marginLeft: "auto", display: "inline-flex", gap: "6px", flexWrap: "wrap" } }, [
        counts.OPEN ? V.pill(counts.OPEN + " open", "danger", null) : null,
        counts.UNPROVEN ? V.pill(counts.UNPROVEN + " unproven", "reconnect", null) : null,
        counts.CLOSED ? V.pill(counts.CLOSED + " closed", "sm ok", null) : null,
      ]);
      var table = h("div.scroll-x", null, h("table.tbl", null, [
        h("thead", null, h("tr", null, [
          h("th", null, "Parameter"), h("th", null, "Class"), h("th", null, "Status"),
          h("th", null, "Evidence oracle(s)"), h("th", null, "Verification"), h("th", null, "Probes")])),
        h("tbody", null, rows.map(function (c) {
          var oracles = (c.evidence_oracle_kinds || []);
          return h("tr", null, [
            h("td.mono", null, c.param || "—"),
            h("td", null, c.class || "—"),
            h("td", null, postureBadge(c.status)),
            h("td", null, oracles.length
              ? h("span", { style: { display: "inline-flex", gap: "4px", flexWrap: "wrap" } },
                  oracles.map(function (k) { return V.pill(k, "sm", null); }))
              : h("span.dim", null, String(c.status).toUpperCase() === "CLOSED" ? "—" : "(none fired)")),
            h("td", null, postureTier(c.verification)),
            h("td.mono", null, String(c.n_probes != null ? c.n_probes : "—")),
          ]);
        })),
      ]));
      return h("div", { style: { marginTop: "12px" } }, [
        h("div.row-flex", { style: { alignItems: "center" } }, [
          h("b.mono", { style: { fontSize: "var(--fs-sm)" } }, surf), chips]),
        table,
      ]);
    });
    return h("div", { style: { marginTop: "8px" } }, [
      h("span.label", null, "posture claims by surface"), sections]);
  }

  function postureTrust(c, tr, authz) {
    return h("div", { style: { marginTop: "14px" } }, [
      h("span.label", null, "trust root & out-of-band pin"),
      h("div.kv", { style: { marginTop: "8px" } }, [
        c.schema ? trustKv("Schema", h("span.mono", null, c.schema)) : null,
        trustKv("Signed digest", h("span.mono", null, trustShort(c.scorecard_digest))),
        trustKv("Trust root", "m-of-n threshold " + (tr.threshold != null ? tr.threshold : "?") + " of " + authz.length),
        h("div.kv", null, [h("div.k", null, "Authorizers"), h("div.v", null, authz.length
          ? authz.map(function (a) { return h("div", { style: { marginBottom: "3px" } },
              [V.pill(a.key_id || "?", null, null), " ", h("span.mono", null, trustShort(a.public_key_b64, 14, 6))]); })
          : "—")]),
        trustKv("Fingerprint pin (out-of-band)", c.fingerprint
          ? h("span.mono", null, trustShort(c.fingerprint, 26, 8)) : "—"),
        trustKv("Owner pubkey", c.owner_pubkey ? h("span.mono", null, trustShort(c.owner_pubkey, 16, 6)) : "—"),
      ]),
      h("div.hint", { style: { marginTop: "8px" } },
        "Publish the fingerprint pin + owner pubkey on a channel SEPARATE from the bundle. A verifier passes "
        + "the pin as --posture-fingerprint; a forger who re-signs a tampered certificate with a fresh key is "
        + "rejected before any signature check."),
    ]);
  }

  function postureVerifyCommand(c) {
    var fp = c.fingerprint || "<publish-out-of-band>";
    var owner = c.owner_pubkey || "<publish-out-of-band>";
    var eng = c.engagement || "<engagement>";
    var lines = [];
    if (c.bundle_dir) lines.push("cd " + c.bundle_dir);
    lines.push("python3 verify_offline.py verify \\");
    lines.push("    --bundle bundle.json \\");
    lines.push("    --posture-fingerprint " + fp + " \\");
    lines.push("    --posture-owner-pubkey " + owner + " \\");
    lines.push("    --posture-engagement " + eng + " \\");
    lines.push("    --posture-now $(date +%s)");
    return lines.join("\n");
  }

  function postureVerify(c) {
    var cmd = postureVerifyCommand(c);
    return h("div", { style: { marginTop: "14px" } }, [
      h("span.label", null, "verify offline (no VIGIL, no trust in us)"),
      h("div.hint", { style: { margin: "6px 0 8px" } },
        "Exit 0 = SOUND. Re-checks, fail-closed: the m-of-n signature over the canonical bytes; the "
        + "out-of-band pin; that every claim re-projects from the embedded coverage evidence (a forged "
        + "CLOSED is refused); and the owner-signed target binding. It does NOT re-fire the oracle "
        + "(that needs VIGIL) — the certificate states this residual on its face."),
      h("div", { style: { display: "flex", gap: "8px", alignItems: "stretch" } }, [
        h("pre.code.scroll-x", { style: { flex: "1", margin: "0" } }, cmd),
        h("button.btn", { title: "Copy the offline-verify command",
          onClick: function () { copyText(cmd); } }, "Copy"),
      ]),
      c.bundle_present
        ? h("div", { style: { marginTop: "10px" } }, [
            h("span.label", null, "portable bundle"),
            h("div.hint", { style: { margin: "6px 0 6px" } },
              "Self-contained: bundle.json + its own verify_offline.py + HOW-TO-VERIFY.md + the out-of-band "
              + "pins. Copy this directory off-box and run the command above inside it."),
            h("div", { style: { display: "flex", gap: "8px", alignItems: "stretch" } }, [
              h("pre.code.scroll-x", { style: { flex: "1", margin: "0" } }, c.bundle_dir || ""),
              h("button.btn", { title: "Copy the bundle path",
                onClick: function () { copyText(c.bundle_dir || ""); } }, "Copy path"),
            ]),
          ])
        : h("div.hint", { style: { marginTop: "8px" } },
            "No portable bundle exported for this attestation (only the signed triple on disk)."),
    ]);
  }

  // ==========================================================================
  // Replay-the-Proof — import an external report/finding JSON and RE-FIRE its
  // retained oracle certificates OFFLINE (pure re-computation via the console's
  // /api/replay -> verify.reverify.reverify_document). No target, no traffic, no
  // mint. A tampered finding renders CONTRADICTED, never a green "reproduced".
  // ==========================================================================
  function renderReplay(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Replay the Proof"),
        h("span.sub", null, "Paste a VIGIL report or finding (report.json) and re-fire its retained oracle "
          + "proofs OFFLINE — pure re-computation, no target, no traffic. A tampered proof shows as "
          + "CONTRADICTED, never a green reproduction.")]),
      h("div.card", null, [
        h("div.kv", null, [h("div.k", null, "Report / finding JSON"),
          h("div.v", null, h("textarea#replay-input", { rows: "10", spellcheck: "false",
            placeholder: '{ "active_findings": [ … ] }  — or a single finding object' }))]),
        h("div.row", { style: { marginTop: "10px", alignItems: "center" } }, [
          h("button.btn.sm.primary", { onClick: doReplay }, [V.icon("bolt"), "Re-fire proofs offline"]),
          h("span.hint", { style: { marginLeft: "8px" } },
            "Re-runs each finding's retained oracle_context. Offline, read-only — nothing is sent to any target.")]),
      ]),
      h("div#replay-result", { style: { marginTop: "14px" } }),
    ]);
  }

  function doReplay() {
    var slot = V.$("#replay-result");
    var el = V.$("#replay-input");
    var raw = (el && el.value) || "";
    var doc;
    try { doc = JSON.parse(raw); }
    catch (e) {
      V.mount(slot, h("div.empty", null, [V.statusBadge("refuted"),
        h("p", null, "That is not valid JSON. Paste a VIGIL report.json (with active_findings) or a single finding object.")]));
      return;
    }
    V.mount(slot, h("div.row", { style: { alignItems: "center" } },
      [V.statusBadge("running"), h("span.hint", { style: { marginLeft: "8px" } }, "re-firing proofs offline…")]));
    V.postJSON(OFF("/api/replay"), { doc: doc }).then(function (r) { renderReplayResult(slot, r); })
      .catch(function (e) {
        V.mount(slot, h("div.empty", null, [V.statusBadge("refuted"),
          h("p", null, "Replay failed: " + ((e && e.message) || "offense console unreachable."))]));
      });
  }

  function replayBucketBadge(b) {
    if (b === "reproduced") return V.statusBadge("confirmed");
    if (b === "contradicted") return V.statusBadge("refuted");
    return V.statusBadge("idle");
  }

  function renderReplayResult(slot, r) {
    if (!slot) return;
    if (!r || r.error) {
      V.mount(slot, h("div.empty", null, [V.statusBadge("refuted"),
        h("p", null, "Replay error: " + ((r && r.error) || "unknown"))]));
      return;
    }
    var rows = (r.results || []).map(function (x) {
      var label = x.bucket === "reproduced" ? "REPRODUCED"
        : x.bucket === "contradicted" ? "CONTRADICTED (tampered / won't re-fire)" : "UNGROUNDED (no re-runnable claim)";
      return h("div.card", { style: { marginBottom: "8px" } }, [
        h("div.row", { style: { alignItems: "center" } }, [
          replayBucketBadge(x.bucket),
          h("span", { style: { marginLeft: "8px", fontWeight: "700" } }, label),
          h("span.mono", { style: { marginLeft: "10px" } }, trustShort(x.finding, 40, 10)),
        ]),
        x.confirmed_by ? trustKv("Re-fired oracle",
          x.confirmed_by + (x.confidence != null ? " · confidence " + trustPct(x.confidence) : "")) : null,
        x.note ? h("div.hint", null, x.note) : null,
      ]);
    });
    V.mount(slot, [
      h("div.grid.cols-4", null, [
        V.tile("Findings", String(r.total != null ? r.total : 0)),
        V.tile("Reproduced", String(r.reproduced || 0), "oracle re-fired offline", "ok"),
        V.tile("Contradicted", String(r.contradicted || 0), "tampered / won't re-fire", (r.contradicted ? "bad" : null)),
        V.tile("Ungrounded", String(r.ungrounded || 0), "no re-runnable claim"),
      ]),
      rows.length ? h("div", { style: { marginTop: "12px" } }, rows)
        : h("div.empty", { style: { marginTop: "12px" } }, "No findings in that document."),
    ]);
  }

  // ==========================================================================
  // Governance & Gate audit — a READ/AUDIT-ONLY view of the runtime governance
  // posture: GOVERNED vs UNGOVERNED (entitlement enforced?), the sovereignty tier
  // + seal, the safety-gate conjuncts every action must clear, and the m-of-n
  // destruction quorum read from disk. The web CANNOT provision, authorize, or
  // fire a destructive action — this screen reads state only.
  // ==========================================================================
  function renderGovernance(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Governance & Gate Audit"),
        h("span.sub", null, "Read-only: whether exploitation runs GOVERNED (capability entitlement enforced) "
          + "or UNGOVERNED, the sovereignty tier, the safety-gate conjuncts every action must clear, and the "
          + "m-of-n destruction quorum. This screen cannot provision, authorize, or fire anything.")]),
      h("div#gov-body", null, h("div.empty", null, "Reading governance posture…")),
    ]);
    V.getJSON(OFF("/api/governance")).then(renderGovernanceData).catch(function (e) {
      V.mount(V.$("#gov-body"), offlineEmpty(e, "Could not reach the offense console to read the governance posture. Start it (vigil up) and reload."));
    });
  }

  function renderGovernanceData(d) {
    var body = V.$("#gov-body"); if (!body) return;
    d = d || {};
    var sov = d.sovereignty || null, ent = d.entitlement || null, gate = d.gate || {}, des = d.destruction || {};
    var governed = !!d.governed;

    var postureCard = h("div.card", null, [
      h("div.card-h", null, [h("span.label", null, "posture"), h("h3", null, "Exploitation governance")]),
      h("div.row", { style: { alignItems: "center", marginTop: "4px" } }, [
        V.statusBadge(governed ? "confirmed" : "refuted"),
        h("span", { style: { marginLeft: "8px", fontWeight: "700", fontSize: "15px" } },
          governed ? "GOVERNED — capability entitlement is ENFORCED" : "UNGOVERNED — entitlement not enforced"),
      ]),
      ent ? trustKv("Entitlement", (ent.enforced ? "enforced" : "NOT enforced")
        + (ent.granted_tier ? " · granted tier " + ent.granted_tier : "")) : null,
      ent && ent.explain ? h("div.hint", null, ent.explain) : null,
    ]);

    var sovCard = h("div.card", null, [
      h("div.card-h", null, [h("span.label", null, "sovereignty"), h("h3", null, "Sovereignty tier")]),
      sov ? h("div.row", { style: { alignItems: "center", marginTop: "4px" } }, [
        V.pill(sov.tier || "?", null, null),
        h("span", { style: { marginLeft: "8px" } }, sov.sealed ? "SEALED (latched)" : "not sealed"),
      ]) : h("div.hint", null, "sovereignty policy unavailable."),
    ]);

    var gateCard = h("div.card", null, [
      h("div.card-h", null, [h("span.label", null, "safety gate"), h("h3", null, "Conjunctive gate")]),
      h("div.hint", null, "Every target-touching action must clear ALL of these conjuncts (fail-closed):"),
      h("div.row", { style: { flexWrap: "wrap", marginTop: "6px", gap: "6px" } },
        (gate.conjuncts || []).map(function (c) { return V.pill(c, null, null); })),
    ]);

    V.mount(body, [
      d.note ? h("div.hint", { style: { marginBottom: "10px" } }, d.note) : null,
      h("div.grid.cols-2", null, [postureCard, sovCard]),
      h("div", { style: { marginTop: "12px" } }, gateCard),
      h("div", { style: { marginTop: "12px" } }, renderDestructionCard(des)),
    ]);
  }

  function renderDestructionCard(des) {
    var head = h("div.card-h", null, [h("span.label", null, "m-of-n quorum"),
      h("h3", null, "Destruction authority (read-only audit)")]);
    if (!des || des.present === false) {
      return h("div.card", null, [head,
        h("div.empty", { style: { marginTop: "8px" } }, [V.statusBadge("idle"),
          h("p", null, (des && des.note) || "No destruction trust root provisioned — no m-of-n quorum exists on this host.")])]);
    }
    var tr = des.trust_root || {};
    var pend = des.pending || [];
    var pendRows = pend.map(function (p) {
      return h("div.kv", { style: { marginTop: "4px" } }, [
        h("div.k", null, trustShort(p.action_id || "?", 18, 6)),
        h("div.v", null, [
          p.blast_class ? V.pill(p.blast_class, null, null) : null, " ",
          p.target ? h("span.mono", null, trustShort(p.target, 24, 8)) : null,
          h("span.hint", { style: { marginLeft: "6px" } },
            (p.signature_count || 0) + " of " + (tr.threshold != null ? tr.threshold : "?") + " signatures"),
        ])]);
    });
    return h("div.card", null, [head,
      h("div", null, [
        trustKv("Threshold", "m-of-n: " + (tr.threshold != null ? tr.threshold : "?") + " of "
          + (tr.authorizer_count != null ? tr.authorizer_count : (tr.authorizer_ids || []).length)),
        h("div.kv", null, [h("div.k", null, "Authorizers"), h("div.v", null,
          (tr.authorizer_ids || []).length
            ? (tr.authorizer_ids || []).map(function (id) { return V.pill(id, null, null); }) : "—")]),
        trustKv("Consumed nonces", String(des.consumed_nonce_count != null ? des.consumed_nonce_count : 0)
          + " (spent single-use authorizations)"),
        h("div.kv", { style: { marginTop: "6px" } }, [h("div.k", null, "Pending authorizations"),
          h("div.v", null, pendRows.length ? pendRows : "none")]),
        h("div.hint", { style: { marginTop: "8px" } },
          "Read-only audit — the UI cannot provision, authorize, or fire a destructive action. Minting and "
          + "consuming an authorization happen only via the gated CLI with m-of-n independent signatures."),
      ])]);
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

  // -- the offense event kinds: plain-language label + icon + one-line summary --
  // (14 reasoning/finding kinds + the S5 `agent_message` coordination kind, which is ADVISORY — a message
  //  is never evidence; no fact-building path reads it — so it renders in the `review` lane, not as a finding)
  const KIND_META = {
    observation:   { label: "Observed", icon: "find", cat: "observe",
      sum: function (p) { return (p.source ? p.source + ": " : "") + (p.summary || p.surface || ""); } },
    hypothesis:    { label: "Hypothesis", icon: "brain", cat: "orient",
      sum: function (p) { var head = (p.bug_class || "") + (p.surface ? " @ " + p.surface : "") + (p.status ? " — " + p.status : "");
        var r = (p.rationale || "").trim(); return r ? (head ? head + " — " + r : r) : head; } },
    plan:          { label: "Plan", icon: "assess", cat: "plan",
      sum: function (p) { return p.next_action || p.plan_id || ""; } },
    decision:      { label: "Thinking", icon: "gear", cat: "plan",
      // Show the model's PLAIN-WORDS reasoning (its "why"), like Claude Code narrates — with the chosen
      // action in brackets. Falls back to the question→choice when no rationale was carried.
      sum: function (p) { var r = (p.rationale || "").trim(); var c = p.choice || "";
        return r ? (r + (c ? "  [" + c + "]" : "")) : ((p.question || "") + (c ? " → " + c : "")); } },
    action:        { label: "Action", icon: "bolt", cat: "act",
      sum: function (p) { return (p.tool || "") + (p.args_summary ? " · " + p.args_summary : ""); } },
    tool_call:     { label: "Tool call", icon: "bolt", cat: "act",
      sum: function (p) { return (p.tool || "") + (p.target ? " → " + p.target : "") + (p.args_summary ? " · " + p.args_summary : ""); } },
    result:        { label: "Result", icon: function (p) { return p.success ? "check" : "x"; }, cat: "result",
      sum: function (p) { return (p.success ? "ok" : "fail") + (p.status_code ? " · HTTP " + p.status_code : "") + (p.note ? " · " + p.note : ""); } },
    tool_result:   { label: "Tool result", icon: function (p) { return p.refused ? "x" : (p.ok ? "check" : "dot"); }, cat: "result",
      sum: function (p) { return (p.tool || "") + " · " + (p.refused ? "refused by " + (p.gate || "gate") : (p.ok ? "ok" : "no result"))
        + (p.exit_code != null ? " · exit " + p.exit_code : "") + (p.output_bytes ? " · " + p.output_bytes + " B" : "")
        + (p.summary ? " · " + p.summary : (p.note ? " · " + p.note : "")); } },
    finding:       { label: "Finding", icon: "shield", cat: "finding",
      sum: function (p) { return (p.bug_class || "") + (p.title ? " — " + p.title : (p.summary ? " — " + p.summary : "")); } },
    critique:      { label: "Critique", icon: "book", cat: "review",
      sum: function (p) { return (p.decision || "") + ((p.objections || []).length ? " · " + p.objections.join("; ") : ""); } },
    critic_verdict:{ label: "Critic", icon: "book", cat: "review",
      // The server calibrates a verdict about a LEAD: an objection to a finding that never claimed to be a
      // fact is EXPECTED (advisory only; the oracle stays the authority), so it reads calmly instead of as a
      // "(major)" alarm. A verdict about a real FACT keeps its true severity (an object there is a demotion).
      sum: function (p) {
        var sev = p.display_severity || p.severity;
        if (p.expected) return (p.critic || "") + ": " + (p.verdict || "") + " \u00b7 " + (p.display_note || "routine check — kept as lead");
        return (p.critic || "") + ": " + (p.verdict || "") + (sev ? " (" + sev + ")" : ""); } },
    // A folded run of ROUTINE critic checks on leads (see foldRoutineCritics) — one calm summary row in
    // place of the per-lead triple-flood, so genuine demotions / fact endorsements are not buried.
    critic_summary:{ label: "Critics", icon: "book", cat: "review",
      sum: function (p) { var f = p.findings ? (" across " + p.findings + " lead" + (p.findings === 1 ? "" : "s")) : "";
        return (p.count || 0) + " routine critic checks" + f + " — all correctly kept as leads (no fact affected)"; } },
    reflection:    { label: "Reflection", icon: "brain", cat: "review",
      sum: function (p) { return (p.trigger ? p.trigger + ": " : "") + (p.reorientation || (p.observations || []).join("; ")); } },
    reward:        { label: "Reward", icon: "dot", cat: "review",
      sum: function (p) { return (p.source || "") + (p.signal ? " · " + p.signal : "") + " · r=" + (p.reward != null ? p.reward : "?"); } },
    refusal:       { label: "Refusal", icon: "x", cat: "review",
      // the WHY is the point of a refusal row — carry p.reason through, not just what was refused.
      sum: function (p) { return (p.gate || "gate") + " refused: " + (p.action_refused || "")
        + (p.fatal ? " (fatal)" : "") + (p.reason ? " — " + p.reason : ""); } },
    agent_message: { label: "Message", icon: "brain", cat: "review",
      sum: function (p) { return (p.sender || "?") + " → " + (p.recipient || "?") + (p.topic ? " [" + p.topic + "]" : "") + (p.body ? " · " + p.body : "") + " · advisory coordination (not evidence)"; } },
    // E1 — a fireteam MEMBER's step, attributed by role, so the operator watches multiple agents work on
    // different tasks. A member's claim is a LEAD until the oracle re-fires over it in collect() — the
    // summary says so, and this never wears the confirmed-finding register.
    fireteam:      { label: "Fireteam member", icon: "brain", cat: "act",
      sum: function (p) { return (p.role || p.member_id || "member") + (p.step ? " · " + p.step : "")
        + (p.summary ? ": " + p.summary : "") + " · member lead (oracle-pending)"; } },
  };
  function kindIcon(kind, p) { const m = KIND_META[kind]; if (!m) return "dot"; return typeof m.icon === "function" ? m.icon(p || {}) : m.icon; }
  function isFact(p) { return !!(p && p.verified_by_oracle); }

  // Fold a run of consecutive ROUTINE critic verdicts (those about LEADS — see the server's
  // _calibrate_critic) into ONE calm summary row, so the per-lead critic-triple flood cannot bury a
  // genuine demotion or a fact endorsement. Pure over the events array (applied at render), so it is
  // robust to incremental/streaming arrival. Non-routine verdicts (about real facts) pass through
  // untouched and stay individually visible. A short run (< 4) is left as-is — nothing to collapse.
  function foldRoutineCritics(events) {
    var out = [], i = 0, n = events.length;
    while (i < n) {
      var e = events[i], p = e.payload || {};
      if (e.kind === "critic_verdict" && p.routine) {
        var j = i, cnt = 0, last = e, targets = {};
        while (j < n && events[j].kind === "critic_verdict" && (events[j].payload || {}).routine) {
          cnt++; last = events[j];
          var tg = (events[j].payload || {}).target_event_id;
          if (tg != null) targets[tg] = 1;
          j++;
        }
        if (cnt >= 4) {
          out.push({ kind: "critic_summary", id: last.id, posted_at: last.posted_at,
                     payload: { count: cnt, findings: Object.keys(targets).length } });
        } else { for (var k = i; k < j; k++) out.push(events[k]); }
        i = j;
      } else { out.push(e); i++; }
    }
    return out;
  }

  // ---- New Assessment wizard -------------------------------------------------
  const TARGET_TYPES = [
    { mode: "codebase", icon: "book", t: "Scan a codebase", d: "Point at a local path or repo. Deterministic DAA static scan (fix-enabled, no Docker) by default; Strix agent optional." },
    { mode: "url", icon: "live", t: "Scan a website / API", d: "Give a URL; VIGIL engages it through the full gate. A 127.0.0.1 target runs a quick loopback scan." },
    { mode: "tool", icon: "bolt", t: "Run one tool", d: "Pick one real tool from this host's roster and run the gated engagement that drives it." },
    { mode: "suite", icon: "brain", t: "Full autonomous suite", d: "The autonomous OODA loop drives the whole arsenal (gated, oracle-adjudicated)." },
    { mode: "cloud", icon: "live", t: "Cloud / K8s posture", d: "Seedless posture review of a cloud account or Kubernetes cluster (needs a signed charter)." },
    { mode: "aegis", icon: "shield", t: "Defend an app (AEGIS)", d: "Run the defensive dual over your telemetry/logs to detect AI attacks." },
  ];
  // Seedless cloud/K8s/infra posture sub-modes (map to actions.launch_cloud `mode`); `cloud` also needs a provider.
  const CLOUD_MODES = [
    { id: "cloud", label: "Cloud account", d: "Posture over an imported cloud inventory (names a provider)." },
    { id: "k8s", label: "Kubernetes", d: "kube-bench-style posture over a cluster label." },
    { id: "infra", label: "Declared service", d: "Posture over a declared-service inventory." },
  ];
  const CLOUD_PROVIDERS = ["aws", "gcp", "azure"];
  const ENGAGE_MODES = { url: true, tool: true, suite: true };  // modes that spawn `engage`/`scan`

  // ==========================================================================
  // "Run one tool" — the host's REAL tools, and which of them a launch can drive
  // ==========================================================================
  // This picker reads `/api/toolprofiles` — the engine's own joined roster (install status + live
  // version, the admission verdict WITH its honest refusal reason, and the control surface that says
  // HOW each tool is driven) — instead of the capability packs, which are not tools at all.
  //
  // A picked tool still has to BECOME something. `launch_assessment` maps every entry of the `tools`
  // array through its capability table and SILENTLY DROPS any id it does not recognise, so posting a
  // bare binary name would start a plain engagement that never runs the tool the operator chose, and
  // the report would look complete. A tool is therefore selectable here exactly when a gated engage
  // flag really drives that binary — read out of the engine, not assumed:
  //
  //   chromium → --browser-xss : scanner/campaign.py:_maybe_start_browser() resolves it through
  //              scanner/browser.py:find_browser and the DOM-XSS pass confirms by real execution.
  //
  // Every other admitted tool is driven somewhere this launcher cannot reach: a sensor fires only
  // inside an engagement whose fusion plan names it, the SAST backends belong to the `analysis` pass,
  // and the typed-argv tools are built by the live `vigil engage` executor. Those stay LISTED, showing
  // what does drive them, and unselectable. A control that pretends is worse than one honestly out of
  // reach — and hiding an installed tool would only leave the operator hunting for it.
  //
  // WHY THE PHASE-GATE RULE DOES NOT PROMOTE OR DEMOTE ANYTHING HERE. `integration/.../live/wiring.py`
  // DEFAULT_TOOL_VIEW is the fail-closed phase manifest for the live executor: a tool missing from it is
  // denied in EVERY phase, which is how three tools once shipped "controllable" while the engine refused
  // every call. That manifest governs USE_TOOL actions on the `vigil engage` path — a path this wizard
  // never takes (it spawns `python -m framework.v2 engage`). So it can neither rescue nor condemn an
  // entry above, and both directions are traps worth naming:
  //   * Being IN it is not a licence to list a tool. nmap/httpx/nuclei/ffuf/sqlmap/hydra/nikto/wapiti/
  //     zaproxy are all listed there, and every one is still unselectable here, because no capability
  //     flag on THIS launcher's argv runs them — `--arsenal` is the advanced WEB arsenal (content/JS
  //     discovery, smuggling, CSWSH), not the host-CLI arsenal its capability blurb claims.
  //   * Being ABSENT from it is not a reason to drop chromium. Its capability never issues a USE_TOOL:
  //     `--browser-xss` makes the scanner campaign resolve and spawn the browser itself, so the phase
  //     manifest is not on that code path at all.
  // The test that decides selectability is therefore only ever: does a flag this launcher really passes
  // drive that binary? Verified by running it — `tools:["browser-xss"]` puts `--browser-xss` on the argv,
  // while a bare `tools:["nmap"]` is silently dropped by launch_assessment and starts an ordinary run.
  const TOOL_LAUNCH = {
    chromium: { cap: "browser-xss",
      how: "the Browser XSS capability starts it headless and confirms DOM XSS by real execution" },
  };
  // control_surface -> plain language for the roster row.
  const SURFACE_LABEL = { cli: "its own CLI", sensor: "a gated sensor", analyzer: "the source-analysis pass",
    browser: "the headless browser", background: "a background driver" };
  // Every driver the profile actually reports, in its own words. The roster exposes these as separate
  // booleans and `control_surface` only names the winner, so a tool with BOTH a typed argv builder and a
  // gated sensor (nmap, nuclei, zaproxy) reports "cli" and its sensor would go unmentioned. Reading the
  // booleans says all of what drives it — which is the whole point of listing an unreachable tool.
  const TOOL_DRIVERS = [
    ["has_typed_builder", "the live `vigil engage` executor builds it a gated command"],
    ["has_skill_doc", "the codebase agent knows its CLI from a playbook"],
    ["has_sensor", "a gated sensor runs it when an engagement's fusion plan names it"],
    ["has_analyzer", "the source-analysis pass runs it"],
    ["has_browser_driver", "the scanner launches it as its headless browser"],
  ];
  function toolDrivers(p) {
    const out = [];
    TOOL_DRIVERS.forEach(function (d) { if (p && p[d[0]]) out.push(d[1]); });
    return out;
  }

  // Can THIS wizard start this tool? Returns {ok, why} and, when ok, the capability id the launch
  // must carry. Every negative carries the real reason, in the order the operator would hit them.
  function toolPickable(p) {
    if (!p) return { ok: false, why: "unknown tool" };
    if (!p.admitted) return { ok: false, why: p.admit_reason || "not admitted to the arsenal" };
    if (!p.installed) {
      return { ok: false, why: (p.status === "unsupported" ? "not supported on this platform" : "not installed on this host")
        + " — install it from the Tools screen" + (p.apt ? " (apt: " + p.apt + ")" : "") };
    }
    const L = TOOL_LAUNCH[String(p.name || "")];
    if (!L) {
      const drivers = toolDrivers(p);
      return { ok: false, why: "no assessment flag runs it on its own"
        + (drivers.length ? "; driven elsewhere: " + drivers.join(" · ") : "") };
    }
    return { ok: true, cap: L.cap, why: L.how };
  }
  function capLabelOf(caps, id) {
    for (let i = 0; i < (caps || []).length; i++) if (caps[i].id === id) return caps[i].label || id;
    return id || "—";
  }
  function capsOf(d) { return (d && d.caps) || (d && d.capabilities) || []; }

  function renderAssess(screen) {
    // `tool` is the TOOL the operator picked (what they see); `tools` is what the launch payload can
    // actually carry — the capability id that drives it. Keeping both means the summary can name the
    // tool while the request stays something the server really honours.
    const W = { step: 1, mode: "", target: "", slug: "", authorized: false, mount: false, cbEngine: "daa",
      scope: [], scopeInput: "", objective: "", scan_mode: "standard", aiTools: true,
      tool: "", tools: [], apply_fixes: false, aegis_action: "detect",
      session_id: "", graph_backed: false, sessions: [],
      cloud_mode: "cloud", provider: "aws",
      caps: null, profiles: null, profilesErr: false, kernel: null, launching: false,
      // W17-9: the server's PRE-Send engine plan — WHICH engine will run and WHY, naming the unmet
      // conjunct of the agentic gate (no session / remote target / `vigil` not on PATH). Read-only.
      enginePlan: null };
    // real capability catalog + backend/LLM status (never hardcoded)
    V.getJSON(OFF("/api/capabilities")).then(function (d) { W.caps = d; draw(); }).catch(function () { W.caps = { capabilities: [], scan_modes: [] }; });
    V.getJSON(OFF("/api/kernel")).then(function (d) { W.kernel = d; draw(); }).catch(function () { W.kernel = { backends: [] }; });
    // the host's REAL tool roster — what "Run one tool" offers (see TOOL_LAUNCH above). The endpoint is
    // _safe-wrapped server-side: a probe failure answers 200 with an empty list AND an `error`, so an
    // empty list alone must not be reported as "this host has no tools".
    V.getJSON(OFF("/api/toolprofiles")).then(function (d) {
      W.profiles = (d && d.profiles) || []; W.profilesErr = !!(d && d.error); draw();
    }).catch(function () { W.profiles = []; W.profilesErr = true; draw(); });
    // permanent sessions (F2) — optional; a graph-backed loopback run partitions this session's Neo4j graph.
    V.getJSON(OFF("/api/sessions")).then(function (d) { W.sessions = (d && d.sessions) || []; draw(); }).catch(function () { W.sessions = []; });

    function set(patch) { Object.assign(W, patch); draw(); }
    function isEngage() { return !!ENGAGE_MODES[W.mode]; }
    function isLoopback() { return isLoopbackHost(hostOf(W.target)); }

    function stepValid(n) {
      if (n === 1) return !!W.mode;
      if (n === 2) {
        if (W.mode === "codebase") return !!W.target.trim() && W.authorized;
        if (W.mode === "aegis") return !!W.target.trim();
        if (W.mode === "cloud") return !!W.target.trim() && !!W.slug.trim() && W.authorized
          && (W.cloud_mode !== "cloud" || !!W.provider);
        return isURL(W.target) && W.authorized;
      }
      if (n === 3) return true;   // scope is optional / validated on launch
      if (n === 4) {
        // one tool mode: a tool must be picked AND have resolved to a capability the launch really carries
        if (W.mode === "tool") return !!W.tool && W.tools.length === 1;
        return true;
      }
      return true;
    }
    function canLaunch() { return stepValid(1) && stepValid(2) && stepValid(3) && stepValid(4) && !W.launching; }

    // WHICH BRANCH ACTUALLY CARRIES A CAPABILITY PACK — ONE definition, read by the picker AND by the
    // launch payload, so the control the operator sees and the control the request sends can never
    // disagree. Only `launch_assessment`'s engage branch turns a pack id into a flag. A `url` run against
    // loopback goes to the deterministic quick-scan CLI and a graph-backed run to the `vigil` bridge, and
    // NEITHER reads `tools`: five ticked packs produced a run with none of them on its argv, reporting
    // "running", with nothing on screen saying the run was narrower than the one just configured. The
    // server now names that gap in `tools_note`; this stops the wizard asking for it in the first place.
    // (`tool` mode always engages, loopback or not, so its one capability is never filtered.)
    function wantsGraph() { return !!(W.graph_backed && W.session_id && isLoopback()); }
    function packsRun() {
      if (W.mode === "tool") return true;
      return !(wantsGraph() || (W.mode === "url" && isLoopback()));
    }

    // W17-9: the body the preflight scores — the SAME fields the launch payload sends, so the plan the
    // operator reads cannot disagree with the engine the run picks. `agentic` mirrors the graph-backed
    // opt-in the wizard offers today (loopback + session); `graph_backed` is the legacy alias the server
    // also honours. Only the fields the routing/gate reads are included.
    // A codebase scan runs one of two engines: the DETERMINISTIC DAA static oracle (default — no Docker, and
    // the ONLY codebase path that grounds a gated fix in the signed spine) launches as mode "sast"; the Strix
    // agent (Docker + LLM) launches as "codebase". The wizard keeps its internal mode "codebase" either way so
    // its config/gating/review all apply; only the LAUNCH mode is remapped here.
    function launchMode() { return (W.mode === "codebase" && W.cbEngine !== "strix") ? "sast" : W.mode; }
    function planBody() {
      return { mode: launchMode(), target: W.target.trim(), slug: W.slug.trim(),
        session_id: W.session_id, agentic: !!W.graph_backed, graph_backed: !!W.graph_backed,
        cloud_mode: W.cloud_mode };
    }
    // Fetch the server's engine plan and re-render the summary in place. Read-only (`/api/launch/preview`
    // spawns nothing). The `vigil`-on-PATH conjunct is a SERVER fact the page cannot know locally, so this
    // is how the UI can name it BEFORE Send. Fire-and-forget; a failure leaves the last plan (or none).
    function refreshPlan() {
      if (W.mode === "cloud") { W.enginePlan = null; return; }
      V.postJSON(OFF("/api/launch/preview"), planBody()).then(function (r) {
        if (r && !r.error) { W.enginePlan = r; const s = V.$("#wiz-summary"); if (s) V.mount(s, summaryCard()); }
      }).catch(function () { /* leave the prior plan; never block the wizard on a preflight */ });
    }

    function goto(n) { if (n > W.step && !stepValid(W.step)) { V.toast("Please complete this step first."); return; } set({ step: Math.max(1, Math.min(5, n)) }); }

    // ---- step bodies ----
    function stepTargetType() {
      return h("div.wizbody", null, [
        h("h2", null, "What do you want to assess?"),
        h("p.helper", null, "Pick the kind of target. Everything after adapts to this choice."),
        h("div.choice-grid", null, TARGET_TYPES.map(function (tt) {
          const sel = W.mode === tt.mode;
          return h("button.choice" + (sel ? ".sel" : "") + (tt.mode === "aegis" ? ".defense" : ""),
            { onClick: function () { set({ mode: tt.mode, step: 2, tool: "", tools: [], aiTools: tt.mode !== "tool" }); } },
            [h("span.cico", null, V.icon(tt.icon)), h("div", null, [h("div.ct", null, tt.t), h("div.cd", null, tt.d)])]);
        })),
      ]);
    }
    function stepWhere() {
      const rows = [];
      if (W.mode === "codebase") {
        rows.push(field("Scan engine",
          h("select", { onChange: function (e) { W.cbEngine = e.target.value; updateSummary(); refreshFoot(); draw(); } }, [
            h("option", { value: "daa", selected: W.cbEngine !== "strix" }, "Deterministic DAA — static rules, no Docker, fix-enabled"),
            h("option", { value: "strix", selected: W.cbEngine === "strix" }, "Strix agent — Docker + LLM, broader"),
          ]),
          W.cbEngine === "strix"
            ? "The vendored Strix agent chooses its own analysis passes (needs Docker + a model). Findings are model-driven."
            : "DAA runs deterministic static rules over the source and writes each finding into the signed spine, so a gated fix can be applied and re-verified. No Docker, no model needed to scan."));
        rows.push(field("Codebase path", h("input", { type: "text", value: W.target, placeholder: "/home/you/project  or  https://github.com/org/repo",
          onInput: function (e) { W.target = e.target.value; updateSummary(); refreshFoot(); } }),
          W.cbEngine === "strix" ? "A local path (or a git URL Strix can clone). Large trees: use bind-mount below."
                                 : "A local path (or a git URL to clone). DAA reads the source read-only."));
        if (W.cbEngine === "strix")
          rows.push(checkbox("Bind-mount instead of copy (large monorepos)", W.mount, function (v) { W.mount = v; }));
      } else if (W.mode === "aegis") {
        rows.push(field("Telemetry / log file", h("input", { type: "text", value: W.target, placeholder: "/path/to/telemetry-envelope.json",
          onInput: function (e) { W.target = e.target.value; updateSummary(); refreshFoot(); } }), "AEGIS detect runs its defensive oracles over one TelemetryEnvelope/log file."));
      } else if (W.mode === "cloud") {
        rows.push(field("Assessment type",
          h("select", { onChange: function (e) { W.cloud_mode = e.target.value; if (W.cloud_mode !== "cloud") W.provider = ""; else if (!W.provider) W.provider = "aws"; draw(); } },
            CLOUD_MODES.map(function (m) { return h("option", { value: m.id, selected: m.id === W.cloud_mode }, m.label); })),
          (CLOUD_MODES.find(function (m) { return m.id === W.cloud_mode; }) || {}).d || ""));
        if (W.cloud_mode === "cloud") {
          rows.push(field("Cloud provider",
            h("select", { onChange: function (e) { W.provider = e.target.value; updateSummary(); refreshFoot(); } },
              CLOUD_PROVIDERS.map(function (p) { return h("option", { value: p, selected: p === W.provider }, p.toUpperCase()); })),
            "Named on the task for operator context; the sensor reads your imported inventory, never the live account."));
        }
        rows.push(field("Cloud target label", h("input", { type: "text", value: W.target, placeholder: "prod-account-1234   or   cluster: staging-eks",
          onInput: function (e) { W.target = e.target.value; updateSummary(); refreshFoot(); } }),
          "An account id / subscription / project / cluster label — NOT a URL, CIDR, or path. Posture is seedless (no traffic to the account)."));
        rows.push(field("Engagement slug", h("input#wiz-slug", { type: "text", value: W.slug, placeholder: "cloud-prod",
          onInput: function (e) { W.slug = e.target.value; updateSummary(); refreshFoot(); } }),
          "Names the charter + reasoning spine. A cloud/K8s posture needs a SIGNED charter under this slug (the console cannot mint it)."));
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
          // It is NOT recorded with the run: the launch body carries no `authorized` field and the
          // launcher reads none, so claiming it was recorded put a promise on screen that no file keeps.
          h("div.hint", null, "VIGIL is for authorized testing only. This box gates the wizard — it is not "
            + "sent with the launch and nothing stores it. The binding authorization is the signed charter "
            + "and scope the engine enforces for this slug."),
        ]));
      }
      // A cloud/K8s posture goes to its own launcher, whose request carries slug/mode/target/provider and
      // nothing else — an objective typed here would be dropped on the floor, so it is not offered.
      if (W.mode !== "cloud") {
        rows.push(field("Objective (optional)", h("textarea", { placeholder: "e.g. focus on authentication and access control",
          onInput: function (e) { W.objective = e.target.value; updateSummary(); } }, W.objective),
          W.mode === "codebase"
            ? "Handed to the agent as its instruction — this one really steers the run. It never widens scope."
            : "Recorded with the run for your own record. The gated engagement takes no free-text objective, "
              + "so it does NOT steer this run — use Depth and the capability packs for that."));
      }
      return h("div.wizbody", null, [h("h2", null, "Where is it?"),
        h("p.helper", null, "Tell VIGIL exactly what to point at, and confirm you're allowed to."), h("div", null, rows)]);
    }
    function syncSlug() { const el = V.$("#wiz-slug"); if (el) el.value = W.slug; }
    function stepScope() {
      if (!isEngage()) {
        const helper = W.mode === "codebase"
          ? "A codebase scan reads source only — it sends no traffic, so there is no network scope to set."
          : W.mode === "cloud"
            ? "A cloud/K8s posture is seedless — it reads your imported inventory, so there is no network scope to set. Its authority is the signed charter for the slug."
            : "AEGIS reads your telemetry defensively — there is no offensive scope to set.";
        const legend = W.mode === "cloud"
          ? [V.icon("key"), "Needs a SIGNED charter under slug " + (W.slug.trim() ? "\"" + W.slug.trim() + "\"" : "(set one)") + " — the console cannot mint it."]
          : [V.icon("info"), "Nothing to configure here for this mode."];
        return h("div.wizbody", null, [h("h2", null, "Scope"),
          h("p.helper", null, helper), h("div.legend", null, legend)]);
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
    // -- the REAL tool roster (only for "Run one tool") -----------------------
    // Every tool the engine knows about is shown, installed or not, admitted or not. Selecting one
    // sets BOTH `tool` (what the operator picked) and `tools` (the capability id the launch carries),
    // so the thing that leaves the browser is the thing the launcher actually acts on.
    function toolRosterField() {
      if (W.profiles == null) return h("div.field", null, h("div.muted", null, "Reading this host's tool roster…"));
      if (!W.profiles.length) {
        return h("div.field", null, h("div.muted", null, W.profilesErr
          ? "Tool roster unavailable — the offense engine could not probe this host. Start it (`vigil up`) and reload."
          : "This host reports no tools at all."));
      }
      const rows = W.profiles.map(function (p) {
        const v = toolPickable(p);
        const on = W.tool === p.name;
        const cls = ".toolpick" + (v.ok ? "" : ".off") + (on ? ".sel" : "");
        const kids = [
          h("div.tp-h", null, [
            h("span.tp-n.mono", null, p.name),
            p.installed ? h("span.pill.sm.live", null, "installed")
              : h("span.pill.sm.idle", null, p.status === "unsupported" ? "not supported here" : "not installed"),
            h("span.pill.sm", null, "driven by " + (SURFACE_LABEL[String(p.control_surface || "")] || "nothing yet")),
            p.admitted ? null : h("span.pill.sm.danger", null, "not admitted"),
            on ? h("span.pill.sm.live", null, [V.icon("check"), "picked"]) : null,
          ]),
          p.purpose ? h("div.tp-p", null, p.purpose) : null,
          h("div.tp-w" + (v.ok ? ".yes" : ""), null, v.ok
            ? ["Runs here: " + v.why + " (capability “" + capLabelOf(capsOf(W.caps), v.cap) + "”)."]
            : ["Not startable here — " + v.why + "."]),
        ];
        if (!v.ok) return h("div" + cls, null, kids);
        return h("button" + cls, { onClick: function () {
          set(on ? { tool: "", tools: [] } : { tool: p.name, tools: [v.cap] });
        } }, kids);
      });
      const n = W.profiles.filter(function (p) { return toolPickable(p).ok; }).length;
      return h("div.field", null, [
        h("label", null, "Pick one tool"),
        h("div.hint", { style: { marginBottom: "10px" } },
          "These are the real tools on this host, exactly as the engine's roster reports them — not capability "
          + "packs. " + n + " of " + W.profiles.length + " can be started from this wizard; the rest are listed "
          + "with whatever does drive them, so an installed tool never just disappears."),
        h("div.toolpick-list", null, rows),
        n ? null : h("div.legend", { style: { marginTop: "10px" } }, [V.icon("info"),
          "Nothing on this host can be started as a single tool right now. Pick “Scan a website / API” and add "
          + "capability packs instead, or run the tool from the Tools screen."]),
      ]);
    }

    function stepMode() {
      const caps = capsOf(W.caps);
      const modes = (W.caps && W.caps.scan_modes) || [{ id: "quick", label: "Quick" }, { id: "standard", label: "Standard" }, { id: "deep", label: "Deep" }];
      const body = [];
      if (isEngage()) {
        body.push(field("Depth", h("div.choice-grid", null, modes.map(function (m) {
          const sel = W.scan_mode === m.id;
          return h("button.choice" + (sel ? ".sel" : ""), { onClick: function () { set({ scan_mode: m.id }); } },
            [h("div", null, [h("div.ct", null, m.label), h("div.cd", null, m.purpose || "")])]);
        })), "Sets the run's page/request budget. A loopback scan also runs targeted at Quick depth."));
        if (W.mode === "tool") {
          body.push(toolRosterField());
        } else if (!packsRun()) {
          // THIS RUN CANNOT CARRY A PACK (see `packsRun`), so it does not offer one. A dead picker here
          // is the whole defect: the operator ticks packs, the launch answers "running", and not one of
          // them reaches the argv. `W.tools` is deliberately NOT cleared — the payload filters it, and
          // clearing during a render would throw away picks made for a non-loopback host the moment the
          // operator stepped back to look at the target.
          body.push(h("div.legend", null, [V.icon("info"), wantsGraph()
            ? "Capability packs are not part of a graph-backed run — it goes through the `vigil` bridge, "
              + "which takes no pack flags. Untick “graph-backed” on the previous step to add them."
            : "Capability packs are not part of a loopback quick-scan — this target runs the deterministic "
              + "scanner, which takes no pack flags. Its standard audit runs in full. To add packs, run a "
              + "Full engagement suite, or point the assessment at a non-loopback host."]));
        } else {
          // NOT "let the AI choose the tools": nothing chooses capability packs for you. On simply means
          // no extra flags are added, and the engagement runs its standard audit. (In a Full autonomous
          // suite the OODA planner does choose each next ACTION — that is the --autonomous loop, and it
          // happens whether or not this box is ticked.)
          body.push(h("div.field", null, [
            h("label", { class: "row-flex", style: { cursor: "pointer" } }, [
              h("input", { type: "checkbox", checked: W.aiTools, style: { width: "auto" },
                onChange: function (e) { set({ aiTools: e.target.checked }); } }),
              h("span", null, "Run the engine's standard set (recommended)."),
            ]),
            h("div.hint", null, W.mode === "suite"
              ? "On: the engagement runs its standard audit and the autonomous loop picks each next action. "
                + "Off: you also add specific gated capability packs. The loop chooses actions either way — "
                + "nothing chooses the packs for you."
              : "On: the engagement runs its standard audit and no extra flags are added. Off: you choose "
                + "exactly which gated capability packs are added to it."),
          ]));
          if (!W.aiTools) {
            body.push(h("div.field", null, [
              h("label", null, "Add capability packs"),
              h("div.hint", { style: { marginBottom: "8px" } },
                "These are capability PACKS, not individual tools — each maps to one already-gated engage flag. "
                + "To run one of this host's actual tools, pick “Run one tool” back on step 1."),
              caps.length ? h("div", { style: { display: "flex", flexWrap: "wrap", gap: "8px" } }, caps.map(function (c) {
                const on = W.tools.indexOf(c.id) >= 0;
                return h("button.pill" + (on ? ".live" : ""), { title: c.purpose || "",
                  onClick: function () {
                    const i = W.tools.indexOf(c.id); if (i >= 0) W.tools.splice(i, 1); else W.tools.push(c.id);
                    draw();
                  } }, [on ? V.icon("check") : null, c.label, h("span.muted", { style: { fontSize: "var(--fs-micro)" } }, " " + c.tier)]);
              })) : h("div.muted", null, "Capability catalog unavailable (offense engine offline)."),
              h("div.hint", null, "Nothing here can widen authority — a pack only adds a flag the gate already governs."),
            ]));
          }
        }
        body.push(fixesCheckbox());
      } else {
        const legendTxt = W.mode === "codebase" ? (W.cbEngine === "strix" ? "Strix chooses its own analysis passes over the source." : "DAA runs deterministic static rules over the source; each finding is written to the signed spine (fix-enabled).")
          : W.mode === "cloud" ? "The posture sensor runs its full deterministic check set over your imported inventory."
            : "AEGIS runs its full defensive oracle set over the telemetry.";
        body.push(h("div.legend", null, [V.icon("info"), legendTxt]));
        if (W.mode !== "cloud") body.push(fixesCheckbox());
      }
      return h("div.wizbody", null, [h("h2", null, "How should it run?"),
        h("p.helper", null, W.mode === "tool"
          ? "Choose how deep it goes, and which of this host's tools to run."
          : "Choose how deep it goes, and which capabilities run."), h("div", null, body)]);
    }
    // `apply_fixes` is RECORDED on the run and echoed by the Fixes screen; it starts nothing and changes
    // no flag. "Apply fixes after discovery" read like it scheduled work, so it says what it does instead.
    function fixesCheckbox() {
      return checkbox("Flag this run as one I want fixed", W.apply_fixes, function (v) { W.apply_fixes = v; },
        "Recorded with the run and shown on the Fixes screen, which lists the fixable findings and the gated "
        + "ladder either way. Ticking it applies nothing — a real fix is a separate, signed, gated step.");
    }
    // What a run of THIS mode actually does with a model. Read out of the engine rather than assumed:
    // `framework.v2 engage` / `scan` / `aegis` import no LLM backend at all (only __main__, the console
    // API and the sovereignty policy do), so a url / one-tool / AEGIS / cloud run is deterministic end to
    // end. `--autonomous` is the one exception — it calls the reasoning kernel for ONE bounded ADVISORY
    // step per cycle and degrades to the deterministic dry-run backend with no key. A codebase run IS the
    // model: the Strix agent is the thing that reads the source.
    function modelNeed() {
      if (W.mode === "codebase") {
        return { key: true, txt: "A codebase scan IS the model — the Strix agent reads and reasons over your "
          + "source. Without a working backend it has nothing to run." };
      }
      if (W.mode === "suite") {
        return { key: false, txt: "The audit itself is deterministic. The autonomous loop additionally takes one "
          + "bounded ADVISORY reasoning step per cycle; with no backend it falls back to the engine's "
          + "deterministic advice and the run still completes. Advice never confirms a finding — only an "
          + "oracle does." };
      }
      if (W.mode === "aegis") {
        return { key: false, txt: "AEGIS detect runs its deterministic defensive oracles over your telemetry "
          + "file. It calls no model." };
      }
      if (W.mode === "cloud") {
        return { key: false, txt: "A cloud / Kubernetes posture is deterministic sensor fusion over your "
          + "imported inventory. It calls no model." };
      }
      return { key: false, txt: "A website / API / one-tool engagement is deterministic — the offense engine "
        + "calls no model at all. Findings come from oracles, not from a model." };
    }
    function stepModel() {
      const backends = (W.kernel && W.kernel.backends) || [];
      const live = backends.filter(function (b) { return b.available; });
      const status = W.kernel == null ? "Checking…"
        : (live.length ? live.map(function (b) { return b.name; }).join(", ") + " available"
          : "No live LLM backend detected — add a key in Settings.");
      const need = modelNeed();
      // There is no "run keyless" switch here any more. It was accepted, written to the run's meta and
      // read by nothing: the offense CLIs never call a model, so those runs were already keyless, and a
      // codebase run needs Strix's model whether or not the box was ticked. Saying which is which is the
      // honest version of the same information.
      const body = [
        h("div.field", null, [h("label", null, "Does this run need a model?"),
          h("div.legend", null, [V.icon(need.key ? "key" : "check"), need.txt]),
          need.key
            ? h("div.hint", { style: { marginTop: "8px" } }, "Backends: " + status
                + ". The model and key come from the environment (Settings) — keys are never shown or entered here.")
            : h("div.hint", { style: { marginTop: "8px" } }, "Backends (for the screens that do use one): "
                + status + ". Keys are never shown or entered here."),
        ]),
      ];
      if (W.mode === "cloud") {
        // launch_cloud takes slug / mode / target / provider and nothing else — no session id, so it
        // never links the run. Offering the picker here would have quietly detached the run instead.
        body.push(h("div.legend", null, [V.icon("info"),
          "A cloud / Kubernetes posture attaches to its engagement slug and signed charter, not to a session — "
          + "the cloud launcher takes no session, so none is offered here."]));
      } else {
        // F2/F3/F4: attach this run to a permanent session, and (loopback only) run it GRAPH-BACKED so it
        // accumulates in — and reuses — that session's Neo4j knowledge graph via the integration `vigil engage`.
        body.push(field("Session (optional)",
          h("select", { onChange: function (e) { W.session_id = e.target.value; if (!W.session_id) W.graph_backed = false; updateSummary(); draw(); } },
            [h("option", { value: "", selected: !W.session_id }, "— none —")].concat(
              (W.sessions || []).map(function (s) { return h("option", { value: s.id, selected: s.id === W.session_id }, s.name || s.id); }))),
          "Runs sharing a session accumulate and reuse each other's prior context."));
        if (W.session_id && isLoopback()) {
          body.push(checkbox("Graph-backed run (accumulate in this session's knowledge graph)", W.graph_backed,
            function (v) { W.graph_backed = v; },
            "Loopback only. Routes the run through `vigil engage --session` so its facts partition this "
            + "session's Neo4j graph (and union any connected sessions). If `vigil`/Neo4j isn't available it "
            + "falls back to the normal engine — and this screen will tell you so at launch."));
        }
      }
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
      if (W.mode === "cloud") {
        const cm = CLOUD_MODES.find(function (m) { return m.id === W.cloud_mode; });
        put("Type", cm ? cm.label : (W.cloud_mode || "—"));
        if (W.cloud_mode === "cloud") put("Provider", (W.provider || "—").toUpperCase());
        put("Cloud target", W.target || "—");
        put("Slug", W.slug || "—");
      } else {
        put("Target", W.target || "—");
        if (isEngage()) put("Scope", isLoopback() ? "127.0.0.1 (loopback)" : (W.scope.length ? W.scope.join(", ") : "(host only)"));
        if (isEngage()) put("Slug", W.slug || slugify(hostOf(W.target), "engagement"));
        if (isEngage()) put("Depth", W.scan_mode);
        if (isEngage()) {
          // Read through the SAME `packsRun` the payload uses. Picks made for a non-loopback host are
          // kept in `W.tools` when the operator steps back and retargets at loopback (losing them to a
          // redraw would be its own defect) — so without this the summary would still list them while
          // the request no longer carries them, which is the exact mismatch this whole fix is about.
          put("Tools", W.mode === "tool"
            ? (W.tool ? W.tool + " · via the " + capLabelOf(capsOf(W.caps), W.tools[0]) + " capability" : "—")
            : !packsRun() ? "engine standard set (this run takes no capability packs)"
              : (W.aiTools ? "engine standard set" : (W.tools.join(", ") || "none")));
        }
        // objective only reaches the run for a codebase (--instruction); elsewhere it is recorded, not acted on
        if (W.objective.trim()) {
          put("Objective", W.mode === "codebase" ? "steers the agent" : "recorded only (does not steer)");
        }
        put("Fixes", W.apply_fixes ? "flagged (nothing auto-applies)" : "off");
      }
      put("Model", modelNeed().key ? "needed (the agent reads your source)"
        : (W.mode === "suite" ? "optional (advisory reasoning only)" : "not used (deterministic run)"));
      // W17-9: state WHICH engine will run BEFORE Send, and — when the agentic engine was requested but a
      // conjunct is unmet (no session / remote target / `vigil` not on PATH) — name that reason, so the
      // operator is never surprised after the fact by a silent fall-through to the plain offense engine.
      const engineRows = [];
      if (W.mode !== "cloud" && W.enginePlan) {
        const p = W.enginePlan;
        engineRows.push(h("div.kv", null, [h("div.k", null, "Engine"),
          h("div.v", null, p.engine_label || p.engine || "—")]));
        if (p.agentic_requested && p.agentic_unmet) {
          engineRows.push(h("div.legend", { style: { marginTop: "10px" } }, [V.icon("info"),
            "Agentic engine will NOT run — " + (p.agentic_unmet_reason || p.why || "a condition is unmet")
            + "."]));
        } else if (p.why) {
          engineRows.push(h("div.hint", { style: { marginTop: "6px" } }, p.why));
        }
      }
      return V.card("What will happen", "SUMMARY", h("div", null, [
        h("div.stack", { style: { gap: "8px" } }, rows),
        engineRows.length ? h("div.stack", { style: { gap: "8px", marginTop: "12px" } }, engineRows) : null,
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
    function updateSummary() { const s = V.$("#wiz-summary"); if (s) V.mount(s, summaryCard()); refreshPlan(); }
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
      // Seedless cloud/K8s/infra posture → its own gated action (needs a signed charter; no seed/scope).
      if (W.mode === "cloud") {
        const cbody = { slug: W.slug.trim(), mode: W.cloud_mode, target: W.target.trim(),
          provider: W.cloud_mode === "cloud" ? W.provider : "" };
        V.postJSON(OFF("/api/launch/cloud"), cbody).then(function (r) {
          if (r && r.error) { W.launching = false; V.toast(r.error, true); refreshFoot(); return; }
          // the new job becomes the one being worked on (see the assessment branch below)
          setEngagement((r && r.slug) || cbody.slug || "");
          V.toast("Cloud posture launched — watching it live.");
          location.hash = "#/live?run=" + encodeURIComponent(r.run_id);
        }).catch(function (e) {
          W.launching = false; V.toast((e && e.message) || "Launch failed", true); refreshFoot();
        });
        return;
      }
      // `keyless` and `model` used to ride along here. Both were written to the run's meta and read by
      // nothing that changes a run, and no control in this wizard ever set `model` at all, so sending
      // them only made the request look richer than it was.
      const wantGraph = wantsGraph();
      const body = {
        mode: launchMode(), target: W.target.trim(), slug: W.slug.trim(), scope: W.scope,
        objective: W.objective.trim(), scan_mode: W.scan_mode,
        // `packsRun` is the SAME predicate the picker above is drawn from, so what was offered and what
        // is sent cannot drift: a branch that would drop the packs is never asked to carry them.
        tools: (W.mode !== "tool" && (W.aiTools || !packsRun())) ? [] : W.tools,
        apply_fixes: W.apply_fixes,
        mount: W.mount, aegis_action: W.aegis_action,
        session_id: W.session_id,
        graph_backed: wantGraph,
      };
      V.postJSON(OFF("/api/launch/assessment"), body).then(function (r) {
        if (r && r.error) { W.launching = false; V.toast(r.error, true); refreshFoot(); return; }
        // A NEW JOB TAKES OVER THE CONSOLE: scope every screen to the engagement this run was launched
        // under, so the operator lands on their new job's work and nothing else — which, until it
        // produces anything, is honestly empty. Prefer the slug the SERVER reports (the one the run
        // records for itself); the wizard's is only what was asked for.
        setEngagement((r && r.slug) || body.slug || "");
        V.toast("Assessment launched — watching it live.");
        // A graph-backed request falls back to the normal engine whenever the `vigil` entrypoint is
        // missing. The server tags the agentic run `engine:"integration"`; anything else (with an
        // `engine_note` naming the fall-through) means the plain offense engine ran. Fix (W17-9): this
        // used to compare against `"integration-graph"`, a value the server never returns, so the toast
        // fired even when the agentic engine DID run — the false-fallback claim is gone.
        if (wantGraph && !(r && r.engine === "integration")) {
          V.toast((r && r.engine_note) ? r.engine_note
            : ("Graph-backed was requested but is unavailable here (it needs the `vigil` entrypoint) — "
               + "this ran on the normal engine. The run is still linked to the session."), true);
        }
        // Same rule for the capability packs: only the engage branch turns a pack into a flag, so a
        // loopback quick-scan / graph-backed / Strix / AEGIS run carries none of them. The server says so
        // in `tools_note`; passing that on is the difference between a run the operator understands and a
        // run they believe was broader than it was.
        if (r && r.tools_note) V.toast(r.tools_note, true);
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
      // W17-9: keep the pre-Send engine plan fresh as the operator moves through the wizard — the
      // `vigil`-on-PATH conjunct is server-only, so the summary can only name it after this fetch.
      if (W.mode && W.mode !== "cloud") refreshPlan();
    }
    draw();
  }

  // ---- Live run view ---------------------------------------------------------
  let liveES = null, liveTimers = [], liveApprovalModal = null;
  function teardownLive() {
    if (liveES) { try { liveES.close(); } catch (e) {} liveES = null; }
    liveTimers.forEach(function (t) { clearInterval(t); });
    liveTimers = [];
    if (liveApprovalModal) { try { liveApprovalModal.close(); } catch (e) {} liveApprovalModal = null; }  // don't leave a proposal popup floating after navigation
  }

  // Shared approval interaction (Claude-Code "propose" interrupt: Approve / Deny / Deny-&-redirect), used by
  // BOTH the Live view and Chat so there is ONE implementation. `ctx` = { mem:{popped,seen,modal}, slugOf():
  // string, reason:string, after():void, onModal(m):void }. `mem` is per-surface — its own baseline +
  // one-at-a-time guard. The signed-approval model is untouched: Approve/Deny post the signed SOV /api/action;
  // "Deny & redirect" DENIES the exact proposal and sends the note as ordinary mid-run guidance (/api/instruct).
  function makeApprovalUX(ctx) {
    function act(action, seq) {
      V.postJSON(SOV("/api/action"), { action: action, seq: seq, reason: action + " " + (ctx.reason || "") })
        .then(function (r) { if (r && r.error) { V.toast(r.error, true); return; }
          V.toast(action === "approve" ? "Approved." : "Denied."); if (ctx.after) ctx.after(); })
        .catch(function (e) { V.toast((e && e.message) || "Action failed", true); });
    }
    function popModal(a) {
      ctx.mem.popped[a.seq] = true;   // never re-pop the same proposal (dismiss = "I'll use the list")
      const redirect = h("input.input", { type: "text",
        placeholder: "Tell the agent what to do instead… (for Deny & redirect)" });
      const body = h("div.stack", null, [
        h("div.why", null, (a.agent ? a.agent + " proposes: " : "The agent proposes an action that ")
          + (a.subject || "requires your sign-off")),
        h("div.kv", null, [
          h("span.k", null, "Action"), h("span.v", null, a.kind || "action"),
          h("span.k", null, "Tier"), h("span.v", null, a.tier || "—"),
          h("span.k", null, "Request"), h("span.v.mono", null, "seq " + a.seq),
        ]),
        redirect,
        h("p.helper", null, "Approve runs exactly this one action under the gates. Deny refuses it. "
          + "Deny & redirect refuses it AND sends your note to steer the agent so it re-plans. "
          + "Dismiss (Esc) to decide later from the list."),
      ]);
      const done = function () { if (m) m.close(); ctx.mem.modal = null; if (ctx.onModal) ctx.onModal(null); };
      const denyRedirect = function () {
        const t = (redirect.value || "").trim();
        if (!t) { V.toast("Type what the agent should do instead first.", true); if (redirect.focus) redirect.focus(); return; }
        injectIntoRun(ctx.slugOf && ctx.slugOf(), redirect);   // steer (honest toast about live vs queued)
        act("deny", a.seq);                                    // and refuse the exact proposal
        done();
      };
      redirect.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); denyRedirect(); } });
      const m = openModal("Approve this action?", body, [
        h("button.btn", { onClick: denyRedirect }, [V.icon("edit"), "Deny & redirect"]),
        h("button.btn.danger", { onClick: function () { act("deny", a.seq); done(); } }, [V.icon("x"), "Deny"]),
        h("button.btn.owner", { onClick: function () { act("approve", a.seq); done(); } }, [V.icon("check"), "Approve"]),
      ], { onCancel: function () { ctx.mem.modal = null; if (ctx.onModal) ctx.onModal(null); } });
      ctx.mem.modal = m; if (ctx.onModal) ctx.onModal(m);   // module-ref so a teardown can close it on navigation
    }
    // baseline whatever is already pending on entry (no nag), then INTERRUPT for a NEW proposal; one at a time.
    function maybePop(pend) {
      if (ctx.mem.modal) return;
      if (!ctx.mem.seen) { pend.forEach(function (a) { ctx.mem.popped[a.seq] = true; }); ctx.mem.seen = true; return; }
      for (let i = 0; i < pend.length; i++) { if (!ctx.mem.popped[pend[i].seq]) { popModal(pend[i]); return; } }
    }
    function card(a) {
      return h("div.approval", null, [
        h("div.ah", null, [V.icon("key"), h("span.t", null, (a.kind || "action") + " · seq " + a.seq),
          a.tier ? h("span.pill.sm", null, "tier " + a.tier) : null]),
        h("div.why", null, (a.agent ? a.agent + " → " : "") + (a.subject || "requires owner sign-off")),
        h("div.acts", null, [
          h("button.btn.owner", { onClick: function () { act("approve", a.seq); } }, [V.icon("check"), "Approve"]),
          h("button.btn.danger", { onClick: function () { act("deny", a.seq); } }, [V.icon("x"), "Deny"]),
          h("button.btn", { title: "Deny this proposal and tell the agent what to do instead",
            onClick: function () { if (!ctx.mem.modal) popModal(a); } }, [V.icon("edit"), "Deny & redirect"]),
        ]),
      ]);
    }
    function reset() { ctx.mem.popped = {}; ctx.mem.seen = false; if (ctx.mem.modal) { try { ctx.mem.modal.close(); } catch (e) {} } ctx.mem.modal = null; }
    return { act: act, popModal: popModal, maybePop: maybePop, card: card, reset: reset };
  }

  // Shared tool-call CARD (command + redacted output + badges), used by the Live timeline AND the chat
  // process box. `toolPairFrom` links a tool_call with its tool_result (by parent_id) within any events array.
  function toolPairFrom(events, e) {
    events = events || [];
    if (e.kind === "tool_call") return { call: e, result: events.find(function (x) { return x.kind === "tool_result" && x.parent_id === e.id; }) || null };
    if (e.kind === "tool_result") return { call: events.find(function (x) { return x.kind === "tool_call" && x.id === e.parent_id; }) || null, result: e };
    return { call: null, result: null };
  }
  function toolCardBody(call, result) {
    const cp = (call && call.payload) || {}; const rp = (result && result.payload) || {};
    const argv = (rp.argv && rp.argv.length) ? rp.argv.join(" ") : "";
    const ran = rp.ok === true; const refused = rp.refused === true;
    const badges = [];
    const badge = function (label, cls) { if (label != null && label !== "") badges.push(h("span.pill.sm" + (cls ? "." + cls : ""), null, String(label))); };
    badge((cp.tier || rp.tier) ? "tier " + (cp.tier || rp.tier) : "");
    badge(cp.target || "");
    badge(refused ? ("refused" + (rp.gate ? " · " + rp.gate : "")) : (ran ? "ran" : (rp.summary || "pending")), refused ? "danger" : (ran ? "ok" : ""));
    if (rp.exit_code != null) badge("exit " + rp.exit_code, rp.exit_code === 0 ? "ok" : "danger");
    if (rp.timed_out) badge("timed out", "danger");
    if (rp.truncated) badge("truncated");
    if (rp.output_bytes != null) badge(rp.output_bytes + " B out");
    const out = [];
    out.push(h("div.dsection", null, [h("span.label", null, "COMMAND"),
      argv ? h("pre.code", { style: { marginTop: "8px" } }, argv)
           : h("div.hint", null, "No command — this call did not run" + (rp.note ? " (" + rp.note + ")" : "") + ".")]));
    if (badges.length) out.push(h("div.dsection", { style: { display: "flex", gap: "6px", flexWrap: "wrap" } }, badges));
    if (rp.output_excerpt) out.push(h("div.dsection", null, [
      h("span.label", null, "OUTPUT" + (rp.output_excerpt_truncated ? " (truncated — the full redacted output is in the signed record)" : "")),
      h("pre.code", { style: { marginTop: "8px" } }, rp.output_excerpt)]));
    if (rp.stderr_excerpt) out.push(h("div.dsection", null, [h("span.label", null, "STDERR"),
      h("pre.code", { style: { marginTop: "8px" } }, rp.stderr_excerpt)]));
    if (refused && rp.note) out.push(h("div.legend", null, [V.icon("info"), rp.note]));
    out.push(h("div.dsection", null, [h("span.label", null, "RAW PAYLOAD (redacted)"),
      h("pre.code", { style: { marginTop: "8px" } }, JSON.stringify({ tool_call: cp, tool_result: rp }, null, 2))]));
    return out;
  }

  // S10: a SAFE markdown renderer for assistant replies. XSS-safe by construction — every text run becomes a
  // DOM text node (h() → createTextNode), NEVER innerHTML; links accept only http(s)/mailto hrefs (any other
  // scheme renders as plain text). Supports a practical subset: fenced + inline code, bold/italic, links,
  // bullet/numbered lists, headings, and paragraphs with line breaks.
  function _mdInline(text) {
    const rest = String(text);
    const nodes = [];
    const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*]+\*)|(\[[^\]]+\]\([^)\s]+\))/g;
    let last = 0, m;
    while ((m = re.exec(rest)) !== null) {
      if (m.index > last) nodes.push(rest.slice(last, m.index));
      const tok = m[0];
      if (tok.charAt(0) === "`") nodes.push(h("code.md-ic", null, tok.slice(1, -1)));
      else if (tok.slice(0, 2) === "**") nodes.push(h("strong", null, tok.slice(2, -2)));
      else if (tok.charAt(0) === "*") nodes.push(h("em", null, tok.slice(1, -1)));
      else {
        const mm = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(tok);
        if (mm && /^(https?:|mailto:)/i.test(mm[2])) nodes.push(h("a", { href: mm[2], target: "_blank", rel: "noopener noreferrer" }, mm[1]));
        else nodes.push(mm ? mm[1] : tok);        // unsafe/relative scheme → just the visible text
      }
      last = re.lastIndex;
    }
    if (last < rest.length) nodes.push(rest.slice(last));
    return nodes.length ? nodes : [rest];
  }
  function renderMarkdown(text) {
    const lines = String(text || "").split("\n");
    const out = []; let i = 0;
    const special = /^```|^\s*[-*]\s+|^\s*\d+\.\s+|^#{1,4}\s+/;
    while (i < lines.length) {
      const line = lines[i];
      if (/^```/.test(line.trim())) {
        const fence = []; i++;
        while (i < lines.length && !/^```/.test(lines[i].trim())) { fence.push(lines[i]); i++; }
        i++;                                        // skip the closing fence
        out.push(h("pre.md-code", null, h("code", null, fence.join("\n")))); continue;
      }
      const hm = /^(#{1,4})\s+(.*)$/.exec(line);
      if (hm) { out.push(h("div.md-h" + hm[1].length, null, _mdInline(hm[2]))); i++; continue; }
      if (/^\s*[-*]\s+/.test(line)) {
        const items = [];
        while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) { items.push(h("li", null, _mdInline(lines[i].replace(/^\s*[-*]\s+/, "")))); i++; }
        out.push(h("ul.md-ul", null, items)); continue;
      }
      if (/^\s*\d+\.\s+/.test(line)) {
        const items = [];
        while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) { items.push(h("li", null, _mdInline(lines[i].replace(/^\s*\d+\.\s+/, "")))); i++; }
        out.push(h("ol.md-ol", null, items)); continue;
      }
      if (line.trim() === "") { i++; continue; }
      const para = [line]; i++;
      while (i < lines.length && lines[i].trim() !== "" && !special.test(lines[i])) { para.push(lines[i]); i++; }
      const pn = [];
      para.forEach(function (ln, idx) { if (idx) pn.push(h("br")); _mdInline(ln).forEach(function (n) { pn.push(n); }); });
      out.push(h("div.md-p", null, pn));
    }
    return out.length ? out : [String(text || "")];
  }

  function renderLive(screen) {
    const L = { run: null, runs: [], events: [], seen: {}, filter: "all", snapshot: null, started: null,
      inbox: [], inboxLoaded: false, inboxLoading: false, elsewhere: "", scanDone: false, reconciled: false,
      // approval "propose" popup memory (baseline-on-entry + one-at-a-time), driven by the shared makeApprovalUX.
      approvalMem: { popped: {}, seen: false, modal: null } };
    // the shared approve/deny/deny-&-redirect interaction, bound to THIS view's run + snapshot refresh.
    const AUX = makeApprovalUX({ mem: L.approvalMem, reason: "from Live view",
      slugOf: function () { return L.run && L.run.slug; },
      after: function () { pollSnapshot(); },
      onModal: function (m) { liveApprovalModal = m; } });
    const want = hashQuery().run || "";

    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Live"),
        h("span.sub", null, "Every action, as it happens — with proof-grade FACT vs LEAD clarity.")]),
      h("div#live-body", null, h("div.empty", null, "Loading runs…")),
    ]);

    // scoped to the active engagement — this screen shows the job being worked on, not every job ever
    V.getJSON(runsURL()).then(function (d) {
      L.runs = runsOf(d);
      L.run = L.runs.find(function (r) { return r.run_id === want; }) || L.runs[0] || null;
      // a deep link into a run this job does not own: fall back to this job's newest run, and SAY so
      L.elsewhere = (want && !L.runs.some(function (r) { return r.run_id === want; })) ? want : "";
      if (L.run) { L.started = L.run.started; attachStream(); }
      drawBody();
    }).catch(function (e) {
      V.mount(V.$("#live-body"), offlineEmpty(e, "Could not reach the offense console. Start it (vigil up) and reload."));
    });

    function selectRun(runId) {
      teardownLive();
      L.run = L.runs.find(function (r) { return r.run_id === runId; }) || null;
      L.events = []; L.seen = {}; L.snapshot = null; L.started = L.run && L.run.started; L.elsewhere = "";
      L.inbox = []; L.inboxLoaded = false; L.inboxLoading = false;   // per-engagement advisory inbox (B4)
      L.scanDone = false; L.reconciled = false;   // per-run: re-arm the terminal reconcile for the new run
      AUX.reset();   // re-baseline approvals + close any open modal for the new run
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
      // B4: keep the advisory agent inbox fresh, but only while its tab is open (torn down on nav).
      liveTimers.push(setInterval(function () { if (L.filter === "inbox") loadInbox(); }, 8000));
      if (run.stream === "blackboard" && run.slug) {
        // the 14-kind reasoning spine. EventSource resumes from Last-Event-ID (durable cursor).
        liveES = V.sse(OFF("/api/blackboard?slug=" + encodeURIComponent(run.slug)), function (ev) {
          if (!ev || !ev.kind) return;
          if (ev.id != null) { if (L.seen[ev.id]) return; L.seen[ev.id] = 1; }  // dedup any reconnect replay
          L.events.push(ev); onEvents();
        }, function () { /* auto-reconnect; the id: cursor prevents gaps/replays */ });
      } else if (run.stream === "progress") {
        // a loopback scan / codebase run writes a progress log (not the reasoning spine) — render it
        // honestly. The tailer defaults to EOF, so replay the file from the START: otherwise opening a
        // run that already finished (or joining a live one late) shows an empty timeline and a
        // "Refusals 0" tile for a run that may have been blocked many times.
        liveES = V.sse(OFF("/api/events?run=" + encodeURIComponent(run.run_id) + "&from_start=1"), function (ev) {
          // dedup on the stream's _seq cursor exactly as the blackboard branch dedups on ev.id. The server
          // already resumes from Last-Event-ID, so this is defence in depth: without BOTH, a reconnect on a
          // replaying stream would re-count every event and the tiles would read a fabricated total.
          if (ev && ev._seq != null) { if (L.seen["p" + ev._seq]) return; L.seen["p" + ev._seq] = 1; }
          const norm = progressToEvent(ev); if (norm) { L.events.push(norm); onEvents(); }
          // scan.done is the LAST progress row — once it lands, every scan.finding has landed, so it is the
          // safe point to reconcile the streamed (conservative-LEAD) findings against the graded report.
          if (ev && ev.event === "scan.done") { L.scanDone = true; maybeReconcile(); }
        });
      }
      // No completion signal in the stream → poll run status instead. 'none' (aegis) has no feed at all;
      // a codebase (Strix) run now streams ACTIVITY (W6c: strix.graph / warden.block) but still emits no
      // terminal event, so without this its header would never leave "running". A 'progress' loopback scan
      // needs the same poll so its header flips to done AND a terminal run can reconcile its Live
      // tally/labels to the graded report (see maybeReconcile).
      if (run.stream === "none" || run.mode === "codebase" || run.stream === "progress") {
        liveTimers.push(setInterval(refreshRunMeta, 3000));
      }
    }
    function refreshRunMeta() {
      V.getJSON(runsURL()).then(function (d) {
        const r = runsOf(d).find(function (x) { return x.run_id === L.run.run_id; });
        if (r) { L.run = r; updateHeader(); maybeReconcile(); }
      }).catch(function () {});
    }
    // On COMPLETION, reconcile the Live view to the run's AUTHORITATIVE graded findings — the SAME
    // /api/report source the Findings screen reads. A loopback scan streams each finding as a conservative
    // LEAD (progressToEvent hardcodes verified_by_oracle:false because only the report's grounding pass —
    // re-executing each oracle over retained evidence — decides FACT), so Live's Facts tile would otherwise
    // stay 0 while Findings/Report show the same findings CONFIRMED. Only progress-stream runs that CAPTURE
    // a report need this; a blackboard engage run already streams the grounded verdict. Runs at most once,
    // and ONLY when the run is terminal AND the whole progress log has replayed (scanDone) AND the report is
    // present — so a still-running run is never touched and no finding is relabelled before it has streamed.
    function maybeReconcile() {
      if (L.reconciled || !L.run) return;
      if (L.run.stream !== "progress" || p3RunCapturesNoReport(L.run)) return;   // nothing to reconcile against
      const st = L.run.status;
      if (st !== "done" && st !== "error" && st !== "cancelled" && st !== "interrupted") return;
      if (!L.scanDone) return;   // wait for the terminal scan.done row to replay — then all findings are in
      V.getJSON(OFF("/api/report/" + encodeURIComponent(L.run.run_id))).then(function (rep) {
        if (!rep || rep.pending || L.reconciled) return;   // report not captured yet → a later poll retries
        L.reconciled = true;
        // The streamed finding events mirror the report's ACTIVE findings; relabel each to the graded truth,
        // consuming each authoritative finding at most once (by bug class, preferring an exact oracle match).
        // p3IsFact reads the report's live `grounding` verdict, so a demoted finding stays a LEAD — the
        // reconcile can PROMOTE a confirmed lead to a fact but never over-claims one the oracle did not prove.
        const auth = ((rep.findings) || []).filter(function (f) { return f && f.kind === "active"; });
        L.events.forEach(function (e) {
          if (e.kind !== "finding") return;
          const p = e.payload || {};
          let pick = -1, exact = -1;
          for (let i = 0; i < auth.length; i++) {
            if (auth[i]._used) continue;
            if (String(auth[i].bug_class || "") !== String(p.bug_class || "")) continue;
            if (pick < 0) pick = i;
            const ok = auth[i].confirmed_by || auth[i].oracle_kind || "";
            if (ok && ok === (p.oracle_kind || "")) { exact = i; break; }
          }
          const idx = exact >= 0 ? exact : pick;
          if (idx >= 0) { auth[idx]._used = true; p.verified_by_oracle = p3IsFact(auth[idx]); e.payload = p; }
        });
        onEvents();   // recompute the Facts/Leads tiles + relabel the timeline from the reconciled events
      }).catch(function () { /* report unreachable — keep the honest streamed (conservative) state */ });
    }
    function pollSnapshot() {
      V.getJSON(SOV("/api/snapshot")).then(function (s) {
        L.snapshot = s; drawApprovals();
        const sovPending = (s && (s.pending_approvals || []).length) || 0;
        const killed = !!(s && (s.kill_switch === "ENGAGED" || (s.kill_switch && s.kill_switch.engaged)));
        mergeWaiting(sovPending, function (waiting) {   // + offense pending, so a live Strix run shows up
          if (app.get().waiting !== waiting || app.get().killed !== killed) { app.set({ waiting: waiting, killed: killed }); refreshTopbar(); }
        });
      }).catch(function () { /* sovereign plane offline — approvals just won't show */ });
    }

    // convert a scan progress-log row into a timeline-shaped event
    function progressToEvent(ev) {
      if (!ev) return null;
      // Integration-engine OODA mirror (bridge): a progress line already in spine shape ({kind, payload})
      // passes straight through — KIND_META renders every OODA kind natively, so `vigil engage`'s full
      // timeline (decision/tool_call/tool_result/finding/refusal/hypothesis/observation) shows in the feed.
      if (ev.kind && KIND_META[ev.kind]) return { kind: ev.kind, payload: ev.payload || {}, _progress: true };
      if (!ev.event) return null;
      if (ev.event === "scan.phase") return { kind: "observation", payload: { source: "scan", summary: "phase: " + (ev.phase || "") }, _progress: true };
      if (ev.event === "scan.finding") return { kind: "finding", payload: { bug_class: ev.bug_class, title: (ev.param || "") + " @ " + (ev.endpoint || ""),
        confidence: ev.confidence, verified_by_oracle: false, oracle_kind: ev.confirmed_by, severity: "" }, _progress: true };
      if (ev.event === "scan.done") return { kind: "decision", payload: { question: "scan complete", choice: (ev.findings || 0) + " findings · " + (ev.requests_sent || 0) + " requests" }, _progress: true };
      // W6c — a codebase (Strix) run's own progress, normalised into the kinds this view already renders.
      // `_progress: true` tags these the same way the scan rows above are tagged — provenance metadata
      // that says "came over the progress file, not the signed spine". (Nothing renders it today; it is
      // carried for parity with the existing rows, not as a claim that the UI distinguishes them.)
      if (ev.event === "warden.block") return { kind: "refusal", payload: {
        gate: ev.gate || "warden", action_refused: ev.action_refused || "",
        reason: ev.reason || "", fatal: !!ev.fatal }, _progress: true };
      if (ev.event === "strix.graph") {
        var st = ev.statuses || {}, parts = [];
        Object.keys(st).forEach(function (k) { parts.push(k + ":" + st[k]); });
        return { kind: "observation", payload: { source: "strix",
          summary: (ev.agents || 0) + " agent" + ((ev.agents === 1) ? "" : "s")
                   + (parts.length ? " (" + parts.join(", ") + ")" : "") }, _progress: true };
      }
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
      // Lifecycle controls (Claude-Code-style). WHILE RUNNING: "Stop run" cancels THIS run's process only
      // (its memory — the signed engagement spine — is KEPT, so it can be resumed; siblings keep going), and
      // "Halt engagement" is the heavier kill-switch that stops EVERY run of the job. ONCE ENDED: "Resume
      // run" continues it from the last checkpoint (memory intact), or restarts if the run's kind can't
      // resume mid-flight. So an operator can pause (Stop → later Resume) or end (Stop and walk away — the
      // memory stays on the spine as history) without ever losing progress.
      const ended = !running && !!run.status &&
        ["error", "interrupted", "cancelled", "done", "completed"].indexOf(run.status) >= 0;
      const stop = h("button.btn.danger", { disabled: !running || !run.run_id,
        title: "Stop just THIS run — signals its process (SIGTERM→SIGKILL). Its memory (the engagement spine) is KEPT, so you can Resume it later. Other runs of the same job keep going.",
        onClick: cancelThisRun }, [V.icon("x"), "Stop run"]);
      const halt = h("button.btn", { disabled: !running || !run.slug,
        title: "Emergency halt: trip this engagement's kill-switch — stops EVERY run of this job and blocks new tool calls until you clear it in Approvals & Safety.",
        onClick: haltEngagement }, [V.icon("shield"), "Halt engagement"]);
      const resume = (ended && run.run_id) ? h("button.btn.owner", {
        title: run.resumable
          ? "Resume this run from its last signed checkpoint — its memory is intact, so it continues where it left off."
          : "Relaunch this run — this run's kind can't resume mid-flight, so it restarts from the beginning (a new linked run).",
        onClick: function () { runRetry(run.run_id, function () { selectRun(run.run_id); }); } },
        [V.icon("play"), run.resumable ? "Resume run" : "Restart run"]) : null;
      const controls = running ? [stop, halt] : (resume ? [resume] : []);
      return [
        h("div", { style: { display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" } }, [
          statusPill,
          h("b.mono", null, run.target || run.slug || run.run_id),
          h("span.pill.sm", null, run.mode || "url"),
          // the run id distinguishes two runs of the SAME prompt/target in the selector + when killing one
          run.run_id ? h("span.pill.sm.mono", { title: "This run's id — use it to tell two same-prompt runs apart" }, "run " + run.run_id) : null,
          // once ended, say the memory is kept so "stopped" never reads as "lost"
          ended ? h("span.pill.sm", { title: "This run's memory (the signed engagement spine) is kept — Resume continues from the last checkpoint" }, "memory kept") : null,
          h("span.muted", { style: { marginLeft: "auto" } }, [V.icon("live"), " ", elapsed]),
        ].concat(controls)),
        h("div.muted", { style: { marginTop: "8px" } }, "Phase: " + phaseLabel()),
        h("div.grid.cols-4", { style: { marginTop: "12px" } }, [
          V.tile("Actions", String(c.calls), "tool calls"),
          V.tile("Facts", String(c.facts), "oracle-confirmed", c.facts ? "up" : ""),
          V.tile("Leads", String(c.leads), "unconfirmed"),
          V.tile("Refusals", String(c.refusals), "gates fired", c.refusals ? "down" : ""),
        ]),
      ];
    }
    // Per-run cancel: SIGTERM→SIGKILL only THIS run's process (server: /api/run/<id>/cancel → cancel_run).
    // The one-of-two-same-prompt-runs control — it never touches sibling runs or the kill-switch.
    function cancelThisRun() {
      const run = L.run; if (!run || !run.run_id) return;
      V.postJSON(OFF("/api/run/" + encodeURIComponent(run.run_id) + "/cancel"), {})
        .then(function (r) {
          if (r && r.error) { V.toast(r.error, true); return; }
          const st = (r && r.status) || "cancelled";
          // honest wording: say what the server reports, and that siblings are untouched
          V.toast("Run " + run.run_id + " is now " + st + (r && r.terminated ? " (process stopped)" : "") + ". Other runs of this job keep going.");
          run.status = st; updateHeader();
        })
        .catch(function (e) { V.toast((e && e.message) || "Could not stop this run", true); });
    }
    // Emergency halt for the WHOLE engagement — the kill-switch (all runs of this slug + new tool calls).
    function haltEngagement() {
      const run = L.run; if (!run || !run.slug) return;
      if (!confirm("Halt the WHOLE engagement \"" + run.slug + "\"?\n\nThis trips the kill-switch: every run of this job stops and no new tool calls run until you clear it in Approvals & Safety. To stop just this one run, use \"Stop run\" instead.")) return;
      V.postJSON(OFF("/api/killswitch/" + encodeURIComponent(run.slug) + "/trip"), { reason: "halted from Live view" })
        .then(function (r) { if (r && r.error) { V.toast(r.error, true); return; } V.toast("Kill-switch tripped — the engagement will halt.");
          L.run.status = "stopping"; updateHeader(); })
        .catch(function (e) { V.toast((e && e.message) || "Could not halt the engagement", true); });
    }

    // ---- approvals (sovereign plane) — the interrupt + cards come from the shared makeApprovalUX (AUX) ----
    function drawApprovals() {
      const host = V.$("#live-approvals"); if (!host) return;
      const pend = (L.snapshot && L.snapshot.pending_approvals) || [];
      AUX.maybePop(pend);
      if (!pend.length) { V.mount(host, null); return; }
      V.mount(host, V.card("Waiting for your approval", "OWNER", h("div.stack", null, pend.map(AUX.card)), true));
    }

    // ---- graph + timeline ----
    function drawGraph() { const g = V.$("#live-graph"); if (g) liveGraph(g, L.events); }
    // ---- agent inbox (B4): advisory agent-to-agent coordination — NOT evidence ----
    // The console GETs one engagement's `agent_message` spine kind. Load-bearing honesty: no fact-building
    // path reads these messages, so nothing here can promote a finding — the tab renders them as coordination
    // only. Read-only; keyed by the selected run's engagement slug.
    function loadInbox() {
      const slug = L.run && L.run.slug;
      if (!slug) { L.inbox = []; L.inboxLoaded = true; if (L.filter === "inbox") drawTimeline(); return; }
      L.inboxLoading = true;
      V.getJSON(OFF("/api/inbox/" + encodeURIComponent(slug))).then(function (d) {
        L.inbox = (d && d.messages) || []; L.inboxLoaded = true; L.inboxLoading = false;
        if (L.filter === "inbox") drawTimeline();
      }).catch(function () {
        L.inbox = []; L.inboxLoaded = true; L.inboxLoading = false;
        if (L.filter === "inbox") drawTimeline();
      });
    }
    function drawInbox(host) {
      if (!L.run || !L.run.slug) {
        V.mount(host, h("div.empty", null, "This run has no engagement — an agent inbox is per-engagement.")); return;
      }
      if (!L.inboxLoaded) { if (!L.inboxLoading) loadInbox(); V.mount(host, h("div.empty", null, "Loading inbox…")); return; }
      const note = h("div.legend", { style: { marginBottom: "10px" } }, [V.icon("info"),
        "Advisory coordination only. These are agent-to-agent messages — NOT evidence. No fact-building path "
        + "reads them, so nothing here can promote a finding. Only a fired oracle mints a FACT."]);
      if (!L.inbox.length) {
        V.mount(host, [note, h("div.empty", null, "No coordination messages on this engagement yet.")]); return;
      }
      const rows = [];
      for (let i = L.inbox.length - 1; i >= 0; i--) {   // newest first
        const msg = L.inbox[i]; const p = msg || {};
        rows.push(h("div.trow.kind-agent_message", null, [
          h("div.ico", null, V.icon("brain")),
          h("div.body", null, [
            h("div.k", null, [
              h("span.pill.sm", null, "advisory"),
              h("b", { style: { marginLeft: "6px" } }, (p.sender || "?") + " → " + (p.recipient || "all")),
              p.topic ? h("span", { style: { marginLeft: "6px", opacity: 0.8 } }, "· " + p.topic) : null]),
            h("div.m", null, String(p.body || "—"))]),
          h("div.meta", null, [h("span.t", null, p.posted_at ? String(p.posted_at).slice(11, 19) : (p.id != null ? "#" + p.id : ""))]),
        ]));
      }
      V.mount(host, [note].concat(rows));
    }
    function drawTimeline() {
      const host = V.$("#live-timeline"); if (!host) return;
      if (L.filter === "inbox") { drawInbox(host); return; }
      // An empty timeline means different things — say which, and never imply "still coming" for a run
      // that has ended. A finished run whose feed replayed empty genuinely recorded no steps.
      function liveEmptyText() {
        const r = L.run || {};
        if (r.stream === "none") return "This run reports in its own sandbox — see Findings for its results.";
        // Only a KNOWN-terminal status may assert a finished lifecycle. api.list_runs defaults a run with
        // no meta to status "unknown" — claiming that one "has finished" would state a lifecycle we never
        // observed, for a run that may never have started.
        if (r.status === "interrupted") return "This run was interrupted before it reported any steps.";
        if (r.status === "done" || r.status === "error" || r.status === "cancelled") {
          return "This run finished and recorded no steps here.";
        }
        if (r.status === "running" || !r.status) return "Waiting for the first event…";
        return "No steps have been recorded for this run.";   // unknown/other — state the fact, claim nothing
      }
      let rows = L.events;
      if (L.filter === "facts") rows = rows.filter(function (e) { return e.kind === "finding" && isFact(e.payload); });
      else if (L.filter === "leads") rows = rows.filter(function (e) { return e.kind === "finding" && !isFact(e.payload); });
      rows = foldRoutineCritics(rows);   // one calm summary row in place of the routine per-lead critic flood
      if (!rows.length) {
        V.mount(host, h("div.empty", null, L.events.length ? "No events match this filter." : liveEmptyText()));
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
      var _muted = (e.kind === "critic_summary" || (e.kind === "critic_verdict" && p.expected)) ? ".pb-muted" : "";
      return h("div.trow.kind-" + e.kind + ".new" + _muted, { onClick: function () { openEventDrawer(e); } }, [
        h("div.ico", null, V.icon(kindIcon(e.kind, p))),
        h("div.body", null, [h("div.k", null, m.label), h("div.m", null, m.sum(p) || "—")]),
        h("div.meta", null, meta.concat([h("span.t", null, e.posted_at ? String(e.posted_at).slice(11, 19) : (e.id != null ? "#" + e.id : ""))])),
      ]);
    }
    function openEventDrawer(e) {
      // tool_call / tool_result → the shared paired command/output card (uses the now-resizable drawer)
      if (e.kind === "tool_call" || e.kind === "tool_result") {
        const pair = toolPairFrom(L.events, e);
        openDrawer("Tool call", toolCardBody(pair.call, pair.result));
        return;
      }
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
        V.mount(body, activeEngagement()
          ? scopedEmpty("runs", "Nothing has run under this job yet — the moment one starts, every action appears here live.", [newAssessBtn()])
          : h("div.empty", null, [h("div.big", null, "No runs yet"),
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
      const filterSeg = h("div.segmented", null, [["all", "All"], ["facts", "Facts"], ["leads", "Leads"], ["inbox", "Inbox"]].map(function (f) {
        return h("button" + (L.filter === f[0] ? ".on" : ""), { onClick: function () { L.filter = f[0]; if (f[0] === "inbox" && !L.inboxLoaded) loadInbox(); drawBody(); } }, f[1]);
      }));
      V.mount(body, [
        L.elsewhere ? otherEngagementNote(L.elsewhere) : null,
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

  // ---- Activity: the background-activity screen (A4e-2) -----------------------
  // A READ-ONLY window on "how things are working in the background" across both
  // planes. It reuses only existing read endpoints — nothing here mutates:
  //   · runsURL()             → active/recent runs for the ACTIVE ENGAGEMENT (Watch-live links
  //                             into #/live); unscoped ⇒ every job, exactly as before
  //   · SOV("/api/snapshot")  → SIGIL agent mesh (recent_by_agent), budget_today,
  //                             ingest_lag, spine head_seq, kill-switch
  //   · SOV("/api/stream")    → the live spine SSE (the "background" event feed)
  // Two-env boundary: SOV for sovereign, OFF for offense — never crossed. The
  // per-run offense reasoning spine is intentionally NOT streamed here (the Live
  // screen owns that); a single sovereign EventSource keeps teardownLive() clean.
  function renderBackground(screen) {
    teardownLive();   // close any stream/timers from the previous screen
    const B = { runs: [], snap: null, offOnline: null, offErr: null, sovOnline: null, seen: {}, eventCount: 0, streamAttached: false };

    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Activity"),
        h("span.sub", null, "How VIGIL is working in the background — active runs, the SIGIL agent mesh, spine activity, and a live event stream.")]),
      h("div.card#bg-status", { style: { marginTop: "4px" } }, h("div.empty", null, "Checking both planes…")),
      h("div.legend", { style: { marginTop: "12px" } }, [V.icon("info"),
        "A read-only view across both planes — nothing here changes anything. To act, use Live, Approvals & Safety, or New Assessment."]),
      h("div.grid.cols-4#bg-tiles", { style: { marginTop: "16px" } }),
      h("div.grid.cols-2", { style: { marginTop: "4px", alignItems: "start" } }, [
        h("div.stack", null, [
          V.card("Active work", "OFFENSE", h("div#bg-runs", null, h("div.empty", null, "Loading runs…")), false),
          V.card("Agent mesh & spine", "SOVEREIGN", h("div#bg-mesh", null, h("div.empty", null, "Loading…")), false),
        ]),
        V.card("Live event stream", "LIVE", h("div.feed#bg-feed", null, h("div.empty", null, "Connecting to the background event stream…")), false),
      ]),
    ]);

    // -- one run row: status/mode/target + elapsed (derived from started) + link --
    function runRow(r) {
      const running = r.status === "running";
      const started = typeof r.started === "number" ? r.started : parseFloat(r.started);
      const elapsed = (started && !isNaN(started)) ? fmtElapsed((Date.now() / 1000) - started) : "—";
      return h("div.card", { style: { padding: "12px" } }, [
        h("div", { style: { display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" } }, [
          running ? V.pill("running", "live", null) : V.pill(r.status || "done", r.status === "error" ? "danger" : "idle", null),
          h("span.pill.sm", null, r.mode || "url"),
          h("b.mono", null, r.target || r.slug || r.run_id),
          h("span.muted", { style: { marginLeft: "auto" } }, [V.icon("live"), " ", elapsed]),
        ]),
        h("div.muted", { style: { marginTop: "6px", fontSize: "var(--fs-sm)" } },
          (r.slug ? ("slug " + r.slug + " · ") : "") +
          (r.findings != null ? (r.findings + " findings · ") : "") +
          "stream: " + (r.stream || "none")),
        h("div", { style: { marginTop: "8px" } },
          h("button.btn.sm", { onClick: function () { location.hash = "#/live?run=" + encodeURIComponent(r.run_id); } },
            [V.icon("live"), "Watch live"])),
      ]);
    }

    // -- the SIGIL agent mesh + spine, straight from the sovereign snapshot ------
    function meshBody(snap) {
      const rba = snap.recent_by_agent || {};
      const bud = snap.budget_today || {};
      const lag = snap.ingest_lag || {};
      const names = Object.keys(rba);
      Object.keys(bud).forEach(function (n) { if (names.indexOf(n) < 0) names.push(n); });
      names.sort(function (a, b) { return (rba[b] || 0) - (rba[a] || 0); });
      const rows = names.length ? names.map(function (n) {
        const b = bud[n] || {};
        return h("div.cap-row", null, [
          h("div.cap-l", null, [h("b", null, n),
            h("span.muted", { style: { fontSize: "var(--fs-xs)" } }, (rba[n] || 0) + " recent record" + ((rba[n] || 0) === 1 ? "" : "s"))]),
          h("span.muted.mono", { style: { fontSize: "var(--fs-xs)" } },
            (b.actions || 0) + " action" + ((b.actions || 0) === 1 ? "" : "s") + (b.interrupts ? (" · " + b.interrupts + " interrupts") : "")),
        ]);
      }) : [h("div.empty", null, "No agent activity in the recent window.")];
      const lagLine = h("div.hint", { style: { marginTop: "12px" } },
        "Spine head " + (snap.head_seq != null ? ("#" + snap.head_seq) : "—") +
        " · " + (lag.records_since_checkpoint != null ? lag.records_since_checkpoint : "?") + " records since last checkpoint" +
        (lag.last_consolidation_seq != null ? (" · last consolidation #" + lag.last_consolidation_seq) : ""));
      return h("div", null, [h("div.stack", null, rows), lagLine]);
    }

    // -- normalize a sovereign spine record to {kind, actor, summary, seq} -------
    function normSov(ev) {
      if (!ev || typeof ev !== "object") return null;
      const payload = ev.payload || {};
      return {
        id: ev.seq != null ? ("s" + ev.seq) : null,   // dedup key across reconnects
        seq: ev.seq,
        kind: ev.kind || ev.k || "event",
        actor: ev.actor || ev.source || ev.agent || "",
        summary: ev.text || ev.subject || payload.signal || payload.subject || "",
      };
    }
    function feedRowBg(n) {
      return h("div.feed-row", null, [
        h("span.pill.sm", null, n.kind),
        h("span.fr-t", null, [n.actor ? h("b", null, n.actor) : null, n.summary ? (" · " + n.summary) : ""]),
        h("span.fr-seq.mono.dim", null, n.seq != null ? ("#" + n.seq) : ""),
      ]);
    }
    function addFeedRow(n) {
      const feed = V.$("#bg-feed"); if (!feed) return;
      const empty = feed.querySelector(".empty"); if (empty) empty.remove();
      feed.insertBefore(feedRowBg(n), feed.firstChild);
      while (feed.childNodes.length > 60) feed.removeChild(feed.lastChild);
      B.eventCount++;
    }

    // -- system-status header (both planes + kill-switch) -----------------------
    function statusBody() {
      const killed = !!(B.snap && (B.snap.kill_switch === "ENGAGED" || (B.snap.kill_switch && B.snap.kill_switch.engaged)));
      return h("div", { style: { display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" } }, [
        B.offOnline === null ? V.pill("Offense: checking…", "idle", null)
          : (B.offOnline ? V.pill("Offense: online", "live", null) : V.pill("Offense: offline", "danger", null)),
        B.sovOnline === null ? V.pill("Sovereign: checking…", "idle", null)
          : (B.sovOnline ? V.pill("Sovereign: online", "live", null) : V.pill("Sovereign: offline", "danger", null)),
        B.sovOnline ? (killed ? V.pill("Kill-switch: ENGAGED", "danger", null) : V.pill("Kill-switch: released", "idle", null)) : null,
      ]);
    }

    // -- drawing (each pull re-renders its own region; fail-soft per plane) ------
    function drawStatus() { const host = V.$("#bg-status"); if (host) V.mount(host, statusBody()); }
    function drawTiles() {
      const host = V.$("#bg-tiles"); if (!host) return;
      const runsRunning = B.runs.filter(function (r) { return r.status === "running"; }).length;
      const rba = (B.snap && B.snap.recent_by_agent) || {};
      const lag = (B.snap && B.snap.ingest_lag) || {};
      const killed = !!(B.snap && (B.snap.kill_switch === "ENGAGED" || (B.snap.kill_switch && B.snap.kill_switch.engaged)));
      V.mount(host, [
        V.tile("Active runs", B.offOnline === false ? "—" : String(runsRunning),
          B.offOnline === false ? "offense offline" : (runsRunning ? "in progress" : "nothing running"), runsRunning ? "up" : ""),
        V.tile("Agents active", B.sovOnline === false ? "—" : String(Object.keys(rba).length),
          B.sovOnline === false ? "sovereign offline" : "recent activity window"),
        V.tile("Ingest lag", B.sovOnline === false ? "—" : String(lag.records_since_checkpoint != null ? lag.records_since_checkpoint : "—"),
          "records since checkpoint", (lag.records_since_checkpoint > 0 ? "warn" : "")),
        V.tile("Kill-switch", B.sovOnline === false ? "—" : (killed ? "ENGAGED" : "Released"),
          killed ? "mesh halted" : "mesh live", killed ? "danger" : "ok"),
      ]);
    }
    function drawRuns() {
      const host = V.$("#bg-runs"); if (!host) return;
      if (B.offOnline === false) {
        // WS2a: the runs region surfaces the REAL poll error (offlineEmpty distinguishes a backend 4xx/5xx
        // from a down plane). The compact status pill + "Active runs" tile stay boolean by design.
        V.mount(host, offlineEmpty(B.offErr, "Could not reach the offense console. Start it with `vigil up` and it appears here.")); return;
      }
      if (!B.runs.length) {
        V.mount(host, activeEngagement()
          ? scopedEmpty("active work", "Nothing has run under this job yet — the mesh and the event stream beside this panel are console-wide and keep working.", [newAssessBtn()])
          : h("div.empty", null, [h("div.big", null, "No runs yet"),
            h("p", null, "Start one from New Assessment and it shows up here, live."),
            h("button.btn.primary", { style: { marginTop: "12px" }, onClick: function () { location.hash = "#/assess"; } }, [V.icon("bolt"), "New Assessment"])])); return;
      }
      V.mount(host, h("div.stack", null, B.runs.slice(0, 12).map(runRow)));
    }
    function drawMesh() {
      const host = V.$("#bg-mesh"); if (!host) return;
      if (B.sovOnline === false) { V.mount(host, h("div.empty", null, "The sovereign plane is offline. Start it with `vigil up`.")); return; }
      if (!B.snap) { V.mount(host, h("div.empty", null, "Loading…")); return; }
      V.mount(host, meshBody(B.snap));
    }

    // -- polling (read-only GETs; cleaned up by teardownLive via liveTimers) -----
    function pollRuns() {
      V.getJSON(runsURL()).then(function (d) {
        B.runs = runsOf(d); B.offOnline = true; B.offErr = null; drawRuns(); drawStatus(); drawTiles();
      }).catch(function (e) { B.offOnline = false; B.offErr = e; drawRuns(); drawStatus(); drawTiles(); });
    }
    function pollSnap() {
      V.getJSON(SOV("/api/snapshot")).then(function (s) {
        B.snap = s; B.sovOnline = true; drawMesh(); drawStatus(); drawTiles();
        // keep the shared top bar honest (read-only, exactly as Live/Safety do)
        const sovPending = (s && (s.pending_approvals || []).length) || 0;
        const killed = !!(s && (s.kill_switch === "ENGAGED" || (s.kill_switch && s.kill_switch.engaged)));
        mergeWaiting(sovPending, function (waiting) {   // + offense pending, so a live Strix run shows up
          if (app.get().waiting !== waiting || app.get().killed !== killed) { app.set({ waiting: waiting, killed: killed }); refreshTopbar(); }
        });
        // attach the live spine feed ONCE, tailing from the current head so we stream what
        // happens from now on (not a full replay of the whole spine).
        if (!B.streamAttached) attachStream(typeof s.head_seq === "number" ? s.head_seq : undefined);
        const feed = V.$("#bg-feed");
        if (feed && !B.eventCount) V.mount(feed, h("div.empty", null, "Connected — no background events yet. They will appear here live."));
      }).catch(function () {
        B.sovOnline = false; B.snap = null; drawMesh(); drawStatus(); drawTiles();
        const feed = V.$("#bg-feed");
        if (feed && !B.eventCount) V.mount(feed, h("div.empty", null, "The sovereign plane is offline — no background events. Start it with `vigil up`."));
      });
    }

    // -- live spine feed: ONE sovereign SSE, dedup by seq, native auto-reconnect.
    //    Tailing from the current head keeps this a LIVE feed (no whole-spine replay).
    function attachStream(headSeq) {
      if (B.streamAttached) return;
      B.streamAttached = true;   // set before the try so a permanently-unavailable EventSource isn't retried each poll
      const base = SOV("/api/stream");
      const url = (typeof headSeq === "number" && headSeq >= 0) ? (base + "?since=" + headSeq) : base;
      try {
        liveES = V.sse(url, function (ev) {
          const n = normSov(ev); if (!n) return;
          if (n.id) { if (B.seen[n.id]) return; B.seen[n.id] = 1; }   // guard reconnect replay
          addFeedRow(n);
        }, function () { /* SSE error — auto-reconnects; the polls keep the rest live */ });
      } catch (e) { /* EventSource unavailable — non-fatal; the polls keep the rest live */ }
    }

    // the SSE attaches on the first successful snapshot (so it can tail from head_seq)
    pollRuns(); pollSnap();
    liveTimers.push(setInterval(pollRuns, 3000));
    liveTimers.push(setInterval(pollSnap, 4000));
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
  // A STATIC fact: confirmed by a deterministic DAA static rule over the SOURCE (source/oracle_kind
  // "daa:<rule_id>"), not by a live-exploit oracle. It IS a re-runnable fact (the pattern is present), but it
  // is NOT proof the sink is reachable at runtime — so it is labelled distinctly from a live-oracle fact.
  function p3IsStatic(f) {
    var ob = String((f && (f.oracle_kind || f.confirmed_by)) || "");
    return ob.indexOf("daa:") === 0;
  }
  function p3Surface(f) {
    return f.location || f.surface || f.insertion_point || f.param || f.endpoint || "—";
  }
  function p3Oracle(f) { return f.confirmed_by || f.oracle_kind || "—"; }
  // The weakness-class taxonomy the server stamps onto every finding (report.standards): the CWE id(s)
  // and OWASP Top-10 category the bug_class denotes. Shown INLINE beside the bug class so a finding reads
  // as "xss · CWE-79", not just "xss". Class DATA, not a compliance-coverage claim (that is the Compliance
  // screen). Empty string when the class is unmapped or the server did not classify it — no fabrication.
  function p3Cwe(f) { return (f && f.cwe && f.cwe.length) ? f.cwe.join(", ") : ""; }
  function p3Owasp(f) { return (f && f.owasp) ? f.owasp : ""; }
  function p3Rationale(f) { return f.oracle_rationale || f.evidence || f.rationale || ""; }
  function p3Sev(f) { return String(f.severity || "").trim(); }
  function p3SevChip(sev) {
    const s = String(sev || "").toLowerCase();
    return s ? h("span.sev.sev-" + s, null, sev) : h("span.muted", null, "—");
  }
  function p3StatusChip(f) {
    if (p3IsFact(f)) return p3IsStatic(f)
      ? h("span.shield", { title: "Confirmed by a deterministic static rule over the source (pattern present); not a live-exploit proof" }, [V.icon("check"), "STATIC"])
      : h("span.shield", null, [V.icon("check"), "CONFIRMED"]);
    // a LEAD is explicitly "not proven". If it is an ACTIVE finding whose oracle failed to
    // re-ground (contradicted / ungrounded), say so honestly rather than a bland "lead".
    const g = f.grounding;
    const label = (g === "contradicted") ? "CONTRADICTED"
      : (g === "ungrounded") ? "UNGROUNDED" : "LEAD";
    return h("span.shield.lead", { title: "Not proven by an oracle" }, label);
  }

  // ---- the hub ---------------------------------------------------------------
  function renderFindings(screen) {
    const S = { runs: [], run: null, tab: "findings", elsewhere: "" };
    const q = hashQuery();
    const want = q.run || "";
    const wantTab = q.tab || "";

    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Findings"),
        h("span.sub", null, "Proven bugs, the attack graph, re-checkable evidence, coverage and replay — all oracle-gated.")]),
      h("div#p3-body", null, h("div.empty", null, "Loading runs…")),
    ]);

    // scoped to the active engagement — one job's findings are never mixed with another's
    V.getJSON(runsURL()).then(function (d) {
      S.runs = runsOf(d);
      S.run = S.runs.find(function (r) { return r.run_id === want; }) || S.runs[0] || null;
      S.elsewhere = (want && !S.runs.some(function (r) { return r.run_id === want; })) ? want : "";
      if (P3_TABS.some(function (t) { return t.id === wantTab; })) S.tab = wantTab;
      drawShell();
    }).catch(function (e) {
      V.mount(V.$("#p3-body"), offlineEmpty(e, "Could not reach the offense console. Start it (vigil up) and reload."));
    });

    function syncHash() {
      if (!S.run) return;
      history.replaceState(null, "", "#/findings?run=" + encodeURIComponent(S.run.run_id) + "&tab=" + S.tab);
    }
    function selectRun(runId) {
      S.run = S.runs.find(function (r) { return r.run_id === runId; }) || null;
      S.elsewhere = "";
      syncHash(); drawShell();
    }
    function selectTab(tab) { S.tab = tab; syncHash(); drawTab(); }

    function drawShell() {
      const body = V.$("#p3-body"); if (!body) return;
      if (!S.runs.length) {
        V.mount(body, activeEngagement()
          ? scopedEmpty("findings", "No run in this job has produced findings yet — its findings, attack graph and evidence appear here as soon as one does.", [newAssessBtn()])
          : h("div.empty", null, [h("div.big", null, "No runs yet"),
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
      V.mount(body, [S.elsewhere ? otherEngagementNote(S.elsewhere) : null, picker, tabs,
        h("div#p3-view", { style: { marginTop: "16px" } })]);
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

  // A run that never CAPTURES a report: aegis (stream 'none'), a codebase/Strix run (mode 'codebase'), and
  // an agentic `vigil engage` bridge run (engine 'integration') — launch_assessment spawns all three with
  // capture_report=False, so /api/report stays {pending:true} forever. Keyed on all three axes because no
  // single one identifies the set: a codebase run now STREAMS its activity (W6c) so is no longer identifiable
  // by stream alone, and the integration bridge run shares that same stream 'progress' with the loopback scan
  // that DOES capture a report — only its engine 'integration' distinguishes the two. (The remote-engage case,
  // stream 'blackboard', is handled by the blackboard branch above before this predicate is reached.) Without
  // the engine test an agentic run sat on "Still running… no saved report YET", false twice over: it has
  // finished, and no report is ever coming.
  // NB: the AEGIS no-report case keys on mode === "aegis" (NOT stream === "none"): a DAA codescan run is
  // also stream "none" but DOES capture a report.json, so it must fall through to its real report,
  // never the "captures no report" empty state.
  function p3RunCapturesNoReport(run) { return run.mode === "aegis" || run.mode === "codebase" || run.engine === "integration"; }
  function p3NoReportEmpty(run, what) {
    if (run.stream === "blackboard") {
      return h("div.empty", null, [h("div.big", null, "This run reports on the reasoning spine"),
        h("p", null, (what || "Findings") + " for a live engage run stream onto the blackboard — open it in Live to watch every FACT and LEAD as an oracle adjudicates it."),
        h("button.btn", { style: { marginTop: "14px" }, onClick: function () { location.hash = "#/live?run=" + encodeURIComponent(run.run_id); } },
          [V.icon("live"), "Open in Live"])]);
    }
    if (p3RunCapturesNoReport(run)) {
      return h("div.empty", null, [h("div.big", null, "This run streams its work"),
        h("p", null, "A codebase (Strix) scan, an AEGIS run, or an agentic engage run streams its activity in its own sandbox — no re-checkable web report is captured here."),
        // Offer Live ONLY for a run that actually HAS a replayable feed (stream "progress"). A legacy
        // codebase run predates the feed and has stream "none" — sending it to Live would bounce the
        // operator to an empty screen that points straight back here.
        (run.stream === "progress"
          ? h("button.btn", { style: { marginTop: "14px" }, onClick: function () { location.hash = "#/live?run=" + encodeURIComponent(run.run_id); } },
              [V.icon("live"), "See what it did in Live"])
          : null)]);
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
                h("td", null, [h("b.mono", null, f.bug_class || "—"),
                  p3Cwe(f) ? h("span.pill.sm", { style: { marginLeft: "6px" }, title: p3Owasp(f) ? ("OWASP " + p3Owasp(f)) : "" }, p3Cwe(f)) : null]),
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
    }).catch(function (e) { V.mount(host, offlineEmpty(e)); });
  }

  function p3HowToVerify(f) {
    // Per-finding how-to (B1): prefer the authoritative server-derived note if the provider supplied one,
    // else derive a concise, HONEST note from the finding's own fields — a fact points at the offline
    // re-verify of its retained proof; a lead says how to CONFIRM it and never implies proof.
    if (f.how_to_verify) return String(f.how_to_verify);
    var surface = p3Surface(f);
    var oracle = p3Oracle(f);
    var oracleRef = (oracle && oracle !== "—") ? "`" + oracle + "`" : "a deterministic";
    if (p3IsFact(f)) {
      return "Re-run this finding's retained proof OFFLINE (the Re-verify button below, or "
        + "`python3 -m framework.v2 verify` over the run's reverifiable material): the " + oracleRef
        + " oracle re-fires over the captured bytes and reports OK when it reproduces. Surface: " + surface
        + ". Then apply the remediation below and re-verify that the oracle goes silent.";
    }
    return "This is a LEAD, not a proven fact — no deterministic oracle fired for it. To CONFIRM it, reproduce "
      + "the test against " + surface + " and capture the oracle signal (a divergent response, an out-of-band "
      + "callback, an achieved state); only a fired oracle promotes it to a fact.";
  }

  function p3OpenFindingDrawer(run, f) {
    const kv = [];
    const put = function (k, v) { if (v == null || v === "") return; kv.push(h("div.kv", null, [h("div.k", null, k), h("div.v", null, String(v))])); };
    const fact = p3IsFact(f);
    put("Verdict", fact ? (p3IsStatic(f)
        ? ("STATIC FACT — a deterministic rule (" + p3Oracle(f) + ") matched your source; the vulnerable "
           + "pattern is PRESENT and re-runnable, but this is not a live-exploit proof of reachability")
        : "CONFIRMED — an oracle re-fired over the retained evidence (a FACT)")
      : (f.grounding === "contradicted" ? "CONTRADICTED — the oracle did NOT re-ground this claim"
        : f.grounding === "ungrounded" ? "UNGROUNDED — no live oracle proof"
          : "LEAD — a proposal, not proven"));
    put("Severity", p3Sev(f) || "—");
    put("Bug class", f.bug_class);
    put("CWE", p3Cwe(f));
    put("OWASP", p3Owasp(f) ? ("OWASP Top 10 — " + p3Owasp(f)) : "");
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

    sections.push(h("div.dsection", null, [h("span.label", null, "HOW TO VERIFY & TEST"),
      h("p.muted", { style: { marginTop: "6px", lineHeight: "1.55" } }, p3HowToVerify(f))]));
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
    }).catch(function (e) { V.mount(host, offlineEmpty(e)); });
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
      V.getJSON(OFF("/api/evidence/" + encodeURIComponent(run.run_id))).then(then).catch(function (e) { V.mount(host, offlineEmpty(e)); });
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
      // W16-7: the raw per-action HTTP evidence the executor captured (request/response bytes) — loaded
      // separately so a failure here never blanks the certificate view above.
      const httpHost = h("div", { style: { marginTop: "18px" } });
      p3HttpEvidence(httpHost, run);
      V.mount(host, [tiles, doctrine, cards, httpHost]);
    });
  }
  // W16-7 — raw HTTP evidence panel: the exact request/response the gated executor sent and received,
  // captured verbatim (non-LLM bytes). Read-only preview; the FULL capture ships in the dossier ZIP.
  function p3HttpEvidence(host, run) {
    V.getJSON(OFF("/api/http-evidence/" + encodeURIComponent(run.run_id))).then(function (ev) {
      const ex = (ev && ev.exchanges) || [];
      const title = h("h3", { style: { margin: "0 0 8px" } }, "Raw HTTP evidence");
      if (!ex.length) {
        V.mount(host, [title, h("div.empty", null,
          "No raw HTTP capture for this run. The gated executor writes request.http / response.http / response.body per action; a loopback library scan records its findings without a per-action HTTP archive.")]);
        return;
      }
      const doctrine = h("div.legend", { style: { marginBottom: "10px" } }, [V.icon("shield"),
        (ev.doctrine || "The exact request/response the executor sent and received, captured verbatim.")]);
      const cards = ex.map(function (x) {
        const files = x.files || {};
        const parts = ["request.http", "response.http", "response.body"].map(function (name) {
          const f = files[name];
          if (!f) return null;
          return h("div", { style: { marginTop: "8px" } }, [
            h("div.k", null, name + " (" + f.bytes + " bytes" + (f.truncated ? ", preview truncated" : "") + ")"),
            h("pre.mono", { style: { maxHeight: "220px", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" } }, f.preview || ""),
          ]);
        }).filter(Boolean);
        return h("div.card", null, [h("b.mono", null, x.action_id)].concat(parts));
      });
      V.mount(host, [title, doctrine, h("div.stack", null, cards),
        h("p.muted", { style: { marginTop: "8px", fontSize: "var(--fs-xs)" } },
          "This is a capped preview. The complete, tamper-evident capture is in the downloadable dossier ZIP.")]);
    }).catch(function () { V.mount(host, ""); });
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
    }).catch(function (e) { V.mount(host, offlineEmpty(e)); });
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
    }).catch(function (e) { V.mount(host, offlineEmpty(e)); });
  }

  // ---- shared small empties --------------------------------------------------
  function pendingEmpty(run) {
    return h("div.empty", null, [h("div.big", null, "Still running"),
      h("p", null, "This run has not produced a saved report yet. Watch it in Live, then come back."),
      h("button.btn", { style: { marginTop: "12px" }, onClick: function () { location.hash = "#/live?run=" + encodeURIComponent(run.run_id); } }, [V.icon("live"), "Open in Live"])]);
  }
  function offlineEmpty(err, hint) {
    // WS2a: distinguish a real BACKEND error from a DOWN plane, instead of masking every read failure as
    // "offline". WS0's getJSON attaches .status/.data on an HTTP error — so a failure WITH a status means
    // the plane is reachable but the endpoint erred (surface the real server message), while a failure with
    // NO status is a fetch/network failure, i.e. the plane is genuinely unreachable.
    if (err && (err.status === 401 || err.status === 403)) {
      // WS2a-2: a stale SESSION token (it rotates on every server restart — a Claim-6 property) 401s every
      // request. That is NOT "offline"; the engine is up, the token is just old. The token is deliberately
      // not embedded in the page, so recovery is reloading with a fresh `?token=` URL, not a plain reload.
      return h("div.empty", null, [
        h("div.big", null, "Session expired"),
        h("p", null, "Your session token is stale — it rotates whenever the server restarts. The engine is "
          + "up; your token is just old."),
        h("p.hint", null, "Reload the interface with a fresh token URL — get the current one from the terminal:"),
        h("pre.mono", { style: { whiteSpace: "pre-wrap", userSelect: "all", marginTop: "6px" } },
          "journalctl --user -u vigil-command.service | grep -oE 'http://127.0.0.1:8770/\\?token=[A-Za-z0-9_-]+' | tail -1"),
      ]);
    }
    if (err && err.status) {
      var msg = (err.data && err.data.error) || err.message || ("HTTP " + err.status);
      return h("div.empty", null, [
        h("div.big", null, "Request failed (" + err.status + ")"),
        h("p", null, String(msg)),
        h("p.hint", null, "The engine is reachable but this request errored — retry, or check the engine logs."),
      ]);
    }
    return h("div.empty", null, [h("div.big", null, "Offense engine offline"),
      h("p", null, hint || "Could not reach the offense console read plane. Start it (vigil up) and reload.")]);
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
        // okMsg may be a function of the response so the toast can tell the TRUTH the server reported
        // (e.g. whether a secret was actually sealed or fell back to plaintext) instead of a fixed claim.
        V.toast(typeof okMsg === "function" ? okMsg(r) : okMsg); if (then) then(r);
      })
      .catch(function (e) { V.toast((e && e.message) || "Action failed — check you are on the owner plane", true); });
  }

  // The HONEST post-seal toast: report what the server said actually happened. `r.sealed` is true only when
  // the secret rests as ciphertext (OS keyring / TPM-backed vault); false means it fell through to the 0600
  // plaintext ~/.sigil/sigil.env, which is NOT sealed — so we say so instead of falsely claiming "sealed".
  function sealResultMsg(r, label) {
    var name = label || "The secret";
    if (r && r.sealed) {
      return r.backend === "sealed"
        ? name + " sealed to the TPM-backed vault."
        : name + " sealed to your OS keyring.";
    }
    return name + " stored in ~/.sigil/sigil.env — NOT sealed (install a keyring backend or provision the vault to seal).";
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
      h("div.grid.cols-2", { style: { alignItems: "start", marginTop: "16px" } }, [
        V.card("Reasoning effort", "OWNER", h("div#set-effort", null, h("div.empty", null, "Loading…")), true),
        V.card("Bring your own model", "OWNER", h("div#set-provider", null, h("div.empty", null, "Loading…")), true),
      ]),
      h("div", { style: { marginTop: "16px" } },
        V.card("System configuration", "OWNER",
          h("div#set-config", null, h("div.empty", null, "Loading…")), true)),
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
    drawEffortCard(st);
    drawProviderCard(st);
    drawConfigCard(st);
  }

  // The universal system-configuration plane: every non-secret operational env var the server exposes
  // (CONFIG_META), grouped by subsystem, each editable + saved with one owner-signed request. An empty
  // value clears the var (the code falls back to its default). The server type-validates every value
  // (int ranges, url/cidr/host/ports/enum) and refuses an unknown var — the UI writes no arbitrary env.
  function drawConfigCard(st) {
    var host = V.$("#set-config"); if (!host) return;
    var groups = st.config_groups || [];
    if (!groups.length) { V.mount(host, h("div.empty", null, "No configuration exposed by the server.")); return; }
    var sections = [
      h("div.hint", null, "Tune the whole system from here — offense engine, sovereign runtime, egress gateway, bring-up. Blank = the built-in default. Changes are signed on the server and take effect on the next `vigil up` (or service restart)."),
    ];
    groups.forEach(function (g) {
      var rows = g.fields.map(function (f) {
        var input;
        if (f.type === "enum") {
          input = h("select.input", null, (f.choices || []).map(function (c) {
            var o = h("option", { value: c }, c); if (c === f.value) o.selected = true; return o;
          }));
        } else if (f.type === "bool") {
          input = h("input", { type: "checkbox" }); input.checked = (f.value === "1");
        } else {
          input = h("input.input", { value: f.value || "", placeholder: f.placeholder || f.default || "" });
        }
        var save = h("button.btn.sm.owner", { onClick: function () {
          var val = (f.type === "bool") ? (input.checked ? "1" : "") : (input.value || "").trim();
          save.disabled = true;
          settingsAct({ action: "set_config", env: f.env, value: val, reason: "set " + f.env + " from Settings" },
            (f.label || f.env) + " saved.", function () { loadSettings(); })
            .then(function () { save.disabled = false; });
        } }, [V.icon("check"), "Save"]);
        return h("div.field", { style: { marginBottom: "10px" } }, [
          h("label", null, [f.label || f.env, h("code.mono", { style: { marginLeft: "8px", opacity: "0.6" } }, f.env)]),
          h("div.hint", { style: { margin: "2px 0 6px" } }, f.purpose || ""),
          // Prominent danger banner for a safety-floor toggle (e.g. VIGIL_ALLOW_PROTECTED_DOMAINS).
          f.warn ? h("div.set-status.off", { style: { color: "var(--warn,#d9a441)", fontWeight: "600", margin: "4px 0 8px" } },
            [V.icon("info"), h("span", null, f.warn)]) : null,
          h("div.row", { style: { display: "flex", gap: "8px", alignItems: "center" } }, [input, save]),
          // W10-2 — the sovereignty tier is delivered to the offense children at spawn; if the running
          // engine is enforcing a DIFFERENT tier than Settings request, say so here (the Governance pill
          // is the truthful one) so the operator knows the change needs an offense-plane restart to apply.
          f.env === "CRUCIBLE_SOVEREIGNTY_TIER" ? h("div#sov-tier-disagree", null, []) : null,
        ]);
      });
      sections.push(h("div", { style: { marginTop: "16px" } }, [
        h("h3", { style: { margin: "0 0 8px" } }, g.label),
        h("div", null, rows),
      ]));
    });
    V.mount(host, sections);
    // After the card is mounted, compare the CONFIGURED sovereignty tier against the tier the running
    // offense engine is actually enforcing (the Governance pill), and surface any disagreement.
    var tierField = null;
    groups.forEach(function (g) {
      (g.fields || []).forEach(function (f) { if (f.env === "CRUCIBLE_SOVEREIGNTY_TIER") tierField = f; });
    });
    if (tierField) surfaceSovereigntyTierDisagreement((tierField.value || "").trim() || "PERMISSIVE");
  }

  // W10-2 — Settings ↔ Governance-pill disagreement. The sovereignty tier reaches the keyless offense
  // children in their environment when they START; changing it in Settings updates the sovereign store,
  // not an already-running child. So the tier the engine is ENFORCING (read from the offense governance
  // posture — the Governance pill) can lag what Settings request until the offense plane is restarted. When
  // they differ, warn here and name the pill as the truth. The offense plane can be restarted from the
  // Status panel (Stop → Start) — a fresh `vigil up` is no longer required (PlaneControl re-resolves the
  // tier on restart), but it works too.
  function surfaceSovereigntyTierDisagreement(configured) {
    var box = V.$("#sov-tier-disagree"); if (!box) return;
    V.getJSON(OFF("/api/governance")).then(function (d) {
      var effective = d && d.sovereignty && d.sovereignty.tier;
      if (!effective || effective === configured) return;   // offense offline, or they agree → no banner
      V.mount(box, h("div.set-status.off", {
        style: { color: "var(--warn,#d9a441)", fontWeight: "600", margin: "6px 0 2px",
                 flexDirection: "column", alignItems: "stretch" } }, [
        h("div", null, [V.icon("info"), h("span", null,
          "The offense engine is enforcing tier " + effective + " right now — the Governance pill, the tier "
          + "actually in force — but Settings request " + configured + ".")]),
        h("div", { style: { marginTop: "4px", fontWeight: "400" } },
          "The offense children receive the tier when they start, so your change applies the next time the "
          + "offense plane starts. Restart it from the Status panel (Stop, then Start) — or run `vigil up`. "
          + "Until then the Governance pill is the truth."),
      ]));
    }).catch(function () { /* offense plane offline — nothing to compare, no banner */ });
  }

  // Reasoning-effort control: how hard current-generation models think (output_config.effort). "Model
  // default" clears it. Applies to the offense reasoning engine, the sovereign think step, AND the Strix
  // codebase agent (our "max" maps to Strix's top "xhigh"); older models ignore it (they steer by
  // prompting). The chatbot (A4) will offer the same control per-message.
  function drawEffortCard(st) {
    var host = V.$("#set-effort"); if (!host) return;
    var levels = st.effort_levels || ["low", "medium", "high", "xhigh", "max"];
    var current = st.selected_effort || "";
    var sel = h("select.input", null,
      [h("option", { value: "" }, "Model default")].concat(levels.map(function (lv) {
        var o = h("option", { value: lv }, lv.charAt(0).toUpperCase() + lv.slice(1));
        if (lv === current) o.selected = true;
        return o;
      })));
    var save = h("button.btn.owner", { onClick: function () {
        save.disabled = true;
        settingsAct({ action: "set_effort", effort: sel.value, reason: "set reasoning effort" },
          sel.value ? ("Reasoning effort set to " + sel.value + ".") : "Reasoning effort reset to the model default.",
          function () { loadSettings(); })
          .then(function () { save.disabled = false; });
      } }, [V.icon("check"), "Apply effort"]);
    V.mount(host, [
      h("div.field", null, [h("label", null, "Effort level"), sel]),
      h("div.acts", { style: { marginTop: "12px" } }, save),
      h("div.hint", { style: { marginTop: "10px" } },
        "Higher effort = deeper reasoning per step (slower, costs more); lower = faster, cheaper. Takes effect on the next `vigil up`. Only current-generation models honor this."),
    ]);
  }

  // Bring-your-own-model: pick a provider (Bedrock/Vertex/Azure/Mistral/self-hosted/Ollama/Claude), enter its
  // model + config; the server routes CRUCIBLE_LLM_BACKEND + model/config + Strix and clears the rest. Keys are
  // sealed in the API Keys screen; this card links there and shows which keys the chosen provider needs.
  function drawProviderCard(st) {
    var host = V.$("#set-provider"); if (!host) return;
    var providers = st.providers || [];
    if (!providers.length) { V.mount(host, h("div.empty", null, "No providers available from the server.")); return; }
    var cfg = st.provider_config || {};
    var chosen = st.selected_provider || (providers[0] && providers[0].id);
    var secretsByName = {}; (st.secrets || []).forEach(function (s) { secretsByName[s.name] = s; });

    var body = h("div", null, []);
    function spec() { return providers.filter(function (p) { return p.id === chosen; })[0] || providers[0]; }
    function render() {
      var p = spec();
      var modelInput = h("input", { placeholder: (p.models && p.models[0]) || "model / deployment id" });
      if (p.model_var && cfg[p.model_var]) modelInput.value = cfg[p.model_var];
      var configInputs = (p.config || []).map(function (c) {
        var inp = h("input", { placeholder: c.placeholder || "", value: cfg[c.env] || "" });
        inp.dataset.env = c.env;
        return h("div.field", { style: { marginTop: "10px" } },
          [h("label", null, c.label + (c.required ? " *" : "")), inp]);
      });
      var keyNeeds = (p.keys || []).map(function (kn) {
        var s = secretsByName[kn]; var hs = (s && s.health && s.health.status) || (s && s.set ? "unchecked" : "missing");
        var cls = hs === "ok" ? ".ok" : (hs === "fail" || hs === "missing" ? ".danger" : "");
        return h("span.pill.sm" + cls, { title: (s && s.health && s.health.reason) || "" },
          (s && s.label || kn) + (hs === "missing" ? " — not set" : (hs === "fail" ? " — failing" : (hs === "ok" ? " ✓" : ""))));
      });
      var save = h("button.btn.owner", { onClick: function () {
          var conf = {};
          configInputs.forEach(function (fld) { var i = fld.querySelector("input"); if (i && i.dataset.env) conf[i.dataset.env] = (i.value || "").trim(); });
          save.disabled = true;
          settingsAct({ action: "set_provider", provider: p.id, model: (modelInput.value || "").trim(),
            config: conf, reason: "set provider " + p.id },
            (p.label) + " selected.", function () { loadSettings(); refreshKeysBadge(); })
            .then(function () { save.disabled = false; });
        } }, [V.icon("check"), "Use this provider"]);
      V.mount(body, [
        p.keyless ? null : h("div.hint", { style: { marginBottom: "6px" } },
          [h("span", null, "Needs: "), keyNeeds.length ? keyNeeds : h("span.dim", null, "an API key"),
           h("span", null, " · "), h("a", { href: "#/apikeys" }, "manage keys")]),
        p.note ? h("div.set-status.off", null, [V.icon("info"), h("span", null, p.note)]) : null,
        p.model_var ? h("div.field", null, [h("label", null, "Model" + (p.models && p.models.length ? " (suggested: " + p.models.join(", ") + ")" : "")), modelInput]) : h("div.hint", null, "This provider uses your local session — no model id needed."),
        configInputs,
        h("div.acts", { style: { marginTop: "12px" } }, save),
      ]);
    }
    var sel = h("select.input", { onChange: function (e) { chosen = e.target.value; render(); } },
      providers.map(function (p) {
        var o = h("option", { value: p.id }, p.label + (p.id === st.selected_provider ? " — current" : ""));
        if (p.id === chosen) o.selected = true;
        return o;
      }));
    V.mount(host, [
      h("div.field", null, [h("label", null, "Provider"), sel]),
      body,
      h("div.hint", { style: { marginTop: "10px" } }, "Routes the offense reasoning engine (and the Strix codebase agent) to your chosen provider. Cloud/self-hosted models need their key + config; sovereign deployments can pick an EU or local provider. A running engine picks up the change on the next `vigil up`."),
    ]);
    render();
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
          function (r) { return sealResultMsg(r, sec.label || sec.name); },
          function () { input.value = ""; reload(); refreshKeysBadge(); })
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

  // ---- Cloud credentials: a detailed per-provider card (AWS / Azure / …) --------------------------
  // Each field is either a SEALED secret (masked input + Seal + set/health status) or a NON-SECRET config
  // var (text input + Save). One "Test connection" per provider runs the provider's live probe.
  function drawCloudField(f, reload) {
    if (f.kind === "secret") {
      // a "file" credential (a pasted GCP service-account JSON / kubeconfig) uses a textarea + the
      // base64-sealing action; a "line" credential uses a masked single-line input.
      var isFile = f.input === "file";
      var input = isFile
        ? h("textarea", { rows: "6", autocomplete: "off", spellcheck: "false",
            style: { fontFamily: "var(--mono, monospace)", fontSize: "12px", width: "100%" },
            placeholder: f.set ? "paste a new value to replace it…" : "paste the whole file…" })
        : h("input", { type: "password", autocomplete: "off", spellcheck: "false",
            placeholder: f.set ? "enter a new value to replace it" : "paste the value…" });
      var save = h("button.btn.owner", { onClick: function () {
          var v = (input.value || "").trim();
          if (!v) { V.toast("Paste a value first.", true); return; }
          save.disabled = true;
          var payload = isFile
            ? { action: "set_cloud_file_secret", name: f.env, content: v, reason: "set " + f.env + " (cloud creds)" }
            : { action: "set_secret", name: f.env, value: v, reason: "set " + f.env + " (cloud creds)" };
          settingsAct(payload, function (r) { return sealResultMsg(r, f.label || f.env); },
            function () { input.value = ""; reload(); refreshKeysBadge(); })
            .then(function () { save.disabled = false; });
        } }, [V.icon("key"), "Seal"]);
      var status = f.set
        ? h("div.set-status.ok", null, [V.icon("check"), h("span", null, "Set"),
            h("span.mono.dim", null, f.fingerprint), f.probeable ? healthChip(f) : null])
        : h("div.set-status.off", null, [V.icon("info"), h("span", null, "Not set")]);
      return h("div.field", null, [
        h("label", null, f.label || f.env), input, status,
        h("div.acts", { style: { marginTop: "6px" } }, [save]),
        f.purpose ? h("div.hint", null, f.purpose) : null,
      ]);
    }
    // non-secret config (region / role ARN / tenant / subscription) — value is shown
    var cin = h("input", { type: "text", autocomplete: "off", spellcheck: "false",
      value: f.value || "", placeholder: f.placeholder || "" });
    var csave = h("button.btn", { onClick: function () {
        csave.disabled = true;
        settingsAct({ action: "set_cloud_config", env: f.env, value: (cin.value || "").trim(),
          reason: "set " + f.env }, (f.label || f.env) + " saved.", function () { reload(); })
          .then(function () { csave.disabled = false; });
      } }, "Save");
    return h("div.field", null, [
      h("label", null, f.label || f.env),
      h("div.row-flex", null, [cin, csave]),
      f.warn ? h("div.hint", { style: { color: "var(--warn, #d9a441)" } }, [V.icon("info"), " " + f.warn]) : null,
    ]);
  }

  function drawCloudProvider(prov, st, reload) {
    var probeField = (prov.fields || []).filter(function (f) { return f.env === prov.probe_env; })[0];
    var test = (probeField && probeField.set) ? h("button.btn", { onClick: function () {
        test.disabled = true; test.textContent = "Testing…";
        settingsAct({ action: "check_secret", name: prov.probe_env, reason: "test " + prov.id + " credential" },
          "", function (r) {
            if (r && r.status === "ok") V.toast(prov.label + ": working.");
            else if (r && r.status === "fail") V.toast(prov.label + ": FAILING — " + (r.reason || ""), true);
            else V.toast(prov.label + ": " + ((r && r.reason) || "can't verify"), true);
            reload(); refreshKeysBadge();
          }).then(function () { test.disabled = false; test.textContent = "Test connection"; });
      } }, [V.icon("bolt"), "Test connection"]) : null;
    var body = [
      prov.purpose ? h("div.hint", { style: { marginBottom: "10px" } }, prov.purpose) : null,
      h("div.grid.cols-2", { style: { alignItems: "start" } },
        (prov.fields || []).map(function (f) { return drawCloudField(f, reload); })),
      test ? h("div.acts", { style: { marginTop: "12px" } }, [test])
           : h("div.hint", { style: { marginTop: "12px" } },
               "Seal the " + (prov.probe_env || "credential") + " to enable a live connection test."),
    ];
    return V.card(prov.label, "OWNER", body, true);
  }

  // ---- API Keys screen (owner plane) — every secret the system uses, grouped, with LIVE health -------
  // ---- Users & Roles (Claim 6 — OWNER-ONLY) ----------------------------------
  // Create per-user accounts with a role, hand out a one-time bearer token, change a role, or revoke.
  // Every account is an OWNER-SIGNED spine grant; the owner key stays the sole signer and RBAC is an
  // admission gate in front of it. This screen is owner-only both in the nav (V.can) and here (defence in
  // depth); the server also refuses create/assign/revoke to any non-owner (403).
  var USER_ROLES = ["viewer", "analyst", "operator"];
  // Token-lifetime presets for the create form. `secs: null` ⇒ never expires (the backward-compatible
  // default). The owner may also type a custom number of hours. The SERVER derives the absolute deadline
  // from its own clock and signs it into the grant; the browser only chooses the length.
  var TTL_PRESETS = [
    { label: "Never expires", secs: null },
    { label: "1 hour", secs: 3600 },
    { label: "8 hours", secs: 28800 },
    { label: "24 hours", secs: 86400 },
    { label: "7 days", secs: 604800 },
    { label: "30 days", secs: 2592000 },
  ];
  function renderUsers(screen) {
    if (!V.can("manage_users")) {
      V.mount(screen, h("div.wrap", null, [
        h("div.screen-head", null, [h("h1", null, "Users & Roles")]),
        V.card("Owner only", null, h("div.empty", null,
          "Managing users is owner-only. Sign in with the owner token to add or change accounts.")),
      ]));
      return;
    }
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Users & Roles"),
        h("span.sub", null, "Multi-user access control. Each account is an owner-signed grant; the owner key stays the sole signer.")]),
      ownerBanner("Owner plane — accounts are owner-signed on the server. A bearer token is shown ONCE at creation; only its salted hash is stored."),
      h("div.hint", { style: { margin: "4px 0 12px" } },
        [V.icon("info"), h("span", null,
          "Each account enforces per-user roles across the CLI (sigil accounts …), the direct API, and — "
          + "through vigil up — the browser login gate, which offers a bearer token, password + TOTP, or SSO "
          + "sign-in (W17-2); each user carries their own bearer and their role constrains them in the "
          + "browser. Enrol a teammate's login factors on their account below — a public key (strongest), a "
          + "TOTP second factor, or a password — or from the CLI, then they sign in through the gate.")]),
      h("div.grid.cols-2", { style: { alignItems: "start", marginTop: "16px" } }, [
        V.card("Create an account", "OWNER", h("div#users-create", null, usersCreateForm()), true),
        V.card("Accounts", "OWNER", h("div#users-list", null, h("div.empty", null, "Loading…")), true),
      ]),
      h("div", { style: { marginTop: "16px" } },
        V.card("Owner session", "OWNER", ownerSessionCard(), true)),
    ]);
    loadUsers();
  }
  // Owner session (bootstrap-token) controls (Slice 1b). The owner login token now PERSISTS across restarts
  // in dev posture (the same ?token= URL keeps working); rotate issues a new one, revoke kills it. Both are
  // FILE operations effective on the next cockpit restart (the reverse proxy re-reads the token then), so we
  // never desync a live `vigil up` session mid-flight.
  function ownerSessionCard() {
    var out = h("div", null, "");
    var rotate = h("button.btn.owner", { onClick: function () {
      if (!window.confirm("Rotate the owner session token?\n\nA new ?token= URL is issued. It applies on the "
        + "next cockpit restart; the current URL stops working then. Copy the new URL before you restart.")) return;
      settingsAct({ action: "rotate_bootstrap_token", reason: "rotate owner session from Users & Roles" },
        "Session rotated — copy the new URL, then restart.", function (r) {
        if (r && r.new_url_path) {
          var url = location.origin + r.new_url_path;
          var box = h("input.input.mono", { value: url, readonly: true,
            onClick: function (e) { e.target.select(); } });
          V.mount(out, h("div.set-status.ok", { style: { marginTop: "12px", flexDirection: "column", alignItems: "stretch" } }, [
            h("div", null, [V.icon("check"), h("span", null, " New session URL — applies on the next restart; "
              + "copy it now, then restart `vigil up`:")]),
            h("div.acts", { style: { marginTop: "8px", display: "flex", gap: "8px" } }, [box,
              h("button.btn.sm", { onClick: function () {
                try { navigator.clipboard.writeText(url); V.toast("Copied."); } catch (e) { box.select(); } } }, "Copy")]),
          ]));
        }
      });
    } }, [V.icon("bolt"), "Rotate session"]);
    var revoke = h("button.btn.danger", { onClick: function () {
      if (!window.confirm("Revoke the owner session token?\n\nThe next cockpit start mints a fresh one; the "
        + "current ?token= URL stops working after the restart.")) return;
      settingsAct({ action: "revoke_bootstrap_token", reason: "revoke owner session from Users & Roles" },
        "Session revoked — the next restart mints a fresh token.", function () { V.mount(out, ""); });
    } }, [V.icon("trash"), "Revoke session"]);
    var signoutAll = h("button.btn.danger", { onClick: function () {
      if (!window.confirm("Sign out ALL active cookie sessions?\n\nEvery teammate (and owner) cookie session "
        + "is invalidated immediately server-side; they must log in again. Bearer / URL-token sessions are "
        + "unaffected.")) return;
      settingsAct({ action: "revoke_sessions", reason: "sign out all sessions from Users & Roles" },
        "All cookie sessions signed out.", function () {});
    } }, [V.icon("x"), "Sign out all sessions"]);
    var enrollPk = _hasWebAuthn()
      ? h("button.btn.owner", { onClick: passkeyEnroll }, [V.icon("shield"), "Enrol a passkey"]) : null;
    return h("div", null, [
      h("div.hint", null, "Your owner login token now PERSISTS across restarts (dev posture) — the same "
        + "?token= URL keeps working after a reboot. Rotate to issue a new token, or revoke to kill it; both "
        + "apply on the next cockpit restart (the reverse proxy re-reads the token then). In production "
        + "posture the URL-token owner path is disabled — the owner logs in with a passkey. “Sign out all "
        + "sessions” immediately invalidates every server-side cookie session (idle + absolute expiry are "
        + "enforced automatically)."),
      h("div.acts", { style: { marginTop: "12px", display: "flex", gap: "8px", flexWrap: "wrap" } },
        [rotate, revoke, signoutAll, enrollPk]),
      out,
    ]);
  }
  function usersCreateForm() {
    var name = h("input.input", { placeholder: "username (letters, digits, . _ -)", autocomplete: "off" });
    var role = h("select.input", null, USER_ROLES.map(function (r) { return h("option", { value: r }, r); }));
    var ttl = h("select.input", null, TTL_PRESETS.map(function (t, i) {
      return h("option", { value: String(i) }, t.label); }));
    var ttlCustom = h("input.input.sm", { type: "number", min: "0", step: "1",
      placeholder: "or custom hours", style: { width: "140px" } });
    var out = h("div", null, "");
    var save = h("button.btn.owner", { onClick: function () {
      var u = (name.value || "").trim();
      if (!u) { V.toast("Enter a username.", true); return; }
      // A custom hours value (if > 0) overrides the preset; else the preset's seconds (null ⇒ never).
      var custH = parseFloat(ttlCustom.value);
      var ttlSecs = (custH && custH > 0) ? custH * 3600
        : (TTL_PRESETS[Number(ttl.value)] || TTL_PRESETS[0]).secs;
      save.disabled = true;
      settingsAct({ action: "create_account", username: u, role: role.value, ttl_seconds: ttlSecs,
        reason: "create account from Users & Roles" }, "Account created.", function (r) {
        save.disabled = false; name.value = ""; ttlCustom.value = "";
        if (r && r.bearer_token) {
          // show the one-time bearer with a copy control — it is NEVER retrievable again.
          var tokBox = h("input.input.mono", { value: r.bearer_token, readonly: true,
            onClick: function (e) { e.target.select(); } });
          var expLine = r.expires_at
            ? h("div.hint", { style: { marginTop: "6px" } },
                "Expires " + new Date(r.expires_at * 1000).toLocaleString()
                + " — after that the bearer stops authenticating.")
            : h("div.hint", { style: { marginTop: "6px" } },
                "This token never expires — revoke it to end access.");
          V.mount(out, h("div.set-status.ok", { style: { marginTop: "12px", flexDirection: "column", alignItems: "stretch" } }, [
            h("div", null, [V.icon("check"), h("span", null, " Copy this bearer for " + r.username
              + " (" + r.role + ") NOW — it is shown once and never stored in plaintext:")]),
            h("div.acts", { style: { marginTop: "8px", display: "flex", gap: "8px" } }, [tokBox,
              h("button.btn.sm", { onClick: function () {
                try { navigator.clipboard.writeText(r.bearer_token); V.toast("Copied."); }
                catch (e) { tokBox.select(); } } }, "Copy")]),
            expLine,
          ]));
        }
        loadUsers();
      });
    } }, [V.icon("key"), "Create account"]);
    return h("div", null, [
      h("div.hint", null, "The account gets a bearer token to sign in with. viewer = read-only; analyst = queue proposals; operator = run engagements, approve ≤A2, tune non-secret config. Only the owner approves A3, manages secrets, or manages users."),
      h("div.hint", { style: { marginTop: "6px" } },
        "Set a token lifetime (TTL) to auto-expire access, or leave it Never to revoke manually."),
      h("div.acts", { style: { marginTop: "12px", display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" } },
        [name, role, ttl, ttlCustom, save]),
      out,
    ]);
  }
  function loadUsers() {
    V.getJSON(SOV("/api/accounts")).then(function (d) {
      var host = V.$("#users-list"); if (!host) return;
      var accts = (d && d.accounts) || [];
      if (!accts.length) { V.mount(host, h("div.empty", null, "No accounts yet — create one on the left.")); return; }
      var rows = accts.map(usersRow);
      // Bulk revoke — the owner is never an account, so this cannot lock the owner out.
      rows.push(h("div", { style: { marginTop: "12px", textAlign: "right" } }, [
        h("button.btn.sm.danger", { onClick: function () {
          if (!window.confirm("Revoke ALL " + accts.length + " teammate account(s)?\n\nEvery bearer token "
            + "stops authenticating immediately. This cannot be undone — you would re-create the accounts.")) return;
          settingsAct({ action: "revoke_all_teammates", reason: "bulk revoke from Users & Roles" },
            "Revoked all teammate accounts.", loadUsers);
        } }, [V.icon("x"), "Revoke all"]),
      ]));
      V.mount(host, rows);
    }).catch(function (e) {
      var host = V.$("#users-list"); if (!host) return;
      V.mount(host, h("div.empty", null, (e && e.status === 403)
        ? "Managing users is owner-only." : "Accounts are on the sovereign plane, which is offline."));
    });
  }
  function usersRow(a) {
    var role = h("select.input.sm", null, USER_ROLES.map(function (r) {
      var o = h("option", { value: r }, r); if (r === a.role) o.selected = true; return o; }));
    var assign = h("button.btn.sm.owner", { onClick: function () {
      settingsAct({ action: "assign_role", username: a.username, role: role.value,
        reason: "assign role from Users & Roles" }, "Role updated for " + a.username + ".", loadUsers);
    } }, "Assign role");
    var revoke = h("button.btn.sm.danger", { onClick: function () {
      settingsAct({ action: "revoke_account", username: a.username, reason: "revoke from Users & Roles" },
        "Account " + a.username + " revoked.", loadUsers);
    } }, [V.icon("x"), "Revoke"]);
    // W17-3 enrolment: bind this account's login factors (owner-signed server-side). Non-secret boolean
    // flags from /api/accounts drive the "enrolled" pills so the operator sees the true state. Hidden for a
    // revoked account (the server refuses enrolment on one anyway — the UI does not offer a dead action).
    var factorPills = h("span", { style: { display: "flex", gap: "6px", flexWrap: "wrap" } }, [
      a.has_pubkey ? h("span.pill.sm.ok", null, "key") : null,
      a.has_totp ? h("span.pill.sm.ok", null, "TOTP") : null,
      a.has_password ? h("span.pill.sm", null, "password") : null,
    ]);
    // Token-expiry (TTL) pill: danger once expired, warn within a day, neutral countdown otherwise.
    // a.expires_at === null (⇒ a.remaining === null, a.expired === false) ⇒ never expires ⇒ no pill.
    var expPill = null;
    if (a.expired) {
      expPill = h("span.pill.sm.danger", null, "expired");
    } else if (typeof a.remaining === "number") {
      expPill = (a.remaining < 86400)
        ? h("span.pill.sm.warn", null, "expires " + (a.remaining < 3600
            ? "in " + Math.max(1, Math.round(a.remaining / 60)) + "m"
            : "in " + Math.round(a.remaining / 3600) + "h"))
        : h("span.pill.sm", null, "expires in " + Math.round(a.remaining / 86400) + "d");
    }
    return h("div.approval", null, [
      h("div.ah", null, [V.icon("key"), h("span.t", null, a.username),
        h("span.pill.sm", null, a.role), a.state === "revoked" ? h("span.pill.sm.danger", null, "revoked") : null,
        expPill, factorPills]),
      h("div.acts", { style: { display: "flex", gap: "8px", flexWrap: "wrap" } }, [role, assign, revoke]),
      a.state === "revoked" ? null : usersEnrolBlock(a),
    ]);
  }
  // Per-account login-factor enrolment (W17-3): a public key (strongest PoP login), a TOTP second factor,
  // and an optional password. Each posts an owner-signed action to the SAME broker the CLI drives
  // (enroll_pubkey / enroll_totp / set_password) and is owner-gated server-side (manage_users). TOTP hands
  // back a provisioning URI ONCE — shown here for the operator to scan/relay, never stored.
  function usersEnrolBlock(a) {
    var out = h("div", null, "");
    var pk = h("input.input.sm.mono", { placeholder: "base64 Ed25519 public key", autocomplete: "off",
      spellcheck: "false" });
    var enrollKey = h("button.btn.sm.owner", { onClick: function () {
      var v = (pk.value || "").trim();
      if (!v) { V.toast("Paste the account's base64 public key.", true); return; }
      settingsAct({ action: "enroll_pubkey", username: a.username, user_pubkey: v,
        reason: "enroll pubkey from Users & Roles" }, "Public key enrolled for " + a.username + ".",
        function () { pk.value = ""; loadUsers(); });
    } }, [V.icon("key"), "Enrol key"]);
    var enrollTotp = h("button.btn.sm.owner", { onClick: function () {
      settingsAct({ action: "enroll_totp", username: a.username, reason: "enroll TOTP from Users & Roles" },
        "TOTP enrolled for " + a.username + " — scan the URI below now.", function (r) {
        if (r && r.provisioning_uri) {
          var uriBox = h("input.input.sm.mono", { value: r.provisioning_uri, readonly: true,
            onClick: function (e) { e.target.select(); } });
          V.mount(out, h("div.set-status.ok", { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
            h("div", null, [V.icon("check"), h("span", null, " Scan this otpauth URI into the authenticator "
              + "NOW — shown once; the secret is sealed at rest and never recoverable from the spine:")]),
            h("div.acts", { style: { marginTop: "8px", display: "flex", gap: "8px" } }, [uriBox,
              h("button.btn.sm", { onClick: function () {
                try { navigator.clipboard.writeText(r.provisioning_uri); V.toast("Copied."); }
                catch (e) { uriBox.select(); } } }, "Copy")]),
          ]));
        }
        loadUsers();
      });
    } }, [V.icon("bolt"), a.has_totp ? "Re-enrol TOTP" : "Enrol TOTP"]);
    var pw = h("input.input.sm", { type: "password", placeholder: "new password (≥8 chars)",
      autocomplete: "new-password" });
    var setPw = h("button.btn.sm.owner", { onClick: function () {
      var v = pw.value || "";
      if (v.length < 8) { V.toast("Password must be at least 8 characters.", true); return; }
      settingsAct({ action: "set_password", username: a.username, password: v,
        reason: "set password from Users & Roles" }, "Password set for " + a.username + ".",
        function () { pw.value = ""; loadUsers(); });
    } }, [V.icon("key"), a.has_password ? "Reset password" : "Set password"]);
    return h("div", { style: { marginTop: "10px", paddingTop: "10px", borderTop: "1px solid var(--line,#2a2a2a)" } }, [
      h("div.hint", { style: { marginBottom: "8px" } }, "Login factors — a public key is the strongest "
        + "(challenge/response; the private key never touches the host); TOTP is a second factor on "
        + "password/PoP logins; a password is an optional weaker convenience."),
      h("div.acts", { style: { display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" } },
        [pk, enrollKey]),
      h("div.acts", { style: { display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center", marginTop: "8px" } },
        [enrollTotp, pw, setPw]),
      out,
    ]);
  }

  function renderApiKeys(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "API Keys"),
        h("span.sub", null, "Every key the system uses — sealed to your OS keyring or a TPM vault when available (otherwise stored 0600 in ~/.sigil/sigil.env, which is not sealed), and never shown back to the browser. Press Test to check a key is live; a failing key always shows here.")]),
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
      // provider-backed categories (cloud / graph) render as detailed PER-PROVIDER credential cards, each
      // with its full field set + a live Test. The provider's category is set server-side from its probe
      // secret, so a graph provider (Neo4j) groups under "Knowledge graph" and cloud ones under "Cloud".
      var provs = (st.cloud_providers || []).filter(function (p) { return (p.category || "cloud") === cat.id; });
      if (provs.length) {
        var hint = cat.id === "cloud"
          ? "Enter each cloud provider's credentials for the read-only pentest collectors. Everything is sealed "
            + "to a keyring or TPM vault when available (otherwise stored 0600 in ~/.sigil/sigil.env, not sealed), "
            + "and never shown back to the browser; a tenant/subscription id is shown, access "
            + "keys and secrets are masked. Press Test connection to verify a credential is live."
          : "Enter the connection details. The password is sealed to a keyring or TPM vault when available "
            + "(otherwise stored 0600 in ~/.sigil/sigil.env, not sealed), and never shown back to the "
            + "browser; the URI and username are shown. Press Test connection to verify it is live.";
        return h("div", { style: { marginTop: "18px" } }, [
          h("div.screen-head", { style: { marginBottom: "6px" } }, h("h2", null, cat.label)),
          h("div.hint", { style: { marginBottom: "8px" } }, hint),
          provs.map(function (p) { return drawCloudProvider(p, st, loadApiKeys); }),
        ]);
      }
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
          V.card("Agent promotions", "OWNER", h("div#safety-promos", null, h("div.empty", null, "Loading…")), true),
        ]),
        h("div.stack", null, [
          V.card("Kill-switch", "OWNER", h("div#safety-kill", null, h("div.empty", null, "Loading…")), true),
          V.card("Live governance feed", "LIVE", h("div.feed#safety-feed", null, h("div.empty", null, "Connecting to the sovereign spine…")), false),
        ]),
      ]),
      h("div.grid", { style: { marginTop: "4px" } }, [
        V.card("Pending approvals", "OWNER", h("div#safety-pending", null, h("div.empty", null, "Loading…")), true),
      ]),
    ]);
    loadSafety();
    loadPendingApprovals();
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
    // canonical kill-switch read: the producer emits the STRING "ENGAGED" (dashboard.snapshot); also accept
    // an object `.engaged` form. (A lowercase `=== "engaged"` here left the Safety tile/banner/button dead.)
    var engaged = !!(snap.kill_switch === "ENGAGED" || (snap.kill_switch && snap.kill_switch.engaged));
    var pend = snap.pending_approvals || [];
    var caps = snap.capabilities || {};
    // tiles
    var tiles = V.$("#safety-tiles");
    if (tiles) V.mount(tiles, [
      V.tile("Kill-switch", engaged ? "ENGAGED" : "Released", engaged ? "mesh halted" : "mesh live", engaged ? "danger" : "ok"),
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
    // agent promotions (trust-widening — owner-signed grant/revoke)
    var pb = V.$("#safety-promos");
    if (pb) V.mount(pb, safetyPromotions(snap.promotions || []));
    // kill-switch
    var kb = V.$("#safety-kill");
    if (kb) V.mount(kb, [
      h("div.set-status." + (engaged ? "off" : "ok"), null, [
        V.icon(engaged ? "info" : "check"),
        h("span", null, engaged
          ? "The kill-switch is ENGAGED — the agent mesh is halted (perception and memory-read stay alive)."
          : "The kill-switch is released — the agent mesh runs normally."),
      ]),
      h("div.acts", { style: { marginTop: "12px" } }, engaged
        // Releasing is OWNER-ONLY (kill_release). Halting is safe (any authenticated role). Real action
        // gating via V.can: an operator sees Release DISABLED (the server also refuses it → 403).
        ? h("button.btn.owner", { disabled: !V.can("kill_release"),
            title: V.can("kill_release") ? "" : "Releasing the kill-switch is owner-only.",
            onClick: function () {
            settingsAct({ action: "release", reason: "release from Safety" }, "Kill-switch released.", loadSafety); } }, [V.icon("play"), "Release"])
        : h("button.btn.danger", { onClick: function () {
            settingsAct({ action: "kill", reason: "engage from Safety" }, "Kill-switch engaged — mesh halted.", loadSafety); } }, [V.icon("x"), "Engage kill-switch"])),
      h("div.hint", { style: { marginTop: "10px" } }, "Halting is always safe and immediate. Releasing requires the owner's signed request."),
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

  // ---- Pending approvals (OFFENSE plane; OWNER-actionable via the sovereign signer) ---------------
  // The offense worker publishes a public-safe pending request per queued action. The OFFENSE console
  // stays KEYLESS (it only GET-lists these from OFF /api/status/approvals). Signing happens on the
  // SOVEREIGN plane: Approve/Deny POST to SOV /api/action (offense_approve/offense_deny), where the
  // cockpit mints an owner-signed token in-process and drops it in the shared approvals/signed/ dir for
  // the keyless offense broker to verify + consume (route-via-sovereign; see knowledge/decisions/0004
  // and kb/approvals.md). The owner PRIVATE key never reaches this offense console. `vigil approve sign`
  // from a terminal remains a valid fallback, shown under each item.
  function loadPendingApprovals() {
    function refresh() {
      V.getJSON(OFF("/api/approvals/loopback")).then(drawPendingApprovals).catch(function () {
        var box = V.$("#safety-pending");
        if (box) V.mount(box, h("div.empty", null, "The offense console is offline. Start it with `vigil up`."));
      });
    }
    refresh();
    liveTimers.push(setInterval(refresh, 5000));    // cleaned up by teardownLive() on navigation
  }

  function drawPendingApprovals(data) {
    var box = V.$("#safety-pending"); if (!box) return;
    var pend = (data && data.pending) || [];
    var base = (data && data.base_dir) || ".vigil-live";
    if (!pend.length) { V.mount(box, h("div.empty", null, "No actions awaiting approval.")); return; }
    V.mount(box, [
      h("div.hint", { style: { marginBottom: "10px" } },
        "These offense actions are queued and awaiting your owner signature. Approve signs in the sovereign "
        + "cockpit with your owner key (the offense console stays keyless — your key never reaches it). You can "
        + "still sign from a terminal instead; the command is under each item."),
      h("div.stack", null, pend.map(function (p) { return pendingApprovalCard(p, base); })),
    ]);
  }

  // Approve ONE queued offense action from the UI. The sovereign cockpit signs in-process with your owner
  // key (route-via-sovereign). First time, it needs the offense authority bound to that key — if the backend
  // says so, confirm the one-time bind and retry. `then` refreshes the queue.
  function _afterOffenseApprove(p, then) {
    pboxForgetApproval(p.request_id);
    V.toast("Approved — the action can run.");
    if (then) then();
    // APPROVE-THEN-CONTINUE (Wave 7): a run still block-waiting for the signature consumes the token
    // and continues on its own; a run that already PAUSED (operator slow past the wait window) needs
    // an explicit Resume. Only resume one that is actually paused-awaiting-approval, so this never
    // double-fires (the backend also refuses a second running run of a slug). Followed-run only.
    setTimeout(function () {
      var _pp = PBOX.run && String(PBOX.run.paused || "");
      if (PBOX.run && PBOX.run.status === "paused" && (_pp === "awaiting_approval" || _pp === "approval_rejected")) {
        V.toast("Resuming the run with your approval…");
        pboxRetry();
      }
    }, 1500);
  }

  function offenseApprove(p, then) {
    V.postJSON(SOV("/api/action"), { action: "offense_approve", request_id: p.request_id })
      .then(function (r) {
        if (r && r.needs_bind) {
          if (!confirm("Enable UI approvals? This binds offense approvals to your owner key (one time), so "
                     + "the cockpit can sign them. Your key stays sovereign-side.")) return;
          V.postJSON(SOV("/api/action"), { action: "offense_bind_authority" }).then(function (b) {
            if (b && b.error) { V.toast(b.error, true); return; }
            V.postJSON(SOV("/api/action"), { action: "offense_approve", request_id: p.request_id })
              .then(function (r2) {
                if (r2 && r2.ok) { _afterOffenseApprove(p, then); }
                else { V.toast((r2 && r2.error) || "Approve failed", true); }
              }).catch(function (e) { V.toast((e && e.message) || "Approve failed", true); });
          }).catch(function (e) { V.toast((e && e.message) || "Bind failed", true); });
          return;
        }
        if (r && r.ok) { _afterOffenseApprove(p, then); }
        else { V.toast((r && r.error) || "Approve failed — are you on the owner plane?", true); }
      })
      .catch(function (e) { V.toast((e && e.message) || "Approve failed", true); });
  }

  function offenseDeny(p, then) {
    if (!confirm("Deny this action? It is removed from the queue and the run's request is refused.")) return;
    V.postJSON(SOV("/api/action"), { action: "offense_deny", request_id: p.request_id })
      .then(function (r) {
        if (r && r.ok) { pboxForgetApproval(p.request_id); V.toast("Denied."); if (then) then(); }
        else { V.toast((r && r.error) || "Deny failed", true); }
      })
      .catch(function (e) { V.toast((e && e.message) || "Deny failed", true); });
  }

  function pendingApprovalCard(p, base) {
    var cmd = "vigil approve sign --base-dir " + base + " --request-id " + p.request_id;
    var refresh = function () { var b = V.$("#safety-pending"); if (b) loadPendingApprovals(); };
    return h("div.approval", null, [
      h("div.ah", null, [V.icon("key"), h("span.t", null, pbActionLabel(p) + " → " + (p.target || "—"))]),
      h("div.why", null, [
        h("div.mono.dim", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all" } },
          "request " + (p.request_id || "—") + (p.created_at_iso ? (" · " + p.created_at_iso) : "")),
        p.args_preview ? h("div.mono.dim", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all", marginTop: "4px" } }, p.args_preview) : null,
      ]),
      // owner-plane actions: sign / deny from the UI (the cockpit holds the key, not this console)
      h("div", { style: { marginTop: "10px", display: "flex", gap: "8px" } }, [
        h("button.btn.sm.owner", { onClick: function () { offenseApprove(p, refresh); } }, [V.icon("check"), "Approve"]),
        h("button.btn.sm", { onClick: function () { offenseDeny(p, refresh); } }, [V.icon("x"), "Deny"]),
      ]),
      // fallback: sign from a terminal instead (the offense console remains keyless either way)
      h("div", { style: { marginTop: "8px", display: "flex", gap: "8px", alignItems: "stretch" } }, [
        h("pre.code", { style: { flex: "1", margin: "0" } }, cmd),
        h("button.btn.sm", { title: "Copy the CLI sign command", onClick: function () { copyText(cmd); } }, "Copy"),
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

  // Agent promotions: an owner may promote a specific (agent, record-kind scope) so that agent's A2
  // proposals of that kind AUTO-APPROVE instead of queuing — a deliberate TRUST WIDENING. Every grant/
  // revoke here is signed with the owner key ON THE SERVER (the browser holds no key); ENVOY + DELEGATE
  // have no promotion path (the broker refuses). The list is the verified fold — a forged grant is not shown.
  function safetyPromotions(promos) {
    var rows = (promos || []).length
      ? h("div.stack", { style: { gap: "6px" } }, promos.map(function (p) {
          return h("div.cap-row", null, [
            h("div.cap-l", null, [h("b.mono", null, String(p.agent || "?")),
              h("span.pill.sm", null, "scope " + String(p.scope || "*"))]),
            h("button.btn.sm.danger", { onClick: function () {
              settingsAct({ action: "revoke", agent: p.agent, scope: p.scope, reason: "revoke from Safety" },
                "Promotion revoked for " + p.agent + ".", loadSafety); } }, "Revoke"),
          ]);
        }))
      : h("div.empty", null, "No agents are promoted — every A2 proposal queues for your sign-off.");
    var agentIn = h("input", { type: "text", placeholder: "agent (e.g. ARCHIVIST)", style: { maxWidth: "180px" } });
    var scopeIn = h("input", { type: "text", placeholder: "scope (record kind, or * )", value: "*", style: { maxWidth: "180px" } });
    var grant = h("button.btn.sm.owner", { onClick: function () {
      var a = (agentIn.value || "").trim(); var s = (scopeIn.value || "").trim() || "*";
      if (!a) { V.toast("Enter an agent to promote."); return; }
      settingsAct({ action: "promote", agent: a, scope: s, reason: "promote from Safety" },
        "Promoted " + a + " for scope " + s + ".", function () { agentIn.value = ""; loadSafety(); });
    } }, "Grant promotion");
    return [
      rows,
      h("div.hint", { style: { margin: "10px 0 8px" } },
        "Promoting an (agent, scope) lets that agent's A2 proposals of that kind auto-approve instead of queuing — a trust widening. A scope of * covers every kind; a per-kind revoke does NOT reduce a * grant — revoke the * row to fully un-promote. ENVOY and DELEGATE can never be promoted. The grant is signed with your owner key on the server."),
      h("div.row-flex", { style: { gap: "8px", flexWrap: "wrap", alignItems: "center" } }, [agentIn, scopeIn, grant]),
    ];
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
      h("div", { style: { marginTop: "16px" } }, detectIdentityCard()),
      h("div", { style: { marginTop: "16px" } }, destructionQuorumCard()),
    ]);
    loadDefense();
  }

  // Wave 11 (parity, SAFE orchestration console) — the m-of-n DESTRUCTION quorum that gates `vigil patch
  // --open-pr`. The browser shows only the PUBLIC quorum SHAPE (read-only) + the exact host/cosigner commands
  // to run: the key-minting (`provision-destruction` prints PRIVATE keys), per-host `enroll-cosigner`, the
  // `authorize-destruction`, and the actual `--open-pr` fire all run on the CLI — keys NEVER enter the browser
  // and no real PR is ever opened from here (ORCHESTRATE-while-key-on-host).
  function destructionQuorumCard() {
    var st = h("div#dq-status", null, h("div.empty", null, "Loading quorum status…"));
    function refresh() {
      V.getJSON(OFF("/api/destruction/status")).then(function (r) {
        r = r || {};
        if (r.ok === false) { V.mount(st, h("div.set-status.danger", null, r.error || "could not read the quorum")); return; }
        if (!r.provisioned) {
          V.mount(st, h("div.set-status.warn", { style: { flexDirection: "column", alignItems: "stretch" } }, [
            h("div", null, [V.icon("info"), h("span", null, " No destruction quorum provisioned")]),
            h("div.hint", { style: { marginTop: "4px" } }, r.detail || ""),
          ]));
          return;
        }
        V.mount(st, h("div.set-status.ok", { style: { flexDirection: "column", alignItems: "stretch" } }, [
          h("div", null, [V.icon("check"), h("span", null, " Provisioned: " + (r.threshold != null ? r.threshold : "?") + "-of-" + (r.signers != null ? r.signers : "?"))]),
          h("div.hint", { style: { marginTop: "4px" } }, "signers: " + ((r.signer_ids || []).join(", ") || "—") + "   ·   base-dir: " + (r.base_dir || "")),
        ]));
      }).catch(function (e) { V.mount(st, offlineEmpty(e, "Could not read the quorum status (owner only).")); });
    }
    refresh();
    // ORCHESTRATE-while-key-on-host: these run on the HOST / each cosigner's own host — never the browser.
    var cmds = [
      ["1. provision (mint keys — prints PRIVATE keys ONCE, on the host):", "vigil provision-destruction --threshold M --signers N"],
      ["   (or, per-host separation of duties) each co-signer, on THEIR host:", "vigil enroll-cosigner --key-id <id>            # sends back a PUBLIC enrollment.json"],
      ["   then assemble on the minting box (PUBLIC material only):", "vigil assemble-destruction --enrollment owner=owner.enrollment.json --enrollment w1=w1.enrollment.json --threshold M"],
      ["2. dry-run a patch (opens NOTHING — prints the action + pr-denied):", "vigil patch --finding-envelope <F.json> --target-repo <R>"],
      ["3. authorize ONE action (owner key from Settings, single-use):", "vigil authorize-destruction --action-id <pr-id> --slug <slug> --target <R>"],
      ["4. fire the gated PR (opens a REAL PR — only when fully armed):", "vigil patch --finding-envelope <F.json> --target-repo <R> --open-pr"],
    ];
    var guide = cmds.map(function (c) {
      return h("div", { style: { marginTop: "8px" } }, [
        h("div.hint", null, c[0]),
        h("pre.mono", { style: { margin: "2px 0 0", whiteSpace: "pre-wrap", fontSize: "12px" } }, c[1]),
      ]);
    });
    return h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Destruction quorum (m-of-n) — orchestration")]),
      h("div.hint", null, "The m-of-n quorum that gates `vigil patch --open-pr`. This view is READ-ONLY: it "
        + "shows the PUBLIC quorum shape below, and the exact commands to run ON THE HOST / each co-signer's own "
        + "host. The signing keys print ONCE on the host and NEVER enter the browser; no real PR is opened from "
        + "here. Run the steps in order; the fire step (4) opens a real PR only when the quorum is fully armed."),
      h("div", { style: { marginTop: "10px" } }, st),
      h("div", { style: { marginTop: "12px" } }, [h("div.hint", { style: { fontWeight: "600" } }, "Run on the host / each co-signer's own host:")].concat(guide)),
    ]);
  }

  // Wave 7 (parity) — the log-plane Detection Mirror (`vigil detect`, owner-only — it reads arbitrary host
  // log paths) + the offense stable PUBLIC identity keys (`vigil identity`, read). Both offense CLI-spawn.
  function detectIdentityCard() {
    var acc = h("input.inp", { type: "text", placeholder: "access log path (CLF) — optional" });
    var aut = h("input.inp", { type: "text", placeholder: "auth log path — optional" });
    var con = h("input.inp", { type: "text", placeholder: "connection/flow log path — optional" });
    var out = h("div", null, "");
    function show(title, promise) {
      V.mount(out, h("div.hint", { style: { marginTop: "8px" } }, title + "…"));
      promise.then(function (r) {
        var okv = !!(r && r.ok);
        V.mount(out, h("div.set-status" + (okv ? ".ok" : ".danger"), { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
          h("div", null, [V.icon(okv ? "check" : "x"), h("span", null, " " + title + ": " + (okv ? "done" : "failed"))]),
          (r && (r.text || r.error)) ? h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px", maxHeight: "260px", overflow: "auto" } }, r.text || r.error) : null,
        ]));
      }).catch(function (e) { V.mount(out, h("div.set-status.danger", { style: { marginTop: "8px" } }, title + ": " + ((e && e.message) || e))); });
    }
    return h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Log detection & offense identity")]),
      h("div.hint", null, "Run the Detection Mirror over your host log files (owner-only — it reads host paths), "
        + "and export the offense stable PUBLIC identity keys for owner delegation / pinning."),
      h("div", { style: { display: "flex", flexDirection: "column", gap: "8px", marginTop: "10px", maxWidth: "520px" } }, [acc, aut, con,
        h("div.acts", { style: { display: "flex", gap: "8px", flexWrap: "wrap" } }, [
          h("button.btn.sm.owner", { onClick: function () {
            if (!(acc.value || aut.value || con.value).trim()) { V.toast("enter at least one log path", true); return; }
            show("Detection Mirror", V.postJSON(OFF("/api/detect"), { access_log: acc.value || "", auth_log: aut.value || "", conn_log: con.value || "" }));
          } }, [V.icon("shield"), "Run Detection Mirror"]),
          h("button.btn.sm", { onClick: function () { show("Offense identity keys", V.postJSON(OFF("/api/identity"), {})); } }, [V.icon("key"), "Show identity keys"]),
        ]),
      ]),
      out,
    ]);
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
    // The status poll re-runs defDrawStatus every 4s; re-mounting defSetupForm() each tick replaces the
    // uncontrolled <input> nodes and wipes whatever the operator is mid-typing (upstream/port/secret/slug/
    // honeypot). Only (re)build the form when it is not already on screen — first paint, or after the
    // running panel / an offline message cleared it (detected by the absence of the upstream url input,
    // which is unique to the form). While the form is present, leave its live inputs untouched. The
    // running panel has no inputs, so re-mounting it every tick to refresh live status is harmless.
    if (setup) {
      if (running) V.mount(setup, defRunningPanel(gw, eff, req));
      else if (!setup.querySelector('input[type="url"]')) V.mount(setup, defSetupForm());
    }
    var ab = V.$("#def-actors");
    if (ab) {
      if (!actors.length) V.mount(ab, h("div.empty", null, running ? "No actors yet — drive some traffic through the gateway." : "Start the gateway to build per-actor beliefs."));
      else V.mount(ab, h("div.stack", null, actors.slice(0, 24).map(defActorRow)));
    }
  }

  function defRunningPanel(gw, eff, req) {
    var cur = eff || req;   // the mode actually in force
    var next = cur === "enforce" ? "observe" : "enforce";
    var toggleLabel = cur === "enforce" ? "Switch to Observe (watch-only)" : "Switch to Enforce (blocking)";
    var toggleBtn = h("button.btn.primary", { onClick: function () {
      if (next === "enforce" && !confirm("Enforce will BLOCK requests proven to be attacks — live, no restart. (Needs the AEGIS_RESPOND entitlement, else it stays observe.) Continue?")) return;
      V.postJSON(OFF("/api/aegis/mode"), { mode: next })
        .then(function (r) { if (r && r.error) { V.toast(r.error, true); return; } V.toast("Mode → " + next + "."); loadDefense(); })
        .catch(function (e) { V.toast((e && e.message) || "Could not change mode", true); });
    } }, [V.icon(next === "enforce" ? "shield" : "info"), toggleLabel]);
    return [
      h("div.set-status.ok", null, [V.icon("check"),
        h("span", null, "Gateway running — " + (gw.bind || "") + " → " + (gw.upstream || "") + " · mode " + (eff || req))]),
      req === "enforce" && eff !== "enforce"
        ? h("div.set-status.off", null, [V.icon("info"), h("span", null, "You requested ENFORCE but it downgraded to observe (the AEGIS_RESPOND entitlement isn’t available here) — nothing is being blocked.")])
        : null,
      h("div.acts", { style: { marginTop: "12px" } }, [
        toggleBtn,
        h("button.btn.danger", { onClick: function () {
          V.postJSON(OFF("/api/aegis/stop"), {}).then(function () { V.toast("Gateway stopped."); loadDefense(); })
            .catch(function (e) { V.toast((e && e.message) || "Could not stop the gateway", true); });
        } }, [V.icon("x"), "Stop gateway"]),
      ]),
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
    var S = { runs: [], run: null, elsewhere: "" };
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Fixes"),
        h("span.sub", null, "What to fix after discovery, and the gated process an auto-fix follows.")]),
      h("div#fx-body", null, h("div.empty", null, "Loading runs…")),
    ]);
    var want = (hashQuery().run) || "";
    V.getJSON(runsURL()).then(function (d) {
      S.runs = runsOf(d);                       // scoped to the active engagement
      S.run = S.runs.find(function (r) { return r.run_id === want; }) || S.runs[0] || null;
      S.elsewhere = (want && !S.runs.some(function (r) { return r.run_id === want; })) ? want : "";
      drawFixes(S);
    }).catch(function () {
      var b = V.$("#fx-body");
      if (b) V.mount(b, h("div.empty", null, "The offense engine is offline. Start it with `vigil up`."));
    });
  }

  function drawFixes(S) {
    var body = V.$("#fx-body"); if (!body) return;
    if (!S.runs.length) {
      V.mount(body, activeEngagement()
        ? scopedEmpty("runs", "Nothing has run under this job yet — a run's oracle-confirmed findings become fixable here.", [newAssessBtn()])
        : h("div.empty", null, [h("div.big", null, "No runs yet"),
          h("p", null, "Run an assessment first — its confirmed findings become fixable here."),
          h("button.btn.primary", { style: { marginTop: "12px" }, onClick: function () { location.hash = "#/assess"; } }, "New Assessment")]));
      return;
    }
    var picker = h("div.field", { style: { maxWidth: "560px", marginBottom: "0" } }, [
      h("label", null, "Run"),
      h("select", { onChange: function (e) {
          S.run = S.runs.find(function (r) { return r.run_id === e.target.value; }) || null;
          history.replaceState(null, "", "#/fixes?run=" + encodeURIComponent(S.run ? S.run.run_id : ""));
          S.elsewhere = "";
          drawFixes(S);
        } }, S.runs.map(function (r) {
        return h("option", { value: r.run_id, selected: S.run && r.run_id === S.run.run_id },
          (r.mode || "url") + " · " + (r.target || r.slug || r.run_id) + " · " + r.status);
      })),
    ]);
    V.mount(body, [S.elsewhere ? otherEngagementNote(S.elsewhere) : null, picker,
      h("div#fx-view", { style: { marginTop: "16px" } }, h("div.empty", null, "Loading fix plan…"))]);
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
      nodes.push(V.card("Fixable findings", "CONFIRMED", h("div.stack", null,
        fixable.map(function (f, i) { return fixFindingCard(f, plan.run_id, i, plan.runnable, plan.why_not); })), false));
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
  // The "Apply fix (gated)" button renders ONLY when the backend says this run can actually run the gated
  // ladder (`plan.runnable` — the SAME precondition `actions.apply_fix` enforces, served by the one shared
  // helper). Otherwise we show the backend's own `why_not` verbatim and point at the CLI. The UI must never
  // offer an action the backend is guaranteed to refuse.
  function fixFindingCard(f, runId, idx, runnable, whyNot) {
    var outId = "fx-out-" + idx, btnId = "fx-btn-" + idx;
    var applyBlock;
    if (!f.ref) {
      applyBlock = h("div.hint", { style: { marginTop: "10px" } },
        "No stable finding reference on record — apply from the CLI with `vigil patch`.");
    } else if (!runnable) {
      applyBlock = h("div.hint", { style: { marginTop: "10px" } },
        "In-console apply is unavailable for this run: " + (whyNot || "its precondition is not met.")
        + " You can still apply from the CLI with `vigil patch`.");
    } else {
      var vbtnId = "fx-vbtn-" + idx, voutId = "fx-vout-" + idx;
      applyBlock = h("div", { style: { marginTop: "10px" } }, [
        h("button.btn.sm#" + btnId, { onClick: function () { applyFix(runId, f.ref, btnId, outId); } },
          [V.icon("bolt"), "Apply fix (gated)"]),
        h("button.btn.sm.ghost#" + vbtnId, { style: { marginLeft: "8px" },
          onClick: function () { verifyFix(runId, f.ref, vbtnId, voutId); } },
          [V.icon("check"), "Verify (re-scan)"]),
        h("span.hint", { style: { marginLeft: "8px" } },
          "Apply runs the gated `vigil patch` ladder — your click is the operator approval for the "
          + "non-destructive stages AND a blanket up-front approval of every proposed edit (no per-file "
          + "prompt); the edits land in a disposable clone, so your source is never touched and no PR is "
          + "opened. Verify re-runs the deterministic static rule over YOUR source: `cleared` means the "
          + "rule no longer fires anywhere in the tree (apply the shown diff to your tree first). It proves "
          + "the pattern is gone, not that a runtime exploit was ever reachable."),
        h("div#" + outId, { style: { marginTop: "8px" } }),
        h("div#" + voutId, { style: { marginTop: "8px" } }),
      ]);
    }
    return h("div.fix-card", null, [
      h("div.fix-h", null, [
        h("span.vbadge." + (sevClass(f.severity) || "muted"), null, (f.severity || "?").toUpperCase()),
        h("b", null, f.title || f.bug_class || "finding"),
        f.bug_class ? h("span.pill.sm", null, f.bug_class) : null,
        p3Cwe(f) ? h("span.pill.sm", { title: p3Owasp(f) ? ("OWASP " + p3Owasp(f)) : "" }, p3Cwe(f)) : null,
      ]),
      f.location ? h("div.mono.dim", { style: { fontSize: "var(--fs-xs)", margin: "4px 0" } }, f.location) : null,
      h("div.fix-rem", null, [h("span.label", null, "Remediation"), h("p", null, f.remediation)]),
      f.confirmed_by ? h("div.dim", { style: { fontSize: "var(--fs-xs)", marginTop: "6px" } }, "confirmed by " + f.confirmed_by) : null,
      applyBlock,
    ]);
  }
  function applyFix(runId, ref, btnId, outId) {
    var btn = V.$("#" + btnId), out = V.$("#" + outId);
    if (btn) btn.disabled = true;
    if (out) V.mount(out, h("div.dim", null, "Running the gated patch ladder (non-destructive)…"));
    V.postJSON(OFF("/api/remediate/" + encodeURIComponent(runId) + "/" + encodeURIComponent(ref) + "/apply"), {})
      .then(function (r) {
        if (btn) btn.disabled = false;
        if (!out) return;
        if (r && r.error) { V.mount(out, h("div.legend", null, [V.icon("info"), r.error])); return; }
        V.mount(out, [
          h("div.legend", null, [V.icon(r.ok ? "check" : "info"),
            r.ok ? "The gated ladder ran (non-destructive — your source was not touched)."
                 : "The gated ladder refused or could not finish — its exact output is below."]),
          r.command ? h("div.mono.dim", { style: { fontSize: "var(--fs-xs)", margin: "4px 0" } }, r.command) : null,
          r.note ? h("div.hint", null, r.note) : null,
          h("pre.mono", { style: { marginTop: "6px", maxHeight: "260px", overflow: "auto", fontSize: "var(--fs-xs)", whiteSpace: "pre-wrap" } }, r.output || "(no output)"),
        ]);
      })
      .catch(function (e) {
        if (btn) btn.disabled = false;
        if (out) V.mount(out, h("div.legend", null, [V.icon("x"), (e && e.message) || "apply failed"]));
      });
  }
  function verifyFix(runId, ref, btnId, outId) {
    var btn = V.$("#" + btnId), out = V.$("#" + outId);
    if (btn) btn.disabled = true;
    if (out) V.mount(out, h("div.dim", null, "Re-scanning your source with the deterministic rule…"));
    V.postJSON(OFF("/api/remediate/" + encodeURIComponent(runId) + "/" + encodeURIComponent(ref) + "/verify"), {})
      .then(function (r) {
        if (btn) btn.disabled = false;
        if (!out) return;
        if (r && r.error) { V.mount(out, h("div.legend", null, [V.icon("info"), r.error])); return; }
        var stillAt = (r.still_fires_at || []).join(", ");
        V.mount(out, h("div.legend", null, [V.icon(r.cleared ? "check" : "x"),
          r.cleared
            ? "CLEARED — the deterministic rule no longer fires anywhere in your source (the vulnerable pattern is gone)."
            : ((r.moved ? "STILL PRESENT (moved) — the rule now fires at a different path"
                        : "STILL PRESENT — the rule still fires")
               + (stillAt ? " at " + stillAt : "")
               + ". Apply the proposed diff to your source, then Verify again.")]));
      })
      .catch(function (e) {
        if (btn) btn.disabled = false;
        if (out) V.mount(out, h("div.legend", null, [V.icon("x"), (e && e.message) || "verify failed"]));
      });
  }

  // ---- Terminal screen (T2) — AI proposes; allowlist + gate + you approve; only local reads run ----
  // The chat box translates English → a candidate command via Claude, shows its gate verdict, and waits for
  // your Run click. That command goes through the SAME gated `vigil terminal` path as a typed command — the
  // allowlist rejects anything off-list (network / writers / interpreters) even if the AI hallucinates it, and
  // nothing runs without your approval. Every run is signed. No key ⇒ the direct terminal still works.
  function termVerdictBadge(v) {
    var verdict = (v && v.verdict) || "refused";
    var cls = verdict === "refused" ? "danger" : (verdict === "queued" ? "warn" : "");
    var label = verdict === "queued" ? "QUEUES FOR YOU" : (verdict === "allowed" ? "ALLOWED" : "REFUSED");
    return h("span.vbadge." + (cls || "muted"), null, label);
  }
  // --- T2b: the chat DOCK (minimize / maximize, persisted across navigations) ----------------------
  // A collapsible chat panel. "min" collapses it to a slim pill (the terminal gets full height); "max"
  // focuses the chat (tall, scrollable); "open" is the default. State persists in localStorage. Every
  // control is a real focusable button, and Escape restores from a min/max state — keyboard-accessible.
  var TERM_DOCK_KEY = "vigil-term-dock";
  var _termEsc = null;
  function termDockState() {
    try { var s = localStorage.getItem(TERM_DOCK_KEY); return (s === "min" || s === "max") ? s : "open"; }
    catch (e) { return "open"; }
  }
  function termApplyDock(state) {
    var body = V.$("#term-dock-body"), pill = V.$("#term-dock-pill"),
        ctrls = V.$("#term-dock-ctrls"), maxBtn = V.$("#term-dock-max"), minBtn = V.$("#term-dock-min");
    var minimized = state === "min", maximized = state === "max";
    if (body) {
      body.style.display = minimized ? "none" : "";
      body.style.minHeight = maximized ? "46vh" : "";
      body.style.maxHeight = maximized ? "62vh" : "";
      body.style.overflowY = maximized ? "auto" : "";
    }
    if (pill) pill.style.display = minimized ? "flex" : "none";
    if (ctrls) ctrls.style.display = minimized ? "none" : "flex";
    if (minBtn) minBtn.setAttribute("aria-pressed", String(minimized));
    if (maxBtn) { maxBtn.textContent = maximized ? "Restore" : "Maximize"; maxBtn.setAttribute("aria-pressed", String(maximized)); }
  }
  function termToggleDock(target) {
    var next = termDockState() === target ? "open" : target;   // clicking the active control restores
    try { localStorage.setItem(TERM_DOCK_KEY, next); } catch (e) {}
    termApplyDock(next);
  }

  function renderTerminal(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Terminal"),
        h("span.sub", null, "Ask in plain English or type a command. The AI proposes; you approve; only local read-only commands run.")]),
      h("div.legend", null, [V.icon("shield"), h("span", null,
        "The AI is a capability-router: it can propose an allowlisted command (you approve with Run), answer a question about this session from retained findings, or point you at the right screen for a scan. Every command goes through the same allowlist + gate + signed record — it can only run local, read-only tools (ls, cat, grep, find, stat, …), never reach the network, change files, or run a shell. Even if the AI is wrong or prompt-injected, the allowlist refuses it and nothing runs without your approval. Answers and routes run nothing.")]),
      // --- the beginner-friendly path: ask in English (a minimize/maximize chat DOCK) -----------------
      h("div.card#term-dock", null, [
        h("div.card-h", { style: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px", flexWrap: "wrap" } }, [
          h("div", null, [h("span.label", null, "AI CHAT"), h("h3", { style: { margin: "0" } }, "Ask in plain English")]),
          h("div#term-dock-ctrls.row", { style: { gap: "6px" } }, [
            h("button.btn.sm#term-dock-min", { type: "button", "aria-label": "Minimize the chat dock", "aria-pressed": "false",
              onClick: function () { termToggleDock("min"); } }, "Minimize"),
            h("button.btn.sm#term-dock-max", { type: "button", "aria-label": "Maximize the chat dock", "aria-pressed": "false",
              onClick: function () { termToggleDock("max"); } }, "Maximize"),
          ]),
        ]),
        h("div#term-dock-pill", { style: { display: "none", alignItems: "center", justifyContent: "space-between", gap: "8px", padding: "4px 2px" } }, [
          h("span.dim", null, "Chat dock minimized — the terminal has full height."),
          h("button.btn.sm", { type: "button", "aria-label": "Restore the chat dock",
            onClick: function () { termToggleDock("min"); } }, "Restore chat"),
        ]),
        h("div#term-dock-body.stack", null, [
          h("div.field", { style: { marginBottom: "0" } }, [
            h("label", null, "What do you want to inspect or ask?"),
            h("div.row", { style: { gap: "8px" } }, [
              h("input#term-intent", { type: "text", placeholder: "e.g. show the last 20 lines of /etc/hostname — or: what did we prove this session?",
                style: { flex: "1" },
                onKeydown: function (e) { if (e.key === "Enter") { e.preventDefault(); termPropose(); } } }),
              h("button.btn.primary#term-propose-btn", { onClick: termPropose }, [V.icon("brain"), "Ask"]),
            ]),
          ]),
          h("div#term-proposal"),
        ]),
      ]),
      // --- the direct path: type a command ------------------------------------------------------------
      V.card("Or type a command", "DIRECT", h("div.stack", null, [
        h("div.field", { style: { marginBottom: "0" } }, [
          h("label", null, "Command (allowlisted local read/inspect binaries only)"),
          h("div.row", { style: { gap: "8px" } }, [
            h("input#term-direct", { type: "text", placeholder: "ls -la",
              style: { flex: "1", fontFamily: "var(--font-mono, monospace)" },
              onInput: function (e) { termDirectDryrun(e.target.value); },
              onKeydown: function (e) { if (e.key === "Enter") { e.preventDefault(); termRunDirect(); } } }),
            h("button.btn#term-direct-btn", { onClick: termRunDirect }, [V.icon("play"), "Run"]),
          ]),
          h("div#term-direct-badge", { style: { marginTop: "6px", minHeight: "18px" } }),
        ]),
      ]), false),
      // --- output + history ---------------------------------------------------------------------------
      V.card("Output", "SIGNED", h("pre.mono#term-output", { style: { maxHeight: "320px", overflow: "auto",
        whiteSpace: "pre-wrap", margin: "0", fontSize: "var(--fs-xs)" } }, "No command run yet."), false),
      V.card("Recent commands", "HISTORY", h("div#term-history", null, h("div.empty", null, "Loading…")), false),
    ]);
    termApplyDock(termDockState());              // restore the persisted dock state
    if (_termEsc) document.removeEventListener("keydown", _termEsc);
    _termEsc = function (e) {
      if (e.key === "Escape" && V.$("#term-dock") && termDockState() !== "open") {
        try { localStorage.setItem(TERM_DOCK_KEY, "open"); } catch (_) {}
        termApplyDock("open");
      }
    };
    document.addEventListener("keydown", _termEsc);
    termLoadHistory();
  }

  function termPropose() {
    var input = V.$("#term-intent"), btn = V.$("#term-propose-btn"), out = V.$("#term-proposal");
    var intent = input ? String(input.value || "").trim() : "";
    if (!out) return;
    if (!intent) { V.mount(out, h("div.hint", null, "Describe what you want to inspect, or ask about this session.")); return; }
    if (btn) btn.disabled = true;
    V.mount(out, h("div.dim", null, "Thinking (the AI is deciding whether this needs a command, an answer, or a scan)…"));
    var q = hashQuery();
    V.postJSON(OFF("/api/terminal/propose"), { intent: intent, run_id: q.run || "", session_id: q.id || "" })
      .then(function (r) {
        if (btn) btn.disabled = false;
        if (r && r.need_key) {
          V.mount(out, h("div.legend", null, [V.icon("key"), h("span", null, r.note ||
            "Add a Claude API key in Settings to use natural language, or type a command directly.")]));
          return;
        }
        if (r && r.error) { V.mount(out, h("div.legend", null, [V.icon("info"), r.error])); return; }
        termRenderProposal(r);
      })
      .catch(function (e) {
        if (btn) btn.disabled = false;
        V.mount(out, h("div.legend", null, [V.icon("x"), (e && e.message) || "propose failed"]));
      });
  }
  // ASK vs DO: render the router's three modes. answer → a cited bubble (no Run); route → a suggestion +
  // link to the right screen (no Run); command → the proposal + verdict + Run/Edit/Cancel (as T2).
  function termRenderProposal(r) {
    var out = V.$("#term-proposal"); if (!out) return;
    var mode = (r && r.mode) || ((r && r.command) ? "command" : "");
    if (mode === "answer") { termRenderAnswer(r); return; }
    if (mode === "route") { termRenderRoute(r); return; }
    var verdict = r && r.verdict;
    var refused = !r || !r.ok || (verdict && verdict.verdict === "refused");
    var nodes = [
      h("div.row", { style: { gap: "8px", alignItems: "center", flexWrap: "wrap" } }, [
        h("span.label", null, "Proposed command"), termVerdictBadge(verdict),
      ]),
      h("pre.mono", { style: { margin: "6px 0", whiteSpace: "pre-wrap", fontSize: "var(--fs-sm)" } },
        (r && r.command) ? r.command : "(the AI proposed no runnable command)"),
      r && r.explanation ? h("div.hint", null, r.explanation) : null,
      verdict && verdict.reason ? h("div.dim", { style: { fontSize: "var(--fs-xs)", margin: "4px 0" } }, verdict.reason) : null,
    ];
    if (refused || !r.command) {
      nodes.push(h("div.legend", null, [V.icon("shield"), h("span", null,
        "This request maps to no allowlisted local command, so nothing will run. Rephrase, or type a command directly.")]));
    } else {
      nodes.push(h("div.row", { style: { gap: "8px", marginTop: "8px" } }, [
        h("button.btn.primary", { onClick: function () { termRun(r.command); } }, [V.icon("play"), "Run"]),
        h("button.btn", { onClick: function () {
            var d = V.$("#term-direct"); if (d) { d.value = r.command; d.focus(); termDirectDryrun(r.command); } } },
          [V.icon("fixes"), "Edit"]),
        h("button.btn", { onClick: function () { var p = V.$("#term-proposal"); if (p) V.clear(p); } }, "Cancel"),
      ]));
    }
    V.mount(out, nodes);
  }
  function termRenderAnswer(r) {
    var out = V.$("#term-proposal"); if (!out) return;
    var cites = (r && r.cites) || [];
    V.mount(out, h("div.card", { style: { background: "var(--surface-2, rgba(120,150,255,0.06))", padding: "10px 12px", margin: "0" } }, [
      h("div.row", { style: { gap: "8px", alignItems: "center", marginBottom: "4px" } }, [
        h("span.label", null, "ANSWER"), h("span.vbadge.muted", null, "READ-ONLY · NOTHING RAN"),
      ]),
      h("div", { style: { whiteSpace: "pre-wrap" } }, (r && r.answer) || ""),
      cites.length ? h("div.dim", { style: { fontSize: "var(--fs-xs)", marginTop: "8px" } },
        [h("span.label", null, "Cites: "), cites.join("  ·  ")]) : null,
      h("div.hint", { style: { marginTop: "6px" } }, "Answered from the retained session data only — no command was run and no traffic was sent."),
    ]));
  }
  function termRenderRoute(r) {
    var out = V.$("#term-proposal"); if (!out) return;
    var screen = (r && r.screen) || "assess";
    V.mount(out, h("div.card", { style: { padding: "10px 12px", margin: "0" } }, [
      h("div.row", { style: { gap: "8px", alignItems: "center", marginBottom: "4px" } }, [
        h("span.label", null, "USE THE ENGAGEMENT PATH"), h("span.vbadge.muted", null, "NOTHING RAN"),
      ]),
      h("div", { style: { whiteSpace: "pre-wrap" } }, (r && r.suggestion) || "This needs the gated engagement path."),
      h("div.row", { style: { gap: "8px", marginTop: "8px" } }, [
        h("button.btn.primary", { onClick: function () { location.hash = "#/" + screen; } }, [V.icon("bolt"), "Go to " + (screen === "assess" ? "New Assessment" : screen)]),
      ]),
      h("div.hint", { style: { marginTop: "6px" } }, "The local terminal is read-only and offline — a scan, crawl, or exploit runs on the gated engagement path with its own approvals."),
    ]));
  }

  var _termDryrunTimer = null;
  function termDirectDryrun(command) {
    var badge = V.$("#term-direct-badge"); if (!badge) return;
    command = String(command || "").trim();
    if (_termDryrunTimer) clearTimeout(_termDryrunTimer);
    if (!command) { V.clear(badge); return; }
    _termDryrunTimer = setTimeout(function () {
      V.postJSON(OFF("/api/terminal/dryrun"), { command: command })
        .then(function (v) {
          V.mount(badge, h("div.row", { style: { gap: "8px", alignItems: "center" } }, [
            termVerdictBadge(v),
            h("span.dim", { style: { fontSize: "var(--fs-xs)" } }, (v && v.reason) || ""),
          ]));
        })
        .catch(function () { V.clear(badge); });
    }, 300);
  }
  function termRunDirect() {
    var d = V.$("#term-direct"); var command = d ? String(d.value || "").trim() : "";
    if (command) termRun(command);
  }
  function termRun(command) {
    var out = V.$("#term-output"); if (out) V.mount(out, "Running (gated, signed)…");
    V.postJSON(OFF("/api/terminal/run"), { command: command })
      .then(function (r) { termRenderOutput(command, r); termLoadHistory(); })
      .catch(function (e) {
        if (out) V.mount(out, "Run failed: " + ((e && e.message) || "error"));
      });
  }
  function termRenderOutput(command, r) {
    var out = V.$("#term-output"); if (!out) return;
    if (!r) { V.mount(out, "No result."); return; }
    var lines = [];
    lines.push("$ " + command);
    if (r.error) { lines.push("refused: " + r.error); }
    lines.push("outcome : " + (r.outcome || "?") + "   tier: " + (r.tier || "?") + "   ran: " + (r.ran ? "yes" : "no"));
    if (r.reason) lines.push("reason  : " + r.reason);
    if (r.exit_code != null) lines.push("exit    : " + r.exit_code);
    if (r.record_id) lines.push("signed record: " + r.record_id);
    lines.push("");
    if (r.stdout) lines.push(r.stdout);
    if (r.stderr) lines.push("[stderr]\n" + r.stderr);
    V.mount(out, lines.join("\n"));
  }
  function termLoadHistory() {
    var host = V.$("#term-history"); if (!host) return;
    V.getJSON(OFF("/api/terminal/history"))
      .then(function (d) {
        var recs = (d && d.records) || [];
        if (!recs.length) { V.mount(host, h("div.empty", null, "No commands run yet. Each run is gated and appended here as a signed record.")); return; }
        V.mount(host, h("div.stack", null, recs.map(function (rec) {
          var argv = (rec.argv || []).join(" ");
          return h("div.kv", null, [
            h("div.k", null, "#" + (rec.seq != null ? rec.seq : "?")),
            h("div.v.mono", { style: { fontSize: "var(--fs-xs)" } }, argv || "(command)"),
            h("div.k", null, (rec.tier || "A2")),
            h("div.v", null, "exit " + (rec.exit_code != null ? rec.exit_code : "?") + (rec.signature ? " · signed" : "")),
          ]);
        })));
      })
      .catch(function () { V.mount(host, h("div.empty", null, "History is unavailable (start the engine with `vigil up`).")); });
  }

  // ---- Brain screen (Memory / Benchmark / Catalog / Intel / Planner) ---------
  // Every tab is REAL data from an existing read endpoint; honest empty states throughout — no fabricated
  // priors/scores. Reasoning is presented as advisory-only (it never promotes a finding — the oracle does).
  var BRAIN_TABS = [
    { id: "decide", label: "Decision engine" },
    { id: "memory", label: "Memory" }, { id: "benchmark", label: "Benchmark" },
    { id: "catalog", label: "Catalog" }, { id: "intel", label: "Intel" }, { id: "planner", label: "Planner" },
  ];

  // MCP Servers — the gated CRUCIBLE capabilities this engine EXPOSES to an external MCP (Model Context
  // Protocol) client over an on-host stdio server. READ-ONLY: it lists the fixed, fail-closed allowlist of
  // exposable tools + their gate posture (tier / gated / observation / read-only). Starting the stdio server
  // (`crucible mcp serve --slug <engagement>`) is a CLI act; a UI start/stop toggle is a later slice.
  function renderMcp(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "MCP Servers"),
        h("span.sub", null, "The gated capabilities this engine exposes to an external MCP (Model Context Protocol) client over an on-host stdio server.")]),
      h("div#mcp-body", { style: { marginTop: "16px" } }, h("div.empty", null, "Loading MCP capabilities…")),
    ]);
    V.getJSON(OFF("/api/mcp")).then(drawMcp).catch(function (e) {
      V.mount(V.$("#mcp-body"), offlineEmpty(e, "Could not reach the offense console to list MCP capabilities. Start it (`vigil up`) and reload."));
    });
  }

  function drawMcp(d) {
    var body = V.$("#mcp-body"); if (!body) return;
    var tools = (d && d.exposed_tools) || [];
    function toolCard(t) {
      var m = (t._meta && t._meta.crucible) || {};
      var ann = t.annotations || {};
      return V.card(t.name, "GATED", [
        h("p", { style: { marginTop: "0", color: "var(--text-1)" } }, t.description || ""),
        h("div", { style: { display: "flex", gap: "6px", flexWrap: "wrap", marginTop: "8px" } }, [
          V.pill("tier " + (m.tier || "T1"), "", null),
          m.gated ? V.pill("gated", "", null) : null,
          V.pill(m.provenance || "observation", "idle", null),
          ann.readOnlyHint ? V.pill("read-only", "up", null) : null,
        ]),
      ], false);
    }
    V.mount(body, [
      h("div.legend", { style: { marginBottom: "12px" } }, [V.icon("info"), d.note || ""]),
      tools.length
        ? h("div.grid.cols-2", { style: { alignItems: "start" } }, tools.map(toolCard))
        : h("div.empty", null, "No MCP capabilities are exposed in this build."),
      h("div.legend", { style: { marginTop: "12px" } }, [V.icon("info"),
        "Transport: " + (d.transport || "stdio") + " — on-host, no network surface. Start the server with `crucible mcp serve --slug <engagement>`."]),
    ]);
  }

  // System & Services — the whole system's readiness at a glance (the `vigil doctor` report surfaced in the
  // UI): prerequisites (binaries + both venvs + writable dirs), the four UI ports, and every docker
  // service's live state. READ-ONLY; bring up the absent services with `vigil services up`.
  function renderSystem(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "System & Services"),
        h("span.sub", null, "Everything the system needs, at a glance — prerequisites, the UI ports, and every docker service's state.")]),
      h("div#system-body", { style: { marginTop: "16px" } }, h("div.empty", null, "Checking system readiness…")),
    ]);
    V.getJSON(OFF("/api/services")).then(drawSystem).catch(function (e) {
      V.mount(V.$("#system-body"), offlineEmpty(e, "Could not reach the offense console for the readiness report. Start it (`vigil up`) and reload."));
    });
  }

  function drawSystem(d) {
    var body = V.$("#system-body"); if (!body) return;
    function row(label, ok, detail, cls) {
      return h("div.kv", null, [
        h("div.k", null, [V.pill(ok ? "OK" : "—", cls || (ok ? "up" : "idle"), null), " " + label]),
        h("div.v", null, detail || ""),
      ]);
    }
    var bins = d.binaries || {}, venvs = d.venvs || {}, dirs = d.dirs || {}, ports = d.ui_ports || {}, svcs = d.docker_services || {};
    var prereq = V.card("Prerequisites", d.ok ? "READY" : "ACTION NEEDED", [
      h("div", null, Object.keys(bins).map(function (b) { return row(b, bins[b], bins[b] ? "installed" : "missing"); })),
      h("div", null, Object.keys(venvs).map(function (v) { return row(v + " venv", venvs[v], venvs[v] ? "built" : "not built — run ./bootstrap.sh"); })),
      h("div", null, Object.keys(dirs).map(function (k) { var x = dirs[k] || {}; return row(k, !!x.writable, (x.path || "") + (x.writable ? " (writable)" : " (NOT writable)")); })),
    ], false);
    var portCard = V.card("UI ports (127.0.0.1)", "", h("div", null,
      Object.keys(ports).map(function (p) { return row(p, ports[p] === "free", ports[p], ports[p] === "free" ? "up" : "idle"); })), false);
    var allChk = h("input", { type: "checkbox" });
    var upBtn = h("button.btn.owner", { onClick: function () {
      upBtn.disabled = true;
      V.postJSON(OFF("/api/services/up"), { all: allChk.checked })
        .then(function (r) {
          if (r && r.error) { V.toast(r.error, true); }
          else { V.toast("Services bring-up requested — refreshing state…"); }
          setTimeout(function () { if (V.$("#system-body")) V.getJSON(OFF("/api/services")).then(drawSystem).catch(function () {}); }, 1800);
        })
        .catch(function (e) { V.toast((e && e.message) || "Bring-up failed — is the offense console up?", true); })
        .then(function () { upBtn.disabled = false; });
    } }, [V.icon("play"), "Bring up missing services"]);
    var svcCard = V.card("Docker services", "", [
      h("div.hint", { style: { marginBottom: "8px" } }, "Create the absent ones — idempotent, running ones are left alone."),
      h("div", null, Object.keys(svcs).map(function (name) {
        var s = svcs[name] || {}; var st = (typeof s === "string") ? s : (s.state || (s.error ? "error" : "?"));
        var running = st === "running", absent = st === "absent";
        return h("div.kv", null, [
          h("div.k", null, [V.pill(running ? "running" : st, running ? "up" : (absent ? "idle" : "danger"), null), " " + name]),
          h("div.v", null, (typeof s === "object" && s.purpose) ? s.purpose : ""),
        ]);
      })),
      h("div.acts", { style: { marginTop: "12px", display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" } }, [
        upBtn,
        h("label", { style: { display: "flex", gap: "6px", alignItems: "center", fontSize: "13px", color: "var(--text-1)" } }, [allChk, "include Neo4j + otel"]),
        // Wave 4 — gateway lifecycle down/render (owner). `render` only rewrites the compose file (safe);
        // `down` stops+removes the gateway container (networks left in place).
        h("button.btn.sm", { onClick: function () {
          if (!confirm("Stop + remove the egress-gateway container? (docker networks are left in place)")) return;
          V.postJSON(OFF("/api/services/down"), {}).then(function (r) { V.toast(r && r.ok ? "Gateway stopped." : (r && r.error) || "down failed", !(r && r.ok)); setTimeout(function () { if (V.$("#system-body")) V.getJSON(OFF("/api/services")).then(drawSystem).catch(function () {}); }, 1200); }).catch(function (e) { V.toast((e && e.message) || "down failed", true); });
        } }, [V.icon("x"), "Gateway down"]),
        h("button.btn.sm", { onClick: function () {
          V.postJSON(OFF("/api/services/render"), {}).then(function (r) { V.toast(r && r.ok ? "Compose file re-rendered." : (r && r.error) || "render failed", !(r && r.ok)); }).catch(function (e) { V.toast((e && e.message) || "render failed", true); });
        } }, [V.icon("gear"), "Re-render compose"]),
      ]),
    ], false);
    var issues = d.issues || [];
    var issuesCard = issues.length ? V.card("Action needed", "!", h("ul", { style: { margin: "0", paddingLeft: "18px" } }, issues.map(function (m) { return h("li", null, m); })), false) : null;
    var notes = d.notes || [];
    V.mount(body, [
      h("div", null, daemonsCard()),
      h("div.grid.cols-2", { style: { alignItems: "start", marginTop: "16px" } }, [prereq, portCard]),
      h("div.grid.cols-2", { style: { alignItems: "start", marginTop: "16px" } }, [svcCard, issuesCard].filter(Boolean)),
      h("div", { style: { marginTop: "16px" } }, doctorCard()),
      h("div", { style: { marginTop: "16px" } }, lifecycleCard()),
      notes.length ? h("div.legend", { style: { marginTop: "12px" } }, [V.icon("info"), notes.join("  ·  ")]) : null,
    ]);
  }

  // Wave 4 (parity) — the read-only daemon/unit health strip (`vigil alerts --status --json`): a light per
  // HA/scheduled unit (backup, off-host push, recovery drill, HA mirror-sync, integrity, posture, reprove).
  function daemonsCard() {
    var out = h("div", null, h("div.empty", null, "Loading daemon health…"));
    function pill(state) {
      var up = state === "HEALTHY", absent = state === "ABSENT";
      return V.pill(state || "?", up ? "up" : (absent ? "idle" : "danger"), null);
    }
    V.postJSON(OFF("/api/daemons/status"), {}).then(function (r) {
      if (r && r.error) { V.mount(out, h("div.set-status.danger", null, [V.icon("x"), h("span", null, " " + r.error)])); return; }
      var st = (r && r.statuses) || [];
      if (!st.length) {
        // distinguish "the read failed" (ok:false, no statuses) from "genuinely nothing registered"
        var msg = (r && r.ok) ? "No scheduled units registered." : "Could not read daemon health (the check did not return a unit list).";
        V.mount(out, h("div.empty", null, msg)); return;
      }
      V.mount(out, [
        h("div", null, st.map(function (s) {
          return h("div.kv", null, [
            h("div.k", null, [pill(s.state), " " + s.unit]),
            h("div.v", { style: { fontSize: "12.5px", color: "var(--text-2)" } }, s.detail || ""),
          ]);
        })),
        (r.delivery_stale ? h("div.set-status.danger", { style: { marginTop: "8px" } }, [V.icon("x"), h("span", null, " alert delivery is STALE — " + (r.delivery_detail || ""))]) : null),
      ]);
    }).catch(function (e) { V.mount(out, offlineEmpty(e, "Could not reach the offense console for daemon health.")); });
    return h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Daemons & scheduled units"),
        h("button.btn.sm", { style: { marginLeft: "auto" }, onClick: function () { drawSystem({}); V.getJSON(OFF("/api/services")).then(drawSystem).catch(function () {}); } }, [V.icon("play"), "Refresh"])]),
      h("div.hint", null, "Heartbeat staleness for every HA / scheduled unit — read-only. A stale or failed heartbeat lights amber/red."),
      h("div", { style: { marginTop: "10px" } }, out),
    ]);
  }

  // Wave 4 (parity) — Lifecycle & Emergency: Restricted Mode (emergency-stop), the emergency hard-stop
  // (panic), and containing the console (down). panic/down are DETACHED on the server — they stop THIS
  // console, so the connection drops after the request; both are double-confirmed here.
  function lifecycleCard() {
    var esOut = h("div", null, "");
    function esStatus() {
      V.postJSON(OFF("/api/emergency-stop"), { action: "status" }).then(function (r) {
        V.mount(esOut, h("pre.mono", { style: { marginTop: "8px", whiteSpace: "pre-wrap", fontSize: "12px" } }, (r && r.text) || (r && r.error) || ""));
      }).catch(function (e) { V.mount(esOut, h("div.hint", { style: { marginTop: "8px" } }, (e && e.message) || "status failed")); });
    }
    return h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Lifecycle & Emergency")]),
      h("div.hint", null, "Restricted Mode trips every kill-switch but keeps the process UP for diagnosis. "
        + "The hard-stop and Contain the console are DETACHED — they stop this console, so the page will drop after you confirm."),
      h("div.acts", { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "10px" } }, [
        h("button.btn.sm", { onClick: esStatus }, [V.icon("find"), "Mode status"]),
        h("button.btn.sm.danger", { onClick: function () {
          if (!confirm("Enter RESTRICTED MODE? Every engagement's kill-switch is tripped — all target-touching actions are refused until an owner lifts it. The process stays up.")) return;
          V.postJSON(OFF("/api/emergency-stop"), { action: "enter" }).then(function (r) { V.toast(r && r.ok ? "Restricted Mode ON." : (r && r.error) || "failed", !(r && r.ok)); esStatus(); }).catch(function (e) { V.toast((e && e.message) || "failed", true); });
        } }, [V.icon("shield"), "Enter Restricted Mode"]),
        h("button.btn.sm.owner", { onClick: function () {
          if (!confirm("Leave Restricted Mode and restore full operation? (owner only)")) return;
          V.postJSON(OFF("/api/emergency-stop/leave"), {}).then(function (r) { V.toast(r && r.ok ? "Restricted Mode OFF." : (r && r.error) || "failed", !(r && r.ok)); esStatus(); }).catch(function (e) { V.toast((e && e.message) || "failed", true); });
        } }, [V.icon("check"), "Leave (owner)"]),
      ]),
      esOut,
      h("div", { style: { height: "1px", background: "var(--line)", margin: "14px 0" } }),
      h("div.acts", { style: { display: "flex", gap: "8px", flexWrap: "wrap" } }, [
        h("button.btn.sm.danger", { onClick: function () {
          if (!confirm("EMERGENCY HARD-STOP (panic)?\n\nThis trips every kill-switch, masks + stops the command unit, disables the cadence timers, and kills tracked processes. THIS CONSOLE WILL STOP — the page will go blank. Clearing containment is a manual CLI act.\n\nProceed?")) return;
          V.postJSON(OFF("/api/panic"), { reason: "UI panic" }).then(function (r) { V.toast(r && r.ok ? "Panic initiated — the console is stopping." : (r && r.error) || "failed", !(r && r.ok)); }).catch(function () { V.toast("Panic initiated — the console is stopping (connection dropped).", false); });
        } }, [V.icon("bolt"), "Emergency hard-stop (panic)"]),
        h("button.btn.sm", { onClick: function () {
          if (!confirm("Contain the running console (vigil down)?\n\nStops + disables the systemd unit (so it won't restore) and kills the backends + proxy. THIS CONSOLE WILL STOP.\n\nProceed?")) return;
          V.postJSON(OFF("/api/down"), {}).then(function (r) { V.toast(r && r.ok ? "Containment initiated — the console is stopping." : (r && r.error) || "failed", !(r && r.ok)); }).catch(function () { V.toast("Containment initiated — the console is stopping (connection dropped).", false); });
        } }, [V.icon("x"), "Contain the console (down)"]),
      ]),
    ]);
  }

  // Wave 2b (parity) — run the `vigil doctor` / `sigil doctor` install-health verbs from the browser.
  // The board above already reflects the offense readiness read (`/api/services`); this card runs the
  // actual doctor CLI verbs on demand: the offense plane shells `vigil doctor --json`, the sovereign plane
  // returns the same report `sigil doctor --json` emits, in-process. Read-only — a preflight, no mutation.
  function doctorCard() {
    var out = h("div", null, "");
    function showDoctor(title, promise) {
      V.mount(out, h("div.hint", { style: { marginTop: "8px" } }, title + ": running…"));
      promise.then(function (r) {
        var okv = !!(r && r.ok);
        var lines = [];
        if (r && r.error) { lines.push(r.error); }
        if (r && r.checks && r.checks.length) {          // sovereign report: {checks:[{id,ok,required,detail}], ...}
          lines = lines.concat(r.checks.map(function (c) {
            return (c.ok ? "OK   " : (c.required ? "FAIL " : "warn ")) + c.id + (c.detail ? " — " + c.detail : ""); }));
          (r.posture || []).forEach(function (p) {        // posture: [{control,state,detail}] — security controls
            lines.push("posture " + (p.control || "?") + ": " + (p.state || "?") + (p.detail ? " — " + p.detail : "")); });
          if (r.production_gate) {                        // {armed, ok, controls} — the prod bring-up gate
            lines.push("production gate: " + (r.production_gate.armed ? "ARMED" : "not armed") + (r.production_gate.ok ? " (ok)" : " (blocking)")); }
        } else {                                          // offense report: {ok, binaries, venvs, issues, notes, ...}
          (r && r.issues || []).forEach(function (m) { lines.push("issue: " + m); });
          var bins = (r && r.binaries) || {}, venvs = (r && r.venvs) || {};
          Object.keys(bins).forEach(function (b) { lines.push((bins[b] ? "OK   " : "FAIL ") + b); });
          Object.keys(venvs).forEach(function (v) { lines.push((venvs[v] ? "OK   " : "FAIL ") + v + " venv"); });
          (r && r.notes || []).forEach(function (m) { lines.push("note: " + m); });
        }
        V.mount(out, h("div.set-status" + (okv ? ".ok" : ".danger"), { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
          h("div", null, [V.icon(okv ? "check" : "x"), h("span", null, " " + title + ": " + (okv ? "HEALTHY" : "ACTION NEEDED"))]),
          lines.length ? h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px", maxHeight: "280px", overflow: "auto" } }, lines.join("\n")) : null,
        ]));
      }).catch(function (e) {
        V.mount(out, h("div.set-status.danger", { style: { marginTop: "8px" } }, title + ": " + ((e && e.message) || e)));
      });
    }
    return h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Run doctor")]),
      h("div.hint", null, "Run the install/health self-check from the browser — read-only, no traffic. "
        + "The offense plane shells `vigil doctor`; the sovereign plane returns the `sigil doctor` report in-process. "
        + "(`doctor --install`, which mutates the host, stays a deliberate CLI act.)"),
      h("div.acts", { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "10px" } }, [
        h("button.btn.sm", { onClick: function () { showDoctor("Offense doctor", V.postJSON(OFF("/api/doctor"), {})); } }, [V.icon("shield"), "Run offense doctor"]),
        h("button.btn.sm", { onClick: function () { showDoctor("Sovereign doctor", V.getJSON(SOV("/api/doctor"))); } }, [V.icon("shield"), "Run sovereign doctor"]),
      ]),
      out,
    ]);
  }

  // Wave 3 (durability) — OWNER-ONLY encrypted off-box backup of the trust root + spine, and a verify-first
  // restore into a FRESH staging home. The operator supplies the passphrase (used once, never stored); the
  // server signs/encrypts in-process (the owner key never leaves the host). Download is a token-header blob.
  function renderDurability(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Durability"),
        h("span.sub", null, "Owner-only encrypted off-box backup of the trust root + spine, and a verify-first "
          + "restore into a fresh staging home. Your passphrase encrypts the backup, is used once, and is never "
          + "stored — keep it safe: lose it and the backup is unrecoverable.")]),
      h("div#durability-body", { style: { marginTop: "16px" } }, h("div.empty", null, "Loading backups…")),
    ]);
    drawDurability();
  }

  function drawDurability() {
    var body = V.$("#durability-body"); if (!body) return;

    function fmtSize(n) { n = n || 0; return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

    function download(id) {
      // fetch WITH the token header (keeps the secrets-tier token out of the URL), then save the blob.
      var hh = { "X-SIGIL-Token": V.token() };
      fetch(SOV("/api/backup/download/" + encodeURIComponent(id)), { headers: hh, credentials: "same-origin" })
        .then(function (r) { if (!r.ok) throw new Error("download failed (" + r.status + ")"); return r.blob(); })
        .then(function (b) {
          var u = URL.createObjectURL(b);
          var a = document.createElement("a"); a.href = u; a.download = id; document.body.appendChild(a);
          a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(u); }, 4000);
        })
        .catch(function (e) { V.toast((e && e.message) || "download failed", true); });
    }

    var listWrap = h("div", null, "");
    function refreshList() {
      V.getJSON(SOV("/api/backup/list")).then(function (d) {
        var rows = (d.backups || []).map(function (b) {
          return h("div.kv", null, [
            h("div.k", null, [V.icon("shield"), " " + b.id]),
            h("div.v", { style: { display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" } }, [
              h("span.mono", { style: { fontSize: "12px", color: "var(--text-2)" } }, fmtSize(b.size)),
              h("button.btn.sm", { onClick: function () { download(b.id); } }, [V.icon("book"), "Download"]),
              h("button.btn.sm", { onClick: function () { restorePick.value = b.id; V.toast("Selected " + b.id + " for restore"); } }, [V.icon("check"), "Use for restore"]),
            ]),
          ]);
        });
        V.mount(listWrap, rows.length ? h("div", null, rows) : h("div.empty", null, "No backups yet."));
      }).catch(function (e) { V.mount(listWrap, offlineEmpty(e, "Could not list backups (owner token required).")); });
    }

    // --- backup card ---
    var bpw = h("input.inp", { type: "password", placeholder: "backup passphrase (min 8 chars)", autocomplete: "new-password" });
    var bpw2 = h("input.inp", { type: "password", placeholder: "confirm passphrase", autocomplete: "new-password" });
    var bStatus = h("div", null, "");
    var mkBtn = h("button.btn.owner", { onClick: function () {
      var p = bpw.value || "", p2 = bpw2.value || "";
      if (p.length < 8) { V.toast("passphrase must be at least 8 characters", true); return; }
      if (p !== p2) { V.toast("passphrases do not match", true); return; }
      mkBtn.disabled = true; V.mount(bStatus, h("div.hint", { style: { marginTop: "8px" } }, "Encrypting backup…"));
      V.postJSON(SOV("/api/backup"), { passphrase: p }).then(function (r) {
        if (r && r.error) { V.mount(bStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, r.error)); return; }
        bpw.value = ""; bpw2.value = "";      // clear the secret from the DOM
        V.mount(bStatus, h("div.set-status.ok", { style: { marginTop: "8px" } }, [V.icon("check"),
          h("span", null, " Backup written: " + r.id + " (" + fmtSize(r.size) + ", " + r.files + " files). Download it and store it off-box.")]));
        refreshList();
      }).catch(function (e) { V.mount(bStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "backup failed")); })
        .then(function () { mkBtn.disabled = false; });
    } }, [V.icon("shield"), "Create backup"]);
    var backupCard = h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Create backup")]),
      h("div.hint", null, "Encrypts the trust root + spine to a server-side archive with your passphrase (used once, never stored). "
        + "The owner key signs it in-process and never leaves the host."),
      h("div", { style: { display: "flex", flexDirection: "column", gap: "8px", marginTop: "10px", maxWidth: "420px" } }, [bpw, bpw2, mkBtn]),
      bStatus,
    ]);

    // --- restore card ---
    var restorePick = h("input.inp", { type: "text", placeholder: "backup id (or click 'Use for restore')" });
    var rpw = h("input.inp", { type: "password", placeholder: "backup passphrase", autocomplete: "off" });
    var rStatus = h("div", null, "");
    var rsBtn = h("button.btn.owner", { onClick: function () {
      var id = (restorePick.value || "").trim(), p = rpw.value || "";
      if (!id) { V.toast("pick a backup to restore", true); return; }
      if (!p) { V.toast("enter the backup passphrase", true); return; }
      rsBtn.disabled = true; V.mount(rStatus, h("div.hint", { style: { marginTop: "8px" } }, "Verifying + staging restore…"));
      V.postJSON(SOV("/api/restore"), { passphrase: p, backup_id: id }).then(function (r) {
        if (r && r.error) { V.mount(rStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, r.error)); return; }
        rpw.value = "";
        V.mount(rStatus, h("div.set-status" + (r.verified ? ".ok" : ".danger"), { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
          h("div", null, [V.icon(r.verified ? "check" : "x"), h("span", null, " Restore " + (r.verified ? "VERIFIED" : "NOT verified") + " (" + (r.files || 0) + " files), staged — NOT applied to the live home.")]),
          h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px" } }, "staged at: " + (r.home || "") + "\npromote it deliberately (out of band); the live home was left intact."),
        ]));
      }).catch(function (e) { V.mount(rStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "restore failed")); })
        .then(function () { rsBtn.disabled = false; });
    } }, [V.icon("bolt"), "Restore to staging"]);
    var restoreCard = h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Restore (to a fresh staging home)")]),
      h("div.hint", null, "Decrypts + verifies a backup, then stages it into a fresh home — it NEVER overwrites the live "
        + "trust root. Fail-closed on a wrong passphrase or any tamper. Promote the verified staging tree yourself."),
      h("div", { style: { display: "flex", flexDirection: "column", gap: "8px", marginTop: "10px", maxWidth: "420px" } }, [restorePick, rpw, rsBtn]),
      rStatus,
    ]);

    // --- escrow card (Wave 9, SENSITIVE, owner-only, offense plane) ---
    // Split-knowledge recovery of the backup passphrase (Shamir m-of-n). The passphrase is typed here,
    // sent once over the authenticated channel, handed to the child via env (never argv/logged), and the
    // SECRET shares are written 0600 ON THE HOST — the browser only ever sees their file names + the public
    // metadata path. Opting in trades sole-owner custody for survivability of passphrase loss.
    var epw = h("input.inp", { type: "password", placeholder: "backup passphrase to escrow (min 8 chars)", autocomplete: "off" });
    var eThr = h("input.inp", { type: "number", value: "2", min: "2", max: "20", style: { maxWidth: "120px" } });
    var eShr = h("input.inp", { type: "number", value: "3", min: "2", max: "20", style: { maxWidth: "120px" } });
    var eHold = h("input.inp", { type: "text", placeholder: "holder names, comma-separated (optional; else auto-named)", autocomplete: "off" });
    var eStatus = h("div", null, "");
    var esBtn = h("button.btn.owner", { onClick: function () {
      var p = epw.value || "";
      var m = parseInt(eThr.value, 10), n = parseInt(eShr.value, 10);
      if (p.length < 8) { V.toast("passphrase must be at least 8 characters", true); return; }
      if (!(m >= 2 && n >= m && n <= 20)) { V.toast("need 2 ≤ threshold ≤ shares ≤ 20", true); return; }
      var holders = (eHold.value || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
      if (holders.length && holders.length !== n) { V.toast("give exactly " + n + " holder names, or none to auto-name", true); return; }
      esBtn.disabled = true; V.mount(eStatus, h("div.hint", { style: { marginTop: "8px" } }, "Splitting the passphrase m-of-n on the host…"));
      V.postJSON(OFF("/api/escrow"), { passphrase: p, threshold: m, shares: n, holders: holders }).then(function (r) {
        if (r && (r.error || r.ok === false)) { V.mount(eStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, (r && (r.error || r.stderr)) || "escrow failed")); return; }
        epw.value = "";      // clear the secret from the DOM
        V.mount(eStatus, h("div.set-status.ok", { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
          h("div", null, [V.icon("check"), h("span", null, " Escrowed " + r.threshold + "-of-" + r.shares + ". SECRET shares written 0600 on the host (the browser never sees them):")]),
          h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px" } },
            "out dir: " + (r.out_dir || "") + "\nfiles:   " + ((r.files || []).join("\n         ") || "(none)")
            + "\n\nSOVEREIGNTY TRADE-OFF: any " + r.threshold + " of these " + r.shares + " holders can COLLECTIVELY\nrecover the passphrase. Distribute each share to a DIFFERENT holder, off any central box."),
        ]));
      }).catch(function (e) { V.mount(eStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "escrow failed")); })
        .then(function () { esBtn.disabled = false; });
    } }, [V.icon("key"), "Escrow passphrase (m-of-n)"]);
    var escrowCard = h("div.card", { style: { marginTop: "16px" } }, [
      h("div.card-h", null, [h("h3", null, "Escrow the backup passphrase (opt-in, m-of-n)")]),
      h("div.hint", null, "OPT-IN split-knowledge recovery: Shamir-splits the passphrase into "
        + "shares recoverable at a threshold, so a quorum of holders can recover a lost passphrase. The SECRET "
        + "shares are written 0600 on THIS host and never cross the browser; the passphrase is used once and never "
        + "stored. Declining (not running this) keeps the sole-owner lose-it-and-it-is-gone guarantee."),
      h("div", { style: { display: "flex", flexDirection: "column", gap: "8px", marginTop: "10px", maxWidth: "520px" } }, [
        epw,
        h("div", { style: { display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" } }, [
          h("span.dim", { style: { fontSize: "12px" } }, "threshold"), eThr,
          h("span.dim", { style: { fontSize: "12px" } }, "of shares"), eShr,
        ]),
        eHold, esBtn,
      ]),
      eStatus,
    ]);

    V.mount(body, [
      h("div.grid.cols-2", { style: { alignItems: "start" } }, [backupCard, restoreCard]),
      escrowCard,
      h("div.card", { style: { marginTop: "16px" } }, [h("div.card-h", null, [h("h3", null, "Backups on this host")]), listWrap]),
    ]);
    refreshList();
  }

  // Wave 10 (ceremonies) — read-only KEY-MATERIAL CEREMONY status: the owner PUBLIC key + its signed
  // succession chain, the at-rest vault seal, and the WARDEN kernel integrity pin. Every panel shows public
  // keys + sealing metadata only — no secret ever crosses, and none of these reads unseal the private key.
  // The owner-key MUTATIONS (provision/pin/rotate/authorize/reset) are wired owner-only in a later slice.
  // Sovereign plane (SOV), viewer+.
  function renderCeremonies(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Ceremonies"),
        h("span.sub", null, "The sovereign trust-root key material at a glance — the owner public key and its "
          + "signed succession chain, the at-rest vault seal, and the WARDEN kernel integrity pin. Read-only: "
          + "these panels show public keys + sealing metadata only, and the owner private key never leaves the "
          + "host. Key-material mutations (rotate, provision, pin, authorize, reset) land here next, owner-only.")]),
      h("div#ceremonies-body", { style: { marginTop: "16px" } }, h("div.empty", null, "Loading…")),
    ]);
    drawCeremonies();
  }

  function drawCeremonies() {
    var body = V.$("#ceremonies-body"); if (!body) return;
    // one read card: title + hint, an optional danger note, and a <pre> filled from a GET. Two distinct
    // problem states are surfaced, never hidden behind a false green: (1) the status command itself FAILED
    // (non-zero exit — e.g. a forked/tampered succession chain sys.exit(2), or a spawn error) → ok:false;
    // (2) the command RAN but its output carries the CLI's `!!` problem marker (a tampered kernel pin or an
    // incomplete KEK rotation exit 0 yet print `!!`) — that would otherwise look green, so we flag it too.
    function readCard(title, hint, url, icon) {
      var note = h("div", null, "");
      var pre = h("pre.mono", { style: { whiteSpace: "pre-wrap", fontSize: "12px", margin: "10px 0 0", maxHeight: "280px", overflow: "auto" } }, "Loading…");
      V.getJSON(SOV(url)).then(function (r) {
        r = r || {};
        var txt = (r.text || "").trim();
        if (r.ok === false) V.mount(note, h("div.set-status.danger", { style: { marginTop: "10px" } }, (r.error || r.stderr || "the status command failed (non-zero exit)")));
        else if (txt.indexOf("!!") >= 0) V.mount(note, h("div.set-status.danger", { style: { marginTop: "10px" } }, "This status flags a problem (see the “!!” line below) — the command ran, but it is NOT clean."));
        V.mount(pre, h("span", null, txt || "(nothing reported)"));
      }).catch(function (e) { V.mount(pre, ""); V.mount(note, offlineEmpty(e, "Could not read this status (sovereign plane).")); });
      return h("div.card", null, [h("div.card-h", null, [h("h3", null, [V.icon(icon), " " + title])]), h("div.hint", null, hint), note, pre]);
    }
    var grid = h("div.grid.cols-2", { style: { alignItems: "start" } }, [
      readCard("Owner public key", "The base64 owner PUBLIC signing key. The private half is sealed at rest and never leaves the host.", "/api/ceremonies/owner-pubkey", "key"),
      readCard("Owner-key succession", "The signed key history: pinned genesis root → each epoch → the validated current tip. Fail-closed if the chain is forked or tampered.", "/api/ceremonies/key", "shield"),
      readCard("Vault (at-rest seal)", "Whether the trust root + secrets are sealed at rest under a TPM-sealed KEK.", "/api/ceremonies/vault", "shield"),
      readCard("Kernel integrity pin", "The owner-signed WARDEN kernel content pin + any config drift from the signed manifest.", "/api/ceremonies/kernel", "gear"),
    ]);
    var parts = [grid];

    // OWNER-only (secrets) mutations — run the real `sigil` verb ON THE HOST; the owner key stays sealed on
    // the host and never crosses the browser. Only rendered for an owner; the SERVER re-enforces `secrets`.
    if (V.can("secrets")) {
      function cerBtn(label, url, confirmMsg, icon) {
        var st = h("div", null, "");
        var btn = h("button.btn.owner", { onClick: function () {
          if (!window.confirm(confirmMsg)) return;
          btn.disabled = true; V.mount(st, h("div.hint", { style: { marginTop: "8px" } }, "Running the ceremony on the host…"));
          V.postJSON(SOV(url), {}).then(function (r) {
            r = r || {};
            var failed = (r.ok === false);
            V.mount(st, h("div.set-status" + (failed ? ".danger" : ".ok"), { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
              h("div", null, [V.icon(failed ? "x" : "check"), h("span", null, " " + (failed ? "Ceremony did not complete" : "Ceremony complete"))]),
              h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px" } }, ((r.text || "") + (r.stderr ? "\n" + r.stderr : "")).trim() || (r.error || "(no output)")),
            ]));
            drawCeremonies();   // refresh the read panels so the new sealed/pinned state shows
          }).catch(function (e) { V.mount(st, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "ceremony failed")); })
            .then(function () { btn.disabled = false; });
        } }, [V.icon(icon), label]);
        return h("div", null, [btn, st]);
      }
      parts.push(h("div.card", { style: { marginTop: "16px" } }, [
        h("div.card-h", null, [h("h3", null, "Seal & pin (owner)")]),
        h("div.hint", null, "Owner ceremonies that run the real `sigil` verb ON THE HOST — the owner key is "
          + "sealed on the host and never crosses the browser. Provisioning the vault TPM-seals a fresh KEK so "
          + "the trust root seals at rest (idempotent); pinning the kernel owner-signs the WARDEN kernel binary "
          + "hash so it fails closed on tamper."),
        h("div", { style: { display: "flex", gap: "10px", marginTop: "10px", flexWrap: "wrap" } }, [
          cerBtn("Provision vault (TPM-seal a KEK)", "/api/ceremonies/vault-provision",
            "Provision the vault? This TPM-seals a fresh KEK to THIS machine so the trust root seals at rest. Idempotent — a no-op if already provisioned.", "shield"),
          cerBtn("Pin kernel binary", "/api/ceremonies/kernel-pin",
            "Pin the WARDEN kernel binary? This owner-signs its content hash into the security manifest; the kernel then fails CLOSED on tamper.", "gear"),
        ]),
      ]));

      // --- Device mesh (phone pairing) — enroll/revoke a phone DEVICE key, owner-signed on the host. The
      //     ENROLL flow preserves the CLI's anti-key-swap guard: preview the fingerprint the SERVER computes,
      //     eyeball-match it against what the phone shows, THEN authorize.
      var did = h("input.inp", { type: "text", placeholder: "device id (e.g. junior-pixel)", autocomplete: "off" });
      var dpub = h("input.inp", { type: "text", placeholder: "device pubkey (base64, 32-byte Ed25519)", autocomplete: "off", style: { fontFamily: "var(--mono, monospace)" } });
      var mStatus = h("div", null, "");
      var roster = h("pre.mono", { style: { whiteSpace: "pre-wrap", fontSize: "12px", margin: "0" } }, "Loading…");
      function refreshRoster() {
        V.getJSON(SOV("/api/ceremonies/mesh/devices")).then(function (r) {
          r = r || {}; V.mount(roster, h("span", null, ((r.text || "") + (r.ok === false && r.stderr ? "\n" + r.stderr : "")).trim() || "(no authorized devices)"));
        }).catch(function (e) { V.mount(roster, ""); V.mount(mStatus, offlineEmpty(e, "Could not read the device roster (owner only).")); });
      }
      function meshAct(url, confirmMsg) {
        if (confirmMsg && !window.confirm(confirmMsg)) return;
        V.mount(mStatus, h("div.hint", { style: { marginTop: "8px" } }, "Running on the host…"));
        V.postJSON(SOV(url), { device_id: did.value || "", pubkey: dpub.value || "" }).then(function (r) {
          r = r || {}; var failed = (r.ok === false);
          V.mount(mStatus, h("div.set-status" + (failed ? ".danger" : ".ok"), { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
            h("div", null, [V.icon(failed ? "x" : "check"), h("span", null, " " + (failed ? "Failed" : "Done"))]),
            h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px" } }, ((r.text || "") + (r.stderr ? "\n" + r.stderr : "")).trim() || (r.error || "(no output)")),
          ]));
          refreshRoster();
        }).catch(function (e) { V.mount(mStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "failed")); });
      }
      var previewBtn = h("button.btn", { onClick: function () {
        V.mount(mStatus, h("div.hint", { style: { marginTop: "8px" } }, "Computing fingerprint…"));
        V.postJSON(SOV("/api/ceremonies/mesh/fingerprint"), { pubkey: dpub.value || "" }).then(function (r) {
          r = r || {};
          if (r.ok === false) { V.mount(mStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, r.error || "invalid pubkey")); return; }
          V.mount(mStatus, h("div.set-status.ok", { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
            h("div", null, [V.icon("key"), h("span", null, " Fingerprint: "), h("strong.mono", null, r.fingerprint)]),
            h("div.hint", { style: { marginTop: "4px" } }, "Confirm this EXACTLY matches the code the phone shows, THEN Authorize. A mismatch means a key swap — do not authorize."),
          ]));
        }).catch(function (e) { V.mount(mStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "failed")); });
      } }, [V.icon("find"), "Preview fingerprint"]);
      var authBtn = h("button.btn.owner", { onClick: function () {
        meshAct("/api/ceremonies/mesh/authorize", "Authorize this device? Only proceed if the fingerprint you previewed matches what the phone shows.");
      } }, [V.icon("check"), "Authorize device"]);
      var revBtn = h("button.btn.owner", { onClick: function () {
        meshAct("/api/ceremonies/mesh/revoke", "Revoke this device key? It will no longer be trusted by the mesh.");
      } }, [V.icon("x"), "Revoke device"]);
      parts.push(h("div.card", { style: { marginTop: "16px" } }, [
        h("div.card-h", null, [h("h3", null, "Device mesh (phone pairing)")]),
        h("div.hint", null, "Owner-sign a phone DEVICE key into the mesh, on the host. Enter the device id + its "
          + "base64 public key, PREVIEW the fingerprint and eyeball-match it against what the phone shows (this "
          + "defeats a key swap), then Authorize. The phone's private key never leaves the phone; the owner key "
          + "signs on the host."),
        h("div", { style: { display: "flex", flexDirection: "column", gap: "8px", marginTop: "10px", maxWidth: "560px" } }, [
          did, dpub,
          h("div", { style: { display: "flex", gap: "10px", flexWrap: "wrap" } }, [previewBtn, authBtn, revBtn]),
        ]),
        mStatus,
        h("div", { style: { marginTop: "12px" } }, [h("div.hint", { style: { marginBottom: "6px" } }, "Authorized devices (pubkey [fingerprint]):"), roster]),
      ]));
      refreshRoster();

      // --- Delegate offense authority — the owner blesses the OFFENSE plane's PUBLIC identity. Preview the
      //     two keys and confirm them out-of-band against the offense host BEFORE signing (a swapped identity
      //     file would get an attacker key owner-blessed). The owner key signs on the host; the certs are PUBLIC.
      var idJson = h("textarea.inp", { rows: "6", placeholder: "paste the offense-identity.json exported by `vigil identity` (schema 1)", style: { fontFamily: "var(--mono, monospace)", fontSize: "12px", resize: "vertical" } });
      var dScope = h("input.inp", { type: "text", placeholder: "engagement scope/slug the delegation is valid for" });
      var dHours = h("input.inp", { type: "number", value: "24", min: "1", style: { maxWidth: "140px" } });
      var dStatus = h("div", null, "");
      function parseIdentity() {
        try { return JSON.parse(idJson.value || "null"); }
        catch (e) { V.mount(dStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, "the offense identity is not valid JSON")); return undefined; }
      }
      var dPrevBtn = h("button.btn", { onClick: function () {
        var id = parseIdentity(); if (id === undefined) return;
        V.mount(dStatus, h("div.hint", { style: { marginTop: "8px" } }, "Validating identity…"));
        V.postJSON(SOV("/api/ceremonies/delegate/preview"), { identity: id }).then(function (r) {
          r = r || {};
          if (r.ok === false) { V.mount(dStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, r.error || "invalid offense identity")); return; }
          V.mount(dStatus, h("div.set-status.ok", { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
            h("div", null, [V.icon("key"), h("span", null, " Keys to be owner-blessed — confirm these EXACTLY match the offense host before signing:")]),
            h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px" } },
              "spine      " + r.spine.key_id + "  " + r.spine.pubkey + "\ngovernance " + r.governance.key_id + "  " + r.governance.pubkey),
          ]));
        }).catch(function (e) { V.mount(dStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "failed")); });
      } }, [V.icon("find"), "Preview keys"]);
      var dSignBtn = h("button.btn.owner", { onClick: function () {
        var id = parseIdentity(); if (id === undefined) return;
        if (!window.confirm("Owner-sign the offense delegation? Only proceed if the previewed keys match the offense host — a swapped identity would bless an attacker's key.")) return;
        dSignBtn.disabled = true; V.mount(dStatus, h("div.hint", { style: { marginTop: "8px" } }, "Signing on the host…"));
        V.postJSON(SOV("/api/ceremonies/delegate"), { identity: id, scope: dScope.value || "", hours: dHours.value || "24" }).then(function (r) {
          r = r || {}; var failed = (r.ok === false);
          var kids = Object.keys(r.certs || {});
          V.mount(dStatus, h("div.set-status" + (failed ? ".danger" : ".ok"), { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
            h("div", null, [V.icon(failed ? "x" : "check"), h("span", null, " " + (failed ? "Delegation failed" : "Delegation signed"))]),
            h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px" } },
              ((r.text || "") + (r.stderr ? "\n" + r.stderr : "")).trim() || (r.error || "(no output)")
              + (kids.length ? "\n\nwritten (PUBLIC certs): " + kids.join(", ") + " → " + (r.out_dir || "") : "")),
          ]));
        }).catch(function (e) { V.mount(dStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "failed")); })
          .then(function () { dSignBtn.disabled = false; });
      } }, [V.icon("shield"), "Sign delegation"]);
      parts.push(h("div.card", { style: { marginTop: "16px" } }, [
        h("div.card-h", null, [h("h3", null, "Delegate offense authority (owner)")]),
        h("div.hint", null, "Owner-sign a time-boxed delegation over the OFFENSE plane's PUBLIC identity "
          + "(exported by `vigil identity`). Paste the identity, PREVIEW the two keys and confirm they match "
          + "the offense host out-of-band, then Sign. The owner key signs on the host; the delegation certs are "
          + "public (no private key)."),
        h("div", { style: { display: "flex", flexDirection: "column", gap: "8px", marginTop: "10px", maxWidth: "620px" } }, [
          idJson,
          h("div", { style: { display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" } }, [
            dScope, h("span.dim", { style: { fontSize: "12px" } }, "hours"), dHours,
          ]),
          h("div", { style: { display: "flex", gap: "10px", flexWrap: "wrap" } }, [dPrevBtn, dSignBtn]),
        ]),
        dStatus,
      ]));

      // --- DANGER ZONE — destructive owner ceremonies. Each requires TYPING an exact phrase (a window.prompt
      //     match) before the POST fires, and the SERVER re-checks the same phrase — an irreversible op must
      //     not go off on a fat-fingered click. The `sigil` verb's own danger flags are hardcoded server-side.
      var dzStatus = h("div", null, "");
      function dangerBtn(label, url, phrase, warn, icon) {
        return h("button.btn.danger", { onClick: function () {
          var typed = window.prompt(warn + "\n\nType exactly \"" + phrase + "\" to proceed (or Cancel):", "");
          if (typed !== phrase) { if (typed !== null) V.mount(dzStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, "phrase did not match — nothing was done")); return; }
          V.mount(dzStatus, h("div.hint", { style: { marginTop: "8px" } }, "Running the ceremony on the host…"));
          V.postJSON(SOV(url), { confirm: typed }).then(function (r) {
            r = r || {}; var failed = (r.ok === false);
            V.mount(dzStatus, h("div.set-status" + (failed ? ".danger" : ".ok"), { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
              h("div", null, [V.icon(failed ? "x" : "check"), h("span", null, " " + (failed ? "Did not complete" : "Ceremony complete"))]),
              h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px" } }, ((r.text || "") + (r.stderr ? "\n" + r.stderr : "")).trim() || (r.error || "(no output)")),
            ]));
            drawCeremonies();   // refresh the read panels (succession/floor state changed)
          }).catch(function (e) { V.mount(dzStatus, h("div.set-status.danger", { style: { marginTop: "8px" } }, (e && e.message) || "failed")); });
        } }, [V.icon(icon), label]);
      }
      parts.push(h("div.card", { style: { marginTop: "16px", borderColor: "var(--danger, #b00)" } }, [
        h("div.card-h", null, [h("h3", null, "Danger zone (owner) — destructive")]),
        h("div.hint", null, "Irreversible or trust-weakening owner ceremonies. Each runs the real `sigil` verb "
          + "ON THE HOST and requires you to TYPE an exact phrase; the server re-checks it. Rotating mints a "
          + "successor key (old heads still verify); re-genesis ABANDONS continuity (out-of-band verifiers must "
          + "re-pin); resetting the floor LOWERS the anti-rollback guarantee."),
        h("div", { style: { display: "flex", flexDirection: "column", gap: "8px", marginTop: "10px" } }, [
          dangerBtn("Rotate owner key", "/api/ceremonies/key/rotate", "ROTATE OWNER KEY",
            "Rotate the owner key? A successor is cross-signed into the key history; every pre-rotation head/grant still verifies. Re-pin any out-of-band verifier that pins the CURRENT key.", "key"),
          dangerBtn("Re-genesis (abandon continuity)", "/api/ceremonies/key/re-genesis", "ABANDON CONTINUITY",
            "RE-GENESIS is the COMPROMISE fallback. It mints a fresh genesis and DELIBERATELY ABANDONS verifiable continuity of ALL prior history. Use ONLY for an actual key compromise. Out-of-band verifiers MUST re-pin to the new key.", "shield"),
          dangerBtn("Reset anti-rollback floor", "/api/ceremonies/floor/reset", "LOWER THE FLOOR",
            "Reset (LOWER) the durable anti-rollback floor to the current spine? Only after a legitimate reset/restore — never routinely. This weakens the anti-rollback guarantee.", "bolt"),
        ]),
        dzStatus,
      ]));
    }
    V.mount(body, parts);
  }

  function renderBrain(screen) {
    var B = { tab: (hashQuery().tab) || "decide", runs: [], run: null, catalogQ: "" };
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Brain"),
        h("span.sub", null, "The propose-only decision engine, plus what the system has learned, how well it scores, and the capabilities it can bring to bear.")]),
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
      if (B.tab === "decide") brainDecision(v);
      else if (B.tab === "memory") brainMemory(v);
      else if (B.tab === "benchmark") brainBenchmark(v);
      else if (B.tab === "catalog") brainCatalog(v, B);
      else brainRunScoped(v, B, B.tab);   // intel / planner (per-engagement)
    }
    drawTabs(); drawView();
  }

  // ---- Brain > Decision engine (the pluggable, PROPOSE-ONLY agent-body brain) -----------------
  // Shows the ACTIVE brain + the propose-only banner + the gate posture (queue vs auto), and the proposed
  // attack chain of LEADs IF a real proposal is persisted. It NEVER invents a chain: no live proposal
  // source → honest empty state. Danger chip (recon/active) + effectiveness bar + a per-step QUEUE-vs-
  // auto verdict mirror the WARDEN gate (A2 floor on a live target; recon auto-eligible only in staging/twin).
  function brainStepGate(danger, posture) {
    var p = String(posture || "live");
    if ((p === "staging" || p === "twin") && danger === "recon")
      return { auto: true, label: "auto-eligible", detail: "recon in " + p + " posture" };
    return { auto: false, label: "queues for owner approval",
             detail: (danger === "recon" ? "recon" : "active") + " on a " + p + " target (A2 floor)" };
  }
  function brainDangerChip(danger) {
    return danger === "recon" ? V.pill("recon", "sm", null) : V.pill("active", "sm warn", null);
  }
  function brainEffBar(eff) {
    var pct = Math.max(0, Math.min(100, Math.round((Number(eff) || 0) * 100)));
    var cls = pct >= 80 ? "" : (pct >= 50 ? ".mid" : ".hi");
    return h("div", { style: { minWidth: "128px" } }, [
      h("div.dim", { style: { fontSize: "var(--fs-micro)" } }, "effectiveness (prior) " + pct + "%"),
      h("div.bar", { style: { margin: "4px 0 0" } }, h("div.bar-fill" + cls, { style: { width: pct + "%" } })),
    ]);
  }
  function brainProfile(profile) {
    var p = profile || {};
    function row(k, v) {
      if (v == null || v === "" || (Array.isArray(v) && !v.length)) return null;
      return trustKv(k, Array.isArray(v) ? v.join(", ") : String(v));
    }
    var svc = p.services && Object.keys(p.services).length
      ? Object.keys(p.services).map(function (k) { return k + "/" + p.services[k]; }).join(", ") : null;
    var kvs = [
      row("Target", p.target),
      row("Type", p.target_type),
      row("IP addresses", p.ip_addresses),
      row("Open ports", (p.open_ports || []).map(String)),
      row("Services", svc),
      row("Technologies", p.technologies),
      row("CMS", p.cms_type),
      row("Cloud", p.cloud_provider),
      row("Attack surface", p.attack_surface_score),
      row("Risk", p.risk_level),
      row("Confidence", p.confidence_score),
    ].filter(Boolean);
    if (!kvs.length) return h("div.hint", null, "no profile fields recorded for this proposal.");
    return h("div.kv", { style: { marginTop: "8px" } }, kvs);
  }
  // Join a proposed step's tool against THIS host's real tool roster (/api/toolprofiles) to say, with the
  // engine's own reason, whether it could run here. Never fabricates: an unknown tool (or no roster) is
  // "unknown — resolved at run time", not a green light. `SURFACE_LABEL` is the shared roster vocabulary.
  function brainAvail(toolName, roster) {
    var name = String(toolName || "").toLowerCase();
    var prof = null;
    for (var i = 0; i < (roster || []).length; i++) {
      if (String(roster[i].name || "").toLowerCase() === name) { prof = roster[i]; break; }
    }
    if (!prof) return { state: "unknown",
      why: "not in this host's tool roster — availability is resolved at run time (checkpoint-gated)" };
    if (!prof.admitted) return { state: "unavailable", why: prof.admit_reason || "not admitted to the arsenal" };
    if (!prof.installed) return { state: "unavailable",
      why: (prof.status === "unsupported" ? "not supported on this platform" : "not installed on this host")
        + " — install it from the Tools screen" };
    return { state: "available",
      why: "installed + admitted; driven by " + (SURFACE_LABEL[String(prof.control_surface || "")] || "the engine") };
  }

  // The four verdict classes the render keeps SEPARATE. A brain proposal is entirely LEADs; FACT/CLEAN/
  // INCONCLUSIVE are outcomes a step can only earn after it actually runs (checkpoint-gated), so they read
  // 0 here — the separation is explicit so the panel can never blur a proposed step into a confirmed fact.
  function brainVerdictLegend(steps) {
    var n = (steps || []).length;
    function chip(label, count, cls, desc) {
      return h("div.fix-card", { style: { padding: "8px 10px" } }, [
        h("div.row-flex", { style: { gap: "6px", alignItems: "center" } },
          [V.pill(label, cls, null), h("b", null, String(count))]),
        h("div.dim", { style: { fontSize: "var(--fs-micro)", marginTop: "4px" } }, desc),
      ]);
    }
    return h("div", { style: { marginTop: "12px" } }, [
      h("span.label", null, "verdict classes (render separation)"),
      h("div.grid.cols-4", { style: { marginTop: "8px" } }, [
        chip("FACT", 0, "sm ok", "minted only by a fired VIGIL oracle over real evidence — a proposal never mints one."),
        chip("LEAD", n, "sm warn", "what the brain proposes: an ordered, gated step. Every proposed step is a LEAD."),
        chip("CLEAN", 0, "sm", "a checked surface with a sound negative — recorded only after a step runs."),
        chip("INCONCLUSIVE", 0, "sm", "a missing channel / degraded run — recorded only after a step runs."),
      ]),
    ]);
  }

  // The plan-a-chain control row: a loopback target, a brain selector, the CLOSED objective enum (derived
  // server-side from the brain's own `Objective` enum), and a PROPOSE-ONLY button (B3/H10). Clicking it
  // POSTs /api/brain/propose, which SPAWNS `vigil engage --brain hexstrike --plan-only` — one think() that
  // PERSISTS the proposed chain then STOPS before the gate/scope/traffic — and re-renders the panel over that
  // fresh proposal. It runs NO tools, sends NO traffic, mints NO findings. DRIVING the chain (execution)
  // stays the owner-checkpoint-gated New-Assessment path; this button never executes. `v` is the panel node,
  // so a successful propose can re-render it against the new run's proposal.
  function brainControls(brain, v) {
    var b = brain || {};
    var objs = b.objectives || [];
    // The `--brain` flag distinguishes: the propose-only brain this panel plans with (its name is derived
    // from source), and the default agentic path (Strix, which EXECUTES — not planned here; the propose
    // endpoint refuses it with an honest reason).
    var brainOpts = [
      { id: "hexstrike", label: (b.name || "HexStrike") + " (propose-only)" },
      { id: "strix", label: "Strix (default agentic path)" },
    ];
    var brainSel = h("select", null, brainOpts.map(function (o, i) {
      return h("option", { value: o.id, selected: i === 0 }, o.label);
    }));
    var objSel = objs.length
      ? h("select", null, objs.map(function (o) {
          return h("option", { value: o.id, selected: !!o.default }, o.id + (o.default ? " (default)" : "")); }))
      : h("select", { disabled: true }, [h("option", null, "objective vocabulary unavailable")]);
    var tgtInput = h("input", { type: "text", placeholder: "http://127.0.0.1:PORT/  (loopback only)",
      style: { width: "100%" } });
    var propOut = h("div", { style: { marginTop: "10px" } });
    var canRun = V.can("run_engagement");
    var idle = [V.icon("bolt"), "Propose chain (plan-only)"];
    var runBtn = h("button.btn.owner", {
      disabled: !canRun,
      title: canRun
        ? "Propose-only: persists a proposed chain and shows it below — runs no tools, sends no traffic"
        : "requires the run_engagement permission",
      onClick: function () {
        var tgt = (tgtInput.value || "").trim();
        if (!tgt) { V.mount(propOut, brainActErr("enter a loopback target URL to plan against")); return; }
        if (objs.length === 0) { V.mount(propOut, brainActErr("no objective vocabulary available")); return; }
        runBtn.disabled = true; V.mount(runBtn, [V.icon("bolt"), "Proposing…"]);
        V.mount(propOut, h("div.hint", null, "Planning a propose-only chain (no gate, no traffic, no execution)…"));
        V.postJSON(OFF("/api/brain/propose"), { brain: brainSel.value, target: tgt, objective: objSel.value })
          .then(function (r) {
            if (!r || r.ok !== true) { V.mount(propOut, brainActErr((r && r.error) || "propose failed")); return; }
            brainDecision(v, r.run_id);   // re-render the whole panel over THIS run's persisted proposal
          })
          .catch(function () { V.mount(propOut, brainActErr("could not reach the propose action")); })
          .then(function () { runBtn.disabled = !canRun; V.mount(runBtn, idle); });
      },
    }, idle);
    return V.card("Plan a chain", "PROPOSE-ONLY", h("div", null, [
      h("div.field", { style: { marginBottom: "10px" } }, [h("label", null, "Target (loopback)"), tgtInput]),
      h("div.grid.cols-2", { style: { gap: "12px", alignItems: "end" } }, [
        h("div.field", null, [h("label", null, "Brain"), brainSel]),
        h("div.field", null, [h("label", null, "Objective"), objSel]),
      ]),
      h("div.row-flex", { style: { gap: "10px", alignItems: "center", marginTop: "10px", flexWrap: "wrap" } }, [
        runBtn, V.pill("propose-only", "sm ok", null),
      ]),
      propOut,
      h("div.hint", { style: { marginTop: "8px" } },
        "Plans a chain with the propose-only brain and shows it below. It PERSISTS a proposal and sends NO "
        + "traffic to the target and mints NO findings (it does run a local check of which tools are "
        + "installed, to annotate each step). DRIVING the chain (execution) stays the owner-checkpoint-gated "
        + "New-Assessment path — this button never executes against the target."),
    ]), true);
  }

  function brainChain(prop, roster) {
    var steps = prop.steps || [];
    var posture = prop.posture || "live";
    var head = h("div.row-flex", { style: { flexWrap: "wrap", gap: "8px", alignItems: "center" } }, [
      h("span.label", null, "proposed attack chain"),
      prop.objective ? V.pill("objective " + prop.objective, "sm", null) : null,
      V.pill("posture " + posture, (posture === "live" ? "sm warn" : "sm"), null),
      prop.run_id ? V.pill("run " + prop.run_id, "sm", null) : null,
    ]);
    function resCol(k, val) {
      return h("div", null, [
        h("div.dim", { style: { fontSize: "var(--fs-micro)" } }, k),
        h("div.mono", { style: { fontSize: "var(--fs-xs)", marginTop: "2px" } }, val),
      ]);
    }
    var list = h("div.stack", { style: { marginTop: "10px", gap: "10px" } }, steps.map(function (s, i) {
      var gate = brainStepGate(s.danger, posture);
      var avail = brainAvail(s.tool, roster);
      var availCls = avail.state === "available" ? "sm ok" : (avail.state === "unavailable" ? "sm danger" : "sm");
      var params = s.params ? Object.keys(s.params).filter(function (k) { return k !== "danger"; })
        .map(function (k) { return k + "=" + JSON.stringify(s.params[k]); }).join("  ") : "";
      return h("div.fix-card", null, [
        h("div.fix-h", null, [
          h("span.pill.sm", null, "#" + (s.priority != null ? s.priority : i + 1)),
          h("b.mono", null, s.tool || "?"),
          V.pill("LEAD", "sm warn", null),
          brainDangerChip(s.danger),
          gate.auto ? h("span.st.st-confirmed", null, [h("span.dot"), gate.label])
                    : h("span.st.st-queued", null, [h("span.dot"), gate.label]),
          h("span", { style: { marginLeft: "auto" } }, brainEffBar(s.effectiveness)),
        ]),
        params ? h("div.dim.mono", { style: { marginTop: "8px", fontSize: "var(--fs-xs)", wordBreak: "break-word" } }, params) : null,
        // availability annotation WITH the engine's own reason (joined against this host's tool roster)
        h("div.row-flex", { style: { marginTop: "8px", gap: "6px", alignItems: "center", flexWrap: "wrap" } }, [
          h("span.dim", { style: { fontSize: "var(--fs-micro)" } }, "availability"),
          V.pill(avail.state, availCls, null),
          h("span.dim", { style: { fontSize: "var(--fs-micro)" } }, avail.why),
        ]),
        // per-step result columns — placeholders until the (checkpoint-gated) live run fills them
        h("div.grid.cols-4", { style: { marginTop: "8px" } }, [
          resCol("outcome", "pending — not executed"),
          resCol("verdict", "LEAD"),
          resCol("evidence", "—"),
          resCol("admission", "—"),
        ]),
        h("div.dim", { style: { marginTop: "6px", fontSize: "var(--fs-micro)" } }, "LEAD · " + gate.detail
          + " · outcome/evidence/admission fill only after a gated run (checkpoint-gated)"),
      ]);
    }));
    return h("div", { style: { marginTop: "12px" } }, [head, list]);
  }
  function brainDecision(v, runId) {
    // runId (optional): after a propose, read THAT run's persisted proposal deterministically (no
    // cross-run stale fallback); without it, the reader returns the newest run carrying a valid proposal.
    var url = OFF("/api/brain/decision") + (runId ? "?run=" + encodeURIComponent(runId) : "");
    V.getJSON(url).then(function (d) {
      var brain = (d && d.brain) || {};
      var prop = (d && d.proposal) || { present: false };
      var doctrine = (d && d.doctrine) || "";
      // The host tool roster annotates each proposed step's availability with the engine's own reason.
      // Fail-soft: no roster → steps annotate "unknown — resolved at run time (checkpoint-gated)".
      V.getJSON(OFF("/api/toolprofiles")).then(function (tp) {
        render((tp && tp.profiles) || []);
      }).catch(function () { render([]); });

      function render(roster) {
        var banner = h("div.legend", { style: { alignItems: "flex-start",
          borderColor: "var(--owner-line)", background: "var(--owner-dim)" } },
          [V.icon("info"), h("span", null, [h("b", null, "Proposals only. "),
            "Every step crosses the conjunctive gate + egress gate; a finding is a FACT only when a VIGIL oracle fires."])]);
        var brainCard = V.card("Active brain", "DECISION ENGINE", h("div", null, [
          h("div.row-flex", { style: { flexWrap: "wrap", gap: "8px", alignItems: "center" } }, [
            h("b", null, brain.name || "—"),
            brain.propose_only ? V.pill("propose-only", "sm ok", null) : null,
            brain.derived ? V.pill("derived from source", "sm", null) : null,
            (brain.available === false) ? V.pill("brain source unavailable", "sm danger", null) : null,
          ]),
          brain.design_credit ? h("div.hint", { style: { marginTop: "8px" } },
            [h("b", null, "Design credit: "), brain.design_credit]) : null,
          brain.module ? h("div.dim.mono", { style: { marginTop: "6px", fontSize: "var(--fs-micro)" } }, brain.module) : null,
          brain.note ? h("div.dim", { style: { marginTop: "6px", fontSize: "var(--fs-micro)" } }, brain.note) : null,
        ]), false);
        var gatePosture = doctrine ? h("div.legend", { style: { marginTop: "12px", alignItems: "flex-start" } },
          [V.icon("shield"), h("span", null, doctrine)]) : null;
        var legend = brainVerdictLegend(prop.present ? prop.steps : []);
        var chain;
        if (prop.present) {
          chain = h("div", { style: { marginTop: "12px" } }, [
            V.card("Target profile", "OBSERVED", brainProfile(prop.profile), false),
            brainChain(prop, roster),
          ]);
        } else {
          chain = h("div.empty", { style: { marginTop: "12px" } }, [
            h("div.big", null, "No live proposal wired"),
            h("p", null, prop.note || "No proposal source is wired into this console yet. Plan a chain above "
              + "(checkpoint-gated) or run `vigil engage --brain hexstrike`, which persists the proposal this panel surfaces."),
          ]);
        }
        V.mount(v, [banner, brainControls(brain, v), brainCard, gatePosture, legend, chain]);
      }
    }).catch(function (e) { V.mount(v, offlineEmpty(e)); });
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
    }).catch(function (e) { V.mount(v, offlineEmpty(e)); });
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
      // The LIVE-run panel: an owner-plane action that re-derives this host's score right now against the
      // in-process labelled corpus (the same soundness check the make-gate regression runs). Self-contained —
      // no target, no scope, no egress. Result renders below the button.
      var liveSlot = h("div#bench-live", { style: { marginTop: "10px" } });
      var runBtn = h("button.btn.owner", { onClick: function () { runBenchmark(runBtn, liveSlot); } },
        "Run benchmark now");
      V.mount(v, [
        V.card("Run the soundness benchmark", "LIVE", [
          h("p.dim", { style: { marginBottom: "10px" } },
            "Score CRUCIBLE against the in-process corpus of 11 planted bugs + 5 safe controls, live. It runs " +
            "loopback-only with no incumbents — no external target, no scope, no egress. A precise result is " +
            "every planted bug found (tp) and zero safe controls flagged (fp)."),
          runBtn, liveSlot,
        ], true),
        V.card("Benchmark baseline", "CALIBRATION", [
          h("p.dim", { style: { marginBottom: "10px" } }, base.label || "the in-process benchmark corpus"),
          rows.length ? h("div.stack", null, rows) : h("div.empty", null, "No benchmark scores recorded yet."),
        ], false),
        h("div.legend", null, [V.icon("info"), h("span", null, "tp = planted bugs found · fp = safe controls wrongly flagged · fn = missed bugs. The corpus includes safe controls a precise engine must leave alone.")]),
      ]);
    }).catch(function (e) { V.mount(v, offlineEmpty(e)); });
  }
  function runBenchmark(btn, slot) {
    if (btn) { btn.disabled = true; btn.textContent = "Running… (up to ~5 min)"; }
    V.mount(slot, h("div.hint", { style: { marginTop: "10px" } }, "Standing up the corpus and scoring CRUCIBLE…"));
    V.postJSON(OFF("/api/benchmark/run"), {}).then(function (r) {
      if (!r || r.ok !== true) {
        V.mount(slot, h("div.legend", { style: { marginTop: "10px", borderColor: "var(--bad-line)" } },
          [V.icon("x"), h("span", null, "Benchmark did not complete: " + ((r && r.error) || "unknown error"))]));
        return;
      }
      var s = r.result || {};
      function num(x) { return (x == null) ? "—" : x; }
      function pct(x) { return (typeof x === "number") ? Math.round(x * 100) + "%" : "—"; }
      var clean = (s.fp === 0);
      V.mount(slot, [
        h("div.grid.cols-4", { style: { marginTop: "10px" } }, [
          V.tile("True positives", String(num(s.tp)), "planted bugs found", "ok"),
          V.tile("False positives", String(num(s.fp)), clean ? "safe controls flagged" : "FLAGGED a safe control", clean ? "ok" : "danger"),
          V.tile("False negatives", String(num(s.fn)), "planted bugs missed", null),
          V.tile("F1", pct(s.f1), "precision " + pct(s.precision) + " · recall " + pct(s.recall), null),
        ]),
        h("div.legend", { style: { marginTop: "10px" } }, [V.icon(clean ? "check" : "x"),
          h("span", null, clean
            ? ("Live: CRUCIBLE flagged none of the safe controls" + (s.elapsed_s != null ? " (" + Number(s.elapsed_s).toFixed(1) + "s)" : "") + " — the soundness/FP property holds on this host.")
            : "Live: a safe control was flagged — investigate before trusting this build's precision.")]),
      ]);
    }).catch(function () {
      V.mount(slot, h("div.legend", { style: { marginTop: "10px", borderColor: "var(--bad-line)" } },
        [V.icon("x"), h("span", null, "Could not reach the benchmark action.")]));
    }).then(function () { if (btn) { btn.disabled = false; btn.textContent = "Run benchmark now"; } });
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
    }).catch(function (e) { V.mount(v, offlineEmpty(e)); });
  }

  function brainRunScoped(v, b, tab) {
    var ep = tab === "intel" ? "/api/intel/" : "/api/planner/";
    V.getJSON(runsURL()).then(function (d) {
      b.runs = runsOf(d);                       // scoped to the active engagement
      // a run picked under a previous scope is another job's work — drop it rather than keep showing it
      if (!b.run || !b.runs.find(function (r) { return r.run_id === b.run.run_id; })) b.run = b.runs[0] || null;
      var picker = b.runs.length ? h("div.field", { style: { maxWidth: "560px" } }, [
        h("label", null, "Engagement"),
        h("select", { onChange: function (e) { b.run = b.runs.find(function (r) { return r.run_id === e.target.value; }); brainRunScoped(v, b, tab); } },
          b.runs.map(function (r) { return h("option", { value: r.run_id, selected: b.run && r.run_id === b.run.run_id }, (r.mode || "url") + " · " + (r.target || r.slug || r.run_id)); })),
      ]) : null;
      var slot = h("div#brain-rs", { style: { marginTop: "12px" } },
        b.runs.length ? h("div.empty", null, "Loading…")
          : (activeEngagement()
            ? scopedEmpty("engagements", "Nothing has run under this job yet, and " + tab + " is per-engagement.", [newAssessBtn()])
            : h("div.empty", null, "No engagements yet — " + tab + " is per-engagement.")));
      var actPanel = b.run ? brainRunAction(tab, (b.run.slug || b.run.run_id)) : null;
      V.mount(v, [picker, actPanel, slot]);
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
    }).catch(function (e) { V.mount(v, offlineEmpty(e)); });
  }

  // The per-engagement ACTION for the intel/planner tabs. Planner: compute the read-only plan projection
  // (`plan <slug>` — no traffic, no tools). Intel: run OFFLINE recon (`intel ingest` — passive collectors,
  // no egress; live collection is a charter-gated engagement, never a one-click button). Both are owner-plane.
  function brainRunAction(tab, slug) {
    var out = h("div#brain-act-out", { style: { marginTop: "10px" } });
    if (tab === "planner") {
      var pbtn = h("button.btn.owner", { onClick: function () {
        pbtn.disabled = true; pbtn.textContent = "Computing…";
        V.mount(out, h("div.hint", null, "Projecting the ranked plan over the persisted world-model…"));
        V.postJSON(OFF("/api/planner/run"), { slug: slug }).then(function (r) {
          if (!r || r.ok !== true) { V.mount(out, brainActErr((r && r.error) || "planner failed")); return; }
          V.mount(out, [h("div.legend", null, [V.icon("check"), h("span", null, "Read-only projection — no traffic, no tools.")]),
            h("pre.code.scroll-x", null, r.plan || "(empty plan)")]);
        }).catch(function () { V.mount(out, brainActErr("could not reach the planner action")); })
          .then(function () { pbtn.disabled = false; pbtn.textContent = "Compute plan projection"; });
      } }, "Compute plan projection");
      return V.card("Planner", "READ-ONLY PROJECTION", [
        h("p.dim", { style: { marginBottom: "10px" } }, "Reason over the world-model a prior spine engagement persisted and print the ranked attack plan. It sends no traffic and drives no tools."),
        pbtn, out], true);
    }
    // intel tab
    var seed = h("input", { type: "text", placeholder: "apex domain, e.g. example.com", style: { maxWidth: "320px" } });
    var ibtn = h("button.btn.owner", { onClick: function () {
      var val = (seed.value || "").trim();
      if (!val) { V.mount(out, brainActErr("enter an apex domain to seed the offline recon")); return; }
      ibtn.disabled = true; ibtn.textContent = "Ingesting…";
      V.mount(out, h("div.hint", null, "Running passive collectors over bundled fixtures (offline)…"));
      V.postJSON(OFF("/api/intel/run"), { slug: slug, seed: val }).then(function (r) {
        if (!r || r.ok !== true) { V.mount(out, brainActErr((r && r.error) || "intel ingest failed")); return; }
        V.mount(out, [h("div.legend", null, [V.icon("check"), h("span", null, "Offline ingest for " + (r.seed || val) + " — no egress. Reload the tab to see the updated world-model.")]),
          r.output ? h("pre.code.scroll-x", null, r.output) : null]);
      }).catch(function () { V.mount(out, brainActErr("could not reach the intel action")); })
        .then(function () { ibtn.disabled = false; ibtn.textContent = "Run offline recon"; });
    } }, "Run offline recon");
    return V.card("Intel recon", "OFFLINE", [
      h("p.dim", { style: { marginBottom: "10px" } }, "Ingest passive recon for this engagement from bundled fixtures — no network. Live collection is a charter-gated engagement decision, never a one-click button, so this control cannot egress."),
      h("div.row-flex", { style: { gap: "8px", flexWrap: "wrap", alignItems: "center" } }, [seed, ibtn]),
      out], true);
  }
  function brainActErr(msg) {
    return h("div.legend", { style: { borderColor: "var(--bad-line)" } }, [V.icon("x"), h("span", null, String(msg))]);
  }

  // ---- Chat -----------------------------------------------------------------
  // Tell the agent what to test in plain language — or hand it material (a zip of a codebase, loose
  // files, screenshots) and ask questions about it. Each launched turn goes through the SAME gated
  // launcher a hand-run engagement uses (scope charter-signed, WARDEN approve-then-run, oracle-confirmed
  // findings); the conversation is saved on the operator's machine (.vigil-live/chats/<id>.jsonl).
  //
  // THREE THINGS THIS SCREEN MUST NEVER BLUR:
  //   1. An answer about uploaded material is a LEAD. A finding becomes a FACT only when a deterministic
  //      oracle fires over real evidence — so every model-authored reply is badged as a lead, and where
  //      the reply reports an extracted codebase it offers the gated REAL scan of those same files.
  //   2. Nothing leaves this machine unannounced. Before the first send that carries an attachment the
  //      operator is shown exactly what goes: how many files, how many bytes, and the list. Once per
  //      attachment — not once per message, and never implicitly.
  //   3. A linked chat is a READ-TIME scope, not a merge. This chat draws on that one, one-way, and
  //      nothing is copied — which is why disconnecting takes effect immediately.
  //
  // Uploads ride the ordinary JSON action plane in slices (V.uploadChunked): the console refuses a POST
  // body over 1 MiB, and a transcript record must stay small (it is re-read whole on every render and
  // appended lock-free), so a record holds a POINTER to an attachment — never its bytes.
  const CHAT_MAX_ATTACH = 12;
  // Records the ENGINE authors itself: a launch, a refusal, an error, a prompt for a target, an
  // attachment receipt. Anything else an assistant says is model prose → a LEAD, and is badged as one.
  const CHAT_ENGINE_KINDS = { launched: 1, refused: 1, error: 1, need_target: 1, attached: 1, system: 1, agent_question: 1, awaiting_approval: 1, approval_rejected: 1 };

  function fmtBytes(n) {
    const b = Number(n) || 0;
    if (b < 1024) return b + " B";
    const u = ["KB", "MB", "GB", "TB"];
    let v = b / 1024, i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
    return (v >= 100 ? Math.round(v) : Math.round(v * 10) / 10) + " " + u[i];
  }

  // A real modal — the screen has two decisions that must not be taken by `window.prompt` (which cannot
  // show a list, cannot be styled, and cannot be read by a screen reader as a dialog): the egress
  // consent and the link picker. Escape / backdrop / ✕ all cancel; the caller learns via onCancel.
  function openModal(title, body, actions, opts) {
    opts = opts || {};
    const host = h("div.vmodal", { role: "dialog", "aria-modal": "true", "aria-label": String(title || "Dialog") });
    let closed = false;
    function close() {
      if (closed) return; closed = true;
      document.removeEventListener("keydown", onKey);
      host.remove();
    }
    function cancel() { if (closed) return; close(); if (opts.onCancel) opts.onCancel(); }
    function onKey(e) { if (e.key === "Escape") { e.preventDefault(); cancel(); } }
    const card = h("div.vmodal-card", null, [
      h("div.vmodal-h", null, [
        h("h3", null, String(title || "")),
        h("button.iconbtn", { "aria-label": "Close", onClick: cancel }, V.icon("x")),
      ]),
      h("div.vmodal-b", null, body),
      (actions && actions.length) ? h("div.vmodal-f", null, actions) : null,
    ]);
    host.appendChild(card);
    host.addEventListener("mousedown", function (e) { if (e.target === host) cancel(); });
    document.addEventListener("keydown", onKey);
    document.body.appendChild(host);
    const first = card.querySelector(".vmodal-b input, .vmodal-f button, .vmodal-b button");
    if (first && first.focus) first.focus();
    return { close: close, card: card };
  }

  // ---- Strix Control (S10): the Strix runtime CONTROL STATE, read-only --------------------------
  // Surfaces what the Strix runtime actually reports — mode/target/scope, model locality + data
  // residency, the VIGIL egress gateway + sandbox status, the pending WARDEN approval queue, proof
  // health (the S9 4-way degraded state), the FACT/LEAD/CLEAN/INCONCLUSIVE verdict separation,
  // resource state, the kill controls and resume/recovery. It reads /api/strix/control (a PURE
  // reader): it spawns nothing and mints no FACT (the run/execute path stays checkpoint-gated
  // elsewhere, as H10). Where a runtime source does not exist on this build (a live per-tool feed,
  // live cpu/mem/pids, an on-demand container kill) the surface says UNAVAILABLE — never a
  // fabricated number. The kill controls it DOES wire are STOPS (host-pid cancel + engagement
  // kill-switch), never a spawn.
  var STX = { run: "", data: null, err: null, loaded: false, _body: null };
  function renderStrix(screen) {
    var body = V.mount(screen, [h("div.screen-head", null, [h("h1", null, "Strix Control"),
      h("span.sub", null, "The Strix agent's runtime control state — gateway, sandbox, approvals, "
        + "proof health and the FACT/LEAD/CLEAN/INCONCLUSIVE verdicts. Read-only: nothing here spawns "
        + "a run or mints a fact.")])]);
    loadStrix(body);
  }
  function loadStrix(body) {
    STX._body = body;
    var slug = activeEngagement();
    var url = OFF("/api/strix/control"
      + (STX.run ? ("?run=" + encodeURIComponent(STX.run)) : "")
      + (slug ? ((STX.run ? "&" : "?") + "slug=" + encodeURIComponent(slug)) : ""));
    V.getJSON(url).then(function (d) {
      STX.data = d; STX.err = null; STX.loaded = true; STX.run = d.run_id || "";   // reflect the server's selection
    }).catch(function (e) {
      STX.data = null; STX.err = e; STX.loaded = true;   // WS2a-2: capture the REAL error (401 = stale token)
    }).then(function () { drawStrix(body); });            // render ALWAYS runs, OUTSIDE the catch — so a render
  }                                                       // throw is no longer swallowed and mislabelled "offline"
  function strixLocalityChip(model) {
    var m = model || {};
    if (m.locality === "local") return V.pill("model: local", "sm ok", null);
    if (m.locality === "cloud") return V.pill("model: cloud", "sm warn", null);
    return V.pill("model: unknown", "sm", null);
  }
  function strixPicker(d) {
    var runs = d.runs || [];
    return h("div.card", null, [h("label", { style: { marginRight: "8px" } }, "Strix run"),
      h("select", { onChange: function (e) { STX.run = e.target.value; loadStrix(STX._body); } },
        [h("option", { value: "", selected: !STX.run }, runs.length ? "— newest Strix run —" : "— none —")].concat(
          runs.map(function (r) {
            var lab = (r.label || r.slug || r.run_id) + " · " + (r.run_kind || "") + " · " + (r.status || "");
            return h("option", { value: r.run_id, selected: r.run_id === d.run_id }, lab);
          }))),
      h("span", { style: { marginLeft: "8px" } }, strixLocalityChip(d.model))]);
  }
  function strixOverviewCard(d) {
    var sel = d.selected; var m = d.model || {};
    if (!sel) return V.card("Overview", "NO STRIX RUN", h("div.hint", null,
      "No Strix run recorded" + (d.slug ? " for this engagement" : "") + ". Start a Strix (codebase / "
      + "agentic) assessment from New Assessment; its control state appears here."), false);
    return V.card("Overview", "STRIX RUN", h("div", null, [
      h("div.grid.cols-2", null, [
        h("div", null, [
          trustKv("Mode", String(sel.run_kind || "—")),
          trustKv("Target", String(sel.target || "—")),
          trustKv("Scope (engagement)", String(sel.slug || "—")),
          trustKv("Status", String(sel.status || "—"))]),
        h("div", null, [
          trustKv("Model", (m.model || "—") + " · " + (m.locality || "unknown")),
          trustKv("Data residency", String(m.residency || "—")),
          (m.endpoint ? trustKv("Endpoint", String(m.endpoint)) : null),
          (sel.interrupted_reason ? trustKv("Interrupted", String(sel.interrupted_reason)) : null)])])]), false);
  }
  function strixGatewayCard(gw) {
    gw = gw || {}; var running = !!gw.running; var eg = gw.egress || "UNKNOWN";
    var egCls = eg === "ON" ? "ok" : (eg === "OFF" ? "warn" : null);
    return V.card("Egress gateway + sandbox network", "VIGIL", h("div", null, [
      h("div.grid.cols-3", null, [
        V.tile("Gateway", gw.available ? (running ? "RUNNING" : String(gw.state || "absent").toUpperCase()) : "UNKNOWN",
          gw.available ? (running ? "vigil-gateway container up" : "not running") : "docker probe unavailable",
          running ? "ok" : (gw.available ? "warn" : null)),
        V.tile("Sandbox pin", gw.sandbox_pinned ? "PINNED" : "UNPINNED",
          gw.sandbox_pinned ? "pinned onto the gated net" : "NOT pinned onto the gated net",
          gw.sandbox_pinned ? "ok" : "warn"),
        V.tile("Egress", eg, eg === "ON" ? "routed through the gateway" : "NOT gated", egCls)]),
      h("div.hint", { style: { marginTop: "8px" } }, gw.note || ""),
      (gw.error ? h("div.hint", { style: { marginTop: "4px", color: "var(--st-blocked)" } }, "probe error: " + gw.error) : null)]), false);
  }
  function strixSandboxCard(sb) {
    sb = sb || {}; var hp = sb.host_process;
    return V.card("Sandbox / container", "STATUS", h("div", null, [
      trustKv("Container status", sb.container_status_available ? "available" : "not persisted by this build (no container registry)"),
      (hp ? trustKv("Host process", (hp.running ? "running" : (hp.status || "—"))
        + (hp.pid != null ? (" (pid " + hp.pid + ")") : "")) : null),
      h("div.hint", { style: { marginTop: "8px" } }, sb.note || "")]), false);
  }
  function strixVerdictCard(v) {
    v = v || {};
    function chip(label, val, cls, desc) {
      return h("div.fix-card", { style: { padding: "8px 10px" } }, [
        h("div.row-flex", { style: { gap: "6px", alignItems: "center" } }, [V.pill(label, cls, null), h("b", null, String(val))]),
        h("div.dim", { style: { fontSize: "var(--fs-micro)", marginTop: "4px" } }, desc)]);
    }
    var cleanVal = !v.has_run ? "—" : (v.clean ? "yes" : "no");
    return V.card("Verdicts — the verification manifest", "FACT / LEAD / CLEAN / INCONCLUSIVE", h("div", null, [
      h("div.grid.cols-4", null, [
        chip("FACT", v.has_run ? v.fact : "—", "sm ok", "oracle FIRED over captured bytes — never a Strix claim alone."),
        chip("LEAD", v.has_run ? v.lead : "—", "sm warn", "reported but not VIGIL-verified — a Strix finding is a LEAD until re-driven."),
        chip("CLEAN", cleanVal, "sm", "a checked surface with a sound negative — impossible while degraded/incomplete."),
        chip("INCONCLUSIVE", v.has_run ? v.inconclusive : "—", "sm", "a missing channel, a degraded subsystem, or a run that did not complete.")]),
      (v.clean_blocked_reason ? h("div.hint", { style: { marginTop: "8px" } }, "CLEAN is blocked: " + v.clean_blocked_reason) : null),
      (v.denied ? h("div.hint", { style: { marginTop: "4px" } }, String(v.denied) + " dangerous PoC(s) refused before any mint.") : null)]), false);
  }
  function strixProofCard(ph) {
    ph = ph || {}; var degraded = !!ph.verification_degraded;
    var banner = degraded ? h("div.card.verification-degraded", { role: "alert" }, [
      h("div.card-h", null, [h("h3", { style: { color: "var(--st-blocked)" } }, [V.icon("info"), " Verification degraded — this run is NOT clean"]),
        h("span.pill.sm.danger", { style: { marginLeft: "auto" } }, String(ph.disposition || "degraded"))]),
      h("p", null, PROOF_DEG_LABEL[ph.disposition] || "The proof subsystem degraded on this run, so an empty proof list does NOT mean the target is clean."),
      ((ph.degraded_causes || []).length ? h("div.kv", null, [h("div.k", null, "Causes"),
        h("div.v", null, (ph.degraded_causes || []).map(function (c) { return h("span.pill.sm.danger", null, String(c.kind) + " ×" + String(c.count || 1)); }))]) : null)]) : null;
    var covRows = (ph.inconclusive_surfaces || []).length ? h("div.kv", null, [h("div.k", null, "Unassessed surfaces"),
      h("div.v", null, (ph.inconclusive_surfaces || []).map(function (s) { return h("span.pill.sm.warn", null, String(s)); }))]) : null;
    return h("div", null, [banner, V.card("Proof health", "S9", h("div", null, [
      trustKv("Disposition", String(ph.disposition || (ph.has_run ? "—" : "no run selected"))),
      trustKv("Degraded", degraded ? "yes" : "no"),
      trustKv("Coverage", ph.coverage_incomplete ? "INCOMPLETE — a declared surface went unassessed" : "complete"),
      covRows,
      h("div.hint", { style: { marginTop: "8px" } }, "Distinguishes nothing-found from proof-subsystem-unavailable / capture-failed / redrive-failed / mint-failed. See Proof Studio for the records.")]), false)]);
  }
  function strixApprovalsCard(ap) {
    ap = ap || {}; var pend = ap.pending || [];
    var rows = pend.length ? pend.map(function (p) {
      return h("div.fix-card", { style: { padding: "8px 10px", marginTop: "6px" } }, [
        h("div.row-flex", { style: { gap: "8px", alignItems: "center", flexWrap: "wrap" } }, [
          V.pill(String(p.tool_name || "?"), "sm warn", null), h("b.mono", null, String(p.target || "—")),
          h("span.dim", { style: { marginLeft: "auto", fontSize: "var(--fs-micro)" } }, String(p.created_at_iso || ""))]),
        (p.args_preview ? h("div.dim", { style: { fontSize: "var(--fs-micro)", marginTop: "4px" } }, "args: " + String(p.args_preview)) : null)]);
    }) : [h("div.empty", null, "No Strix action is waiting for an owner signature.")];
    return V.card("Pending WARDEN approvals", (pend.length ? String(pend.length) + " WAITING" : "0 WAITING"), h("div", null, [
      h("div.hint", null, ap.note || ""),
      h("div", { style: { marginTop: "6px" } }, rows),
      (ap.base_dir ? h("div.hint", { style: { marginTop: "8px" } }, ["Sign out-of-band: ",
        h("code", null, "vigil approve sign --base-dir " + ap.base_dir + " <request-id>")]) : null)]), false);
  }
  function strixActivityCard(a) {
    a = a || {};
    return V.card("Live tool activity", a.live_tool_feed_available ? "LIVE" : "NO LIVE FEED", h("div", null, [
      h("div.hint", null, a.note || ""),
      h("div.row-flex", { style: { gap: "8px", marginTop: "8px", flexWrap: "wrap" } }, [
        h("button.btn.sm", { onClick: function () { location.hash = "#/live"; } }, [V.icon("live"), "Live spine feed"]),
        h("button.btn.sm", { onClick: function () { location.hash = "#/proof"; } }, [V.icon("shield"), "Proof Studio"])])]), false);
  }
  function strixResourceCard(rs) {
    rs = rs || {}; var lim = rs.configured_limits || {};
    return V.card("Resource consumption", rs.live_usage_available ? "LIVE" : "LIMITS ONLY", h("div", null, [
      h("div.hint", null, rs.note || ""),
      h("div", { style: { marginTop: "8px" } }, [
        trustKv("Memory limit", String(lim.mem_limit || "—")),
        trustKv("CPU limit", String(lim.cpus || "—")),
        trustKv("PID limit", String(lim.pids_limit || "—")),
        trustKv("shm size", String(lim.shm_size || "—"))])]), false);
  }
  function strixTripKill(slug) {
    if (!slug) return;
    if (!window.confirm("Trip the engagement kill-switch?\n\nThe engagement will HALT on its next poll. This is the offense-side hard stop.")) return;
    V.postJSON(OFF("/api/killswitch/" + encodeURIComponent(slug) + "/trip"), { reason: "tripped from Strix Control" })
      .then(function (r) { if (r && r.error) { V.toast(r.error, true); return; } V.toast("Kill-switch tripped — the engagement will halt."); loadStrix(STX._body); })
      .catch(function (e) { V.toast((e && e.message) || "Could not trip the kill-switch", true); });
  }
  function strixKillCard(ks) {
    ks = ks || {}; var eng = ks.engagement || {}; var ps = ks.process_stop || {}; var ck = ks.container_kill || {};
    var engTripped = eng.tripped === true; var canTrip = !!eng.slug && !engTripped;
    var stopBtn = h("button.btn.danger", { disabled: !ps.available,
      title: ps.available ? "Stop the Strix host process (SIGTERM->SIGKILL)" : "No running Strix run to stop",
      onClick: function () { if (ps.run_id) runCancel(ps.run_id, function () { loadStrix(STX._body); }); } }, [V.icon("x"), "Stop Strix process"]);
    var tripBtn = h("button.btn.danger", { disabled: !canTrip,
      title: canTrip ? "Trip this engagement's kill-switch (offense-side hard stop)" : (engTripped ? "Already tripped" : "No engagement slug for this run"),
      onClick: function () { strixTripKill(eng.slug); } }, [V.icon("x"), "Trip engagement kill-switch"]);
    var containerBtn = h("button.btn", { disabled: true, title: ck.note || "not available" }, [V.icon("x"), "Kill container"]);
    return V.card("Kill controls", "SAFETY", h("div", null, [
      h("div.grid.cols-3", null, [
        V.tile("Engagement kill-switch", engTripped ? "TRIPPED" : (eng.slug ? "released" : "—"),
          eng.reason || (eng.slug ? "offense-side hard stop" : "no slug"), engTripped ? "danger" : null),
        V.tile("Process stop", ps.available ? "available" : "—", "host pid SIGTERM->SIGKILL", null),
        V.tile("Container kill", "UNAVAILABLE", "not wired in this build", "warn")]),
      h("div.row-flex", { style: { gap: "8px", marginTop: "10px", flexWrap: "wrap" } },
        [stopBtn, tripBtn, containerBtn, V.pill("container-reap: checkpoint-gated", "sm warn", null)]),
      h("div.hint", { style: { marginTop: "8px" } }, ck.note || ""),
      h("div.hint", { style: { marginTop: "4px" } }, ps.note || "")]), false);
  }
  function strixRecoveryCard(rc) {
    rc = rc || {};
    if (!rc.present) return V.card("Resume / recovery", "—", h("div.hint", null, rc.note || "No Strix run selected."), false);
    var retryable = !!rc.retryable;
    var btn = h("button.btn", { disabled: !retryable,
      title: retryable ? (rc.action === "resume" ? "Resume this run from its last signed checkpoint" : "Restart this run from the beginning")
        : "Retry/resume becomes available once the run has ended",
      onClick: function () { if (rc.run_id) runRetry(rc.run_id, function () { loadStrix(STX._body); }); } },
      [V.icon("play"), rc.action === "resume" ? "Resume run" : "Restart run"]);
    return V.card("Resume / recovery", rc.resumable ? "RESUMABLE" : "RESTART-ONLY", h("div", null, [
      h("div.grid.cols-3", null, [
        V.tile("Run status", String(rc.status || "—"), rc.interrupted_reason || "", rc.status === "error" ? "danger" : null),
        V.tile("Recovery", rc.action === "resume" ? "RESUME" : "RESTART", rc.resumable ? "continues from last checkpoint" : "restarts from the beginning", null),
        V.tile("Return code", rc.rc == null ? "—" : String(rc.rc), "", null)]),
      h("div.row-flex", { style: { gap: "8px", marginTop: "10px" } }, [btn]),
      h("div.hint", { style: { marginTop: "8px" } }, rc.note || "")]), false);
  }
  function drawStrix(body) {
    var d = STX.data;
    if (!d) { V.mount(body, h("div.card", null, offlineEmpty(STX.err,
      "Could not load the Strix control state — is the offense plane up? (vigil up)"))); return; }
    STX._body = body;
    V.mount(body, [
      strixPicker(d), strixOverviewCard(d), strixGatewayCard(d.gateway), strixSandboxCard(d.sandbox),
      strixVerdictCard(d.verdicts), strixProofCard(d.proof_health), strixApprovalsCard(d.approvals),
      strixActivityCard(d.activity), strixResourceCard(d.resources), strixKillCard(d.killswitch),
      strixRecoveryCard(d.recovery),
      h("div.hint", { style: { marginTop: "10px" } }, d.doctrine || "")]);
  }

  // A file dropped NEXT TO the transcript (on the nav, the top bar, the margin) would otherwise make the
  // browser navigate away to that file and take the console with it. Same function reference every time,
  // so re-entering the screen cannot stack duplicate listeners, and it unhooks itself once the chat
  // screen is gone. It only ever cancels a default; it reads nothing.
  function chatDropGuard(e) {
    if (!document.getElementById("chat-wrap")) {
      window.removeEventListener("dragover", chatDropGuard);
      window.removeEventListener("drop", chatDropGuard);
      return;
    }
    const types = (e.dataTransfer && e.dataTransfer.types) || [];
    if (Array.prototype.indexOf.call(types, "Files") !== -1) e.preventDefault();
  }

  function renderChat(screen) {
    teardownLive();
    window.addEventListener("dragover", chatDropGuard);
    window.addEventListener("drop", chatDropGuard);
    const C = {
      id: hashQuery().id || "",
      messages: [], sessions: [], chatMeta: {}, st: null, busy: false,
      attach: [], seq: 0, dragDepth: 0,
      // the real tool roster + capability catalog, so the composer's "one tool" mode can send something
      // the launcher actually acts on (see TOOL_LAUNCH)
      profiles: [], caps: [], profilesErr: false,
      // the composer's own selections, kept OUT of the DOM so a redraw after a send does not quietly
      // reset the mode (and with it the picked tool) back to "auto" under the operator
      mode: "", tool: "",
      // how hard to reason on THIS reply (Ask / Research / Plan). "ask" = default, byte-identical to the
      // prior single-shot behaviour; research/plan turn on extended thinking backend-side.
      reasonMode: "ask",
      // Phase C: this chat's hypothesis ledger (open first, then confirmed/refuted with the finding ref).
      hyps: [],
      // the chat drives the AGENTIC engine by default (OODA loop, steerable, resumable). Off = a lighter
      // gated scan. Sent as `agentic` so the server-side default can be opted out of (red-pen F2).
      agentic: true,
      // E3 — per-session model sovereignty. `models` is the picker roster (each with its trust class +
      // whether the current sovereignty tier permits it + the consequence of choosing it); `model` is THIS
      // session's choice ("" = the server default, Claude Opus 5), remembered per session in localStorage so
      // it survives a reload. A LOCAL choice means an uploaded codebase never leaves the machine.
      models: [], modelTier: "",
      model: "",
      // F1 — the in-flight STREAMING turn ({text, msg}) or null. The tokens render in a transient live bubble;
      // when the turn completes the transcript is refreshed from the persisted record and this is cleared.
      stream: null,
      // D2b: per-run codebase working state, keyed by run_id — a proposed dev-mode diff (awaiting the
      // operator's review-and-apply), the last test result, and per-run busy flags. Kept OUT of the DOM so
      // a transcript redraw (which rebuilds every bubble from the saved records) does not drop a diff the
      // operator is mid-review on. The PATH it acts on is always read from the record (m.codebase_path) and
      // RE-CONFINED server-side — this cache never becomes an authority on which directory is touched.
      codebase: {},
    };

    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Chat"),
        h("span.sub", null, "Ask in plain language, or attach a zip, files and images and ask about them. Answers are leads; the gated run is what mints facts.")]),
      h("div#chat-wrap", null, [
        h("div#chat-sessions", null, h("div.empty", null, "…")),
        h("div#chat-main", null, h("div.empty", null, "Loading…")),
      ]),
    ]);

    function load() {
      // The roster is AWAITED, not fired and forgotten: drawing the composer before it lands would
      // render the one-tool picker empty and tell the operator no tool can be started here — a false
      // negative about their own machine, produced by a race.
      const roster = Promise.all([
        V.getJSON(OFF("/api/toolprofiles")).then(function (d) {
          C.profiles = (d && d.profiles) || []; C.profilesErr = !!(d && d.error);
        }).catch(function () { C.profiles = []; C.profilesErr = true; }),
        V.getJSON(OFF("/api/capabilities")).then(function (d) { C.caps = capsOf(d); }).catch(function () { C.caps = []; }),
        // E3: the model-sovereignty roster — each selectable model + trust class + whether the tier permits it.
        V.getJSON(OFF("/api/chat/models")).then(function (d) {
          C.models = (d && d.models) || []; C.modelTier = (d && d.tier) || "";
        }).catch(function () { C.models = []; C.modelTier = ""; }),
      ]);
      V.getJSON(SOV("/api/settings")).then(function (st) { C.st = st; }).catch(function () { C.st = null; })
        .then(function () { return roster; })
        .then(loadChatList)
        .then(function () {
          restoreModel();                 // E3: this session's remembered model choice (default = server default)
          if (!C.id) { C.messages = []; drawSessions(); drawMain(); return; }
          return refreshTranscript().then(refreshHyps).then(function () { drawSessions(); drawMain(); });
        });
    }

    // E3 — the per-session model choice is remembered in localStorage keyed by session id, so a reload keeps
    // it (the operator's decision was "ask per session"). A blank/unknown choice means the server default.
    function modelKey(id) { return "vigil.chat.model." + (id || "new"); }
    function restoreModel() { try { C.model = localStorage.getItem(modelKey(C.id)) || ""; } catch (e) { C.model = ""; } }
    function rememberModel() { try { localStorage.setItem(modelKey(C.id), C.model || ""); } catch (e) {} }

    // The sidebar reads the SESSIONS listing rather than /api/chat/sessions, because only that one
    // carries `connections` — the other chats this one draws on. The chat listing is still read and
    // merged in by id, for the title (first user line) and the turn count it alone knows. Union, not
    // intersection: a transcript the registry has not adopted yet still shows up.
    function loadChatList() {
      return Promise.all([
        V.getJSON(OFF("/api/sessions")).then(function (d) { return (d && d.sessions) || []; }).catch(function () { return []; }),
        V.getJSON(OFF("/api/chat/sessions")).then(function (d) { return (d && d.sessions) || []; }).catch(function () { return []; }),
      ]).then(function (r) {
        const sess = r[0] || [], chats = r[1] || [];
        const meta = {};
        chats.forEach(function (c) { if (c && c.id) meta[c.id] = c; });
        C.chatMeta = meta;
        const byId = {};
        sess.forEach(function (s) {
          if (!s || !s.id) return;
          if (s.kind !== "chat" && s.kind !== "mixed") return;
          byId[s.id] = { id: s.id, name: s.name || "", kind: s.kind, connections: (s.connections || []).slice(),
            updated: Number(s.updated) || 0, runs: (s.run_ids || []).length, registered: true };
        });
        chats.forEach(function (c) {
          if (!c || !c.id || byId[c.id]) return;
          byId[c.id] = { id: c.id, name: c.title || "", kind: "chat", connections: [],
            updated: Number(c.updated) || 0, runs: 0, registered: false };
        });
        C.sessions = Object.keys(byId).map(function (k) { return byId[k]; })
          .sort(function (a, b) { return (b.updated || 0) - (a.updated || 0); });
      });
    }

    function rowOf(id) {
      if (!id) return null;
      for (let i = 0; i < C.sessions.length; i++) if (C.sessions[i].id === id) return C.sessions[i];
      return null;
    }
    function titleOf(id) {
      const m = C.chatMeta[id], r = rowOf(id);
      return (m && m.title) || (r && r.name) || id || "(chat)";
    }
    function turnsOf(id) { const m = C.chatMeta[id]; return m && m.turns != null ? Number(m.turns) : null; }

    function refreshTranscript() {
      if (!C.id) { C.messages = []; return Promise.resolve(); }
      return V.getJSON(OFF("/api/chat/session/" + encodeURIComponent(C.id)))
        .then(function (d) { C.messages = (d && d.messages) || []; })
        .catch(function () { C.messages = []; });
    }

    // Phase C: the hypothesis ledger. Reconciled server-side against the engine's confirmed FACTs, so a
    // hypothesis a run has since settled shows as confirmed on a plain reload. Never blocks the transcript.
    function refreshHyps() {
      if (!C.id) { C.hyps = []; return Promise.resolve(); }
      return V.getJSON(OFF("/api/chat/hypotheses?chat_id=" + encodeURIComponent(C.id)))
        .then(function (d) { C.hyps = (d && d.hypotheses) || []; })
        .catch(function () { /* keep the last-known ledger on a transient error */ });
    }

    // One writer for "this conversation now has an id": the URL, the state and the upload's chat
    // binding can then never disagree.
    function adoptChatId(id) {
      const next = String(id || "");
      if (!next || C.id === next) return;
      C.id = next;
      history.replaceState(null, "", "#/chat?id=" + encodeURIComponent(next));
    }

    function openSession(id) {
      C.id = id || "";
      C.messages = []; C.attach = []; C.hyps = [];
      history.replaceState(null, "", "#/chat" + (id ? ("?id=" + encodeURIComponent(id)) : ""));
      // SWITCHING chats only needs THIS chat's transcript + hypotheses — the models/settings/tool
      // roster/session-list are session-global and already cached from the first load(), so re-fetching
      // them on every click made opening a saved chat pay ~6 serial cross-plane round-trips (incl. the
      // 143ms models probe + the proxy's per-request auth). Redraw instantly from cache, then fetch the
      // two per-chat things IN PARALLEL. (First-ever load still runs the full load() from renderChat.)
      restoreModel();
      drawSessions(); drawMain();
      if (!C.id) return;
      Promise.all([refreshTranscript(), refreshHyps()])
        .then(function () { drawMain(); scrollDown(); })
        .catch(function () { drawMain(); });
    }

    function drawSessions() {
      const host = V.$("#chat-sessions"); if (!host) return;
      const rows = [
        h("button.btn.primary.chat-new", { onClick: function () { openSession(""); } }, [V.icon("bolt"), "New chat"]),
        h("div.chat-rail-cap", null, "Chats"),
      ];
      if (!C.sessions.length) {
        rows.push(h("div.hint", null, "No saved chats yet. Start one above."));
      } else {
        C.sessions.forEach(function (s) {
          const active = s.id === C.id;
          const turns = turnsOf(s.id);
          const links = (s.connections || []).length;
          const main = h("button.chat-session" + (active ? ".on" : ""), {
            title: titleOf(s.id) + (links ? ("\ndraws on " + links + " other chat" + (links === 1 ? "" : "s")) : ""),
            onClick: function () { openSession(s.id); },
          }, [
            h("span.chat-session-t", null, titleOf(s.id)),
            h("span.chat-session-m", null,
              (turns != null ? turns + (turns === 1 ? " turn" : " turns") : "") + (links ? " · " + links + "⛓" : "")),
          ]);
          const rn = h("button.iconbtn.sm", { title: "Rename chat", "aria-label": "Rename chat",
            onClick: function (e) { if (e) e.stopPropagation(); renameChat(s); } }, V.icon("edit"));
          const del = h("button.iconbtn.sm", { title: "Delete chat", "aria-label": "Delete chat",
            onClick: function (e) { if (e) e.stopPropagation(); deleteChat(s); } }, V.icon("trash"));
          rows.push(h("div.chat-session-row" + (active ? ".on" : ""), null, [main, rn, del]));
        });
      }
      V.mount(host, rows);
    }

    function renameChat(s) {
      // S12: a proper modal (Esc/backdrop-cancel, focus-managed) instead of window.prompt.
      const cur = titleOf(s.id);
      const nameInput = h("input.input", { type: "text", value: cur === "(empty)" ? "" : cur,
        placeholder: "Chat title", style: { width: "100%" } });
      function save() {
        const t = (nameInput.value || "").trim();
        if (!t) { V.toast("Title must not be empty.", true); if (nameInput.focus) nameInput.focus(); return; }
        if (m) m.close();
        V.postJSON(OFF("/api/chat/rename"), { chat_id: s.id, title: t }).then(function (d) {
          if (d && d.error) { V.toast(d.error, true); return; }
          loadChatList().then(function () { drawSessions(); drawMain(); });
        }).catch(function (e) { V.toast(String(e), true); });
      }
      nameInput.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); save(); } });
      const m = openModal("Rename chat", h("div.stack", null, [nameInput]), [
        h("button.btn.primary", { onClick: save }, [V.icon("check"), "Rename"]),
      ]);
    }

    function deleteChat(s) {
      if (!window.confirm("Delete chat ‘" + titleOf(s.id) + "’?\n\nIts transcript and any attachments "
        + "are removed. Runs it launched and their signed records are kept.")) return;
      V.postJSON(OFF("/api/chat/delete"), { chat_id: s.id }).then(function (d) {
        if (d && d.error) { V.toast(d.error, true); return; }
        V.toast("Chat deleted");
        if (s.id === C.id) { openSession(""); }    // clears the active chat + reloads via load()
        else { loadChatList().then(function () { drawSessions(); }); }
      }).catch(function (e) { V.toast(String(e), true); });
    }

    // -- attachments ---------------------------------------------------------
    // An attachment is uploaded the moment it is chosen (so the operator sees a refusal early), but it
    // does not LEAVE the machine for the model until the send that carries it is consented to.
    function addFiles(fileList) {
      const files = Array.prototype.slice.call(fileList || []);
      if (!files.length) return;
      files.forEach(function (f) {
        if (C.attach.length >= CHAT_MAX_ATTACH) {
          V.toast("At most " + CHAT_MAX_ATTACH + " attachments at a time — send these first.", true);
          return;
        }
        const a = {
          key: "att" + (++C.seq), name: String(f.name || "file"), size: Number(f.size) || 0,
          status: "uploading", pct: 0, err: "", refusals: [], consented: false, sent: false,
          id: "", sha256: "", kind: "", files: null, fileList: [], more: 0, path: "",
          abortRef: { aborted: false }, previewUrl: "",
        };
        // S11: a local image thumbnail (object URL from the picked File — never leaves the browser; the
        // actual bytes still upload + gate exactly as before).
        try { if (f.type && f.type.indexOf("image/") === 0) a.previewUrl = URL.createObjectURL(f); } catch (e) {}
        C.attach.push(a);
        drawAttach();
        V.uploadChunked({
          begin: OFF("/api/chat/attach/begin"),
          chunk: OFF("/api/chat/attach/chunk"),
          finish: OFF("/api/chat/attach/finish"),
          abort: OFF("/api/chat/attach/abort"),
        }, f, {
          fields: C.id ? { chat_id: C.id } : {},
          finishFields: C.id ? { chat_id: C.id } : {},
          abortRef: a.abortRef,
          onProgress: function (sent, total) {
            a.pct = total > 0 ? Math.round((sent / total) * 100) : 100;
            drawAttach();
          },
        }).then(function (r) { applyUpload(a, r); })
          .catch(function (e) {
            // A 404 here is not "your file is bad" — it is a console without the upload routes. Say which,
            // but keep any refusals the body did carry: a refusal must reach the operator either way.
            const data = (e && e.data) || {};
            const why = (e && e.status === 404)
              ? "this console build has no chat upload route (404) — nothing was sent"
              : (data.error || (e && e.message) || "upload failed");
            applyUpload(a, { error: why, refusals: data.refusals });
          })
          .then(function () { drawAttach(); });
      });
    }

    // A refusal EXPLAINS ITSELF. Whatever shape the console sends it in — a string, an object with a
    // reason, a list — it reaches the operator as readable prose, never as a swallowed failure.
    function normRefusals(list) {
      if (list == null) return [];
      if (!Array.isArray(list)) list = [list];
      return list.map(function (x) {
        if (typeof x === "string") return x;
        if (x && typeof x === "object") {
          const why = String(x.reason || x.error || x.message || x.detail || "");
          const where = String(x.path || x.name || x.entry || "");
          if (why && where) return why + " — " + where;
          if (why) return why;
          try { return JSON.stringify(x); } catch (e) { return String(x); }
        }
        return String(x);
      }).filter(function (s) { return s !== ""; });
    }

    function applyUpload(a, r) {
      r = r || {};
      // The console returns the MANIFEST at the top level (`{chat_id, ok, attachment_id, name, kind,
      // files, bytes, sha256, …}`). Reading only a nested `attachment` object left the count, the
      // digest and the kind blank — and those three are exactly what the egress-consent dialog shows
      // the operator before their code leaves the machine. A consent screen that cannot say how many
      // files it is about to send is not consent. So the manifest is read where it actually is, with
      // the nested shape still honoured for a console that sends one.
      const att = r.attachment || r.file || r;
      a.refusals = normRefusals(r.refusals || att.refusals || r.refused || att.refused);
      if (r.chat_id) adoptChatId(String(r.chat_id));
      const id = att.attachment_id || att.id || r.attachment_id || r.id;
      if (r.error || r.refused || r.ok === false || !id) {
        a.status = "failed";
        a.err = String(r.error || r.refused || "the console did not return an attachment to send");
        return;
      }
      a.id = String(id);
      a.name = String(att.name || a.name);
      const sz = att.bytes != null ? att.bytes : att.size;
      if (sz != null) a.size = Number(sz) || a.size;
      a.sha256 = String(att.sha256 || att.digest || "");
      a.kind = String(att.kind || att.type || "");
      const cnt = att.files != null ? att.files : (att.file_count != null ? att.file_count : null);
      a.files = cnt == null ? null : Number(cnt);
      const names = att.names || att.file_names || att.entries;
      a.fileList = Array.isArray(names) ? names.map(String) : [];
      a.more = Number(att.names_truncated || att.more || 0) || 0;
      a.path = String(att.path || att.root || "");
      a.status = "ready";
    }

    // Removing an attachment DELETES IT ON THE CONSOLE, it does not just drop the chip. Every chat turn
    // reasons over everything the chat still holds, so an attachment taken off this row while the store
    // kept it would keep going to the model on every later turn with nothing on screen saying so — the
    // interface would be lying about what leaves the machine. The row is dropped only once the console
    // confirms; if it refuses, the operator is told and the chip stays, because it is still attached.
    function removeAttach(a) {
      a.abortRef.aborted = true;
      if (!a.id || !C.id) {                    // never uploaded (or still opening): nothing to delete
        C.attach = C.attach.filter(function (x) { return x !== a; });
        drawAttach();
        return;
      }
      const was = a.status;
      a.status = "removing"; drawAttach();
      V.postJSON(OFF("/api/chat/attach/remove"), { chat_id: C.id, attachment_id: a.id })
        .then(function (d) {
          if (d && d.error) throw new Error(d.error);
          C.attach = C.attach.filter(function (x) { return x !== a; });
        })
        .catch(function (e) {
          a.status = was;
          V.toast("Could not remove " + a.name + " — it is still attached to this chat. "
            + ((e && e.message) || ""), true);
        })
        .then(function () { drawAttach(); });
    }

    function attachChip(a) {
      const cls = a.status === "failed" ? ".chip.bad"
        : ((a.status === "uploading" || a.status === "removing") ? ".chip.busy"
          : (a.sent ? ".chip.sent" : ".chip"));
      const bits = [];
      if (a.previewUrl) bits.push(h("img.att-thumb", { src: a.previewUrl, alt: a.name, title: a.name }));   // S11
      bits.push(h("span.nm", { title: a.name }, a.name), h("span.meta", null, fmtBytes(a.size)));
      if (a.files != null) bits.push(h("span.meta", null, "· " + a.files + " file" + (a.files === 1 ? "" : "s")));
      if (a.status === "uploading") {
        bits.push(h("span.bar", null, h("span.bar-fill", { style: { width: a.pct + "%" } })));
        bits.push(h("span.meta", null, a.pct + "%"));
      } else if (a.status === "removing") {
        bits.push(h("span.meta", null, "· removing…"));
      } else if (a.status === "ready" && a.consented) {
        // Honest about the real behaviour: an attachment stays attached to the CHAT, and every answer in
        // it is given over everything attached. There used to be an "Include again" button here, which
        // implied a per-message choice the console does not have — the file went either way. Removing it
        // is the only thing that stops it, and that now really deletes it.
        bits.push(h("span.meta", { title: "Attached to this chat: every answer here is given over it. "
          + "Remove it to stop that." }, a.sent ? "· attached (sent)" : "· approved to send"));
      }
      bits.push(h("button.x", { "aria-label": "Remove " + a.name, title: "Remove from this chat (deletes it on the console)",
        disabled: a.status === "removing", onClick: function () { removeAttach(a); } }, "✕"));
      return h("span" + cls, null, bits);
    }

    function drawAttach() {
      const host = V.$("#chat-attach"); if (!host) return;
      if (!C.attach.length) { V.mount(host, null); return; }
      const notes = [];
      C.attach.forEach(function (a) {
        if (a.status === "failed") {
          notes.push(h("div.refusal", null, [
            h("b", null, a.name + " — this upload did not complete."), h("br"), a.err,
            a.refusals.length ? h("div", { style: { marginTop: "6px" } }, a.refusals.map(function (t) { return h("div", null, "• " + t); })) : null,
          ]));
        } else if (a.refusals.length) {
          notes.push(h("div.refusal", null, [
            h("b", null, a.name + " — the console refused part of this upload:"),
            h("div", { style: { marginTop: "6px" } }, a.refusals.map(function (t) { return h("div", null, "• " + t); })),
            h("div.dim", { style: { marginTop: "6px" } }, "Everything it accepted is still attached; the refused entries are not on this machine and will not be sent."),
          ]));
        }
      });
      V.mount(host, [
        h("div.chip-row", { style: { marginTop: "8px" } }, C.attach.map(attachChip)),
        notes.length ? h("div.stack", { style: { marginTop: "8px", gap: "8px" } }, notes) : null,
      ]);
    }

    // -- egress consent ------------------------------------------------------
    // The one place where material actually leaves the machine. It states the count, the bytes and the
    // list, names where it is going, and is answered once per attachment.
    function egressConsent(items) {
      return new Promise(function (resolve) {
        const bytes = items.reduce(function (n, a) { return n + (a.size || 0); }, 0);
        const count = items.reduce(function (n, a) { return n + (a.files != null ? a.files : 1); }, 0);
        const model = (C.st && (C.st.selected_model || C.st.model)) || "";
        const body = [
          h("p", null, "Sending this message copies the contents below off this machine to the model that answers this chat"
            + (model ? (" (" + model + ")") : "") + ". Nothing else on this machine is sent — not your other chats, not your findings, not your keys."),
          h("div.legend", { style: { marginTop: "10px" } }, [
            V.icon("info"),
            h("span", null, count + " file" + (count === 1 ? "" : "s") + " · " + fmtBytes(bytes) + " · " + items.length + " attachment" + (items.length === 1 ? "" : "s")),
          ]),
          h("div.stack", { style: { marginTop: "12px", gap: "10px" } }, items.map(function (a) {
            const lines = a.fileList.slice(0, 200);
            const hidden = Math.max(0, (a.files != null ? a.files : a.fileList.length) - lines.length) + (a.more || 0);
            return h("div", null, [
              h("div", null, [h("b", null, a.name), h("span.dim", null, "  " + fmtBytes(a.size)
                + (a.files != null ? ("  ·  " + a.files + " file" + (a.files === 1 ? "" : "s")) : "")
                + (a.sha256 ? ("  ·  sha256 " + a.sha256.slice(0, 12)) : ""))]),
              lines.length ? h("pre.code", { style: { maxHeight: "180px", overflowY: "auto", marginTop: "6px" } },
                lines.join("\n") + (hidden > 0 ? ("\n… and " + hidden + " more") : "")) : null,
              (!lines.length && a.files != null && a.files > 1)
                ? h("div.dim", { style: { marginTop: "4px" } }, "The console did not return a file list for this archive; the count above is what it extracted.") : null,
            ]);
          })),
          h("div.hint", { style: { marginTop: "12px" } },
            "What comes back is a LEAD — the model's reading of your files. It is not a finding. A finding "
            + "becomes a fact only when a deterministic oracle fires over real evidence, which is what the "
            + "gated scan does."),
        ];
        let done = false;
        const m = openModal("Send these files to the model?", body, [
          h("button.btn", { onClick: function () { done = true; m.close(); resolve(false); } }, "Cancel"),
          h("button.btn.primary", { onClick: function () { done = true; m.close(); resolve(true); } }, [V.icon("check"), "Send them"]),
        ], { onCancel: function () { if (!done) resolve(false); } });
      });
    }

    // -- linked histories ----------------------------------------------------
    // The chat id IS the session id, so the session connect/disconnect actions take a chat id verbatim.
    // Phase C: the hypothesis ledger. Open first (a lead badge), then confirmed (a green shield + the
    // finding that closed it) / refuted. Rendered only when there is something to show, so it never
    // clutters a fresh chat. An open hypothesis is a suspicion recorded from the conversation; it closes
    // itself when an oracle confirms a matching finding (server-side reconcile) — the loop CHAT-VISION
    // asks for: "the thing you suspected on Tuesday is now confirmed — here is the proof."
    function drawHyps() {
      const host = V.$("#chat-hyps"); if (!host) return;
      const hyps = C.hyps || [];
      if (!hyps.length) { V.clear(host); return; }
      // S9: render the live plan/hypothesis ledger as a Claude-Code-style CHECKLIST — a state icon per item
      // (✓ confirmed by a finding · ✗ refuted · ○ open) with a running progress count. Data is the same
      // engine-driven ledger (C.hyps); each item still closes only when an oracle confirms a matching finding.
      const done = hyps.filter(function (hp) { return String(hp.status || "open") === "confirmed"; }).length;
      const rows = hyps.map(function (hp) {
        const st = String(hp.status || "open");
        const chk = st === "confirmed" ? h("span.chk.chk-done", null, V.icon("check"))
          : st === "refuted" ? h("span.chk.chk-no", null, V.icon("x"))
            : h("span.chk.chk-open", null, V.icon("dot"));
        // "Confirmed by a finding" (not a bare FACT badge): the hypothesis is LINKED to a real
        // oracle-confirmed finding (shown by its ref below), it is not itself the minted fact (red-pen F3).
        const badge = st === "confirmed" ? h("span.shield", null, [V.icon("check"), "Confirmed by a finding"])
          : st === "refuted" ? h("span.pill.sm", null, "Refuted")
            : h("span.shield.lead", null, [V.icon("info"), "Open"]);
        const meta = [];
        if (hp.would_confirm) meta.push(h("div.dim", { style: { fontSize: "var(--fs-xs)" } }, "Confirm if: " + hp.would_confirm));
        if (hp.would_refute) meta.push(h("div.dim", { style: { fontSize: "var(--fs-xs)" } }, "Refute if: " + hp.would_refute));
        if (st === "confirmed" && hp.finding_ref) meta.push(h("div.dim", { style: { fontSize: "var(--fs-xs)" } }, "Closed by run: " + hp.finding_ref));
        return h("div.hyp-row.chk-row" + (st === "confirmed" ? ".is-done" : ""), null, [
          h("div", { style: { display: "flex", gap: "8px", alignItems: "baseline", flexWrap: "wrap" } },
            [chk, badge, h("span", null, String(hp.statement || ""))]),
        ].concat(meta));
      });
      V.mount(host, h("div.hyp-panel", null, [
        h("div.label", null, [h("span", null, "Plan · hypotheses"),
          h("span.chk-count", null, "  " + done + " / " + hyps.length + " confirmed")]),
        h("div.hint", { style: { marginBottom: "6px", fontSize: "var(--fs-xs)" } },
          "The live plan for this conversation — each item closes itself (✓) only when an oracle confirms a matching finding."),
      ].concat(rows)));
    }

    function drawLinks() {
      const host = V.$("#chat-links"); if (!host) return;
      if (!C.id) {
        V.mount(host, h("div.hint", { style: { marginTop: "8px" } },
          "Send a first message to create this chat — then you can link other chats into it for context."));
        return;
      }
      const row = rowOf(C.id);
      const conns = (row && row.connections) || [];
      const chips = conns.map(function (cid) {
        return h("span.chip", null, [
          V.icon("link"),
          h("span.nm", { title: cid }, titleOf(cid)),
          h("button.x", { "aria-label": "Disconnect " + titleOf(cid), title: "Disconnect", onClick: function () { doDisconnect(cid); } }, "✕"),
        ]);
      });
      V.mount(host, h("div", { style: { marginTop: "10px", padding: "10px 12px", border: "1px solid var(--border)", borderRadius: "var(--r-2)", background: "var(--bg-1)" } }, [
        h("div.chip-row", null, [
          h("span.label", null, "Draws on"),
          conns.length ? null : h("span.dim", null, "nothing yet — this chat answers from its own history only"),
        ].concat(chips).concat([
          h("button.btn.sm", { onClick: openLinkPicker }, [V.icon("link"), "Link another chat"]),
        ])),
        h("div.hint", { style: { marginTop: "8px" } },
          conns.length
            ? "This chat draws on the chats above: their history is available as extra context when it answers. It is one-way — they do not draw on this one — and linking copies nothing, so disconnecting takes effect immediately."
            : "Linking is one-way and copies nothing: this chat would draw on the other's history as extra context, the other would not see this one, and disconnecting takes effect immediately."),
      ]));
    }

    function openLinkPicker() {
      if (!C.id) return;
      const row = rowOf(C.id);
      const linked = {};
      ((row && row.connections) || []).forEach(function (cid) { linked[cid] = 1; });
      const candidates = C.sessions.filter(function (s) { return s.id !== C.id && !linked[s.id]; });
      const listHost = h("div.stack", { style: { gap: "6px", marginTop: "10px" } });
      const filter = h("input.input", { type: "text", placeholder: "Filter by name or id…", style: { width: "100%" } });
      let m = null;
      function draw() {
        const q = (filter.value || "").trim().toLowerCase();
        const rows = candidates.filter(function (s) {
          if (!q) return true;
          return (titleOf(s.id) + " " + s.id).toLowerCase().indexOf(q) !== -1;
        }).slice(0, 200);
        V.mount(listHost, rows.length ? rows.map(function (s) {
          const turns = turnsOf(s.id);
          return h("button.picker-row", { onClick: function () { if (m) m.close(); doConnect(s.id); } }, [
            V.icon("live"),
            h("span.pn", { title: s.id }, titleOf(s.id)),
            h("span.dim", { style: { fontSize: "var(--fs-xs)" } },
              (turns != null ? turns + " turn" + (turns === 1 ? "" : "s") + " · " : "") + s.id),
          ]);
        }) : h("div.empty", null, candidates.length ? "No chat matches that filter." : "No other chats to link yet."));
      }
      filter.addEventListener("input", draw);
      draw();
      m = openModal("Link another chat into this one", [
        h("p", null, "Pick a chat for this one to DRAW ON. Its history becomes available as extra context when this chat answers."),
        h("div.hint", { style: { margin: "8px 0 4px" } },
          "One-way: the other chat is not changed and does not see this one. Nothing is copied — it is a read-time scope, so you can disconnect at any moment and this chat is isolated again on its very next answer."),
        filter,
        listHost,
      ], [h("button.btn", { onClick: function () { if (m) m.close(); } }, "Cancel")]);
    }

    function doConnect(otherId) {
      V.postJSON(OFF("/api/session/connect"), { id: C.id, other: otherId }).then(function (d) {
        if (d && d.error) { V.toast(d.error, true); return; }
        V.toast("Linked — this chat now draws on " + titleOf(otherId));
        return loadChatList().then(function () { drawLinks(); drawSessions(); });
      }).catch(function (e) { V.toast((e && e.message) || String(e), true); });
    }

    function doDisconnect(otherId) {
      V.postJSON(OFF("/api/session/disconnect"), { id: C.id, other: otherId }).then(function (d) {
        if (d && d.error) { V.toast(d.error, true); return; }
        V.toast("Disconnected — takes effect immediately (nothing was ever copied)");
        return loadChatList().then(function () { drawLinks(); drawSessions(); });
      }).catch(function (e) { V.toast((e && e.message) || String(e), true); });
    }

    // -- transcript ----------------------------------------------------------
    function scanTargetOf(m) {
      // Only an EXPLICIT "here is where the extracted material lives" field counts. A stray `path` on
      // some other record must not conjure a scan button pointed at an unrelated directory.
      const t = m && (m.scan_target || m.extract_path || m.upload_path
        || (m.attachment && (m.attachment.path || m.attachment.root)));
      return t ? String(t) : "";
    }
    function recordAttachments(m) {
      const list = (m && (m.attachments || m.files)) || [];
      if (!Array.isArray(list) || !list.length) return null;
      return h("div.chip-row", { style: { marginTop: "8px" } }, list.slice(0, CHAT_MAX_ATTACH).map(function (a) {
        const nm = String((a && (a.name || a.id)) || a);
        const sz = a && a.size != null ? fmtBytes(a.size) : "";
        const cnt = a && (a.files != null ? a.files : a.file_count);
        return h("span.chip", null, [
          h("span.nm", { title: nm }, nm),
          sz ? h("span.meta", null, sz) : null,
          cnt != null ? h("span.meta", null, "· " + cnt + " file" + (Number(cnt) === 1 ? "" : "s")) : null,
        ]);
      }));
    }

    // S2: click-to-pick suggested answers for an agent question, with an "Other → type your own" escape
    // hatch. A pick just fills the composer and sends it — the SAME reply path that auto-resumes the run
    // (no new endpoint, no relaxed gate). Rendered only on the PENDING question.
    function answerOptions(opts) {
      const btns = (opts || []).map(function (opt) {
        return h("button.btn.sm", { onClick: function () { input.value = String(opt); doSend(); } }, String(opt));
      });
      btns.push(h("button.btn.sm.ghost", { title: "Type your own answer in the composer below",
        onClick: function () { try { input.focus(); input.scrollIntoView({ block: "center" }); } catch (e) {} } },
        [V.icon("edit"), "Other…"]));
      return h("div.answer-options", null, btns);
    }
    function bubble(m, i, arr) {
      const isPendingQ = m.kind === "agent_question" && arr && i === arr.length - 1;
      const isUser = m.role === "user";
      const wrap = { style: { display: "flex", justifyContent: isUser ? "flex-end" : "flex-start", margin: "8px 0" } };
      const box = {
        style: {
          maxWidth: "80%", padding: "10px 12px", borderRadius: "var(--r-3)",
          background: isUser ? "var(--primary-bg)" : "var(--bg-2)",
          color: isUser ? "var(--primary-fg)" : "var(--text-0)",
          border: "1px solid var(--border)", whiteSpace: "pre-wrap", wordBreak: "break-word",
        },
      };
      // A model-authored answer is a LEAD. Say so on the message itself, not only in a footnote.
      const isLead = !isUser && !CHAT_ENGINE_KINDS[String(m.kind || "")];
      const kids = [];
      if (isLead) {
        kids.push(h("div", { style: { marginBottom: "6px" } },
          [h("span.shield.lead", null, [V.icon("info"), "Lead — not a confirmed finding"])]));
      }
      // AGENT ASK_USER: the engagement paused to ask the operator something. Render it as a distinct,
      // owner-gold prompt (not a lead) so it's unmistakable that a reply is expected — typing an answer in
      // the composer below auto-resumes the run (server-side resume_engage_with_message). Styled + labelled
      // so the operator knows exactly where to answer.
      if (m.kind === "agent_question") {
        box.style.borderColor = "var(--owner, #d4af37)";
        box.style.borderLeftWidth = "3px";
        box.style.background = "var(--owner-bg, var(--bg-2))";
        kids.push(h("div", { style: { marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" } },
          [h("span.shield", { style: { color: "var(--owner, #d4af37)" } }, [V.icon("info"), "The engagement is asking you"])]));
        kids.push(h("div", null, String(m.text || m.reply || "")));
        // click-to-pick options on the PENDING question (a historical one just shows its text).
        if (isPendingQ && Array.isArray(m.options) && m.options.length) kids.push(answerOptions(m.options));
        kids.push(h("div.dim", { style: { fontSize: "var(--fs-xs)", marginTop: "8px" } },
          (isPendingQ && m.options && m.options.length)
            ? "Pick an answer above, or type your own below — I'll resume the engagement with it."
            : "Reply below and I'll resume the engagement with your answer."));
        return h("div", wrap, h("div", box, kids));
      }
      // AWAITING APPROVAL (Wave 8): the engagement paused because its next step needs a SIGNED owner
      // approval. Surface it IN the transcript (not only the floating process box), styled amber so a
      // blocked run never reads as idle. The interactive Approve / Deny / Deny & redirect live in the
      // process box below (owner key stays sovereign-side); a reply here steers + resumes.
      if (m.kind === "approval_rejected") {
        // ENH1: the operator DID approve, but the approval expired or was already used, so it couldn't be
        // spent. A DISTINCT red register (vs awaiting's amber) + "approve again" copy, so a recoverable
        // state never reads as the same "awaiting your first approval" invisible loop. Placed BEFORE the
        // isLead markdown push with an early return (mirrors awaiting_approval; isLead falls through).
        box.style.borderColor = "var(--st-deny, #d9534f)";
        box.style.borderLeftWidth = "3px";
        kids.push(h("div", { style: { marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" } },
          [h("span.shield", { style: { color: "var(--st-deny, #d9534f)" } },
            [V.icon("key"), "Paused — your last approval expired or was already used"])]));
        kids.push(h("div", null, String(m.text || "")));
        kids.push(h("div.dim", { style: { fontSize: "var(--fs-xs)", marginTop: "8px" } },
          "Approve it AGAIN in the process box (Approve / Deny / Deny & redirect), or reply here to steer me — then I continue."));
        return h("div", wrap, h("div", box, kids));
      }
      if (m.kind === "awaiting_approval") {
        box.style.borderColor = "var(--st-queued, #d4af37)";
        box.style.borderLeftWidth = "3px";
        kids.push(h("div", { style: { marginBottom: "6px", display: "flex", alignItems: "center", gap: "6px" } },
          [h("span.shield", { style: { color: "var(--st-queued, #d4af37)" } },
            [V.icon("key"), "Paused — awaiting your approval"])]));
        kids.push(h("div", null, String(m.text || "")));
        kids.push(h("div.dim", { style: { fontSize: "var(--fs-xs)", marginTop: "8px" } },
          "Approve it in the process box (Approve / Deny / Deny & redirect), or reply here to steer me — then I continue."));
        return h("div", wrap, h("div", box, kids));
      }
      // S10: assistant replies render as SAFE markdown (code/bold/lists/links); user messages stay literal.
      kids.push(isLead
        ? h("div.md", null, renderMarkdown(m.text || m.reply || ""))
        : h("div", { style: { whiteSpace: "pre-wrap", wordBreak: "break-word" } }, String(m.text || m.reply || "")));
      const atts = recordAttachments(m);
      if (atts) kids.push(atts);
      // GROUNDED-IN legend (A2): the VERIFIED sources this lead drew on, in visibly distinct registers —
      // attached code vs a linked chat. Everything uncited is the model's own inference (the Lead badge
      // above). "Evidence" is never rendered here: chat mints no facts, so this can never wear the green
      // confirmed-finding register.
      const srcs = (!isUser && Array.isArray(m.sources)) ? m.sources : [];
      if (srcs.length) {
        kids.push(h("div.chat-srcs", null, [
          h("span.chat-srcs-lbl", null, "Grounded in"),
          h("span.chat-src-row", null, srcs.map(function (s) { return sourceChip(s); })),
        ]));
      }
      if (m.kind === "launched" && m.run_id) {
        // A5: surface the run's LIVE STEPS without leaving the chat. "Show live steps" focuses the
        // persistent process box on THIS run and reveals it — reusing the tested, redraw-safe SSE feed
        // (its EventSource lives outside the transcript, so it survives every chat redraw). "Open live
        // view" is the full-screen route for when the operator wants the whole timeline + graph.
        kids.push(h("div", { style: { marginTop: "8px", display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" } }, [
          h("button.btn.sm.primary", { onClick: function () { chatShowSteps(m); } }, [V.icon("live"), "Show live steps"]),
          h("button.btn.sm", { onClick: function () { location.hash = "#/live?run=" + encodeURIComponent(m.run_id); } }, [V.icon("book"), "Open live view"]),
          m.slug ? h("span.pill.sm", null, m.slug) : null,
        ]));
        // B1: steer a RUNNING agentic engagement mid-flight. Only the integration engine consumes
        // operator messages (the scanner has no such seam), so the affordance appears only for it — an
        // honest control, never a dead one. The message is advisory: the engine folds it into its next
        // think; it re-runs no completed tool and fires nothing ungated.
        if (m.engine === "integration" && m.slug) {
          var steer = h("input.input", { type: "text", placeholder: "Add a message to this run… (e.g. also check the password-reset flow)",
            style: { flex: "1 1 auto", minWidth: "0" } });
          function sendSteer() { injectIntoRun(String(m.slug), steer); }
          steer.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); sendSteer(); } });
          kids.push(h("div", { style: { marginTop: "8px", display: "flex", gap: "8px", alignItems: "center" } }, [
            steer, h("button.btn.sm", { onClick: sendSteer }, [V.icon("play"), "Send to the run"]),
          ]));
        }
      }
      // D2b: when this run is over a codebase THIS chat cloned, offer the gated dev-mode affordances —
      // propose an edit (reviewed as a diff, applied only on the operator's click), and run its tests in
      // the no-net sandbox. The panel appears only for a launched CODEBASE run that carries a path; the
      // path is re-confined server-side on every call, so the client never becomes an authority on it.
      if (m.kind === "launched" && m.mode === "codebase" && m.codebase_path && m.run_id) {
        kids.push(codebasePanel(m));
      }
      const scanPath = isLead ? scanTargetOf(m) : "";
      if (scanPath) {
        // The reply read an extracted codebase. Offer the REAL thing on the same files: a gated run,
        // whose findings an oracle either confirms or does not.
        kids.push(h("div", { style: { marginTop: "10px", paddingTop: "10px", borderTop: "1px solid var(--border)" } }, [
          h("div.dim", { style: { fontSize: "var(--fs-xs)", marginBottom: "6px" } },
            "Everything above is the model reading " + scanPath + ". To turn any of it into a finding, scan the same files:"),
          h("button.btn.sm.primary", { onClick: function () { launchScan(scanPath); } }, [V.icon("bolt"), "Run the gated scan on these files"]),
        ]));
      }
      // PROPOSE-GATED-ACTIONS (A1): the model may suggest a few next steps as clickable chips. They are
      // inert — a click routes through the same gated launcher / navigation as everywhere else. Rendered
      // for assistant records only, and de-duplicated against the scan-offer button above so a codebase
      // scan is never shown twice.
      const props = (!isUser && Array.isArray(m.proposals)) ? m.proposals : [];
      const shownProps = props.filter(function (p) {
        return !(p && p.action === "scan_codebase" && scanPath && String(p.target || "") === scanPath);
      });
      if (shownProps.length) {
        kids.push(h("div.chat-props", { style: { marginTop: "10px" } }, [
          h("div.dim", { style: { fontSize: "var(--fs-xs)", marginBottom: "6px" } }, "Suggested next steps — you choose:"),
          h("div.chat-prop-row", null, shownProps.map(function (p) { return proposalChip(p); })),
        ]));
      }
      if (m.kind === "refused" || m.kind === "error") { box.style.borderColor = "var(--sev-high, #e5a13a)"; }
      // S3: per-message actions (copy / edit-&-resend / regenerate) on plain text bubbles — a hover row like
      // Claude Code. Copy reuses copyText; Edit repopulates the composer for the operator to tweak + send;
      // Regenerate re-sends the preceding user turn. All go through the normal send path (no new endpoint).
      if (isUser || isLead) {
        const text = String(m.text || m.reply || "");
        const acts = [h("button.msg-act", { title: "Copy this message", onClick: function () { copyText(text); } }, [V.icon("clip"), "Copy"])];
        if (isUser) {
          acts.push(h("button.msg-act", { title: "Put this back in the composer to edit and resend",
            onClick: function () { input.value = text; try { input.focus(); input.scrollIntoView({ block: "center" }); } catch (e) {} } }, [V.icon("edit"), "Edit & resend"]));
        }
        if (isLead) {
          acts.push(h("button.msg-act", { title: "Re-run the question that produced this reply",
            onClick: function () {
              var prev = ""; for (var j = (i || 0) - 1; j >= 0; j--) { if (arr[j] && arr[j].role === "user") { prev = String(arr[j].text || ""); break; } }
              if (prev) { input.value = prev; doSend(); } else { V.toast("No earlier message to regenerate from.", true); }
            } }, [V.icon("live"), "Regenerate"]));
        }
        kids.push(h("div.msg-actions", null, acts));
      }
      return h("div", wrap, h("div", box, kids));
    }

    // One "grounded in" source chip (A2). A verified attachment or a linked chat, each in its own
    // register — deliberately NOT the green confirmed-finding shield, because a chat answer is a lead.
    function sourceChip(s) {
      const kind = s && String(s.kind || "");
      const ref = String((s && s.ref) || "");
      const note = String((s && s.note) || "");
      if (kind === "attached") {
        return h("span.chat-src.src-attached", { title: note || ref }, [V.icon("clip"), h("span.rf", null, ref)]);
      }
      if (kind === "linked") {
        return h("span.chat-src.src-linked", { title: note || ("chat " + ref) }, [V.icon("link"), h("span.rf", null, ref)]);
      }
      return null;
    }

    // One suggested-action chip. Inert until clicked; the click runs the SAME gated path a hand-run uses
    // (launch_assessment for a scan, navigation for a screen). The model proposed it; the operator's
    // click, through the gate, is the only thing that acts.
    function proposalChip(p) {
      const action = p && String(p.action || "");
      const label = String((p && p.label) || "Do this");
      const why = String((p && p.why) || "");
      let onClick = null;
      let icon = "bolt";
      if (action === "scan_codebase") { onClick = function () { launchScan(String(p.target || "")); }; }
      else if (action === "scan_sast") { icon = "assess"; onClick = function () { launchSast(String(p.target || "")); }; }
      else if (action === "scan_url") { icon = "live"; onClick = function () { launchUrlScan(String(p.target || "")); }; }
      else if (action === "open_screen") {
        icon = "book";
        onClick = function () { location.hash = "#/" + String(p.screen || ""); };
      }
      if (!onClick) return null;
      return h("button.chat-prop", { onClick: onClick, title: why || label, disabled: C.busy ? "disabled" : null },
        [V.icon(icon), h("span.pl", null, label)]);
    }

    // A5: focus the persistent process box on THIS chat-launched run and reveal it, so the operator
    // sees the ongoing steps (with the same lead/fact + blocked/failed/network tagging the box already
    // does) without leaving the conversation. Reuses pboxFollow — the EventSource lives outside the
    // transcript (PBOX.es, never liveES), so it is not churned by chat redraws; the box's own poll
    // reconciles the run's final status. A run with no live spine (stream:"none") still shows its status.
    function chatShowSteps(m) {
      var runId = String((m && m.run_id) || "");
      if (!runId) return;
      var run = { run_id: runId, slug: String((m && m.slug) || ""),
                  stream: String((m && m.stream) || ""), status: "running" };
      PBOX.ui.open = true; PBOX.ui.dismissed = false; pboxSaveUI();
      pboxFollow(run);
    }

    // B1: add a message to a running engagement. Advisory mid-run steering — the engine folds it into its
    // next think (it re-runs no completed tool, relaxes no scope, fires nothing ungated). Only offered for
    // the integration engine, which is the one that drains this queue.
    function injectIntoRun(slug, inputEl) {
      var text = ((inputEl && inputEl.value) || "").trim();
      if (!slug || !text) return;
      V.postJSON(OFF("/api/instruct"), { slug: slug, text: text }).then(function (r) {
        if (r && r.ok) {
          // HONEST about delivery (red-pen BLOCK-1): only claim "steers" when a run is actually alive to
          // drain it; otherwise say it's queued and will apply on resume.
          V.toast(r.running
            ? "Sent to the run — it steers on its next step."
            : "Queued — this run isn't active right now, so it'll be applied only if you resume it.", false);
          if (inputEl) inputEl.value = "";
        } else {
          V.toast((r && r.error) || "Could not send the message to the run.", true);
        }
      }).catch(function (e) { V.toast((e && e.message) || "Could not reach the run — is the offense console up?", true); });
    }

    // D2b — the dev-mode codebase panel on a launched CODEBASE bubble: propose an edit (reviewed as a
    // diff), apply it (the operator's click IS the approval), and run tests in the no-net sandbox. Every
    // call re-confines the path server-side; nothing here can touch a directory this chat did not clone.
    function codebasePanel(m) {
      const runId = String(m.run_id || "");
      const st = C.codebase[runId] || (C.codebase[runId] = { busy: "", diff: "", test: null });
      const path = String(m.codebase_path || "");
      // display the tail relative to the per-chat clone base, but the FULL path is what is sent (and
      // re-confined server-side); the title carries the whole path for the curious.
      const shortPath = path.replace(/^.*\/clones\/[^/]+\//, "") || path;
      const kids = [
        h("div.cb-head", null, [V.icon("book"), h("span", null, "Work on this cloned codebase"),
          h("span.cb-path", { title: path }, shortPath)]),
        h("div.dim", { style: { fontSize: "var(--fs-xs)", margin: "2px 0 8px" } },
          "Dev-mode edits and tests act on the repo this chat cloned. A diff is a proposal you approve by "
          + "clicking Apply; a passing test is a lead, never an oracle-confirmed fact."),
      ];
      // Propose-an-edit
      const instr = h("input.input", { type: "text",
        placeholder: "Describe the change… (e.g. fix the off-by-one in utils/pagination.py)",
        style: { flex: "1 1 auto", minWidth: "0" } });
      function doPropose() { cbProposeEdit(m, instr); }
      instr.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); doPropose(); } });
      kids.push(h("div.cb-row", null, [instr,
        h("button.btn.sm.primary", { onClick: doPropose, disabled: st.busy ? "disabled" : null },
          [V.icon("bolt"), st.busy === "edit" ? "Proposing…" : "Propose an edit"])]));
      // The proposed diff (if any) + review/apply/discard
      if (st.diff) {
        kids.push(h("div", { style: { marginTop: "8px" } },
          h("span.shield.lead", null, [V.icon("info"), "Proposed change — review before applying"])));
        kids.push(diffView(st.diff));
        kids.push(h("div.cb-row", null, [
          h("button.btn.sm.primary", { onClick: function () { cbApplyEdit(m); }, disabled: st.busy ? "disabled" : null },
            [V.icon("check"), st.busy === "apply" ? "Applying…" : "Apply this diff"]),
          h("button.btn.sm", { onClick: function () { st.diff = ""; drawMain(); } }, [V.icon("x"), "Discard"]),
        ]));
      }
      // Run tests (no-net sandbox)
      const cmd = h("input.input", { type: "text", value: "pytest -q", placeholder: "pytest -q",
        style: { flex: "1 1 auto", minWidth: "0" } });
      function doTest() { cbRunTests(m, cmd); }
      cmd.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); doTest(); } });
      kids.push(h("div.cb-row", null, [cmd,
        h("button.btn.sm", { onClick: doTest, disabled: st.busy ? "disabled" : null },
          [V.icon("play"), st.busy === "test" ? "Running…" : "Run tests (no-net sandbox)"])]));
      if (st.test) kids.push(testResultView(st.test));
      return h("div.chat-cb", { style: { marginTop: "10px", paddingTop: "10px", borderTop: "1px solid var(--border)" } }, kids);
    }

    // Render a unified diff, add/remove/hunk-coloured. XSS-SAFE BY CONSTRUCTION: every line becomes a
    // text node (h() with a string child sets textContent, never innerHTML), so diff content — which comes
    // from a cloned repo + the model — can never inject markup. Wide lines scroll inside the box; the page
    // body never scrolls sideways.
    function diffView(diffText) {
      const lines = String(diffText || "").split("\n");
      const rows = lines.map(function (ln) {
        let cls = "diff-ctx";
        if (ln.indexOf("+++ ") === 0 || ln.indexOf("--- ") === 0 || ln.indexOf("diff --git") === 0) cls = "diff-file";
        else if (ln.indexOf("@@") === 0) cls = "diff-hunk";
        else if (ln.charAt(0) === "+") cls = "diff-add";
        else if (ln.charAt(0) === "-") cls = "diff-del";
        return h("div.diff-line." + cls, null, ln === "" ? " " : ln);
      });
      return h("pre.chat-diff", null, rows);
    }

    // A test run's result — a LEAD. Green frame on pass, amber on fail, but never the confirmed-finding
    // shield: a passing test is not an oracle FACT, and this says so.
    function testResultView(t) {
      const passed = !!(t && t.passed);
      const rc = (t && typeof t.rc === "number") ? t.rc : null;
      const head = h("div", { style: { marginBottom: "4px" } }, [
        h("span.shield.lead", null, [V.icon("info"),
          passed ? "Tests passed (a lead — not an oracle-confirmed fact)"
                 : "Tests failed" + (rc !== null ? " (exit " + rc + ")" : "")]),
      ]);
      const kids = [head];
      const out = String((t && t.output) || "").slice(-4000);
      if (out) kids.push(h("pre.chat-diff", { style: { borderColor: passed ? "var(--sev-low, #3a9)" : "var(--sev-high, #e5a13a)" } },
        h("div.diff-line.diff-ctx", null, out)));
      return h("div", { style: { marginTop: "8px" } }, kids);
    }

    // Propose a dev-mode edit → a unified diff for review (D2). The path rides the record and is
    // re-confined server-side; a store hiccup or refusal is reported honestly, never as a silent success.
    function cbProposeEdit(m, instrEl) {
      const runId = String(m.run_id || "");
      const st = C.codebase[runId] || (C.codebase[runId] = { busy: "", diff: "", test: null });
      const instruction = ((instrEl && instrEl.value) || "").trim();
      if (st.busy || !instruction) return;
      st.busy = "edit"; drawMain();
      V.postJSON(OFF("/api/codebase/edit"), { chat_id: C.id || "", path: String(m.codebase_path || ""), instruction: instruction })
        .then(function (r) {
          st.busy = "";
          if (r && r.ok && r.diff) { st.diff = String(r.diff); if (instrEl) instrEl.value = ""; }
          else { V.toast((r && r.error) || "No change was proposed.", true); }
        })
        .catch(function (e) { st.busy = ""; V.toast((e && e.message) || "Could not reach the codebase tool.", true); })
        .then(function () { drawMain(); });
    }

    // Apply the reviewed diff (D2). Gated A2 code_edit; the operator's click is the human-approval leg.
    // git-apply is clone-only, so a rename/symlink in the diff cannot escape the confined workdir.
    function cbApplyEdit(m) {
      const runId = String(m.run_id || "");
      const st = C.codebase[runId]; if (!st || !st.diff || st.busy) return;
      st.busy = "apply"; drawMain();
      V.postJSON(OFF("/api/codebase/apply"), { chat_id: C.id || "", path: String(m.codebase_path || ""), diff: st.diff })
        .then(function (r) {
          st.busy = "";
          if (r && r.ok) { st.diff = ""; V.toast("Applied to the cloned repo. Run the tests to check it.", false); }
          else { V.toast((r && r.error) || "The diff did not apply.", true); }
        })
        .catch(function (e) { st.busy = ""; V.toast((e && e.message) || "Could not reach the codebase tool.", true); })
        .then(function () { drawMain(); });
    }

    // Run the repo's tests in the no-net sandbox (D3). A3-gated; the operator's click is the approval. The
    // result is a LEAD — a passing test is not an oracle-confirmed fact — and testResultView says so.
    function cbRunTests(m, cmdEl) {
      const runId = String(m.run_id || "");
      const st = C.codebase[runId] || (C.codebase[runId] = { busy: "", diff: "", test: null });
      const command = ((cmdEl && cmdEl.value) || "").trim() || "pytest -q";
      if (st.busy) return;
      st.busy = "test"; st.test = null; drawMain();
      V.postJSON(OFF("/api/codebase/test"), { chat_id: C.id || "", path: String(m.codebase_path || ""), command: command })
        .then(function (r) {
          st.busy = "";
          if (r && r.ok) {
            // D3 returns {passed, exit_code, stdout, stderr}. Show both streams; stderr carries pytest's
            // failure summary. A passing test is a LEAD — testResultView says so.
            const body = [String(r.stdout || ""), String(r.stderr || "")].filter(Boolean).join("\n");
            st.test = { passed: !!r.passed, rc: (typeof r.exit_code === "number" ? r.exit_code : null), output: body };
          } else { V.toast((r && r.error) || "The test run was refused or could not start.", true); }
        })
        .catch(function (e) { st.busy = ""; V.toast((e && e.message) || "Could not reach the sandbox.", true); })
        .then(function () { drawMain(); });
    }

    // The gated web/API launcher for a proposed URL scan — the same launch_assessment path, url mode.
    // Scope is charter-signed; target-touching steps still wait for approval.
    function launchUrlScan(url) {
      if (C.busy || !url) return;
      C.busy = true;
      V.postJSON(OFF("/api/chat/send"), {
        chat_id: C.id || undefined,
        message: "Run the gated assessment against " + url,
        target: url, mode: "url",
      }).then(function (r) {
        if (r && r.error && !r.reply) V.toast(r.error, true);
        if (r && r.run_id && r.slug) setEngagement(String(r.slug));
        if (r && r.chat_id) adoptChatId(String(r.chat_id));
        return refreshTranscript();
      }).catch(function (e) { V.toast((e && e.message) || "Could not start the scan — is the offense console up?", true); })
        .then(function () { C.busy = false; loadChatList().then(function () { drawSessions(); drawMain(); scrollDown(); }); });
    }

    // The same gated launcher every other entry point uses — scope charter-signed, target-touching steps
    // held for approval. The chat only ASKS for it; it cannot widen scope or skip a gate.
    function launchSast(path) {
      // Native source review (framework.v2 analysis review — DAA static analysis + per-finding confirm/
      // refute). Distinct from launchScan (the vendored Strix codebase mode); mode:"sast", no Docker.
      if (C.busy || !path) return;
      C.busy = true;
      V.postJSON(OFF("/api/chat/send"), {
        chat_id: C.id || undefined,
        message: "Run the native source review (static analysis + confirm/refute) over the files at " + path,
        target: path, mode: "sast",
      }).then(function (r) {
        if (r && r.error && !r.reply) V.toast(r.error, true);
        if (r && r.run_id && r.slug) setEngagement(String(r.slug));
        if (r && r.chat_id) adoptChatId(String(r.chat_id));
        return refreshTranscript();
      }).catch(function (e) { V.toast((e && e.message) || "Could not start the source review — is the offense console up?", true); })
        .then(function () { C.busy = false; loadChatList().then(function () { drawSessions(); drawMain(); scrollDown(); }); });
    }

    function launchScan(path) {
      if (C.busy || !path) return;
      C.busy = true;
      V.postJSON(OFF("/api/chat/send"), {
        chat_id: C.id || undefined,
        message: "Run the gated assessment over the uploaded files at " + path,
        target: path, mode: "codebase",
      }).then(function (r) {
        if (r && r.error && !r.reply) V.toast(r.error, true);
        if (r && r.run_id && r.slug) setEngagement(String(r.slug));
        if (r && r.chat_id) adoptChatId(String(r.chat_id));
        return refreshTranscript();
      }).catch(function (e) { V.toast((e && e.message) || "Could not start the scan — is the offense console up?", true); })
        .then(function () { C.busy = false; loadChatList().then(function () { drawSessions(); drawMain(); scrollDown(); }); });
    }

    function drawMain() {
      const host = V.$("#chat-main"); if (!host) return;
      const st = C.st || {};
      // A PENDING engagement question = the transcript's LAST message is an unanswered agent_question. When
      // present we pin a banner above the transcript and steer the operator to the ONE composer where the
      // answer goes (a reply auto-resumes the paused run) — so the question can never scroll out of view.
      const _pendingQ = (C.messages.length && C.messages[C.messages.length - 1].kind === "agent_question")
        ? C.messages[C.messages.length - 1] : null;
      // THESE controls are SYSTEM-WIDE: they set the model + effort the ENGINE reasons with (engagements,
      // scans, the codebase agent) via the SAME owner-plane actions the Settings screen posts
      // (`set_model` / `set_effort`), effective on the engine's next `vigil up`. They are DISTINCT from the
      // per-session model picker in the composer below (E3), which chooses the model that answers THIS
      // conversation — immediately, with sovereignty (a local pick keeps everything on this machine). So a
      // reply here now comes from the per-session pick when set (else the console default); these buttons
      // change the ENGINE's model, not this chat's answer. Named for what they change, and kept separate.
      const modelSel = h("select.input", { style: { minWidth: "160px" } },
        (st.models || []).map(function (m) {
          const o = h("option", { value: m.id }, m.label || m.id);
          if (m.id === st.selected_model) o.selected = true; return o;
        }));
      const effortSel = h("select.input", { style: { minWidth: "130px" } },
        [h("option", { value: "" }, "Effort: default")].concat((st.effort_levels || ["low", "medium", "high", "xhigh", "max"]).map(function (lv) {
          const o = h("option", { value: lv }, "Effort: " + lv); if (lv === st.selected_effort) o.selected = true; return o;
        })));
      const controls = st.models ? h("div.chat-sysctl", null, [
        h("div.hint.wide", null, "System-wide settings, not this chat. These are the same controls as Settings: "
          + "they set the model and effort the ENGINE reasons with (engagements, scans, the codebase agent) "
          + "and take effect on its next `vigil up`. To choose the model that answers THIS conversation "
          + "(immediately, with sovereignty — a local model keeps everything on this machine), use the model "
          + "picker in the composer below."),
        modelSel,
        h("button.btn.sm.owner", { onClick: function () { settingsAct({ action: "set_model", model: modelSel.value, reason: "set model from Chat" }, "System model set — effective on the next `vigil up`.", load); } }, "Set system model"),
        effortSel,
        h("button.btn.sm.owner", { onClick: function () { settingsAct({ action: "set_effort", effort: effortSel.value, reason: "set effort from Chat" }, "System effort set — effective on the next `vigil up`.", load); } }, "Set system effort"),
      ]) : h("div.hint", { style: { marginBottom: "8px" } }, "The system-wide model & effort controls need the owner plane (start with `vigil up`).");

      const list = h("div#chat-list.dropzone.chat-transcript", null,
        C.messages.length ? C.messages.map(bubble)
          : h("div.empty.chat-empty", null, [h("div.big", null, "What should we test?"),
              h("p", null, "Ask in plain language — e.g. “scan http://127.0.0.1:8080 for auth bugs” — or drop a zip, files or screenshots and ask about them. Type “/” for commands or “@” to reference an attachment.")]));

      // drag-and-drop onto the transcript. The counter survives the dragleave that fires when the
      // pointer crosses a CHILD element, which is why a bare boolean flickers here.
      list.addEventListener("dragenter", function (e) {
        e.preventDefault(); C.dragDepth += 1; list.classList.add("over");
      });
      list.addEventListener("dragover", function (e) { e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = "copy"; });
      list.addEventListener("dragleave", function () { C.dragDepth = Math.max(0, C.dragDepth - 1); if (!C.dragDepth) list.classList.remove("over"); });
      list.addEventListener("drop", function (e) {
        e.preventDefault(); C.dragDepth = 0; list.classList.remove("over");
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
      });

      const fileInput = h("input", { type: "file", multiple: true, style: { display: "none" },
        onChange: function (e) { addFiles(e.target.files); e.target.value = ""; } });
      const attachBtn = h("button.btn", { title: "Attach a zip, files or images to this message", onClick: function () { fileInput.click(); } },
        [V.icon("clip"), "Attach"]);

      const input = h("textarea.input", { rows: "2", placeholder: "Ask about the attached files, or tell the agent what to test… (Enter to send, Shift+Enter for a new line)",
        style: { resize: "vertical", flex: "1 1 auto", minWidth: "0" } });
      const target = h("input.input", { type: "text", placeholder: "target (optional): URL or codebase path", style: { flex: "1 1 auto", minWidth: "0" } });
      const modeSel = h("select.input", null, [["", "auto"], ["url", "url / API / infra"], ["codebase", "codebase"], ["suite", "suite (autonomous)"], ["tool", "one tool (pick it)"]].map(function (p) {
        const o = h("option", { value: p[0] }, p[1]); if (p[0] === C.mode) o.selected = true; return o;
      }));
      // "one tool" USED TO RUN NO TOOL. The mode was sent on its own, and `chat_send` forwards a `tools`
      // array the composer never filled, so the launcher added no capability flag and started an ordinary
      // engagement — the operator asked for a single tool and got the default run. The picker below is the
      // same roster the wizard uses; sending its capability id is what makes the mode mean anything.
      const pickable = (C.profiles || []).filter(function (p) { return toolPickable(p).ok; });
      const toolSel = h("select.input", { style: { minWidth: "220px" } },
        [h("option", { value: "" }, pickable.length ? "— pick the tool —"
          : (C.profilesErr ? "— tool roster unavailable —" : "— no tool can be started from here —"))]
          .concat(pickable.map(function (p) {
            const o = h("option", { value: p.name }, p.name + " — via the " + capLabelOf(C.caps, toolPickable(p).cap) + " capability");
            if (p.name === C.tool) o.selected = true; return o;
          })));
      toolSel.addEventListener("change", function () { C.tool = toolSel.value; });
      const toolRow = h("div.chat-toolrow", { style: { display: "none" } }, [
        toolSel,
        h("span.hint", null, pickable.length
          ? "This host's real tools. Only the ones a gated engagement can actually drive are listed — the Tools screen shows the whole roster and what drives the rest."
          : (C.profilesErr
            ? "The offense engine could not probe this host's tools. Start it (`vigil up`) and reopen this chat."
            : "No tool on this host can be started from a chat turn right now. Use “url / API / infra” instead, or the Tools screen.")),
      ]);
      // C.mode is the source of truth, not the <select>: a redraw rebuilds the element, and reading the
      // fresh one back would make the row's visibility depend on how the option/`selected` round-trip
      // happens to resolve at construction time.
      function syncToolRow() { toolRow.style.display = C.mode === "tool" ? "flex" : "none"; }
      modeSel.addEventListener("change", function () { C.mode = modeSel.value; syncToolRow(); });
      syncToolRow();
      // How hard to reason on THIS reply. Ask = quick (default, unchanged). Research = exhaustive + cited,
      // with extended thinking. Plan = an ordered confirm/refute plan + hypotheses + gated next actions.
      // The reply is a LEAD in every mode; the mode changes depth, not what counts as truth.
      const reasonSel = h("select.input", { style: { minWidth: "150px" },
        title: "How hard to reason on the reply — Ask (quick) · Research (exhaustive, deep thinking) · Plan (a confirm/refute plan)" },
        [["ask", "Reasoning: Ask"], ["research", "Research (deep)"], ["plan", "Plan"]].map(function (p) {
          const o = h("option", { value: p[0] }, p[1]); if (p[0] === C.reasonMode) o.selected = true; return o;
        }));
      reasonSel.addEventListener("change", function () { C.reasonMode = reasonSel.value; });
      // E3 — the per-session MODEL picker. This is a sovereignty control, not a preference: a LOCAL model
      // means an uploaded codebase never leaves the machine (no cloud fallback). Each option shows its trust
      // class; one the current sovereignty tier forbids is DISABLED with the reason in its tooltip (told up
      // front, never a surprise at send time). The choice is remembered per session.
      const sessModelSel = buildModelSelect();
      const modelNote = h("div.chat-model-note", null, modelConsequence());
      sessModelSel.addEventListener("change", function () {
        C.model = sessModelSel.value; rememberModel();
        modelNote.textContent = modelConsequence();
      });
      // Agentic-engine opt-out (red-pen F2): on = the live OODA engine (reasons, runs tools, steerable,
      // resumable, live steps); off = a lighter gated scan. Loopback engagements only; a remote target is
      // charter-gated regardless.
      const agenticChk = h("input", { type: "checkbox", checked: C.agentic ? "checked" : null });
      agenticChk.addEventListener("change", function () { C.agentic = !!agenticChk.checked; });
      const agenticTog = h("label.chat-agentic", { title: "Agentic engine: the live OODA engine that reasons, runs tools, steers, and resumes. Off = a lighter gated scan." },
        [agenticChk, h("span", null, "Agentic")]);
      // E1 — request a FIRETEAM (multiple agents on parallel subtasks). Honest: this composes a directive
      // and ensures the agentic engine is on; the engine deploys a BOUNDED fireteam (each member ≤A2, never
      // self-approving, facts minted only by the oracle) WHEN its plan calls for one, and any over-cap step
      // still waits for your signed approval. Each member's steps stream into the live feed, attributed.
      const fireteamBtn = h("button.btn.sm", { type: "button",
        title: "Ask the agentic engine to fan out into a bounded fireteam — multiple agents on parallel subtasks (each ≤A2, oracle-bounded). Their steps stream below, attributed per member.",
        onClick: function () { requestFireteam(); } }, [V.icon("brain"), "Fireteam"]);
      const send = h("button.btn.primary", { onClick: doSend }, [V.icon("bolt"), "Send"]);
      input.addEventListener("keydown", function (e) {
        if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); doSend(); return; }
        if (e.key === "Escape" && C.stream && C.stream.stop) { e.preventDefault(); C.stream.stop(); }   // S4: stop the streaming reply
      });

      // E3 — build the model <select> from the sovereignty-aware roster. A model the current tier FORBIDS is
      // rendered disabled with the reason in its tooltip; the trust class rides each label. If the roster
      // could not be read, fall back to a single default option (the send still works — the server defaults).
      function buildModelSelect() {
        const sel = h("select.input", { style: { minWidth: "170px" },
          title: "The model that reasons on your messages. A LOCAL model keeps everything on this machine (no cloud fallback)." });
        const roster = (C.models && C.models.length) ? C.models
          : [{ id: "", label: "Claude Opus 5 (default)", kind: "cloud", trust_class: "cloud_only", permitted: true, why_not: "" }];
        roster.forEach(function (m) {
          const tc = m.trust_class ? (" · " + m.trust_class) : "";
          const o = h("option", { value: m.id }, m.label + tc);
          if (!m.permitted) { o.disabled = "disabled"; o.title = m.why_not || "not permitted under this sovereignty tier"; }
          // restore this session's remembered pick; if it is now forbidden, fall through to the default
          if (m.id === C.model && m.permitted) o.selected = true;
          sel.appendChild(o);
        });
        // if the remembered choice is gone/forbidden, reflect the effective (default) selection in state AND
        // persist it, so a stale forbidden id does not linger in localStorage (red-pen LOW-7)
        if (C.model && !roster.some(function (m) { return m.id === C.model && m.permitted; })) { C.model = ""; rememberModel(); }
        return sel;
      }

      // E1 — compose a parallel-investigation (fireteam) directive. Honest by construction: it ensures the
      // agentic engine is on (a fireteam only exists there) and drops a template the operator fills with
      // subtasks; the engine decides + gates the actual fan-out. It never claims to force a fireteam.
      function requestFireteam() {
        C.agentic = true;
        if (agenticChk) agenticChk.checked = true;
        const tmpl = "Deploy a fireteam — investigate these in parallel, one agent per task "
          + "(each stays ≤A2 and oracle-bounded; over-cap steps wait for my approval):\n1. \n2. \n3. ";
        const cur = (input.value || "").trim();
        input.value = cur ? (cur + "\n\n" + tmpl) : tmpl;
        input.focus();
        try { input.setSelectionRange(input.value.length, input.value.length); } catch (e) {}
        V.toast("Fireteam directive added — list your subtasks and Send. The agentic engine fans out into "
          + "bounded members when its plan calls for it; each member's steps stream below, attributed.", false);
      }

      // S6: composer SLASH-COMMANDS. Type "/" for a discovery menu; a leading /command runs a chat action
      // instead of sending a message. Each maps to an EXISTING gated action (no new powers) — a slash is a
      // shortcut, never a bypass. An unrecognised /token is sent as an ordinary message (never swallowed).
      const SLASH = [
        { cmd: "/scan", arg: "<path|url>", desc: "Gated scan of a codebase path or a URL", run: function (a) {
            if (!a) { V.toast("Usage: /scan <path or url>", true); return; }
            if (/^https?:\/\//i.test(a)) launchUrlScan(a); else launchScan(a); } },
        { cmd: "/url", arg: "<url>", desc: "Scan a website / API URL", run: function (a) { if (a) launchUrlScan(a); else V.toast("Usage: /url <url>", true); } },
        { cmd: "/plan", desc: "Switch to Plan reasoning", run: function () { C.reasonMode = "plan"; if (reasonSel) reasonSel.value = "plan"; V.toast("Plan mode — ask your question.", false); try { input.focus(); } catch (e) {} } },
        { cmd: "/research", desc: "Switch to Research reasoning", run: function () { C.reasonMode = "research"; if (reasonSel) reasonSel.value = "research"; V.toast("Research mode.", false); try { input.focus(); } catch (e) {} } },
        { cmd: "/model", desc: "Pick the model for this chat", run: function () { try { sessModelSel.focus(); } catch (e) {} } },
        { cmd: "/fireteam", desc: "Compose a fireteam directive", run: function () { requestFireteam(); } },
        { cmd: "/resume", desc: "Resume the paused run from its last checkpoint", run: function () {
            if (PBOX.run && runIsRetryable(PBOX.run)) pboxRetry();
            else V.toast("No paused/resumable run to resume.", true); } },
        { cmd: "/stop", desc: "Stop the running engagement", run: function () {
            if (PBOX.run && PBOX.run.status === "running") pboxCancel();
            else V.toast("No running engagement to stop.", true); } },
        { cmd: "/approve", desc: "Approve the pending owner action", run: function () {
            var pend = PBOX.offenseApprovals || [];
            if (pend.length) offenseApprove(pend[0], function () { pboxApprovalPoll(); });
            else V.toast("Nothing is awaiting your approval.", true); } },
        { cmd: "/findings", desc: "Open the Findings screen", run: function () { location.hash = "#/findings"; } },
        { cmd: "/report", desc: "Open the Report screen", run: function () { location.hash = "#/report"; } },
        { cmd: "/status", desc: "Show the followed run's status", run: function () {
            var r = PBOX.run;
            V.toast(r ? ("Run " + (r.slug || r.run_id) + " \u2014 " + (r.status || "unknown")
                         + (r.paused ? " (" + r.paused + ")" : ""))
                      : "No run is being followed.", false); } },
        { cmd: "/new", desc: "Start a new chat", run: function () { openSession(""); } },
        { cmd: "/clear", desc: "Start a new chat", run: function () { openSession(""); } },
      ];
      function runSlash(msg) {
        const sp = msg.search(/\s/);
        const cmd = (sp < 0 ? msg : msg.slice(0, sp)).toLowerCase();
        const arg = sp < 0 ? "" : msg.slice(sp + 1).trim();
        const hit = SLASH.find(function (s) { return s.cmd === cmd; });
        if (!hit) return false;                    // not a known command → send as an ordinary message
        hideSlash(); hit.run(arg); return true;
      }
      const slashMenu = h("div.slash-menu", { style: { display: "none" } });
      document.body.appendChild(slashMenu);
      function hideSlash() { slashMenu.style.display = "none"; }
      function updateSlash() {
        const v = input.value || "";
        if (v.charAt(0) !== "/" || /\s/.test(v)) { hideSlash(); return; }
        const q = v.toLowerCase();
        const hits = SLASH.filter(function (s) { return s.cmd.indexOf(q) === 0; });
        if (!hits.length) { hideSlash(); return; }
        V.mount(slashMenu, hits.map(function (s) {
          return h("button.slash-item", { onClick: function () {
            if (s.arg) { input.value = s.cmd + " "; try { input.focus(); } catch (e) {} updateSlash(); }
            else { input.value = ""; hideSlash(); s.run(""); }
          } }, [h("span.slash-cmd", null, s.cmd + (s.arg ? " " + s.arg : "")), h("span.slash-desc", null, s.desc)]);
        }));
        const r = input.getBoundingClientRect();
        slashMenu.style.display = "block"; slashMenu.style.position = "fixed";
        slashMenu.style.left = r.left + "px";
        slashMenu.style.bottom = (window.innerHeight - r.top + 6) + "px";
        slashMenu.style.width = Math.min(r.width || 460, 460) + "px";
        slashMenu.style.zIndex = "70";
      }
      input.addEventListener("input", updateSlash);
      input.addEventListener("blur", function () { setTimeout(hideSlash, 150); });   // let a menu click land first

      // S8: @-mentions — reference an attached FILE or a LINKED CHAT from the composer. Frontend-only; it
      // inserts "@name" (files are already in the answer context — a mention just points the question at one).
      const mentionMenu = h("div.slash-menu", { style: { display: "none" } });
      document.body.appendChild(mentionMenu);
      function hideMention() { mentionMenu.style.display = "none"; }
      function mentionSources() {
        const out = [];
        (C.attach || []).forEach(function (a) { if (a && a.name) out.push({ label: a.name, kind: "file" }); });
        const row = rowOf(C.id); const conns = (row && row.connections) || [];
        conns.forEach(function (cid) { out.push({ label: titleOf(cid) || String(cid), kind: "linked chat" }); });
        return out;
      }
      function currentMention() {
        const v = input.value || ""; const pos = (input.selectionStart != null) ? input.selectionStart : v.length;
        const mm = /@([\w.\-]*)$/.exec(v.slice(0, pos));
        return mm ? { q: mm[1], start: pos - mm[0].length, end: pos } : null;
      }
      function updateMention() {
        const cm = currentMention();
        if (!cm) { hideMention(); return; }
        const q = cm.q.toLowerCase();
        const hits = mentionSources().filter(function (s) { return !q || s.label.toLowerCase().indexOf(q) >= 0; }).slice(0, 8);
        if (!hits.length) { hideMention(); return; }
        hideSlash();
        V.mount(mentionMenu, hits.map(function (s) {
          return h("button.slash-item", { onClick: function () {
            const v = input.value; input.value = v.slice(0, cm.start) + "@" + s.label + " " + v.slice(cm.end);
            hideMention(); try { input.focus(); } catch (e) {}
          } }, [h("span.slash-cmd", null, "@" + s.label), h("span.slash-desc", null, s.kind)]);
        }));
        const r = input.getBoundingClientRect();
        mentionMenu.style.display = "block"; mentionMenu.style.position = "fixed";
        mentionMenu.style.left = r.left + "px"; mentionMenu.style.bottom = (window.innerHeight - r.top + 6) + "px";
        mentionMenu.style.width = Math.min(r.width || 460, 460) + "px"; mentionMenu.style.zIndex = "70";
      }
      input.addEventListener("input", updateMention);
      input.addEventListener("blur", function () { setTimeout(hideMention, 150); });

      // The plain-language consequence of the current pick — shown under the picker so the sovereignty
      // trade-off is visible at the moment of choosing, not buried.
      function modelConsequence() {
        const m = (C.models || []).find(function (x) { return x.id === C.model; })
          || (C.models || []).find(function (x) { return x.default; });
        if (!m) return "";
        const tier = C.modelTier ? (" (sovereignty tier: " + C.modelTier + ")") : "";
        return (m.kind === "local" ? "Local · " : "Cloud · ") + (m.consequence || "") + tier;
      }

      // CONSENT COVERS WHAT ACTUALLY GOES. A turn is answered over EVERYTHING the chat still holds —
      // the console assembles the attachment block from the chat's stored attachments, not from a
      // per-message list — so asking about only the ones ticked on this message would have shown the
      // operator a dialog naming two files while three left the machine. The gate is therefore every
      // READY attachment they have not already approved. (Approval is still once per attachment, not
      // once per message: `consented` persists, so this does not nag.) To stop an attachment being sent,
      // remove it — which now really deletes it on the console.
      function doSend() {
        const msg = (input.value || "").trim();
        // S6: a leading /command runs a chat action instead of sending it as a message (unknown → sent normally).
        if (msg && msg.charAt(0) === "/" && runSlash(msg)) { input.value = ""; hideSlash(); return; }
        const outgoing = C.attach.filter(function (a) { return a.status === "ready"; });
        if (C.busy) return;
        if (!msg && !outgoing.length) return;
        if (C.attach.some(function (a) { return a.status === "uploading"; })) {
          V.toast("An attachment is still uploading — one moment.", true); return;
        }
        if (C.mode === "tool" && !C.tool) {
          V.toast("Pick which tool to run, or switch the mode back to “auto”.", true); return;
        }
        const needConsent = outgoing.filter(function (a) { return !a.consented; });
        const gate = needConsent.length ? egressConsent(needConsent) : Promise.resolve(true);
        gate.then(function (ok) {
          if (!ok) return;
          needConsent.forEach(function (a) { a.consented = true; });
          reallySend(msg, outgoing);
        });
      }

      function reallySend(msg, outgoing) {
        C.busy = true; send.disabled = true;
        const payload = { chat_id: C.id || undefined, message: msg, target: (target.value || "").trim(),
          mode: C.mode || undefined, reason_mode: (C.reasonMode && C.reasonMode !== "ask") ? C.reasonMode : undefined,
          agentic: C.agentic,     // explicit so the operator can opt OUT of the agentic engine (default on)
          model: C.model || undefined };   // E3: the per-session model choice (blank = server default; local = no egress)
        // No per-message attachment list: the console answers over everything the chat HOLDS, so a
        // list here would be decoration that reads like a control. Removing an attachment is the control.
        if (C.mode === "tool" && C.tool) {
          const pick = toolPickable((C.profiles || []).find(function (p) { return p.name === C.tool; }));
          if (pick.ok) payload.tools = [pick.cap];
        }
        // F1: a pure QUESTION turn (no explicit target/mode) STREAMS the reply token-by-token. A launch/clone
        // turn is not streamable — send it straight through /api/chat/send. The stream endpoint itself falls
        // back to a JSON response for anything it can't stream, and any stream error falls back too, so the
        // turn is never lost.
        const streamable = !payload.target && !payload.mode;
        return streamable ? streamSend(payload, msg, outgoing) : sendViaPost(payload, outgoing);
      }

      // Apply a turn's result to the UI (shared by the streamed + non-streamed paths).
      function afterSendResult(r, outgoing) {
        if (r && r.error && !r.reply) { V.toast(r.error, true); }
        if (r && r.run_id && r.slug) setEngagement(String(r.slug));   // a LAUNCH turn scopes to its run
        if (r && r.chat_id) adoptChatId(String(r.chat_id));
        if (r && Array.isArray(r.hypotheses)) C.hyps = r.hypotheses;  // Phase C: show the ledger at once
        // S7: remember this turn's token usage + accumulate a running context estimate for the meter.
        if (r && r.usage && (r.usage.input_tokens != null || r.usage.output_tokens != null)) {
          C.lastUsage = r.usage;
          C.ctxTokens = (C.ctxTokens || 0) + (r.usage.input_tokens || 0) + (r.usage.output_tokens || 0);
        }
        (outgoing || []).forEach(function (a) { a.sent = true; });
        input.value = ""; target.value = "";
      }
      function finishSend() {
        C.busy = false; send.disabled = false;
        C.stream = null; removeStreamBubble();
        // G3 — a RENDER exception here must never reject this promise: streamSend's .catch re-sends on a
        // rejection, so a throw in drawSessions/drawMain/scrollDown could otherwise trigger a duplicate turn
        // (the red-pen's one remaining non-reachable edge). Swallow render errors — the turn is already
        // persisted; the worst case is a stale view the next interaction repaints, never a double-send.
        return loadChatList().then(function () {
          try { drawSessions(); drawMain(); scrollDown(); } catch (e) { /* render-only; turn is saved */ }
        }).catch(function () { /* loadChatList failed — the turn is still saved; never re-send */ });
      }
      // The reliable non-streamed turn — the SAME gated launcher / question path.
      function sendViaPost(payload, outgoing) {
        return V.postJSON(OFF("/api/chat/send"), payload).then(function (r) {
          afterSendResult(r, outgoing);
          return refreshTranscript();
        }).catch(function (e) { V.toast((e && e.message) || "Send failed — is the offense console up?", true); })
          .then(finishSend);
      }
      // F1: try the streamed endpoint; render tokens live; on done refresh from the PERSISTED record (the
      // authoritative bubble with its lead badge / proposals / sources / coverage). Any fallback or error
      // routes to the reliable /send path so a turn is never dropped.
      function streamSend(payload, msg, outgoing) {
        // S4: an AbortController so the operator can STOP the streaming reply (button + Esc). `aborted` tells
        // the catch/incomplete paths this was a deliberate Stop (never a dropped connection) so we don't re-send.
        const ctrl = (typeof AbortController !== "undefined") ? new AbortController() : null;
        let aborted = false;
        C.stream = { text: "", msg: msg, stop: function () { aborted = true; if (ctrl) { try { ctrl.abort(); } catch (e) {} } } };
        drawStreamBubble();
        // `committed` guards against a DUPLICATE turn (red-pen MEDIUM-1): once the server has sent an
        // event-stream response it has ALREADY persisted the turn (it appends before emitting `done`), so a
        // later abort or a render error must NOT re-POST to /send — that would double-record the turn AND
        // make a second billable model call. We only re-send when the stream never established.
        let committed = false;
        return streamChat(payload, function (tok) { C.stream.text += tok; drawStreamBubble(); }, ctrl && ctrl.signal)
          .then(function (res) {
            if (res && res.fallback) {                 // not streamable — the server persisted NOTHING → /send
              C.stream = null; removeStreamBubble();
              return sendViaPost(payload, outgoing);
            }
            committed = true;                          // got an event-stream ⇒ the server committed the turn
            if (res && res.incomplete) {               // stream aborted after commit — reload the saved answer
              C.stream = null; removeStreamBubble();
              V.toast(aborted ? "Stopped — reloading whatever the run had already saved."
                              : "The connection dropped mid-reply — the answer was saved; reloading it.", false);
              return refreshTranscript().then(finishSend);
            }
            afterSendResult(res, outgoing);
            return refreshTranscript().then(finishSend);
          })
          .catch(function () {
            C.stream = null; removeStreamBubble();
            if (aborted) { V.toast("Stopped.", false); return finishSend(); }   // deliberate Stop — never re-send
            if (committed) return finishSend();        // a post-commit (e.g. render) error — never re-send
            return sendViaPost(payload, outgoing);     // the stream never established — safe to send once
          });
      }

      // F1 — the fetch-stream reader. POSTs the turn to /api/chat/stream and parses the SSE frames: a
      // "text/event-stream" response streams `token`/`done` events (onToken per delta, resolves with the
      // final result); a JSON response (the server couldn't stream this turn) resolves with {fallback:true}.
      // Same credentials the rest of the page uses (custom header + token); the browser sets Sec-Fetch-Site.
      function streamChat(payload, onToken, signal) {
        const hh = { "X-Requested-With": "vigil-ui", "Content-Type": "application/json" };
        const t = V.token(); if (t) hh["X-SIGIL-Token"] = t;
        const opts = { method: "POST", headers: hh, credentials: "same-origin",
            cache: "no-store", body: JSON.stringify(payload) };
        if (signal) opts.signal = signal;              // S4: lets the operator abort the streaming reply
        return fetch(OFF("/api/chat/stream"), opts).then(function (resp) {
          const ct = (resp.headers.get("Content-Type") || "").toLowerCase();
          if (ct.indexOf("text/event-stream") < 0) {
            // not streamable (fallback) or an error status — read JSON and signal fallback
            return resp.json().then(function (j) { return (j && j.fallback) ? { fallback: true } : j; })
              .catch(function () { return { fallback: true }; });
          }
          if (!resp.body || !resp.body.getReader) return { fallback: true };   // very old browser — use /send
          const reader = resp.body.getReader();
          const dec = new TextDecoder();
          let buf = "";
          let final = null;
          function pump() {
            return reader.read().then(function (r) {
              if (r.done) return final || {};
              buf += dec.decode(r.value, { stream: true });
              let idx;
              while ((idx = buf.indexOf("\n\n")) >= 0) {
                const frame = buf.slice(0, idx); buf = buf.slice(idx + 2);
                const dl = frame.split("\n").filter(function (l) { return l.indexOf("data:") === 0; });
                for (let i = 0; i < dl.length; i++) {
                  let ev; try { ev = JSON.parse(dl[i].slice(5).trim()); } catch (e) { continue; }
                  if (ev && ev.event === "token") { if (onToken) onToken(String(ev.text || "")); }
                  else if (ev && ev.event === "done") { final = ev.result || {}; }
                }
              }
              return pump();
            });
          }
          // Reaching here means the event-stream response was ESTABLISHED (headers received). If the read
          // aborts before `done`, the server has still very likely committed the turn (it persists before
          // emitting done), so resolve with the final result if we got it, else an `incomplete` marker —
          // NEVER reject into streamSend's re-send path (which would double-record). A pre-response fetch
          // failure rejects the outer promise instead, and that IS safe to re-send.
          return pump().catch(function () { return final || { established: true, incomplete: true }; });
        });
      }

      // A transient live bubble for the streaming turn: the operator's message + the reply-so-far with a
      // caret. Honest during streaming — it wears the same "Lead" register as any model answer. Replaced by
      // the persisted record on refresh. Text is set via textContent (never innerHTML) — XSS-safe.
      function drawStreamBubble() {
        const l = V.$("#chat-list"); if (!l || !C.stream) return;
        let wrap = V.$("#chat-stream-wrap");
        if (!wrap) {
          const textEl = h("div#chat-stream-text", { style: { whiteSpace: "pre-wrap", wordBreak: "break-word" } }, "");
          const box = h("div", { style: { maxWidth: "80%", padding: "10px 12px", borderRadius: "var(--r-3)",
            background: "var(--bg-2)", color: "var(--text-0)", border: "1px solid var(--border)" } },
            [h("div", { style: { marginBottom: "6px", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px" } },
               [h("span.shield.lead", null, [V.icon("info"), "Lead — streaming…"]),
                // S4: stop generating (also Esc in the composer). Keeps the partial shown; reloads saved state.
                h("button.btn.sm", { title: "Stop generating (Esc)", onClick: function () { if (C.stream && C.stream.stop) C.stream.stop(); } }, [V.icon("x"), "Stop"])]), textEl]);
          wrap = h("div#chat-stream-wrap", null, [
            bubble({ role: "user", text: C.stream.msg }),
            h("div", { style: { display: "flex", justifyContent: "flex-start", margin: "8px 0" } }, box),
          ]);
          l.appendChild(wrap);
        }
        const te = V.$("#chat-stream-text");
        // S7: an honest thinking indicator — until the first token flows, the model is thinking.
        if (te) te.textContent = C.stream.text ? (C.stream.text + " ▌") : "Thinking…";
        l.scrollTop = l.scrollHeight;
      }
      function removeStreamBubble() { const w = V.$("#chat-stream-wrap"); if (w && w.parentNode) w.parentNode.removeChild(w); }

      // AWAITING-REPLY banner: pinned above the transcript so a paused engagement's question can't scroll out
      // of view; "Reply now" focuses the ONE composer where the answer goes (typing there auto-resumes the run).
      const askBanner = _pendingQ ? h("div.chat-askbanner", {
        style: { marginBottom: "8px", padding: "10px 12px", borderRadius: "var(--r-3)",
          border: "1px solid var(--owner, #d4af37)", borderLeft: "3px solid var(--owner, #d4af37)",
          background: "var(--owner-bg, var(--bg-2))", display: "flex", alignItems: "center",
          gap: "10px", flexWrap: "wrap" } }, [
        h("span.shield", { style: { color: "var(--owner, #d4af37)", fontWeight: "600", whiteSpace: "nowrap" } },
          [V.icon("info"), "Waiting for your answer"]),
        h("div", { style: { flex: "1 1 240px", minWidth: "0" } }, String(_pendingQ.text || _pendingQ.reply || "")),
        // S2: the same click-to-pick options as the bubble, so the operator can answer without scrolling up.
        (_pendingQ && Array.isArray(_pendingQ.options) && _pendingQ.options.length)
          ? h("div", { style: { flex: "1 1 100%" } }, answerOptions(_pendingQ.options))
          : h("button.btn.sm.owner", { onClick: function () { try { input.focus(); input.scrollIntoView({ block: "center" }); } catch (e) {} } }, "Reply now"),
      ]) : null;
      // Clean, professional hierarchy: the TRANSCRIPT is the focus (fills); a single docked COMPOSER CARD
      // holds the attachments strip, the run-options, the input row, the usage meter and a one-line footer;
      // secondary CONTEXT (plan checklist + linked chats) sits below; and the system-wide engine settings are
      // tucked into a collapsed disclosure at the very bottom so they never dominate the conversation.
      const usage = (C.lastUsage ? h("div.chat-usage", null,
        "Last turn: " + (C.lastUsage.input_tokens != null ? C.lastUsage.input_tokens + " in" : "—")
        + " / " + (C.lastUsage.output_tokens != null ? C.lastUsage.output_tokens + " out" : "—") + " tokens"
        + (C.ctxTokens ? "  ·  ~" + C.ctxTokens.toLocaleString() + " this conversation" : "")) : null);
      // F2 — run options grouped into ONE compact, collapsible cluster (target/mode/reasoning/model/agentic/
      // fireteam) so they're one line by default and out of the way when not needed. Same controls, same
      // behaviour. Open by default the first time; the operator can fold it.
      const runopts = h("details.chat-runopts", { open: "open" }, [
        h("summary.chat-runopts-cap", null, [V.icon("gear"), h("span", null, "Run options — how the next message is handled")]),
        h("div.chat-runopts-row", null, [target, modeSel, reasonSel, sessModelSel, agenticTog, fireteamBtn]),
        modelNote,
        toolRow,
      ]);
      const dock = h("div.chat-dock", null, [
        h("div#chat-attach"),                                  // attachments strip (drawn by drawAttach)
        runopts,
        h("div.chat-composer", null, [attachBtn, fileInput, input, send]),
        usage,
        h("div.chat-foot", { title: "Attachments are read on this machine and only sent to the model after you "
          + "approve them once. A chat answer is a LEAD — a finding becomes a FACT only when an oracle confirms "
          + "it in a gated run. Conversations are saved locally under .vigil-live/chats/." },
          [V.icon("info"), h("span", null, "Answers are leads · a gated run mints facts · saved locally")]),
      ]);
      const contextPanels = h("div.chat-context", null, [h("div#chat-hyps"), h("div#chat-links")]);
      const engineSettings = h("details.chat-engine-settings", null, [
        h("summary", null, [V.icon("gear"), h("span", null, "Engine model & effort — system-wide (not this chat)")]),
        controls,
      ]);
      V.mount(host, [askBanner, list, dock, contextPanels, engineSettings]);
      if (_pendingQ) { try { input.focus(); } catch (e) {} }   // steer the operator straight to the reply box
      drawAttach();
      drawLinks();
      drawHyps();
      scrollDown();
    }

    function scrollDown() { const l = V.$("#chat-list"); if (l) l.scrollTop = l.scrollHeight; }

    load();
  }

  // ---- Token Budgets (per-tool daily token caps, operator-editable; warn + throttle, never block) --
  function renderBudgets(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Token Budgets"),
        h("span.sub", null, "A daily token budget for every tool/API — edit any limit here. When a tool "
          + "goes over, the system warns and throttles (slows) it; it never hard-blocks a call.")]),
      h("div#budgets-body", null, h("div.empty", null, "Loading budgets…")),
    ]);
    loadBudgets();
  }
  function loadBudgets() {
    V.getJSON(OFF("/api/token-budgets")).then(drawBudgets).catch(function (e) {
      var host = V.$("#budgets-body"); if (!host) return;
      V.mount(host, offlineEmpty(e, "Could not load token budgets — is the offense console up? (vigil up)"));
    });
  }
  function budgetLevelPill(level) {
    if (level === "over") return V.pill("Over — throttling", "danger", null);
    if (level === "warn") return V.pill("Near limit", "reconnect", null);
    return V.pill("OK", "idle", null);
  }
  function budgetNum(n) { try { return Number(n || 0).toLocaleString(); } catch (e) { return String(n); } }
  function drawBudgets(d) {
    var host = V.$("#budgets-body"); if (!host) return;
    var tools = (d && d.tools) || [];
    if (!tools.length) {
      V.mount(host, h("div.empty", null, [h("div.big", null, "No tools registered"),
        h("p", null, (d && d.error) || "No token-spending tools are registered yet.")]));
      return;
    }
    var cards = tools.map(function (t) {
      var frac = Math.max(0, Math.min(1, t.frac || 0));
      var fillCls = t.level === "over" ? "hi" : (t.level === "warn" ? "mid" : "");
      var unit = t.kind === "requests" ? "requests" : "tokens";
      var limitInput = h("input.input", { type: "number", min: "0", value: String(t.limit),
        style: { width: "130px" } });
      var modeSel = h("select.input", { style: { width: "120px" } },
        ["throttle", "warn", "off"].map(function (m) {
          return h("option", { value: m, selected: t.mode === m ? "selected" : null }, m);
        }));
      var outInput = t.kind === "requests" ? null
        : h("input.input", { type: "number", min: "1", value: String(t.output_max), style: { width: "110px" } });
      var save = h("button.btn.sm.primary", { onClick: function () {
        var payload = { tool: t.tool, limit: limitInput.value, mode: modeSel.value };
        if (outInput) payload.output_max = outInput.value;
        save.disabled = true;
        V.postJSON(OFF("/api/token-budgets"), payload).then(function (r) {
          save.disabled = false;
          if (r && r.error) { V.toast(r.error, true); return; }
          V.toast(t.label + " budget saved");
          drawBudgets({ tools: r.tools, doctrine: d.doctrine });   // repaint with the fresh numbers
        }).catch(function (e) { save.disabled = false; V.toast(String(e), true); });
      } }, "Save");
      return h("div.card", null, [
        h("div.card-h", null, [h("h3", null, t.label), h("span", { style: { flex: 1 } }),
          budgetLevelPill(t.level)]),
        h("div.hint", { style: { marginBottom: "6px" } },
          budgetNum(t.used) + " / " + budgetNum(t.limit) + " " + unit + " today · "
          + Math.round(frac * 100) + "%"),
        h("div.bar", null, h("div.bar-fill" + (fillCls ? "." + fillCls : ""),
          { style: { width: Math.round(frac * 100) + "%" } })),
        h("div", { style: { display: "flex", gap: "12px", alignItems: "flex-end", flexWrap: "wrap", marginTop: "12px" } }, [
          h("div", null, [h("div.label", { style: { marginBottom: "4px" } }, "Daily " + unit), limitInput]),
          h("div", null, [h("div.label", { style: { marginBottom: "4px" } }, "When over"), modeSel]),
          outInput ? h("div", null, [h("div.label", { style: { marginBottom: "4px" } }, "Max / call"), outInput]) : null,
          save,
        ]),
      ]);
    });
    V.mount(host, [
      h("div.hint", { style: { marginBottom: "12px" } }, (d && d.doctrine) || ""),
      h("div.grid.cols-2", { style: { alignItems: "start" } }, cards),
    ]);
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

  // ---- sessions (F2) — permanent, renamable/deletable engagement sessions ----
  function sessionKindPill(kind) {
    var tone = kind === "engagement" ? "live" : "idle";
    var label = kind ? kind.charAt(0).toUpperCase() + kind.slice(1) : "Session";
    return V.pill(label, tone, null);
  }

  function loadSessions() {
    var host = V.$("#sessions-body"); if (!host) return;
    V.getJSON(OFF("/api/sessions")).then(function (d) { drawSessions((d && d.sessions) || []); })
      .catch(function (e) { V.mount(host, h("div.empty", null, "Couldn't load sessions: " + e)); });
  }

  function drawSessions(rows) {
    var host = V.$("#sessions-body"); if (!host) return;
    if (!rows.length) {
      V.mount(host, h("div.empty", null, "No sessions yet. Create one, or start a chat or assessment."));
      return;
    }
    var linkStyle = { padding: "2px 8px", border: "1px solid var(--border,#334)", borderRadius: "6px",
      fontSize: "12px", textDecoration: "none" };
    V.mount(host, h("div.grid.cols-2", { style: { alignItems: "start" } }, rows.map(function (s) {
      var runs = s.run_ids || [];
      var body = h("div", null, [
        h("div", { style: { display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" } }, [
          sessionKindPill(s.kind),
          h("span.dim", null, runs.length + (runs.length === 1 ? " run" : " runs")),
          s.legacy ? h("span.dim", null, "· legacy chat") : null,
        ]),
        runs.length
          ? h("div", { style: { marginTop: "8px", display: "flex", gap: "6px", flexWrap: "wrap" } },
              runs.slice(0, 8).map(function (rid) {
                return h("a", { href: "#/live?run=" + encodeURIComponent(rid), title: "Open in Live",
                  style: linkStyle }, rid);
              }))
          : h("div.dim", { style: { marginTop: "8px" } }, "No runs yet."),
        (s.connections && s.connections.length)
          ? h("div", { style: { marginTop: "8px", display: "flex", gap: "6px", flexWrap: "wrap",
              alignItems: "center" } },
              [h("span.dim", null, "draws on:")].concat(s.connections.map(function (cid) {
                return h("span", { style: linkStyle, title: "Connected — click ✕ to disconnect" }, [
                  cid + " ",
                  h("a", { href: "#", title: "Disconnect", style: { textDecoration: "none" },
                    onClick: function (e) { e.preventDefault(); disconnectSession(s, cid); } }, "✕"),
                ]);
              })))
          : null,
        h("div", { style: { marginTop: "12px", display: "flex", gap: "8px", flexWrap: "wrap" } }, [
          h("button.btn", { onClick: function () { renameSession(s); } }, "Rename"),
          h("button.btn", { onClick: function () { connectSession(s, rows); } }, "Connect…"),
          h("button.btn", { onClick: function () { deleteSession(s, false); } }, "Delete"),
          h("button.btn.danger", { onClick: function () { deleteSession(s, true); } }, "Delete permanently"),
        ]),
      ]);
      return V.card(s.name || "(unnamed session)", (s.kind || "session").toUpperCase(), body, true);
    })));
  }

  function connectSession(s, rows) {
    var others = (rows || []).filter(function (o) { return o.id !== s.id; });
    if (!others.length) { V.toast("No other sessions to connect to", true); return; }
    var listing = others.map(function (o) { return o.id + "  (" + (o.name || "") + ")"; }).join("\n");
    var other = window.prompt("Connect '" + (s.name || s.id) + "' to another session — a live "
      + "`vigil engage --session " + s.id + " --connect <id>` run can then draw on that session's knowledge "
      + "as priors (advisory, never facts). Enter the target session id:\n\n" + listing, others[0].id);
    if (other === null) return;
    other = other.trim(); if (!other) return;
    V.postJSON(OFF("/api/session/connect"), { id: s.id, other: other }).then(function (d) {
      if (d && d.error) { V.toast(d.error, true); return; }
      V.toast("Connected"); loadSessions();
    }).catch(function (e) { V.toast(String(e), true); });
  }

  function disconnectSession(s, other) {
    V.postJSON(OFF("/api/session/disconnect"), { id: s.id, other: other }).then(function (d) {
      if (d && d.error) { V.toast(d.error, true); return; }
      V.toast("Disconnected"); loadSessions();
    }).catch(function (e) { V.toast(String(e), true); });
  }

  function createSession() {
    var name = window.prompt("Name this session:", "");
    if (name === null) return;
    V.postJSON(OFF("/api/session/create"), { name: name, kind: "engagement" }).then(function (d) {
      if (d && d.error) { V.toast(d.error, true); return; }
      V.toast("Session created"); loadSessions();
    }).catch(function (e) { V.toast(String(e), true); });
  }

  function renameSession(s) {
    var cur = s.name === "(unnamed session)" ? "" : s.name;
    var name = window.prompt("Rename session:", cur);
    if (name === null) return;
    V.postJSON(OFF("/api/session/rename"), { id: s.id, name: name }).then(function (d) {
      if (d && d.error) { V.toast(d.error, true); return; }
      loadSessions();
    }).catch(function (e) { V.toast(String(e), true); });
  }

  function deleteSession(s, hard) {
    var label = s.name || s.id;
    var msg = hard
      ? "Permanently delete '" + label + "'? It is removed from history — your runs and the signed record are kept."
      : "Remove '" + label + "' from your session list?";
    if (!window.confirm(msg)) return;
    V.postJSON(OFF("/api/session/delete"), { id: s.id, hard: !!hard }).then(function (d) {
      if (d && d.error) { V.toast(d.error, true); return; }
      V.toast(hard ? "Deleted permanently" : "Removed"); loadSessions();
    }).catch(function (e) { V.toast(String(e), true); });
  }

  function renderSessions(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [
        h("h1", null, "Sessions"),
        h("button.btn.primary", { onClick: createSession }, [V.icon("assess"), "New session"]),
      ]),
      h("div.hint", { style: { marginBottom: "10px" } },
        "Every chat and assessment is a permanent session you can rename, reopen, connect, and remove. "
        + "Connecting a session lets a live `vigil engage --session … --connect …` run draw on the other "
        + "session's knowledge as advisory priors (never facts). Removing from the list is reversible; "
        + "'Delete permanently' takes it out of history — your runs and the signed record are always kept."),
      h("div#sessions-body", null, h("div.empty", null, "Loading…")),
    ]);
    loadSessions();
  }

  // ---- Engagement Library — the past jobs you can come back to, months later ------------------
  //
  // The old listing was an alphabetical `ls targets/` with no timestamps (and it returned NOTHING for
  // a job that only ever existed on the signed spine). A library needs three things that shape could
  // not give: a WHEN, a human NAME, and a way IN. So each row carries its label, a real date and time
  // rendered in the VIEWER'S OWN TIMEZONE, what kind of operation it was, what it was pointed at, and
  // how much it produced — and clicking it opens the runs inside that job, each run's findings, the
  // evidence view and the dossier download that already exist.
  //
  // RENAMING IS PRESENTATION ONLY. It writes one key in the console's label side-car; no run artifact,
  // no certificate and no signed event is touched, so a relabelled job still re-verifies byte for byte.
  var LIB = { rows: [], detail: null };

  function libTimeZone() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (e) { return ""; }
  }
  // A human date+time WITH ITS TIMEZONE. The API hands out UTC ISO-8601 stamps; the operator reads
  // them months later in their own zone, so the zone is shown rather than assumed.
  function fmtWhen(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    try {
      return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit",
        hour: "2-digit", minute: "2-digit", timeZoneName: "short" });
    } catch (e) { return d.toISOString(); }
  }
  // A tile's value is set in a large display face, so a full "Aug 13, 2026, 08:25 AM EDT" wraps to four
  // lines there (seen while driving it). Split it: the DAY is the value, the clock time + zone the foot.
  function fmtDay(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    try { return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" }); }
    catch (e) { return d.toISOString().slice(0, 10); }
  }
  function fmtClock(iso) {
    if (!iso) return "no recorded activity";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    try { return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", timeZoneName: "short" }); }
    catch (e) { return ""; }
  }
  function libName(row) { return (row && row.label) || (row && row.slug) || "(unnamed)"; }
  function libRunName(run) { return (run && run.label) || (run && run.run_id) || "(run)"; }
  // "—" for a stamp we genuinely do not have. A dormant job is honestly blank, never back-dated.
  function libWhenCell(iso) {
    return iso ? h("span", null, fmtWhen(iso)) : h("span.dim", { title: "no recorded activity" }, "—");
  }

  function renderLibrary(screen) {
    var slug = hashQuery().slug || "";
    if (slug) { renderLibraryDetail(screen, slug); return; }
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Engagement Library"),
        h("span.sub", null, "Every past job, most recently worked first — open one to get back to its runs, findings and proof.")]),
      h("div.hint", { style: { marginBottom: "10px" } },
        "Opening a job makes it the one you are working on: every screen then shows that job's runs and "
        + "nothing else, until you open another or widen back to all engagements. Scoping hides nothing "
        + "permanently and deletes nothing. Times are shown in your timezone"
        + (libTimeZone() ? " (" + libTimeZone() + ")" : "")
        + ". Renaming a job or a run is presentation only — it stores a human name beside the "
        + "machine identity and touches no signed byte, so every certificate still verifies."),
      h("div#library-body", null, h("div.empty", null, "Loading past jobs…")),
    ]);
    loadLibrary();
  }

  function loadLibrary() {
    V.getJSON(OFF("/api/engagements")).then(function (d) {
      LIB.rows = (d && d.engagements) || [];
      drawLibrary();
    }).catch(function (e) {
      var host = V.$("#library-body"); if (!host) return;
      V.mount(host, offlineEmpty(e, "Could not load the library — is the offense console up? (vigil up)"));
    });
  }

  function drawLibrary() {
    var host = V.$("#library-body"); if (!host) return;
    if (!LIB.rows.length) {
      V.mount(host, h("div.empty", null, [h("div.big", null, "No past jobs yet"),
        h("p", null, "Every assessment you run is filed here with its date and time; you can rename it and come back to it later."),
        h("button.btn.primary", { style: { marginTop: "16px" }, onClick: function () { location.hash = "#/assess"; } },
          [V.icon("bolt"), "New Assessment"])]));
      return;
    }
    var cols = ["Job", "Last worked on", "First seen", "Kind", "Subject", "Runs", "Findings", ""];
    var table = h("div.scroll-x", null, h("table.tbl", null, [
      h("thead", null, h("tr", null, cols.map(function (c) { return h("th", null, c); }))),
      h("tbody", null, LIB.rows.map(function (r) {
        var isActive = !!r.slug && r.slug === activeEngagement();
        // OPENING A JOB SWITCHES THE SCOPE to it — the library is where the operator says "this is the
        // job I am working on now", and every other screen follows.
        function open() {
          setEngagement(r.slug, r.label || "");
          location.hash = "#/library?slug=" + encodeURIComponent(r.slug);
        }
        return h("tr.click", { onClick: open }, [
          h("td", null, [h("b", null, libName(r)),
            (isActive ? h("span.pill.sm", { style: { marginLeft: "8px" }, title: "every screen is currently filtered to this job — a view filter, not a running job" }, "viewing") : null),
            (r.label ? h("div.dim", { style: { fontSize: "var(--fs-xs)" } }, r.slug) : null),
            (r.on_spine ? null : h("div.dim", { style: { fontSize: "var(--fs-xs)" } }, "not on the spine"))]),
          h("td", null, libWhenCell(r.last_activity)),
          h("td", null, libWhenCell(r.first_seen)),
          h("td", null, (r.kinds && r.kinds.length) ? h("span.mono", { style: { fontSize: "var(--fs-xs)" } }, r.kinds.join(", "))
            : h("span.dim", null, "—")),
          h("td", null, (r.subjects && r.subjects.length)
            ? h("span.mono", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all" } }, r.subjects.join(", "))
            : h("span.dim", null, "—")),
          h("td", null, String(r.run_count != null ? r.run_count : 0)),
          h("td", null, [String(r.finding_count != null ? r.finding_count : 0),
            (r.fact_count ? h("span.dim", { style: { fontSize: "var(--fs-xs)" } }, " · " + r.fact_count + " proven") : null)]),
          h("td", null, h("div", { style: { display: "flex", gap: "6px" } }, [
            h("button.btn.sm", { onClick: function (e) { e.stopPropagation(); open(); } }, "Open"),
            h("button.btn.sm", { onClick: function (e) { e.stopPropagation(); renameEngagement(r); } }, "Rename"),
          ])),
        ]);
      })),
    ]));
    // The explicit way OUT of a scope, so no past job is ever unreachable: widening is a presentation
    // switch and nothing more — every job, run, finding and certificate is exactly where it was.
    var scopeRow = h("div.row-flex", { style: { marginTop: "10px", gap: "10px", flexWrap: "wrap" } }, [
      h("span.hint", null, activeEngagement()
        ? ("Every screen is showing " + engagementName() + " only.")
        : "Every screen is showing all engagements. Open a job below to work on just that one."),
      activeEngagement()
        ? h("button.btn.sm", { style: { marginLeft: "auto" }, onClick: function () { setEngagement(""); drawLibrary(); } },
          [V.icon("book"), "All engagements"])
        : null,
    ]);
    V.mount(host, h("div.card", null, [
      h("div.card-h", null, [h("span.label", null, "PAST JOBS"),
        h("h3", null, LIB.rows.length + (LIB.rows.length === 1 ? " engagement" : " engagements"))]),
      scopeRow,
      h("div", { style: { marginTop: "12px" } }, table),
    ]));
  }

  function renameEngagement(row) {
    var name = window.prompt("Name this job so it is easy to find later:\n\n" + row.slug
      + "\n\n(The name is for you — it changes nothing that is signed.)", row.label || "");
    if (name === null) return;
    V.postJSON(OFF("/api/label/engagement"), { slug: row.slug, label: name }).then(function (d) {
      if (d && d.error) { V.toast(d.error, true); return; }
      V.toast(name ? "Renamed" : "Name cleared");
      if (LIB.detail && LIB.detail.slug === row.slug) { loadLibraryDetail(row.slug); } else { loadLibrary(); }
    }).catch(function (e) { V.toast(String(e), true); });
  }

  function renameRun(run, slug) {
    var name = window.prompt("Name this run:\n\n" + run.run_id
      + "\n\n(The name is for you — it changes nothing that is signed.)", run.label || "");
    if (name === null) return;
    V.postJSON(OFF("/api/label/run"), { run_id: run.run_id, label: name }).then(function (d) {
      if (d && d.error) { V.toast(d.error, true); return; }
      V.toast(name ? "Renamed" : "Name cleared");
      loadLibraryDetail(slug);
    }).catch(function (e) { V.toast(String(e), true); });
  }

  function renderLibraryDetail(screen, slug) {
    // Viewing one job's detail — from a bookmark, a shared link, a reload, or browser back — does NOT
    // change the global view filter. Scoping is an EXPLICIT act: the list row's Open (drawLibrary) sets
    // it, and this detail page offers a "Scope every screen to this job" button. Re-pinning on every
    // view was exactly why a job the operator only looked at got stuck as the "active" scope with no way
    // to shake it. drawLibraryDetail fills the name from the job's own label when it lands.
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Engagement Library"),
        h("span.sub", null, "One past job — its runs, and the way back into each one's findings and proof.")]),
      h("div", { style: { marginBottom: "10px" } },
        h("button.btn.sm", { onClick: function () { location.hash = "#/library"; } }, "← All past jobs")),
      h("div#library-detail", null, h("div.empty", null, "Loading…")),
    ]);
    loadLibraryDetail(slug);
  }

  function loadLibraryDetail(slug) {
    // The detail route carries the runs + charter state; the timestamps and counts live on the ROSTER
    // row. Deep-linking to #/library?slug=… (a bookmark, a shared link, a reload) never went through
    // the list, so the roster was empty and the header honestly but uselessly showed "—" for "last
    // worked on" and the finding count. Found by driving it. Fetch both, and let the detail render as
    // soon as it lands rather than blocking on the roster.
    var needRoster = !LIB.rows.length;
    V.getJSON(OFF("/api/library/" + encodeURIComponent(slug))).then(function (d) {
      LIB.detail = d || null;
      drawLibraryDetail(slug);
    }).catch(function (e) {
      var host = V.$("#library-detail"); if (!host) return;
      V.mount(host, h("div.empty", null, "Could not load this job: " + ((e && e.message) || e)));
    });
    if (needRoster) {
      V.getJSON(OFF("/api/engagements")).then(function (d) {
        LIB.rows = (d && d.engagements) || [];
        if (LIB.detail) drawLibraryDetail(slug);      // repaint the header with its real stamps
      }).catch(function () { /* the detail still renders; the header stays honestly blank */ });
    }
  }

  function drawLibraryDetail(slug) {
    var host = V.$("#library-detail"); if (!host) return;
    var d = LIB.detail;
    if (!d) { V.mount(host, h("div.empty", null, "Not found.")); return; }
    // the roster row carries the timestamps + counts; the detail carries the runs + charter/safety.
    var roster = null;
    LIB.rows.forEach(function (r) { if (r.slug === slug) roster = r; });
    // now that the job's own human name is known, let the scope chip call it that
    noteEngagementName(slug, d.label || (roster && roster.label) || "");
    var runs = d.runs || [];
    var ks = d.killswitch || {};

    var header = h("div.card", null, [
      h("div.card-h", null, [h("span.label", null, "PAST JOB"), h("h3", null, libName(d.label ? d : { slug: slug })),
        h("span", { style: { flex: 1 } }),
        h("button.btn.sm", { onClick: function () { renameEngagement({ slug: slug, label: d.label || "" }); } }, "Rename")]),
      h("div.grid.cols-4", { style: { marginTop: "12px" } }, [
        V.tile("Machine identity", slug, "never changes"),
        V.tile("Last worked on", fmtDay(roster && roster.last_activity),
          fmtClock(roster && roster.last_activity)
          + (roster && roster.last_activity && libTimeZone() ? " · " + libTimeZone() : "")),
        V.tile("Runs", String(runs.length), "in this job"),
        V.tile("Findings", String(roster && roster.finding_count != null ? roster.finding_count : "—"),
          roster && roster.fact_count ? roster.fact_count + " oracle-proven" : "as recorded"),
      ]),
      h("div", { style: { marginTop: "10px", display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" } }, [
        d.has_charter ? V.pill("Charter on file", "ok", null) : V.pill("No charter", "idle", null),
        ks.tripped ? V.pill("Kill-switch TRIPPED", "danger", null) : null,
        roster && roster.on_spine ? V.pill("On the signed spine", "live", null) : null,
        activeEngagement() === slug ? V.pill("View filter: this job", "idle", null) : null,
        activeEngagement() === slug
          ? h("button.btn.sm", { style: { marginLeft: "auto" }, title: "Stop filtering every screen to this job",
            onClick: function () { setEngagement(""); location.hash = "#/library"; } }, [V.icon("book"), "All engagements"])
          : h("button.btn.sm", { style: { marginLeft: "auto" },
            title: "Filter every screen to this job's runs (a view filter — it changes nothing signed or gated)",
            onClick: function () { setEngagement(slug, (roster && roster.label) || ""); drawLibraryDetail(slug); } },
            [V.icon("book"), "Scope every screen to this job"]),
      ]),
      h("div.hint", { style: { marginTop: "8px" } },
        "Live, Findings, Fixes, Report, Proof, Compliance, Assurance and Activity are showing this job's "
        + "runs only. Scoping is presentation — it changes nothing that is signed or gated."),
    ]);

    var runsCard;
    if (!runs.length) {
      runsCard = h("div.card", null, [h("div.card-h", null, [h("span.label", null, "RUNS"), h("h3", null, "No runs recorded")]),
        h("div.hint", null, "This job has a charter or a spine entry but no console-launched run yet.")]);
    } else {
      var cols = ["Run", "Started", "Status", "Subject", "Findings", ""];
      runsCard = h("div.card", null, [
        h("div.card-h", null, [h("span.label", null, "RUNS"),
          h("h3", null, runs.length + (runs.length === 1 ? " run" : " runs"))]),
        h("div.hint", { style: { marginTop: "6px" } },
          "Each run inside this job stays distinct — its own time, its own findings, its own proof."),
        h("div.scroll-x", { style: { marginTop: "12px" } }, h("table.tbl", null, [
          h("thead", null, h("tr", null, cols.map(function (c) { return h("th", null, c); }))),
          h("tbody", null, runs.map(function (run) {
            return h("tr", null, [
              h("td", null, [h("b", null, libRunName(run)),
                (run.label ? h("div.dim", { style: { fontSize: "var(--fs-xs)" } }, run.run_id) : null)]),
              h("td", null, libWhenCell(run.started_iso)),
              h("td", null, V.statusBadge(run.status || "unknown")),
              h("td", null, h("span.mono", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all" } },
                run.target || "—")),
              h("td", null, run.findings != null ? String(run.findings) : h("span.dim", null, "—")),
              h("td", null, h("div", { style: { display: "flex", gap: "6px", flexWrap: "wrap" } }, [
                h("button.btn.sm", { onClick: function () {
                  location.hash = "#/findings?run=" + encodeURIComponent(run.run_id) + "&tab=findings"; } }, "Findings"),
                h("button.btn.sm", { onClick: function () {
                  location.hash = "#/findings?run=" + encodeURIComponent(run.run_id) + "&tab=evidence"; } }, "Evidence"),
                h("button.btn.sm", { onClick: function (e) {
                  downloadDossier(run.run_id, e.target, V.$("#library-dossier-status")); } }, "Dossier"),
                h("button.btn.sm", { onClick: function () { renameRun(run, slug); } }, "Rename"),
                // W4: stop a running run, or relaunch a finished one (Resume where the CLI supports it).
                (run.status === "running"
                  ? h("button.btn.sm", { onClick: function () { runCancel(run.run_id, function () { loadLibraryDetail(slug); }); } }, "Cancel")
                  : (runIsRetryable(run)
                    ? h("button.btn.sm", { onClick: function () { runRetry(run.run_id, function () { loadLibraryDetail(slug); }); } },
                        run.resumable ? "Resume" : "Retry")
                    : null)),
              ])),
            ]);
          })),
        ])),
        h("div#library-dossier-status", { style: { marginTop: "10px" } }),
      ]);
    }
    V.mount(host, [header, h("div", { style: { marginTop: "16px" } }, runsCard)]);
  }

  // ---- Knowledge Engine (K1) — vuln-intel feed + defensive CATALOG (read-only) ----
  var K = { slug: "", data: null, engagements: [], feedInterval: 3600, feedBusy: false };
  function renderKnowledge(screen) {
    V.mount(screen, [
      h("div.screen-head", null, [h("h1", null, "Knowledge Engine")]),
      h("div.hint", { style: { marginBottom: "10px" } },
        "An auto-updating feed of vulnerability intelligence from trusted sources (NVD, OSV, CISA-KEV), "
        + "alongside the defensive knowledge catalog. Every feed entry is an intel-tier LEAD, never a "
        + "fact — only a fired oracle confirms. The live pull is a gated, opt-in egress act; offline is "
        + "the default."),
      hostOpsCard(),
      h("div#knowledge-body", null, h("div.empty", null, "Loading…")),
    ]);
    loadKnowledge();
  }

  // Wave 6 (parity) — the sovereign HOST-RUN BROKER: launch a CLOSED SET of long memory host-ops (rebuild
  // the vector index, rebuild memory from transcripts/docs/git, dry-run consolidation) as tracked background
  // subprocesses, from the browser. OWNER-only (the launch is owner-gated server-side; non-owners get a 403
  // toast). Status/runs are viewer+. The server validates the verb + flags — the UI only offers the allowed set.
  function hostOpsCard() {
    var runsOut = h("div", null, "");
    var iReset = h("input", { type: "checkbox" }), iDocs = h("input", { type: "checkbox" }), iGit = h("input", { type: "checkbox" });
    function launch(verb, flags) {
      V.postJSON(SOV("/api/hostcmd/" + verb), { flags: flags || [] }).then(function (r) {
        if (r && r.ok) { V.toast((r.detail || (verb + " started")) ); setTimeout(refreshRuns, 800); }
        else { V.toast((r && r.error) || (verb + " failed"), true); }
      }).catch(function (e) { V.toast((e && e.message) || (verb + " failed (owner only?)"), true); });
    }
    function pill(st) {
      var up = st === "done", run = st === "running" || st === "starting", bad = st === "failed" || st === "error" || st === "interrupted";
      return V.pill(st || "?", up ? "up" : (run ? "idle" : (bad ? "danger" : "idle")), null);
    }
    function refreshRuns() {
      V.getJSON(SOV("/api/hostcmd/runs")).then(function (d) {
        var runs = (d && d.runs) || [];
        if (!runs.length) { V.mount(runsOut, h("div.hint", { style: { marginTop: "8px" } }, "No host-op runs yet.")); return; }
        V.mount(runsOut, h("div", { style: { marginTop: "8px" } }, runs.map(function (r) {
          return h("div.kv", null, [
            h("div.k", null, [pill(r.status), " " + r.verb + (r.flags && r.flags.length ? " (" + r.flags.join(",") + ")" : "")]),
            h("div.v", { style: { fontSize: "12px", color: "var(--text-2)" } }, (r.status === "running" || r.status === "starting") ? "running…" : (r.exit_code != null ? ("exit " + r.exit_code) : (r.detail || ""))),
          ]);
        })));
        // keep polling while anything is live
        if (runs.some(function (r) { return r.status === "running" || r.status === "starting"; }) && current() === "knowledge") setTimeout(refreshRuns, 5000);
      }).catch(function () {});
    }
    refreshRuns();
    return h("div.card", { style: { marginBottom: "14px" } }, [
      h("div.card-h", null, [h("h3", null, "Memory host operations"),
        h("button.btn.sm", { style: { marginLeft: "auto" }, onClick: refreshRuns }, [V.icon("live"), "Refresh"])]),
      h("div.hint", null, "Owner-only sovereign maintenance — rebuild the vector index / rebuild memory / dry-run "
        + "consolidation. Each runs as a tracked background host process (poll below). A closed verb set; no free-form commands."),
      h("div.acts", { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "10px", alignItems: "center" } }, [
        h("button.btn.sm.owner", { onClick: function () { launch("index", []); } }, [V.icon("bolt"), "Rebuild vector index"]),
        h("button.btn.sm.owner", { onClick: function () {
          var f = []; if (iReset.checked) f.push("reset"); if (iDocs.checked) f.push("docs"); if (iGit.checked) f.push("git");
          launch("ingest", f);
        } }, [V.icon("brain"), "Rebuild memory"]),
        h("label", { style: { display: "flex", gap: "5px", alignItems: "center", fontSize: "12.5px" } }, [iReset, "reset"]),
        h("label", { style: { display: "flex", gap: "5px", alignItems: "center", fontSize: "12.5px" } }, [iDocs, "docs"]),
        h("label", { style: { display: "flex", gap: "5px", alignItems: "center", fontSize: "12.5px" } }, [iGit, "git"]),
        h("button.btn.sm.owner", { onClick: function () { launch("consolidate", ["dry-run"]); } }, [V.icon("check"), "Consolidate (dry-run)"]),
      ]),
      runsOut,
    ]);
  }
  function loadKnowledge() {
    V.getJSON(OFF("/api/engagements")).then(function (d) {
      K.engagements = (d && d.engagements ? d.engagements : []).map(function (e) { return e.slug; });
      if (!K.slug && K.engagements.length) K.slug = K.engagements[0];
      loadKnowledgeData();
    }).catch(function () { K.engagements = []; loadKnowledgeData(); });
  }
  function loadKnowledgeData() {
    // federate the two planes: the feed/proposals come from the OFFENSE mirror; the autolearn latch +
    // kill-switch come from the SOVEREIGN snapshot (owner-signed governance). One failing plane is tolerated.
    Promise.all([
      V.getJSON(OFF("/api/vulnintel/" + encodeURIComponent(K.slug || ""))).catch(function () { return null; }),
      V.getJSON(SOV("/api/snapshot")).catch(function () { return null; }),
      V.getJSON(OFF("/api/evolve/" + encodeURIComponent(K.slug || ""))).catch(function () { return null; }),
      V.getJSON(OFF("/api/feed/status")).catch(function () { return null; }),
    ]).then(function (res) { K.data = res[0]; K.snap = res[1]; K.evolve = res[2]; K.feed = res[3]; drawKnowledge(); });
  }
  function drawKnowledge() {
    var body = V.$("#knowledge-body"); if (!body) return;
    var d = K.data;
    if (!d) { V.mount(body, h("div.empty", null, "Offense console offline — cannot load the feed.")); return; }
    var sources = d.sources || [], vulns = d.vulnerabilities || [], cat = d.catalog || [];
    var counts = d.counts || {};
    var snap = K.snap || {};
    var caps = snap.capabilities || {};
    var autolearn = caps.autolearn;                     // "enabled" | "disabled" | undefined (sovereign offline)
    var learnOn = autolearn === "enabled";
    var killed = !!(snap.kill_switch === "ENGAGED" || (snap.kill_switch && snap.kill_switch.engaged));

    var picker = h("div.row", { style: { display: "flex", gap: "10px", alignItems: "center", marginBottom: "12px" } }, [
      h("label.k", null, "Engagement"),
      h("select", { onChange: function (e) { K.slug = e.target.value; loadKnowledgeData(); } },
        [h("option", { value: "", selected: !K.slug }, "— select —")].concat(
          K.engagements.map(function (s) { return h("option", { value: s, selected: s === K.slug }, s); }))),
      d.slug ? h("span.pill.sm", null,
        (counts.vulnerabilities || 0) + " leads · " + (counts.exploit_known || 0) + " known-exploited") : null,
    ]);

    var sourcesCard = h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Feed sources")]),
      h("div", null, sources.map(function (s) {
        return h("div.kv", null, [h("div.k", null, s.name),
          h("div.v", null, [h("span.pill.sm", null, s.mode), " ", h("code", null, s.host)])]);
      })),
      h("div.hint", { style: { marginTop: "8px" } },
        "The live pull is offline by default; enable it with a gated `intel refresh-vulnintel --live`. "
        + "No traffic fires without it, and every source is a fixed, concrete apex host (never the target)."),
    ]);

    // ---- Vuln-feed pull (K1/U2): one-shot gated 'Pull now' + recurring sidecar Start/Stop (B5) ----
    var feed = K.feed || {};
    var feedRec = feed.recurring || {};
    var sidecars = feedRec.sidecars || [];
    var mine = d.slug ? sidecars.filter(function (s) { return s.slug === d.slug; })[0] : null;
    var running = !!(mine && mine.alive);
    var feedCard = h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Vuln-feed pull"),
        h("span.st.st-idle", { style: { marginLeft: "auto" } }, [h("span.dot"),
          "egress " + (feed.egress_default || "offline") + " by default"])]),
      h("div.hint", { style: { marginBottom: "8px" } },
        "\"Pull now\" is a ONE-SHOT, conscious opt-in egress: it refreshes the feed from the trusted "
        + "sources (NVD / OSV / CISA-KEV) through the gated transport. Every entry is an intel-tier LEAD, "
        + "never a fact — only a fired oracle confirms."),
      h("div.row", { style: { marginTop: "4px" } }, [
        h("button.btn.sm", { disabled: killed || !d.slug || K.feedBusy,
          title: killed ? "kill-switch engaged" : (!d.slug ? "select an engagement" : ""),
          onClick: function () {
            V.toast("Pulling the vuln feed (gated egress)…");
            V.postJSON(OFF("/api/feed/" + encodeURIComponent(d.slug) + "/pull"), {}).then(function (r) {
              if (r && r.ok) {
                var applied = r.applied != null ? r.applied : 0;
                V.toast("Feed pulled — " + applied + " lead(s) applied"
                  + (r.hosts_refused ? " · " + r.hosts_refused + " host(s) refused" : ""));
              } else { V.toast((r && (r.refused || r.error)) || "Feed pull failed", true); }
              loadKnowledgeData();
            }).catch(function () { V.toast("Feed pull failed", true); });
          } }, "Pull now"),
        h("span.hint", { style: { marginLeft: "8px" } },
          "One-shot, kill-switch gated. Leads only — mints no fact, fires no oracle."),
      ]),
      // --- Recurring sidecar (B5): Start/Stop the `intel feed-daemon --live` this console supervises ---
      h("div.card-h", { style: { marginTop: "12px" } }, [h("h3", null, "Recurring feed sidecar"),
        (running
          ? h("span.st.st-confirmed", { style: { marginLeft: "auto" } }, [h("span.dot"),
              "running · pid " + mine.pid + " · every " + (mine.interval || "?") + "s"])
          : h("span.st.st-idle", { style: { marginLeft: "auto" } }, [h("span.dot"), "stopped"]))]),
      h("div.hint", { style: { marginBottom: "8px" } },
        "Recurring auto-pull is an OPT-IN, kill-switch-gated egress the console supervises. Each tick honours "
        + "this engagement's kill-switch (STOP halts it within one poll) and mints only intel-tier LEADS. "
        + "There is no persisted schedule — only the live pid and the interval you choose."),
      h("div.row", { style: { marginTop: "6px", display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" } }, [
        h("label.k", null, "Interval (s)"),
        h("input", { type: "number", min: "60", max: "86400", step: "60",
          style: { width: "110px" }, value: String(K.feedInterval), disabled: running,
          onInput: function (e) { K.feedInterval = parseInt(e.target.value, 10) || 3600; } }),
        h("button.btn.sm", { disabled: killed || !d.slug || running || K.feedBusy,
          title: killed ? "kill-switch engaged" : (!d.slug ? "select an engagement" : (running ? "already running" : "")),
          onClick: function () {
            K.feedBusy = true; drawKnowledge();
            V.postJSON(OFF("/api/feed/" + encodeURIComponent(d.slug) + "/start"), { interval: K.feedInterval })
              .then(function (r) {
                K.feedBusy = false;
                if (r && r.ok) V.toast(r.already_running ? "Feed sidecar already running." : "Feed sidecar started (leads only).");
                else V.toast((r && (r.refused || r.error)) || "Could not start the feed sidecar", true);
                loadKnowledgeData();
              }).catch(function () { K.feedBusy = false; V.toast("Could not start the feed sidecar", true); loadKnowledgeData(); });
          } }, "Start"),
        h("button.btn.sm.danger", { disabled: !running || K.feedBusy,
          onClick: function () {
            K.feedBusy = true; drawKnowledge();
            V.postJSON(OFF("/api/feed/" + encodeURIComponent(d.slug) + "/stop"), {})
              .then(function (r) {
                K.feedBusy = false;
                V.toast(r && r.stopped ? "Feed sidecar stopped." : "No running feed sidecar to stop.");
                loadKnowledgeData();
              }).catch(function () { K.feedBusy = false; V.toast("Could not stop the feed sidecar", true); loadKnowledgeData(); });
          } }, "Stop"),
      ]),
    ]);

    var vulnCard = h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Vulnerability leads")]),
      vulns.length ? h("div", null, vulns.map(function (v) {
        return h("div.kv", null, [
          h("div.k", null, [v.exploit_known
            ? h("span.pill.sm.danger", { title: "CISA known-exploited" }, "KEV")
            : h("span.pill.sm", null, "lead"), " ", v.id]),
          h("div.v", null, [
            v.severity ? h("span.pill.sm.warn", null, String(v.severity)) : null,
            v.summary ? h("span", { style: { marginLeft: "6px" } }, String(v.summary)) : null,
            v.feed ? h("span.hint", { style: { marginLeft: "6px" } }, "· " + v.feed) : null,
          ]),
        ]);
      })) : h("div.empty", null, d.slug
        ? "No vulnerability leads yet for this engagement — ingest a feed or run a gated refresh."
        : "Select an engagement to see its feed."),
    ]);

    var catCard = h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Defensive knowledge catalog"),
        h("span.pill.sm", { style: { marginLeft: "auto" } }, cat.length + " operators")]),
      h("div.hint", { style: { marginBottom: "8px" } },
        "Read-only skillset — advisory detection/attack operators mapped to ATT&CK/CWE. Never facts."),
      h("div", null, cat.slice(0, 200).map(function (op) {
        return h("div.kv", null, [h("div.k", null, op.id),
          h("div.v", null, [op.name, " "].concat(
            (op.technique_ref || []).map(function (t) {
              return h("span.pill.sm", { style: { marginRight: "4px" } }, t);
            })))]);
      })),
    ]);

    // ---- Learning card: the owner-signed autolearn latch + propose-to-learn queue + STOP ----
    var proposals = d.proposals || [];
    // reconcile the offense-drafted candidates against the SOVEREIGN pending-approval queue (by vuln_id):
    // a queued proposal shows Accept/Deny (owner-signed); an un-queued one shows "Queue for approval".
    var pendingByVuln = Object.create(null);
    (snap.learn_proposals || []).forEach(function (lp) {
      if (lp && lp.vuln_id != null) pendingByVuln[lp.vuln_id] = lp.seq;
    });
    var latchLabel = autolearn === undefined ? "unknown (sovereign offline)" : autolearn;
    var latchTone = learnOn ? "confirmed" : "idle";
    var learnCard = h("div.card.owner", null, [
      h("div.card-h", null, [h("h3", null, "Propose-to-learn"),
        h("span.st.st-" + latchTone, { style: { marginLeft: "auto" } }, [h("span.dot"), "autolearn " + latchLabel])]),
      h("div.hint", { style: { marginBottom: "10px" } },
        "Autolearn ranks the vulnerability leads into proposals to deep-learn (find / detect / prevent). "
        + "A proposal authorises NOTHING — it is a suggestion; accepting one authorises LEARNING, never a "
        + "fact. Only a fired oracle mints a fact. Turning autolearn off stops proposing; the kill-switch "
        + "halts all autonomous activity."),
      h("div.acts", { style: { display: "flex", gap: "8px", marginBottom: "12px", flexWrap: "wrap" } }, [
        learnOn
          ? h("button.btn.sm.danger", { onClick: function () {
              settingsAct({ action: "disable_autolearn", reason: "deactivate from Knowledge" },
                "Autolearn deactivated.", loadKnowledgeData); } }, "Deactivate autolearn")
          : h("button.btn.sm.owner", { disabled: autolearn === undefined, onClick: function () {
              settingsAct({ action: "enable_autolearn", reason: "activate from Knowledge" },
                "Autolearn activated.", loadKnowledgeData); } }, "Activate autolearn"),
        killed
          ? h("button.btn.sm.owner", { onClick: function () {
              settingsAct({ action: "release", reason: "release from Knowledge" },
                "Kill-switch released.", loadKnowledgeData); } }, "Release kill-switch")
          : h("button.btn.sm.danger", { onClick: function () {
              settingsAct({ action: "kill", reason: "STOP from Knowledge" },
                "Kill-switch engaged — all autonomous activity halted.", loadKnowledgeData); } },
              "STOP (emergency halt)"),
      ]),
      killed ? h("div.set-status.off", null, [V.icon("info"),
        h("span", null, "The kill-switch is ENGAGED — all autonomous activity is halted.")]) : null,
      !learnOn
        ? h("div.empty", null, autolearn === undefined
            ? "Sovereign plane offline — cannot read the autolearn latch."
            : "Autolearn is off. Activate it to review the proposed vulnerabilities to learn.")
        : (proposals.length
          ? h("div", null, proposals.map(function (p) {
              var pseq = pendingByVuln[p.vuln_id];      // spine seq if awaiting approval, else undefined
              var queued = pseq !== undefined;
              var actions = queued
                ? [h("span.pill.sm.warn", { style: { marginRight: "6px" } }, "awaiting approval"),
                   h("button.btn.sm.owner", { onClick: function () {
                     settingsAct({ action: "approve", seq: pseq, reason: "accept learn " + p.vuln_id },
                       "Accepted — learning authorised.", loadKnowledgeData); } }, "Accept"),
                   h("button.btn.sm.danger", { style: { marginLeft: "6px" }, onClick: function () {
                     settingsAct({ action: "deny", seq: pseq, reason: "deny learn " + p.vuln_id },
                       "Denied.", loadKnowledgeData); } }, "Deny")]
                : [h("button.btn.sm", { disabled: killed, title: killed ? "kill-switch engaged" : "",
                     onClick: function () {
                       settingsAct({ action: "queue_learn", vuln_id: p.vuln_id, slug: K.slug, rank: p.rank,
                         exploit_known: p.exploit_known, severity: p.severity, rationale: p.rationale },
                         "Queued for your approval.", loadKnowledgeData); } }, "Queue for approval")];
              return h("div.kv", null, [
                h("div.k", null, ["#" + p.rank + " ",
                  p.exploit_known ? h("span.pill.sm.danger", null, "KEV") : h("span.pill.sm", null, "propose"),
                  " ", p.vuln_id]),
                h("div.v", null, [p.severity ? h("span.pill.sm.warn", null, String(p.severity)) : null,
                  h("span.hint", { style: { marginLeft: "6px", marginRight: "8px" } }, p.rationale || "")]
                  .concat(actions)),
              ]);
            }))
          : h("div.empty", null, "No proposals yet — the feed has no vulnerability leads for this engagement.")),
    ]);

    // ---- Add & learn a source (K4): manual CVE add + point-at-URL learning ----
    var ll = K.lastLearn;
    var learnSourceCard = (learnOn ? h("div.card.owner", null, [
      h("div.card-h", null, [h("h3", null, "Add & learn a source")]),
      h("div.hint", { style: { marginBottom: "10px" } },
        "Add a CVE to the learn queue, or point at a documentation URL to learn from it. URL-learn fetches "
        + "PUBLIC pages through the scope / robots / SSRF gate; nothing a page asserts becomes a fact — "
        + "grounded claims are verbatim source spans, everything else is advisory."),
      h("div.row", { style: { display: "flex", gap: "8px", marginBottom: "8px", flexWrap: "wrap" } }, [
        h("input#k-manual-vuln", { type: "text", placeholder: "CVE-2024-… (add to learn queue)",
          style: { flex: "1 1 240px" } }),
        h("button.btn.sm.owner", { disabled: killed, onClick: function () {
          var el = V.$("#k-manual-vuln"); var v = (el && el.value || "").trim();
          if (!v) { V.toast("Enter a CVE id", true); return; }
          settingsAct({ action: "queue_learn", vuln_id: v, slug: K.slug, rationale: "manually added" },
            "Added to the learn queue for your approval.", loadKnowledgeData); } }, "Add to learn queue"),
      ]),
      h("div.row", { style: { display: "flex", gap: "8px", flexWrap: "wrap" } }, [
        h("input#k-learn-url", { type: "text", placeholder: "https://owasp.org/… (learn from a URL)",
          style: { flex: "1 1 240px" } }),
        h("button.btn.sm.owner", { disabled: killed, onClick: function () {
          var el = V.$("#k-learn-url"); var u = (el && el.value || "").trim();
          if (!u) { V.toast("Enter an http(s) URL", true); return; }
          V.toast("Learning — fetching + grounding…");
          settingsAct({ action: "start_learn", url: u }, "Learned — see the result below.",
            function (r) { K.lastLearn = r; drawKnowledge(); }); } }, "Learn from URL"),
      ]),
      ll ? h("div", { style: { marginTop: "12px" } }, [
        h("div.kv", null, [h("div.k", null, "Last learn"),
          h("div.v", null, [
            h("span.pill.sm.ok", null, (ll.grounded != null ? ll.grounded : 0) + " grounded"),
            " ", h("span.pill.sm", null, (ll.advisory != null ? ll.advisory : 0) + " advisory"),
            " ", h("span.hint", null, (ll.url || ll.host || "") + (ll.pages_fetched != null
              ? " · " + ll.pages_fetched + " page(s)" : ""))])]),
        ll.text ? h("pre", { style: { whiteSpace: "pre-wrap", fontSize: "var(--fs-xs)", marginTop: "6px",
          maxHeight: "220px", overflow: "auto", background: "var(--bg-1)", padding: "8px",
          borderRadius: "6px" } }, String(ll.text).slice(0, 4000)) : null,
      ]) : null,
    ]) : null);

    // ---- Self-evolve (K5): bounded horizon → gated DRAFT proposals + completion signal ----
    var ev = K.evolve;
    var se = ev && ev.studied_enough || {};
    var evolveCard = (ev && d.slug) ? h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Self-evolve"),
        (se.done === true
          ? h("span.st.st-confirmed", { style: { marginLeft: "auto" } }, [h("span.dot"), "studied everything in scope"])
          : h("span.st.st-idle", { style: { marginLeft: "auto" } }, [h("span.dot"), "in progress"]))]),
      h("div.hint", { style: { marginBottom: "8px" } },
        "A bounded, deterministic horizon over the disclosed leads plus coverage gaps → GATED DRAFT proposals "
        + "(never merged or applied). \"Studied everything in scope\" means drafted everything for the "
        + "disclosed leads — not that the system is complete. Only a fired oracle mints a fact."),
      h("div.kv", null, [h("div.k", null, "Horizon gaps"), h("div.v", null, String(ev.horizon_gaps || 0))]),
      h("div.kv", null, [h("div.k", null, "Coverage gaps"),
        h("div.v", null, (ev.coverage_gaps || []).length
          ? (ev.coverage_gaps || []).map(function (g) { return h("span.pill.sm.warn", { style: { marginRight: "4px" } }, g.bug_class); })
          : "none")]),
      h("div.kv", null, [h("div.k", null, "Draft proposals"), h("div.v", null, String((ev.proposals || []).length))]),
      h("div.kv", null, [h("div.k", null, "Unlearned leads"),
        h("div.v", null, String((ev.unlearned_leads || []).length)
          + ((ev.unlearned_leads || []).length ? " — draft their skills below" : " — none"))]),
      (ev.unlearned_leads || []).length ? h("div", { style: { marginTop: "6px" } },
        (ev.unlearned_leads || []).map(function (vid) {
          return h("div.kv", null, [
            h("div.k", null, [h("span.pill.sm", null, "lead"), " ", String(vid)]),
            h("div.v", null, [
              h("button.btn.sm", { disabled: killed, title: killed ? "kill-switch engaged" : "",
                onClick: function () {
                  V.postJSON(OFF("/api/knowledge/" + encodeURIComponent(d.slug) + "/deeplearn"),
                    { vuln_id: vid }).then(function (r) {
                    if (r && r.ok) {
                      var props = (r.drafted_oracle_proposals || []).length;
                      V.toast("Drafted advisory skills for " + vid
                        + (props ? " · " + props + " gated DETECT proposal(s)" : "") + " — mints no fact");
                    } else { V.toast((r && (r.refused || r.error)) || "Deep-learn failed", true); }
                    loadKnowledgeData();
                  }).catch(function () { V.toast("Deep-learn failed", true); });
                } }, "Draft skills (deep-learn)"),
            ]),
          ]);
        })) : null,
      (ev.unlearned_leads || []).length ? h("div.hint", { style: { marginTop: "4px" } },
        "Deep-learn drafts FIND/PREVENT advisory skills + a GATED DETECT proposal (authorise≠apply). "
        + "It mints no fact, bumps no prior, and fires no oracle.") : null,
      ev.calibration ? h("div.kv", null, [h("div.k", null, "Calibration"),
        h("div.v", null, ev.calibration.resolved + " resolved · Brier "
          + (ev.calibration.brier != null ? Number(ev.calibration.brier).toFixed(3) : "—"))]) : null,
      h("div.row", { style: { marginTop: "10px" } }, [
        h("button.btn.sm", { disabled: killed, title: killed ? "kill-switch engaged" : "",
          onClick: function () {
            V.postJSON(OFF("/api/evolve/" + encodeURIComponent(d.slug) + "/tick"), {}).then(function (r) {
              if (r && r.ok) {
                V.toast("Evolve tick — " + (r.predictions_recorded || 0) + " prediction(s) recorded");
              } else { V.toast((r && (r.refused || r.error)) || "Evolve tick failed", true); }
              loadKnowledgeData();
            }).catch(function () { V.toast("Evolve tick failed", true); });
          } }, "Run evolve tick"),
        h("span.hint", { style: { marginLeft: "8px" } },
          "Records a calibration prediction per draft — drafts only, never merges or applies, mints no fact."),
      ]),
    ]) : null;

    // ---- knowledge/ folder → git (A6c/K6): local regenerate + secret-scan + commit (push is CLI-only) ----
    var gitCard = h("div.card.owner", null, [
      h("div.card-h", null, [h("h3", null, "knowledge/ folder → git")]),
      h("div.hint", { style: { marginBottom: "8px" } },
        "Regenerate the system-map, SECRET-SCAN the knowledge/ folder, and commit it locally. A hit REFUSES "
        + "the commit and lists the files to redact. Pushing to GitHub stays a deliberate `vigil knowledge "
        + "push` CLI act — this never pushes."),
      h("div.row", { style: { display: "flex", gap: "8px" } }, [
        h("button.btn.sm", { onClick: function () {
          V.postJSON(OFF("/api/knowledge/gitsync"), { action: "status" }).then(function (r) {
            V.toast(r && r.status !== undefined ? ("git status: " + (r.status || "clean")) : "status checked");
          }).catch(function () { V.toast("status failed", true); }); } }, "Status"),
        h("button.btn.sm.owner", { onClick: function () {
          V.postJSON(OFF("/api/knowledge/gitsync"), { action: "sync" }).then(function (r) {
            if (r && r.ok) { V.toast("knowledge/ synced + committed locally"); }
            else if (r && r.refused) { V.toast("REFUSED: " + r.refused, true); }
            else { V.toast((r && r.error) || "sync failed", true); }
          }).catch(function () { V.toast("sync failed", true); }); } }, "Regenerate + commit"),
      ]),
    ]);

    V.mount(body, [picker, learnCard, learnSourceCard, evolveCard, sourcesCard, feedCard, vulnCard, catCard, gitCard,
      h("div.hint", { style: { marginTop: "10px" } }, d.doctrine || "")]);
  }

  // ---- SIGIL HUD channel (S2) — persistent voice/gesture navigation ----------
  var _hudES = null;
  function startSigilHud() {
    if (_hudES) return;
    // the authoritative allowlist of in-app screens (S1 CI keeps system-map == NAV, so this IS the map).
    // Object.create(null) → no inherited prototype keys, so `navIds[id]` is a strict membership test (a
    // payload of "constructor"/"__proto__"/… can never read truthy off the prototype chain).
    var navIds = Object.create(null);
    var navOrder = [];
    NAV.forEach(function (g) { g.items.forEach(function (it) { navIds[it.id] = true; navOrder.push(it.id); }); });
    try {
      // persistent (NOT stored in liveES) so teardownLive() on route changes never closes it. It fans out
      // sigil.nav SIGNALS from the owner-signed spine → a hash navigation, but ONLY to a KNOWN in-app NAV
      // screen id (a spoofed/garbled payload navigates to nothing — never an arbitrary URL or the prototype).
      _hudES = V.sse(SOV("/api/sigil/hud"), function (ev) {
        if (!ev) return;
        if (ev.t === "state") { updateSigilHud(ev); return; }       // S4: the on-screen SIGIL state HUD
        if (ev.t !== "nav") return;
        if (ev.screen_id && navIds[ev.screen_id] === true) {          // voice / pinch: an absolute screen id
          if (current() !== ev.screen_id) location.hash = "#/" + ev.screen_id;
        } else if ((ev.direction === "next" || ev.direction === "prev") && navOrder.length) {
          // gesture swipe: step the NAV list from the current screen (wraps; lands only on a known NAV id).
          var i = navOrder.indexOf(current());
          if (i < 0) i = 0;
          var n = navOrder.length;
          var j = ev.direction === "next" ? (i + 1) % n : (i - 1 + n) % n;
          location.hash = "#/" + navOrder[j];
        }
      });
    } catch (e) { _hudES = null; }
  }

  // ---- SIGIL on-screen HUD (S4) — a small corner overlay of SIGIL's state --------------------------
  var _hudUI = { dismissed: false, minimized: false, last: null };
  var _HUD_TONE = { listening: "live", thinking: "reconnect", speaking: "owner", idle: "idle" };
  function sigilHudHost() {
    var host = V.$("#sigil-hud");
    if (!host) { host = h("div#sigil-hud"); document.body.appendChild(host); }
    return host;
  }
  function updateSigilHud(ev) {
    _hudUI.last = ev;
    var state = (ev && ev.state) || "idle";
    if (state !== "idle") _hudUI.dismissed = false;      // a new interaction re-shows a dismissed HUD
    var host = sigilHudHost();
    if (_hudUI.dismissed) { host.style.display = "none"; return; }
    host.style.display = "";
    var tone = _HUD_TONE[state] || "idle";
    var label = state.charAt(0).toUpperCase() + state.slice(1);
    var line = state === "speaking" ? (ev.feedback || "") : (ev.transcript || "");
    if (_hudUI.minimized) {
      V.mount(host, h("div.pill.sm." + tone, { title: "SIGIL — click to expand",
        onClick: function () { _hudUI.minimized = false; updateSigilHud(_hudUI.last); } },
        [h("span.dot"), "SIGIL"]));
      return;
    }
    V.mount(host, h("div.sigil-hud-card", null, [
      h("div.sigil-hud-head", null, [
        h("div.pill.sm." + tone, null, [h("span.dot"), "SIGIL · " + label]),
        h("div.sigil-hud-btns", null, [
          h("button.sigil-hud-x", { title: "Minimize",
            onClick: function () { _hudUI.minimized = true; updateSigilHud(_hudUI.last); } }, "–"),
          h("button.sigil-hud-x", { title: "Dismiss",
            onClick: function () { _hudUI.dismissed = true; sigilHudHost().style.display = "none"; } }, "×"),
        ]),
      ]),
      line ? h("div.sigil-hud-line", null, line) : null,
    ]));
  }

  // ============================================================================
  // W5 — the PROCESS BOX. A global, collapsible, resizable, scrollable overlay that
  // shows, live, exactly what the backend is doing on the active run: every step, and
  // clearly WHAT blocked (which gate + why) or WHAT failed (a bad tool result / a
  // backend network/API error). It discovers the newest running run on its own, tails
  // the SAME SSE feeds the Live view uses, and SURVIVES route changes — its EventSource
  // is held in PBOX.es, NOT in liveES, so teardownLive() never closes it. It is a fixed
  // overlay (bottom-right, below the toast stack) that never covers the workspace.
  var PBOX_KEY = "vigil-process-box";
  var PBOX_CAP = 200;                                   // rows kept in the scrollback ring buffer
  var PBOX = { es: null, run: null, following: "", events: [], seen: {}, poll: null,
               // S1: the approve/deny/deny-&-redirect interrupt in CHAT — the PBOX follows the run globally,
               // so it surfaces approvals on any screen (chat included) via the SHARED makeApprovalUX.
               approvalMem: { popped: {}, seen: false, modal: null }, pendingApprovals: [],
               // S1b: OFFENSE engage approvals (request_id-keyed, keyless broker) — a chat-launched engage's
               // queued tool lives HERE, not in the sovereign snapshot the seq-based AUX polls. Own baseline
               // + one-at-a-time guard (mirrors approvalMem, keyed by request_id).
               offenseApprovals: [], offenseMem: { popped: {}, seen: false, modal: null, base: ".vigil-live" },
               ui: { open: false, dismissed: false, w: 0, h: 0, max: false } };
  var pboxApprovalModal = null;
  var PBOX_AUX = makeApprovalUX({
    mem: PBOX.approvalMem, reason: "from chat",
    slugOf: function () { return PBOX.run && PBOX.run.slug; },
    after: function () { pboxApprovalPoll(); },
    onModal: function (m) { pboxApprovalModal = m; } });

  // S1b: the OFFENSE-approval interrupt for chat. Offense engage approvals are request_id-keyed and are
  // signed route-via-sovereign (offenseApprove/offenseDeny → SOV /api/action; the cockpit signs with the
  // owner key, the offense console stays keyless), so they need their own card/pop distinct from the
  // seq-based sovereign AUX. Same discipline: baseline what is already queued on entry (no nag), then
  // interrupt for a NEW one, one modal at a time across BOTH approval kinds.
  function pbActionLabel(p) {
    // A fan-out (deploy_fireteam) reads as a friendly "Approve fan-out" label naming the agent count; every
    // other offense action shows its tool name. Governed identically — Approve signs the SAME per-action token.
    if (p && p.tool_name === "deploy_fireteam") {
      var n = 0;
      try {
        var a = p.args_preview;
        if (a && typeof a === "object") { n = a.members || 0; }
        else if (typeof a === "string") { var m = a.match(/members["']?\s*[:=]\s*(\d+)/); if (m) { n = +m[1]; } }
      } catch (e) { /* label is best-effort */ }
      return "fan-out — deploy " + (n ? n + " " : "") + "specialist agent" + (n === 1 ? "" : "s");
    }
    return (p && p.tool_name) || "action";
  }
  function pboxOffenseCard(p) {
    var refresh = function () { pboxApprovalPoll(); };
    return h("div.approval", null, [
      h("div.ah", null, [V.icon("key"),
        h("span.t", null, pbActionLabel(p) + " → " + (p.target || "—")),
        h("span.pill.sm", null, "offense")]),
      p.args_preview ? h("div.why", null,
        h("div.mono.dim", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all" } }, p.args_preview)) : null,
      h("div.acts", null, [
        h("button.btn.owner", { onClick: function () { offenseApprove(p, refresh); } }, [V.icon("check"), "Approve"]),
        h("button.btn.danger", { onClick: function () { offenseDeny(p, refresh); } }, [V.icon("x"), "Deny"]),
      ]),
    ]);
  }
  function pboxOffensePop(p) {
    PBOX.offenseMem.popped[p.request_id] = true;   // never re-pop the same request (dismiss = use the card)
    var cmd = "vigil approve sign --base-dir " + (PBOX.offenseMem.base || ".vigil-live")
            + " --request-id " + p.request_id;
    var redirect = h("input.input", { type: "text",
      placeholder: "Tell the agent what to do instead\u2026 (for Deny & redirect)" });
    var body = h("div.stack", null, [
      h("div.why", null, "The agent's next step needs your signed approval before it can run."),
      h("div.kv", null, [
        h("span.k", null, "Action"), h("span.v", null, pbActionLabel(p)),
        h("span.k", null, "Target"), h("span.v.mono", null, p.target || "—"),
      ]),
      p.args_preview ? h("div.mono.dim", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all" } }, p.args_preview) : null,
      redirect,
      h("p.helper", null, "Approve signs it in the sovereign cockpit with your owner key (it never reaches "
        + "the offense console) and the run continues. Deny refuses it. Deny & redirect refuses it AND sends "
        + "your note to steer the agent so it re-plans. You can also sign from a terminal:"),
      h("code.mono", { style: { fontSize: "var(--fs-xs)", wordBreak: "break-all", display: "block" } }, cmd),
    ]);
    var done = function () { if (m) { try { m.close(); } catch (e) {} } PBOX.offenseMem.modal = null; };
    var refresh = function () { pboxApprovalPoll(); };
    var denyRedirect = function () {
      var t = (redirect.value || "").trim();
      if (!t) { V.toast("Type what the agent should do instead first.", true); if (redirect.focus) redirect.focus(); return; }
      injectIntoRun((PBOX.run && PBOX.run.slug) || "", redirect);   // steer (honest toast: live vs queued)
      offenseDeny(p, refresh);                                       // and refuse the exact action
      done();
    };
    redirect.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); denyRedirect(); } });
    var m = openModal("Approve this action?", body, [
      h("button.btn", { onClick: denyRedirect }, [V.icon("edit"), "Deny & redirect"]),
      h("button.btn.danger", { onClick: function () { offenseDeny(p, refresh); done(); } }, [V.icon("x"), "Deny"]),
      h("button.btn.owner", { onClick: function () { offenseApprove(p, refresh); done(); } }, [V.icon("check"), "Approve"]),
    ], { onCancel: function () { PBOX.offenseMem.modal = null; } });
    PBOX.offenseMem.modal = m;
  }
  function pboxOffenseMaybePop(pend) {
    if (PBOX.offenseMem.modal || PBOX.approvalMem.modal) return;   // one modal at a time across both kinds
    if (!PBOX.offenseMem.seen) { pend.forEach(function (p) { PBOX.offenseMem.popped[p.request_id] = true; }); PBOX.offenseMem.seen = true; return; }
    for (var i = 0; i < pend.length; i++) { if (!PBOX.offenseMem.popped[pend[i].request_id]) { pboxOffensePop(pend[i]); return; } }
  }
  function pboxOffenseReset() {
    PBOX.offenseMem.popped = {}; PBOX.offenseMem.seen = false;
    if (PBOX.offenseMem.modal) { try { PBOX.offenseMem.modal.close(); } catch (e) {} }
    PBOX.offenseMem.modal = null;
  }

  // #1b: the moment an offense approval is ACTED on (approve/deny), drop it from the box optimistically so
  // the card/popup disappears at once — the pending file lingers on disk until the run consumes the token,
  // and the 4s poll would otherwise keep re-showing an already-approved card (the "popup after I approve" bug).
  function pboxForgetApproval(rid) {
    if (!rid) return;
    PBOX.offenseApprovals = (PBOX.offenseApprovals || []).filter(function (x) { return x.request_id !== rid; });
    if (PBOX.offenseMem) { PBOX.offenseMem.popped[rid] = true;                 // never re-pop it
      if (PBOX.offenseMem.modal) { try { PBOX.offenseMem.modal.close(); } catch (e) {} PBOX.offenseMem.modal = null; } }
    if (PBOX.ui.open && !PBOX.ui.dismissed) pboxRenderShell();
  }

  function pboxLoadUI() {
    try {
      var s = JSON.parse(localStorage.getItem(PBOX_KEY) || "{}");
      if (s && typeof s === "object") { PBOX.ui.open = !!s.open; PBOX.ui.dismissed = !!s.dismissed;
        PBOX.ui.w = Number(s.w) || 0; PBOX.ui.h = Number(s.h) || 0; PBOX.ui.max = !!s.max; }
    } catch (e) { /* storage off — defaults (collapsed, visible) */ }
  }
  function pboxSaveUI() {
    try { localStorage.setItem(PBOX_KEY, JSON.stringify(PBOX.ui)); } catch (e) {}
  }
  function pboxHost() {
    var host = V.$("#process-box");
    if (!host) { host = h("div#process-box"); document.body.appendChild(host); }
    return host;
  }
  // The per-event status tag — this is the "what blocked / what failed" clarity the operator asked for.
  // W6b: a classified BACKEND-CALL failure — either the dormant 'error_class' kind or (what the engine
  // actually emits) an 'observation' whose source is 'backend-error'. Returns the class string, else "".
  function pboxErrClass(e) {
    var p = e.payload || {};
    if (e.kind === "error_class") return String(p.error_class || "unknown");
    if (e.kind === "observation" && String(p.source || "") === "backend-error") return String(p.error_class || "unknown");
    return "";
  }
  function pboxTag(e) {
    var p = e.payload || {};
    if (e.kind === "refusal" || (e.kind === "tool_result" && p.refused)) {
      // A >=A2 offense action QUEUED for your signature is NOT an error — it is WAITING ON YOU. Render it as
      // a distinct amber "needs approval", not a red "blocked". Only a genuine gate DENY (out-of-scope,
      // kill-switch, structurally-invalid) is "blocked". This is the per-action gate working, not a failure.
      var _rsn = String(p.reason || p.note || "").toLowerCase();
      if (/owner approval|requires\s+(?:a\s+)?signed|requires\s+.*approval|awaiting\s+.*approval|needs\s+.*approval/.test(_rsn))
        return { cls: "pb-approval", label: "needs approval" };
      return { cls: "pb-blocked", label: "blocked" };
    }
    if (e.kind === "tool_result" && p.ok === false) return { cls: "pb-failed", label: "failed" };
    if (e.kind === "result" && p.success === false) return { cls: "pb-failed", label: "failed" };
    var ec = pboxErrClass(e);                          // W6b: network vs API vs blocked, so WHY is clear
    if (ec) {
      var k = ec.toLowerCase();
      if (k === "network") return { cls: "pb-failed", label: "network" };
      if (k === "api" || k === "api_transient") return { cls: "pb-failed", label: "API error" };
      if (k === "blocked") return { cls: "pb-blocked", label: "blocked" };
      return { cls: "pb-failed", label: k || "error" };
    }
    if (e.kind === "finding") {
      // lead ≠ fact: only an oracle-CONFIRMED finding earns the proven-fact colour. An unconfirmed
      // finding (every loopback-scan finding, an un-adjudicated blackboard lead) is a LEAD — the same
      // distinction the Live view draws — so this ticker never shows a confirmation the oracle never gave.
      return isFact(p) ? { cls: "pb-finding", label: "fact" } : { cls: "pb-lead", label: "lead" };
    }
    return { cls: "", label: "" };
  }
  // The RESULT card an operator opens from a finding row — the oracle VERDICT + details, XSS-safe (all
  // values are DOM text nodes). A FACT is a deterministic oracle re-execution over the target's own bytes;
  // a LEAD is an unconfirmed model/tool proposal.
  function findingCardBody(p) {
    p = p || {};
    var fact = isFact(p);
    var kv = [];
    function add(k, v) { if (v) { kv.push(h("span.k", null, k)); kv.push(h("span.v", null, String(v))); } }
    add("Verdict", fact ? "FACT — oracle-confirmed" : "LEAD — unconfirmed");
    add("Finding", p.title || p.summary || p.bug_class || "finding");
    add("Bug class", p.bug_class);
    add("Surface", p.surface);
    add("Target", p.target || p.host);
    add("Severity", p.severity);
    add("Reference", p.ref);
    add("Evidence", p.evidence_ref ? "signed evidence certificate attached"
                                   : (fact ? "oracle re-drive over fresh target bytes" : ""));
    return h("div.stack", null, [
      h("div.why" + (fact ? ".ok" : ""), null, fact
        ? "Confirmed by a deterministic oracle re-executing the exploit over the target's OWN response bytes — a signed FACT, not a model claim."
        : "An unconfirmed LEAD (a model/tool proposal). Only an oracle-confirmed finding is a FACT."),
      h("div.kv", null, kv),
    ]);
  }

  function pboxRow(e) {
    var p = e.payload || {};
    var m = KIND_META[e.kind] || { label: e.kind, sum: function () { return ""; } };
    var st = pboxTag(e);
    var t = e.posted_at ? String(e.posted_at).slice(11, 19) : (e.id != null ? "#" + e.id : "");
    var isErr = !!pboxErrClass(e);
    var sum = isErr ? (p.summary || p.detail || p.error_class || "the model call failed") : (m.sum(p) || "—");
    // S5: a tool step opens the full command/output CARD in the (resizable) drawer — inline tool cards in chat.
    var isTool = e.kind === "tool_call" || e.kind === "tool_result";
    // THINKING rows (decision/hypothesis/reasoning) show the model's plain-words rationale — let them WRAP
    // (full text) instead of the one-line-ellipsis every other row uses.
    var isThink = e.kind === "decision" || e.kind === "hypothesis" || e.kind === "reasoning";
    // A FINDING row opens the RESULT card — "where do I see the fact": click the finding to see the full
    // oracle verdict (FACT vs LEAD) + details, right here in the chat.
    var isFinding = e.kind === "finding";
    var attrs = isTool ? { style: { cursor: "pointer" }, title: "Show the command + output",
      onClick: function () { var pr = toolPairFrom(PBOX.events, e); openDrawer("Tool call", toolCardBody(pr.call, pr.result)); } }
      : (isFinding ? { style: { cursor: "pointer" }, title: "Show the finding / fact",
        onClick: function () { openDrawer(isFact(p) ? "Confirmed FACT" : "Lead (unconfirmed)", findingCardBody(p)); } } : null);
    var _muted = (e.kind === "critic_summary" || (e.kind === "critic_verdict" && p.expected)) ? ".pb-muted" : "";
    return h("div.pb-row" + (st.cls ? "." + st.cls : "") + (isTool || isFinding ? ".pb-clickable" : "") + (isThink ? ".pb-think-row" : "") + _muted, attrs, [
      h("span.pb-ico", null, V.icon(isErr ? "x" : kindIcon(e.kind, p))),
      h("div.pb-body", null, [
        h("div.pb-k", null, [isErr ? "Backend error" : m.label,
          st.label ? h("span.pb-tag" + (st.cls ? "." + st.cls : ""), null, st.label) : null]),
        h("div.pb-m", { title: sum }, sum),
      ]),
      h("span.pb-t", null, t),
    ]);
  }
  // is the followed run in a TERMINAL (finished) state? (anything but running / no status yet)
  function pboxIsTerminal() {
    return !!(PBOX.run && PBOX.run.status && PBOX.run.status !== "running");
  }
  function pboxStepText() {
    // TERMINAL: when the run has FINISHED, print a clear "Done" (with the confirmed-fact count) instead of
    // leaving the last mid-run step up, so the operator plainly sees it completed (operator ask).
    if (pboxIsTerminal()) {
      // PAUSED (Wave 7): not Done — the run stopped resumably. Say WHY and what unblocks it, so the
      // operator never reads a blocked run as finished, and can approve/reply then Resume.
      if (PBOX.run.status === "paused") {
        var _pr = String((PBOX.run && PBOX.run.paused) || "");
        var _pm = _pr === "approval_rejected" ? "Paused \u2014 your last approval expired or was already used; approve the pending action again, then Resume"
                : _pr === "awaiting_approval" ? "Paused \u2014 awaiting your approval; approve the pending action, then Resume"
                : _pr === "anti-spin" ? "Paused \u2014 stopped after repeating an action; Resume to continue"
                : _pr === "ask_user" ? "Paused \u2014 waiting for your reply below"
                : _pr === "plan-only" ? "Paused \u2014 plan ready (no tools were run)"
                : ("Paused" + (_pr ? " \u2014 " + _pr : ""));
        return "\u23F8 " + _pm;
      }
      var _facts = 0;
      for (var j = 0; j < PBOX.events.length; j++) {
        if (PBOX.events[j].kind === "finding" && isFact(PBOX.events[j].payload || {})) _facts++;
      }
      var _lbl = ({ done: "Done", completed: "Done", error: "Ended with an error",
                    interrupted: "Interrupted", cancelled: "Cancelled" })[PBOX.run.status] || PBOX.run.status;
      // A whole-app / suite run (stream="blackboard") writes its findings to the evidence spine + Findings
      // screen, NOT this box's progress stream \u2014 so the inline count can read 0 even when the engine
      // confirmed real vulnerabilities. Direct the operator to Findings instead of a FALSE "no facts
      // confirmed" (the inline count still shows when the stream did surface facts).
      if (PBOX.run.stream === "blackboard" && !_facts) {
        return "\u2713 " + _lbl + " \u2014 whole-app scan complete; open the Findings screen for the "
             + "confirmed vulnerabilities";
      }
      return "\u2713 " + _lbl + (_facts ? " \u2014 " + _facts + " fact(s) confirmed"
                                         : " \u2014 no facts confirmed");
    }
    for (var i = PBOX.events.length - 1; i >= 0; i--) {
      var e = PBOX.events[i], p = e.payload || {};
      // W6c: carry the WHY, not just WHAT was refused. W6b's pboxErrClass supersedes the older
      // `kind === "error_class"` branch (no producer ever emitted that kind) — keep the live one.
      if (e.kind === "refusal") return "blocked by " + (p.gate || "gate") + ": " + (p.action_refused || "")
        + (p.reason ? " — " + p.reason : "");
      var _ec = pboxErrClass(e);
      if (_ec) return _ec + " error: " + (p.summary || p.detail || "the model call failed");
      if (e.kind === "tool_call") return "running " + (p.tool || "") + (p.target ? " → " + p.target : "");
      if (e.kind === "plan") return "planning: " + (KIND_META.plan.sum(p) || "");
      if (e.kind === "observation") return KIND_META.observation.sum(p) || "observing";
      if (e.kind === "finding") return "found: " + (KIND_META.finding.sum(p) || "");
    }
    return PBOX.run ? (PBOX.run.status || "starting…") : "";
  }
  function pboxIsRunning() { return !!(PBOX.run && PBOX.run.status === "running"); }
  function pboxUpdateChrome() {
    // update just the pill/step/dot without rebuilding the feed (so scroll position is preserved).
    var step = V.$("#pb-step");
    if (step) { step.textContent = pboxStepText() || "waiting…";
      step.className = "pb-step" + ((PBOX.run && PBOX.run.status === "paused") ? " pb-paused"
                                    : (pboxIsTerminal() ? " pb-done" : "")); }
    var pill = V.$("#pb-pill");
    if (pill) {
      pill.className = "pb-pill" + (pboxIsRunning() ? " live" : "");
      // keep the pill TEXT in sync too (not just the dot), so a run starting while minimized doesn't
      // leave a live green dot next to the text "Activity · idle".
      if (pill.lastChild && pill.lastChild.nodeType === 3) {
        pill.lastChild.textContent = pboxIsRunning() ? "Activity" : "Activity · idle";
      }
    }
    var dot = V.$("#pb-run-dot"); if (dot) dot.className = "dot" + (pboxIsRunning() ? " pb-on" : "");
  }
  function pboxAppendRow(e) {
    var feed = V.$("#pb-feed"); if (!feed) return;
    var empty = feed.querySelector(".pb-empty"); if (empty) empty.remove();
    var atBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 28;   // "stick" only if already there
    feed.appendChild(pboxRow(e));
    var trimmed = 0;
    while (feed.childNodes.length > PBOX_CAP) {
      var fc = feed.firstChild; trimmed += (fc.offsetHeight || 0); feed.removeChild(fc);
    }
    if (atBottom) feed.scrollTop = feed.scrollHeight;
    else if (trimmed) feed.scrollTop = Math.max(0, feed.scrollTop - trimmed);   // keep a scrolled-up view steady
  }
  // W4 — run control (shared by the process box and the Runs table). Non-destructive lifecycle: Cancel
  // terminates the run's process; Retry relaunches its recorded argv (Resume where the CLI supports it).
  function runIsRetryable(r) {
    // "paused" (Wave 7): a run that exited resumably (awaiting a signature / anti-spin / ask_user /
    // plan-only) offers Resume — the same runRetry path, which resumes from the last signed checkpoint.
    return !!(r && r.run_id && (r.status === "error" || r.status === "interrupted"
                                || r.status === "cancelled" || r.status === "paused"));
  }
  // in-flight guard: a second click on the same run's control is ignored until the first resolves, so a
  // double-click can never fire two concurrent cancels/retries (the backend also refuses a second running
  // run of a slug, but this stops the request storm at the source).
  var _runBusy = {};
  function _runAct(runId, verb, body, okMsg, after) {
    if (!runId || _runBusy[runId]) return;
    _runBusy[runId] = true;
    V.postJSON(OFF("/api/run/" + encodeURIComponent(runId) + "/" + verb), body || {})
      .then(function (res) {
        if (res && res.ok) { V.toast(okMsg(res), false); if (after) after(res); }
        else { V.toast((res && res.error) || ("Could not " + verb + "."), true); }
      })
      .catch(function (e) { V.toast("Could not " + verb + ": " + ((e && e.message) || e), true); })
      .then(function () { delete _runBusy[runId]; });
  }
  function runCancel(runId, after) {
    if (!runId) return;
    if (!window.confirm("Stop this run? The process is terminated; findings and proof so far stay on disk.")) return;
    _runAct(runId, "cancel", {}, function () { return "Run cancelled."; }, after);
  }
  function runRetry(runId, after) {
    if (!runId) return;
    if (!window.confirm("Relaunch this run? A resumable run continues from its last checkpoint; otherwise it restarts.")) return;
    _runAct(runId, "retry", {}, function (res) { return res.resumed ? "Resuming from the last checkpoint…" : "Restarting…"; }, after);
  }
  function pboxRetryable() { return runIsRetryable(PBOX.run); }
  function pboxRetryTitle() {
    return (PBOX.run && PBOX.run.resumable)
      ? "Resume this run from its last signed checkpoint"
      : "Restart this run from the beginning";
  }
  function pboxCancel() { if (PBOX.run) runCancel(PBOX.run.run_id, function () { pboxPoll(); }); }
  function pboxRetry() {
    if (PBOX.run) runRetry(PBOX.run.run_id, function () { PBOX.following = ""; pboxPoll(); });  // follow the NEW run
  }
  // #2 RESIZE/MAXIMIZE: the process box is a bottom-right HUD, so a native bottom-right resize handle grows
  // off-screen. A TOP-LEFT grip dragged up/left grows it INTO the screen; the size + maximized state persist.
  function pboxToggleMax() { PBOX.ui.max = !PBOX.ui.max; pboxSaveUI(); pboxRenderShell(); }
  function pboxStartResize(ev) {
    ev.preventDefault();
    var card = V.$(".pb-card"); if (!card) return;
    var sx = ev.clientX, sy = ev.clientY;
    var r = card.getBoundingClientRect(), sw = r.width, sh = r.height;
    var maxW = window.innerWidth * 0.96, maxH = window.innerHeight * 0.90;
    function move(e2) {
      // bottom-right anchored → dragging the grip up/left (negative delta) ENLARGES the box.
      var w = Math.max(260, Math.min(maxW, sw + (sx - e2.clientX)));
      var h = Math.max(150, Math.min(maxH, sh + (sy - e2.clientY)));
      card.style.width = w + "px"; card.style.height = h + "px";
      PBOX.ui.w = Math.round(w); PBOX.ui.h = Math.round(h); PBOX.ui.max = false;
    }
    function up() {
      document.removeEventListener("pointermove", move);
      document.removeEventListener("pointerup", up);
      pboxSaveUI();
    }
    document.addEventListener("pointermove", move);
    document.addEventListener("pointerup", up);
  }

  function pboxRenderShell() {
    var host = pboxHost();
    if (PBOX.ui.dismissed) { host.style.display = "none"; return; }
    host.style.display = "";
    if (!PBOX.ui.open) {
      V.mount(host, h("button.pb-pill#pb-pill" + (pboxIsRunning() ? ".live" : ""), {
        title: "Show live backend activity",
        onClick: function () { PBOX.ui.open = true; pboxSaveUI(); pboxRenderShell(); } },
        [h("span.dot"), pboxIsRunning() ? "Activity" : "Activity · idle"]));
      return;
    }
    var head = h("div.pb-head", null, [
      h("div.pb-title", null, [h("span.dot#pb-run-dot" + (pboxIsRunning() ? ".pb-on" : "")),
        h("b", null, "Activity"),
        PBOX.run ? h("span.pb-run", { title: "the run this is following" },
          (PBOX.run.engagement_label || PBOX.run.slug || PBOX.run.run_id || "")) : null]),
      h("div.pb-btns", null, [
        // W4: control the followed run right where the operator watches it. Cancel while it runs; Resume
        // (a resumable run — continues its checkpoint) / Retry (restart) once it has ended.
        (pboxIsRunning() && PBOX.run && PBOX.run.run_id
          ? h("button.pb-act.pb-cancel", { title: "Stop this run", onClick: pboxCancel }, "Cancel")
          : (pboxRetryable()
            ? h("button.pb-act.pb-retry", { title: pboxRetryTitle(), onClick: pboxRetry },
                (PBOX.run && PBOX.run.resumable) ? "Resume" : "Retry")
            : null)),
        h("button.pb-x", { title: PBOX.ui.max ? "Restore size" : "Maximize",
          "aria-label": PBOX.ui.max ? "Restore activity size" : "Maximize activity",
          onClick: pboxToggleMax }, V.icon(PBOX.ui.max ? "minimize" : "maximize")),
        h("button.pb-x", { title: "Minimize", "aria-label": "Minimize activity",
          onClick: function () { PBOX.ui.open = false; pboxSaveUI(); pboxRenderShell(); } }, "–"),
        h("button.pb-x", { title: "Hide", "aria-label": "Hide activity",
          onClick: function () { PBOX.ui.dismissed = true; pboxSaveUI(); pboxHost().style.display = "none"; } }, "×"),
      ]),
    ]);
    var step = h("div.pb-step" + ((PBOX.run && PBOX.run.status === "paused") ? ".pb-paused"
                 : (pboxIsTerminal() ? ".pb-done" : "")) + "#pb-step", null, pboxStepText() || "waiting…");
    // S1/S1b: pending approvals for the followed run — sovereign (seq-based) AND offense-engage (request_id)
    // cards right in the box, so a chat-launched engage's queued tool is actionable without leaving the chat.
    var sovCards = (PBOX.pendingApprovals && PBOX.pendingApprovals.length)
      ? PBOX.pendingApprovals.map(PBOX_AUX.card) : [];
    var offCards = (PBOX.offenseApprovals && PBOX.offenseApprovals.length)
      ? PBOX.offenseApprovals.map(pboxOffenseCard) : [];
    var allCards = sovCards.concat(offCards);
    var approvals = allCards.length
      ? h("div.pb-approvals", null, [h("div.pb-approvals-h", null, [V.icon("key"), h("span", null, "Waiting for your approval")])]
          .concat(allCards))
      : null;
    var body;
    if (PBOX.run && PBOX.run.stream === "none") {
      body = h("div.pb-feed#pb-feed", null,
        h("div.pb-empty", null, "This run reports inside its own sandbox — its results land in Findings."));
    } else if (!PBOX.events.length) {
      body = h("div.pb-feed#pb-feed", null, h("div.pb-empty", null,
        pboxIsRunning() ? "Waiting for the first step…"
                        : "No active run. Start an assessment and its steps stream here, live."));
    } else {
      body = h("div.pb-feed#pb-feed", null, foldRoutineCritics(PBOX.events.slice(-PBOX_CAP)).map(pboxRow));
    }
    var cardStyle = {};
    if (!PBOX.ui.max && PBOX.ui.w && PBOX.ui.h) { cardStyle.width = PBOX.ui.w + "px"; cardStyle.height = PBOX.ui.h + "px"; }
    var grip = h("div.pb-grip#pb-grip", { title: "Drag to resize" });
    V.mount(host, h("div.pb-card" + (PBOX.ui.max ? ".pb-max" : ""), { style: cardStyle },
      [grip, head, step, approvals, body]));
    var g = V.$("#pb-grip"); if (g) g.addEventListener("pointerdown", pboxStartResize);
    var f = V.$("#pb-feed"); if (f) f.scrollTop = f.scrollHeight;   // land at the newest on (re)open
  }
  function pboxOnEvent(e) {
    if (!e || !e.kind) return;
    if (e.id != null) { if (PBOX.seen[e.id]) return; PBOX.seen[e.id] = 1; }   // dedup a reconnect replay
    PBOX.events.push(e);
    if (PBOX.events.length > PBOX_CAP * 2) {
      PBOX.events = PBOX.events.slice(-PBOX_CAP);
      // keep `seen` bounded too — rebuild it from the retained events. Both streams the box consumes now
      // carry an id: cursor (the blackboard's event id; the progress stream's _seq), and the server
      // resumes from Last-Event-ID, so a reconnect never replays events older than the buffer.
      var s = {}; PBOX.events.forEach(function (x) { if (x.id != null) s[x.id] = 1; }); PBOX.seen = s;
    }
    pboxUpdateChrome();
    if (PBOX.ui.open && !PBOX.ui.dismissed) {
      // A routine critic verdict (about a lead) is folded into a summary row — appending it individually
      // would defeat the fold, so coalesce the burst into ONE full re-render instead of a per-row append.
      if (e.kind === "critic_verdict" && (e.payload || {}).routine) pboxScheduleRender();
      else pboxAppendRow(e);
    }
  }
  function pboxScheduleRender() {
    if (PBOX._renderPending) return;
    PBOX._renderPending = true;
    setTimeout(function () { PBOX._renderPending = false;
      if (PBOX.ui.open && !PBOX.ui.dismissed) pboxRenderShell(); }, 120);
  }
  function pboxDetach() {
    if (PBOX.es) { try { PBOX.es.close(); } catch (e) {} PBOX.es = null; }
    PBOX.events = []; PBOX.seen = {};
  }
  // S1: poll the sovereign-plane pending approvals for the followed run and INTERRUPT with the shared
  // approve/deny/deny-&-redirect modal — so a chat operator never misses a proposal. Live owns the interrupt
  // on its own screen (it has its own AUX + inline cards); everywhere else the global PBOX pops it.
  function pboxApprovalPoll() {
    V.getJSON(SOV("/api/snapshot")).then(function (s) {
      PBOX.pendingApprovals = (s && s.pending_approvals) || [];
      if ((location.hash || "").indexOf("#/live") !== 0) PBOX_AUX.maybePop(PBOX.pendingApprovals);
      if (PBOX.ui.open && !PBOX.ui.dismissed) pboxRenderShell();
    }).catch(function () { /* sovereign plane offline — approvals just won't show */ });
    // S1b: ALSO surface OFFENSE engage approvals. The chat launches an offense `vigil engage`; its queued
    // higher-tier tool is published to the keyless offense broker (OFF /api/approvals/), which the sovereign
    // snapshot above does NOT carry — so without this a chat-launched engage that paused at awaiting_approval
    // would never surface its approval in the chat (the gap this closes).
    V.getJSON(OFF("/api/approvals/loopback")).then(function (d) {
      var had = (PBOX.offenseApprovals || []).length;
      PBOX.offenseApprovals = (d && d.pending) || [];
      PBOX.offenseMem.base = (d && d.base_dir) || PBOX.offenseMem.base;
      // #1: an offense action is BLOCKING the run on your signature — make it impossible to miss. A NEWLY
      // pending approval un-hides + opens the process box so the actionable Approve/Deny card is visible
      // (the operator asked "why can I only SEE 'needs approval', not act on it" — the card lives in the box).
      if (PBOX.offenseApprovals.length && !had) {
        if (PBOX.ui.dismissed) { PBOX.ui.dismissed = false; }
        if (!PBOX.ui.open) { PBOX.ui.open = true; }
        pboxSaveUI(); pboxHost().style.display = "";
      }
      if ((location.hash || "").indexOf("#/live") !== 0) pboxOffenseMaybePop(PBOX.offenseApprovals);
      if (PBOX.ui.open && !PBOX.ui.dismissed) pboxRenderShell();
    }).catch(function () { /* offense plane offline — offense approvals just won't show */ });
  }
  function pboxFollow(run) {
    // (re)subscribe to a run's live feed. Held in PBOX.es (never liveES), so a route change can't kill it.
    pboxDetach();
    // A new RUNNING run re-shows a box the operator had hidden — HUD parity (a "Hide" is per-lull, not a
    // permanent kill). It comes back as whatever it was (pill if collapsed), never force-expanded.
    if (run && PBOX.ui.dismissed) { PBOX.ui.dismissed = false; pboxSaveUI(); }
    PBOX.run = run; PBOX.following = run ? run.run_id : "";
    PBOX_AUX.reset();   // S1: re-baseline approvals for the newly-followed run
    pboxOffenseReset(); // S1b: re-baseline OFFENSE approvals too
    if (run && run.stream === "blackboard" && run.slug) {
      PBOX.es = V.sse(OFF("/api/blackboard?slug=" + encodeURIComponent(run.slug)), pboxOnEvent, function () {});
    } else if (run && run.stream === "progress") {
      // from_start: the tailer defaults to EOF, so a box attaching mid-run (or to a run that just ended)
      // would show nothing. The ring buffer caps what is kept, so replaying the file is bounded.
      PBOX.es = V.sse(OFF("/api/events?run=" + encodeURIComponent(run.run_id) + "&from_start=1"), function (ev) {
        // pboxOnEvent dedups on e.id, which a progress event does not have — carry the stream's _seq
        // cursor onto the normalised event so a reconnect can't duplicate rows in the ring buffer.
        var norm = pboxProgressToEvent(ev);
        if (norm) { if (ev && ev._seq != null) norm.id = "p" + ev._seq; pboxOnEvent(norm); }
      }, function () {});
    }
    // stream 'none' (strix/aegis): no live spine — the chrome poll keeps its status fresh.
    pboxRenderShell();
  }
  function pboxProgressToEvent(ev) {
    if (!ev) return null;
    // Integration-engine OODA mirror (bridge): a progress line already in spine shape ({kind, payload})
    // passes straight through so `vigil engage`'s full timeline renders in the process box via KIND_META.
    if (ev.kind && KIND_META[ev.kind]) return { kind: ev.kind, payload: ev.payload || {} };
    if (!ev.event) return null;
    if (ev.event === "scan.phase") return { kind: "observation", payload: { source: "scan", summary: "phase: " + (ev.phase || "") } };
    if (ev.event === "scan.finding") return { kind: "finding", payload: { bug_class: ev.bug_class, title: (ev.param || "") + " @ " + (ev.endpoint || "") } };
    if (ev.event === "scan.done") return { kind: "decision", payload: { question: "scan complete", choice: (ev.findings || 0) + " findings" } };
    // W6c — a codebase (Strix) run's own progress. Normalise into the SAME spine-shaped events the box
    // already renders, so pboxTag/pboxRow need no change:
    //  • warden.block → a "refusal" event: the box tags it "blocked" and both the row summary
    //    (KIND_META.refusal) and the step line read "blocked by warden: <tool> — <reason>", so the
    //    operator sees WHAT was blocked and WHY. (The reason is carried by both. NB: this repo runs
    //    no JS test suite, so the UI half of this slice is checked by `node --check` only.)
    if (ev.event === "warden.block") return { kind: "refusal", payload: {
      gate: ev.gate || "warden", action_refused: ev.action_refused || "",
      reason: ev.reason || "", fatal: !!ev.fatal } };
    //  • strix.graph → an "observation": a compact "N agents (running:2, done:1)" heartbeat.
    if (ev.event === "strix.graph") {
      var st = ev.statuses || {}, parts = [];
      Object.keys(st).forEach(function (k) { parts.push(k + ":" + st[k]); });
      return { kind: "observation", payload: { source: "strix",
        summary: (ev.agents || 0) + " agent" + ((ev.agents === 1) ? "" : "s")
                 + (parts.length ? " (" + parts.join(", ") + ")" : "") } };
    }
    return null;
  }
  function pboxPickRun(runs) {
    // the newest RUNNING run wins (list_runs is newest-first); else nothing to follow.
    for (var i = 0; i < runs.length; i++) if (runs[i] && runs[i].status === "running") return runs[i];
    return null;
  }
  function pboxPoll() {
    // GLOBAL box → all runs, unscoped (never the active-engagement filter).
    fetch(OFF("/api/runs"), { headers: (function () { var hh = { "X-Requested-With": "vigil-ui" }; var t = V.token(); if (t) hh["X-SIGIL-Token"] = t; return hh; })(),
      credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        var runs = (d && d.runs) || [];
        var run = pboxPickRun(runs);
        if (run) {
          if (run.run_id !== PBOX.following) pboxFollow(run);   // a new/changed RUNNING run → resubscribe
          else { PBOX.run = run; pboxUpdateChrome(); }          // same run → refresh its status only
        } else {
          // no running run: close the (now-silent) stream but KEEP the last run's steps on screen, and
          // reflect its final status (done / error / interrupted) so the operator sees how it ended.
          if (PBOX.es) { try { PBOX.es.close(); } catch (e) {} PBOX.es = null; }
          if (PBOX.following) {
            var last = runs.find(function (x) { return x.run_id === PBOX.following; });
            if (last) PBOX.run = last;
          }
          pboxUpdateChrome();
        }
      })
      .catch(function () { /* offense plane down — the box just shows idle */ });
  }
  function startProcessBox() {
    pboxLoadUI();
    pboxRenderShell();
    pboxPoll();
    pboxApprovalPoll();
    PBOX.poll = setInterval(function () { if (!document.hidden) { pboxPoll(); pboxApprovalPoll(); } }, 4000);
  }

  // ---- boot ------------------------------------------------------------------
  // ---- Compliance & ATT&CK (C3): map proven findings → standards controls ----
  var CMP = { run: "", runs: [], data: null, loaded: false };
  function renderCompliance(screen) {
    var body = V.mount(screen, [h("div.screen-head", null, [
      h("h2", null, "Compliance & ATT&CK"),
      h("p.sub", null, "Every oracle-confirmed FACT mapped to OWASP / CWE / PCI-DSS / SOC 2 / ISO 27001 + "
        + "MITRE ATT&CK. A lead never asserts control coverage — only a proven fact does.")])]);
    V.getJSON(runsURL()).then(function (d) {
      CMP.runs = runsOf(d); CMP.loaded = true;   // scoped to the active engagement
      // this screen's selection outlives a route change, so a run picked under a previous scope has to go
      if (CMP.run && !CMP.runs.some(function (r) { return r.run_id === CMP.run; })) { CMP.run = ""; CMP.data = null; }
      if (!CMP.run && CMP.runs.length) CMP.run = CMP.runs[0].run_id;
      loadCompliance(body);
    }).catch(function () { CMP.runs = []; CMP.loaded = false; loadCompliance(body); });
  }
  function loadCompliance(body) {
    if (!CMP.run) { drawCompliance(body); return; }
    V.getJSON(OFF("/api/compliance/" + encodeURIComponent(CMP.run))).then(function (d) {
      CMP.data = d; drawCompliance(body);
    }).catch(function () { CMP.data = null; drawCompliance(body); });
  }
  function _ctrlPills(c) {
    var out = [];
    if (c.owasp) out.push(h("span.pill.sm", null, "OWASP " + c.owasp));
    (c.cwe || []).slice(0, 3).forEach(function (x) { out.push(h("span.pill.sm", null, x)); });
    (c.attack || []).slice(0, 3).forEach(function (x) { out.push(h("span.pill.sm.warn", null, "ATT&CK " + x)); });
    (c.pci_dss || []).slice(0, 2).forEach(function (x) { out.push(h("span.pill.sm", null, "PCI " + x)); });
    return out;
  }
  function drawCompliance(body) {
    var d = CMP.data || {};
    if (CMP.loaded && !CMP.runs.length && activeEngagement()) {
      V.mount(body, scopedEmpty("runs", "Nothing has run under this job yet — a run's proven facts map to standards controls here.", [newAssessBtn()]));
      return;
    }
    var picker = h("div.card", null, [h("label", { style: { marginRight: "8px" } }, "Run"),
      h("select", { onChange: function (e) { CMP.run = e.target.value; loadCompliance(body); } },
        [h("option", { value: "", selected: !CMP.run }, "— select a run —")].concat(
          CMP.runs.map(function (r) {
            return h("option", { value: r.run_id, selected: r.run_id === CMP.run }, (r.slug || r.run_id));
          })))]);
    var rows = (d.findings || []).map(function (f) {
      var proven = f.status === "proven";
      var badge = proven
        ? h("span.st.st-confirmed", null, [h("span.dot"), "proven"])
        : h("span.st.st-idle", null, [h("span.dot"), (f.status || "advisory")]);
      var ctrls = proven && f.controls ? _ctrlPills(f.controls)
        : [h("span.hint", null, "advisory note only — a lead / unmapped class asserts no control coverage")];
      return h("div.kv", null, [
        h("div.k", null, [badge, " ", (f.bug_class || f.finding_ref || "?")]),
        h("div.v", null, ctrls)]);
    });
    V.mount(body, [picker,
      h("div.card", null, [h("div.card-h", null, [h("h3", null, "Findings → standards controls")]),
        (rows.length ? h("div", null, rows)
          : h("div.empty", null, d.pending ? "run pending — no re-verifiable findings yet"
            : "no findings for this run (only proven facts assert coverage)"))]),
      h("div.hint", { style: { marginTop: "10px" } }, d.doctrine || "")]);
  }

  // ---- Charter & Attestation (owner): authorization + who/when/what ledger ----
  var CHT = { slug: "loopback", auth: null, ledger: null, remoteTarget: "" };
  // Advisory client-side scope check — the AUTHORITATIVE gate is server-side; this only GUIDES the operator.
  function _scopeCovers(scope, target) {
    target = String(target || "").trim().toLowerCase();
    if (!target) return false;
    return (scope || []).some(function (host) {
      host = String(host || "").trim().toLowerCase();
      if (!host) return false;
      if (host === target) return true;
      if (host.charAt(0) === "*") {                 // *.example.com — a wildcard grant
        var suf = host.replace(/^\*\.?/, "");
        return suf && (target === suf || target.slice(-(suf.length + 1)) === ("." + suf));
      }
      return false;
    });
  }
  function renderCharter(screen) {
    var body = V.mount(screen, [h("div.screen-head", null, [
      h("h2", null, "Charter & Attestation"),
      h("p.sub", null, "Every target-touching action is gated on a signed engagement charter + a who/when/what "
        + "usage attestation minted BEFORE anything runs — no attestation, no run. This UI provisions a "
        + "LOOPBACK authority; a REMOTE target needs a signed charter this UI cannot mint — it VERIFIES + "
        + "guides you through the out-of-band ceremony instead.")])]);
    drawCharter(body);
    loadAuthority(body);
  }
  function loadAuthority(body) {
    V.getJSON(OFF("/api/charter/" + encodeURIComponent(CHT.slug)))
      .then(function (d) { CHT.auth = d; drawCharter(body); })
      .catch(function () { CHT.auth = null; drawCharter(body); });
  }
  function drawCharter(body) {
    var a = CHT.auth || {};
    var scope = a.scope || [];
    var win = a.window || {};
    var slugRow = h("div.card", null, [
      h("label", { style: { marginRight: "8px" } }, "Engagement slug"),
      h("input#cht-slug", { type: "text", value: CHT.slug, style: { width: "220px" },
        onChange: function (e) { CHT.slug = (e.target.value || "").trim(); } }),
      h("button.btn.sm", { style: { marginLeft: "8px" }, onClick: function () {
        var el = V.$("#cht-slug"); CHT.slug = (el && el.value || "").trim(); loadAuthority(body); } }, "Load")]);
    var status = h("div.card", null, [h("div.card-h", null, [h("h3", null, "Authorization status")]),
      h("div.kv", null, [h("div.k", null, "Charter present"),
        h("div.v", null, a.charter_present
          ? h("span.st.st-confirmed", null, [h("span.dot"), "yes"])
          : h("span.st.st-idle", null, [h("span.dot"), "no — provision loopback below, or add a charter file"]))]),
      h("div.kv", null, [h("div.k", null, "Authorized scope"),
        h("div.v", null, (scope.length ? scope.map(function (x) { return h("span.pill.sm", null, x); })
          : [h("span.hint", null, "no authority yet")]))]),
      h("div.kv", null, [h("div.k", null, "Reach"),
        h("div.v", null, a.has_remote_authority
          ? h("span.st.st-confirmed", null, [h("span.dot"), "REMOTE authorized — " + (a.remote_hosts || []).join(", ")])
          : (a.is_loopback_only
              ? h("span.st.st-idle", null, [h("span.dot"), "loopback only (127.0.0.1)"])
              : h("span.st.st-idle", null, [h("span.dot"), "none"])))]),
      h("div.kv", null, [h("div.k", null, "Window"),
        h("div.v", null, String((win.not_after ? (win.not_before || "—") + " → " + win.not_after : "—")
          + (win.environment ? "  (" + win.environment + ")" : "")))]),
      h("div.kv", null, [h("div.k", null, "Gate chain"),
        h("div.v", null, (a.gates || []).map(function (g) { return h("span.pill.sm", null, g); }))])]);
    var provision = h("div.card.owner", null, [h("div.card-h", null, [h("h3", null, "Provision a loopback authority")]),
      h("div.hint", { style: { marginBottom: "8px" } },
        "Mints + signs a CRUCIBLE authority for this slug, scope HARD-FIXED to 127.0.0.1. For a REMOTE target, "
        + "use the section below — this UI can never mint or widen a remote charter."),
      h("button.btn.sm.owner", { onClick: function () {
        V.postJSON(OFF("/api/authority/provision"), { slug: CHT.slug }).then(function (r) {
          if (r && r.ok) { V.toast("Provisioned a loopback authority for " + CHT.slug); loadAuthority(body); }
          else { V.toast((r && r.error) || "provision failed", true); }
        }).catch(function () { V.toast("provision failed", true); }); } }, "Provision (loopback only)")]);
    // ---- Remote target: the UI VERIFIES + guides, never mints ----
    var covered = CHT.remoteTarget ? _scopeCovers(scope, CHT.remoteTarget) : null;
    var remoteCard = h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Remote target — charter required (out-of-band)")]),
      h("div.hint", { style: { marginBottom: "8px" } },
        String(a.remote_note || "A REMOTE target needs a signed charter minted OUT-OF-BAND on a trusted host "
          + "that holds the owner key. This UI can never mint or widen a remote charter — it verifies + guides.")),
      h("div.kv", null, [h("div.k", null, "Target host"),
        h("div.v", null, h("input#cht-remote", { type: "text", placeholder: "app.example.com",
          value: CHT.remoteTarget, style: { width: "260px" },
          onChange: function (e) { CHT.remoteTarget = (e.target.value || "").trim(); drawCharter(body); } }))]),
      (CHT.remoteTarget ? h("div.kv", null, [h("div.k", null, "Authorized for this target?"),
        h("div.v", null, covered
          ? h("span.st.st-confirmed", null, [h("span.dot"), "yes — a signed charter authorizes this target (advisory; the gate enforces)"])
          : h("span.st.st-idle", null, [h("span.dot"), "NOT authorized — mint a charter out-of-band (below), then Re-check"]))]) : null),
      h("div.kv", null, [h("div.k", null, "Out-of-band ceremony"),
        h("div.v", null, [
          h("div.hint", { style: { marginBottom: "4px" } },
            "Run this on a TRUSTED host that holds the owner key — NOT in this UI:"),
          h("code", { style: { fontSize: "12px", whiteSpace: "pre-wrap", display: "block" } },
            "vigil provision --slug " + (CHT.slug || "<slug>") + " --scope "
            + (CHT.remoteTarget || "<REMOTE-HOST[,HOST2,...]>"))])]),
      h("button.btn.sm", { style: { marginTop: "6px" }, onClick: function () { loadAuthority(body); } },
        "Re-check charter")]);
    var ledgerCard = h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Usage attestation ledger — who / when / what")]),
      h("button.btn.sm", { onClick: function () {
        V.postJSON(OFF("/api/authority/ledger"), {}).then(function (r) { CHT.ledger = r; drawCharter(body); })
          .catch(function () { CHT.ledger = { error: "failed to load ledger" }; drawCharter(body); }); } },
        "Load ledger + verify chain"),
      (CHT.ledger ? h("div", { style: { marginTop: "8px" } }, [
        h("div.kv", null, [h("div.k", null, "Chain verified"),
          h("div.v", null, CHT.ledger.verified
            ? h("span.st.st-confirmed", null, [h("span.dot"), "verified — signed, monotonic, not back-dated"])
            : h("span.st.st-idle", null, [h("span.dot"), "unverified"]))]),
        h("pre", { style: { whiteSpace: "pre-wrap", fontSize: "12px", marginTop: "6px", overflowX: "auto" } },
          String(CHT.ledger.who || CHT.ledger.error || "no records yet"))]) : null)]);
    V.mount(body, [slugRow, status, provision, remoteCard, ledgerCard,
      h("div.hint", { style: { marginTop: "10px" } },
        String(a.note || CHT.ledger && CHT.ledger.note
          || "No attestation, no run. The UI can never widen a charter-signed scope."))]);
  }

  // ---- Report (C4): a live, re-verified, proof-carrying client report ----
  var RPT = { run: "", runs: [], ev: null, cmp: null, loaded: false };
  // R3 — one-click download: build the run's tamper-evident dossier (CSRF-guarded POST), then stream the
  // pre-built ZIP via an <a download> click (Content-Disposition attachment — the first client download).
  function downloadDossier(runId, btn, statusEl) {
    if (!runId) { V.toast("Pick a run first.", true); return; }
    if (btn) btn.disabled = true;
    if (statusEl) V.mount(statusEl, h("div.dim", null, "Packaging the dossier (reports + proof bundle + signed manifest)…"));
    V.postJSON(OFF("/api/dossier/" + encodeURIComponent(runId) + "/build"), {})
      .then(function (r) {
        if (btn) btn.disabled = false;
        if (r && r.error) { if (statusEl) V.mount(statusEl, h("div.legend", null, [V.icon("info"), r.error])); return; }
        var a = document.createElement("a");
        // A download navigation cannot set a request header, so the session token rides the query
        // string (the same carrier the SSE streams use) — a credentialed console 401s otherwise.
        a.href = V.authUrl(OFF("/api/dossier/" + encodeURIComponent(runId) + ".zip"));
        a.download = "vigil-dossier-" + runId + ".zip";
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        if (statusEl) V.mount(statusEl, [
          h("div.legend", null, [V.icon("check"), "Dossier downloaded — tamper-evident + offline-verifiable."]),
          r.note ? h("div.hint", null, r.note) : null,
        ]);
        V.toast("Dossier downloaded.");
      })
      .catch(function (e) { if (btn) btn.disabled = false; if (statusEl) V.mount(statusEl, h("div.legend", null, [V.icon("x"), (e && e.message) || "dossier failed"])); });
  }

  // A filename-safe timestamp for client-side exports (e.g. 2026-08-12T14-05-33).
  function nowStamp() {
    try { return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19); }
    catch (e) { return String(Date.now()); }
  }
  // Client-side JSON export: serialize an ALREADY-FETCHED read-only view to a file the operator can save
  // or hand to an offline verifier. Pure browser (Blob) — no backend, no new endpoint, no new data exposure
  // (it only re-packages what the screen already displays).
  function downloadJSON(filename, obj) {
    try {
      var blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 0);
      V.toast("Downloaded " + filename);
    } catch (e) { V.toast("Could not export: " + ((e && e.message) || "error"), true); }
  }

  function renderReport(screen) {
    var body = V.mount(screen, [h("div.screen-head", null, [
      h("h2", null, "Client Report"),
      h("p.sub", null, "A LIVE, always-current report: every finding is re-verified OFFLINE on load, so a "
        + "FACT is a re-checkable certificate — not a stale PDF, and not the AI's word. Read-only.")])]);
    V.getJSON(runsURL()).then(function (d) {
      RPT.runs = runsOf(d); RPT.loaded = true;   // scoped to the active engagement
      if (RPT.run && !RPT.runs.some(function (r) { return r.run_id === RPT.run; })) { RPT.run = ""; RPT.ev = null; RPT.cmp = null; }
      if (!RPT.run && RPT.runs.length) RPT.run = RPT.runs[0].run_id;
      loadReport(body);
    }).catch(function () { RPT.runs = []; RPT.loaded = false; loadReport(body); });
  }
  function loadReport(body) {
    if (!RPT.run) { drawReport(body); return; }
    var run = encodeURIComponent(RPT.run);
    Promise.all([
      V.getJSON(OFF("/api/evidence/" + run)).catch(function () { return null; }),
      V.getJSON(OFF("/api/compliance/" + run)).catch(function () { return null; })
    ]).then(function (r) { RPT.ev = r[0]; RPT.cmp = r[1]; drawReport(body); });
  }
  function drawReport(body) {
    if (RPT.loaded && !RPT.runs.length && activeEngagement()) {
      V.mount(body, scopedEmpty("runs", "Nothing has run under this job yet — a run's re-verified findings become its client report here.", [newAssessBtn()]));
      return;
    }
    var ev = RPT.ev || {}, cmp = RPT.cmp || {};
    var findings = ev.findings || [];
    var proven = findings.filter(function (f) { return f.sound; });
    var ctrlByClass = {};
    (cmp.findings || []).forEach(function (m) {
      if (m.status === "proven" && m.controls) ctrlByClass[m.bug_class] = m.controls; });
    function runSel() {
      return h("select", { onChange: function (e) { RPT.run = e.target.value; loadReport(body); } },
        [h("option", { value: "" }, "— select a run —")].concat(
          RPT.runs.map(function (r) {
            return h("option", { value: r.run_id, selected: r.run_id === RPT.run }, (r.slug || r.run_id)); })));
    }
    var exec = h("div.card", null, [h("div.card-h", null, [h("h3", null, "Executive summary")]),
      h("div.kv", null, [h("div.k", null, "Findings re-verified"),
        h("div.v", null, (ev.reproduced || 0) + " sound of " + (ev.total || 0) + " total")]),
      h("div.hint", { style: { marginTop: "6px" } },
        "Every 'sound' finding below carries a certificate anyone can re-check OFFLINE — no target, no trust "
        + "in this tool. " + (ev.doctrine || ""))]);
    var cards = proven.map(function (f) {
      var c = ctrlByClass[f.bug_class];
      return h("div.card", null, [
        h("div.card-h", null, [h("h3", null, (f.bug_class || f.ref)),
          h("span.st.st-confirmed", { style: { marginLeft: "auto" } },
            [h("span.dot"), "PROVEN — cert re-verified"])]),
        h("div.kv", null, [h("div.k", null, "Surface"), h("div.v", null, (f.surface || "—"))]),
        h("div.kv", null, [h("div.k", null, "Oracle"),
          h("div.v", null, (f.confirmed_by || "—") + " · confidence " + (f.confidence != null ? f.confidence : "—"))]),
        (f.cert_id ? h("div.kv", null, [h("div.k", null, "Certificate"),
          h("div.v", null, h("code", null, String(f.cert_id).slice(0, 28) + "…"))]) : null),
        (c ? h("div.kv", null, [h("div.k", null, "Standards"), h("div.v", null, _ctrlPills(c))]) : null)]);
    });
    V.mount(body, [h("div.card", null, [
        h("label", { style: { marginRight: "8px" } }, "Run"), runSel(),
        RPT.run ? h("button.btn.sm#dossier-btn", { style: { marginLeft: "12px" },
          onClick: function () { downloadDossier(RPT.run, V.$("#dossier-btn"), V.$("#dossier-status")); } },
          "⤓ Download dossier") : null,
        h("div#dossier-status", { style: { marginTop: "8px" } }),
      ]),
      exec,
      (proven.length ? h("div", null, cards)
        : h("div.card", null, [h("div.empty", null,
            ev.error ? "could not re-verify this run" : "no proven findings yet for this run")]))]);
  }

  // ---- Assurance (C2): continuous proof / drift between two runs ----
  var ASR = { curr: "", prev: "", runs: [], data: null, telemetry: null, loaded: false };
  function renderAssurance(screen) {
    var body = V.mount(screen, [h("div.screen-head", null, [
      h("h2", null, "Assurance — continuous proof / drift"),
      h("p.sub", null, "Diff the ORACLE-CONFIRMED fact set between two runs: a fact that newly appears is a "
        + "regression (a new exposure); one that disappears is a fix. Deterministic + offline — each run's "
        + "certificates are re-fired, never re-attacked. A lead is never counted.")])]);
    // B3: the live assurance/metrics PROJECTION over the signed spine (read-only, mints nothing). One-way —
    // no new authority, no scope widening. A separate fetch so a missing collector never blocks the drift view.
    ASR.telemetry = null;
    V.getJSON(OFF("/api/telemetry")).then(function (t) { ASR.telemetry = t; drawAssurance(body); })
      .catch(function () { ASR.telemetry = { ok: false }; drawAssurance(body); });
    V.getJSON(runsURL()).then(function (d) {
      ASR.runs = runsOf(d); ASR.loaded = true;   // scoped: drift is only ever diffed WITHIN one job
      var mine = function (id) { return !!id && ASR.runs.some(function (r) { return r.run_id === id; }); };
      if (ASR.curr && !mine(ASR.curr)) { ASR.curr = ""; ASR.data = null; }
      if (ASR.prev && !mine(ASR.prev)) ASR.prev = "";
      if (!ASR.curr && ASR.runs.length) ASR.curr = ASR.runs[0].run_id;
      if (!ASR.prev && ASR.runs.length > 1) ASR.prev = ASR.runs[1].run_id;
      loadAssurance(body);
    }).catch(function () { ASR.runs = []; ASR.loaded = false; loadAssurance(body); });
  }
  function loadAssurance(body) {
    if (!ASR.curr) { drawAssurance(body); return; }
    var arg = encodeURIComponent(ASR.curr + (ASR.prev ? (":" + ASR.prev) : ""));
    V.getJSON(OFF("/api/drift/" + arg)).then(function (d) { ASR.data = d; drawAssurance(body); })
      .catch(function () { ASR.data = null; drawAssurance(body); });
  }
  function drawAssurance(body) {
    var d = ASR.data || {};
    if (ASR.loaded && !ASR.runs.length && activeEngagement()) {
      V.mount(body, scopedEmpty("runs", "Drift is a diff between two runs of the SAME job, and this one has none yet — run it twice and the second run is checked against the first.", [newAssessBtn()]));
      return;
    }
    function runSel(which) {
      return h("select", { onChange: function (e) { ASR[which] = e.target.value; loadAssurance(body); } },
        [h("option", { value: "" }, "— none —")].concat(
          ASR.runs.map(function (r) {
            return h("option", { value: r.run_id, selected: r.run_id === ASR[which] }, (r.slug || r.run_id));
          })));
    }
    var reverifyBtn = h("button.btn.sm", { style: { marginLeft: "14px" }, onClick: function () {
      // Re-fire the retained certificates for this pair (pure offline re-computation — no traffic).
      V.toast("Re-verifying — re-firing the retained certificates offline…");
      loadAssurance(body);
    } }, [V.icon("check"), "Re-verify now"]);
    var dlBtn = h("button.btn.sm", { style: { marginLeft: "8px" }, onClick: function () {
      if (!ASR.data || ASR.data.pending) { V.toast("Select two runs with re-verifiable findings first.", true); return; }
      downloadJSON("vigil-drift-" + nowStamp() + ".json", ASR.data);
    } }, [V.icon("book"), "Download drift (JSON)"]);
    var picker = h("div.card", null, [
      h("label", { style: { marginRight: "6px" } }, "Now"), runSel("curr"),
      h("label", { style: { margin: "0 6px 0 14px" } }, "vs baseline"), runSel("prev"),
      reverifyBtn, dlBtn]);
    function list(title, ids, cls) {
      return h("div.card", null, [h("div.card-h", null, [h("h3", null, title + " (" + ids.length + ")")]),
        (ids.length
          ? h("div", null, ids.slice(0, 100).map(function (x) {
              return h("div.kv", null, [h("div.k", null, h("span.pill.sm" + cls, null, String(x)))]); }))
          : h("div.empty", null, "none"))]);
    }
    var summary = d.pending
      ? h("div.empty", null, "select a run (no re-verifiable findings yet)")
      : h("div", null, [
          (d.has_drift
            ? h("span.st.st-idle", null, [h("span.dot"), "drift detected"])
            : h("span.st.st-confirmed", null, [h("span.dot"), "no drift — same proven set"])),
          list("Regressions — newly-proven exposures", d.regressions || [], ".danger"),
          list("Fixed — no longer proven", d.fixed || [], ""),
          list("Stable — proven in both", d.stable || [], "")]);
    // Wave 2 (parity) — run the spine/ledger integrity self-checks from the browser (read-only, no traffic).
    var vout = h("div", null, "");
    function showVerify(title, promise) {
      V.mount(vout, h("div.hint", { style: { marginTop: "8px" } }, title + ": running…"));
      promise.then(function (r) {
        var okv = !!(r && r.ok);
        var lines = [];
        if (r && typeof r.chain_ok !== "undefined") {   // the sovereign spine verify (chain + head)
          lines.push((r.chain_ok ? "chain OK" : "chain FAIL") + " — " + (r.chain_detail || ""));
          lines.push((r.head_present ? (r.head_ok ? "head OK" : "head FAIL") : "head —") + " — " + (r.head_detail || ""));
        } else if (r && r.text) { lines.push(r.text); }
        else if (r && r.error) { lines.push(r.error); }
        else if (r && r.checks) { lines = r.checks.map(function (c) { return (c.ok ? "OK  " : "FAIL ") + c.id + " — " + (c.detail || ""); }); }
        V.mount(vout, h("div.set-status" + (okv ? ".ok" : ".danger"), { style: { marginTop: "8px", flexDirection: "column", alignItems: "stretch" } }, [
          h("div", null, [V.icon(okv ? "check" : "x"), h("span", null, " " + title + ": " + (okv ? "VERIFIED" : "FAILED"))]),
          lines.length ? h("pre.mono", { style: { marginTop: "6px", whiteSpace: "pre-wrap", fontSize: "12px", maxHeight: "240px", overflow: "auto" } }, lines.join("\n")) : null,
        ]));
      }).catch(function (e) {
        V.mount(vout, h("div.set-status.danger", { style: { marginTop: "8px" } }, title + ": " + ((e && e.message) || e)));
      });
    }
    var integrityCard = h("div.card", null, [
      h("div.card-h", null, [h("h3", null, "Integrity & verify")]),
      h("div.hint", null, "Run the spine / ledger integrity self-checks from the browser — read-only, no traffic. "
        + "The offense verbs shell `vigil` on the offense plane; the sovereign spine verify runs in-process."),
      h("div.acts", { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "10px" } }, [
        h("button.btn.sm", { onClick: function () { showVerify("Offense integrity", V.postJSON(OFF("/api/verify"), { kind: "integrity" })); } }, [V.icon("shield"), "Verify integrity"]),
        h("button.btn.sm", { onClick: function () { showVerify("Offense ledger", V.postJSON(OFF("/api/verify"), { kind: "ledger" })); } }, [V.icon("check"), "Verify ledger"]),
        h("button.btn.sm", { onClick: function () { showVerify("Offense spine segments", V.postJSON(OFF("/api/verify"), { kind: "spine" })); } }, [V.icon("check"), "Verify spine segments"]),
        h("button.btn.sm", { onClick: function () { showVerify("Sovereign spine", V.getJSON(SOV("/api/verify"))); } }, [V.icon("shield"), "Verify sovereign spine"]),
      ]),
      vout,
    ]);
    V.mount(body, [telemetryCard(), picker, integrityCard, summary, h("div.hint", { style: { marginTop: "10px" } }, d.doctrine || "")]);
  }

  // B3: the live assurance/metrics PROJECTION — a read-only, one-way view of the signed spine the
  // `vigil up --with-telemetry` collector materializes (per-engagement FACT/LEAD/refusal/tool counts + a
  // by-kind histogram + totals). It confers NO authority and widens NO scope — it only reflects what the
  // oracle + gate already recorded. The telemetry snapshot exposes counts, not a graph; the attack-path /
  // asset graph is per-run (World Model on the Findings screen), so this panel does not fabricate one.
  function telemetryCard() {
    var t = ASR.telemetry;
    if (!t) return h("div.card", null, [h("div.card-h", null, [h("h3", null, "Live assurance projection")]),
      h("div.empty", null, "Loading telemetry…")]);
    var head = h("div.card-h", null, [h("h3", null, "Live assurance projection"),
      (t.running
        ? h("span.st.st-confirmed", { style: { marginLeft: "auto" } }, [h("span.dot"), "collector running"])
        : h("span.st.st-idle", { style: { marginLeft: "auto" } }, [h("span.dot"), "collector not running"]))]);
    var intro = h("div.hint", { style: { marginBottom: "8px" } },
      "A read-only, one-way projection of the signed spine — it mints no fact and widens no scope; it only "
      + "reflects what the oracle and gate already recorded.");
    if (!t.running) {
      return h("div.card", null, [head, intro,
        h("div.empty", null, (t.note || "The telemetry collector is not running.")
          + " Metrics still compute on demand elsewhere; start the live projection with `vigil up --with-telemetry`.")]);
    }
    var tot = t.totals || {};
    var tiles = h("div.grid.cols-4", { style: { marginTop: "4px", marginBottom: "10px" } }, [
      V.tile("Facts", String(tot.facts || 0), "oracle-confirmed"),
      V.tile("Leads", String(tot.leads || 0), "unconfirmed"),
      V.tile("Refusals", String(tot.refusals || 0), "gates fired"),
      V.tile("Tool calls", String(tot.tool_calls || 0), "actions"),
    ]);
    var engs = (t.engagements || []);
    var perEng = engs.length
      ? h("div", null, engs.map(function (e) {
          return h("div.kv", null, [h("div.k", null, String(e.slug || "?")),
            h("div.v", null, [
              h("span.pill.sm", null, (e.facts || 0) + " FACT"),
              h("span.pill.sm", { style: { marginLeft: "4px" } }, (e.leads || 0) + " lead"),
              h("span.pill.sm.warn", { style: { marginLeft: "4px" } }, (e.refusals || 0) + " refused"),
              h("span.hint", { style: { marginLeft: "6px" } }, (e.events || 0) + " events")])]);
        }))
      : h("div.empty", null, "No engagements on the spine yet.");
    var byKind = tot.by_kind || {};
    var kinds = Object.keys(byKind).sort(function (a, b) { return byKind[b] - byKind[a]; });
    var histo = kinds.length
      ? h("div", { style: { display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "8px" } },
          kinds.map(function (k) { return h("span.pill.sm", null, k + " · " + byKind[k]); }))
      : null;
    return h("div.card", null, [head, intro, tiles,
      h("div.card-h", null, [h("h3", null, "Per engagement")]), perEng,
      histo ? h("div.card-h", { style: { marginTop: "8px" } }, [h("h3", null, "By kind")]) : null, histo,
      h("div.hint", { style: { marginTop: "8px" } },
        "Attack-path / asset graphs are per-run — see the World Model on the Findings screen.")]);
  }

  // ---- Proof Studio (B5): oracle-confirmed, signed, replayable exploit proofs ----
  var PRF = { run: "", runs: [], data: null, loaded: false };
  function renderProof(screen) {
    var body = V.mount(screen, [h("div.screen-head", null, [
      h("h2", null, "Proof Studio"),
      h("p.sub", null, "Strix generates an exploit; VIGIL turns it into PROOF. A FACT here means a "
        + "deterministic oracle FIRED over the executor-captured raw bytes of the reproduction — not the "
        + "model's word. A LEAD is an honest 'not reproduced'. A DENIED proof had dangerous PoC content "
        + "refused BEFORE any mint. Read-only.")])]);
    V.getJSON(runsURL()).then(function (d) {
      PRF.runs = runsOf(d); PRF.loaded = true;   // scoped to the active engagement
      if (PRF.run && !PRF.runs.some(function (r) { return r.run_id === PRF.run; })) { PRF.run = ""; PRF.data = null; PRF.exported = null; }
      if (!PRF.run && PRF.runs.length) PRF.run = PRF.runs[0].run_id;
      loadProof(body);
    }).catch(function () { PRF.runs = []; PRF.loaded = false; loadProof(body); });
  }
  function loadProof(body) {
    if (!PRF.run) { drawProof(body); return; }
    V.getJSON(OFF("/api/proof/" + encodeURIComponent(PRF.run))).then(function (d) {
      PRF.data = d; drawProof(body);
    }).catch(function () { PRF.data = null; drawProof(body); });
  }
  // inv 12 (S9): a degraded proof subsystem must NOT read like a clean run. Each typed disposition
  // gets its own plain-language line so a degraded-with-zero-records run is VISIBLY different from an
  // honest "nothing found". Keyed on d.disposition (never on d.pending, which conflated the four).
  var PROOF_DEG_LABEL = {
    proof_subsystem_unavailable: "The proof subsystem never came up on this run (bootstrap / gateway / Caido down). NO finding here could be verified — this is NOT a clean result.",
    capture_failed: "Evidence capture failed for at least one finding, so it could not reach a FACT — this is NOT a clean result.",
    redrive_failed: "A gated web re-drive could not RUN (gateway down / network crash / import error), so a finding could not be verified — this is NOT a clean result.",
    mint_failed: "The proof mint crashed for at least one captured finding, so it could not reach a FACT — this is NOT a clean result."
  };
  function proofEmptyText(d) {
    // Branch on the typed disposition, NEVER on d.pending — an empty proof list means four different
    // things and each must read differently. The four degraded dispositions are never "nothing found".
    switch (d.disposition) {
      case "proof_subsystem_unavailable":
      case "capture_failed":
      case "redrive_failed":
      case "mint_failed":
        return "No proof records — but the proof subsystem DEGRADED on this run (" + String(d.disposition)
          + "). This is NOT 'nothing found': the check could not be completed here, so the run is NOT clean.";
      case "nothing_found":
        return "no proofs yet for this run — Strix mints a proof when a reproduction is oracle-confirmed";
      default:
        return "no proofs for this run";
    }
  }
  function drawProof(body) {
    var d = PRF.data || {};
    if (PRF.loaded && !PRF.runs.length && activeEngagement()) {
      V.mount(body, scopedEmpty("proofs", "Nothing has run under this job yet — a reproduction an oracle confirms becomes a signed, replayable proof here.", [newAssessBtn()]));
      return;
    }
    // inv 12 (S9): a DISTINCT, prominent banner whenever verification_degraded — it names the typed
    // disposition and the rolled-up causes so an operator cannot mistake a down subsystem for clean.
    var degradedBanner = d.verification_degraded ? h("div.card.verification-degraded", { role: "alert" }, [
      h("div.card-h", null, [
        h("h3", { style: { color: "var(--st-blocked)" } }, [V.icon("info"), " Verification degraded — this run is NOT clean"]),
        h("span.pill.sm.danger", { style: { marginLeft: "auto" } }, String(d.disposition || "degraded"))]),
      h("p", null, PROOF_DEG_LABEL[d.disposition]
        || "The proof subsystem degraded on this run, so an empty proof list does NOT mean the target is clean."),
      ((d.degraded_causes || []).length ? h("div.kv", null, [h("div.k", null, "Causes"),
        h("div.v", null, (d.degraded_causes || []).map(function (c) {
          return h("span.pill.sm.danger", null, String(c.kind) + " ×" + String(c.count || 1)); }))]) : null)
    ]) : null;
    var picker = h("div.card", null, [h("label", { style: { marginRight: "8px" } }, "Run"),
      h("select", { onChange: function (e) { PRF.run = e.target.value; loadProof(body); } },
        [h("option", { value: "", selected: !PRF.run }, "— select a run —")].concat(
          PRF.runs.map(function (r) {
            return h("option", { value: r.run_id, selected: r.run_id === PRF.run }, (r.slug || r.run_id));
          })))]);
    var canExport = !!PRF.run && (d.facts || 0) > 0;
    var exportBtn = h("button.btn.sm", {
      title: canExport ? "Assemble a client-verifiable proof bundle (offline, zero-trust re-verify)"
        : "Export needs at least one oracle-confirmed FACT",
      disabled: !canExport || PRF.exporting,
      onClick: function () {
        PRF.exporting = true; drawProof(body);
        V.postJSON(OFF("/api/proof/export"), { run: PRF.run }).then(function (r) {
          PRF.exporting = false; PRF.exported = r;
          if (r && r.ok) V.toast("Proof bundle written to " + r.bundle);
          else V.toast((r && r.error) || "export failed", true);
          drawProof(body);
        }).catch(function () { PRF.exporting = false; V.toast("export failed", true); drawProof(body); });
      } }, PRF.exporting ? "Exporting…" : "Export verifiable bundle");
    var exported = PRF.exported && PRF.exported.ok ? h("div", { style: { marginTop: "8px" } }, [
      h("div.kv", null, [h("div.k", null, "Bundle"), h("div.v", null, h("code", null, String(PRF.exported.bundle)))]),
      (PRF.exported.trust_root_fingerprint ? h("div.kv", null, [
        h("div.k", null, "Trust-root fingerprint"),
        h("div.v", null, [h("code", null, String(PRF.exported.trust_root_fingerprint)),
          h("div.hint", null, "PUBLISH this out-of-band — the client pins it so a bundle re-signed under "
            + "another key is refused.")])]) : null),
      h("div.kv", null, [h("div.k", null, "Verify offline"),
        h("div.v", null, h("code", { style: { fontSize: "11px", whiteSpace: "pre-wrap" } },
          String(PRF.exported.verify_cmd || "")))]),
      h("div.hint", null, String(PRF.exported.note || ""))]) : null;
    var summary = h("div.card", null, [h("div.card-h", null, [h("h3", null, "Proofs"),
      h("span", { style: { marginLeft: "auto" } }, exportBtn)]),
      h("div.kv", null, [
        h("div.k", null, "Disposition"),
        h("div.v", null, [
          h("span.pill.sm", null, (d.facts || 0) + " FACT"),
          h("span.pill.sm", null, (d.leads || 0) + " lead"),
          h("span.pill.sm.warn", null, (d.denied || 0) + " denied")])]),
      exported]);
    var rows = (d.proofs || []).map(function (p) {
      var st = p.status === "fact"
        ? h("span.st.st-confirmed", null, [h("span.dot"), "FACT — oracle re-fired over captured bytes"])
        : (p.status === "denied"
            ? h("span.st.st-idle", null, [h("span.dot"), "DENIED — dangerous PoC refused (" + (p.gate_category || "content") + ")"])
            : h("span.st.st-idle", null, [h("span.dot"), "LEAD — not reproduced"]));
      var chans = (p.exchanges || []).map(function (e) {
        return h("span.pill.sm", null, String(e.channel || "?")); });
      return h("div.card", null, [
        h("div.card-h", null, [h("h3", null, (p.bug_class || p.finding_ref || "?")),
          h("span", { style: { marginLeft: "auto" } }, st)]),
        h("div.kv", null, [h("div.k", null, "Finding"), h("div.v", null, String(p.finding_ref || "—"))]),
        (p.status === "fact"
          ? h("div.kv", null, [h("div.k", null, "Oracle"),
              h("div.v", null, (p.confirmed_by || "—")
                + (p.confidence != null ? " · confidence " + p.confidence : ""))])
          : null),
        (chans.length
          ? h("div.kv", null, [h("div.k", null, "Reproduced from"), h("div.v", null, chans)])
          : null),
        h("div.kv", null, [h("div.k", null, "Crossed to spine"),
          h("div.v", null, p.spooled
            ? h("span.st.st-confirmed", null, [h("span.dot"), "signed evidence spooled"])
            : h("span.hint", null, "not spooled (only a FACT crosses)"))]),
        (p.reason ? h("div.hint", { style: { marginTop: "4px" } }, String(p.reason)) : null)]);
    });
    V.mount(body, [picker, degradedBanner, summary,
      (rows.length ? h("div", null, rows)
        : h("div.card", null, [h("div.empty", null, proofEmptyText(d))])),
      h("div.hint", { style: { marginTop: "10px" } }, d.doctrine || "")]);
  }

  function route() {
    const id = current();
    teardownLive();               // close any live stream/timers when navigating away
    renderNav();
    const screen = V.$("#screen"); if (!screen) return;
    if (id === "home") { renderHome(screen); return; }
    if (id === "manual") { renderManual(screen); return; }
    if (id === "knowledge") { renderKnowledge(screen); return; }
    if (id === "tools") { renderTools(screen); return; }
    if (id === "trust") { renderTrust(screen); return; }
    if (id === "posture") { renderPosture(screen); return; }
    if (id === "replay") { renderReplay(screen); return; }
    if (id === "governance") { renderGovernance(screen); return; }
    if (id === "assess") { renderAssess(screen); return; }
    if (id === "chat") { renderChat(screen); return; }
    if (id === "terminal") { renderTerminal(screen); return; }
    if (id === "library") { renderLibrary(screen); return; }
    if (id === "sessions") { renderSessions(screen); return; }
    if (id === "live") { renderLive(screen); return; }
    if (id === "activity") { renderBackground(screen); return; }
    if (id === "findings") { renderFindings(screen); return; }
    if (id === "proof") { renderProof(screen); return; }
    if (id === "settings") { renderSettings(screen); return; }
    if (id === "users") { renderUsers(screen); return; }
    if (id === "apikeys") { renderApiKeys(screen); return; }
    if (id === "safety") { renderSafety(screen); return; }
    if (id === "defense") { renderDefense(screen); return; }
    if (id === "fixes") { renderFixes(screen); return; }
    if (id === "brain") { renderBrain(screen); return; }
    if (id === "strix") { renderStrix(screen); return; }
    if (id === "mcp") { renderMcp(screen); return; }
    if (id === "system") { renderSystem(screen); return; }
    if (id === "durability") { renderDurability(screen); return; }
    if (id === "ceremonies") { renderCeremonies(screen); return; }
    if (id === "budgets") { renderBudgets(screen); return; }
    if (id === "compliance") { renderCompliance(screen); return; }
    if (id === "assurance") { renderAssurance(screen); return; }
    if (id === "report") { renderReport(screen); return; }
    if (id === "charter") { renderCharter(screen); return; }
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
    // the job the operator was last working on — the scope survives a refresh and a console restart,
    // so the first paint already shows that job's work (and the chip already names it).
    try {
      app.set({ engagement: localStorage.getItem(ENGAGEMENT_KEY) || "",
        engagementName: localStorage.getItem(ENGAGEMENT_NAME_KEY) || "" });
    } catch (e) { /* storage disabled: start unscoped (all engagements) */ }
    shell();
    window.addEventListener("hashchange", route);
    if (!location.hash) location.hash = "#/home";
    route();
    // Claim 6: learn WHO is signed in (owner token → owner; a per-user bearer → that principal; neither →
    // the login gate). Re-render the nav (role gating) + topbar (current-user chip) once whoami answers.
    // W17-2: if this load is an OIDC/SSO return (redirect_uri carried ?code&state), FINISH that login first
    // — it adopts the minted bearer, so the whoami below then resolves as the signed-in principal.
    completeOidcReturn(function () {
      loadPrincipal(function (p, ok) {
        refreshTopbar();
        renderNav();
        if (ok && p && !p.authenticated) { renderLoginGate(V.$("#screen")); return; }
        route();                  // authenticated (owner, per-user, or just-completed SSO), or plane offline
      });
    });
    refreshKeysBadge();           // surface any failing API key in the top bar from first paint
    startSigilHud();              // S2: persistent SIGIL voice/gesture nav channel (survives route changes)
    watchOffensePlane();          // W0-B: probe the offense plane + keep the Start/Stop chip live. Without
                                  // this the chip stays `display:none` forever (OFFENSE.known never flips),
                                  // which is exactly why the Start/Stop control never appeared.
    watchBuildVersion();          // W0-deploy: notice a republished bundle and offer to reload.
    startProcessBox();            // W5: the global live-activity box (survives route changes).
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
