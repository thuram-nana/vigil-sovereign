/* VIGIL customer app — the onboarding guide: the first-sign-in tour, the Guide screen and the branded loader.
 *
 * Shown only while the edge writes data-onboarding="1" into the page (VIGIL_CUSTOMER_ONBOARDING, default OFF);
 * app.js decides that and calls in here. This file only DEFINES things: nothing runs at load, nothing is fetched,
 * nothing is sent. Every element is built with the UI kit's h() (passed in), so no HTML string is ever parsed and the
 * strict CSP holds (no inline script or style).
 *
 * WHEN THE TOUR OPENS: after a sign-in, once per account in this browser, until the person finishes it or skips it
 * (localStorage "vigil.guide.v1.<username>"). With storage unavailable it opens at most once per page load. The Guide
 * screen (#/guide) can replay it at any time.
 *
 * The copy follows the product's rules: no cost estimate for any assessment, credits only, no model or engine names,
 * and only hosts and repositories the customer controls.
 */
(function () {
  "use strict";

  var STORE_PREFIX = "vigil.guide.v1.";
  var STEP_PREFIX = "vigil.guide.v1.step.";

  // ---- the guide's content ---------------------------------------------------------------------------------------
  // Each chapter is a sequence the customer follows in order. A step names the screen it happens on (`where`: the
  // label shown, and `route`: the app's own hash when the screen exists in the top bar), the clicks, in order
  // (`clicks`), and what VIGIL does meanwhile (`why`).
  var CHAPTERS = [
    {
      id: "start", title: "Get started",
      lead: "Create your account and bring in the people who will work with you.",
      steps: [
        { id: "account", title: "Create your account", where: "Create your account", route: null,
          clicks: ["Open VIGIL and choose Create your account. If your organization uses Google accounts, you can choose Continue with Google instead.",
                   "Enter your work email and select Send verification.",
                   "Open the email from VIGIL. Enter the 6-digit code, or paste the verification token it contains.",
                   "Choose your password. Your account and your workspace are created together."],
          why: "Your account and workspace exist only once your email is confirmed. Every screen after that shows your workspace only." },
        { id: "team", title: "Bring in your team", where: "Team", route: "#/team",
          clicks: ["Select Team in the top bar.",
                   "Add each teammate with their work email. They sign in with their own account.",
                   "Give testing access only to people allowed to test your hosts and repositories. Give billing access to the people who handle payments."],
          why: "Testing and billing are separate. Paying for VIGIL never gives anyone permission to test, and billing members cannot see hosts or findings." },
      ],
    },
    {
      id: "credits", title: "Add credits",
      lead: "Assessments and reviews draw on prepaid credits. You choose how many to add.",
      steps: [
        { id: "buy", title: "Buy credits", where: "Billing", route: "#/billing",
          clicks: ["Select Billing in the top bar. Your available credits are at the top.",
                   "Under Buy credits, choose a pack and select Buy.",
                   "Confirm with your authenticator app if VIGIL asks for a fresh check.",
                   "Pay on the payment processor's secure page.",
                   "Back in VIGIL, the Payment received page shows your balance. Credits appear once the payment is verified, usually within a minute."],
          why: "Credits are added only after VIGIL verifies the payment with the processor. Leaving the payment page without paying charges nothing." },
        { id: "how", title: "How credits are spent", where: "Billing", route: "#/billing",
          clicks: ["Start an assessment or a review. It sets aside a share of your credits while it runs.",
                   "It draws on them only as it works, and returns whatever it did not use when it ends.",
                   "Open Billing at any time to see every charge on your statement."],
          why: "VIGIL never estimates or quotes what an assessment or a review will cost. You see exactly what each one used, after it used it." },
      ],
    },
    {
      id: "hosts", title: "Prove you control a host",
      lead: "VIGIL tests and protects a host only after you prove you control it.",
      steps: [
        { id: "register", title: "Register the host", where: "Assets", route: "#/assets",
          clicks: ["Select Assets in the top bar.",
                   "Under Register a new host, enter the host, for example app.example.com.",
                   "Select Request ownership challenge. VIGIL shows three ways to prove control."],
          why: "Proving control never starts a test by itself." },
        { id: "publish", title: "Publish one proof", where: "Assets", route: "#/assets",
          clicks: ["DNS: add a TXT record named _vigil-challenge.<your host> whose value is the vigil-site-verification=… line VIGIL shows.",
                   "Or a file: serve the same line at https://<your host>/.well-known/vigil-site-verification.txt.",
                   "Or a meta tag: add <meta name=\"vigil-site-verification\" content=\"…\"> to your homepage's <head>.",
                   "One proof is enough. Copy the values exactly as VIGIL shows them."],
          why: "The token is unique to your workspace and this host, so no other proof can stand in for it." },
        { id: "verify", title: "Confirm and verify", where: "Assets", route: "#/assets",
          clicks: ["Tick I confirm I am authorized to test this asset. Controlling a domain is not the same as being allowed to test it.",
                   "Select the Verify button for the proof you published.",
                   "The host shows Verified. Testing is then authorized for exactly this host, for a limited time."],
          why: "A proof lasts 90 days. When a host shows Expired, select Re-check now or Re-issue challenge to renew it." },
      ],
    },
    {
      id: "assess", title: "Test a host",
      lead: "Run an assessment of a verified host and read what VIGIL proved.",
      steps: [
        { id: "launch", title: "Launch an assessment", where: "Assessments", route: "#/assessments",
          clicks: ["Select Assessments in the top bar and choose your verified host.",
                   "Choose a depth: Quick for a focused first pass, Deep for a broader and more thorough one, or Max for the most thorough assessment VIGIL runs.",
                   "Launch. No price appears: VIGIL never estimates assessment costs."],
          why: "Before any traffic reaches your host, VIGIL checks your testing access, the host's current proof, the authorization for exactly this host, and your credits. If any check fails, nothing is sent and nothing is charged." },
        { id: "follow", title: "Follow it while it runs", where: "Assessments", route: "#/assessments",
          clicks: ["Pause stops it at the next safe point. Nothing runs, and nothing is charged, while it is paused.",
                   "Resume picks the same assessment back up.",
                   "Cancel ends it. You pay only for what it already used.",
                   "If your credits run out, it pauses instead of failing. Add credits in Billing, then resume it.",
                   "The bell in the top bar shows new findings and billing notices."],
          why: "You stay in control of every run." },
        { id: "findings", title: "Read your findings", where: "Assessments", route: "#/assessments",
          clicks: ["In Assessments, select View findings for the host.",
                   "Each finding shows its severity, its class, where it was found and how strong the proof is.",
                   "Use Verify offline to re-run the proof yourself, without VIGIL."],
          why: "VIGIL lists a finding only when a deterministic check confirmed it on evidence your host produced. Anything it could not prove is never shown as a finding." },
      ],
    },
    {
      id: "redpen", title: "Red-Pen and GitHub",
      lead: "Connect GitHub and VIGIL reviews your code: every pull request, or a whole repository.",
      steps: [
        { id: "connect", title: "Connect your GitHub account", where: "Code", route: null,
          clicks: ["Open Code and select Connect GitHub. VIGIL sends you to GitHub.",
                   "On GitHub, choose the account or organization that owns your repositories.",
                   "Choose Only select repositories, then pick the repositories VIGIL may review.",
                   "Select Install. GitHub sends you back to VIGIL, and your repositories appear under Code."],
          why: "VIGIL works only on the repositories you picked. You can change the list, or remove VIGIL, from your GitHub settings at any time. GitHub is supported first; other code hosts come later." },
        { id: "pr", title: "Red-Pen reviews every pull request", where: "Code", route: null,
          clicks: ["Open or update a pull request on a connected repository. Red-Pen starts on its own.",
                   "It maps what the change touches, attacks it from many angles, and tries to reproduce each problem it suspects in an isolated copy of your code.",
                   "Only a problem it reproduced is posted, as a review comment on the pull request, with the command that reproduces it and the evidence.",
                   "Critical and High findings block the merge through the VIGIL Red-Pen check. Medium and Low findings are comments only.",
                   "Anything Red-Pen could not reproduce stays in VIGIL for you to review, and is never posted as a finding."],
          why: "For each repository you choose what blocks a merge (nothing, Critical and High, or Medium and up) and can set a monthly spending limit. Reviews are charged by use, like any assessment." },
        { id: "system", title: "Review a whole repository", where: "Code", route: null,
          clicks: ["Open Code and choose a repository.",
                   "Select Red-Pen System to review the whole repository now.",
                   "Or set a weekly or monthly schedule, and VIGIL reviews it on its own."],
          why: "The findings follow the same rule: only reproduced problems are reported." },
        { id: "fix", title: "Fix a finding", where: "Code", route: null,
          clicks: ["On a finding, select Fix this.",
                   "VIGIL writes a patch, then checks it: the reproduction now passes, your tests pass, and a quick Red-Pen of the patch finds nothing new.",
                   "Only then does VIGIL open a pull request with the fix, for you to review and merge."],
          why: "VIGIL never merges anything itself. A finding counts as fixed only when its reproduction stops failing." },
      ],
    },
    {
      id: "aegis", title: "AEGIS monitoring",
      lead: "AEGIS watches live traffic to a host you proved and tells you about attacks as they happen.",
      steps: [
        { id: "plans", title: "Choose an AEGIS plan", where: "Billing", route: "#/billing",
          clicks: ["Select Billing and find the AEGIS plans.",
                   "AEGIS Observe watches traffic to your host and reports attacks.",
                   "AEGIS Respond does the same and can also block attacks on the host.",
                   "Choose a plan for 1 or 5 hosts and select Buy."],
          why: "AEGIS plans are monthly and billed on their own line. They never use your credits." },
        { id: "monitor", title: "Turn on monitoring for a host", where: "Monitoring", route: null,
          clicks: ["Make sure the host shows Verified in Assets.",
                   "Open Monitoring and choose the host.",
                   "Choose Observe or Respond, then confirm with your authenticator app.",
                   "Monitoring starts for that host and runs until the end of your plan period."],
          why: "Turning monitoring on needs a workspace admin. Without monitoring turned on, traffic to the host passes through AEGIS uninspected." },
        { id: "events", title: "Connect your traffic and see events", where: "Monitoring", route: null,
          clicks: ["VIGIL sets your host up behind the managed AEGIS gateway with you.",
                   "Open Monitoring to see the events for your hosts. Only your workspace sees them.",
                   "The bell in the top bar tells you when something new arrives."],
          why: "When a plan renews, monitoring carries on. If you move from Respond to Observe, blocking turns off. You can turn monitoring off at any time." },
      ],
    },
    {
      id: "billing", title: "Statement and invoices",
      lead: "See exactly what you bought and what each assessment and review used.",
      steps: [
        { id: "statement", title: "Read your statement", where: "Billing", route: "#/billing",
          clicks: ["Select Billing to see your balance.",
                   "Your statement lists every charge, newest first: when it happened, what it was for, the quantity, the rate and the credits.",
                   "Select Invoices to see every purchase with its date, type, amount and credits."],
          why: "An assessment or review is charged only for what it actually used. Usage that could not be confirmed is never charged to you." },
      ],
    },
  ];

  // The first-sign-in tour: one screen per step of the journey, in order. `chapter`/`step` point at the detailed
  // step on the Guide screen; `route` (when set) lights up the matching tab in the top bar.
  var TOUR = [
    { title: "Welcome to VIGIL", route: null,
      body: ["VIGIL tests the hosts and code your organization controls, and reports only what it can prove.",
             "This short tour shows you every step, from adding credits to your first confirmed finding, Red-Pen on GitHub and AEGIS monitoring.",
             "Select Next to begin, or Skip guide to go straight to the app. You can open the guide again from Guide in the top bar."] },
    { chapter: "start", step: "team" },
    { chapter: "credits", step: "buy" },
    { chapter: "credits", step: "how" },
    { chapter: "hosts", step: "register" },
    { chapter: "hosts", step: "verify" },
    { chapter: "assess", step: "launch" },
    { chapter: "assess", step: "follow" },
    { chapter: "assess", step: "findings" },
    { chapter: "redpen", step: "connect" },
    { chapter: "redpen", step: "pr" },
    { chapter: "redpen", step: "fix" },
    { chapter: "aegis", step: "plans" },
    { chapter: "aegis", step: "monitor" },
    { chapter: "billing", step: "statement" },
    { title: "You're ready", route: "#/guide",
      body: ["Start with Assets: register your first host and prove you control it.",
             "The full guide, with every click, is under Guide in the top bar, and you can replay this tour from there."] },
  ];

  function findStep(chapterId, stepId) {
    for (var i = 0; i < CHAPTERS.length; i++) {
      if (CHAPTERS[i].id !== chapterId) continue;
      for (var j = 0; j < CHAPTERS[i].steps.length; j++) {
        if (CHAPTERS[i].steps[j].id === stepId) return { chapter: CHAPTERS[i], step: CHAPTERS[i].steps[j] };
      }
    }
    return null;
  }

  // ---- when the tour opens -------------------------------------------------------------------------------------------
  var openedThisLoad = {};

  function safeGet(storage, key) {
    try { return storage ? storage.getItem(key) : null; } catch (e) { return null; }
  }
  function safeSet(storage, key, value) {
    try { if (storage) storage.setItem(key, value); return true; } catch (e) { return false; }
  }
  function doneKey(username) { return STORE_PREFIX + String(username || ""); }

  /** True when the tour should open now: the guide is on, someone is signed in, they have neither finished nor
   *  skipped it in this browser, and it has not already opened during this page load. */
  function shouldOpen(opts) {
    var u = String((opts && opts.username) || "");
    if (!opts || !opts.enabled || !u) return false;
    if (openedThisLoad[u]) return false;
    return !safeGet(opts.storage, doneKey(u));
  }

  /** Record that `username` finished ("done") or skipped ("skipped") the tour, so it does not open again. */
  function markDone(username, storage, how) {
    var u = String(username || "");
    if (!u) return false;
    openedThisLoad[u] = true;
    return safeSet(storage, doneKey(u), how === "skipped" ? "skipped" : "done");
  }

  // ---- the branded loader ---------------------------------------------------------------------------------------------
  /** The VIGIL wordmark, brightening and dimming while a screen loads (app.css: .cust-loader). The two images are the
   *  owner's artwork for the dark and the light theme (components.css shows the one that fits). */
  function loader(h, label) {
    var text = label || "Loading";
    return h("div.cust-loader", { role: "status", "aria-live": "polite", "aria-label": text }, [
      h("img.vigil-logo.for-dark.cust-loader-mark", { src: "brand/vigil-wordmark-white.svg", alt: "", width: "132", height: "29" }),
      h("img.vigil-logo.for-light.cust-loader-mark", { src: "brand/vigil-wordmark.svg", alt: "", width: "132", height: "29" }),
      h("span.cust-loader-text", { text: text }),
    ]);
  }

  // ---- the tour ----------------------------------------------------------------------------------------------------------
  function spotlight(doc, route) {
    var lit = doc.querySelectorAll ? doc.querySelectorAll(".cust-nav-spot") : [];
    for (var i = 0; i < lit.length; i++) lit[i].classList.remove("cust-nav-spot");
    if (!route || !doc.querySelector) return;
    var el = doc.querySelector('.cust-nav-link[data-route="' + route + '"]');
    if (el) el.classList.add("cust-nav-spot");
  }

  /**
   * Open the tour over the app. env: {h, doc, username, storage, nav, onClose}. Returns {el, close, go, index}.
   * Skip guide and Finish both record the outcome (markDone), close the tour and remove the top-bar highlight; Esc
   * skips; the arrow keys move between steps.
   */
  function openTour(env) {
    var h = env.h, doc = env.doc || document;
    var u = String(env.username || "");
    if (u) openedThisLoad[u] = true;
    var idx = 0, closed = false;
    var panel = h("div.cust-tour-panel", { role: "dialog", "aria-modal": "true", "aria-labelledby": "cust-tour-title",
                                           tabindex: "-1" });
    var scrim = h("div.cust-tour", {}, panel);

    function close(how) {
      if (closed) return;
      closed = true;
      markDone(u, env.storage, how);
      spotlight(doc, null);
      if (doc.body && doc.body.classList) doc.body.classList.remove("cust-touring");
      if (scrim.parentNode) scrim.parentNode.removeChild(scrim);
      doc.removeEventListener("keydown", onKey);
      if (typeof env.onClose === "function") env.onClose(how);
    }
    function onKey(ev) {
      if (ev.key === "Escape") { ev.preventDefault(); close("skipped"); }
      else if (ev.key === "ArrowRight") { ev.preventDefault(); go(idx + 1); }
      else if (ev.key === "ArrowLeft") { ev.preventDefault(); go(idx - 1); }
    }
    function content(i) {
      var t = TOUR[i];
      if (!t.chapter) return { title: t.title, body: t.body, route: t.route, clicks: null, where: null, chapter: null };
      var f = findStep(t.chapter, t.step);
      return { title: f.step.title, body: [f.step.why], route: f.step.route, clicks: f.step.clicks, where: f.step.where,
               chapter: f.chapter.title };
    }
    function go(i) {
      if (closed) return;
      if (i < 0) i = 0;
      if (i >= TOUR.length) { close("done"); return; }
      idx = i;
      var c = content(i);
      var last = i === TOUR.length - 1;
      var dots = [];
      for (var d = 0; d < TOUR.length; d++) {
        dots.push(h("button.cust-tour-dot" + (d === i ? ".on" : ""), {
          type: "button", "aria-label": "Step " + (d + 1), "aria-current": d === i ? "step" : null,
          onClick: (function (k) { return function () { go(k); }; })(d) }));
      }
      var head = h("div.cust-tour-head", {}, [
        h("span.cust-tour-count", { text: "Step " + (i + 1) + " of " + TOUR.length }),
        c.chapter ? h("span.chip.cust-tour-chapter", { text: c.chapter }) : null,
        h("span.spacer"),
        h("button.cust-nav-link.cust-tour-skip", { type: "button", text: "Skip guide", onClick: function () { close("skipped"); } }),
      ]);
      var body = [h("h2#cust-tour-title", { text: c.title })];
      if (c.where) body.push(h("p.cust-tour-where", { text: "Where: " + c.where }));
      if (c.clicks) {
        body.push(h("ol.cust-tour-clicks", {}, c.clicks.map(function (s) { return h("li", { text: s }); })));
      }
      (c.body || []).forEach(function (p) { body.push(h("p.cust-tour-why", { text: p })); });
      var foot = h("div.cust-tour-foot", {}, [
        h("div.cust-tour-dots", {}, dots),
        h("span.spacer"),
        i > 0 ? h("button.btn", { type: "button", text: "Back", onClick: function () { go(idx - 1); } }) : null,
        h("button.btn.btn-primary", { type: "button", text: last ? "Finish" : "Next", onClick: function () { go(idx + 1); } }),
      ]);
      clear(panel);
      panel.appendChild(head);
      panel.appendChild(h("div.cust-tour-body", {}, body));
      panel.appendChild(foot);
      spotlight(doc, c.route);
      try { panel.focus(); } catch (e) { /* focus is a convenience */ }
    }
    doc.addEventListener("keydown", onKey);
    if (doc.body && doc.body.classList) doc.body.classList.add("cust-touring");   // keeps the top bar above the scrim
    (doc.body || doc.documentElement).appendChild(scrim);
    go(0);
    return { el: scrim, close: close, go: go, index: function () { return idx; } };
  }

  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  // ---- the Guide screen ----------------------------------------------------------------------------------------------
  function stepKey(username, chapterId, stepId) { return STEP_PREFIX + String(username || "") + "." + chapterId + "." + stepId; }

  /**
   * The Guide screen's body. env: {h, username, storage, nav, replayTour, chapter}. Chapter tabs on top; each step of
   * the chapter is a card that opens to its clicks, in order, with "Go to <screen>" and a per-step "Mark as done".
   */
  function viewGuide(env) {
    var h = env.h;
    var current = env.chapter || CHAPTERS[0].id;
    var root = h("div.cust-guide", {});

    function draw() {
      var ch = CHAPTERS[0];
      for (var i = 0; i < CHAPTERS.length; i++) { if (CHAPTERS[i].id === current) ch = CHAPTERS[i]; }
      var tabs = CHAPTERS.map(function (c) {
        return h("button.cust-guide-tab", { type: "button", text: c.title, "aria-pressed": c.id === ch.id ? "true" : "false",
                                            onClick: function () { current = c.id; draw(); } });
      });
      var cards = ch.steps.map(function (s, n) {
        var key = stepKey(env.username, ch.id, s.id);
        var isDone = !!safeGet(env.storage, key);
        var open = n === 0;
        var detail = h("div.cust-guide-detail", {}, [
          h("ol.cust-tour-clicks", {}, s.clicks.map(function (c) { return h("li", { text: c }); })),
          h("p.cust-tour-why", { text: s.why }),
        ]);
        detail.hidden = !open;
        var mark = h("button.btn", { type: "button", text: isDone ? "✓ Done" : "Mark as done",
                                     "aria-pressed": isDone ? "true" : "false" });
        mark.addEventListener("click", function () {
          var now = !safeGet(env.storage, key);
          if (now) safeSet(env.storage, key, "1"); else { try { env.storage.removeItem(key); } catch (e) { /* off */ } }
          draw();
        });
        var actions = [mark];
        if (s.route && typeof env.nav === "function") {
          actions.unshift(h("button.btn", { type: "button", text: "Go to " + s.where,
                                            onClick: function () { env.nav(s.route); } }));
        }
        var toggle = h("button.cust-guide-step-head", { type: "button", "aria-expanded": open ? "true" : "false" }, [
          h("span.cust-guide-num" + (isDone ? ".done" : ""), { text: String(n + 1) }),
          h("span.cust-guide-step-title", { text: s.title }),
          h("span.chip", { text: s.where }),
        ]);
        toggle.addEventListener("click", function () {
          detail.hidden = !detail.hidden;
          toggle.setAttribute("aria-expanded", detail.hidden ? "false" : "true");
        });
        detail.appendChild(h("div.row.cust-guide-actions", {}, actions));
        return h("div.card.cust-guide-step", {}, [toggle, detail]);
      });
      var replay = typeof env.replayTour === "function"
        ? h("button.btn", { type: "button", text: "Replay the welcome tour", onClick: function () { env.replayTour(); } })
        : null;
      clear(root);
      root.appendChild(h("div.cust-guide-head", {}, [
        h("p.cust-muted", { text: "Everything you can do in VIGIL, step by step: testing your hosts, Red-Pen on your "
          + "code, AEGIS monitoring and billing. Select a step to see each click." }),
        replay,
      ]));
      root.appendChild(h("div.cust-guide-tabs", { role: "group", "aria-label": "Guide chapters" }, tabs));
      root.appendChild(h("p.cust-guide-lead", { text: ch.lead }));
      root.appendChild(h("div.cust-guide-steps", {}, cards));
    }
    draw();
    return root;
  }

  window.VIGIL_GUIDE = {
    CHAPTERS: CHAPTERS, TOUR: TOUR, doneKey: doneKey, shouldOpen: shouldOpen, markDone: markDone, loader: loader,
    openTour: openTour, viewGuide: viewGuide, findStep: findStep,
    _resetForTests: function () { openedThisLoad = {}; },
  };
})();
