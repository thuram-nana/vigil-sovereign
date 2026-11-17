/* VIGIL customer app — the onboarding guide: the first-sign-in tour, the Guide screen and the branded loader.
 *
 * Shown only while the edge writes data-onboarding="1" into the page (VIGIL_CUSTOMER_ONBOARDING, default OFF);
 * app.js decides that and calls in here. This file only DEFINES things: nothing runs at load, nothing is fetched,
 * nothing is sent. Every element is built with the UI kit's h() (passed in), so no HTML string is ever parsed and the
 * strict CSP holds (no inline script or style).
 *
 * WHEN THE TOUR OPENS: after a person's first sign-in, and at every sign-in after it — on any device — until they
 * finish it or skip it. The SERVER keeps that answer per account (app.js asks api/customer/onboarding and records the
 * outcome there); this browser also remembers it (localStorage "vigil.guide.v1.<username>"), which is what decides when
 * the server cannot be asked, and the tour opens at most once per page load. The Guide screen (#/guide) can replay it.
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
      lead: "Create your account, sign in the way that suits you, and keep the account safe.",
      steps: [
        { id: "account", title: "Create your account", where: "Create your account", route: null,
          clicks: ["On the sign-in screen, choose Create an account.",
                   "Enter your work email and select Send verification. If your organization uses Google accounts, you can choose Continue with Google instead.",
                   "Open the email from VIGIL. Enter the 6-digit code, or select I already have a code and paste the token it contains.",
                   "Pick a password, name your workspace and select Create account. Your account and your workspace are created together."],
          why: "Your account and workspace exist only once your email is confirmed. Every screen after that shows your workspace only." },
        { id: "signin", title: "Sign in", where: "Sign in", route: null,
          clicks: ["Enter your work email and password, then select Sign in.",
                   "Or choose Continue with Google, if your organization uses Google accounts.",
                   "Or use a passkey once you have added one: your device's fingerprint, face or screen lock.",
                   "In the app installed on a phone, Google sign-in finishes in your browser: type the 6-digit code it shows into the app."],
          why: "After too many wrong attempts, sign-in pauses for a moment. Wait a little and try again." },
        { id: "security", title: "Protect your account", where: "Account security", route: null,
          clicks: ["Open Account security from your name in the top bar.",
                   "Under Two-step verification, select Set up, scan the code with your authenticator app and enter the 6-digit code it shows.",
                   "Under Passkeys, select Add a passkey and follow your device's prompt.",
                   "Before sensitive actions, such as buying credits, changing your team or turning on monitoring, VIGIL may ask for a fresh code from your authenticator app."],
          why: "Your authenticator secret is shown once and is never stored in readable form." },
        { id: "install", title: "Install the app", where: "Your browser", route: null,
          clicks: ["On a computer, use your browser's Install option in the address bar or the menu.",
                   "On an Android phone, choose Install app from the browser menu.",
                   "On an iPhone or iPad, open VIGIL in Safari, tap Share, then Add to Home Screen.",
                   "When a new version is ready, VIGIL shows a notice. Select Refresh to use it."],
          why: "The installed app keeps only the app itself on your device, never your workspace's data." },
        { id: "recover", title: "Reset a forgotten password", where: "Reset your password", route: null,
          clicks: ["On the sign-in screen, choose Forgot your password?",
                   "Enter your work email and select Send reset email.",
                   "Enter the 6-digit code, or select I already have a code and paste the token from the email.",
                   "Choose a new password and select Set new password, then sign in with it."],
          why: "The reset code works once, for a short time, and only from the email VIGIL sent." },
        { id: "signout", title: "Sign out", where: "Top bar", route: null,
          clicks: ["Select Sign out in the top bar. The button shows the account you are signed in as.",
                   "Signing out also removes the app's stored files from this browser, so nothing of your session stays on a shared computer.",
                   "If sign-out cannot complete, VIGIL tells you that you are still signed in, so you can try again."],
          why: "Your session is ended on the server, not only in this browser." },
      ],
    },
    {
      id: "workspace", title: "Your workspace",
      lead: "See where things stand, bring in your team and decide how you hear about news.",
      steps: [
        { id: "overview", title: "The Overview", where: "Overview", route: "#/",
          clicks: ["Select Overview in the top bar.",
                   "It shows the account you are signed in as and your workspace.",
                   "As you use VIGIL, it brings your credits, hosts, assessments and monitoring together in one place."],
          why: "Every screen shows your workspace only. The server decides what each person may see." },
        { id: "team", title: "Bring in your team", where: "Team", route: "#/team",
          clicks: ["Select Team in the top bar, then Add member. Enter your teammate's work email and choose a role: Admin, Analyst or Viewer.",
                   "Admin: billing, the team and monitoring. No testing and no findings.",
                   "Analyst and Viewer: can sign in and look around, without billing or findings.",
                   "Founder: you, the person who signed the workspace up, and the one role here that can test hosts and read findings.",
                   "To let a teammate test hosts and read findings too, contact VIGIL: that role, Operator, is granted only by VIGIL.",
                   "Select Remove next to a member to take them off the workspace."],
          why: "Testing and billing are separate: paying for VIGIL, or running the workspace, never gives anyone permission to test. Team changes may ask for a fresh authenticator code." },
        { id: "notifications", title: "Notifications", where: "The bell", route: null,
          clicks: ["Select the bell in the top bar. It lists new findings, assessment outcomes, billing notices and monitoring events.",
                   "The number on the bell counts what you have not read yet. Select Mark all read to clear it.",
                   "Untick Sound to silence the chime, or untick Enabled to turn notifications off on this device."],
          why: "Notifications show your workspace only. What you have read, and your settings, are remembered on this device." },
      ],
    },
    {
      id: "credits", title: "Credits and plans",
      lead: "Assessments and reviews draw on prepaid credits. You decide how many to add, and when.",
      steps: [
        { id: "buy", title: "Buy credits", where: "Billing", route: "#/billing",
          clicks: ["Select Billing in the top bar. Your available credits are at the top.",
                   "Under Buy credits, choose a pack and select Buy.",
                   "Confirm with your authenticator app if VIGIL asks for a fresh code.",
                   "Pay on the payment processor's secure page.",
                   "Back in VIGIL, the Payment received page shows your balance. Credits appear once the payment is verified, usually within a minute."],
          why: "Credits are added only after VIGIL verifies the payment with the processor. Leaving the payment page without paying charges nothing." },
        { id: "plans", title: "Monthly plans", where: "Billing", route: "#/billing",
          clicks: ["Under Buy credits, a plan adds a set of credits at the start of every billing period.",
                   "Plan credits are used first and expire at the end of their period. Credits you buy separately never expire.",
                   "Your plan, its status and its credits for this period appear under Subscription on Billing.",
                   "A workspace has one plan at a time. To change plans, contact VIGIL."],
          why: "A plan's credits and a pack's credits are spent the same way; only their expiry differs." },
        { id: "trial", title: "Trial credits", where: "Billing", route: "#/billing",
          clicks: ["A new workspace may start with trial credits: one trial per email address and per domain.",
                   "Trial credits are spent like any others, and you still prove you control a host before testing it.",
                   "During a trial you see every finding, and one of them in full.",
                   "Your first purchase unlocks the proof and the fix of every finding straight away."],
          why: "The trial lets you see real, confirmed results on your own host before you buy." },
        { id: "how", title: "How credits are spent", where: "Billing", route: "#/billing",
          clicks: ["Start an assessment or a review. It sets aside a share of your credits while it runs.",
                   "It draws on them only as it works, and returns whatever it did not use when it ends.",
                   "Open Billing at any time to see every charge on your statement."],
          why: "VIGIL never estimates or quotes what an assessment or a review will cost. You see exactly what each one used, after it used it." },
        { id: "rates", title: "See the rates", where: "Billing", route: "#/billing",
          clicks: ["On Billing, select Rates to see what each kind of usage is charged, in credits.",
                   "The rates are the same for every customer.",
                   "Each line of your statement shows the rate it used, so a later change never reprices past usage."],
          why: "VIGIL publishes the price of each unit of usage, but never predicts the total for a whole assessment." },
        { id: "alerts", title: "Low balance and auto top-up", where: "Billing", route: "#/billing",
          clicks: ["When your balance runs low, VIGIL tells you by email and in the bell, once each time it drops.",
                   "To avoid running out, turn on Auto top-up on Billing: choose the balance that starts it, the pack to buy and a monthly limit.",
                   "Auto top-up never charges above your monthly limit and sends a receipt for every charge."],
          why: "If an assessment paused for credit, a successful top-up lets it carry on." },
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
          why: "If verification does not pass, check that the proof is published exactly as shown, wait a moment for DNS, and select Verify again." },
        { id: "renew", title: "Keep the proof current", where: "Assets", route: "#/assets",
          clicks: ["A proof lasts 90 days. After that the host shows Expired.",
                   "If the proof is still published, select Re-check now.",
                   "Otherwise select Re-issue challenge and publish the new token.",
                   "A host whose proof has expired cannot be tested or monitored until it is verified again."],
          why: "Re-checking before the 90 days are up keeps your assessments and monitoring running without a gap." },
      ],
    },
    {
      id: "assess", title: "Test a host",
      lead: "Run an assessment of a verified host, follow it, and act on what VIGIL proved.",
      steps: [
        { id: "launch", title: "Launch an assessment", where: "Assessments", route: "#/assessments",
          clicks: ["Select Assessments in the top bar, then select Launch on your verified host.",
                   "Choose a depth: Quick for a focused first pass, or Deep for a broader and more thorough one. The assessment starts straight away.",
                   "No price appears: VIGIL never estimates assessment costs.",
                   "If it cannot start, VIGIL says why and where to fix it: Go to Billing to add credits, or Go to Assets to verify the host again."],
          why: "Before any traffic reaches your host, VIGIL checks your testing access, the host's current proof, the authorization for exactly this host, and your credits. If any check fails, nothing is sent and nothing is charged." },
        { id: "follow", title: "Follow it while it runs", where: "Assessments", route: "#/assessments",
          clicks: ["The host's card shows its state: Running, Paused or Not started. It refreshes by itself while the screen is open.",
                   "Pause stops it at the next safe point. Nothing runs, and nothing is charged, while it is paused.",
                   "Resume picks the same assessment back up.",
                   "Before an assessment starts, Cancel releases it: confirm with Yes, cancel. Nothing is charged.",
                   "If your credits run out, it pauses instead of failing. Add credits in Billing, then resume it.",
                   "When it ends, it moves to Finished assessments. The bell in the top bar tells you when it finds something and when it ends."],
          why: "You stay in control of every run." },
        { id: "findings", title: "Read your findings", where: "Assessments", route: "#/assessments",
          clicks: ["In Assessments, select View findings for the host.",
                   "Each finding shows its severity, its class, where it was found and how strong the proof is.",
                   "Use Verify offline to re-run the proof yourself, without VIGIL."],
          why: "VIGIL lists a finding only when a deterministic check confirmed it on evidence your host produced. Anything it could not prove is never shown as a finding." },
        { id: "retest", title: "Confirm a fix", where: "Assessments", route: "#/assessments",
          clicks: ["Fix the weakness on your side.",
                   "Open the finding and select Retest. VIGIL re-runs that finding's proof against your host.",
                   "When the proof no longer works, the finding is marked fixed.",
                   "Or launch a new assessment of the host to check everything again."],
          why: "A finding counts as fixed only when its proof stops working." },
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
          why: "VIGIL works only on the repositories you picked. GitHub is supported first; other code hosts come later." },
        { id: "pr", title: "Red-Pen reviews every pull request", where: "Code", route: null,
          clicks: ["Open or update a pull request on a connected repository. Red-Pen starts on its own.",
                   "It maps what the change touches, attacks it from many angles, and tries to reproduce each problem it suspects in an isolated copy of your code.",
                   "Only a problem it reproduced is posted, as a review comment on the pull request, with the command that reproduces it and the evidence.",
                   "Critical and High findings block the merge through the VIGIL Red-Pen check. Medium and Low findings are comments only.",
                   "Anything Red-Pen could not reproduce stays in VIGIL for you to review, and is never posted as a finding."],
          why: "Reviews are charged by use, like any assessment." },
        { id: "settings", title: "Choose what blocks a merge", where: "Code", route: null,
          clicks: ["Open Code and choose a repository.",
                   "Under Red-Pen, choose what blocks a merge: nothing, Critical and High, or Medium and up.",
                   "Optionally set a monthly spending limit for the repository. Once it is reached, new reviews wait until the next month and VIGIL tells you."],
          why: "VIGIL never estimates what a review will cost; the limit is how you cap it." },
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
        { id: "disconnect", title: "Disconnect a repository", where: "GitHub", route: null,
          clicks: ["On GitHub, open Settings, then Applications, then the VIGIL app.",
                   "Remove a repository from its list, or uninstall the app.",
                   "VIGIL stops reviewing it straight away. Findings already reported stay in VIGIL."],
          why: "You decide, on GitHub, exactly which code VIGIL may read." },
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
          why: "Turning monitoring on needs the founder or an admin. Without monitoring turned on, traffic to the host passes through AEGIS uninspected." },
        { id: "events", title: "Connect your traffic and see events", where: "Monitoring", route: null,
          clicks: ["VIGIL sets your host up behind the managed AEGIS gateway with you.",
                   "Open Monitoring to see the events for your hosts. Only your workspace sees them.",
                   "The bell in the top bar tells you when something new arrives."],
          why: "Each event is checked before it reaches you; a report that cannot be verified is never shown." },
        { id: "manage", title: "Change or stop monitoring", where: "Monitoring", route: null,
          clicks: ["Open Monitoring and choose the host.",
                   "Select Turn off to stop monitoring it. Its traffic then passes through uninspected.",
                   "Monitoring carries on when your plan renews, and ends when the plan is cancelled.",
                   "Moving from Respond to Observe turns blocking off. Monitoring of a host also ends when its proof expires, so keep the proof current."],
          why: "You can turn monitoring off at any time." },
      ],
    },
    {
      id: "billing", title: "Statement and invoices",
      lead: "See exactly what you bought and what each assessment and review used.",
      steps: [
        { id: "statement", title: "Read your statement", where: "Billing", route: "#/billing",
          clicks: ["Select Billing to see your available credits, what is on hold for running assessments, what you bought and what you used.",
                   "Each running assessment shows what it has used so far.",
                   "Your statement lists every charge, newest first: when it happened, what it was for, the quantity, the rate and the credits."],
          why: "An assessment or review is charged only for what it actually used. Usage that could not be confirmed is never charged to you." },
        { id: "invoices", title: "Invoices", where: "Invoices", route: "#/invoices",
          clicks: ["Select Invoices in the top bar.",
                   "Every purchase is listed with its date, type, plan, amount and credits."],
          why: "Invoices show your workspace's purchases only." },
        { id: "payments", title: "When a payment does not go through", where: "Billing", route: "#/billing",
          clicks: ["If you leave the payment page or the payment fails, VIGIL shows Payment not completed. Nothing is charged.",
                   "If a payment is still confirming, the Payment received page keeps checking, and your balance updates by itself.",
                   "If a payment is reversed or disputed, VIGIL may hold new assessments until the balance is settled. Your next top-up settles it first."],
          why: "Credits only ever arrive from a payment VIGIL has verified." },
      ],
    },
  ];

  // The first-sign-in tour: one screen per step of the journey, in order. `chapter`/`step` point at the detailed
  // step on the Guide screen; `route` (when set) lights up the matching tab in the top bar.
  var TOUR = [
    { title: "Welcome to VIGIL", route: null,
      body: ["VIGIL tests the hosts and code your organization controls, and reports only what it can prove.",
             "This tour shows every part of the app in order: your account and team, credits, proving a host, assessments, Red-Pen on GitHub, AEGIS monitoring and billing.",
             "Select Next to begin, or Skip guide to go straight to the app. You can open the guide again from Guide in the top bar."] },
    { chapter: "start", step: "security" },
    { chapter: "workspace", step: "team" },
    { chapter: "workspace", step: "notifications" },
    { chapter: "credits", step: "buy" },
    { chapter: "credits", step: "how" },
    { chapter: "hosts", step: "register" },
    { chapter: "hosts", step: "publish" },
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
             "Everything in this tour, and more, is under Guide in the top bar, step by step, and you can replay the tour from there."] },
  ];

  // Questions first-time users ask (the Guide screen's last tab).
  var FAQ = [
    { q: "How much will an assessment cost?",
      a: "VIGIL does not estimate or quote assessment costs. You decide how many credits to add. An assessment draws credits only as it works and returns what it did not use, and your statement shows every charge." },
    { q: "What happens if my credits run out during an assessment?",
      a: "The assessment pauses instead of failing. Add credits in Billing, then resume it." },
    { q: "Can I test a host or a repository I do not control?",
      a: "No. VIGIL tests a host only after you prove you control it and confirm you are authorized to test it, and reviews only the repositories you connect." },
    { q: "Does VIGIL change my code?",
      a: "Only when you select Fix this, and then only by opening a pull request for you to review. VIGIL never merges anything itself." },
    { q: "I paid, but my credits have not appeared.",
      a: "Credits appear once the payment processor confirms the payment, usually within a minute and sometimes a few minutes. Your balance in Billing updates by itself. Nothing is lost." },
    { q: "Why does my host show Expired?",
      a: "A proof of control lasts 90 days. Select Re-check now if the proof is still published, or Re-issue challenge to publish a new one." },
    { q: "What is the difference between a finding and a signal VIGIL could not prove?",
      a: "A finding is confirmed by a deterministic check that fired on evidence from your host, and it includes the steps to re-run that check yourself. Anything VIGIL could not prove is never presented as a finding." },
    { q: "Who in my organization can see our findings?",
      a: "The founder, and any teammate VIGIL has made an Operator. Admins see billing, the team and monitoring, but not findings. Analysts and viewers see neither billing nor findings." },
    { q: "How do I see this guide again?",
      a: "Select Guide in the top bar. Replay the welcome tour shows the tour again." },
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

  /** What this browser remembers for `username`: "done", "skipped", or null. */
  function localState(username, storage) {
    var v = safeGet(storage, doneKey(String(username || "")));
    return v === "done" || v === "skipped" ? v : null;
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
      var ch = null;
      for (var i = 0; i < CHAPTERS.length; i++) { if (CHAPTERS[i].id === current) ch = CHAPTERS[i]; }
      var tabs = CHAPTERS.map(function (c) {
        return h("button.cust-guide-tab", { type: "button", text: c.title, "aria-pressed": ch && c.id === ch.id ? "true" : "false",
                                            onClick: function () { current = c.id; draw(); } });
      });
      tabs.push(h("button.cust-guide-tab", { type: "button", text: "Questions", "aria-pressed": ch ? "false" : "true",
                                             onClick: function () { current = "faq"; draw(); } }));
      if (!ch) {                                            // the Questions tab
        clear(root);
        root.appendChild(h("div.cust-guide-tabs", { role: "group", "aria-label": "Guide chapters" }, tabs));
        root.appendChild(h("div.cust-guide-steps", {}, FAQ.map(function (f) {
          return h("details.card.cust-guide-faq", {}, [h("summary", { text: f.q }), h("p.cust-tour-why", { text: f.a })]);
        })));
        return;
      }
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
        h("p.cust-muted", { text: "Everything you can do in VIGIL, step by step: your account and team, credits, "
          + "proving and testing your hosts, Red-Pen on your code, AEGIS monitoring and billing. Select a step to see "
          + "each click." }),
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
    CHAPTERS: CHAPTERS, TOUR: TOUR, FAQ: FAQ, doneKey: doneKey, shouldOpen: shouldOpen, markDone: markDone, loader: loader,
    localState: localState,
    openTour: openTour, viewGuide: viewGuide, findStep: findStep,
    _resetForTests: function () { openedThisLoad = {}; },
  };
})();
