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
  // (`clicks`), and what VIGIL does meanwhile (`why`). A step marked `onlyIfShown` describes a screen a deployment may
  // not have: the Guide screen lists it only when the app says that screen is shown (`shown(route)`), so a deployment
  // without it sees exactly the guide it always had. A step on a screen a page switch turns on also names that switch
  // (`when`: the name app.js reads with pageFlag); the Guide screen lists such a step only where app.js's `flag(when)`
  // says the switch is on AND its `shown(route)` says the screen is shown, so with the switch off the guide is exactly
  // what it was without the step.
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
                   "Or select Sign in with a passkey once you have added one, and use your device's fingerprint, face or screen lock.",
                   "In the app installed on a phone, Google sign-in finishes in your browser: type the 6-digit code it shows into the app."],
          why: "After too many wrong attempts, sign-in pauses for a moment. Wait a little and try again." },
        { id: "security", title: "Protect your account", where: "Account security", route: "#/security",
          clicks: ["Open Account security from your name in the top bar.",
                   "Under Two-step verification, select Set up. Scan the QR code with your authenticator app, or enter the key shown under it, then enter the 6-digit code the app shows and select Confirm.",
                   "Under Passkeys, select Add a passkey and follow your device's prompt.",
                   "Before sensitive actions, such as buying credits, changing your team or turning on monitoring, VIGIL may ask you to verify with your authenticator: enter the 6-digit code it shows and select Verify."],
          why: "Your authenticator key is shown once and is never stored in readable form." },
        { id: "authorizations", title: "See your authorizations", where: "Authorizations", route: "#/settings/authorizations", onlyIfShown: true,
          clicks: ["Open Authorizations from Settings in the top bar.",
                   "Each host you have proven and the owner has authorized is listed here, read-only: its scope, the dates it is valid, and whether it is active now.",
                   "A host that is not yet authorized has a Request authorization action that asks the VIGIL owner to sign one; it grants nothing by itself.",
                   "The screen only discloses what the owner has signed — the gate that runs an assessment checks that same owner signature again before anything runs."],
          why: "It discloses the owner-signed authorization read-only; it is never a second way to grant or widen one." },
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
          clicks: ["Select Sign out in the top bar, next to the account you are signed in as.",
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
                   "It opens on the account you are signed in as and your workspace.",
                   "Summary cards bring your credits, hosts, assessments and monitoring together, each with a button that opens its full screen.",
                   "A card for something your role cannot see says so plainly, and never shows an error."],
          why: "Every screen shows your workspace only. The server decides what each person may see, so each card shows just what you are allowed to." },
        { id: "team", title: "Bring in your team", where: "Team", route: "#/team",
          clicks: ["Select Team in the top bar. Under Add member, enter your teammate's work email and choose a role: Admin, Analyst or Viewer.",
                   "Select Add member. Your teammate needs a VIGIL account first: if there is none for that email, VIGIL says so and adds no one. They can create one with Create an account on the sign-in screen.",
                   "Admin: billing, the team and monitoring. No testing and no findings.",
                   "Analyst and Viewer: can sign in and look around, without billing or findings.",
                   "Founder: everything an Admin can do, plus testing hosts and reading findings. Only VIGIL changes or removes the founder, so the founder's row has no buttons.",
                   "To let a teammate test hosts and read findings too, contact VIGIL: that role, Operator, is granted only by VIGIL.",
                   "To give a member another role, choose it on their row and select Change role.",
                   "To take a member off the workspace, select Remove on their row, then Yes, remove."],
          why: "Only the founder and admins can see and change the team, and a workspace always keeps one person who can manage it: VIGIL refuses to remove the last one or to make them an Analyst or Viewer. Testing and billing are separate: paying for VIGIL, or running the workspace, never gives anyone permission to test. Team changes may ask for a fresh authenticator code." },
        { id: "notifications", title: "Notifications", where: "The bell", route: null,
          clicks: ["Select the bell in the top bar. It lists new findings, assessment outcomes, billing notices and monitoring events.",
                   "The number on the bell counts what you have not read yet. Select Mark all read to clear it.",
                   "Untick Sound to silence the chime, or untick Enabled to turn notifications off on this device."],
          why: "Notifications show your workspace only. What you have read, and your settings, are remembered on this device." },
        // The settings shell (legal/governance S1): served under data-settings (VIGIL_CUSTOMER_SETTINGS, default OFF).
        { id: "organization", title: "Record your organization's details", where: "Settings", route: "#/settings",
          when: "settings",
          clicks: ["Select Settings in the top bar.",
                   "Under General, enter your legal entity name, its registered or operating address and the email of your primary contractual contact.",
                   "Add your emergency operational contact: a name, a phone number and an email.",
                   "Select Save. VIGIL keeps these details with your account, and you can change them at any time.",
                   "Under Your organization, select Authorized administrators or Billing to open that screen and change its settings there."],
          // where the Account security screen is on (`when`: its page switch), the hub links it too, and so do these
          alt: { when: "security",
                 clicks: ["Select Settings in the top bar.",
                          "Under General, enter your legal entity name, its registered or operating address and the email of your primary contractual contact.",
                          "Add your emergency operational contact: a name, a phone number and an email.",
                          "Select Save. VIGIL keeps these details with your account, and you can change them at any time.",
                          "Under Your organization, select Account security & sign-in, Authorized administrators or Billing to open that screen and change its settings there."] },
          why: "Settings records these details and links to the screens that already exist. It never changes who can do what and never charges anything: roles are changed on Team, and credits are bought on Billing." },
        // The Privacy centre (legal/governance S2): served under data-privacy-center (VIGIL_CUSTOMER_PRIVACY_CENTER, default OFF).
        { id: "privacy", title: "See our cookies and subprocessors", where: "Privacy", route: "#/privacy",
          when: "privacyCenter",
          clicks: ["Select Privacy in the top bar.",
                   "Under Cookies and local data, see the strictly-necessary session cookies this service uses. There are no optional cookies, so there is nothing to consent to.",
                   "Under Subprocessors, see the providers that process data for the hosted service.",
                   "Select Full cookie notice or Full privacy policy to open the published page with the complete details."],
          why: "The Privacy centre shows the privacy information VIGIL has already published, as published. It only reads and links out: it changes nothing, and it collects nothing new." },
        // The Data-rights screen (legal/governance S3): served under data-data-rights (VIGIL_CUSTOMER_DATA_RIGHTS, default OFF).
        { id: "datarights", title: "Your data rights", where: "Data rights", route: "#/data-rights", when: "dataRights",
          clicks: ["Open Data rights from Settings, under Your organization.",
                   "It states your rights — access, correction, deletion and export — in VIGIL's published words, and VIGIL responds to a data-rights request within 30 days at info@sigilsovereign.com.",
                   "Select Export my data to download your workspace's own records (invoices, usage and findings), or Request account deletion to record a close-account request for VIGIL to act on."],
          why: "Data rights states your rights and lets you export your own records or record a deletion request. Recording a request does not erase VIGIL's immutable, signed history by itself — that is the owner-gated hard-prune process; your request is what VIGIL acts on." },
        // The AI governance disclosure (legal/governance S5): served under data-ai-governance (VIGIL_CUSTOMER_AI_GOVERNANCE,
        // default OFF). Route-gated like Account security, so the guide hides this step where the screen is off.
        { id: "ai_governance", title: "See how VIGIL uses AI", where: "How VIGIL uses AI", route: "#/ai-governance",
          when: "aiGovernance",
          clicks: ["Under Settings, open How VIGIL uses AI.",
                   "Read what AI does (it assists and advises), what it never does (it decides no finding, no charge and no scope on its own), and where your data goes.",
                   "Every statement cites the Terms, the README or the Safety and Authorization briefing it is drawn from. Nothing on this screen can be changed: it is a disclosure only."],
          why: "VIGIL uses AI to assist and advise, never as an authority: no finding, charge or action takes effect on an AI's say-so." },
        // The Seller identity screen (legal/governance S7): served under data-seller-identity
        // (VIGIL_CUSTOMER_SELLER_IDENTITY, default OFF). A read-only display; `when` names the page switch app.js reads
        // with pageFlag, `route` lights up its tab.
        { id: "seller", title: "See who provides the service", where: "Seller identity", route: "#/seller-identity",
          when: "sellerIdentity",
          clicks: ["Select Seller identity in the top bar.",
                   "Under Who provides this service, read the company's published details: its legal name and form, where it is registered, its registration number, contact email, website and the law that governs the service.",
                   "There is nothing to fill in here: the screen only shows who you are contracting with."],
          why: "Who provides the hosted service is a legal right to know. These are the company's published details, shown for your records; the screen changes nothing and asks for nothing." },
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
          // PR-G: where this deployment shows Plans, the same step's clicks with the last one pointing there instead.
          alt: { when: "plans",
                 clicks: ["Under Buy credits, a plan adds a set of credits at the start of every billing period.",
                          "Plan credits are used first and expire at the end of their period. Credits you buy separately never expire.",
                          "Your plan, its status and its credits for this period appear under Subscription on Billing.",
                          "A workspace has one plan at a time. To change it, use Plans in the top bar."] },
          why: "A plan's credits and a pack's credits are spent the same way; only their expiry differs." },
        // PR-G: shown only where this deployment shows Plans (`when`: the page switch, asked of the app's `flag`).
        { id: "compare", title: "Compare plans and change yours", where: "Plans", route: "#/plans", when: "plans",
          clicks: ["Select Plans in the top bar to compare the trial, pay as you go and every plan: its price, the credits it adds each period and how long a period lasts.",
                   "With no plan yet, select Choose on a plan and pay on the payment processor's secure page, as when you buy credits.",
                   "With a plan, select Upgrade or Downgrade on another plan, then Yes, switch at renewal. The new plan starts at your next renewal; until then you keep your current plan and its credits, and nothing is charged that day.",
                   "Select Cancel plan, then Yes, cancel, to end it when the period you paid for ends. Keep my current plan undoes a switch or a cancellation before the renewal.",
                   "Only the founder or an admin can change the plan, and VIGIL may ask for a fresh code from your authenticator app."],
          why: "A plan change never cuts short a period you paid for and never charges you twice. A plan sets how many credits arrive each period, not what an assessment costs." },
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
      lead: "VIGIL tests and monitors a host only after you prove you control it.",
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
        { id: "connect", title: "Or connect everything in one place", where: "Connect", route: "#/connect", onlyIfShown: true,
          clicks: ["Select Connect in the top bar. It lists your workspace's websites, code repositories and cloud accounts, each with its proof state.",
                   "Under Website, select Connect a website, or Continue on one you started earlier. VIGIL picks the proof that is usually quickest for that address; choose another if it suits you better, and use Copy to copy each value exactly.",
                   "Tick I confirm I am authorized to test this asset, then select Check now. VIGIL checks again every few seconds and the site turns Verified by itself, with no reload.",
                   "Under Code repository, Connect GitHub opens the same install as the Code screen. Under Cloud account, when it is offered, Connect a cloud account lets you choose your provider — AWS, GCP, Azure or Cloudflare — and shows the exact read-only access to create for the one you pick."],
          why: "Connecting proves you own something; it never starts a test by itself. A cloud account is connected read-only, and VIGIL never changes anything in it." },
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
        // Live Control (#/live): `when` names its page switch (data-live-control); all three steps appear only where
        // the deployment serves the Live Control screen, so with the switch off the guide is unchanged.
        { id: "watch", title: "Watch VIGIL work live", where: "Live Control", route: "#/live", when: "liveControl",
          clicks: ["While an assessment runs, select Live Control in the top bar.",
                   "It shows what VIGIL is doing right now, step by step — scanning the surface, running the authorized checks, recording the evidence.",
                   "The list fills in on its own while the screen is open. It shows the stage of the work only, never a secret, an address or any detail of your target."],
          why: "You see the assessment's progress as it happens, in plain words, with nothing sensitive on the screen." },
        { id: "steer", title: "Tell VIGIL what to focus on", where: "Live Control", route: "#/live", when: "liveControl",
          clicks: ["On Live Control, under Steer the assessment, type what you want VIGIL to concentrate on, for example \"concentrate on authentication\" or \"check the admin API\".",
                   "Select Send to VIGIL. It weighs your note on its next step.",
                   "Your note is advice, not a command: VIGIL still passes every authorization and evidence check, and it never widens the scope of what you authorized."],
          why: "You guide the work in your own words while it runs, and the safety rules still hold — your note can never make VIGIL test something you did not authorize." },
        { id: "pause", title: "Pause or resume from Live Control", where: "Live Control", route: "#/live", when: "liveControl",
          clicks: ["On Live Control, select Pause to hold the assessment where it is, or Resume to carry on.",
                   "Pause and Resume appear only when the run can be paused or resumed."],
          why: "You stay in control of a run as it happens, without cancelling it." },
        { id: "findings", title: "Read your findings", where: "Assessments", route: "#/assessments",
          clicks: ["In Assessments, select View findings for the host.",
                   "Each finding shows its severity, its class, where it was found and how strong the proof is.",
                   "Use Verify offline to re-run the proof yourself, without VIGIL."],
          why: "VIGIL lists a finding only when a deterministic check confirmed it on evidence your host produced. Anything it could not prove is never shown as a finding." },
        // PR-B: `when` names the page switch (data-posture) the Fix first screen is served under.
        { id: "fixfirst", title: "Fix the worst first", where: "Fix first", route: "#/fix-first", when: "posture",
          clicks: ["Select Fix first in the top bar. At the top is your security posture: a score out of 100 for the findings still open on your verified hosts, and how it changed over the last twelve weeks.",
                   "Below it, every open finding is listed worst first. Each says what the weakness is, what VIGIL's check proved, the standards it touches and exactly how to fix it.",
                   "Fix the first one on your side, then select Retest on it. When its proof no longer works, it moves to Fixed and your score goes up.",
                   "Select How the score works to see how each finding counts, or Show the numbers to read the trend as a table."],
          why: "The score is a way to decide what to fix first, not a certified rating. It counts only findings VIGIL proved on your own hosts." },
        { id: "attackpath", title: "See how findings chain into impact", where: "Attack path", route: "#/attack-path",
          clicks: ["When VIGIL proves that separate findings combine, select Attack path in the top bar.",
                   "Each chain reads top to bottom: a confirmed step leads to the next, ending in the real-world impact an attacker reaches.",
                   "Every node is a step VIGIL confirmed — it draws only chains it proved, never a guess, and claims no impact it did not establish.",
                   "A finding confirmed out of band also shows a Confirmed out-of-band badge in its card, with the signed callback you can check yourself.",
                   "Select View findings to open the findings behind a chain."],
          why: "A chain shows the real-world consequence of findings that look minor on their own — exactly how an attacker would combine them into a breach." },
        { id: "retest", title: "Confirm a fix", where: "Assessments", route: "#/assessments",
          clicks: ["Fix the weakness on your side.",
                   "Open the finding and select Retest. VIGIL re-runs that finding's proof against your host.",
                   "When the proof no longer works, the finding is marked fixed.",
                   "Or launch a new assessment of the host to check everything again."],
          why: "A finding counts as fixed only when its proof stops working." },
        // PR-G: each shown only where this deployment offers that part of Reports (`when`: its page switch).
        { id: "report", title: "Download a report", where: "Reports", route: "#/reports", when: "reportExport",
          clicks: ["Select Reports in the top bar, then Download report.",
                   "The report lists every proven finding worst first, in plain language: what it is, how to fix it, the standards it touches and the command that re-runs its proof without VIGIL.",
                   "Select Download PDF for the same report as a PDF, where your workspace offers one.",
                   "During a trial, the full report unlocks with your first purchase."],
          why: "The report holds only what VIGIL proved, so you can hand it to an auditor or a customer as it is." },
        { id: "standards", title: "See the standards your findings touch", where: "Reports", route: "#/reports",
          when: "compliance",
          clicks: ["On Reports, Standards mapping lists the OWASP Top 10 categories, PCI DSS requirements and SOC 2 criteria that your proven findings implicate, each with the findings behind it.",
                   "A finding whose retest shows its proof no longer works is marked fixed.",
                   "A control with no proven weakness is only that: VIGIL never states that a control is met or that you are compliant."],
          why: "The mapping comes only from proven findings, never from a guess." },
      ],
    },
    {
      id: "redpen", title: "Red-Pen and GitHub",
      lead: "Connect GitHub and VIGIL reviews your code: every pull request, or a whole repository.",
      steps: [
        { id: "connect", title: "Connect your GitHub account", where: "Code", route: "#/code",
          clicks: ["Select Code in the top bar, then Connect GitHub. VIGIL sends you to GitHub.",
                   "On GitHub, choose the account or organization that owns your repositories.",
                   "Choose Only select repositories, then pick the repositories VIGIL may review.",
                   "Select Install. GitHub sends you back to VIGIL, and your repositories appear under Code."],
          why: "VIGIL works only on the repositories you picked. GitHub is supported first; other code hosts come later." },
        { id: "pr", title: "Red-Pen reviews every pull request", where: "Code", route: "#/code",
          clicks: ["Open or update a pull request on a connected repository. Red-Pen starts on its own.",
                   "It maps what the change touches, attacks it from many angles, and tries to reproduce each problem it suspects in an isolated copy of your code.",
                   "Only a problem it reproduced is posted, as a review comment on the pull request, with the command that reproduces it and the evidence.",
                   "Critical and High findings block the merge through the VIGIL Red-Pen check. Medium and Low findings are comments only.",
                   "Anything Red-Pen could not reproduce stays in VIGIL for you to review, and is never posted as a finding."],
          why: "Reviews are charged by use, like any assessment." },
        { id: "settings", title: "Choose what blocks a merge", where: "Code", route: "#/code",
          clicks: ["Select Code in the top bar and find the repository.",
                   "Under Red-Pen, choose what blocks a merge: Nothing, Critical and High, or Medium and up.",
                   "Optionally set a monthly spending limit in credits for the repository, then select Save. Once it is reached, new reviews wait until the next month and VIGIL tells you."],
          why: "VIGIL never estimates what a review will cost; the limit is how you cap it." },
        { id: "system", title: "Review a whole repository", where: "Code", route: "#/code",
          clicks: ["Select Code in the top bar and find the repository.",
                   "Under Red-Pen System, select Review now to review the whole repository now.",
                   "Or select Weekly or Monthly, and VIGIL reviews it on its own. No schedule stops it."],
          why: "The findings follow the same rule: only reproduced problems are reported." },
        { id: "fix", title: "Fix a finding", where: "Code", route: "#/code",
          clicks: ["In Code, select Fix this on a finding.",
                   "VIGIL writes a patch, then checks it: the reproduction now passes, your tests pass, and a quick Red-Pen of the patch finds nothing new.",
                   "Only then does VIGIL open a pull request with the fix, for you to review and merge.",
                   "After you merge it, select Retest on the finding to confirm the fix."],
          why: "VIGIL never merges anything itself. A finding counts as fixed only when its reproduction stops failing." },
        { id: "disconnect", title: "Disconnect a repository", where: "GitHub", route: null,
          clicks: ["On GitHub, open Settings, then Applications, then the VIGIL app.",
                   "Remove a repository from its list, or uninstall the app.",
                   "VIGIL stops reviewing it straight away. Findings already reported stay in VIGIL.",
                   "To stop reviews without changing anything on GitHub, select Disconnect on the repository in Code, then Yes, disconnect."],
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
        { id: "monitor", title: "Turn on monitoring for a host", where: "Monitoring", route: "#/monitoring",
          clicks: ["Make sure the host shows Verified in Assets.",
                   "Select Monitoring in the top bar. It lists your hosts and whether AEGIS monitors each one.",
                   "Select Turn on Observe to have AEGIS watch the host's traffic and report attacks, or Turn on Respond to also block them. Turn on Respond appears only when your plan includes Respond.",
                   "Confirm with your authenticator app if VIGIL asks for a fresh code.",
                   "Monitoring starts for that host and runs until the end of your plan period."],
          why: "Turning monitoring on needs the founder or an admin. Without monitoring turned on, traffic to the host passes through AEGIS uninspected." },
        { id: "events", title: "Connect your traffic and see events", where: "Monitoring", route: "#/monitoring",
          clicks: ["VIGIL sets your host up behind the managed AEGIS gateway with you.",
                   "Open Monitoring to see the events for your hosts, newest first. Only your workspace sees them.",
                   "Each event shows when it happened, the host, the kind of attack, whether it was confirmed and what AEGIS did, such as Blocked.",
                   "The list refreshes by itself while Monitoring is open. The bell in the top bar tells you when something new arrives."],
          why: "Each event is checked before it reaches you; a report that cannot be verified is never shown." },
        { id: "manage", title: "Change or stop monitoring", where: "Monitoring", route: "#/monitoring",
          clicks: ["Open Monitoring and find the host.",
                   "Select Switch to Observe or Switch to Respond to change what AEGIS does. Moving from Respond to Observe turns blocking off.",
                   "Select Turn off, then Yes, turn off, to stop monitoring it. Its traffic then passes through uninspected.",
                   "Monitoring carries on when your plan renews, and ends when the plan is cancelled. It also ends when the host's proof expires, so keep the proof current."],
          why: "You can turn monitoring off at any time." },
        { id: "settings", title: "Fine-tune the armed window", where: "Monitoring settings", route: null,
          clicks: ["Open Monitoring settings from the Settings menu. It lists each host you have monitoring turned on for.",
                   "Each host shows the mode it is in and how long its authority stays armed before it must be renewed.",
                   "Select Shorten window to re-arm a host for a shorter time. VIGIL never extends a window beyond its standard length.",
                   "Select Re-arm, then Yes, re-arm, to renew a host to the full standard window from now, in the same mode — its proof of control is re-checked, and the window is never extended beyond that standard length.",
                   "On an AEGIS Respond plan, a host you are watching in Observe shows Release to enforce. Select it, then Yes, release to enforce, to have AEGIS begin blocking confirmed attacks on it — its armed window is unchanged, and you can switch it back to Observe on the Monitoring screen at any time.",
                   "Select Turn off here, then Yes, turn off, to stop monitoring a host — the same as on the Monitoring screen."],
          why: "A shorter armed window is least-privilege: the monitoring authority auto-expires sooner, and you re-arm it to full length when you choose. It changes nothing a manager cannot already do on the Monitoring screen." },
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
    { q: "Can I give our results to an auditor or a customer?", when: "reportExport",   // PR-G: only with the report
      a: "Yes. On Reports, select Download report. It holds only the findings VIGIL proved, each with the command that re-checks it without VIGIL, and the standards they touch. VIGIL never states that you are compliant: the mapping shows only what proven findings implicate." },
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
  // Whether the Guide screen lists a step: always, unless it is marked onlyIfShown — then only when the app says its
  // screen is shown (no `shown`, or a hidden screen, leaves it out: the guide never describes a screen it cannot vouch for).
  function stepListed(s, env) {
    return !s.onlyIfShown || (!!s.route && typeof env.shown === "function" && !!env.shown(s.route));
  }

  // PR-G: a step, a question or a step's `alt` clicks that carry `when` (the name of a page switch, e.g. "plans") exist
  // only where the app's `flag(when)` says the edge turned that switch on; without a `flag`, never. Nothing else moves.
  function guideWhen(env, when) { return !when || (typeof env.flag === "function" && env.flag(when) === true); }

  /** Whether the Guide screen lists step `s`: always, unless it names a page switch (`when`) — then only where
   *  `shown(route)` says this deployment shows its screen (no `shown` at all: not listed, the safe direction). */
  function listed(s, shown) { return !s.when || (typeof shown === "function" && !!shown(s.route)); }

  /**
   * The Guide screen's body. env: {h, username, storage, nav, replayTour, chapter, shown, flag}. Chapter tabs on top;
   * each step of the chapter is a card that opens to its clicks, in order, with "Go to <screen>" and a per-step "Mark as
   * done". `shown(route)` (optional) says whether this deployment shows that screen: no "Go to" leads to one it hides,
   * and a step that names a page switch (`when`) is listed only where shown(route) says its screen is shown (with no
   * shown(), never) — so a switched-off screen leaves the guide exactly as it was without that step.
   * `flag(name)` (optional) answers a page switch, for the steps and questions that carry `when` (see guideWhen).
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
        root.appendChild(h("div.cust-guide-steps", {}, FAQ.filter(function (f) { return guideWhen(env, f.when); }).map(function (f) {
          return h("details.card.cust-guide-faq", {}, [h("summary", { text: f.q }), h("p.cust-tour-why", { text: f.a })]);
        })));
        return;
      }
      var steps = ch.steps.filter(function (s) { return guideWhen(env, s.when) && stepListed(s, env) && listed(s, env.shown); });
      var cards = steps.map(function (s, n) {
        var key = stepKey(env.username, ch.id, s.id);
        var isDone = !!safeGet(env.storage, key);
        var open = n === 0;
        var clicks = (s.alt && s.alt.when && guideWhen(env, s.alt.when)) ? s.alt.clicks : s.clicks;
        var detail = h("div.cust-guide-detail", {}, [
          h("ol.cust-tour-clicks", {}, clicks.map(function (c) { return h("li", { text: c }); })),
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
        if (s.route && typeof env.nav === "function" && (typeof env.shown !== "function" || env.shown(s.route))) {
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
