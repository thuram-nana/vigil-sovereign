# Playbook 17 — Mobile

**Goal:** test mobile applications (Android and iOS) for client-side
weaknesses, mobile-specific attack vectors, and gaps in the
client/server contract.

**Stage in lifecycle:** 4. Run only if the target has a mobile app
in scope.

**Standards:** OWASP MASVS (Mobile Application Security Verification
Standard); OWASP Mobile Application Security Testing Guide (MASTG).

---

## 17.1 What mobile testing is and isn't

Mobile testing has two parts:

1. **Client-side analysis** — what's in the app binary, how it
   stores data, how it communicates. This is the unique part.
2. **Server-side analysis** — the APIs the mobile app talks to are
   web APIs and are tested using playbooks 04-08, 10. Most "mobile
   findings" are actually server findings the web testers missed
   because the mobile API isn't documented as well.

The mobile binary is a goldmine for **server-side recon**: hidden
endpoints, special headers, undocumented parameters, debug flags
the server still respects. Always extract these and feed them back
into the API testing.

---

## 17.2 Acquisition and triage

### Android

```bash
# Get the APK
# Option A: from Google Play (use raccoon, gplaydl, or
#   pull from a rooted device).
# Option B: operator provides (preferred for owner-test).

# Static info
aapt dump badging app.apk
apktool d app.apk -o app-decoded/
jadx-gui app.apk        # Java/Kotlin decompilation

# Native libs
ls app-decoded/lib/
file app-decoded/lib/*/lib*.so
```

### iOS

iOS testing requires a jailbroken device or an unencrypted IPA.

```bash
# Acquire IPA from device with frida-ios-dump or bagbak.
unzip app.ipa
# Decrypt with Clutch / bagbak / frida-ios-dump.
otool -L Payload/App.app/App   # linked libraries
class-dump Payload/App.app/App # ObjC class dumping
```

Charters often allow only Android (operator's mobile is on
Android), or only iOS, or only the web component if no jailbreak
device available. Confirm scope.

---

## 17.3 OWASP MASVS test groups

The MASVS organizes mobile testing into 8 control groups (V1-V8).
Use these as scope:

| Group | Focus |
|-------|-------|
| MASVS-STORAGE | Sensitive data in local storage |
| MASVS-CRYPTO | Crypto correctness on device |
| MASVS-AUTH | Auth and session on the client |
| MASVS-NETWORK | Network communication |
| MASVS-PLATFORM | Platform interactions (IPC, deep links) |
| MASVS-CODE | Code quality / obfuscation |
| MASVS-RESILIENCE | Anti-tamper / runtime integrity |
| MASVS-PRIVACY | Privacy / data handling |

---

## 17.4 Local storage (MASVS-STORAGE)

What sensitive data does the app put on disk?

### Android

- `/data/data/<pkg>/shared_prefs/*.xml` — settings; sometimes
  contains tokens, PINs, API keys.
- `/data/data/<pkg>/databases/*.db` — SQLite. Open with
  `sqlite3` or DB Browser.
- `/data/data/<pkg>/files/` — arbitrary files.
- `/sdcard/Android/data/<pkg>/` — externally readable on older
  Android versions.
- WebView cache, cookies, localStorage in
  `app_webview/` directories.

Look for:
- API tokens / refresh tokens not in Android Keystore.
- User credentials in plain text.
- PII (real names, addresses, payment data).
- Application logs containing tokens (often `Log.d(TAG, "auth: " +
  token)` left in production).

### iOS

- App container `Documents/`, `Library/Caches/`, `tmp/`.
- Plists in `Library/Preferences/`.
- Keychain — should hold sensitive data; verify items have correct
  protection class (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  or `AfterFirstUnlock`).
- WebView state in `Library/WebKit/`.

---

## 17.5 Network (MASVS-NETWORK)

### TLS

- Cert pinning in place? Bypass with Frida (`frida-multiple-unpinning`,
  `objection`).
- If pinning is bypassable trivially (no native check), cert pinning
  is theatrical not security.

### Cleartext traffic

- Android `network-security-config.xml` — `cleartextTrafficPermitted`
  should be `false` for production domains.
- iOS `Info.plist` ATS settings — `NSAllowsArbitraryLoads` should
  be false; per-domain exceptions justified.

### Endpoint discovery

- Run the app through a proxy (Burp / mitmproxy) with a CA cert
  installed, after disabling pinning.
- Map every endpoint, every header (esp. custom auth headers),
  every parameter.
- Cross-reference against the web API surface map — the mobile API
  is usually a superset.

### Hardcoded URLs

```bash
strings -n 10 classes.dex | grep -iE 'http://|https://|api\\.|/v[0-9]/'
```

Often reveals admin / debug / staging endpoints that aren't web-
linked.

---

## 17.6 Auth (MASVS-AUTH)

- Refresh token storage (Keystore / Keychain, not SharedPreferences).
- Biometric auth properly bound to backend (challenge-response, not
  just "user pressed fingerprint = unlock locally").
- Server enforces auth (the mobile app's "logged in" state must
  match the server's session state on every request).
- Logout invalidates server-side, not just clears local state.

---

## 17.7 Platform (MASVS-PLATFORM)

### Android intents / deep links

- Exported activities/services/receivers without permission requirements
  (in `AndroidManifest.xml`):

  ```xml
  <activity android:name=".SecretActivity"
            android:exported="true">
  ```

  → can other apps invoke this?

- Custom URL schemes / App Links — what does the app do with the
  URL data? Often vulnerable to webview injection or auth bypass.

- WebView — `setJavaScriptEnabled(true)` + `addJavascriptInterface()`
  exposes Java to attacker-controlled JS in WebView; if any
  attacker-controlled URL can be loaded, RCE-on-device possible.

- Insecure ContentProvider — readable / writable by other apps.

### iOS URL schemes / Universal Links

- Custom URL schemes — race-condition with other apps registering
  the same scheme.
- Universal Links — domain ownership verified via apple-app-site-
  association file?

---

## 17.8 Code (MASVS-CODE) and Resilience (MASVS-RESILIENCE)

For consumer-facing apps with anti-fraud requirements:

- Obfuscation — code obfuscated meaningfully? (Pro-tip: most apps'
  obfuscation is decoration, not protection.)
- Root / jailbreak detection bypassable? (Almost always yes via
  Frida.)
- Anti-debug bypassable?
- Tamper detection on the binary?

Note: anti-tamper isn't a security boundary. It's a cost-raiser. Don't
mark its absence as a finding above Low unless there's a specific
business case (regulated environment, fraud-sensitive app).

---

## 17.9 Privacy (MASVS-PRIVACY)

- Permissions requested vs actually needed.
- Telemetry / analytics SDKs — what do they exfil? Many third-
  party SDKs leak more than the app does on purpose.
- Logs include PII?
- Crash reports include PII?

---

## 17.10 Mobile-specific server findings

After running the app through a proxy, you'll often find server
findings the web pass missed:

- Mobile API has weaker auth (cert pinning is the only "auth").
- Mobile API exposes admin functions the web doesn't.
- Mobile API trusts client-supplied user-id / device-id.
- Mobile API has rate-limit gaps (no per-device rate limit).
- Mobile API returns more fields than web (BOPLA across web and
  mobile clients).

These findings are scored in playbooks 04-08, but the discovery
came from mobile.

---

## 17.11 Phase exit checklist

- [ ] Binary acquired and decompiled.
- [ ] Strings / resources scanned for hardcoded secrets, URLs.
- [ ] Local storage inspected (databases, prefs, keychain).
- [ ] Network traffic captured via proxy (with pinning bypass if
       needed).
- [ ] Mobile API surface mapped and fed back to playbook 05
       (API security).
- [ ] Exported components / deep links / URL schemes audited.
- [ ] WebView usage audited.
- [ ] Findings logged.
