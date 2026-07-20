# Mobile Android Security Checklist

> Reference checklist for Android application engagements. Cross-reference with `playbooks/17-mobile.md`. Aligned with **OWASP MASVS v2** and **MASTG** (Mobile Application Security Testing Guide).

---

## How to Use This Checklist

- Items are organized by MASVS v2 control groups: **MASVS-STORAGE**, **MASVS-CRYPTO**, **MASVS-AUTH**, **MASVS-NETWORK**, **MASVS-PLATFORM**, **MASVS-CODE**, **MASVS-RESILIENCE**, **MASVS-PRIVACY**.
- Each item: ✅ verified secure | ❌ vulnerable | ⚠️ partial | ⏭ out of scope | 🚫 N/A.
- **Authorization:** static analysis of an APK provided by the client is generally low-risk. Dynamic analysis on a rooted test device of a client-owned app is also typical. Modifying an APK and republishing, or testing against production servers, requires explicit charter approval.
- Tooling baseline: `apktool`, `jadx`, `frida`, `objection`, `mobsf`, `drozer`, `Burp Suite` with Android cert installed.

---

## 0. Pre-Test: App Acquisition & Setup

- [ ] APK obtained from client (preferred) or extracted from device (`adb shell pm path com.example.app`).
- [ ] APK hash recorded (`sha256sum app.apk`) — confirm version under test in `notes/test-artifacts.md`.
- [ ] `aapt dump badging app.apk` — package name, version, min SDK, target SDK, permissions.
- [ ] `apktool d app.apk` to decompile resources and `AndroidManifest.xml`.
- [ ] `jadx-gui app.apk` for Java/Kotlin source.
- [ ] Test device prepared: rooted (Magisk), USB debugging on, Burp CA installed (System Trust on Android 7+ requires modifications).
- [ ] Frida server installed on device matching architecture.
- [ ] App signed with debug or release key (release keys are the realistic threat model).

## 1. AndroidManifest.xml Review

- [ ] `android:allowBackup` — `true` allows ADB backup of app data without root.
- [ ] `android:debuggable` — `true` allows runtime debugging via JDWP.
- [ ] `android:exported` per component (Activities, Services, Broadcast Receivers, Content Providers).
- [ ] Implicit intent filters on exported components (deep link / intent injection surface).
- [ ] `android:taskAffinity` allowing task hijacking.
- [ ] `android:launchMode` — `singleTask` / `singleInstance` strandhogg risk.
- [ ] `android:networkSecurityConfig` reference — review the XML.
- [ ] `android:usesCleartextTraffic` — `true` permits HTTP.
- [ ] `<uses-permission>` review for over-broad permissions (READ_CONTACTS, READ_SMS, ACCESS_FINE_LOCATION when not needed).
- [ ] Custom permissions defined and protection levels (`signature` vs `normal` vs `dangerous`).
- [ ] Min SDK version — older platform versions lack security features.
- [ ] Target SDK version — older targets retain legacy permission models.

## 2. MASVS-STORAGE: Data Storage

- [ ] Sensitive data in SharedPreferences (XML in `/data/data/<pkg>/shared_prefs/`).
- [ ] Sensitive data in SQLite databases (`/data/data/<pkg>/databases/`).
- [ ] Sensitive data on external storage (`/sdcard/`, world-readable historically).
- [ ] EncryptedSharedPreferences / EncryptedFile (Jetpack Security) used for sensitive data?
- [ ] Android Keystore used for key material (vs hardcoded keys)?
- [ ] StrongBox-backed Keystore (where available)?
- [ ] Key alias `setUserAuthenticationRequired(true)` for sensitive operations?
- [ ] Backup rules (`fullBackupContent`, `dataExtractionRules`) exclude sensitive data.
- [ ] Logs (`Log.d`, `Log.v`, `Log.i`) contain sensitive data (visible to other apps with READ_LOGS pre-Jelly Bean, debug builds).
- [ ] Crash reports / analytics SDKs leak PII or tokens.
- [ ] Clipboard usage — sensitive data copied without `setPrimaryClip` privacy flag.
- [ ] Cache files (HTTP cache, image cache, WebView cache) contain sensitive data.
- [ ] Database WAL files (`-wal`, `-shm`).
- [ ] Memory dumps (sensitive data lingering in memory — `frida-memory` dump test).
- [ ] Auto-fill behavior leaks credentials to system autofill.
- [ ] Screenshot in recents (FLAG_SECURE on sensitive screens?).
- [ ] Keyboard cache (passwords flagged with `inputType="textPassword"` to prevent learning?).

## 3. MASVS-CRYPTO: Cryptography

- [ ] Custom crypto implementations (red flag — should use proven libraries).
- [ ] Hardcoded keys / IVs in source.
- [ ] Hardcoded keys in resources (`strings.xml`, `assets/`, `res/raw/`).
- [ ] Key derivation: PBKDF2/scrypt/argon2 vs unsalted SHA-1.
- [ ] PRNG: `SecureRandom` vs `Random` / `Math.random()`.
- [ ] Symmetric: AES-GCM/CBC w/ HMAC vs ECB (`Cipher.getInstance("AES")` defaults to ECB on some platforms).
- [ ] Asymmetric: RSA padding (OAEP vs PKCS#1 v1.5), key size ≥ 2048.
- [ ] Hashing: SHA-256+ vs MD5 / SHA-1 (collision-broken).
- [ ] HMAC vs unkeyed hash for integrity.
- [ ] Certificate pinning implementation (NetworkSecurityConfig vs OkHttp CertificatePinner).
- [ ] Hardcoded crypto secrets revealed via static strings / Frida memory inspection.

## 4. MASVS-AUTH: Authentication & Session Management

- [ ] Authentication factor types (password, biometric, SMS OTP, TOTP, hardware key).
- [ ] Biometric auth: BiometricPrompt API used (vs deprecated FingerprintManager)?
- [ ] BiometricPrompt: `setUserAuthenticationRequired` on Keystore key (cryptographic binding) vs UI-only check.
- [ ] Session token storage location (Keystore-backed?).
- [ ] Session token lifetime / refresh.
- [ ] Logout flow clears tokens locally and invalidates server-side.
- [ ] App lock / re-authentication on app foreground.
- [ ] Step-up authentication for sensitive actions (transfers, settings changes).
- [ ] Account recovery flow security.
- [ ] Multi-device session enumeration / revocation.
- [ ] OAuth flows: PKCE used? redirect URI validation? state parameter?
- [ ] SSO integration (Google Sign-In, Facebook, custom OIDC).

## 5. MASVS-NETWORK: Network Communication

- [ ] HTTPS enforced for all endpoints (no `http://` in source).
- [ ] `usesCleartextTraffic` and per-domain network security config.
- [ ] Certificate pinning: implemented? what type (cert vs SPKI hash)?
- [ ] Pinning bypassable via Frida hooks (test as part of resilience).
- [ ] User-installed CAs trusted (development convenience often left in production).
- [ ] TLS version: 1.2+ enforced.
- [ ] Cipher suite restrictions.
- [ ] WebView `loadUrl` with HTTP scheme.
- [ ] WebView `mixedContentMode` allowing HTTP within HTTPS pages.
- [ ] Server hostname verification not disabled (`HostnameVerifier ALLOW_ALL`).
- [ ] Trust manager not bypassed (`TrustAllCerts`).
- [ ] HTTP request signing / HMAC?

## 6. MASVS-PLATFORM: Platform Interaction

### Components

- [ ] Exported Activities accept Intents from any app — what data do they trust?
- [ ] Activity launch from Intent → privileged action without authentication?
- [ ] Exported Services — bound from any app?
- [ ] AIDL interfaces — input validation.
- [ ] Exported Broadcast Receivers — accept broadcast from any app?
- [ ] Sticky broadcasts containing sensitive data (deprecated, but still present).
- [ ] Content Providers exported with `android:exported="true"`.
- [ ] Content Provider grant URI permissions (path traversal in `openFile`).
- [ ] Content Provider SQL injection in selection / projection.

### Deep Links

- [ ] Deep links (`<data android:scheme="...">`) — what actions are reachable?
- [ ] App Links (verified domain associations via `assetlinks.json`)?
- [ ] Deep link parameters used to bypass authentication or load arbitrary URLs.
- [ ] Deep link → WebView with attacker-controlled URL (XSS / token theft).
- [ ] Deep link → file:// scheme allowed (local file read in WebView).

### WebView

- [ ] `setJavaScriptEnabled(true)` plus `addJavascriptInterface` exposes Java methods to web JS (RCE if attacker-controlled URL loaded).
- [ ] `setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs` (file:// origin SOP bypass).
- [ ] `setAllowContentAccess`.
- [ ] WebView SSL error handler accepts any cert (`onReceivedSslError → handler.proceed()`).
- [ ] WebView debugging enabled in release builds.
- [ ] Custom URL scheme handlers in WebView intercept `intent://` and trigger Activities.

### Permissions

- [ ] Runtime permissions requested only when needed.
- [ ] Permission rationale shown.
- [ ] Permission downgrade on `targetSdkVersion` increase.

## 7. MASVS-CODE: Code Quality

- [ ] Use of `eval`-style execution (`DexClassLoader`, dynamic code loading from external storage).
- [ ] JNI / native code in `lib/` — review for memory corruption vectors.
- [ ] Insecure deserialization (Java serialization, Parcelable from untrusted source).
- [ ] Intent extras parsed without type checking (`getSerializableExtra`).
- [ ] Path traversal in file operations (`new File(getFilesDir(), userInput)`).
- [ ] Tapjacking protection (`filterTouchesWhenObscured` on sensitive views).
- [ ] StrandHogg 1/2 mitigations.
- [ ] Janus / v2 signature scheme.
- [ ] Up-to-date dependencies (Gradle dependency report; check known CVEs).
- [ ] OWASP Dependency-Check / Mobile Audit on libraries.

## 8. MASVS-RESILIENCE: Anti-Tampering & Anti-Reversing

> Resilience controls are typically only required for high-risk apps (banking, IP-protection). The threat model dictates whether absence of these is a finding.

- [ ] Root detection (multiple checks: Magisk presence, su binary, build tags).
- [ ] Emulator detection.
- [ ] Debugger detection (`Debug.isDebuggerConnected`, ptrace anti-attach in native).
- [ ] Frida / objection / runtime instrumentation detection.
- [ ] Code obfuscation (R8/ProGuard, name obfuscation, control flow obfuscation, string encryption).
- [ ] APK integrity check (resource hash verification).
- [ ] Signature verification at runtime (detect repackaging).
- [ ] SafetyNet / Play Integrity API attestation.
- [ ] Anti-hooking (Frida-detector, Xposed-detector).
- [ ] Native libraries stripped of symbols.
- [ ] String encryption / lazy decryption.

> When testing, **demonstrate** bypass via Frida hooks — don't just say "could be bypassed."

## 9. MASVS-PRIVACY

- [ ] Personal data collection inventory (map to privacy policy / charter).
- [ ] Tracking SDKs (Facebook SDK, Firebase Analytics, AppsFlyer, Adjust) — what do they exfiltrate?
- [ ] Permission to data flow mapping (location → which servers?).
- [ ] User consent for tracking (especially on EEA / IDFA equivalent).
- [ ] Data retention on device.
- [ ] Data deletion on logout / uninstall.
- [ ] Children's data (COPPA / Play Families Policy if applicable).

## 10. Backend Integration (often where the real bugs are)

- [ ] Mobile app → API endpoints inventoried (intercept Burp / mitmproxy, Frida hooks).
- [ ] API authentication mechanism (JWT, API key, mTLS, OAuth).
- [ ] Hardcoded API keys / tokens in APK (extract via static analysis).
- [ ] Firebase / Supabase / parse-server endpoints — public read?
  - Firebase Realtime DB: `https://<project>.firebaseio.com/.json` (public read often enabled).
  - Firestore rules — `allow read, write: if true;` (catastrophic).
- [ ] AWS S3 / GCS bucket URLs in app — public list?
- [ ] Map endpoints, repeat all server-side tests from `playbooks/05-api-security.md`.
- [ ] Client-side trust assumptions (e.g., "is_admin" field in API response controlling UI) — flip in proxy.

## 11. Dynamic Analysis Workflow

```
1. Install app on rooted test device.
2. Configure proxy + cert (Burp / mitmproxy with Frida cert-pinning bypass if needed).
3. Walk all flows: register, login, core features, logout, account deletion.
4. Capture all traffic.
5. Decode TLS-pinned traffic via:
   - Frida universal pinning bypass (`frida-codeshare:masbridge`).
   - objection (`android sslpinning disable`).
   - Manual pinning bypass via OkHttp/TrustKit hooks.
6. Replay requests outside the app context.
7. Replay with modified parameters (IDOR, business logic).
8. Test other users' data via known IDs.
```

## 12. Common Critical Findings to Hunt

- [ ] Hardcoded API keys / AWS credentials / Firebase secrets in APK.
- [ ] Firebase database / Firestore with permissive rules.
- [ ] Backup-allowed app + sensitive data in `/data/data/<pkg>/`.
- [ ] Exported Activity that performs privileged action without authentication.
- [ ] Content Provider SQL injection.
- [ ] WebView `addJavascriptInterface` + attacker-controlled URL.
- [ ] Janus-vulnerable signature scheme.
- [ ] No certificate pinning + corporate Wi-Fi MITM.
- [ ] No biometric → Keystore binding (UI-only biometric).
- [ ] Deep link bypassing login flow.
- [ ] PII in `Log.d` shipped to production.

## 13. Cross-References

- Playbook: `framework/playbooks/17-mobile.md`
- OWASP MASVS v2: https://mas.owasp.org/MASVS/
- OWASP MASTG: https://mas.owasp.org/MASTG/
- Android Security Internals (Elenkov).
- frida.re documentation.
- objection: https://github.com/sensepost/objection
