# Mobile iOS Security Checklist

> Reference checklist for iOS application engagements. Cross-reference with `playbooks/17-mobile.md`. Aligned with **OWASP MASVS v2** and **MASTG**.

---

## How to Use This Checklist

- Items organized by MASVS v2 control groups.
- Each item: ✅ secure | ❌ vulnerable | ⚠️ partial | ⏭ out of scope | 🚫 N/A.
- **Authorization:** static analysis of an IPA is low-risk. Dynamic analysis requires a jailbroken device (or a sideloaded build with entitlements) — confirm the client's testing posture in `targets/<name>/charter.md`.
- iOS testing is materially harder than Android due to Apple's stricter platform guarantees. Many resilience checks are platform-enforced.
- Tooling baseline: `class-dump`, `Hopper Disassembler` / `IDA` / `Ghidra`, `frida`, `objection`, `Cycript` (legacy), `Burp Suite`, `MobSF`, `Cydia Substrate`, `r2`/`radare2`.

---

## 0. Pre-Test: App Acquisition & Setup

- [ ] IPA obtained from client (preferred — TestFlight build with entitlements).
- [ ] If from App Store: requires jailbroken device + Frida or `bagbak` to extract decrypted binary.
- [ ] IPA hash recorded in `notes/test-artifacts.md`.
- [ ] `unzip app.ipa` → `Payload/<App>.app/` — extract `Info.plist`, embedded.mobileprovision, binary.
- [ ] Binary architectures (`lipo -info <App>`).
- [ ] `class-dump <App>` for Objective-C class hierarchy (less useful for Swift-heavy apps).
- [ ] `otool -hv <App>` / `otool -L <App>` — load commands, dynamic libraries.
- [ ] Binary protections: `otool -hv` for `PIE` flag; `otool -Iv` for stack canaries (`___stack_chk_fail`); ARC (`_objc_release`).
- [ ] Test device prepared: jailbroken (checkra1n / palera1n / Dopamine depending on iOS version).
- [ ] Frida server / Frida-iOS-Dump installed.
- [ ] Burp / mitmproxy CA installed and trusted in Settings → General → About → Certificate Trust Settings.

## 1. Info.plist Review

- [ ] `NSAppTransportSecurity` — `NSAllowsArbitraryLoads = YES` permits HTTP.
- [ ] Per-domain ATS exceptions (`NSExceptionDomains`).
- [ ] `NSAllowsLocalNetworking`, `NSAllowsArbitraryLoadsInWebContent`.
- [ ] `UIBackgroundModes` for unexpected modes (audio, location-tracking).
- [ ] URL Schemes registered (`CFBundleURLTypes`) — what handles them?
- [ ] Universal Links via `applinks:` entitlement (verify `apple-app-site-association` on server).
- [ ] Privacy usage strings (`NSCameraUsageDescription`, `NSContactsUsageDescription`, etc.) — match what app actually does?
- [ ] App Transport Security minimum TLS version.
- [ ] `LSApplicationQueriesSchemes` — what other apps does it probe for?

## 2. Entitlements (embedded.mobileprovision)

- [ ] Keychain access groups (cross-app keychain sharing).
- [ ] App Groups (shared container with other team apps).
- [ ] Associated Domains (Universal Links, web credentials).
- [ ] Push notification entitlement.
- [ ] iCloud entitlements (CloudKit, Documents, Key-Value).
- [ ] Network extensions (VPN, content filter) — high privilege.
- [ ] Inter-App Audio, Audio component entitlements.
- [ ] Dangerous: `com.apple.developer.kernel.increased-memory-limit`, `get-task-allow` (debug, should not be in App Store builds).

## 3. MASVS-STORAGE: Data Storage

- [ ] Sensitive data in `NSUserDefaults` (plist in app sandbox).
- [ ] Sensitive data in `Library/Caches/`, `tmp/` (not backed up but readable).
- [ ] Sensitive data in `Documents/` (backed up to iCloud).
- [ ] File protection class (`NSFileProtectionComplete`, `NSFileProtectionCompleteUntilFirstUserAuthentication`, `NSFileProtectionNone`).
- [ ] Keychain usage:
  - [ ] Item accessibility (`kSecAttrAccessibleAfterFirstUnlock`, `WhenUnlocked`, `ThisDeviceOnly`).
  - [ ] Access control (`SecAccessControlCreateWithFlags` for biometric requirement).
  - [ ] Items not migrated to new device when accessibility omits `ThisDeviceOnly`.
- [ ] Core Data / SQLite databases — encryption?
- [ ] Realm / other 3rd-party storage encryption.
- [ ] Snapshots in `Library/Caches/Snapshots/` (sensitive UI captured when app backgrounded — fix with overlay view in `applicationDidEnterBackground`).
- [ ] Pasteboard usage (general pasteboard vs named).
- [ ] iOS 14+ pasteboard access notification triggered.
- [ ] Logs (`NSLog`, `os_log`) shipped to syslog.
- [ ] Crash logs in `~/Library/Logs/CrashReporter/MobileDevice/`.
- [ ] iCloud / iCloud Drive sync of sensitive files.
- [ ] Auto-fill / Password AutoFill (iOS 12+) configuration.
- [ ] Keyboard cache for non-secure text fields (set `isSecureTextEntry = true`).

## 4. MASVS-CRYPTO: Cryptography

- [ ] CommonCrypto vs CryptoKit usage.
- [ ] Hardcoded keys / IVs in `__DATA` / `__cstring` / `__TEXT.__cstring` segments (`strings`, Hopper).
- [ ] Hardcoded keys in resources (`.plist`, embedded JSON, `Assets.car`).
- [ ] Key derivation (PBKDF2 iterations, salt).
- [ ] Symmetric: AES-GCM via CryptoKit (preferred) vs CommonCrypto with manual mode selection.
- [ ] PRNG: `SecRandomCopyBytes` / `arc4random_buf` vs `rand()`.
- [ ] Hashing: CC_SHA256+ vs CC_MD5 / CC_SHA1.
- [ ] Secure Enclave usage (kSecAttrTokenIDSecureEnclaveAttribute) for keys backing high-value operations.
- [ ] Custom crypto roll-your-own (red flag).

## 5. MASVS-AUTH

- [ ] LAContext / LocalAuthentication framework — biometric auth.
- [ ] Biometric → Keychain item ACL binding (cryptographic) vs UI-only check.
- [ ] `LAPolicy.deviceOwnerAuthenticationWithBiometrics` (biometric only) vs `deviceOwnerAuthentication` (passcode fallback).
- [ ] `evaluatedPolicyDomainState` to detect enrolled biometrics changes.
- [ ] Session token storage in Keychain with appropriate accessibility class.
- [ ] Session token lifetime / refresh.
- [ ] Logout clears Keychain entries.
- [ ] App lock on background → foreground.
- [ ] Step-up authentication for sensitive actions.

## 6. MASVS-NETWORK

- [ ] HTTPS for all endpoints.
- [ ] ATS configuration (no global `NSAllowsArbitraryLoads`).
- [ ] Certificate pinning implementation:
  - [ ] `URLSessionDelegate` `urlSession(_:didReceive:completionHandler:)`.
  - [ ] TrustKit / Alamofire ServerTrustEvaluating.
- [ ] Pinning bypass test via Frida (`SSL Kill Switch 2` on jailbroken device).
- [ ] `URLSession` `delegateQueue` and trust evaluation.
- [ ] Network request inspection via Burp/mitmproxy after CA install.
- [ ] WKWebView vs UIWebView (deprecated). UIWebView is unsafe.
- [ ] WKWebView `javaScriptEnabled`, `allowsContentJavaScript`.
- [ ] WKWebView `WKWebsiteDataStore` (persistent vs nonPersistent).
- [ ] WKWebView message handlers (`WKScriptMessageHandler`) exposing native methods to JS.
- [ ] TLS minimum version (TLSv12).

## 7. MASVS-PLATFORM

### URL Schemes & Universal Links

- [ ] Custom URL scheme handlers (`application:openURL:`/`scene:openURLContexts:`) — what actions?
- [ ] URL parameters trusted as sensitive (auth tokens, account IDs).
- [ ] URL scheme hijacking (multiple apps registering same scheme — first installed wins).
- [ ] Universal Links validation — does `apple-app-site-association` enforce path patterns?
- [ ] Universal Link → WebView with attacker URL.

### IPC

- [ ] Pasteboard for cross-app data (general pasteboard vs custom).
- [ ] App Groups containers — what's stored, what other apps in group.
- [ ] Shared Keychain access groups.
- [ ] XPC services (less common in iOS apps).
- [ ] Document picker / share extension — input validation.

### App Extensions

- [ ] Today / Widget extensions exposing data.
- [ ] Share extensions — input validation.
- [ ] Custom keyboard extensions — full access toggle, data exfil.
- [ ] Notification service extension — payload handling.

### Permissions

- [ ] Privacy permission rationale strings accurate.
- [ ] App Tracking Transparency (ATT) prompt for tracking SDKs (iOS 14.5+).
- [ ] Camera / Microphone / Location indicators visible to user.

## 8. MASVS-CODE

- [ ] Swift vs Objective-C mix; bridging issues.
- [ ] Use of unsafe pointers (`UnsafePointer`, `UnsafeMutablePointer`).
- [ ] Use of deprecated/dangerous APIs (`UIWebView`, `popen`, `system`, `strcpy`).
- [ ] `NSCoding` / `NSSecureCoding` — secure coding adopted? `decodeObject(of:forKey:)` with class restriction.
- [ ] Format string handling (`NSString stringWithFormat:` with user input).
- [ ] Path traversal in file APIs.
- [ ] CocoaPods / SPM / Carthage dependencies — outdated or vulnerable libs.
- [ ] Embedded frameworks — `lipo -info Frameworks/*.framework/*` for arch + check known CVEs.

## 9. MASVS-RESILIENCE

> Most iOS resilience comes from platform — code signing, ASLR, sandbox. Custom resilience checks below typically required only for high-risk apps.

- [ ] Jailbreak detection: existence of `/Applications/Cydia.app`, `/bin/bash`, `/etc/apt`, write to `/private/`.
- [ ] Sandbox integrity check (can app fork? can it open `/etc/master.passwd`?).
- [ ] Debugger detection (`ptrace(PT_DENY_ATTACH)`, `sysctl` for `P_TRACED`).
- [ ] Frida / Cydia Substrate detection.
- [ ] DeviceCheck / App Attest for server-side validation.
- [ ] Code obfuscation (LLVM Obfuscator, swift-obfuscator).
- [ ] String encryption.
- [ ] Anti-hooking (method swizzling detection).
- [ ] Symbol stripping.
- [ ] PIE (Position Independent Executable) for ASLR.
- [ ] Stack canaries.
- [ ] ARC (Automatic Reference Counting).

## 10. MASVS-PRIVACY

- [ ] Privacy manifest (`PrivacyInfo.xcprivacy`) — required by Apple for SDKs and apps using "required reason" APIs.
- [ ] Tracking SDKs (Facebook, Adjust, AppsFlyer) — disclosed?
- [ ] IDFA usage gated on ATT.
- [ ] Health, financial, location data handling.
- [ ] Data retention.

## 11. Backend Integration

- [ ] Same as Android: intercept and inventory all API calls.
- [ ] Repeat tests from `playbooks/05-api-security.md`.
- [ ] Hardcoded API keys / tokens in binary strings.
- [ ] CloudKit usage — public vs private database.
- [ ] Firebase / Realm / etc. with permissive rules.

## 12. Dynamic Analysis Workflow

```
1. Jailbroken test device, Frida-server installed.
2. Install app (TestFlight, sideload via Sideloadly with developer cert, or App Store + decrypt with bagbak).
3. Configure proxy + CA.
4. Bypass pinning if needed:
   - SSL Kill Switch 2 (tweak).
   - Frida script (`frida-ios-pinning-bypass`).
   - objection (`ios sslpinning disable`).
5. Walk all flows. Capture traffic.
6. Replay / modify requests.
7. Inspect Keychain, file system via objection (`ios keychain dump`, `env`, `ls`).
8. Frida hook sensitive methods (auth checks, pinning, jailbreak detection).
```

## 13. Common Critical Findings to Hunt

- [ ] Hardcoded API keys / Firebase secrets / AWS keys in binary.
- [ ] CloudKit public database with sensitive data.
- [ ] No pinning + corporate Wi-Fi MITM.
- [ ] Jailbreak detection trivially bypassable, **and** financially sensitive operations not bound to Secure Enclave.
- [ ] Keychain accessibility set to `kSecAttrAccessibleAlways` (most permissive, deprecated).
- [ ] Custom URL scheme triggering privileged action without auth.
- [ ] WKWebView with attacker-controlled URL + message handler exposing native Bridge.
- [ ] PII in `os_log` stream.
- [ ] Auth token in pasteboard during deep-link flows.
- [ ] Snapshot in `Snapshots/` shows balance / SSN.

## 14. Cross-References

- Playbook: `framework/playbooks/17-mobile.md`
- OWASP MASVS v2: https://mas.owasp.org/MASVS/
- OWASP MASTG: https://mas.owasp.org/MASTG/
- iOS Hacker's Handbook (Miller et al.).
- Apple Platform Security Guide: https://support.apple.com/guide/security/welcome/web
- frida.re documentation.
