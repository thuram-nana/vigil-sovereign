/* VIGIL customer app — account security: the Account security screen, passkey sign-in and the step-up prompt.
 *
 * Shown only while the edge writes data-security="1" into the page (VIGIL_CUSTOMER_SECURITY_UI, default OFF); app.js
 * decides that and calls in here. Passkeys also need data-passkey="1" (the edge serves passkeys). Like guide.js, this
 * file only DEFINES things: nothing runs at load, nothing is fetched, nothing is stored. Every element is built with
 * the UI kit's h() (passed in) or DOM calls — no HTML string is ever parsed, no inline script or style — so the strict
 * CSP holds.
 *
 * TWO-STEP VERIFICATION (an authenticator app, TOTP). "Set up" asks the edge for a new key (POST
 * api/customer/mfa/totp/enroll), which answers the otpauth:// setup link and the key ONCE: the server keeps only a
 * sealed copy and can never show it again, and from that moment it accepts codes from the new key only. This page shows
 * them in the setup panel only — a QR code drawn here (below; no library, no network), the key in groups of four and
 * the link — never in storage, a cookie or a URL, and the panel goes once a code is confirmed (POST
 * api/customer/mfa/verify). Setting it up again replaces the old key at once, so the screen asks first.
 *
 * PASSKEYS (WebAuthn). "Add a passkey": a single-use challenge (POST api/customer/passkey/enroll/challenge), the
 * browser's navigator.credentials.create (a discoverable credential for this site, so signing in needs no email), then
 * POST api/customer/passkey/enroll/verify with exactly what the server checks: credential_id (base64url of the raw id),
 * public_key_spki_b64 (standard base64 of getPublicKey(), the DER SubjectPublicKeyInfo), cose_alg
 * (getPublicKeyAlgorithm()), uv (the authenticator's user-verified flag), client_data_json (base64url) and the
 * challenge. The challenge bytes are the UTF-8 of the challenge string (webauthn.challenge_b64url). A browser without
 * WebAuthn, or without getPublicKey() (WebAuthn level 2), is told so BEFORE anything is created. No rp.id is sent: the
 * passkey belongs to this page's host, which VIGIL_CUSTOMER_PASSKEY_RP_ID must name.
 * "Sign in with a passkey": POST api/customer/passkey/login/challenge, navigator.credentials.get (no allow list: the
 * device offers its passkeys for this site), then POST api/customer/passkey/login/verify {credential_id,
 * authenticator_data, client_data_json, signature, challenge}; the edge sets the session cookie.
 *
 * STEP-UP. stepUp(env, action) runs action() — a function returning the promise of ONE request. When the server
 * refuses it with 401 {step_up_required: true}, an inline "Verify with your authenticator" box asks for a code; a
 * confirmed code (POST api/customer/mfa/verify) marks this session as freshly verified on the server, and action() runs
 * ONE more time. It never loops: that second answer, a second refusal included, goes back to the caller as it is. A
 * wrong code is said in the box and nothing is re-run; Cancel rejects with an error whose stepUpCancelled is true.
 */
(function () {
  "use strict";

  var API_DEFAULT = "api/customer";
  // The algorithms the server verifies (ui/webauthn.SUPPORTED_ALGS), most widely supported first.
  var COSE_ALGS = [-7, -257, -8];
  var PASSKEY_TIMEOUT_MS = 120000;

  function api(env) { return (env && env.api) || API_DEFAULT; }
  function kit(env) { return (env && env.VUI) || window.VUI; }
  function doc(env) { return (env && env.doc) || document; }

  // ---- bytes <-> text ------------------------------------------------------------------------------------------------
  function bytesOf(buf) {                       // ArrayBuffer / typed array / DataView -> Uint8Array view (no copy)
    if (buf instanceof Uint8Array) return buf;
    if (ArrayBuffer.isView(buf)) return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    return new Uint8Array(buf);
  }
  /** Standard base64 WITH padding — what the server's strict decoder of public_key_spki_b64 reads. */
  function b64(buf) {
    var u = bytesOf(buf), s = "";
    for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s);
  }
  /** base64url without padding — the WebAuthn wire form (credential ids, client data, authenticator data, signatures). */
  function b64url(buf) { return b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function fromB64url(s) {
    var t = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    while (t.length % 4) t += "=";
    var bin = atob(t), u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function utf8(s) { return new TextEncoder().encode(String(s)); }

  function fmtDate(ts) {
    try { return new Date(Number(ts || 0) * 1000).toISOString().slice(0, 10); } catch (e) { return "—"; }
  }
  function say(el, text) { if (el) el.textContent = String(text || ""); }

  // ---- what this browser can do ------------------------------------------------------------------------------------------
  /** "none": no WebAuthn here. "no-key": WebAuthn, but a new passkey's public key cannot reach the page
   *  (getPublicKey(), WebAuthn level 2) — VIGIL could not add it, so nothing is created. "ok": both. Signing in with a
   *  passkey needs only WebAuthn (anything but "none"). */
  function webauthnSupport() {
    var w = window, n = w.navigator;
    if (!w.PublicKeyCredential || !n || !n.credentials || typeof n.credentials.create !== "function"
        || typeof n.credentials.get !== "function") return "none";
    var R = w.AuthenticatorAttestationResponse;
    return (R && R.prototype && typeof R.prototype.getPublicKey === "function") ? "ok" : "no-key";
  }

  function codedError(code, message) { var e = new Error(message); e.code = code; return e; }

  // ---- passkeys: what is sent ----------------------------------------------------------------------------------------
  /** The body of passkey/enroll/verify for a navigator.credentials.create() result: exactly the fields the edge relays
   *  to the provisioner. Null when the browser did not hand over the public key or its algorithm (nothing is sent). */
  function registrationPayload(cred, challenge) {
    var resp = cred && cred.response;
    if (!resp || !cred.rawId || typeof resp.getPublicKey !== "function"
        || typeof resp.getPublicKeyAlgorithm !== "function") return null;
    var spki = resp.getPublicKey(), alg = resp.getPublicKeyAlgorithm();
    if (!spki || typeof alg !== "number") return null;
    var uv = false;
    if (typeof resp.getAuthenticatorData === "function") {
      var ad = bytesOf(resp.getAuthenticatorData());
      uv = ad.length > 32 && (ad[32] & 0x04) !== 0;        // the User Verified flag of the authenticator data
    }
    return { credential_id: b64url(cred.rawId), public_key_spki_b64: b64(spki), cose_alg: alg, uv: uv,
             client_data_json: b64url(resp.clientDataJSON), challenge: challenge };
  }

  /** The body of passkey/login/verify for a navigator.credentials.get() result. */
  function assertionPayload(cred, challenge) {
    var resp = cred.response;
    return { credential_id: b64url(cred.rawId), authenticator_data: b64url(resp.authenticatorData),
             client_data_json: b64url(resp.clientDataJSON), signature: b64url(resp.signature), challenge: challenge };
  }

  /** Create a passkey for the signed-in account and register it: resolves with the server's answer. env: {VUI, api,
   *  who (whoami), status (the security read)}. Rejects with e.code "unsupported" / "nokey" before anything is sent. */
  async function addPasskey(env) {
    var support = webauthnSupport();
    if (support !== "ok") throw codedError(support === "none" ? "unsupported" : "nokey", "passkeys unsupported");
    var V = kit(env), st = env.status || {};
    var user = String((env.who && env.who.username) || "");
    var r = await V.postJSON(api(env) + "/passkey/enroll/challenge", {});
    var challenge = String((r && r.challenge) || "");
    if (!challenge || !user) throw codedError("challenge", "no challenge");
    var name = String(st.account_name || user);
    var cred = await window.navigator.credentials.create({ publicKey: {
      challenge: utf8(challenge),
      rp: { name: "VIGIL" },
      user: { id: utf8(user), name: name, displayName: name },
      pubKeyCredParams: COSE_ALGS.map(function (a) { return { type: "public-key", alg: a }; }),
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "preferred" },
      excludeCredentials: (st.passkeys || []).map(function (p) { return { type: "public-key", id: fromB64url(p.id) }; }),
      attestation: "none",
      timeout: PASSKEY_TIMEOUT_MS,
    } });
    if (!cred) throw codedError("cancelled", "no passkey");
    var body = registrationPayload(cred, challenge);
    if (!body) throw codedError("nokey", "no public key");
    return V.postJSON(api(env) + "/passkey/enroll/verify", body);
  }

  /** Sign in with a passkey: resolves with the edge's login answer ({username, orgs, active_org}; the edge has set the
   *  session cookie). env: {VUI, api}. */
  async function passkeySignIn(env) {
    if (webauthnSupport() === "none") throw codedError("unsupported", "passkeys unsupported");
    var V = kit(env);
    var r = await V.postJSON(api(env) + "/passkey/login/challenge", {});
    var challenge = String((r && r.challenge) || "");
    if (!challenge) throw codedError("challenge", "no challenge");
    var cred = await window.navigator.credentials.get({ publicKey: {
      challenge: utf8(challenge), userVerification: "preferred", timeout: PASSKEY_TIMEOUT_MS } });
    if (!cred || !cred.response) throw codedError("cancelled", "no passkey");
    return V.postJSON(api(env) + "/passkey/login/verify", assertionPayload(cred, challenge));
  }

  function domErrorName(e) { return String((e && e.name) || ""); }

  /** What to tell a person whose passkey sign-in did not complete. */
  function signInMessage(e) {
    var code = e && e.code, name = domErrorName(e), st = e && e.status;
    if (code === "unsupported") return "This browser cannot use passkeys. Sign in with your email and password.";
    if (name === "NotAllowedError" || name === "AbortError" || code === "cancelled") {
      return "Passkey sign-in did not complete. Try again, or sign in with your email and password.";
    }
    if (st === 429) return "Too many attempts — wait a moment and try again.";
    if (st === 401) return "Passkey sign-in took too long. Try again.";
    if (st === 403) {
      return "VIGIL could not sign you in with that passkey. Try another one, or sign in with your email and password.";
    }
    if (st === 404) return "Passkey sign-in is not available here. Sign in with your email and password.";
    return "Passkey sign-in failed. Try again, or sign in with your email and password.";
  }

  /** What to tell a person whose passkey was not added. */
  function addMessage(e) {
    var code = e && e.code, name = domErrorName(e), st = e && e.status;
    if (code === "unsupported") return "This browser cannot create passkeys.";
    if (code === "nokey") {
      return "This browser cannot hand a new passkey to VIGIL, so none was added. Update your browser and try again.";
    }
    if (name === "NotAllowedError" || name === "AbortError" || code === "cancelled") return "No passkey was added.";
    if (name === "InvalidStateError") return "This device already has a passkey for your account.";
    if (name === "SecurityError") return "This browser would not create a passkey for this site.";
    if (name === "NotSupportedError") return "This device cannot create a passkey VIGIL accepts.";
    if (st === 429) return "Too many attempts — wait a moment and try again.";
    if (st === 404) return "Passkeys are not available here yet.";
    var detail = e && e.data && e.data.error;
    return "VIGIL could not add this passkey" + (detail ? ": " + String(detail) : ".") + " Try again.";
  }

  // ---- step-up: one fresh code, then the action ONE more time -------------------------------------------------------------
  var NOT_SET_UP = "Two-step verification is not set up for your account. Set it up in Account security, or sign in "
    + "again with your passkey, then try again.";

  function codeMessage(e) {
    var detail = String((e && e.data && e.data.error) || "");
    if (e && e.status === 429) return "Too many attempts — wait a moment and try again.";
    if (/no TOTP factor/i.test(detail)) return NOT_SET_UP;
    if (/already used/i.test(detail)) return "That code was already used. Wait for the next code in your app, then enter it.";
    if (e && e.status === 403) return "That code did not work. Enter the new code your app shows.";
    return "The code could not be checked" + (detail ? ": " + detail : ".") + " Try again.";
  }

  function isStepUpRefusal(e) { return !!(e && e.status === 401 && e.data && e.data.step_up_required === true); }

  var boxSeq = 0;
  /** The inline "Verify with your authenticator" box. Resolves once a code was verified; rejects on Cancel (an error
   *  with stepUpCancelled) or when the session has ended (that 401, for the caller to send the person to sign in). */
  function askForCode(env) {
    var h = env.h, V = kit(env), d = doc(env);
    return new Promise(function (resolve, reject) {
      var id = "stepup-code-" + (++boxSeq);
      var input = h("input#" + id + ".cust-code-input", { type: "text", inputmode: "numeric", pattern: "[0-9 ]*",
        autocomplete: "one-time-code", maxlength: "7", spellcheck: "false" });
      var msg = h("p.cust-stepup-msg", { role: "alert" });
      var verify = h("button.btn.btn-primary", { type: "button", text: "Verify" });
      var cancel = h("button.btn", { type: "button", text: "Cancel" });
      var extra = h("div.cust-stepup-extra");
      var box = h("div.cust-stepup", { role: "group", "aria-labelledby": id + "-title" }, [
        h("strong#" + id + "-title", { text: "Verify with your authenticator" }),
        h("p.cust-muted", { text: "For your security, this needs a fresh check. Enter the 6-digit code your authenticator "
          + "app shows now." }),
        h("label", { for: id, text: "6-digit code" }), input,
        h("div.row", {}, [verify, cancel]),
        msg, extra,
      ]);
      var settled = false;
      function finish(ok, err) {
        if (settled) return;
        settled = true;
        if (box.parentNode) box.parentNode.removeChild(box);
        if (ok) resolve(); else reject(err);
      }
      function cancelled() { var e = new Error("step-up cancelled"); e.stepUpCancelled = true; return e; }
      async function submit() {
        if (settled || verify.disabled) return;
        var code = String(input.value || "").replace(/\s+/g, "");
        if (!/^[0-9]{6}$/.test(code)) { say(msg, "Enter the 6 digits your authenticator app shows."); return; }
        verify.disabled = true;
        say(msg, "");
        try {
          var r = await V.postJSON(api(env) + "/mfa/verify", { code: code });
          if (r && r.ok) { finish(true); return; }
          say(msg, "That code did not work. Enter the new code your app shows.");
        } catch (e) {
          if (e && e.status === 401) { finish(false, e); return; }    // the session ended: the caller signs in again
          var text = codeMessage(e);
          say(msg, text);
          if (text === NOT_SET_UP && typeof env.nav === "function" && !extra.firstChild) {
            extra.appendChild(h("button.cust-nav-link", { type: "button", text: "Open Account security",
              onClick: function () { finish(false, cancelled()); env.nav("#/security"); } }));
          }
        }
        verify.disabled = false;
      }
      verify.addEventListener("click", submit);
      cancel.addEventListener("click", function () { finish(false, cancelled()); });
      input.addEventListener("keydown", function (ev) { if (ev && ev.key === "Enter") submit(); });
      var where = env.where;
      if (where && typeof where.appendChild === "function") { where.appendChild(box); }
      else {
        var main = d.getElementById ? d.getElementById("cust-main") : null;
        if (main) main.insertBefore(box, main.firstChild); else d.body.appendChild(box);
      }
      try { input.focus(); } catch (e) { /* focus is a convenience */ }
    });
  }

  /** Run action() once; when the server asks for a fresh second factor, ask for a code and run it ONE more time. */
  function stepUp(env, action) {
    var first;
    try { first = Promise.resolve(action()); } catch (e) { first = Promise.reject(e); }
    return first.catch(function (e) {
      if (!isStepUpRefusal(e)) throw e;
      return askForCode(env).then(function () { return action(); });
    });
  }

  // ---- the QR code for the setup link (ISO/IEC 18004) -----------------------------------------------------------------
  // Byte mode, error-correction level M, the smallest of versions 1-40 that holds the text, the mask with the lowest
  // penalty (or `mask`, for tests). Tables and steps follow the standard; the tests compare whole symbols against a
  // reference encoder's.
  var QR_ECC_PER_BLOCK = [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
                          26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
  var QR_BLOCKS = [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
                   17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];
  var QR_ECL_M = 0;                                       // the format-information bits of level M

  function qrRawModules(ver) {                            // modules left for data and error correction
    var n = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
      var align = Math.floor(ver / 7) + 2;
      n -= (25 * align - 10) * align - 55;
      if (ver >= 7) n -= 36;
    }
    return n;
  }
  function qrDataCodewords(ver) {
    return Math.floor(qrRawModules(ver) / 8) - QR_ECC_PER_BLOCK[ver - 1] * QR_BLOCKS[ver - 1];
  }
  function gfMul(x, y) {                                  // multiplication in GF(2^8) modulo x^8+x^4+x^3+x^2+1
    var z = 0;
    for (var i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11D);
      z ^= ((y >>> i) & 1) * x;
    }
    return z;
  }
  function rsDivisor(degree) {
    var r = [];
    for (var i = 0; i < degree - 1; i++) r.push(0);
    r.push(1);
    var root = 1;
    for (var k = 0; k < degree; k++) {
      for (var j = 0; j < r.length; j++) {
        r[j] = gfMul(r[j], root);
        if (j + 1 < r.length) r[j] ^= r[j + 1];
      }
      root = gfMul(root, 0x02);
    }
    return r;
  }
  function rsRemainder(data, divisor) {
    var r = divisor.map(function () { return 0; });
    data.forEach(function (b) {
      var f = b ^ r.shift();
      r.push(0);
      divisor.forEach(function (c, i) { r[i] ^= gfMul(c, f); });
    });
    return r;
  }
  function qrInterleave(data, ver) {                      // split into blocks, add each block's ECC, interleave
    var numBlocks = QR_BLOCKS[ver - 1], eccLen = QR_ECC_PER_BLOCK[ver - 1];
    var raw = Math.floor(qrRawModules(ver) / 8);
    var numShort = numBlocks - raw % numBlocks, shortLen = Math.floor(raw / numBlocks);
    var divisor = rsDivisor(eccLen), blocks = [], k = 0;
    for (var i = 0; i < numBlocks; i++) {
      var dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1));
      k += dat.length;
      var ecc = rsRemainder(dat, divisor);
      if (i < numShort) dat.push(0);                      // a placeholder, skipped when interleaving
      blocks.push(dat.concat(ecc));
    }
    var out = [];
    for (var n = 0; n < blocks[0].length; n++) {
      for (var b = 0; b < blocks.length; b++) {
        if (n !== shortLen - eccLen || b >= numShort) out.push(blocks[b][n]);
      }
    }
    return out;
  }
  function qrAlignPositions(ver) {
    if (ver === 1) return [];
    var num = Math.floor(ver / 7) + 2;
    var step = Math.floor((ver * 8 + num * 3 + 5) / (num * 4 - 4)) * 2;
    var out = [6];
    for (var pos = ver * 4 + 10; out.length < num; pos -= step) out.splice(1, 0, pos);
    return out;
  }
  var QR_MASKS = [
    function (x, y) { return (x + y) % 2 === 0; },
    function (x, y) { return y % 2 === 0; },
    function (x) { return x % 3 === 0; },
    function (x, y) { return (x + y) % 3 === 0; },
    function (x, y) { return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; },
    function (x, y) { return x * y % 2 + x * y % 3 === 0; },
    function (x, y) { return (x * y % 2 + x * y % 3) % 2 === 0; },
    function (x, y) { return ((x + y) % 2 + x * y % 3) % 2 === 0; },
  ];

  /** The QR symbol for `text` as rows of booleans (true = dark), without the quiet zone; null when it is too long. */
  function qrMatrix(text, mask) {
    var bytes = Array.prototype.slice.call(utf8(text));
    var ver = 0;
    for (var v = 1; v <= 40 && !ver; v++) {
      if (4 + (v < 10 ? 8 : 16) + 8 * bytes.length <= 8 * qrDataCodewords(v)) ver = v;
    }
    if (!ver) return null;
    var cap = 8 * qrDataCodewords(ver), bits = [];
    function put(val, n) { for (var i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1); }
    put(4, 4);                                            // byte mode
    put(bytes.length, ver < 10 ? 8 : 16);
    bytes.forEach(function (b) { put(b, 8); });
    put(0, Math.min(4, cap - bits.length));               // terminator
    put(0, (8 - bits.length % 8) % 8);
    for (var pad = 0xEC; bits.length < cap; pad ^= 0xEC ^ 0x11) put(pad, 8);
    var data = [];
    for (var i = 0; i < bits.length; i += 8) {
      var byte = 0;
      for (var j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
      data.push(byte);
    }
    var words = qrInterleave(data, ver);
    var size = ver * 4 + 17, m = [], fn = [];
    for (var y = 0; y < size; y++) {
      m.push([]); fn.push([]);
      for (var x = 0; x < size; x++) { m[y].push(false); fn[y].push(false); }
    }
    function set(x, y, dark) { m[y][x] = dark; fn[y][x] = true; }
    for (var t = 0; t < size; t++) { set(6, t, t % 2 === 0); set(t, 6, t % 2 === 0); }      // timing patterns
    [[3, 3], [size - 4, 3], [3, size - 4]].forEach(function (c) {                           // finders + separators
      for (var dy = -4; dy <= 4; dy++) {
        for (var dx = -4; dx <= 4; dx++) {
          var dist = Math.max(Math.abs(dx), Math.abs(dy)), fx = c[0] + dx, fy = c[1] + dy;
          if (fx >= 0 && fx < size && fy >= 0 && fy < size) set(fx, fy, dist !== 2 && dist !== 4);
        }
      }
    });
    var pos = qrAlignPositions(ver), na = pos.length;
    for (var ai = 0; ai < na; ai++) {
      for (var aj = 0; aj < na; aj++) {
        if ((ai === 0 && aj === 0) || (ai === 0 && aj === na - 1) || (ai === na - 1 && aj === 0)) continue;
        for (var ay = -2; ay <= 2; ay++) {
          for (var ax = -2; ax <= 2; ax++) set(pos[ai] + ax, pos[aj] + ay, Math.max(Math.abs(ax), Math.abs(ay)) !== 1);
        }
      }
    }
    function drawFormat(msk) {
      var dat = (QR_ECL_M << 3) | msk, rem = dat;
      for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
      var fb = ((dat << 10) | rem) ^ 0x5412;
      function bit(i) { return ((fb >>> i) & 1) !== 0; }
      for (var i2 = 0; i2 <= 5; i2++) set(8, i2, bit(i2));
      set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
      for (var i3 = 9; i3 < 15; i3++) set(14 - i3, 8, bit(i3));
      for (var i4 = 0; i4 < 8; i4++) set(size - 1 - i4, 8, bit(i4));
      for (var i5 = 8; i5 < 15; i5++) set(8, size - 15 + i5, bit(i5));
      set(8, size - 8, true);                             // the dark module
    }
    drawFormat(0);                                        // reserve the format areas; redrawn for the chosen mask
    if (ver >= 7) {                                       // version information
      var vr = ver;
      for (var vi = 0; vi < 12; vi++) vr = (vr << 1) ^ ((vr >>> 11) * 0x1F25);
      var vb = (ver << 12) | vr;
      for (var k = 0; k < 18; k++) {
        var dark = ((vb >>> k) & 1) !== 0, va = size - 11 + k % 3, vb2 = Math.floor(k / 3);
        set(va, vb2, dark); set(vb2, va, dark);
      }
    }
    var bi = 0, total = words.length * 8;                 // the data, in the two-column zigzag
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) {
        for (var c2 = 0; c2 < 2; c2++) {
          var zx = right - c2, up = ((right + 1) & 2) === 0, zy = up ? size - 1 - vert : vert;
          if (!fn[zy][zx] && bi < total) { m[zy][zx] = ((words[bi >>> 3] >>> (7 - (bi & 7))) & 1) !== 0; bi++; }
        }
      }
    }
    function applyMask(msk) {
      for (var yy = 0; yy < size; yy++) {
        for (var xx = 0; xx < size; xx++) { if (!fn[yy][xx] && QR_MASKS[msk](xx, yy)) m[yy][xx] = !m[yy][xx]; }
      }
    }
    var best = (typeof mask === "number" && mask >= 0 && mask < 8) ? mask : -1;
    if (best < 0) {
      var lowest = Infinity;
      for (var mk = 0; mk < 8; mk++) {
        applyMask(mk); drawFormat(mk);
        var score = qrPenalty(m);
        if (score < lowest) { lowest = score; best = mk; }
        applyMask(mk);
      }
    }
    applyMask(best);
    drawFormat(best);
    return m;
  }

  // The standard's mask penalty: runs of one colour, 2x2 blocks, finder-like runs and the dark/light balance.
  function qrPenalty(m) {
    var size = m.length, score = 0, dark = 0;
    function addHistory(run, hist) { if (hist[0] === 0) run += size; hist.pop(); hist.unshift(run); }
    function countFinder(hist) {
      var n = hist[1];
      var core = n > 0 && hist[2] === n && hist[3] === n * 3 && hist[4] === n && hist[5] === n;
      return (core && hist[0] >= n * 4 && hist[6] >= n ? 1 : 0) + (core && hist[6] >= n * 4 && hist[0] >= n ? 1 : 0);
    }
    function terminate(color, run, hist) {
      if (color) { addHistory(run, hist); run = 0; }
      addHistory(run + size, hist);
      return countFinder(hist);
    }
    function line(get) {
      var color = false, run = 0, hist = [0, 0, 0, 0, 0, 0, 0];
      for (var i = 0; i < size; i++) {
        if (get(i) === color) {
          run++;
          if (run === 5) score += 3; else if (run > 5) score++;
        } else {
          addHistory(run, hist);
          if (!color) score += countFinder(hist) * 40;
          color = get(i); run = 1;
        }
      }
      score += terminate(color, run, hist) * 40;
    }
    for (var y = 0; y < size; y++) line(function (x) { return m[y][x]; });
    for (var x = 0; x < size; x++) line(function (yy) { return m[yy][x]; });
    for (var by = 0; by < size - 1; by++) {
      for (var bx = 0; bx < size - 1; bx++) {
        var c = m[by][bx];
        if (c === m[by][bx + 1] && c === m[by + 1][bx] && c === m[by + 1][bx + 1]) score += 3;
      }
    }
    m.forEach(function (row) { row.forEach(function (v) { if (v) dark++; }); });
    var all = size * size;
    score += (Math.ceil(Math.abs(dark * 20 - all * 10) / all) - 1) * 10;
    return score;
  }

  /** The QR symbol as an SVG built node by node (no markup string): dark on white, with the 4-module quiet zone. */
  function qrSvg(d, matrix, label) {
    var NS = "http://www.w3.org/2000/svg", size = matrix.length, q = 4, full = size + 2 * q, path = "";
    for (var y = 0; y < size; y++) {
      for (var x = 0; x < size; x++) {
        if (!matrix[y][x]) continue;
        var run = 1;
        while (x + run < size && matrix[y][x + run]) run++;
        path += "M" + (x + q) + " " + (y + q) + "h" + run + "v1h-" + run + "z";
        x += run - 1;
      }
    }
    var svg = d.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 " + full + " " + full);
    svg.setAttribute("class", "cust-qr");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
    svg.setAttribute("shape-rendering", "crispEdges");
    var bg = d.createElementNS(NS, "rect");
    bg.setAttribute("width", String(full));
    bg.setAttribute("height", String(full));
    bg.setAttribute("fill", "#ffffff");
    var fg = d.createElementNS(NS, "path");
    fg.setAttribute("d", path);
    fg.setAttribute("fill", "#000000");
    svg.appendChild(bg);
    svg.appendChild(fg);
    return svg;
  }

  // ---- the Account security screen -------------------------------------------------------------------------------------
  function groupKey(key) { return (String(key || "").replace(/\s+/g, "").match(/.{1,4}/g) || []).join(" "); }

  /** Two-step verification: Set up (or Set up again, after a warning), the one-time setup panel, Confirm. */
  function totpCard(env, status, redraw) {
    var h = env.h, V = kit(env), d = doc(env);
    var on = !!(status && status.totp);
    var body = h("div.cust-sec-body", {});
    var note = h("p.cust-sec-msg", { role: "status" });
    function idle() {
      V.mount(body, on
        ? h("div.row", {}, [h("button.btn", { type: "button", text: "Set up again", onClick: warn })])
        : h("div.row", {}, [h("button.btn.btn-primary", { type: "button", text: "Set up", onClick: start })]));
    }
    function warn() {
      V.mount(body, h("div.cust-sec-warn", {}, [
        h("p", { text: "Setting it up again replaces your current authenticator: its codes stop working as soon as you "
          + "continue." }),
        h("div.row", {}, [h("button.btn.btn-primary", { type: "button", text: "Continue", onClick: start }),
                          h("button.btn", { type: "button", text: "Cancel", onClick: idle })]),
      ]));
    }
    async function start() {
      say(note, "");
      var r;
      try { r = await V.postJSON(api(env) + "/mfa/totp/enroll", {}); }
      catch (e) {
        if (e && e.status === 401) { if (typeof env.onAuthLost === "function") env.onAuthLost(); return; }
        say(note, "Two-step verification could not be set up"
          + ((e && e.data && e.data.error) ? ": " + e.data.error : ".") + " Try again.");
        return;
      }
      if (!r || !r.secret || !r.provisioning_uri) { say(note, "Two-step verification could not be set up. Try again."); return; }
      setupPanel(r.provisioning_uri, r.secret);
    }
    function setupPanel(uri, key) {
      var codeId = "sec-totp-code";
      var input = h("input#" + codeId + ".cust-code-input", { type: "text", inputmode: "numeric", pattern: "[0-9 ]*",
        autocomplete: "one-time-code", maxlength: "7", spellcheck: "false" });
      var confirm = h("button.btn.btn-primary", { type: "button", text: "Confirm" });
      var matrix = null;
      try { matrix = qrMatrix(uri); } catch (e) { matrix = null; }
      var panel = h("div.cust-sec-setup", {}, [
        h("p", { text: matrix ? "Scan this QR code with your authenticator app:" : "Add this key to your authenticator app:" }),
        matrix ? qrSvg(d, matrix, "QR code to add VIGIL to your authenticator app") : null,
        h("p", { text: matrix ? "Can't scan it? Enter this key in the app instead:" : "The key:" }),
        h("code.cust-totp-key", { text: groupKey(key) }),
        h("p", {}, h("a.cust-sec-applink", { href: uri, text: "Open in your authenticator app" })),
        h("p.cust-muted", { text: "This key is shown only once: VIGIL keeps it sealed and cannot show it again. From now "
          + "on, VIGIL accepts codes from this key only." }),
        h("label", { for: codeId, text: "6-digit code" }), input,
        h("div.row", {}, [confirm]),
      ]);
      async function doConfirm() {
        if (confirm.disabled) return;
        var code = String(input.value || "").replace(/\s+/g, "");
        if (!/^[0-9]{6}$/.test(code)) { say(note, "Enter the 6 digits your authenticator app shows."); return; }
        confirm.disabled = true;
        say(note, "");
        var r;
        try { r = await V.postJSON(api(env) + "/mfa/verify", { code: code }); }
        catch (e) {
          confirm.disabled = false;
          if (e && e.status === 401) { if (typeof env.onAuthLost === "function") env.onAuthLost(); return; }
          say(note, codeMessage(e));
          return;
        }
        if (!(r && r.ok)) { confirm.disabled = false; say(note, "That code did not work. Enter the new code your app shows."); return; }
        uri = key = null;                                 // the panel (and the key) go; the read shows "On"
        V.clear(body);
        if (typeof V.toast === "function") V.toast("Two-step verification is on.");
        redraw();
      }
      confirm.addEventListener("click", doConfirm);
      input.addEventListener("keydown", function (ev) { if (ev && ev.key === "Enter") doConfirm(); });
      V.mount(body, panel);
      try { input.focus(); } catch (e) { /* focus is a convenience */ }
    }
    idle();
    return h("section.card.cust-sec-card", { "aria-labelledby": "sec-totp-title" }, [
      h("div.cust-sec-head", {}, [
        h("h3#sec-totp-title", { text: "Two-step verification" }),
        h("span.cust-badge." + (on ? "cust-badge-verified" : "cust-badge-pending"), { text: on ? "On" : "Not set up" }),
      ]),
      h("p.cust-muted", { text: on
        ? "An authenticator app is set up for your account. VIGIL may ask for a code from it before a sensitive action."
        : "Use an authenticator app on your phone to get a 6-digit code whenever VIGIL asks for one." }),
      body, note,
    ]);
  }

  /** Passkeys: the ones registered, and Add a passkey (or why this browser or deployment cannot). */
  function passkeyCard(env, status, redraw) {
    var h = env.h, V = kit(env);
    var keys = (status && status.passkeys) || [];
    var note = h("p.cust-sec-msg", { role: "status" });
    var list = keys.length
      ? h("ul.cust-sec-list", {}, keys.map(function (k, i) {
          return h("li", { text: "Passkey " + (i + 1) + " · added " + fmtDate(k.added_at) });
        }))
      : h("p.cust-muted", { text: "No passkeys yet." });
    var support = webauthnSupport(), action;
    if (!env.passkeys) {
      action = h("p.cust-muted", { text: "Passkeys are not available here yet." });
    } else if (support === "none") {
      action = h("p.cust-muted", { text: "This browser cannot create passkeys. Open VIGIL in a current version of Chrome, "
        + "Edge, Firefox or Safari to add one." });
    } else if (support === "no-key") {
      action = h("p.cust-muted", { text: "This browser cannot add passkeys to VIGIL. Update it, or open VIGIL in a "
        + "current version of Chrome, Edge, Firefox or Safari." });
    } else {
      var add = h("button.btn.btn-primary", { type: "button", text: "Add a passkey" });
      add.addEventListener("click", async function () {
        if (add.disabled) return;
        add.disabled = true;
        say(note, "");
        try {
          var r = await addPasskey({ VUI: V, api: env.api, who: env.who, status: status });
          if (r && r.ok) {
            if (typeof V.toast === "function") V.toast("Passkey added.");
            redraw();
            return;
          }
          say(note, "VIGIL could not add this passkey. Try again.");
        } catch (e) {
          if (e && e.status === 401) { if (typeof env.onAuthLost === "function") env.onAuthLost(); return; }
          say(note, addMessage(e));
        }
        add.disabled = false;
      });
      action = h("div.row", {}, [add]);
    }
    return h("section.card.cust-sec-card", { "aria-labelledby": "sec-passkeys-title" }, [
      h("div.cust-sec-head", {}, [h("h3#sec-passkeys-title", { text: "Passkeys" })]),
      h("p.cust-muted", { text: "Sign in with your device's fingerprint, face or screen lock instead of your password." }),
      list, action, note,
    ]);
  }

  /** The Account security screen's body. env: {h, VUI, api, who, passkeys (data-passkey), nav, onAuthLost, here,
   *  loading}. Reads api/customer/security, then shows Two-step verification and Passkeys. */
  function viewSecurity(env) {
    var h = env.h, V = kit(env);
    var root = h("div.cust-sec", {},
      typeof env.loading === "function" ? env.loading("Loading…") : h("p.cust-muted", { text: "Loading…" }));
    function current() { return typeof env.here !== "function" || env.here() === "#/security"; }
    async function refresh() {
      var st;
      try { st = await V.getJSON(api(env) + "/security"); }
      catch (e) {
        if (!current()) return;
        if (e && e.status === 401) { if (typeof env.onAuthLost === "function") env.onAuthLost(); return; }
        V.mount(root, h("div.card.cust-soon", { text: "Could not load your account security"
          + ((e && e.data && e.data.error) ? ": " + e.data.error : ".") }));
        return;
      }
      if (!current()) return;
      V.mount(root, [
        h("p.cust-muted", { text: "These settings protect your own account on every workspace you belong to." }),
        totpCard(env, st, refresh),
        passkeyCard(env, st, refresh),
      ]);
    }
    refresh();
    return root;
  }

  window.VIGIL_SECURITY = {
    viewSecurity: viewSecurity, passkeySignIn: passkeySignIn, signInMessage: signInMessage, addPasskey: addPasskey,
    addMessage: addMessage, stepUp: stepUp, webauthnSupport: webauthnSupport,
    registrationPayload: registrationPayload, assertionPayload: assertionPayload, qrMatrix: qrMatrix,
  };
})();
