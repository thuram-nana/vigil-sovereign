"use strict";
/* SIGIL Companion — canonical JSON. The JS<->Python PARITY CONTRACT.
 *
 * Byte-identical to Python (sigil/reuse/canonical.py :: canonical_json):
 *     json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")
 * This is the #1 correctness item: the desktop bridge verifies the device signature over
 * exactly these bytes (sigil/bridge/envelope.py :: envelope_message), so the phone MUST
 * reproduce them or every signature is rejected.
 *
 * PINNED PARITY VECTOR (from tests/test_bridge_envelope.py ::
 *   test_envelope_message_fixed_vector_parity):
 *     core = {"v":1,"device":"DEVKEYB64","action":"read:snapshot","args":{},"nonce":1,"ts":1700000000}
 *     canonicalJson(core)  ===  the UTF-8 bytes of the string
 *     {"action":"read:snapshot","args":{},"device":"DEVKEYB64","nonce":1,"ts":1700000000,"v":1}
 *
 * Why plain JSON.stringify is safe for the LEAVES: over the SIGIL value domain — ASCII object
 * keys; strings; INTEGER numbers only (app.js floors ts to whole seconds and uses integer
 * nonces / seqs — floats are NEVER signed, because float repr can diverge between the two
 * runtimes); booleans; null; arrays — ECMAScript JSON.stringify emits bytes identical to Python
 * json.dumps(ensure_ascii=False): the same string escapes (\" \\ \b \t \n \f \r, all other
 * control chars as lowercase \u00xx, non-ASCII left raw, "/" NOT escaped), the same integer
 * rendering, and the same true/false/null tokens. The ONLY two things json.dumps does that plain
 * JSON.stringify does not are (1) recursive KEY SORTING and (2) the compact ","/":" separators
 * with no spaces — which is precisely, and only, what this function adds.
 *
 * Exported for BOTH the browser (window.SigilCanonical) and Node (module.exports) so the parity
 * is falsifiable: tests/test_bridge_webapp.py runs this exact function under Node and asserts the
 * bytes equal Python's envelope_message for the fixed vector.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module !== "undefined" && module.exports) { module.exports = api; }   // Node
  else { root.SigilCanonical = api; }                                              // browser / worker
})(typeof self !== "undefined" ? self : this, function () {
  function canonicalJson(value) {
    if (value === null || typeof value !== "object") {
      // string / number / boolean / null — JSON.stringify matches Python for the SIGIL domain
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
      var parts = [];
      for (var i = 0; i < value.length; i++) { parts.push(canonicalJson(value[i])); }
      return "[" + parts.join(",") + "]";
    }
    // object: sort keys (code-unit order == Unicode code-point order for ASCII keys), compact
    var keys = Object.keys(value).sort();
    var out = "";
    for (var j = 0; j < keys.length; j++) {
      var k = keys[j];
      if (j) { out += ","; }
      out += JSON.stringify(k) + ":" + canonicalJson(value[k]);
    }
    return "{" + out + "}";
  }
  return { canonicalJson: canonicalJson };
});
