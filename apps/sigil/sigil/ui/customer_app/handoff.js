/* VIGIL customer app — the page that shows the pairing code after Google sign-in for the installed app.
 *
 * The edge serves that page at the end of a Google sign-in an installed app started (custui._handoff_page). Usually
 * it opens in a browser outside the app, and the person goes back to the app and types the code there. If it opened
 * inside the installed app itself (no browser around it, no way back), this shows "Continue in VIGIL", which returns
 * to the app's code box. It changes nothing else: no request, no storage. CSP-native (external, same-origin).
 */
(function () {
  "use strict";
  var standalone = navigator.standalone === true
    || !!(window.matchMedia && window.matchMedia("(display-mode: standalone)").matches);
  var el = document.getElementById("handoff-continue");
  if (standalone && el) el.hidden = false;
})();
