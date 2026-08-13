"""
report.plainspeak — the plain-language vocabulary shared by every document in a dossier.

One place holds the sentences that translate the engine's internal vocabulary into words a
regulator, an auditor or a client executive can read. Two documents draw on it — the per-finding
write-ups in the case file, and the catalogue of what the engine is capable of looking for — and
they must say the same thing about the same category, so the sentences live here rather than in
either of them.

Everything in this module describes a CATEGORY of weakness, or a METHOD of confirmation, in
general terms. Nothing here describes any particular system, and nothing here is derived from an
engagement. That distinction is load-bearing and it is repeated wherever these sentences are
rendered: the general description of a category says what that KIND of weakness can lead to, and
it is never evidence of what was demonstrated on the system examined. Only a finding's own proof
establishes that, and the case file states the two separately.

The descriptions are generic, long-established knowledge about well-known weakness categories —
the same standing as the class-level remediation table in :mod:`report.generate` — so rendering
them deterministically asserts nothing that was not public knowledge before the engagement ran.

Where no description is on file, every function here says so plainly and hands back the engine's
own wording instead. Improvising a friendly-sounding description for a category nobody wrote one
for would be the one failure mode this module exists to prevent.

Pure, deterministic, no I/O.
"""

from __future__ import annotations

from typing import Optional

# --------------------------------------------------------------------------------------------------
# plain-language descriptions of weakness categories
#
# Matched by substring against the bug class, then against the finding title (many passive
# observations share the bug class "passive" and carry their meaning in the title instead). An
# unmatched finding falls through to an honest "no plain-language description is on file".
# --------------------------------------------------------------------------------------------------

_PLAIN_BY_CLASS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("boolean_sqli", "time_based_sqli", "error_based_sqli", "sqli", "sql_injection", "nosqli"),
     "The system builds the questions it asks its database by pasting in text that a visitor "
     "supplied. A visitor who supplies the right text can therefore change the question itself, "
     "rather than merely answering it.",
     "Database questions decide who is allowed in and what information comes back. Somebody who "
     "can rewrite them can normally read records they were never meant to see — including other "
     "people's personal data — and on many systems can also change or delete them. This is one "
     "of the most damaging categories of weakness in existence."),
    (("reflected_xss", "stored_xss", "dom_xss", "xss", "reflection_context", "dom_execution"),
     "Text that a visitor supplies is placed back into the web page as working code instead of "
     "as ordinary text, so the visitor's browser runs it.",
     "A browser does whatever the page tells it to do. Someone who can put their own code into "
     "the page can act as any person who opens the affected link — seeing what that person sees "
     "and doing what that person is allowed to do, including on their account."),
    (("ssti", "template_injection", "evaluation"),
     "Text a visitor supplies is treated as part of the page's own template — that is, as "
     "instructions to the system rather than as content.",
     "Instructions supplied by a visitor can be made to run on the organisation's own server. "
     "That is usually the most serious outcome possible, because it puts the visitor in control "
     "of the machine rather than merely of the page."),
    (("command_injection", "os_command", "rce"),
     "Text a visitor supplies reaches a place where the system runs operating-system commands.",
     "This lets an outsider run their own programs on the organisation's server. Everything that "
     "server can reach is then within their reach as well."),
    (("ssrf",),
     "The system can be persuaded to fetch an address chosen by a visitor, and it does so from "
     "inside the organisation's own network.",
     "Internal systems are usually protected by being unreachable from outside. Turning the "
     "organisation's own server into the messenger removes that protection, and is a common route "
     "to internal administration interfaces and cloud credentials."),
    (("path_traversal", "lfi", "rfi"),
     "The system builds file names out of text a visitor supplied, and does not stop a visitor "
     "from stepping outside the folder it intended to use.",
     "It allows files to be read (and sometimes written) that were never meant to be available — "
     "commonly configuration files containing passwords and keys."),
    (("xxe", "blind_xxe"),
     "The system's document reader will follow references to outside resources that a submitted "
     "document names.",
     "A submitted document can make the server fetch files from its own disk or from inside the "
     "network, and return them to the sender."),
    (("idor", "bola", "insecure_direct", "broken_object"),
     "The system decides what to show based on an identifier in the request, without checking "
     "that the person asking is entitled to that particular record.",
     "Changing a number in a web address becomes enough to read or alter somebody else's record. "
     "It is a frequent cause of large personal-data breaches because it scales: one request per "
     "record, repeated."),
    (("bfla", "broken_function", "auth_bypass", "authentication_bypass", "authorization", "authz",
      "privilege_escalation", "priv_esc"),
     "A check that was supposed to decide who may perform an action either does not run or can be "
     "sidestepped.",
     "People end up able to perform actions reserved for someone more senior — often including "
     "administrative actions. Every other control that assumes 'only an administrator can do this' "
     "is weakened at the same time."),
    (("deserial",),
     "The system rebuilds live program objects directly from data it received, rather than reading "
     "the data as plain values.",
     "Carefully shaped data can make the system run the sender's instructions while it is "
     "rebuilding the object."),
    (("open_redirect",),
     "The system will forward a visitor on to any web address supplied in the request.",
     "A link that genuinely begins with the organisation's own address can land the visitor on an "
     "attacker's page. It makes fraudulent messages far more convincing, because the visible "
     "address really is the organisation's."),
    (("cors",),
     "The system tells browsers that other websites may read its responses.",
     "Another website, opened in the same browser, can read data belonging to the signed-in "
     "person — data the browser would otherwise keep to this site alone."),
    (("host_header",),
     "The system trusts the address name supplied by the requester when it builds links and "
     "redirects.",
     "It allows links in emails such as password resets to be pointed at an attacker's site while "
     "still being generated by the real system."),
    (("jwt", "signature", "missing_signature"),
     "The system does not properly check the digital signature that is supposed to prove a token "
     "or message is genuine.",
     "Tokens and messages can be forged. Anything the system decides on the basis of them — who "
     "somebody is, what they paid, what they are allowed to do — can be dictated by the forger."),
    (("weak_tls", "tls_weakness", "weak_cipher"),
     "The encrypted connection between visitors and the system permits outdated protection that is "
     "no longer considered sound.",
     "Someone positioned on the network — on shared wi-fi, or at an internet provider — has a "
     "better chance of reading or altering traffic that should be private."),
    (("request_smuggling",),
     "Two systems in the chain that handles requests disagree about where one request ends and the "
     "next begins.",
     "An attacker can attach a hidden request to their own, which the second system then treats as "
     "if it came from the next visitor."),
    (("rate_limit",),
     "The system does not limit how many times an action can be attempted.",
     "Passwords, codes and vouchers can be guessed by sheer repetition, and the service can be "
     "exhausted by a single sender."),
    (("mass_assignment",),
     "The system copies every field it receives onto its own records, including fields the sender "
     "was never meant to set.",
     "A sender can set fields such as 'administrator' or 'balance' simply by adding them to an "
     "ordinary request."),
    (("exposure", "info_disclosure", "info-disclosure"),
     "Information the system was not meant to publish is reachable by anyone who asks for it.",
     "What is exposed determines the harm: at best it helps an attacker plan, at worst it is "
     "credentials or personal data with no further step required."),
    (("supply_chain", "dependency", "framework_version", "outdated"),
     "The system runs a third-party component with publicly known weaknesses.",
     "Weaknesses in widely used components are documented in public and are among the first "
     "things attackers try, because the same attack works against every organisation that has "
     "not updated."),
)

_PLAIN_BY_TITLE: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("content-security-policy",),
     "The system does not tell visitors' browsers which sources of code they are permitted to run "
     "on its pages.",
     "This instruction is the safety net that limits the damage when a code-injection weakness "
     "exists somewhere else on the site. Without it, such a weakness reaches further than it "
     "otherwise would. On its own it causes no direct harm."),
    (("x-frame-options", "clickjack"),
     "The system does not tell browsers to refuse to display its pages inside another website's "
     "page.",
     "An attacker can lay the real site invisibly over their own page, so that a person believes "
     "they are clicking something harmless while they are in fact clicking a real button on the "
     "real site — approving a payment or a permission change."),
    (("x-content-type-options", "mime sniffing"),
     "The system does not tell browsers to stop guessing what kind of file they have been sent.",
     "A browser that guesses wrongly may treat a file supplied by a visitor as program code and "
     "run it."),
    (("referrer-policy",),
     "The system does not limit the address information browsers pass on when a visitor follows a "
     "link away from it.",
     "Web addresses often contain identifiers such as account or document references. Passing them "
     "to other websites discloses where the person had been and what they were looking at."),
    (("permissions-policy",),
     "The system does not state which browser capabilities — camera, microphone, location — its "
     "pages are allowed to use.",
     "Stating this is what stops injected code on the site from reaching a visitor's hardware. On "
     "its own the omission causes no direct harm."),
    (("cross-origin-opener", "coop"),
     "The system does not ask browsers to keep its pages isolated from pages opened by other sites.",
     "Isolation limits what a page opened from elsewhere can learn about, or do to, a page of this "
     "site that is open at the same time."),
    (("cross-origin-embedder", "coep"),
     "The system does not ask browsers to require that everything it loads has explicitly agreed "
     "to be loaded by it.",
     "It weakens the browser-level isolation that protects data held in memory by the page."),
    (("cross-origin-resource", "corp"),
     "The system does not state which other sites may load its resources.",
     "Other sites can embed its resources, which in some browser conditions helps them infer "
     "information about them."),
    (("x-permitted-cross-domain-policies",),
     "The system does not tell certain browser plug-ins where they may load its data from.",
     "It applies to legacy plug-in technology. The risk is small on a modern estate but the "
     "instruction costs nothing to add."),
    (("hsts", "strict-transport-security"),
     "The system does not instruct browsers to insist on an encrypted connection in future.",
     "A visitor's first request, or a request made from an old link, can be downgraded to an "
     "unencrypted one that somebody on the network can read or alter."),
    (("version banner", "version disclosed", "server version"),
     "The system announces to every visitor exactly which software and version it is running.",
     "It removes guesswork for an attacker: rather than probing to find out what the system is, "
     "they can look up the published list of known weaknesses for that precise version."),
    (("directory listing",),
     "The system shows the contents of a folder to anyone who asks for it.",
     "Files never meant to be found — backups, notes, old versions — become discoverable simply by "
     "browsing."),
    (("cookie",),
     "A cookie the system sets is missing one of the protective attributes browsers understand.",
     "Cookies usually carry the visitor's session. Missing protections make a session easier to "
     "steal or to misuse from another site."),
)

# How each deterministic check establishes its result, in plain language. The checks are named in
# the machine record as "oracles"; these sentences describe the METHOD, and are generic to the
# method rather than specific to any finding. An unknown check falls through to a generic sentence
# that names it rather than describing something it may not do.
_ORACLE_PLAIN: dict[str, str] = {
    "differential_response": (
        "We sent the system one harmless request and one modified request, and compared the two "
        "replies. They differed in a way that only occurs when the modification genuinely changed "
        "what the system did, rather than merely what it displayed."
    ),
    "reflection_context": (
        "We sent the system a unique marker and then examined the page that came back. The marker "
        "had become a live part of the page rather than ordinary text, which is what makes "
        "supplied text executable."
    ),
    "error_signature": (
        "We sent a modified request and the system replied with an internal error message "
        "characteristic of the underlying component processing the modification rather than "
        "rejecting it."
    ),
    "sql_injection_breakout": (
        "We sent a request modified so that, if the text were being pasted into a database "
        "question, it would break out of the surrounding quotation. The system's reply showed "
        "that it had."
    ),
    "oob_callback": (
        "We supplied an address belonging to a listener under our control. The system connected "
        "to that listener, which only happens if it genuinely acted on the supplied address."
    ),
    "statistical_timing": (
        "We repeatedly timed the system's replies to modified and unmodified requests. The "
        "difference was consistent and large enough to rule out ordinary variation."
    ),
    "achieved_state": (
        "We checked the state of the system after the request and found it had reached a state "
        "that only the attempted action produces."
    ),
    "sanitizer_signal": (
        "We ran the target under an instrumentation tool that reports memory-safety violations, "
        "and it reported one during the request."
    ),
}


# A SHORT one-line meaning for the catalogue, where a full paragraph per row would be unreadable.
# Keyed the same way as the tables above; the fallback names the category rather than describing it.
_SHORT_BY_CLASS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("boolean_sqli", "time_based_sqli", "error_based_sqli", "sqli", "sql_injection"),
     "Supplied text changes the question the system asks its database."),
    (("nosqli",), "Supplied text changes the query the system runs against a document database."),
    (("ldap_injection",), "Supplied text changes a directory-service lookup."),
    (("xpath_injection",), "Supplied text changes a query run against an XML document."),
    (("reflected_xss", "stored_xss", "dom_xss", "xss"),
     "Supplied text is placed into a web page as working code rather than as text."),
    (("ssti", "template_injection", "el_injection"),
     "Supplied text is treated as instructions to the system rather than as content."),
    (("command_injection", "os_command", "rce"),
     "Supplied text reaches a place where the system runs operating-system commands."),
    (("ssrf",), "The system can be made to fetch an address chosen by the requester."),
    (("path_traversal", "lfi", "rfi"),
     "File names built from supplied text can step outside the intended folder."),
    (("xxe", "blind_xxe"),
     "The document reader follows references to outside resources named in a submitted document."),
    (("deserial",), "The system rebuilds live program objects directly from received data."),
    (("idor", "bola", "broken_object", "insecure_direct"),
     "A record is returned on the strength of an identifier, without checking entitlement to it."),
    (("bfla", "broken_function", "broken_access_control", "authorization", "authz"),
     "A check on who may perform an action does not run, or can be sidestepped."),
    (("auth_bypass", "authentication_bypass"), "The check on who somebody is can be sidestepped."),
    (("privilege_escalation", "priv_esc"), "A user can obtain rights reserved for someone more senior."),
    (("mass_assignment",), "Fields the sender was never meant to set are copied onto the record."),
    (("open_redirect",), "The system forwards visitors to any address supplied in the request."),
    (("cors",), "Other websites are told they may read this system's responses."),
    (("host_header",), "The address name supplied by the requester is trusted when building links."),
    (("jwt",), "The signature proving a token is genuine is not properly checked."),
    (("request_smuggling",),
     "Two systems in the request chain disagree about where one request ends."),
    (("request_race",),
     "Two requests arriving together produce an outcome neither would alone."),
    (("websocket", "cross_site_websocket"),
     "A long-lived browser connection is opened or driven by a party that should not be able to."),
    (("graphql_introspection", "graphql_suggestions"),
     "The query interface publishes its own internal structure to anyone who asks."),
    (("graphql_depth_limit", "graphql_alias", "graphql_batching", "graphql_cost"),
     "The query interface accepts requests that cost far more to answer than to send."),
    (("business_logic",),
     "Each individual step works correctly, but a sequence of them reaches a state it should not."),
    (("exposure", "sensitive_exposure", "info_disclosure"),
     "Information the system was not meant to publish is reachable by anyone who asks."),
    (("security_misconfiguration",),
     "A setting that protects the system is absent or set to an unsafe value."),
    (("weak_tls", "tls_weakness", "weak_cipher"),
     "The encrypted connection permits protection no longer considered sound."),
    (("service_reachability", "port", "reachability"),
     "A network service answers from somewhere it was not expected to be reachable."),
    (("version_range", "supply_chain", "dependency", "framework_version", "outdated"),
     "A third-party component in use has publicly documented weaknesses."),
    (("iam", "policy_path", "cloud"),
     "Cloud permissions combine to let an identity reach something it should not."),
    (("k8s", "kube"), "A container-platform setting leaves the cluster weaker than intended."),
    (("prompt_injection",),
     "Text supplied to an AI feature is obeyed as an instruction rather than read as content."),
    (("system_prompt_disclosure",),
     "An AI feature can be made to reveal its own confidential instructions."),
    (("credential_stuffing",),
     "Passwords leaked from elsewhere are tried against this system's accounts at scale."),
    (("automated_access",),
     "Automated clients reach resources intended only for people using the interface."),
    (("rate_limit",), "The number of attempts at an action is not limited."),
    (("signature", "missing_signature"),
     "An inbound message is acted on without checking the signature that proves it is genuine."),
    (("sanitizer", "memory_corruption"),
     "The program mishandles memory in a way an attacker can steer."),
    (("buffer_overflow",), "The program writes past the end of a block of memory it reserved."),
    (("use_after_free",), "The program keeps using a block of memory after releasing it."),
    (("crash",), "The program stops abruptly on input an attacker controls."),
    (("anonymous_reachable", "service_reachable"),
     "A service answers requests from a caller who has not identified themselves."),
    (("imds_credential_capture",),
     "The cloud platform's internal credential service can be reached from the application."),
    (("gcp_sa_impersonation",),
     "One cloud identity can act as another without being entitled to."),
    (("excessive_privilege", "privilege_path"),
     "An identity holds more permissions than its role requires, or can chain them to reach more."),
    (("identity_misconfiguration",),
     "A setting in the sign-in system leaves accounts less protected than intended."),
    (("oidc_idtoken_forgery", "saml_assertion_tampering", "saml_structural_forgery"),
     "A single-sign-on token or assertion can be altered or forged and still be accepted."),
    (("oidc_redirect_uri",),
     "The sign-in system will return a visitor, and their token, to an address it should refuse."),
    (("email_auth_misconfiguration",),
     "The records that let recipients verify this organisation's email are missing or too permissive."),
    (("cicd_misconfiguration",),
     "A setting in the build-and-release pipeline lets untrusted input influence what ships."),
    (("mesh_misconfiguration",),
     "A setting in the internal service-to-service network is weaker than intended."),
    (("mobile_misconfiguration",),
     "A setting in the mobile application leaves data or traffic less protected than intended."),
    (("secret_credential_validity",),
     "A credential found in the open is still live and still accepted."),
    (("weak_crypto_artifact",),
     "A key, certificate or algorithm in use is below current strength guidance."),
    (("time_based",),
     "The system takes measurably longer to answer certain inputs, which leaks what it is doing."),
    (("nosql_injection_attempt", "injection_attempt"),
     "A request carried input structured to break out of a query and add instructions to it."),
)


def plain_for(bug_class: str, title: str = "") -> tuple[str, str, bool]:
    """``(what this KIND of weakness is, what it can lead to in general, description_was_missing)``.

    The second element is deliberately general: it describes the consequences the CATEGORY is known
    to produce, not what was demonstrated on any particular system. Callers must present it as such
    — the case file pairs it with a separate statement of what the finding's own proof established."""
    b = (bug_class or "").strip().lower()
    if b and b != "passive":
        for keys, what, why in _PLAIN_BY_CLASS:
            if any(k in b for k in keys):
                return (what, why, False)
    t = (title or "").strip().lower()
    if t:
        for keys, what, why in _PLAIN_BY_TITLE:
            if any(k in t for k in keys):
                return (what, why, False)
        for keys, what, why in _PLAIN_BY_CLASS:
            if any(k in t for k in keys):
                return (what, why, False)
    return (
        "No plain-language description of this category of weakness is held on file, so none is "
        "offered here rather than one being improvised. The engine's own description of what it "
        "observed is reproduced below.",
        "The consequence for this organisation has not been assessed in plain terms. Ask the "
        "engineering team to interpret the technical description before deciding how urgent it is.",
        True,
    )


def short_plain(bug_class: str) -> Optional[str]:
    """A one-line meaning for a category, for the catalogue table. ``None`` when none is on file —
    the caller then prints the category's own name and says no description is held, rather than
    inventing one."""
    b = (bug_class or "").strip().lower()
    if not b:
        return None
    for keys, text in _SHORT_BY_CLASS:
        if any(k in b for k in keys):
            return text
    return None


def oracle_plain(kind: Optional[str]) -> str:
    """How a named deterministic check establishes its result, in plain language."""
    k = (kind or "").strip()
    if not k:
        return ("An automated check confirmed it, but the record does not name which one. Treat "
                "the confirmation as unexplained until the engineering team identifies the check.")
    plain = _ORACLE_PLAIN.get(k)
    if plain:
        return plain
    return (f"An automated check named `{k}` confirmed it by re-examining the saved request and "
            f"reply. The record does not carry a plain-language description of how that particular "
            f"check works; the engineering team can look it up by that name.")


# What a firing check ESTABLISHES — the narrow claim, as distinct from the METHOD above and from
# the general consequences of the category. This is the sentence that keeps a reader from reading
# the category's worst case as a description of their own system: the category description says
# what this KIND of weakness can lead to; this says what THIS engagement actually settled.
#
# Each entry deliberately under-claims. Where a check proves something about the request alone and
# not about what the application did with it, that limit is stated in the sentence itself.
_ORACLE_ESTABLISHES: dict[str, str] = {
    "differential_response": (
        "that input supplied at this point changed what the system DID, not merely what it "
        "displayed — the reply to the modified request diverged from the reply to the harmless one "
        "by more than ordinary variation produces"
    ),
    "boolean_inference": (
        "that the system's answer flipped consistently with a true/false condition embedded in the "
        "supplied input, across repeated trials — which happens only when the input is being "
        "evaluated rather than treated as data"
    ),
    "reflection_context": (
        "that text supplied at this point reaches the page in a position where a browser treats it "
        "as code rather than as text"
    ),
    "dom_execution": (
        "that script supplied at this point actually executed inside a real browser page"
    ),
    "error_signature": (
        "that input supplied at this point reached the underlying component and was processed by "
        "it, rather than being rejected before it got there"
    ),
    "evaluation": (
        "that the server evaluated an expression supplied in the input, rather than treating it as "
        "literal text"
    ),
    "side_effect": (
        "that a unique marker placed in the input reached the internal destination under test"
    ),
    "oob_callback": (
        "that the system genuinely acted on an address supplied to it, because it connected "
        "outward to a listener under the tester's control — an event that cannot occur by accident"
    ),
    "timing": (
        "that the system's response time depended on the supplied input, consistently and by more "
        "than ordinary variation explains"
    ),
    "statistical_timing": (
        "that the system's response time depended on the supplied input, consistently and by more "
        "than ordinary variation explains"
    ),
    "achieved_state": (
        "that the system reached a state which only the attempted action produces"
    ),
    "sanitizer_signal": (
        "that the program violated memory safety while handling this request, as reported by "
        "instrumentation built into the running program"
    ),
    "sql_injection_breakout": (
        "that the value sent provably closes a quoted string and introduces database-query "
        "structure. This is established about the REQUEST. It does not by itself establish that "
        "the application went on to execute that structure"
    ),
    "command_injection_breakout": (
        "that the value sent provably contains a shell command-execution construct. This is "
        "established about the REQUEST. It does not by itself establish that the application went "
        "on to run it"
    ),
    "nosql_injection_breakout": (
        "that the value sent provably injects database query-operator structure. This is "
        "established about the REQUEST. It does not by itself establish that the application went "
        "on to execute it"
    ),
    "service_reachability": (
        "that a network service completed a real connection handshake at the address tested"
    ),
    "tls_weakness": (
        "that a real encrypted connection was negotiated using the weak setting named"
    ),
    "version_range": (
        "that the version in use falls inside the range a published advisory names as affected"
    ),
    "policy_path": (
        "that the permissions as configured allow the identity named to reach the resource named"
    ),
}


def oracle_establishes(kind: Optional[str]) -> str:
    """The NARROW claim a firing check settles — never the category's general consequences.

    Callers must render this separately from :func:`plain_for`'s second element, and must say
    which is which. Conflating them is how a reader comes to believe the worst case for a
    category was demonstrated on their own system."""
    k = (kind or "").strip()
    text = _ORACLE_ESTABLISHES.get(k)
    if text:
        return text
    if k:
        return (f"what the check named `{k}` is defined to establish. The record does not carry a "
                f"plain-language statement of that, so it is not paraphrased here — ask the "
                f"engineering team what this check proves before relying on the finding")
    return ("something the record does not name, because it does not say which check fired. Treat "
            "the confirmation as unexplained until the engineering team identifies it")


def has_oracle_plain(kind: str) -> bool:
    return (kind or "").strip() in _ORACLE_PLAIN


def oracle_plain_map() -> dict[str, str]:
    """A copy of the check-method descriptions, for a glossary that lists only the checks used."""
    return dict(_ORACLE_PLAIN)
