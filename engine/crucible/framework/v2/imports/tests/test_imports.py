"""
imports — external-tool importers (Wave 6).

Pins the load-bearing guarantees:

  * every supported format parses a captured third-party export into leads, and a
    MALFORMED export fails LOUD (never a silent no-op);
  * importing mints GROUNDING_INTEL leads into the world-model — labelled
    ``lead: True, unverified: True``, NEVER a ``FINDING`` node (prove-don't-guess);
  * the importer is DETERMINISTIC + IDEMPOTENT (claim-keyed obs_ids; a re-import does
    not inflate belief or node count);
  * the importer as a gated tool is REFUSED by a tripped kill-switch (fail-closed).
"""

from __future__ import annotations

import json

import pytest

from framework.v2.imports import (
    ImportAdapterError,
    available_formats,
    detect_format,
    import_report,
    parse_export,
)
from framework.v2.imports.tool import ImportFindingsTool
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import GROUNDING_GROUNDED, NodeKind

# --- captured third-party fixtures -----------------------------------------

NUCLEI = (
    '{"template-id":"CVE-2021-44228","matched-at":"http://t.example/api","host":"t.example",'
    '"info":{"name":"Log4j RCE","severity":"critical"}}\n'
    '{"template-id":"tech-detect","matched-at":"http://t.example/","info":{"name":"nginx","severity":"info"}}'
)
ZAP = json.dumps({"site": [{"@name": "http://t.example", "alerts": [
    {"alert": "Cross Site Scripting (Reflected)", "riskdesc": "High (Medium)",
     "instances": [{"uri": "http://t.example/search", "param": "q", "evidence": "<script>"}]},
]}]})
BURP = json.dumps({"issues": [
    {"name": "SQL injection", "severity": "high", "confidence": "certain",
     "url": "http://t.example/item?id=1", "issueDetail": "confirmed"},
]})
SQLMAP = (
    "sqlmap identified the following injection point(s):\n"
    "Parameter: id (GET)\n    Type: boolean-based blind\n    Type: time-based blind\n"
)
GENERIC = json.dumps({"findings": [
    {"bug_class": "idor", "url": "http://t.example/account?id=7", "severity": "high",
     "confirmed": False, "evidence": "swapped id"},
    {"type": "open_redirect", "location": "http://t.example/go", "severity": "medium"},
]})
# A wapiti 3.2.10 report SHAPE, taken from a live run on this host. The `infos` header is the
# load-bearing part and was previously absent from this fixture: wapiti locates each finding by a
# bare PATH and names the scanned host exactly once, there. A fixture without it made "wapiti
# findings have no host" look like a property of the TOOL, when it was a property of the fixture.
WAPITI = json.dumps({"vulnerabilities": {
    "SQL Injection": [{"method": "GET", "path": "/product", "parameter": "id", "level": 3,
                       "info": "SQL Injection via injection in the parameter id"}],
    "Open Redirect": [{"method": "GET", "path": "/go", "parameter": "url", "level": 1,
                       "info": "Open Redirect via injection in the parameter url"}],
}, "infos": {"target": "http://t.example/", "date": "Fri, 14 Aug 2026 07:36:16 +0000",
             "version": "Wapiti 3.2.10", "scope": "folder", "crawled_pages_nbr": 3}})
# The same report with its header stripped — the degradation case. A wapiti report that names no
# target must still import, just unanchored, exactly as it did before the header was consulted.
WAPITI_NO_INFOS = json.dumps({"vulnerabilities": json.loads(WAPITI)["vulnerabilities"]})
# A nikto 2.6.0 report captured from a live run on this host (`nikto -h http://127.0.0.1:18711
# -Format json -output … -Tuning x6`) — every key, every value, and the finding text are the
# tool's own. Only the scanned host is renamed to the documentation host the rest of this file
# uses; nikto records `host` as it was given and `ip` as resolved, so this is exactly the pairing
# a real run against `t.example` writes. Two properties of the shape are load-bearing and were
# both got wrong before:
#   * the TOP LEVEL IS AN ARRAY of per-host blocks. Nikto's report plugin pushes each host onto
#     an arrayref and encodes THAT (`json_host_start`/`json_close` in nikto_report_json.plugin),
#     so a single-host scan is still an array. A bare host object — which is what this fixture
#     used to be — is a shape nikto never emits, and testing against it let `detect_format`
#     route every real report to the generic parser unnoticed.
#   * each vulnerability's `url` is a bare PATH, and the host lives on the block, not the item.
NIKTO = json.dumps([{
    "end_time": "2026-08-13 17:13:14 -0400",
    "host": "t.example", "ip": "127.0.0.1", "port": "18711",
    "server_banner": None,
    "start_time": "2026-08-13 17:13:05 -0400",
    "vulnerabilities": [
        {"id": 999996, "method": "GET", "url": "/robots.txt",
         "references": "https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt",
         "msg": "contains 1 entry which should be manually viewed."},
        {"id": "600720", "method": "HEAD", "url": "/", "references": "",
         "msg": "SimpleHTTP/0.6 appears to be outdated (current is at least 1.2)."},
        {"id": "013587", "method": "GET", "url": "/",
         "references": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
         "msg": "Suggested security header missing: content-security-policy."},
    ],
}])
# --- ffuf / httpx / hydra: captured from LIVE runs of the real binaries on this host -------------
# Every one of these three fixtures is the tool's own output, captured by running the real binary
# against a local HTTP target (a python `http.server` serving /admin, /robots.txt and a Basic-auth
# /private, plus a POST login form). Nothing here is transcribed from a man page. Only the scanned
# host is renamed to the documentation host the rest of this file uses — ffuf, httpx and hydra all
# print the host exactly as it was given them, so this is byte-for-byte what a run against
# `t.example` writes. Tool versions: ffuf 2.1.0-dev, hydra 9.7, ProjectDiscovery httpx (installed on
# Kali as `httpx-toolkit`, because the plain `httpx` name belongs to an unrelated Python HTTP
# client). The shape of a fixture is the whole point of it: a fixture of the WRONG shape is what
# previously let a broken nikto sniffer look correct, so these were captured, not imagined.

# `ffuf -u http://t.example:18821/FUZZ -w wl.txt -noninteractive -of json -o ffuf.json`.
# The `config` block of a real report carries ~50 further keys (threads, matchers, wordlists, …);
# neither the parser nor the sniffer reads any of them — only that the envelope is PRESENT — so it
# is abbreviated here. `results` and the top-level keys are verbatim.
FFUF = json.dumps({
    "commandline": "ffuf -u http://t.example:18821/FUZZ -w wl.txt -noninteractive -of json -o ffuf.json",
    "time": "2026-08-13T18:39:48-04:00",
    "results": [
        {"input": {"FFUFHASH": "f80301", "FUZZ": "admin"}, "position": 1, "status": 200,
         "length": 10, "words": 2, "lines": 1, "content-type": "text/html",
         "redirectlocation": "", "scraper": {}, "duration": 271684, "resultfile": "",
         "url": "http://t.example:18821/admin", "host": "t.example:18821"},
        {"input": {"FFUFHASH": "f80304", "FUZZ": "private"}, "position": 4, "status": 401,
         "length": 0, "words": 1, "lines": 1, "content-type": "",
         "redirectlocation": "", "scraper": {}, "duration": 562718, "resultfile": "",
         "url": "http://t.example:18821/private", "host": "t.example:18821"},
        {"input": {"FFUFHASH": "f80302", "FUZZ": "robots.txt"}, "position": 2, "status": 200,
         "length": 14, "words": 2, "lines": 2, "content-type": "text/html",
         "redirectlocation": "", "scraper": {}, "duration": 919511, "resultfile": "",
         "url": "http://t.example:18821/robots.txt", "host": "t.example:18821"},
    ],
    "config": {"url": "http://t.example:18821/FUZZ", "method": "GET", "outputformat": "json",
               "outputfile": "ffuf.json", "threads": 40, "timeout": 10},
})
# The SAME run against a wordlist that matched nothing — ffuf writes the identical envelope with an
# empty `results`. The clean control's report is a RESULT, not an unreadable file.
FFUF_CLEAN = json.dumps({
    "commandline": "ffuf -u http://t.example:18821/FUZZ -w wl-empty.txt -noninteractive -of json -o ffuf.json",
    "time": "2026-08-13T18:44:02-04:00", "results": [],
    "config": {"url": "http://t.example:18821/FUZZ", "method": "GET", "outputformat": "json"},
})
# ffuf's OTHER real JSON form — `-json` on stdout, one result object per line. Captured from the
# same scan. Note `input` here is BASE64: "cHJpdmF0ZQ==" is "private", "YWRtaW4=" is "admin". `-of
# json` leaves those plain. That difference is why the location is always read off `url`.
FFUF_STDOUT_JSONL = (
    '{"input":{"FFUFHASH":"ZmJjNWU0","FUZZ":"cHJpdmF0ZQ=="},"position":4,"status":401,"length":0,'
    '"words":1,"lines":1,"content-type":"","redirectlocation":"",'
    '"url":"http://t.example:18821/private","duration":232520,"scraper":{},"resultfile":"",'
    '"host":"t.example:18821"}\n'
    '{"input":{"FFUFHASH":"ZmJjNWUx","FUZZ":"YWRtaW4="},"position":1,"status":200,"length":10,'
    '"words":2,"lines":1,"content-type":"text/html","redirectlocation":"",'
    '"url":"http://t.example:18821/admin","duration":384939,"scraper":{},"resultfile":"",'
    '"host":"t.example:18821"}'
)

# `httpx -u <url> -silent -no-color -disable-update-check -json` (two URLs, `-td` on the first).
HTTPX = (
    '{"timestamp":"2026-08-13T18:40:17.57146177-04:00","port":"18821",'
    '"url":"http://t.example:18821/private","input":"http://t.example:18821/private",'
    '"scheme":"http","webserver":"CapTarget/1.0","method":"GET","host":"t.example",'
    '"host_ip":"127.0.0.1","path":"/private","time":"540.146µs","a":["127.0.0.1"],'
    '"tech":["Basic"],"words":0,"lines":0,"status_code":401,"content_length":0,"failed":false,'
    '"knowledgebase":{"pHash":0}}\n'
    '{"timestamp":"2026-08-13T18:40:17.572123043-04:00","port":"18821",'
    '"url":"http://t.example:18821/","input":"http://t.example:18821/","title":"Cap Target",'
    '"scheme":"http","webserver":"CapTarget/1.0","content_type":"text/html","method":"GET",'
    '"host":"t.example","host_ip":"127.0.0.1","path":"/","time":"640.748µs","a":["127.0.0.1"],'
    '"words":2,"lines":1,"status_code":200,"content_length":56,"failed":false,'
    '"knowledgebase":{"pHash":0}}'
)
# The probe of a port with nothing on it (`-probe`): httpx says so explicitly rather than staying
# quiet. The ABSENCE of an endpoint must not become an endpoint.
HTTPX_FAILED = (
    '{"timestamp":"2026-08-13T18:40:18.860611975-04:00","url":"http://t.example:19999/",'
    '"input":"http://t.example:19999/","error":"19999 chain=\\"connection refused\\"","words":0,'
    '"lines":0,"status_code":0,"content_length":0,"failed":true}'
)

# `hydra -s 18821 -L users.txt -P pass.txt -t 4 t.example http-get /private` — a run that CRACKED
# the account. Verbatim stdout, banner and all.
HYDRA = (
    "Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or "
    "secret service organizations, or for illegal purposes (this is non-binding, these *** ignore "
    "laws and ethics anyway).\n\n"
    "Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-13 18:42:51\n"
    "[DATA] max 4 tasks per 1 server, overall 4 tasks, 6 login tries (l:2/p:3), ~2 tries per task\n"
    "[DATA] attacking http-get://t.example:18821/private\n"
    "[18821][http-get] host: t.example   misc: /private   login: admin   password: secret123\n"
    "1 of 1 target successfully completed, 1 valid password found\n"
    "Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-08-13 18:42:51\n"
)
# The SAME command against a form login: `http-post-form "/login:user=^USER^&pass=^PASS^:Login
# failed"`. The `misc` field here holds a colon-delimited spec whose last segment is a SENTENCE —
# spaces and all — which is what makes whitespace-splitting this line wrong.
HYDRA_FORM = (
    "Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-13 18:43:19\n"
    "[DATA] max 4 tasks per 1 server, overall 4 tasks, 6 login tries (l:2/p:3), ~2 tries per task\n"
    "[DATA] attacking http-post-form://t.example:18822/login:user=^USER^&pass=^PASS^:Login failed\n"
    "[18822][http-post-form] host: t.example   misc: /login:user=^USER^&pass=^PASS^:Login failed"
    "   login: admin   password: secret123\n"
    "1 of 1 target successfully completed, 1 valid password found\n"
)
# The NEGATIVE CONTROL: the identical command with a wordlist that contains no valid password.
# hydra prints its banner and its summary and NO hit line.
HYDRA_CLEAN = (
    "Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or "
    "secret service organizations, or for illegal purposes.\n\n"
    "Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-13 18:43:00\n"
    "[DATA] max 4 tasks per 1 server, overall 4 tasks, 4 login tries (l:2/p:2), ~1 try per task\n"
    "[DATA] attacking http-get://t.example:18821/private\n"
    "1 of 1 target completed, 0 valid password found\n"
    "Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-08-13 18:43:00\n"
)

SARIF = json.dumps({
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "Semgrep", "rules": [
        {"id": "xss-rule", "properties": {"tags": ["security", "external/cwe/cwe-079"]}},
        {"id": "sqli-rule", "properties": {"cwe": "CWE-89"}},
        {"id": "secret-rule", "properties": {"tags": ["external/cwe/cwe-798"]}}]}},
        "results": [
            {"ruleId": "xss-rule", "level": "error", "message": {"text": "Reflected XSS"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "http://t.example/search"},
                                                 "region": {"startLine": 1}}}]},
            {"ruleId": "sqli-rule", "level": "warning", "message": {"text": "SQLi"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/db.py"},
                                                 "region": {"startLine": 42}}}]},
            {"ruleId": "passing", "kind": "pass", "message": {"text": "ok"}}]}]})


# --- parsing ----------------------------------------------------------------

@pytest.mark.parametrize("fmt,export,min_n,has_host", [
    ("nuclei", NUCLEI, 2, True), ("zap", ZAP, 1, True), ("burp", BURP, 1, True),
    ("sqlmap", SQLMAP, 1, False), ("generic", GENERIC, 2, True), ("sarif", SARIF, 2, True),
    ("nikto", NIKTO, 3, True), ("wapiti", WAPITI, 2, True),
    ("ffuf", FFUF, 3, True), ("httpx", HTTPX, 2, True), ("hydra", HYDRA, 1, True),
])
def test_each_format_parses(fmt, export, min_n, has_host) -> None:
    findings, tool = parse_export(fmt, export)
    assert len(findings) >= min_n
    assert all(f.bug_class for f in findings)
    # host is derived for the asset-tier observation on URL-bearing exports. sqlmap's
    # stdout carries only the parameter, not the URL, so no host is derivable — honest, not
    # a bug. Nikto's and wapiti's hosts are not on the finding at all: nikto's is on the
    # enclosing per-host block and wapiti's is in the report header's `infos.target`, which
    # is why `parse_nikto_export` and `parse_wapiti_export` lift them. (This case asserted
    # `False` for wapiti until a live 3.2.10 report showed `infos` is a STRUCTURED object
    # carrying the target, not the free-text blob the fixture's omission implied.)
    if has_host:
        assert any(f.host == "t.example" for f in findings)
    else:
        assert all(not f.host for f in findings)


def test_wapiti_findings_are_anchored_to_the_scanned_host() -> None:
    """Wapiti's bare-path locations are qualified with the host its report header names, so a
    finding lands on a real endpoint instead of a path-keyed node every host would share."""
    findings, _ = parse_export("wapiti", WAPITI)
    assert {f.host for f in findings} == {"t.example"}
    assert {f.location for f in findings} == {"http://t.example/product?id", "http://t.example/go?url"}
    # and the surfaces stay distinct per host, which is the point of anchoring them
    other = json.loads(WAPITI)
    other["infos"]["target"] = "http://other.example/"
    other_findings, _ = parse_export("wapiti", json.dumps(other))
    assert {f.location for f in findings} & {f.location for f in other_findings} == set()


def test_wapiti_parameter_only_finding_gets_no_invented_url() -> None:
    """A finding with no `path` falls back to the bare parameter name. That is not a path, so it
    is left alone rather than joined onto the site root — the host is a fact, `/id` would not be."""
    report = json.dumps({"vulnerabilities": {"SQL Injection": [
        {"method": "GET", "parameter": "id", "level": 3, "info": "SQLi in id"}]},
        "infos": {"target": "http://t.example/"}})
    findings, _ = parse_export("wapiti", report)
    assert [f.location for f in findings] == ["id"]
    assert [f.host for f in findings] == ["t.example"]


def test_wapiti_report_without_a_header_degrades_to_unanchored() -> None:
    """A report that names no target imports exactly as it did before: findings survive,
    unanchored. The correction never invents a host it was not told."""
    findings, _ = parse_export("wapiti", WAPITI_NO_INFOS)
    assert len(findings) == 2
    assert all(not f.host for f in findings)
    assert {f.location for f in findings} == {"/product?id", "/go?url"}


def test_wapiti_reflected_xss_maps_to_the_canonical_class() -> None:
    """`Reflected Cross Site Scripting` is the label wapiti 3.2 actually emits for its `xss`
    module; it must reach the engine's canonical `xss` class, not a slug of its own."""
    report = json.dumps({"vulnerabilities": {"Reflected Cross Site Scripting": [
        {"method": "GET", "path": "/search", "parameter": "q", "level": 2,
         "info": "Reflected Cross Site Scripting vulnerability found via injection in the parameter q"}]},
        "infos": {"target": "http://t.example/"}})
    findings, _ = parse_export("wapiti", report)
    assert [f.bug_class for f in findings] == ["xss"]


def test_available_formats_stable() -> None:
    assert available_formats() == ["burp", "ffuf", "generic", "httpx", "hydra", "nikto", "nuclei",
                                   "sarif", "sqlmap", "wapiti", "zap"]


def test_sarif_cwe_mapping_and_code_locations() -> None:
    findings, tool = parse_export("sarif", SARIF)
    by_class = {f.bug_class: f for f in findings}
    # a URL-located finding tagged CWE-79 maps to the CRUCIBLE `xss` class + a host -> re-verifiable
    assert "xss" in by_class
    assert by_class["xss"].host == "t.example" and by_class["xss"].severity == "High"
    # a file-located SAST finding (CWE-89) maps to `sqli` but has NO host (a code location, aggregation)
    assert "sqli" in by_class and by_class["sqli"].host == "" and "src/db.py" in by_class["sqli"].location
    # the passing result (kind=pass) is skipped
    assert "passing" not in by_class
    # every SARIF finding is tool_confirmed=False (a LEAD — CRUCIBLE re-verifies, never trusts say-so)
    assert all(not f.tool_confirmed for f in findings)


def test_sarif_non_sarif_json_is_loud() -> None:
    with pytest.raises(ImportAdapterError):
        parse_export("sarif", json.dumps({"findings": []}))   # a generic export, not SARIF


def test_unknown_format_is_loud() -> None:
    with pytest.raises(ImportAdapterError, match="unknown import format"):
        parse_export("nessus-xml", "<xml/>")


def test_malformed_export_is_loud() -> None:
    # non-JSON where JSON is promised -> a clean adapter error, never a silent []
    with pytest.raises(ImportAdapterError):
        parse_export("zap", "this is not json")
    with pytest.raises(ImportAdapterError):
        parse_export("generic", "not json at all")


def test_generic_skips_malformed_entries_without_aborting() -> None:
    export = json.dumps({"findings": [
        "not-an-object", {"bug_class": "xss", "url": "http://t.example/x"}]})
    findings, _ = parse_export("generic", export)
    assert len(findings) == 1 and findings[0].bug_class == "xss"


def test_detect_format_covers_every_supported_format() -> None:
    """Every registered format must be reachable by the operator-convenience path, or be honestly
    documented as explicit-key-only. Nothing here is: all eleven are self-describing."""
    for fmt, export in [("nuclei", NUCLEI), ("zap", ZAP), ("burp", BURP), ("sqlmap", SQLMAP),
                        ("generic", GENERIC), ("sarif", SARIF), ("wapiti", WAPITI),
                        ("nikto", NIKTO), ("ffuf", FFUF), ("httpx", HTTPX), ("hydra", HYDRA)]:
        assert detect_format(export) == fmt, fmt
    assert set(available_formats()) == {"nuclei", "zap", "burp", "sqlmap", "generic", "sarif",
                                        "wapiti", "nikto", "ffuf", "httpx", "hydra"}


def test_detect_format() -> None:
    assert detect_format(NUCLEI) == "nuclei"
    assert detect_format(ZAP) == "zap"
    assert detect_format(BURP) == "burp"
    assert detect_format(SQLMAP) == "sqlmap"
    assert detect_format(GENERIC) == "generic"
    assert detect_format(SARIF) == "sarif"
    assert detect_format(WAPITI) == "wapiti"
    assert detect_format(NIKTO) == "nikto"
    assert detect_format("") is None
    assert detect_format("plain text, no shape") is None


# --- nikto: the report is an ARRAY, and the sniffer has to know it -----------

def test_a_real_nikto_report_is_sniffed_as_nikto_not_generic() -> None:
    """The defect this pins: nikto's real report is a TOP-LEVEL ARRAY of per-host blocks, and
    the sniffer's only nikto branch looked at a top-level OBJECT — so every real report fell
    through to `if isinstance(data, list): return "generic"`. The operator convenience path
    (`import --format` omitted, `ImportFindingsTool`) then parsed a scanner report with the
    tool-neutral parser."""
    assert json.loads(NIKTO).__class__ is list, "the fixture must be the shape nikto emits"
    assert detect_format(NIKTO) == "nikto"

    findings, tool = parse_export(detect_format(NIKTO), NIKTO)
    assert tool == "nikto" and len(findings) == 3
    assert {f.tool for f in findings} == {"nikto"}
    # every finding keeps the two things the misroute destroyed
    assert all(f.bug_class != "unknown" for f in findings)
    assert all(f.location for f in findings)
    assert "outdated_software" in {f.bug_class for f in findings}
    assert any(f.location.endswith("/robots.txt") for f in findings)


def test_routing_a_nikto_report_to_the_generic_parser_destroys_it() -> None:
    """MUTATION CONTROL for the sniff above: it is not enough that "nikto" is returned — this
    is what the OLD answer produced from the SAME bytes, and it is why the sniff matters. Revert
    the sniffer and the assertions above become these: one entry, no bug class, no location."""
    degraded, tool = parse_export("generic", NIKTO)      # what detect_format used to choose
    assert tool == "generic"
    assert len(degraded) == 1, "a whole host block collapses into one entry"
    assert degraded[0].bug_class == "unknown", "the bug class is gone"
    assert degraded[0].location == "", "the location is gone"
    # the real adapter recovers all three, classed and located — a strict, measurable improvement
    real, _ = parse_export("nikto", NIKTO)
    assert len(real) > len(degraded)
    assert all(f.bug_class != "unknown" and f.location for f in real)


def test_a_clean_nikto_scan_is_still_recognised_as_nikto() -> None:
    """Nikto's report plugin initialises `vulnerabilities` to `[]`, so a scan that found nothing
    is an array of blocks with empty lists. That must sniff as nikto (and parse to no findings),
    not fall through to the generic parser — a clean scan is a result, not an unknown format."""
    clean = json.dumps([{
        "end_time": "2026-08-13 17:26:12 -0400", "host": "t.example", "ip": "127.0.0.1",
        "port": "443", "server_banner": None, "start_time": "2026-08-13 17:26:12 -0400",
        "vulnerabilities": [],
    }])
    assert detect_format(clean) == "nikto"
    assert parse_export("nikto", clean)[0] == []


def test_a_generic_findings_array_is_still_generic() -> None:
    """MUTATION CONTROL for the array branch: widening the sniffer to claim every top-level array
    for nikto would silently steal the generic escape hatch's own bare-array form. A nikto block
    is recognised by its `vulnerabilities` LIST plus nikto's item/host keys — nothing less."""
    bare_array = json.dumps([{"bug_class": "idor", "url": "http://t.example/a?id=7"},
                             {"type": "open_redirect", "location": "http://t.example/go"}])
    assert detect_format(bare_array) == "generic"
    # a wapiti report keeps its own home: its `vulnerabilities` is a DICT, not a list
    assert detect_format(WAPITI) == "wapiti"
    # an array of things that are not host blocks is not a nikto report
    assert detect_format(json.dumps([{"vulnerabilities": "not-a-list"}])) == "generic"
    assert detect_format(json.dumps(["a", "b"])) == "generic"


def test_nikto_findings_carry_the_host_the_block_was_scanned_against() -> None:
    """Nikto puts the host on the BLOCK and a bare path on the item, so without lifting it every
    finding imports host-less: no asset observation, no HOSTS edge, and — the real damage — two
    different hosts' `/` collapse onto one path-keyed endpoint node."""
    findings, _ = parse_export("nikto", NIKTO)
    assert {f.host for f in findings} == {"t.example"}
    assert all(f.location.startswith("t.example:18711/") for f in findings)

    two_hosts = json.loads(NIKTO)
    second = json.loads(NIKTO)[0]
    second["host"], second["ip"], second["port"] = "other.example", "127.0.0.2", "8443"
    two_hosts.append(second)
    multi, _ = parse_export("nikto", json.dumps(two_hosts))
    assert len(multi) == 6
    # MUTATION CONTROL: drop the attribution and every one of these assertions fails — the hosts
    # collapse to one empty label and the two hosts' `/` become the SAME endpoint key.
    by_host: dict = {}
    for f in multi:
        by_host.setdefault(f.host, set()).add(f.location)
    assert set(by_host) == {"t.example", "other.example"}
    assert not (by_host["t.example"] & by_host["other.example"])
    assert len({f.location for f in multi}) == 4        # 2 paths x 2 hosts, none shared


def test_nikto_host_attribution_never_guesses() -> None:
    """It re-walks the raw report to pair findings with blocks. A report it cannot walk 1:1 gets
    NO attribution rather than a wrong one, and no scheme is ever invented for a bare path."""
    # a block with no host at all: parsed, but nothing is attributed
    hostless = json.dumps([{"vulnerabilities": [{"msg": "/x: found", "url": "/x"}]}])
    findings, _ = parse_export("nikto", hostless)
    assert len(findings) == 1 and findings[0].host == "" and findings[0].location == "/x"
    # an item whose url is already absolute keeps it, and its own host wins
    absolute = json.dumps([{"host": "t.example", "port": "80", "vulnerabilities": [
        {"msg": "The X-Frame-Options header is not set.", "url": "http://elsewhere.example/a"}]}])
    findings, _ = parse_export("nikto", absolute)
    assert findings[0].location == "http://elsewhere.example/a"
    assert findings[0].host == "elsewhere.example"
    # nikto's report carries no scheme, so the qualified location must not fabricate one
    findings, _ = parse_export("nikto", NIKTO)
    assert not any("://" in f.location for f in findings)


# --- ffuf / httpx / hydra: the three readers that did not exist -------------
#
# Before these, the engine could RUN ffuf, httpx and hydra and could not READ any of them: the
# registry held no key, so their bytes went nowhere. The tests below pin the two things that makes
# true — that each reader parses its own tool's real output, and that what it emits is GRADED
# honestly. The grading half matters more: a reader that turned ffuf's `/admin` into a vulnerability
# would be worse than no reader at all.

# Classes that assert a WEAKNESS. A content-discovery or fingerprint observation must never carry
# one of these, and the assertion is written as a set intersection so a future parser that starts
# emitting one gets caught rather than merely looking different.
WEAKNESS_CLASSES = {"sqli", "sql_injection", "xss", "rce", "command_injection", "path_traversal",
                    "lfi", "ssrf", "idor", "open_redirect", "exposure", "directory_listing",
                    "weak_credentials", "security_misconfiguration", "auth_bypass", "csrf"}


def test_the_observation_classes_are_declared_and_claim_no_weakness() -> None:
    """`parsers.OBSERVATION_BUG_CLASSES` is where the grading rule is written down rather than left
    implicit in two parsers. It has to stay disjoint from anything that asserts a weakness, and it
    has to be what the two observing readers actually emit — a declaration nothing consults would be
    a comment wearing a constant's clothes."""
    from framework.v2.imports.parsers import OBSERVATION_BUG_CLASSES

    assert not (OBSERVATION_BUG_CLASSES & WEAKNESS_CLASSES)
    emitted = {f.bug_class for f in parse_export("ffuf", FFUF)[0]}
    emitted |= {f.bug_class for f in parse_export("httpx", HTTPX)[0]}
    assert emitted and emitted <= OBSERVATION_BUG_CLASSES
    # hydra's credential result is deliberately NOT one of them — that one IS a weakness.
    assert {f.bug_class for f in parse_export("hydra", HYDRA)[0]} & WEAKNESS_CLASSES


def test_ffuf_discovered_paths_are_observations_never_vulnerabilities() -> None:
    """THE grading rule for ffuf. It discovers CONTENT: `/admin` answering 200 is a fact about the
    application's shape, not a weakness in it. Three real results, three observations, zero
    vulnerability claims — and `/private` answering 401 is emphatically not "an auth finding"."""
    findings, tool = parse_export("ffuf", FFUF)
    assert tool == "ffuf" and len(findings) == 3
    assert {f.bug_class for f in findings} == {"content_discovery"}
    assert not ({f.bug_class for f in findings} & WEAKNESS_CLASSES)
    assert all(f.severity == "info" for f in findings)
    # ffuf makes no vulnerability claim, so there is no tool confidence to record.
    assert all(not f.tool_confirmed for f in findings)
    # each discovered path is located and attributed, so it lands as its OWN endpoint observation
    assert {f.location for f in findings} == {
        "http://t.example:18821/admin", "http://t.example:18821/private",
        "http://t.example:18821/robots.txt"}
    assert {f.host for f in findings} == {"t.example"}
    # the evidence says what the path answered, and says nothing about it being a problem
    admin = next(f for f in findings if f.location.endswith("/admin"))
    assert "status 200" in admin.evidence and "10 bytes" in admin.evidence


def test_ffuf_evidence_is_deterministic_so_a_re_import_is_a_no_op() -> None:
    """`duration` changes on every run of the same scan. If it reached the evidence string, the
    same report imported twice would write two different attrs — and the importer's idempotence
    claim would be false for ffuf while remaining true for everything else."""
    findings, _ = parse_export("ffuf", FFUF)
    for f in findings:
        assert "271684" not in f.evidence and "duration" not in f.evidence
    mutated = json.loads(FFUF)
    for r in mutated["results"]:
        r["duration"] = r["duration"] + 1
    again, _ = parse_export("ffuf", json.dumps(mutated))
    assert [f.model_dump() for f in findings] == [f.model_dump() for f in again]


def test_ffuf_clean_scan_is_a_result_not_an_unreadable_report() -> None:
    """The negative control. ffuf writes its full envelope with `"results": []` when nothing
    matched; that must sniff as ffuf and parse to SILENCE — not fall through to another parser and
    not look like a broken file."""
    assert detect_format(FFUF_CLEAN) == "ffuf"
    assert parse_export("ffuf", FFUF_CLEAN)[0] == []


def test_ffuf_stdout_jsonl_is_read_and_the_base64_input_trap_is_avoided() -> None:
    """ffuf has two real JSON forms and they disagree: `-of json` writes the fuzzed word plainly,
    `-json`/`-of ejson` BASE64-ENCODE it. A reader that rebuilt the path from `input.FUZZ` would
    silently emit `/YWRtaW4=` for half of ffuf's own output. The location comes off `url`, which is
    plain in both."""
    findings, _ = parse_export("ffuf", FFUF_STDOUT_JSONL)
    assert len(findings) == 2
    assert {f.location for f in findings} == {"http://t.example:18821/private",
                                              "http://t.example:18821/admin"}
    assert not any("YWRtaW4" in f.location or "cHJpdmF0ZQ" in f.location for f in findings)


def test_ffuf_sniff_does_not_steal_the_generic_escape_hatch() -> None:
    """MUTATION CONTROL for the sniffer. ffuf keys its findings `results` — one of the two keys the
    tool-neutral parser reads — so a rule any wider than "ffuf's envelope AND a results list" takes
    every generic `{"results": […]}` export with it. Both directions are pinned here."""
    # the narrow rule: a generic export keyed `results` stays generic
    assert detect_format(json.dumps({"results": [{"bug_class": "xss", "url": "http://t.example/x"}]})) == "generic"
    assert detect_format(GENERIC) == "generic"
    # ... and a real ffuf report is NOT swallowed by generic (which is what used to happen to nikto)
    assert detect_format(FFUF) == "ffuf"
    # no other format loses its home to the new rule
    assert detect_format(SARIF) == "sarif" and detect_format(NIKTO) == "nikto"
    assert detect_format(WAPITI) == "wapiti" and detect_format(ZAP) == "zap"
    # the envelope is required: results alone, without ffuf's own keys, is not an ffuf report
    assert detect_format(json.dumps({"results": [json.loads(FFUF)["results"][0]]})) == "generic"


def test_routing_an_ffuf_report_to_the_generic_parser_destroys_it() -> None:
    """MUTATION CONTROL for the sniff above — what the OLD (absent) answer produced from the SAME
    bytes, and why the reader is worth having."""
    degraded, tool = parse_export("generic", FFUF)
    assert tool == "generic" and len(degraded) == 3
    assert all(f.bug_class == "unknown" for f in degraded), "the class is gone"
    assert all(not f.evidence and not f.severity for f in degraded), "what it answered is gone"
    # and the subtler damage: ffuf writes `host` WITH the port, which the tool-neutral parser takes
    # verbatim — so every result attaches to a bogus `t.example:18821` asset that is a different
    # node from the `t.example` the rest of the engagement knows.
    assert {f.host for f in degraded} == {"t.example:18821"}
    real, _ = parse_export("ffuf", FFUF)
    assert all(f.bug_class == "content_discovery" and f.host == "t.example" for f in real)
    assert all(f.evidence for f in real)


def test_httpx_fingerprints_are_observations_never_vulnerabilities() -> None:
    """THE grading rule for httpx. A status code, a title, a server banner and a detected
    technology are what is RUNNING — not what is wrong with it."""
    findings, tool = parse_export("httpx", HTTPX)
    assert tool == "httpx" and len(findings) == 2
    assert {f.bug_class for f in findings} == {"http_fingerprint"}
    assert not ({f.bug_class for f in findings} & WEAKNESS_CLASSES)
    assert all(f.severity == "info" and not f.tool_confirmed for f in findings)
    assert {f.host for f in findings} == {"t.example"}
    root = next(f for f in findings if f.location.endswith(":18821/"))
    assert "status 200" in root.evidence and "title Cap Target" in root.evidence
    assert "server CapTarget/1.0" in root.evidence
    # a 401 is a fingerprint of the surface, NOT an access-control finding
    private = next(f for f in findings if f.location.endswith("/private"))
    assert "status 401" in private.evidence and "tech Basic" in private.evidence
    assert private.bug_class == "http_fingerprint"
    # the response time and timestamp are excluded — they change every run (see the ffuf twin)
    assert all("540.146" not in f.evidence and "2026-08-13T18:40" not in f.evidence for f in findings)


def test_httpx_failed_probe_mints_nothing() -> None:
    """`{"failed": true}` is httpx reporting the ABSENCE of an endpoint. Importing it would write a
    host that refused the connection into the world-model as a live asset."""
    findings, _ = parse_export("httpx", HTTPX_FAILED)
    assert findings == []
    # a mixed export keeps only the live ones
    mixed, _ = parse_export("httpx", HTTPX + "\n" + HTTPX_FAILED)
    assert len(mixed) == 2 and all(":19999" not in f.location for f in mixed)


def test_httpx_sniff_does_not_collide_with_the_other_jsonl_formats() -> None:
    """Three of the supported formats are JSON Lines. httpx is told apart by the pairing only it
    writes — a STRING `input` beside the probed `url`; ffuf's `input` is the fuzzed-word MAP."""
    assert detect_format(HTTPX) == "httpx"
    assert detect_format(NUCLEI) == "nuclei"          # nuclei keeps its own tell (template-id)
    # a single-record httpx export is also parseable as one whole JSON object; it must not fall
    # through to the object branch and be claimed by another rule
    assert detect_format(HTTPX.splitlines()[0]) == "httpx"
    # ffuf's stdout JSONL is NOT claimed for httpx (its `input` is a map) — it is honestly
    # unsniffable and reachable only by explicit key, which is better than a wrong answer
    assert detect_format(FFUF_STDOUT_JSONL) != "httpx"


def test_a_torn_final_line_costs_one_record_not_the_whole_report() -> None:
    """THE STREAM READERS' TRUNCATION CASE, which the strict JSON-Lines rule did not consider.

    httpx writes its JSONL to STDOUT and ``live.executor`` kills an over-running tool with SIGKILL,
    which nothing can catch and flush behind — so the capture routinely ends MID-RECORD. Measured
    before this: two complete probes plus a half-written third raised ImportAdapterError and the two
    complete ones were thrown away. A tool that ran, probed and printed was heard as an unreadable
    export."""
    whole = HTTPX.splitlines()
    torn = whole[0] + "\n" + whole[1] + "\n" + whole[0][:60]      # cut mid-record, no terminator
    findings, _ = parse_export("httpx", torn)
    assert len(findings) == 2                                     # one line lost, the report kept
    assert {f.location for f in findings} == {"http://t.example:18821/private",
                                              "http://t.example:18821/"}
    # the same for ffuf's stdout stream
    ffuf_lines = FFUF_STDOUT_JSONL.splitlines()
    ffuf_torn = ffuf_lines[0] + "\n" + ffuf_lines[1][:40]
    assert len(parse_export("ffuf", ffuf_torn)[0]) == 1


def test_only_a_torn_TAIL_is_forgiven_and_nothing_else_is() -> None:
    """MUTATION CONTROL for the rule above — three ways of being lenient that would each turn a
    genuinely unreadable export into a silent clean result, and are each still LOUD.

    The discriminator is narrow on purpose: LAST line, no terminator after it, and at least one
    complete record already read. Drop any one of the three and an unreadable export reads as a
    clean scan, which is the failure the strict rule exists to prevent."""
    whole = HTTPX.splitlines()
    # (1) garbage in the MIDDLE of a stream that ended cleanly: not a tail, still an error
    with pytest.raises(ImportAdapterError):
        parse_export("httpx", whole[0] + "\ngarbage\n" + whole[1] + "\n")
    # (2) a torn-LOOKING last line in an export that DID end in a newline: the writer finished, so
    #     the line is corrupt rather than cut off
    with pytest.raises(ImportAdapterError):
        parse_export("httpx", whole[0] + "\n" + whole[1][:60] + "\n")
    # (3) an export that is NOTHING BUT an unparseable blob: there is no report to keep, so
    #     salvaging it would mean returning [] for a file nobody could read. This is also what a
    #     truncated ffuf `-of json` report looks like — one long line, cut short.
    with pytest.raises(ImportAdapterError):
        parse_export("httpx", whole[0][:60])
    with pytest.raises(ImportAdapterError):
        parse_export("ffuf", FFUF[:120])


def test_a_one_line_ffuf_stdout_stream_is_still_a_stream() -> None:
    """A scan that discovered exactly ONE path — the ordinary outcome of a small wordlist — writes a
    single `-json` line, which is ALSO a valid whole JSON document. It used to take the report
    branch, find no `results` key, and be refused as a malformed report: ffuf's most common real
    output, unreadable. It is recognised by ffuf's own result SHAPE, so a report that is genuinely
    missing its `results` array is still refused."""
    one = FFUF_STDOUT_JSONL.splitlines()[0]
    findings, tool = parse_export("ffuf", one)
    assert tool == "ffuf" and len(findings) == 1
    assert findings[0].location == "http://t.example:18821/private"
    assert findings[0].bug_class == "content_discovery" and findings[0].severity == "info"
    # and with a trailing newline, the same
    assert len(parse_export("ffuf", one + "\n")[0]) == 1
    # MUTATION CONTROL: an object that is NOT an ffuf result and has no `results` is still an error
    with pytest.raises(ImportAdapterError):
        parse_export("ffuf", json.dumps({"commandline": "ffuf ...", "time": "t"}))


def test_hydra_valid_login_is_graded_as_a_real_finding() -> None:
    """THE grading rule for hydra, and the contrast with the other two: hydra AUTHENTICATED. That is
    a weakness, and it is graded as one."""
    findings, tool = parse_export("hydra", HYDRA)
    assert tool == "hydra" and len(findings) == 1
    hit = findings[0]
    assert hit.bug_class == "weak_credentials" and hit.severity == "high"
    assert hit.tool_confirmed is True          # hydra self-confirms by exploitation, like sqlmap
    assert hit.host == "t.example"
    assert hit.location == "t.example:18821/private"
    assert "://" not in hit.location, "hydra prints no scheme; none may be invented"
    assert "service http-get" in hit.evidence and "login admin" in hit.evidence


def test_hydra_password_is_masked_in_the_persisted_evidence() -> None:
    """The evidence string is persisted into the intel store and rendered into reports. hydra's
    password is a live credential for a real account, so it is masked there exactly as the live
    executor masks the `-p` position in the signed argv record. The finding keeps everything that
    makes it actionable — service, host, login — and the operator's raw run output still holds the
    value."""
    findings, _ = parse_export("hydra", HYDRA)
    assert "secret123" not in findings[0].evidence
    assert "masked" in findings[0].evidence and "login admin" in findings[0].evidence


def test_hydra_form_spec_survives_because_the_line_is_split_on_field_markers() -> None:
    """MUTATION CONTROL for the line parser. hydra separates fields with THREE SPACES and its values
    contain spaces and colons: an `http-post-form` spec ends in a failure SENTENCE. Split this line
    on whitespace and the spec truncates at `/login:user=^USER^&pass=^PASS^:Login`, taking the
    location with it."""
    findings, _ = parse_export("hydra", HYDRA_FORM)
    assert len(findings) == 1
    hit = findings[0]
    assert hit.location == "t.example:18822/login", "the path is the spec's FIRST segment only"
    assert "spec /login:user=^USER^&pass=^PASS^:Login failed" in hit.evidence
    assert hit.evidence.endswith("Login failed"), "the failure sentence is not truncated"
    assert hit.bug_class == "weak_credentials" and hit.host == "t.example"


def test_a_clean_hydra_run_is_recognised_and_stays_silent() -> None:
    """The negative control, which is the row that actually proves the reader. A run that cracked
    nothing prints a banner, `[DATA]` lines and a summary — and NO hit line. It must sniff as hydra
    (a run that found nothing is a result, not an unknown format) and parse to zero findings."""
    assert detect_format(HYDRA_CLEAN) == "hydra"
    assert parse_export("hydra", HYDRA_CLEAN)[0] == []


def test_hydra_never_mistakes_its_chatter_for_a_hit() -> None:
    """Everything else hydra prints — attempts, status, errors, redirects, and the rdp module's
    explicit "might be valid but NOT active" line — is not a valid login and must mint nothing."""
    chatter = (
        '[ATTEMPT] target t.example - login "admin" - pass "wrong1" - 1 of 6 [child 0] (0/0)\n'
        "[STATUS] 120.00 tries/min, 120 tries in 00:01h, 4 to do in 00:01h, 4 active\n"
        "[ERROR] Child with pid 1234 terminating, can not connect\n"
        "[WARNING] Restorefile (./hydra.restore) from a previous session found, to prevent\n"
        "[REDIRECT] to http://t.example:18821/login\n"
        "[3389][rdp] account on t.example might be valid but account not active for remote "
        "desktop: login: admin password: secret123, continuing attacking the account.\n"
        "[INFO] Testing if password authentication is supported by ssh://t.example:22\n"
    )
    assert parse_export("hydra", chatter)[0] == []
    # ... and the same blob with ONE real hit yields exactly one finding
    findings, _ = parse_export("hydra", chatter + HYDRA)
    assert len(findings) == 1 and findings[0].bug_class == "weak_credentials"


def test_hydra_reads_every_shape_its_binary_prints() -> None:
    """The five success formats are taken from the format strings in the shipped hydra 9.7 binary,
    not from its documentation. Each is read, and the two that carry no credential are graded for
    what they actually are."""
    findings, _ = parse_export("hydra", "\n".join([
        "[161][snmp] host: t.example   password: public",              # no username for this service
        "[1521][oracle-sid] host: t.example   login: ORCL",            # no password for this one
        "[22][ssh] host: t.example   login: root   password: toor",
        "[80][http-get] host: t.example   misc: /admin   login: a   password: b",
        "[8080][http-proxy-urlenum] host: t.example   url: http://t.example/internal",
    ]))
    by_loc = {f.location: f for f in findings}
    assert len(findings) == 5
    # four credential results — every one a weakness
    creds = [f for f in findings if f.bug_class == "weak_credentials"]
    assert len(creds) == 4 and all(f.severity == "high" and f.tool_confirmed for f in creds)
    assert by_loc["t.example:161"].bug_class == "weak_credentials"     # password-only still counts
    assert by_loc["t.example:1521"].bug_class == "weak_credentials"    # login-only still counts
    assert by_loc["t.example:80/admin"].location == "t.example:80/admin"
    # ... and the url-enumeration variant is CONTENT DISCOVERY, not a credential
    urlenum = by_loc["http://t.example/internal"]
    assert urlenum.bug_class == "content_discovery" and urlenum.severity == "info"
    assert not urlenum.tool_confirmed


def test_hydra_reports_a_blank_password_account() -> None:
    """hydra prints `password: ` with an EMPTY value for an account that authenticates with no
    password at all (`-e n`). That is the strongest credential result the tool can produce, and a
    truthiness test on the value would have discarded it."""
    findings, _ = parse_export("hydra", "[22][ssh] host: t.example   login: root   password: ")
    assert len(findings) == 1
    assert findings[0].bug_class == "weak_credentials" and findings[0].severity == "high"
    assert "<empty>" in findings[0].evidence
    # a line with NEITHER a credential nor a url proves nothing, so nothing is claimed
    assert parse_export("hydra", "[22][ssh] host: t.example")[0] == []


@pytest.mark.parametrize("fmt", ["ffuf", "httpx", "hydra"])
@pytest.mark.parametrize("bad", [
    "", "   \n\n  ", "not json at all", "\x00\x01\x02\xff", "null", "true", '"a string"',
    "[]", "{}", "[1, 2, 3]", '{"results": null}', '{"results": {"a": 1}}', '{"results": "x"}',
    '{"commandline": "ffuf"}', '{"url": 12, "input": [], "status": "x"}',
    '{"results": [{"url": "http://t.example/a"',                       # truncated mid-object
    '{"results": [null, 1, "x", [], {"no_url": 1}]}',
    '[' * 100_000,                                                     # adversarially nested
    '{"results": [{"url": "http://t.example/a", "status": 200}]}\ngarbage',
    "[80][http] host:",                                                # a truncated hydra hit line
    "[80][http] host: t.example   login:",
    "[not-a-port][x] host: t.example   login: a   password: b",
    "\n".join(["[1][x] host: t.example   login: a   password: b"] * 500),
])
def test_totality_malformed_input_never_crashes(fmt, bad) -> None:
    """TOTALITY, for all three readers at once. Empty, truncated, binary, hostile and
    wrong-shaped input yields either NO findings or a clean `ImportAdapterError` — the two
    outcomes every sibling parser already has. Any other exception type is a crash in an importer
    fed untrusted bytes, and that is the failure this test exists to catch."""
    try:
        findings, _ = parse_export(fmt, bad)
    except ImportAdapterError:
        return                          # the documented loud path
    assert isinstance(findings, list)
    assert all(f.bug_class for f in findings)


def test_totality_sniffer_never_crashes_on_the_same_inputs() -> None:
    """`detect_format` is the operator-convenience path and runs on bytes nobody has vetted."""
    for bad in ["", "   ", "not json", "\x00\xff", "null", "[" * 100_000, "{", "[]",
                '{"results": []}', FFUF[:40], HTTPX[:40], HYDRA[:40]]:
        assert detect_format(bad) in (None, *available_formats())


def test_the_three_new_readers_mint_leads_never_facts() -> None:
    """End to end, the same guarantee every other import has: whatever the tool claimed, the
    world-model gets a labelled, unverified LEAD. hydra's `tool_confirmed=True` is the tool's own
    confidence and does not promote anything — the endpoint is still `unverified`, still not a
    FINDING node, and still not GROUNDED."""
    for fmt, export in (("ffuf", FFUF), ("httpx", HTTPX), ("hydra", HYDRA)):
        world = WorldModel()
        result = import_report(fmt, export, world=world)
        assert result.applied > 0 and result.leads, fmt
        assert all(n.kind is not NodeKind.FINDING for n in world.all_nodes()), fmt
        endpoints = [n for n in world.all_nodes() if n.kind is NodeKind.ENDPOINT]
        assert endpoints, fmt
        for n in endpoints:
            assert n.attrs.get("lead") is True and n.attrs.get("unverified") is True, fmt
            assert n.grounding != GROUNDING_GROUNDED, fmt
            assert n.provenance.startswith(f"intel:import:{fmt}"), fmt
    # and the grading survives the trip into the world-model: ffuf's discovered paths are still
    # observations there, which is where a mis-grade would actually do its damage.
    world = WorldModel()
    import_report("ffuf", FFUF, world=world)
    classes = {n.attrs.get("bug_class") for n in world.all_nodes() if n.kind is NodeKind.ENDPOINT}
    assert classes == {"content_discovery"} and not (classes & WEAKNESS_CLASSES)


# --- ingest into the world-model: leads, never facts ------------------------

def test_import_mints_grounding_intel_leads_never_facts() -> None:
    world = WorldModel()
    result = import_report("generic", GENERIC, world=world)
    assert result.applied > 0 and result.dropped == 0
    assert len(result.leads) == 2

    # NOTHING became a FINDING node (a FINDING is reserved for oracle-confirmed).
    assert all(n.kind is not NodeKind.FINDING for n in world.all_nodes())
    # every written node/edge is GROUNDING_INTEL — real, collected, but not oracle-proof.
    assert world.node_count > 0
    for n in world.all_nodes():
        assert n.grounding != GROUNDING_GROUNDED
        assert n.provenance.startswith("intel:import:")
    for e in world.all_edges():
        assert e.grounding != GROUNDING_GROUNDED

    # the endpoint leads carry the explicit unverified label.
    endpoints = [n for n in world.all_nodes() if n.kind is NodeKind.ENDPOINT]
    assert endpoints and all(n.attrs.get("lead") is True for n in endpoints)
    assert all(n.attrs.get("unverified") is True for n in endpoints)
    bug_classes = {n.attrs.get("bug_class") for n in endpoints}
    assert {"idor", "open_redirect"} <= bug_classes


def test_import_is_idempotent_and_deterministic() -> None:
    w1 = WorldModel()
    import_report("nuclei", NUCLEI, world=w1)
    n_after_first = w1.node_count
    # re-import the SAME export: claim-keyed obs_ids de-dup -> no new nodes.
    import_report("nuclei", NUCLEI, world=w1)
    assert w1.node_count == n_after_first

    # a fresh world from the same export yields identical node ids (pure of wallclock/rng).
    w2 = WorldModel()
    import_report("nuclei", NUCLEI, world=w2)
    assert {n.id for n in w1.all_nodes()} == {n.id for n in w2.all_nodes()}


def test_tool_confirmed_flag_never_promotes_to_fact() -> None:
    # a source tool that self-confirms (burp confidence=certain) is STILL a lead to us.
    world = WorldModel()
    import_report("burp", BURP, world=world)
    endpoints = [n for n in world.all_nodes() if n.kind is NodeKind.ENDPOINT]
    assert endpoints
    ep = endpoints[0]
    assert ep.attrs.get("tool_confirmed") is True   # the tool's own confidence, recorded
    assert ep.attrs.get("unverified") is True        # ... but a lead to CRUCIBLE
    assert ep.grounding != GROUNDING_GROUNDED


# --- persistence + enumeration ---------------------------------------------

def test_import_persists_and_reads_back(tmp_path) -> None:
    from framework.v2.api import reads
    from framework.v2.intel.store import IntelStore
    from framework.v2.memory.store import Store

    db = tmp_path / "m.db"
    factory = lambda: IntelStore(Store(db))  # noqa: E731

    world = WorldModel()
    import_report("generic", GENERIC, world=world, store=factory(),
                  engagement_slug="demo")

    view = reads.imports("demo", store_factory=factory)
    assert view["count"] >= 2
    assert all(row["unverified"] for row in view["leads"])
    assert {"idor", "open_redirect"} <= {row["bug_class"] for row in view["leads"]}
    # a different engagement sees none of them (scoped by slug).
    assert reads.imports("other", store_factory=factory)["count"] == 0


# --- the importer as a GATED tool ------------------------------------------

def _ctx(slug: str, world=None):
    from framework.v2.agents.tools.base import ToolContext
    return ToolContext(slug=slug, world=world)


def test_import_tool_runs_and_refuses_bad_args() -> None:
    tool = ImportFindingsTool(store_factory=lambda: None)  # hermetic: no persistence
    world = WorldModel()
    res = tool.run({"format": "generic", "report": GENERIC}, _ctx("demo", world))
    assert res.ok and res.output["applied"] > 0

    # a missing/undetectable format is a clean failed result, never a crash.
    bad = tool.run({"report": "still not detectable"}, _ctx("demo"))
    assert not bad.ok and "format" in bad.note
    # a non-dict args is handled.
    assert not tool.run("nope", _ctx("demo")).ok


def test_import_tool_refused_by_tripped_killswitch(tmp_path, monkeypatch) -> None:
    # route the kill-switch file to a tmp path so BOTH the trip and invoke_tool's check
    # read the same file — fully hermetic, no real targets/ write.
    from framework.v2.agents.tools.base import ToolContext
    from framework.v2.agents.tools.invoker import invoke_tool
    from framework.v2.agents.tools.base import ToolRegistry
    from framework.v2.authority.killswitch import KillSwitch
    from framework.v2.common import paths

    ks_file = tmp_path / "demo.killswitch"
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: ks_file)

    reg = ToolRegistry()
    reg.register(ImportFindingsTool(store_factory=lambda: None))

    # not tripped -> the import runs.
    world = WorldModel()
    ok = invoke_tool(reg, "import_findings", {"format": "generic", "report": GENERIC},
                     ToolContext(slug="demo", world=world))
    assert ok.ok and not ok.refused

    # tripped -> the SAME action is REFUSED at the kill-switch gate; nothing runs.
    KillSwitch("demo").trip("halt for test")
    world2 = WorldModel()
    refused = invoke_tool(reg, "import_findings", {"format": "generic", "report": GENERIC},
                          ToolContext(slug="demo", world=world2))
    assert refused.refused and refused.gate == "kill-switch"
    assert world2.node_count == 0  # the importer never touched the world-model


# --- hydra: the tally tripwire — silence has to be EARNED --------------------
#
# Every fixture below is a real hydra 9.7 shape: the two-hit run is verbatim stdout from a live
# loopback run (two accounts on one HTTP Basic service, host renamed to the documentation host this
# file uses), and the smb line is the format string carried in the shipped binary
# (`[%d][smb] Host: %s Account: %s Valid password, …`) — a shape the hit regex deliberately does
# not match, which is exactly why it is the right adversary for this check.

# Two accounts cracked in one run — and hydra's PLURAL tally, which the cross-check must read.
HYDRA_TWO_HITS = (
    "[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:2/p:4), ~1 try per task\n"
    "[DATA] attacking http-get://t.example:18804/\n"
    "[18804][http-get] host: t.example   misc: /   login: admin   password: letmein\n"
    "[18804][http-get] host: t.example   misc: /   login: root   password: password\n"
    "1 of 1 target successfully completed, 2 valid passwords found\n"
)
# A success the hit regex CANNOT read: hydra's smb module reports with a capital `Host:`/`Account:`
# and no `login:`/`password:` markers at all. The tally still counts it.
#
# SPACING IS PART OF THE SHAPE, so it is taken from the binary and not approximated: the format
# string is `[%d][smb] Host: %s Account: %s Valid password, …` — SINGLE spaces, unlike the three
# that separate the fields of the lowercase `host:`/`login:`/`password:` line. Writing this fixture
# with the three-space separator would make it a shape hydra never prints, and a fixture of the
# wrong shape is precisely what once let a broken sniffer look correct in this file. (Verified with
# `strings /usr/bin/hydra`; not executed live — the smb module needs an SMB service, and this host
# has none, so the argument for this fixture is the binary's own format string, nothing weaker.)
HYDRA_UNREADABLE_HIT = (
    "[445][smb] Host: t.example Account: admin Valid password, GPO Disabling Remote "
    "Connections Using NULL Passwords\n"
    "1 of 1 target successfully completed, 1 valid password found\n"
)


def test_hydra_tally_is_loud_when_the_reader_could_not_read_a_proven_credential() -> None:
    """THE defect class this whole reader exists to prevent, applied to the reader itself: a tool
    that runs, succeeds, and is heard as silence. hydra tallies what it cracked in the same place it
    prints the hit line, so a shortfall means a credential the TOOL ITSELF proved went unread. That
    must fail LOUD — a short list would be indistinguishable from a clean run."""
    with pytest.raises(ImportAdapterError, match="tallied 1 valid credential"):
        parse_export("hydra", HYDRA_UNREADABLE_HIT)


def test_without_the_tally_the_same_bytes_import_as_a_clean_run() -> None:
    """MUTATION CONTROL for the check above. Strip hydra's own count and the identical hit becomes
    an empty, entirely believable result — no error, no finding, nothing to say the reader failed.
    That silence is what the tally converts into a loud one, and it is the only difference."""
    without_tally = HYDRA_UNREADABLE_HIT.splitlines()[0]
    findings, _ = parse_export("hydra", without_tally)
    assert findings == [], "the hit shape is genuinely unreadable — that is the premise"


def test_hydra_tally_stays_quiet_when_the_reader_kept_up() -> None:
    """It is a cross-check, not a tax. Every honest run agrees with its own count: a clean control
    (0 tallied, 0 read), a single hit, and a two-hit run whose tally is PLURAL — the form a regex
    written against a one-credential run would miss."""
    assert parse_export("hydra", HYDRA_CLEAN)[0] == []       # `0 valid password found`
    assert len(parse_export("hydra", HYDRA)[0]) == 1         # `1 valid password found`
    findings, _ = parse_export("hydra", HYDRA_TWO_HITS)      # `2 valid passwords found`
    assert len(findings) == 2
    assert {f.evidence.split("login ")[1].split(",")[0] for f in findings} == {"admin", "root"}
    assert all(f.bug_class == "weak_credentials" and f.tool_confirmed for f in findings)


# hydra's OPTIONAL JSON report, verbatim from `hydra … -o h.json -b json` on this host (host
# renamed as everywhere else). `-b jsonv1` produced a byte-identical shape. Two things this pins:
# hydra keys its hits `results` — the THIRD format in this module to do so — and `-o` does NOT
# actually silence the stdout hit line the way `hydra -h` claims ("instead of stdout"); 9.7 printed
# both, which is why the stdout contract is the right one and this is a secondary path.
HYDRA_JSON_REPORT = (
    '{ "generator": {\n'
    '\t"software": "Hydra", "version": "v9.7", "built": "2026-08-13 18:59:09",\n'
    '\t"server": "t.example", "service": "http-get", "jsonoutputversion": "1.00",\n'
    '\t"commandline": "hydra -s 18821 -L users.txt -P pass.txt -o h.json -b json t.example '
    'http-get /private"\n'
    '\t},\n"results": [\n'
    '\t{"port": 18821, "service": "http-get", "host": "t.example", "login": "admin", '
    '"password": "secret123"}\n'
    '\t],\n"success": true,\n"errormessages": [  ],\n"quantityfound": 1   }\n'
)


def test_hydra_json_report_is_read_under_the_same_key_not_lost_to_generic() -> None:
    """hydra's `-b json` report keys its hits `results`, so without a rule of its own it lands in
    the tool-neutral parser — class-less and location-less, which is exactly the nikto misroute.
    Same tool, same reader key, same grading."""
    assert detect_format(HYDRA_JSON_REPORT) == "hydra"
    findings, tool = parse_export("hydra", HYDRA_JSON_REPORT)
    assert tool == "hydra" and len(findings) == 1
    hit = findings[0]
    assert hit.bug_class == "weak_credentials" and hit.severity == "high" and hit.tool_confirmed
    assert hit.location == "t.example:18821" and hit.host == "t.example"
    assert "login admin" in hit.evidence and "secret123" not in hit.evidence
    # MUTATION CONTROL: routed to the tool-neutral parser, the same bytes lose everything.
    degraded, _ = parse_export("generic", HYDRA_JSON_REPORT)
    assert len(degraded) == 1 and degraded[0].bug_class == "unknown" and not degraded[0].location


def test_hydra_json_report_carries_its_own_tally_too() -> None:
    """`quantityfound` is the report's version of the stdout tally, and it is cross-checked the same
    way — a report that says it found more than the reader could read fails LOUD."""
    clean = HYDRA_JSON_REPORT.replace(
        '\t{"port": 18821, "service": "http-get", "host": "t.example", "login": "admin", '
        '"password": "secret123"}\n', "").replace('"quantityfound": 1', '"quantityfound": 0')
    assert detect_format(clean) == "hydra"
    assert parse_export("hydra", clean)[0] == []          # the clean control stays silent
    lying = HYDRA_JSON_REPORT.replace('"quantityfound": 1', '"quantityfound": 3')
    with pytest.raises(ImportAdapterError, match="tallied 3 valid credential"):
        parse_export("hydra", lying)


def test_the_three_way_results_key_collision_is_resolved_by_envelope_not_by_order() -> None:
    """ffuf, hydra's report and the tool-neutral escape hatch all key their findings `results`. Each
    rule demands its OWN tool's envelope, so none of the three can be widened into the others — the
    property that keeps this from being a fragile ordering accident."""
    assert detect_format(FFUF) == "ffuf"
    assert detect_format(HYDRA_JSON_REPORT) == "hydra"
    assert detect_format(GENERIC) == "generic"
    assert detect_format(json.dumps({"results": []})) == "generic"
    # each envelope stripped of its own stamp falls back to generic — never to a sibling
    assert detect_format(HYDRA_JSON_REPORT.replace('"software": "Hydra"', '"software": "Other"')) == "generic"
    assert detect_format(json.dumps({"results": json.loads(FFUF)["results"]})) == "generic"
    # and the claim in the sniffer's comment is checked, not merely asserted in prose: the two
    # narrow rules are MUTUALLY EXCLUSIVE, so which of them is tested first cannot change an answer.
    from framework.v2.imports.parsers import _is_ffuf_report, _is_hydra_report

    for blob in (FFUF, FFUF_CLEAN, HYDRA_JSON_REPORT, GENERIC, json.dumps({"results": []})):
        data = json.loads(blob)
        assert not (_is_ffuf_report(data) and _is_hydra_report(data))


def test_the_tally_stays_total_on_a_hostile_digit_run() -> None:
    """The cross-check reads an integer out of untrusted bytes, and `int()` REFUSES a string past
    4300 digits (CPython's int/str conversion limit) with a ValueError — not the ImportAdapterError
    the parser contract promises. The digit run is bounded so a hostile blob gets the documented
    loud path or nothing, never a crash in an importer fed bytes nobody vetted."""
    for blob in ("9" * 5000 + " valid passwords found", "1" * 4400 + " valid password found"):
        with pytest.raises(ImportAdapterError):
            parse_export("hydra", blob)


def test_content_discovery_never_pays_off_a_credential_tally() -> None:
    """The tally counts CRACKED CREDENTIALS, so only credential findings may settle it. hydra's
    `http-proxy-urlenum` line is graded `content_discovery` — if that counted, a run that enumerated
    one URL and cracked one unreadable account would balance to zero and report the URL as though
    nothing had been missed."""
    laundered = ("[8080][http-proxy-urlenum] host: t.example   url: http://t.example/internal\n"
                 + HYDRA_UNREADABLE_HIT)
    with pytest.raises(ImportAdapterError, match="only 0 could be read"):
        parse_export("hydra", laundered)
