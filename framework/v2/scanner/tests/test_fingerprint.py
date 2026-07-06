"""
Technology-fingerprint engine — deterministic detection from observed responses.

Each test crafts concrete responses and asserts the exact technologies, their
categories, and the flat :attr:`Fingerprint.tokens` set that downstream checks
gate on. Detection here is a deterministic function of bytes, so assertions are
exact: a signal is present or it is not, and a bare ``Server: nginx`` must not
hallucinate a CMS. The ``applies_when`` predicate grammar and the merge/implication
behaviour are exercised node-by-node.
"""

from __future__ import annotations

import pytest

from framework.v2.scanner.fingerprint import (
    Fingerprint,
    IMPLICATIONS,
    MalformedPredicate,
    MalformedResponse,
    SIGNATURES,
    TechMatch,
    fingerprint,
    fingerprint_favicon,
    matches_predicate,
)
from framework.v2.scanner.passive import Response


# ---------------------------------------------------------------------------
# core stack detection
# ---------------------------------------------------------------------------


def test_nginx_php_wordpress_full_stack() -> None:
    resp = Response(
        url="https://shop.example/",
        status=200,
        headers=[
            ("Server", "nginx/1.24.0"),
            ("X-Powered-By", "PHP/8.1"),
            ("Content-Type", "text/html"),
        ],
        body=(
            '<html><head>'
            '<meta name="generator" content="WordPress 6.4.2" />'
            '<link rel="stylesheet" href="https://shop.example/wp-content/themes/x/style.css">'
            '</head><body>hi</body></html>'
        ),
    )
    fp = fingerprint(resp)

    assert {"nginx", "php", "wordpress"} <= fp.technologies
    assert {"server", "language", "cms"} <= fp.categories
    # the integration contract: tokens unions names and categories
    assert {"nginx", "php", "wordpress", "server", "language", "cms"} <= fp.tokens
    assert fp.has("wordpress") and fp.has("cms") and fp.has("nginx")
    assert not fp.has("django")

    # evidence points at the concrete signals
    wp = fp.best("wordpress")
    assert wp is not None and "wp-content" in wp.evidence and "WordPress 6.4.2" in wp.evidence
    assert "Server: nginx/1.24.0" == fp.best("nginx").evidence  # exact header banner


def test_wordpress_meta_generator_attribute_order_independent() -> None:
    # content before name — a naive regex would miss this; the HTML parser does not
    resp = Response(url="https://b/", body='<meta content="WordPress 6.5" name="generator">')
    fp = fingerprint(resp)
    assert "wordpress" in fp.technologies
    assert "php" in fp.technologies  # implied runtime


def test_bare_nginx_does_not_hallucinate_cms_or_language() -> None:
    resp = Response(url="https://n/", headers=[("Server", "nginx")], body="")
    fp = fingerprint(resp)
    assert fp.technologies == {"nginx"}
    assert fp.categories == {"server"}
    assert "wordpress" not in fp.tokens
    assert "php" not in fp.tokens
    assert fp.describe() == "server: nginx"


# ---------------------------------------------------------------------------
# frameworks & their implied runtimes
# ---------------------------------------------------------------------------


def test_django_python_from_cookie_and_body() -> None:
    resp = Response(
        url="https://app/",
        headers=[("Set-Cookie", "csrftoken=abc123; Path=/; SameSite=Lax")],
        body='<form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="z"></form>',
    )
    fp = fingerprint(resp)
    assert "django" in fp.technologies
    assert "python" in fp.technologies  # framework -> runtime implication
    assert {"framework", "language"} <= fp.categories
    # python is inferred, not an observed banner — evidence says so
    assert "implied by django" in fp.best("python").evidence


def test_rails_ruby_from_session_cookie_and_token() -> None:
    resp = Response(
        url="https://r/",
        headers=[("Set-Cookie", "_myapp_session=xyz; HttpOnly")],
        body='<input type="hidden" name="authenticity_token" value="t">',
    )
    fp = fingerprint(resp)
    assert "rails" in fp.technologies and "ruby" in fp.technologies


def test_spring_java_from_whitelabel_error_page() -> None:
    resp = Response(url="https://s/x", status=500,
                    body="<html><body><h1>Whitelabel Error Page</h1></body></html>")
    fp = fingerprint(resp)
    assert "spring" in fp.technologies and "java" in fp.technologies


def test_express_node_from_x_powered_by() -> None:
    resp = Response(url="https://e/", headers=[("X-Powered-By", "Express")])
    fp = fingerprint(resp)
    assert "express" in fp.technologies and "node" in fp.technologies
    assert "framework" in fp.categories and "language" in fp.categories


def test_laravel_from_session_cookie() -> None:
    resp = Response(url="https://l/", headers=[("Set-Cookie", "laravel_session=deadbeef; Path=/")])
    fp = fingerprint(resp)
    assert "laravel" in fp.technologies and "php" in fp.technologies


# ---------------------------------------------------------------------------
# languages
# ---------------------------------------------------------------------------


def test_aspnet_and_iis() -> None:
    resp = Response(url="https://ms/", headers=[
        ("Server", "Microsoft-IIS/10.0"),
        ("X-AspNet-Version", "4.0.30319"),
        ("Set-Cookie", "ASP.NET_SessionId=aaa; path=/; HttpOnly"),
    ])
    fp = fingerprint(resp)
    assert "iis" in fp.technologies and "asp.net" in fp.technologies
    assert fp.best("asp.net").confidence >= 0.85


def test_java_from_jsessionid() -> None:
    resp = Response(url="https://j/", headers=[("Set-Cookie", "JSESSIONID=0123456789ABCDEF; Path=/")])
    fp = fingerprint(resp)
    assert "java" in fp.technologies and "language" in fp.categories


# ---------------------------------------------------------------------------
# CDN / edge and WAF (cloudflare is both)
# ---------------------------------------------------------------------------


def test_cloudflare_is_cdn_and_waf() -> None:
    resp = Response(url="https://cf/", headers=[
        ("Server", "cloudflare"),
        ("CF-RAY", "8a1b2c3d4e5f6a7b-SJC"),
    ])
    fp = fingerprint(resp)
    assert "cloudflare" in fp.technologies
    assert "cdn" in fp.categories
    assert "waf" in fp.categories
    # same tech name, two categories -> two distinct matches
    cats = {m.category for m in fp.matches if m.name == "cloudflare"}
    assert cats == {"cdn", "waf"}


def test_cloudfront_and_fastly_and_akamai() -> None:
    cf = fingerprint(Response(url="https://a/", headers=[("X-Amz-Cf-Id", "abc==")]))
    assert "cloudfront" in cf.technologies and "cdn" in cf.categories

    fastly = fingerprint(Response(url="https://a/", headers=[("X-Served-By", "cache-sjc10021-SJC")]))
    assert "fastly" in fastly.technologies

    akamai = fingerprint(Response(url="https://a/", headers=[("Server", "AkamaiGHost")]))
    assert "akamai" in akamai.technologies
    assert {"cdn", "waf"} <= akamai.categories


def test_imperva_and_f5_waf_cookies() -> None:
    imperva = fingerprint(Response(url="https://i/", headers=[
        ("Set-Cookie", "visid_incap_123456=xyz; path=/"),
    ]))
    assert "imperva" in imperva.technologies and "waf" in imperva.categories

    f5 = fingerprint(Response(url="https://f/", headers=[
        ("Set-Cookie", "BIGipServerpool_web=123.45.67.89.20480.0000; path=/"),
    ]))
    assert "f5-big-ip" in f5.technologies


def test_modsecurity_block_page() -> None:
    resp = Response(url="https://m/", status=403,
                    body="<h1>This error was generated by Mod_Security</h1>")
    fp = fingerprint(resp)
    assert "mod_security" in fp.technologies and "waf" in fp.categories


# ---------------------------------------------------------------------------
# API gateways
# ---------------------------------------------------------------------------


def test_kong_and_aws_api_gateway() -> None:
    kong = fingerprint(Response(url="https://k/", headers=[("Via", "1.1 kong/3.4.0")]))
    assert "kong" in kong.technologies and "api_gateway" in kong.categories

    aws = fingerprint(Response(url="https://a/", headers=[("x-amz-apigw-id", "Abc123=")]))
    assert "aws-api-gateway" in aws.technologies


# ---------------------------------------------------------------------------
# input shapes: single vs iterable, dict, duck-typed object; merge behaviour
# ---------------------------------------------------------------------------


def test_accepts_dict_and_duck_typed_object() -> None:
    as_dict = {"url": "https://d/", "status": 200,
               "headers": {"Server": "nginx"}, "body": ""}
    assert "nginx" in fingerprint(as_dict).technologies

    class _Resp:
        url = "https://o/"
        status = 200
        headers = [("X-Powered-By", "PHP/8.2")]
        body = ""

    assert "php" in fingerprint(_Resp()).technologies


def test_merge_keeps_strongest_confidence_and_unions_evidence() -> None:
    # php seen twice: strong X-Powered-By (0.98) and weaker PHPSESSID cookie (0.75)
    r1 = Response(url="https://t/a", headers=[("X-Powered-By", "PHP/8.1")])
    r2 = Response(url="https://t/b", headers=[("Set-Cookie", "PHPSESSID=abc; path=/")])
    fp = fingerprint([r1, r2])

    php = [m for m in fp.matches if m.name == "php" and m.category == "language"]
    assert len(php) == 1  # merged to a single match
    assert php[0].confidence == 0.98  # strongest wins
    assert "X-Powered-By: PHP/8.1" in php[0].evidence
    assert 'cookie "PHPSESSID"' in php[0].evidence  # evidence unioned


def test_single_response_equivalent_to_singleton_list() -> None:
    r = Response(url="https://t/", headers=[("Server", "nginx")])
    assert fingerprint(r).model_dump() == fingerprint([r]).model_dump()


def test_empty_input_yields_empty_fingerprint() -> None:
    fp = fingerprint([])
    assert fp.matches == []
    assert fp.tokens == set()
    assert fp.describe() == "no technologies fingerprinted"


def test_malformed_response_raises() -> None:
    with pytest.raises(MalformedResponse):
        fingerprint([12345])
    with pytest.raises(MalformedResponse):
        fingerprint(["not a response"])


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


def test_determinism_identical_dump_for_identical_input() -> None:
    responses = [
        Response(url="https://t/", headers=[
            ("Server", "nginx/1.25"), ("X-Powered-By", "PHP/8.1"),
            ("Set-Cookie", "PHPSESSID=abc; path=/"),
        ], body='<meta name="generator" content="WordPress 6.4"> /wp-content/ /wp-json/'),
        Response(url="https://t/api", headers=[("CF-RAY", "abc-SJC"), ("Server", "cloudflare")]),
    ]
    a = fingerprint(responses)
    b = fingerprint(responses)
    assert a.model_dump() == b.model_dump()
    # canonical ordering: sorted by (category, name)
    ordering = [(m.category, m.name) for m in a.matches]
    assert ordering == sorted(ordering)


# ---------------------------------------------------------------------------
# predicate grammar — every node
# ---------------------------------------------------------------------------

_TOKENS = {"wordpress", "cms", "php", "language", "nginx", "server"}


def test_predicate_empty_and_none_are_always_true() -> None:
    assert matches_predicate(None, _TOKENS) is True
    assert matches_predicate({}, _TOKENS) is True


def test_predicate_always() -> None:
    assert matches_predicate({"always": True}, _TOKENS) is True
    assert matches_predicate({"always": False}, _TOKENS) is False


def test_predicate_tech() -> None:
    assert matches_predicate({"tech": "wordpress"}, _TOKENS) is True
    assert matches_predicate({"tech": "WordPress"}, _TOKENS) is True  # case-insensitive
    assert matches_predicate({"tech": "django"}, _TOKENS) is False


def test_predicate_category() -> None:
    assert matches_predicate({"category": "cms"}, _TOKENS) is True
    assert matches_predicate({"category": "waf"}, _TOKENS) is False


def test_predicate_any() -> None:
    assert matches_predicate({"any": [{"tech": "django"}, {"tech": "wordpress"}]}, _TOKENS) is True
    assert matches_predicate({"any": [{"tech": "django"}, {"tech": "rails"}]}, _TOKENS) is False
    assert matches_predicate({"any": []}, _TOKENS) is False  # empty OR


def test_predicate_all() -> None:
    assert matches_predicate({"all": [{"tech": "wordpress"}, {"category": "waf"}]}, _TOKENS) is False
    assert matches_predicate({"all": [{"tech": "wordpress"}, {"category": "cms"}]}, _TOKENS) is True
    assert matches_predicate({"all": []}, _TOKENS) is True  # empty AND


def test_predicate_not() -> None:
    assert matches_predicate({"not": {"tech": "django"}}, _TOKENS) is True
    assert matches_predicate({"not": {"tech": "wordpress"}}, _TOKENS) is False


def test_predicate_nested() -> None:
    pred = {"all": [
        {"tech": "wordpress"},
        {"not": {"category": "waf"}},
        {"any": [{"tech": "nginx"}, {"tech": "apache"}]},
    ]}
    assert matches_predicate(pred, _TOKENS) is True


def test_predicate_malformed_raises() -> None:
    with pytest.raises(MalformedPredicate):
        matches_predicate({"bogus": "node"}, _TOKENS)
    with pytest.raises(MalformedPredicate):
        matches_predicate({"any": {"tech": "x"}}, _TOKENS)  # any wants a list


def test_predicate_gates_against_real_fingerprint_tokens() -> None:
    fp = fingerprint(Response(url="https://t/", headers=[
        ("Server", "nginx"), ("X-Powered-By", "PHP/8.1"),
    ], body="/wp-content/"))
    # a WordPress-only check runs; a Spring-only check does not
    assert matches_predicate({"tech": "wordpress"}, fp.tokens) is True
    assert matches_predicate({"tech": "spring"}, fp.tokens) is False
    assert matches_predicate({"all": [{"category": "cms"}, {"category": "language"}]}, fp.tokens) is True


# ---------------------------------------------------------------------------
# favicon
# ---------------------------------------------------------------------------


def test_favicon_known_hit_and_unknown_miss() -> None:
    hit = fingerprint_favicon(b"CRUCIBLE-FIXTURE:wordpress-favicon")
    assert hit is not None
    assert hit.name == "wordpress" and hit.category == "cms"
    assert hit.evidence.startswith("favicon hash md5:")

    assert fingerprint_favicon(b"some other bytes") is None
    assert fingerprint_favicon(b"") is None


# ---------------------------------------------------------------------------
# library invariants
# ---------------------------------------------------------------------------


def test_signature_library_is_wellformed() -> None:
    assert len(SIGNATURES) >= 40
    for sig in SIGNATURES:
        assert sig.name == sig.name.lower()
        assert len(sig.matchers()) == 1  # exactly one observable per row
        assert 0.0 <= sig.confidence <= 1.0


def test_implications_reference_lowercase_names() -> None:
    for src, implied, category in IMPLICATIONS:
        assert src == src.lower() and implied == implied.lower()
        assert category in {"language", "framework", "other"}


def test_techmatch_rejects_out_of_range_confidence() -> None:
    with pytest.raises(Exception):
        TechMatch(name="x", category="server", confidence=1.5)
    with pytest.raises(Exception):
        Fingerprint(matches=[{"name": "x", "category": "server", "confidence": 0.5, "extra": 1}])
