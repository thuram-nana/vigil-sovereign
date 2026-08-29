"""vigil_core.doctor.strip_url_credentials — the ONE URL-credential scrubber both trust planes share.

The doctor reports surface DSNs (QDRANT_URL, LLM_API_BASE) to operator+ over /api/doctor. A name-based
redactor cannot catch a credential embedded in a value under a non-secret-named key; this value-level pass
strips the userinfo of a real scheme://…@authority up to the LAST @ (so an unescaped @ in the password
cannot leak its tail), while an @ in a path/query/fragment is left alone.
"""
from __future__ import annotations

from vigil_core.doctor import strip_url_credentials as s


def test_strips_the_whole_userinfo_up_to_the_last_at():
    # a password with an UNESCAPED @ is a functioning DSN (urllib splits on the last @); the tail must not leak
    assert s("http://vera:hunter2@PASSWORD@10.0.0.5:6333") == "http://***@10.0.0.5:6333"
    assert s("http://u:p@ss@host/db@2") == "http://***@host/db@2"


def test_matches_urllib_parsing_on_the_forms_a_regex_would_miss():
    # urllib DELETES \t\r\n before parsing, so an embedded newline can smuggle a second authority past a
    # naive regex — but not past a urllib-based strip: the real host is `evil`, and that is what is kept.
    assert s("http://u:p@host\nSECOND:cred@evil") == "http://***@evil"
    # a scheme-relative reference still has a netloc with userinfo — it must be stripped too
    assert s("//user:PASSLEAK@host:6333") == "//***@host:6333"
    # a bare email / mailto has no netloc → left alone (not over-redacted)
    assert s("user@example.com") == "user@example.com"
    assert s("mailto:ops@example.com") == "mailto:ops@example.com"


def test_strips_canonical_and_exotic_credential_forms():
    assert s("http://user:pass@host:6333") == "http://***@host:6333"
    assert s("redis://:hunter2@10.0.0.5:6379/0") == "redis://***@10.0.0.5:6379/0"
    assert s("https://tok3n@host:6333") == "https://***@host:6333"
    assert s("http://u:p@[::1]:6333") == "http://***@[::1]:6333"          # IPv6 host (brackets preserved)
    assert s("HTTP://u:p@host") == "http://***@host"                       # scheme normalised (redacted URL)
    assert s("http://user:p%40ss@host") == "http://***@host"              # %40-encoded userinfo
    assert s("http://u:p@host/db?x=y@z") == "http://***@host/db?x=y@z"    # creds + an @ in the query


def test_leaves_non_credential_values_unchanged():
    assert s("http://host:6333") == "http://host:6333"                    # no userinfo
    assert s("http://host/p@th") == "http://host/p@th"                    # @ in the path
    assert s("http://host/x?a=b@c") == "http://host/x?a=b@c"              # @ only in the query
    assert s("http://host/x#f@g") == "http://host/x#f@g"                  # @ only in the fragment
    assert s("https://idp.internal/realms/x") == "https://idp.internal/realms/x"  # a plain OIDC issuer


def test_non_string_and_empty_pass_through():
    assert s(None) is None
    assert s(123) == 123
    assert s("") == ""
    assert s(["http://u:p@h"]) == ["http://u:p@h"]                        # only strings are scrubbed
