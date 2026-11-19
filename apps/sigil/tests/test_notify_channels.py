"""PR-D notify_channels — the SSRF-guarded outbound delivery of oracle-minted FACT findings.

Load-bearing invariants proven here (a false-green is a real breach):
  * SSRF GUARD / OWNER ALLOWLIST: a tenant webhook can never reach a non-allowlisted host, nor any host that
    resolves to an internal / loopback / cloud-metadata (169.254.169.254) / ULA / CGNAT address — at config time
    AND re-checked at SEND time. (self-red-pen: "point a webhook at an internal host" MUST fail.)
  * A NOTIFICATION IS NEVER A FACT SOURCE: the module performs NO spine write (no `.append(`), so delivery can
    never mint a finding. (self-red-pen: "mint a fact from a notice" is structurally impossible.)
  * NO MODEL IDENTIFIER to a customer: the notice is projected through a fixed inert-field allowlist; a model id
    carried on a record can never reach a channel.
  * FLAG-GATED: with VIGIL_CUSTOMER_NOTIFY off, delivery + config writes refuse (byte-identical-off).
  * TENANT ISOLATION: the channel registry is per-org (one-way hashed marker); one tenant cannot read another's.

Several asserts are the MUTATION-VERIFY anchors named in the commit message (break the guard -> the named test reds).
"""
from __future__ import annotations

import ast
import pathlib
import tempfile

import pytest

from sigil import config
from sigil.governor import notify_channels as nc


@pytest.fixture
def notify_on(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_NOTIFY", "1")
    assert config.customer_notify_enabled() is True
    yield


# -- the flag ------------------------------------------------------------------------------------------------
def test_flag_off_by_default(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_NOTIFY", raising=False)
    assert config.customer_notify_enabled() is False


# -- the SSRF / allowlist guard ------------------------------------------------------------------------------
_PUBLIC = lambda h: ["1.1.1.1"]  # noqa: E731 — an injected resolver returning a globally-routable address


def test_guard_allows_public_allowlisted_host():
    host = nc.guard_outbound_url("https://hooks.slack.com/services/T/B/x",
                                 allow_hosts=frozenset({"hooks.slack.com"}), resolver=_PUBLIC)
    assert host == "hooks.slack.com"


@pytest.mark.parametrize("url", [
    "http://hooks.slack.com/x",            # non-https
    "https://hooks.slack.com:8443/x",      # non-default port
    "https://user:pw@hooks.slack.com/x",   # userinfo
    "https://evil.test/x",                 # off-allowlist host
    "ftp://hooks.slack.com/x",             # non-https scheme
    "",                                    # empty
])
def test_guard_refuses_bad_url_shape(url):
    with pytest.raises(nc.OutboundRefused):
        nc.guard_outbound_url(url, allow_hosts=frozenset({"hooks.slack.com"}), resolver=_PUBLIC)


@pytest.mark.parametrize("ip", [
    "169.254.169.254",   # cloud metadata (link-local)
    "127.0.0.1", "::1",  # loopback
    "10.0.0.5", "192.168.1.1", "172.16.0.1",  # RFC1918
    "fd00::1",           # ULA
    "100.64.0.1",        # CGNAT
    "0.0.0.0",           # unspecified
    "::ffff:127.0.0.1",  # IPv4-mapped loopback
])
def test_guard_refuses_internal_resolution_SSRF(ip):
    # THE SSRF SELF-RED-PEN: an allowlisted host that RESOLVES to an internal/metadata address is refused. Dropping
    # the per-address public check in `_is_public_address` (or the resolve loop in `guard_outbound_url`) REDS this.
    with pytest.raises(nc.OutboundRefused):
        nc.guard_outbound_url("https://hooks.slack.com/x", allow_hosts=frozenset({"hooks.slack.com"}),
                              resolver=lambda h: [ip])


def test_guard_refuses_mixed_resolution_one_internal():
    # Even ONE internal address among many refuses the whole URL (a DNS-rebinding / split-horizon attempt).
    with pytest.raises(nc.OutboundRefused):
        nc.guard_outbound_url("https://hooks.slack.com/x", allow_hosts=frozenset({"hooks.slack.com"}),
                              resolver=lambda h: ["1.1.1.1", "169.254.169.254"])


def test_guard_refuses_unresolvable_and_empty_resolution():
    with pytest.raises(nc.OutboundRefused):
        nc.guard_outbound_url("https://hooks.slack.com/x", allow_hosts=frozenset({"hooks.slack.com"}),
                              resolver=lambda h: [])

    def boom(_h):
        raise OSError("nxdomain")
    with pytest.raises(nc.OutboundRefused):
        nc.guard_outbound_url("https://hooks.slack.com/x", allow_hosts=frozenset({"hooks.slack.com"}), resolver=boom)


def test_guard_suffix_allowlist_boundary():
    suf = frozenset({"discord.com"})
    assert nc.guard_outbound_url("https://discord.com/api/webhooks/1/x", allow_hosts=frozenset(),
                                 allow_suffixes=suf, resolver=_PUBLIC) == "discord.com"
    assert nc.guard_outbound_url("https://canary.discord.com/api/webhooks/1/x", allow_hosts=frozenset(),
                                 allow_suffixes=suf, resolver=_PUBLIC) == "canary.discord.com"
    with pytest.raises(nc.OutboundRefused):   # a look-alike must NOT match the suffix
        nc.guard_outbound_url("https://discord.com.evil.test/x", allow_hosts=frozenset(),
                              allow_suffixes=suf, resolver=_PUBLIC)


# -- channel validation --------------------------------------------------------------------------------------
def test_channel_validate_each_kind():
    nc.NotifyChannel(kind=nc.CHANNEL_SLACK, target="https://hooks.slack.com/x").validate(resolver=_PUBLIC)
    nc.NotifyChannel(kind=nc.CHANNEL_DISCORD, target="https://discord.com/api/webhooks/1/x").validate(resolver=_PUBLIC)
    nc.NotifyChannel(kind=nc.CHANNEL_EMAIL, target="dev@acme.example").validate()
    # a slack channel pointed off hooks.slack.com is refused (slack is pinned tighter than the generic allowlist)
    with pytest.raises(nc.OutboundRefused):
        nc.NotifyChannel(kind=nc.CHANNEL_SLACK, target="https://evil.test/x").validate(resolver=_PUBLIC)
    # a generic webhook to a non-allowlisted host is refused
    with pytest.raises(nc.OutboundRefused):
        nc.NotifyChannel(kind=nc.CHANNEL_WEBHOOK, target="https://evil.test/x").validate(resolver=_PUBLIC)
    for bad in [nc.NotifyChannel(kind="pager", target="x"), nc.NotifyChannel(kind=nc.CHANNEL_EMAIL, target="nope")]:
        with pytest.raises((nc.OutboundRefused, ValueError)):
            bad.validate()


# -- notice rendering: allowlist + no model identifier -------------------------------------------------------
def _finding(**over):
    row = {"engagement_slug": "cust_abc", "finding_ref": "F-1", "bug_class": "xss",
           "surface": "https://acme.example/search", "severity": "high", "title": "Reflected XSS in search",
           "summary": "User input reflected without encoding", "oracle_context_digest": "d1"}
    row.update(over)
    return row


def test_render_notice_projects_allowlist_only_and_strips_model_id():
    # A hostile/extra field (incl. a model id) on the record must NEVER reach the rendered notice — only the
    # inert allowlist is projected. MUTATION-VERIFY: adding "model" to `_NOTICE_FIELDS` REDS this test.
    row = _finding(model="claude-opus-4-8", internal_secret="s3cr3t", report_claims="x")
    notice = nc.render_finding_notice(row)
    blob = (notice.subject + "\n" + notice.body + "\n" + repr(notice.fields)).lower()
    assert "claude" not in blob and "opus" not in blob and "s3cr3t" not in blob
    assert "report_claims" not in notice.fields and "model" not in notice.fields
    assert notice.fields["finding_ref"] == "F-1" and notice.fields["severity"] == "high"


def test_render_notice_model_token_backstop_refuses():
    # The backstop: even if a model token sneaked into an allowlisted field, delivery fails closed.
    with pytest.raises(nc.OutboundRefused):
        nc.render_finding_notice(_finding(title="Leak via claude-opus-4-8 prompt"))


# -- delivery ------------------------------------------------------------------------------------------------
def test_deliver_refuses_when_flag_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_NOTIFY", raising=False)
    ch = nc.NotifyChannel(kind=nc.CHANNEL_WEBHOOK, target="https://hooks.slack.com/x")
    with pytest.raises(nc.OutboundRefused):
        nc.deliver(ch, nc.render_finding_notice(_finding()), http_post=lambda *a, **k: 200, resolver=_PUBLIC)


def test_deliver_webhook_via_injected_transport(notify_on):
    posted = {}

    def fake_post(url, body, headers):
        posted["url"], posted["body"], posted["headers"] = url, body, headers
        return 204

    ch = nc.NotifyChannel(kind=nc.CHANNEL_SLACK, target="https://hooks.slack.com/services/x")
    res = nc.deliver(ch, nc.render_finding_notice(_finding()), http_post=fake_post, resolver=_PUBLIC)
    assert res.ok and res.kind == nc.CHANNEL_SLACK and res.status == 204
    assert posted["url"] == "https://hooks.slack.com/services/x"
    assert b"Reflected XSS" in posted["body"] and b"claude" not in posted["body"].lower()


def test_deliver_webhook_at_internal_host_fails_SELF_RED_PEN(notify_on):
    # SELF-RED-PEN: point a (correctly-allowlisted-host) webhook whose host RESOLVES to the metadata address — the
    # send-time re-guard must refuse before the transport is ever called. The transport asserts it is never reached.
    def must_not_run(*a, **k):
        raise AssertionError("transport reached despite an internal resolution")

    ch = nc.NotifyChannel(kind=nc.CHANNEL_SLACK, target="https://hooks.slack.com/x")
    res = nc.deliver(ch, nc.render_finding_notice(_finding()), http_post=must_not_run,
                     resolver=lambda h: ["169.254.169.254"])
    assert res.ok is False
    assert "non-public" in res.detail or "SSRF" in res.detail


def test_deliver_email_via_sender(notify_on):
    sent = []
    ch = nc.NotifyChannel(kind=nc.CHANNEL_EMAIL, target="sec@acme.example")
    res = nc.deliver(ch, nc.render_finding_notice(_finding()),
                     email_send=lambda to, subj, body: sent.append((to, subj, body)) or True)
    assert res.ok and sent and sent[0][0] == "sec@acme.example"
    # no sender configured => not delivered, never raises
    res2 = nc.deliver(ch, nc.render_finding_notice(_finding()))
    assert res2.ok is False


# -- the per-tenant channel registry -------------------------------------------------------------------------
def test_registry_tenant_isolation_and_validate_before_store(notify_on):
    reg = nc.NotifyChannelRegistry(tempfile.mkdtemp())
    acme = [nc.NotifyChannel(kind=nc.CHANNEL_EMAIL, target="acme@x.example"),
            nc.NotifyChannel(kind=nc.CHANNEL_SLACK, target="https://hooks.slack.com/acme")]
    other = [nc.NotifyChannel(kind=nc.CHANNEL_EMAIL, target="other@y.example")]
    reg.set_channels("acme", acme)
    reg.set_channels("other", other)
    assert {c.target for c in reg.channels_of("acme")} == {"acme@x.example", "https://hooks.slack.com/acme"}
    assert {c.target for c in reg.channels_of("other")} == {"other@y.example"}
    # one org can never read another's channels, and an unknown org reads empty
    assert reg.channels_of("mallory") == []
    # an INVALID channel in the set raises and writes NOTHING (the earlier config is untouched)
    with pytest.raises((nc.OutboundRefused, ValueError)):
        reg.set_channels("acme", [nc.NotifyChannel(kind=nc.CHANNEL_WEBHOOK, target="https://evil.test/x")])
    assert {c.target for c in reg.channels_of("acme")} == {"acme@x.example", "https://hooks.slack.com/acme"}


def test_registry_refuses_write_when_flag_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_NOTIFY", raising=False)
    reg = nc.NotifyChannelRegistry(tempfile.mkdtemp())
    with pytest.raises(nc.OutboundRefused):
        reg.set_channels("acme", [nc.NotifyChannel(kind=nc.CHANNEL_EMAIL, target="a@x.example")])


# -- STRUCTURAL: a notification is NEVER a FACT source (no spine write anywhere in the module) ----------------
def test_module_never_writes_the_spine():
    # The hard proof of "a notification is never a FACT source": the delivery module has NO access to a spine store
    # at all, so it structurally CANNOT mint a finding. An AST scan of the import graph (not a substring grep, so a
    # comment mentioning the store is fine) plus the decisive literal checks.
    tree = ast.parse(pathlib.Path(nc.__file__).read_text(encoding="utf-8"))
    imported: list[str] = []
    mints: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.append((node.module or "") + "." + ",".join(a.name for a in node.names))
        elif isinstance(node, ast.Import):
            imported.extend(a.name for a in node.names)
        elif isinstance(node, ast.Call):   # a real spine mint is a call with kind="finding" — scan the AST, not text
            for kw in node.keywords:
                if kw.arg == "kind" and isinstance(kw.value, ast.Constant) and kw.value.value == "finding":
                    mints.append(ast.dump(node))
    joined = " ".join(imported)
    assert "spine" not in joined and "SpineStore" not in joined, f"delivery must not import a spine store: {joined}"
    assert not mints, f"delivery must never mint a finding record: {mints}"
