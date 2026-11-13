"""Registrable domains for the free-trial launch gate, from a VENDORED, sha256-pinned Public Suffix List.

The trial is one per registrable domain. The domain is computed with the ICANN section of the Public Suffix
List only, so `shop.acme.co.uk` and `api.acme.co.uk` share `acme.co.uk` while `acme.co.uk` and `beta.co.uk`
do not. A host under a PRIVATE-section suffix (a free-subdomain platform such as github.io or vercel.app) is
NOT trial-eligible at all: keyed per subdomain it would give unlimited free trials, and keyed per platform the
first user would block everyone else. IP literals, localhost and single-label hosts are not eligible either.

FAIL-CLOSED: if the vendored list is missing or its sha256 does not match the pin, every TRIAL check refuses
(paid launches never call this module). A stale list under-splits new suffixes, which also only refuses.

The list is MPL-2.0 data (apps/sigil/sigil/governor/data/public_suffix_list.dat); update it by replacing the
file and the pin together. FATAL-2: sovereign-side, stdlib only, `assert_no_offense` at import.
"""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

PSL_PATH = Path(__file__).resolve().parent / "data" / "public_suffix_list.dat"
PSL_SHA256 = "b3f2d087e147f5fb4226710acb180d4f2361a281473e234d61005e46afdc8891"


class TrialDomainRefused(ValueError):
    """The host cannot take a trial launch; `.reason` is a machine code, never shown verbatim to a customer."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class _Rules:
    icann: frozenset
    icann_wild: frozenset
    icann_exc: frozenset
    private: frozenset
    private_wild: frozenset


def _idna(label: str) -> Optional[str]:
    try:
        return label.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def _norm_rule(rule: str) -> Optional[str]:
    parts = []
    for lab in rule.split("."):
        if lab == "*":
            parts.append("*")
            continue
        enc = _idna(lab)
        if enc is None:
            return None
        parts.append(enc)
    return ".".join(parts)


def parse(text: str) -> _Rules:
    icann: set = set()
    icann_wild: set = set()
    icann_exc: set = set()
    private: set = set()
    private_wild: set = set()
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("// ===BEGIN ICANN DOMAINS==="):
            section = "icann"
            continue
        if line.startswith("// ===BEGIN PRIVATE DOMAINS==="):
            section = "private"
            continue
        if line.startswith("// ===END"):
            section = None
            continue
        if not line or line.startswith("//") or section is None:
            continue
        rule = line.split()[0]
        exc = rule.startswith("!")
        r = _norm_rule(rule[1:] if exc else rule)
        if r is None:
            continue
        if section == "icann":
            if exc:
                icann_exc.add(r)
            elif r.startswith("*."):
                icann_wild.add(r[2:])
            else:
                icann.add(r)
        else:
            if r.startswith("*."):
                private_wild.add(r[2:])
            elif not exc:
                private.add(r)
    return _Rules(frozenset(icann), frozenset(icann_wild), frozenset(icann_exc), frozenset(private),
                  frozenset(private_wild))


_CACHE: "dict[str, Optional[_Rules]]" = {}


def load_rules(path: Path = PSL_PATH, pin: str = PSL_SHA256) -> Optional[_Rules]:
    """The parsed list, or None when it is missing or its sha256 does not match the pin (fail-closed)."""
    key = f"{path}:{pin}"
    if key in _CACHE:
        return _CACHE[key]
    try:
        data = Path(path).read_bytes()
    except OSError:
        rules = None
    else:
        rules = parse(data.decode("utf-8")) if hashlib.sha256(data).hexdigest() == pin else None
    if rules is not None:              # cache only a good load: a restored file is picked up on the next call
        _CACHE[key] = rules
    return rules


def _icann_suffix_len(labels: "list[str]", rules: _Rules) -> int:
    """Number of trailing labels that form the ICANN public suffix (the implicit `*` rule gives 1)."""
    best = 1
    n = len(labels)
    for i in range(n):
        cand = ".".join(labels[i:])
        size = n - i
        if cand in rules.icann_exc:
            return size - 1                       # an exception rule: the suffix is one label shorter
        if cand in rules.icann:
            best = max(best, size)
        if i + 1 < n and ".".join(labels[i + 1:]) in rules.icann_wild:
            best = max(best, size)
    return best


def _under_private(labels: "list[str]", rules: _Rules) -> bool:
    n = len(labels)
    for i in range(n):
        cand = ".".join(labels[i:])
        if cand in rules.private and n - i < n:
            return True                           # a subdomain of a private-section suffix
        if i + 1 < n and ".".join(labels[i + 1:]) in rules.private_wild:
            return True
    return False


def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
    except ValueError:
        return False
    return True


_LOAD: Any = object()          # default: load the vendored list (an explicit None means "no usable list")


def trial_domain(host: str, *, rules: Any = _LOAD) -> str:
    """The ICANN registrable domain for a TRIAL launch on `host`, or raise TrialDomainRefused. Refuses: no
    usable list, an IP literal, localhost, a single-label or malformed host, a host under a private-section
    (free-subdomain platform) suffix, and a host that IS a public suffix."""
    if rules is _LOAD:
        rules = load_rules()
    if rules is None:
        raise TrialDomainRefused("suffix_list_unavailable")
    h = str(host or "").strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if _is_ip(h):
        raise TrialDomainRefused("ip_literal")
    if not h or h == "localhost" or h.endswith(".localhost"):
        raise TrialDomainRefused("localhost")
    labels = []
    for lab in h.split("."):
        enc = _idna(lab) if lab else None
        if not enc:
            raise TrialDomainRefused("malformed_host")
        labels.append(enc)
    if len(labels) < 2:
        raise TrialDomainRefused("single_label")
    if _under_private(labels, rules):
        raise TrialDomainRefused("private_suffix")
    k = _icann_suffix_len(labels, rules)
    if k >= len(labels):
        raise TrialDomainRefused("public_suffix")
    return ".".join(labels[-(k + 1):])


def same_domain(host: str, domain: str, *, rules: Any = _LOAD) -> bool:
    """True iff `host` is eligible and its trial domain equals `domain`."""
    try:
        return trial_domain(host, rules=rules) == domain
    except TrialDomainRefused:
        return False
