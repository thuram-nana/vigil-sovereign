"""
scanner.quantum_era — quantum-AWARE crypto exposure + quantum-INSPIRED planning.

Two honestly-named capabilities. **Neither runs, simulates, or requires a quantum
computer.** The names "quantum-era" / "quantum-inspired" describe the *threat model*
and the *metaheuristic*, not the hardware.

1. POST-QUANTUM CRYPTO EXPOSURE
   A pure classifier over TLS primitive names plus a live stdlib-``ssl`` probe.
   The classical public-key primitives in wide use — RSA, finite-field/elliptic-curve
   Diffie-Hellman (DHE/ECDHE/X25519/X448), ECDSA/EdDSA — are broken by Shor's
   algorithm on a large fault-tolerant quantum computer (a "CRQC"). No such machine
   is known to exist today. The operational risk that exists *today* is
   HARVEST-NOW-DECRYPT-LATER (HNDL): an adversary records a TLS session now and
   decrypts it years later once a CRQC exists, IF the key exchange that protected it
   was classical. So HNDL risk is a property of the KEY EXCHANGE, not the signature
   (a forged signature must be produced live, so it is a future-authentication risk,
   not a recording risk). The classifier maps primitive names to
   ``vulnerable`` | ``pqc`` | ``hybrid`` | ``unknown``; ``pqc_scan`` negotiates a real
   handshake and reports what a *standard client* got.

   HONEST LIMIT of ``pqc_scan``: Python 3.13's stdlib ``ssl`` cannot advertise PQC key
   groups (no ``SSLContext`` group control until 3.14) and does not expose the
   negotiated TLS 1.3 group. So this probe can prove the server *accepts* a classical,
   quantum-vulnerable key exchange with a normal client — it CANNOT prove the server
   lacks PQC/hybrid support for PQC-capable clients. That is the correct, provable
   conclusion for the HNDL question ("is my traffic, as spoken by ordinary clients,
   harvestable?") and the report says so.

2. QUANTUM-INSPIRED OPTIMIZER
   ``anneal_path_portfolio`` selects a subset of attack paths maximising total value
   under a detection-cost budget — a 0/1 knapsack — using SIMULATED ANNEALING, a
   classical metaheuristic *inspired by* physical/quantum annealing. It is not quantum
   annealing and needs no annealer hardware. Deterministic given a seeded
   ``random.Random``. Duck-types ``.value`` / ``.detection_cost`` so it accepts
   ``orchestrator.AttackPath`` (see ``value_of`` / ``cost_of`` to adapt).

Pure stdlib (+ optional ``cryptography`` for certificate parsing), deterministic.
"""

from __future__ import annotations

import math
import re
import socket
import ssl
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from random import Random
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

try:  # optional; used only to read a leaf certificate's signature algorithm.
    from cryptography import x509 as _x509

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - exercised only where cryptography is absent
    _x509 = None
    _HAVE_CRYPTO = False


CryptoClass = Literal["vulnerable", "pqc", "hybrid", "unknown"]

# ---------------------------------------------------------------------------
# (1) post-quantum crypto exposure — pure classifiers
# ---------------------------------------------------------------------------

# PQC (quantum-resistant) primitives. Kept separate from signatures so the KEX and
# signature classifiers do not cross-contaminate (e.g. "ML-DSA" must not read as the
# classical "DSA"). Names are matched against a separator-stripped, lower-cased form.
_PQC_KEX = ("mlkem", "kyber", "frodo", "ntruprime", "sntrup", "ntru", "bike", "hqc",
            "mceliece", "sike")
_PQC_SIG = ("mldsa", "dilithium", "slhdsa", "sphincs", "falcon", "xmssmt", "xmss", "lms")

# Classical (Shor-breakable) primitives.
_CLASSICAL_KEX = ("x25519", "x448", "curve25519", "ecdhe", "ecdh", "ffdhe", "dhe",
                  "secp", "prime256", "brainpool", "sect", "rsa", "dh")
_CLASSICAL_SIG = ("rsassa", "rsa", "ecdsa", "ed25519", "ed448", "dsa")


def _compact(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _classify(name: str, pqc_tokens: Sequence[str], classical_tokens: Sequence[str]) -> CryptoClass:
    """Core classifier: PQC tokens are detected first and removed from the string
    before classical tokens are checked, so a compound PQC name (``ML-DSA`` →
    ``mldsa``) never leaks its ``dsa`` tail into the classical bucket, while a genuine
    hybrid (``X25519MLKEM768``) still shows both a PQC and a classical component."""
    compact = _compact(name)
    if not compact:
        return "unknown"
    has_pqc = any(tok in compact for tok in pqc_tokens)
    residual = compact
    for tok in pqc_tokens:
        residual = residual.replace(tok, "")
    has_classical = any(tok in residual for tok in classical_tokens)
    if has_pqc and has_classical:
        return "hybrid"
    if has_pqc:
        return "pqc"
    if has_classical:
        return "vulnerable"
    return "unknown"


def classify_kex(name: str) -> CryptoClass:
    """Classify a key-exchange / cipher-suite name by quantum exposure.

    ``vulnerable`` — classical Diffie-Hellman family (RSA/DHE/ECDHE/X25519/X448):
    Shor-breakable, so sessions it protects are harvest-now-decrypt-later exposed.
    ``pqc`` — a standalone PQC KEM (ML-KEM/Kyber/FrodoKEM/…).
    ``hybrid`` — classical ⊕ PQC (X25519MLKEM768): safe unless BOTH break.
    ``unknown`` — no recognised KEX token (e.g. a bare TLS 1.3 suite name, whose group
    is negotiated separately and not encoded in the suite name).
    """
    return _classify(name, _PQC_KEX, _CLASSICAL_KEX)


def classify_signature(name: str) -> CryptoClass:
    """Classify a signature algorithm name by quantum exposure.

    ``vulnerable`` — RSA / ECDSA / EdDSA (Shor-breakable → forgeable by a future CRQC).
    ``pqc`` — ML-DSA/Dilithium, SLH-DSA/SPHINCS+, Falcon, XMSS/LMS.
    ``hybrid`` — a classical+PQC composite signature. ``unknown`` — unrecognised.
    """
    return _classify(name, _PQC_SIG, _CLASSICAL_SIG)


class PqcReport(BaseModel):
    """What a standard TLS client observed about a target's quantum exposure."""

    model_config = ConfigDict(extra="forbid")

    host: str
    port: int
    tls_version: str | None = None
    cipher_suite: str | None = None
    kex_class: CryptoClass
    sig_class: CryptoClass
    signature_algorithm: str | None = Field(
        default=None, description="Leaf-cert signature OID name, if it could be parsed."
    )
    harvest_now_decrypt_later: bool = Field(
        description="True iff the negotiated key exchange (as spoken to a normal "
        "client) is classical, so recorded traffic is decryptable once a CRQC exists."
    )
    kex_inferred: bool = Field(
        default=False,
        description="True when the KEX class was inferred from the fact that a stdlib "
        "client (which offers only classical groups) completed the handshake, rather "
        "than read directly from the negotiated group.",
    )
    weaknesses: list[str] = Field(default_factory=list)


def _leaf_signature_algorithm(der: bytes | None) -> str | None:
    if der is None or not _HAVE_CRYPTO:
        return None
    try:
        cert = _x509.load_der_x509_certificate(der)
    except Exception:  # pragma: no cover - malformed cert
        return None
    oid = cert.signature_algorithm_oid
    return getattr(oid, "_name", None) or oid.dotted_string


def pqc_scan(host: str, port: int = 443, *, timeout: float = 5.0) -> PqcReport | None:
    """Open a real TLS handshake (loopback/authorized targets only) and report the
    quantum exposure of what a standard client negotiated. Returns ``None`` if the
    connection or handshake fails.

    Certificate validation is DISABLED on purpose: this is a crypto-posture probe, not
    a trust check, and it must work against self-signed and internal endpoints. It
    reads the negotiated cipher suite (and, when ``cryptography`` is available, the leaf
    certificate's signature algorithm) and classifies both. See the module docstring
    for why the KEX verdict is inferred rather than read on Python < 3.14.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                version = tls.version()
                cipher = tls.cipher()
                cipher_name = cipher[0] if cipher else None
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None

    sig_alg = _leaf_signature_algorithm(der)
    sig_class = classify_signature(sig_alg) if sig_alg else "unknown"

    weaknesses: list[str] = []

    # KEX: try to read it from the suite name; TLS 1.3 suite names carry no group, so
    # fall back to the sound inference that a stdlib client (classical groups only)
    # could not have negotiated anything but a classical, quantum-vulnerable KEX.
    kex_from_suite = classify_kex(cipher_name) if cipher_name else "unknown"
    kex_inferred = False
    if kex_from_suite in ("vulnerable", "pqc", "hybrid"):
        kex_class: CryptoClass = kex_from_suite
    else:
        kex_class = "vulnerable"
        kex_inferred = True
        weaknesses.append(
            "key-exchange group not directly observable (stdlib ssl < 3.14); inferred "
            "classical because a client offering only classical groups completed the "
            "handshake — this cannot rule out PQC support for PQC-capable clients"
        )

    hndl = kex_class == "vulnerable"
    if hndl:
        label = cipher_name or "negotiated suite"
        weaknesses.append(
            f"classical key exchange ({label}) is quantum-vulnerable: sessions are "
            "exposed to harvest-now-decrypt-later"
        )
    if sig_class == "vulnerable":
        weaknesses.append(
            f"leaf certificate signature '{sig_alg}' is classical and forgeable by a "
            "future CRQC (authentication risk, not a recording risk)"
        )
    elif sig_class == "unknown" and sig_alg is None and not _HAVE_CRYPTO:
        weaknesses.append("certificate signature not parsed (cryptography unavailable)")

    return PqcReport(
        host=host,
        port=port,
        tls_version=version,
        cipher_suite=cipher_name,
        kex_class=kex_class,
        sig_class=sig_class,
        signature_algorithm=sig_alg,
        harvest_now_decrypt_later=hndl,
        kex_inferred=kex_inferred,
        weaknesses=weaknesses,
    )


# ---------------------------------------------------------------------------
# (2) quantum-inspired optimizer — simulated annealing over a path portfolio
# ---------------------------------------------------------------------------

T = TypeVar("T")


@dataclass(frozen=True)
class PortfolioSelection:
    """The subset an annealing run chose, with its achieved value and cost."""

    chosen: tuple[T, ...]
    indices: tuple[int, ...]
    value: float
    detection_cost: float
    budget: float
    feasible: bool
    iterations: int

    def describe(self) -> str:
        return (
            f"{len(self.indices)} paths, value={self.value:.3f}, "
            f"cost={self.detection_cost:.3f}/{self.budget:.3f} "
            f"({'feasible' if self.feasible else 'INFEASIBLE'})"
        )


def _attr_value(it: object) -> float:
    return float(it.value)  # type: ignore[attr-defined]


def _attr_cost(it: object) -> float:
    return float(it.detection_cost)  # type: ignore[attr-defined]


def anneal_path_portfolio(
    items: Iterable[T],
    *,
    budget: float,
    rng: Random,
    iterations: int = 4000,
    value_of: Callable[[T], float] = _attr_value,
    cost_of: Callable[[T], float] = _attr_cost,
    restarts: int = 4,
) -> PortfolioSelection:
    """Select the subset of ``items`` maximising total value with total
    ``detection_cost`` ≤ ``budget`` — a 0/1 knapsack — via SIMULATED ANNEALING.

    A classical, quantum-annealing-INSPIRED metaheuristic; no quantum hardware. State
    is a bitmask over items; each step proposes a neighbour — a single-bit flip or a
    1-for-1 swap (drop a chosen item, add an unchosen one; the swap move is what lets
    the search rebalance a budget-saturated selection, knapsack's characteristic trap)
    — and accepts it if it improves the penalised objective
    ``value − λ·max(0, cost − budget)`` or, when worse, with Metropolis probability
    ``exp(Δ/T)`` under a geometric cooling schedule. λ is
    set above the total available value so any budget violation is strictly dominated
    by any feasible selection, and the best FEASIBLE state seen is returned. ``restarts``
    independent cooling runs (splitting the iteration budget) reduce the chance of a
    poor local optimum. Fully determined by ``rng``; not guaranteed globally optimal on
    large instances (it is a heuristic), but reliably optimal on the small path
    portfolios a campaign produces.

    ``value_of`` / ``cost_of`` default to duck-typed ``.value`` / ``.detection_cost`` so
    an ``orchestrator.AttackPath`` (which exposes ``.detection_cost``) can be used by
    passing a ``value_of`` that maps a path to its impact score.
    """
    pool = list(items)
    n = len(pool)
    values = [value_of(it) for it in pool]
    costs = [cost_of(it) for it in pool]
    if any(c < 0 for c in costs):
        raise ValueError("detection_cost must be non-negative")

    def _select(mask: list[bool]) -> PortfolioSelection:
        idx = tuple(i for i in range(n) if mask[i])
        return PortfolioSelection(
            chosen=tuple(pool[i] for i in idx),
            indices=idx,
            value=sum(values[i] for i in idx),
            detection_cost=sum(costs[i] for i in idx),
            budget=budget,
            feasible=sum(costs[i] for i in idx) <= budget + 1e-9,
            iterations=iterations,
        )

    if n == 0:
        return _select([])

    lam = sum(v for v in values if v > 0) + 1.0  # penalty per unit of budget overrun

    def energy(val: float, cost: float) -> float:
        # minimise: lower is better. -value, plus penalty for any overrun.
        return -val + lam * max(0.0, cost - budget)

    # start empty (always feasible) so a feasible best exists from step 0.
    best_mask = [False] * n
    best_energy = energy(0.0, 0.0)
    best_feasible_val = 0.0

    per_run = max(1, iterations // max(1, restarts))
    t0 = max(1.0, max(values) if values else 1.0)
    t_min = 1e-3
    decay = (t_min / t0) ** (1.0 / max(1, per_run))

    for _ in range(max(1, restarts)):
        mask = [False] * n
        cur_val = 0.0
        cur_cost = 0.0
        cur_energy = energy(cur_val, cur_cost)
        temp = t0
        for _ in range(per_run):
            chosen = [i for i in range(n) if mask[i]]
            unchosen = [i for i in range(n) if not mask[i]]
            # ~half the moves are 1-for-1 swaps when both a chosen and an unchosen item
            # exist; the rest are single-bit flips.
            if chosen and unchosen and rng.random() < 0.5:
                a = rng.choice(chosen)
                b = rng.choice(unchosen)
                nmask = mask.copy()
                nmask[a] = False
                nmask[b] = True
                nval = cur_val - values[a] + values[b]
                ncost = cur_cost - costs[a] + costs[b]
            else:
                j = rng.randrange(n)
                take = not mask[j]
                nmask = mask.copy()
                nmask[j] = take
                nval = cur_val + (values[j] if take else -values[j])
                ncost = cur_cost + (costs[j] if take else -costs[j])
            nenergy = energy(nval, ncost)
            delta = nenergy - cur_energy  # <0 means improvement
            if delta <= 0 or rng.random() < math.exp(-delta / temp):
                mask = nmask
                cur_val, cur_cost, cur_energy = nval, ncost, nenergy
                if cur_energy < best_energy and cur_cost <= budget + 1e-9:
                    best_energy = cur_energy
                    best_mask = mask.copy()
                    best_feasible_val = cur_val
            temp *= decay

        # local polish: greedily apply the best-improving move — a single bit flip OR a
        # 1-for-1 swap (drop a chosen item, add an unchosen one) — until no feasible
        # move improves value. Swaps let it escape the "full budget, wrong items" local
        # optima that single flips alone cannot (knapsack's characteristic trap).
        pmask = best_mask.copy()
        pval = best_feasible_val
        pcost = sum(costs[i] for i in range(n) if pmask[i])
        improved = True
        while improved:
            improved = False
            for j in range(n):  # single flips
                take = not pmask[j]
                nval = pval + (values[j] if take else -values[j])
                ncost = pcost + (costs[j] if take else -costs[j])
                if ncost <= budget + 1e-9 and nval > pval + 1e-12:
                    pmask[j] = take
                    pval, pcost = nval, ncost
                    improved = True
            chosen_now = [i for i in range(n) if pmask[i]]
            unchosen_now = [i for i in range(n) if not pmask[i]]
            for a in chosen_now:  # 1-for-1 swaps
                for b in unchosen_now:
                    nval = pval - values[a] + values[b]
                    ncost = pcost - costs[a] + costs[b]
                    if ncost <= budget + 1e-9 and nval > pval + 1e-12:
                        pmask[a] = False
                        pmask[b] = True
                        pval, pcost = nval, ncost
                        improved = True
                        break
                if improved:
                    break
        if pval > best_feasible_val + 1e-12:
            best_feasible_val = pval
            best_mask = pmask
            best_energy = energy(pval, pcost)

    return _select(best_mask)
