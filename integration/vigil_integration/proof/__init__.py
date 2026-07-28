"""vigil_integration.proof — the Proof Studio backend (deterministic reproduce-from-raw proof minting).

This package is installed in BOTH venvs (it lives under ``vigil_integration``). Every module that touches
offense code (``framework.v2.*``) MUST import it LAZILY (function-local), exactly as ``oracle_adapter`` and
``learn_drain`` do, so importing anything here in the sovereign env never pulls ``framework`` (FATAL-2).
"""
