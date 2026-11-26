"""Static-analysis fixtures for ``test_saas_closure.py``.

These modules are PARSED by ``framework.v2.aegis.closure`` (by name -> source path), NEVER imported at
runtime — so their deliberately-planted offense imports never actually load. They exist so the sound
analyzer's lazy / PEP 562 detection can be flip-tested end-to-end through the public ``check_saas_closure``.
Nothing in the test suite imports this package; pytest does not collect it (no ``test_`` files).
"""
