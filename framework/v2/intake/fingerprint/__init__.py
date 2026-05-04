"""
intake.fingerprint — modular detectors run during UTI intake.

One module per detection class. Each exports `detect(exchanges)`
returning a `DetectionResult`. The shared signature engine in
`_common.py` factors the rule-evaluation logic so each detector is
just a list of signatures.
"""

from __future__ import annotations

from .api_detection import detect as detect_api
from .auth_detection import detect as detect_auth
from .cdn_waf_detection import detect as detect_cdn_waf
from .cms_detection import detect as detect_cms
from .framework_detection import detect as detect_framework
from .payment_detection import detect as detect_payment
from .server_detection import detect as detect_server


ALL_DETECTORS = (
    ("server", detect_server),
    ("framework", detect_framework),
    ("cms", detect_cms),
    ("auth", detect_auth),
    ("api", detect_api),
    ("payment", detect_payment),
    ("cdn_waf", detect_cdn_waf),
)
