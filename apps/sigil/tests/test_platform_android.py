"""SIGIL Phase 9 W2-J — Android/Termux HostBackend. A phone running the SIGIL Python core under
Termux is described HONESTLY (os="android", never a masquerading LinuxBackend) and NEVER claims it
can inject HID into the PC. Secondary path (the primary phone client is the PWA). Every capture is
honest — a `Frame` or `None`, never fabricated.
Run: ~/.sigil/venv/bin/python tests/test_platform_android.py"""
import os
import sys

from sigil.perception.capture import Frame

_ENV_KEYS = ("TERMUX_VERSION", "PREFIX", "ANDROID_ROOT")


# ---- host() selection --------------------------------------------------------------------------
def test_host_selects_android_under_termux():
    import sigil.platform as P
    real_plat = sys.platform
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    try:
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        os.environ["TERMUX_VERSION"] = "0.118.0"       # Termux still reports sys.platform == "linux"
        sys.platform = "linux"
        assert type(P.host()).__name__ == "AndroidBackend", "Termux env selects the AndroidBackend"
    finally:
        sys.platform = real_plat
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def test_without_termux_host_stays_linux():
    import sigil.platform as P
    real_plat = sys.platform
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    try:
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        sys.platform = "linux"
        assert type(P.host()).__name__ == "LinuxBackend", "no Termux env → unchanged LinuxBackend"
    finally:
        sys.platform = real_plat
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


# ---- honest capability descriptor --------------------------------------------------------------
def test_capabilities_are_honest():
    from sigil.platform.android import AndroidBackend
    caps = AndroidBackend().capabilities()
    assert caps.os == "android", "the phone is described as android, not linux"
    assert caps.has_hid_inject is False, "a phone does NOT inject HID into the PC"
    assert caps.has_gpu_vlm is False and caps.always_on is False and caps.has_camera_stream is False, \
        "no GPU-VLM / always-on / camera-stream claims on the secondary phone path"
    assert isinstance(caps.has_screen, bool) and isinstance(caps.has_camera, bool), "honest booleans"
    assert isinstance(caps.host_id, str) and caps.host_id, "a stable host id"


# ---- honest captures (Frame or None, never fabricated) -----------------------------------------
def test_captures_are_honest():
    from sigil.platform.android import AndroidBackend
    b = AndroidBackend()
    for cap in (b.capture_camera(), b.capture_screen()):
        assert cap is None or isinstance(cap, Frame), "a capture is honest — a Frame or None"


def test_camera_absent_is_honest_none():
    # On a host without termux-camera-photo, capture_camera is an honest None and has_camera False.
    import shutil
    from sigil.platform.android import AndroidBackend
    if shutil.which("termux-camera-photo") is not None:
        return                                         # tool present on this host → nothing to assert
    b = AndroidBackend()
    assert b.capture_camera() is None, "no termux-camera-photo → honest None, never a fabricated frame"
    assert b.capabilities().has_camera is False, "has_camera tracks the real tool probe"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  ERROR {fn.__name__}: {e}")
            traceback.print_exc()
    print(f"{passed}/{len(fns)} Phase-9 W2-J (Android/Termux HostBackend) guarantees hold")
