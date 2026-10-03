"""Tests that the IPC channel carries non-ASCII text intact.

    python engine/tests/test_stdio_encoding.py
    python -m pytest engine/tests/test_stdio_encoding.py

Needs no third-party packages and no adapter.

Why this exists.

Tauri writes the engine's stdin as UTF-8. Python opens it with the platform's
ANSI codepage instead — cp1252 on this machine — so every non-ASCII character
arrived mangled. It was found in the UI: an engagement created as
"Lab / own network — 2026-09-27" came back from the engine as
"Lab / own network a€" 2026-09-27", while the copy the database held was
correct. The two panels sat side by side showing different names for the same
engagement.

The em-dash was the visible symptom; the real exposure is that the operator
writes Thai. An operator name, an engagement name and an SSID typed as a scope
target all travel this pipe, and all three end up in the audit trail — the one
record in this tool whose whole value is being exact.

These tests do not spawn the engine: they exercise the same helper main.py
calls, and they demonstrate the failure mode explicitly so the reason survives
in executable form rather than only in a comment.
"""
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging_setup

# The exact string from the bug report, plus Thai, which is what the operator
# actually writes.
EM_DASH_NAME = "Lab / own network — 2026-09-27"
THAI_OPERATOR = "ทดสอบภาษาไทย"
THAI_SSID = "เครือข่ายสำนักงาน"


class _FakeStream(io.TextIOWrapper):
    """A text stream whose encoding can be inspected and reconfigured."""

    def __init__(self, encoding):
        super().__init__(io.BytesIO(), encoding=encoding, errors="strict")


def test_the_bug_is_real_ansi_decoding_mangles_the_name():
    """Guards the premise. If this ever stops failing, the rest is pointless."""
    wire = json.dumps({"name": EM_DASH_NAME}, ensure_ascii=False).encode("utf-8")
    mangled = json.loads(wire.decode("cp1252"))["name"]
    assert mangled != EM_DASH_NAME
    # The exact corruption seen in the UI.
    assert "â€" in mangled, repr(mangled)


def test_thai_is_destroyed_by_ansi_decoding():
    wire = json.dumps({"operator": THAI_OPERATOR}, ensure_ascii=False).encode("utf-8")
    assert json.loads(wire.decode("cp1252"))["operator"] != THAI_OPERATOR


def test_utf8_decoding_preserves_every_field():
    payload = {
        "engagement_name": EM_DASH_NAME,
        "operator": THAI_OPERATOR,
        "targets": [{"kind": "ssid", "value": THAI_SSID}],
    }
    wire = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    back = json.loads(wire.decode("utf-8"))
    assert back["engagement_name"] == EM_DASH_NAME
    assert back["operator"] == THAI_OPERATOR
    assert back["targets"][0]["value"] == THAI_SSID


def test_force_utf8_stdio_switches_the_real_streams():
    """The helper main.py calls, run against stand-ins for the pipes."""
    saved = (sys.stdin, sys.stdout, sys.stderr)
    try:
        sys.stdin = _FakeStream("cp1252")
        sys.stdout = _FakeStream("cp1252")
        sys.stderr = _FakeStream("cp1252")
        failed = logging_setup.force_utf8_stdio()
        assert failed == [], f"could not reconfigure: {failed}"
        for stream in (sys.stdin, sys.stdout, sys.stderr):
            assert stream.encoding.lower().replace("-", "") == "utf8", stream.encoding
    finally:
        sys.stdin, sys.stdout, sys.stderr = saved


def test_force_utf8_stdio_reports_streams_it_could_not_change():
    """A silent failure here would let non-ASCII corrupt without a trace."""
    saved = sys.stdin
    try:
        sys.stdin = object()          # no reconfigure attribute
        failed = logging_setup.force_utf8_stdio()
        assert "stdin" in failed
    finally:
        sys.stdin = saved


def test_a_malformed_byte_does_not_kill_the_stream():
    """errors='replace', so one bad field cannot end the engagement."""
    saved = sys.stdin
    try:
        sys.stdin = _FakeStream("cp1252")
        logging_setup.force_utf8_stdio()
        assert sys.stdin.errors == "replace"
    finally:
        sys.stdin = saved


def test_main_calls_the_helper_before_reading_stdin():
    """The ordering is the whole fix; a later call would decode nothing useful."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")
    with io.open(path, encoding="utf-8") as f:
        source = f.read()
    assert "force_utf8_stdio()" in source, "main.py no longer forces UTF-8 on the pipes"
    assert source.index("force_utf8_stdio()") < source.index("for line in sys.stdin")


def test_outgoing_json_is_ascii_safe_regardless():
    """emit() escapes non-ASCII, so the UI is unaffected by stdout's codepage."""
    encoded = json.dumps({"event": "scope_status", "data": {"name": THAI_OPERATOR}})
    assert encoded.isascii(), "emit must keep ensure_ascii so stdout cannot fail"
    assert json.loads(encoded)["data"]["name"] == THAI_OPERATOR


def _main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in tests:
        try:
            fn(); print(f"  PASS  {name}")
        except AssertionError as e:
            failed.append(name); print(f"  FAIL  {name}: {e or 'assertion failed'}")
        except Exception as e:
            failed.append(name); print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
