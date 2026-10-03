"""Tests for the capability probe and wordlist path resolution.

    python engine/tests/test_capability_and_paths.py
    python -m pytest engine/tests/test_capability_and_paths.py

Why this exists.

**`capability.py`** is the module that decides what the operator is allowed to
trust. Its own docstring names the failure it exists to prevent: a capture that
finds no EAPOL because the adapter cannot enter monitor mode looks identical to
"the target resisted the attack". Two properties therefore have to hold no matter
what the hardware says, and only a test can hold them:

  * monitor mode is never reported as *supported*, because on Windows that
    cannot be established without switching the adapter; and
  * nothing reports itself ready as a constant. `wifi_scan.ready` was hardcoded
    `True`, so a machine with no wireless adapter — or with WLAN AutoConfig
    stopped — was told managed-mode scanning was available. A scan then returns
    an empty list, and an empty list reads as "no access points nearby".

**`wordlists_path.py`** is the only thing standing between the UI's wordlist
picker and the rest of the filesystem. `resolve_wordlist` is handed a name that
came from a client; it must not be possible to walk out of the wordlists
directory with it.

Nothing here touches the network, and the filesystem is only read.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import capability  # noqa: E402
import wordlists_path  # noqa: E402


# ── Wordlist path resolution ────────────────────────────────────────────────

def _resolved(name):
    path = wordlists_path.resolve_wordlist(name)
    return None if path is None else os.path.normpath(path)


def _inside_wordlists(path):
    """Containment against *every* directory a wordlist may live in.

    There are two now — the bundled one that ships with the build and a per-user
    one that uploads go to, because the bundled one is read-only on an installed
    copy. The invariant this guards is unchanged: a crafted name must land in one
    of them and nowhere else. Checking only the bundled directory would start
    passing a name that escaped into the user directory's parent.
    """
    bases = {os.path.normcase(os.path.normpath(d))
             for d in wordlists_path.wordlist_dirs()}
    target = os.path.normcase(os.path.normpath(path))
    return os.path.dirname(target) in bases


def test_a_bare_name_resolves_inside_the_wordlists_directory():
    path = _resolved("rockyou.txt")
    assert path is not None
    assert _inside_wordlists(path)
    assert os.path.basename(path) == "rockyou.txt"


def test_traversal_cannot_escape_the_wordlists_directory():
    for name in (
        "../../../../Windows/System32/config/SAM",
        r"..\..\..\..\Windows\win.ini",
        "../etc/passwd",
        "subdir/../../secret.txt",
        "....//....//secret.txt",
    ):
        path = _resolved(name)
        assert path is not None, name
        assert _inside_wordlists(path), f"{name} escaped to {path}"


def test_an_absolute_path_is_reduced_to_its_file_name():
    for name in (r"C:\Windows\win.ini", "/etc/passwd", r"\\server\share\list.txt"):
        path = _resolved(name)
        assert path is not None, name
        assert _inside_wordlists(path), f"{name} escaped to {path}"


def test_a_name_that_addresses_no_file_is_refused():
    for name in (None, "", "   ", ".", "..", "./", "../", "/", "\\"):
        assert wordlists_path.resolve_wordlist(name) is None, repr(name)


def test_a_trailing_separator_does_not_produce_a_directory():
    path = _resolved("common.txt/")
    assert path is not None
    assert os.path.basename(path) == "common.txt"


def test_uploads_do_not_go_to_the_install_directory():
    """The bundled directory is under %ProgramFiles% on an installed copy, so a
    write there needs elevation — the upload button did nothing for an ordinary
    operator. Uploads go to a per-user directory instead."""
    upload = wordlists_path.writable_wordlists_dir()
    bundled = wordlists_path.get_wordlists_dir()
    assert os.path.isabs(upload)
    assert os.path.normcase(upload) != os.path.normcase(bundled)


def test_a_bundled_list_is_still_readable_after_the_split():
    """Splitting the write target must not cost us the lists that ship."""
    names = {w["name"] for w in wordlists_path.list_wordlists()}
    assert "rockyou-wpa-optimized.txt" in names, sorted(names)
    assert any(w["origin"] == "bundled" for w in wordlists_path.list_wordlists())


def test_an_uploaded_list_takes_precedence_over_a_bundled_name():
    """Uploading a file is an instruction; preferring the shipped copy ignores it."""
    import tempfile
    real = wordlists_path.writable_wordlists_dir
    with tempfile.TemporaryDirectory() as d:
        wordlists_path.writable_wordlists_dir = lambda: d
        try:
            clash = "rockyou-wpa-optimized.txt"
            with open(os.path.join(d, clash), "w", encoding="utf-8") as f:
                f.write("mine")
            assert os.path.dirname(wordlists_path.resolve_wordlist(clash)) == d
            listed = {w["name"]: w for w in wordlists_path.list_wordlists()}
            assert listed[clash]["origin"] == "user"
            # and it is listed once, not twice
            names = [w["name"] for w in wordlists_path.list_wordlists()]
            assert names.count(clash) == 1
        finally:
            wordlists_path.writable_wordlists_dir = real


def test_a_name_that_exists_nowhere_still_reports_the_bundled_directory():
    """Callers put this path in "wordlist not found at ..."; it should name the
    directory an operator is most likely looking at."""
    path = wordlists_path.resolve_wordlist("definitely-not-present-12345.txt")
    assert os.path.dirname(path) == wordlists_path.get_wordlists_dir()


def test_the_directory_is_reported_even_when_it_does_not_exist():
    # Callers use the path in an error message ("wordlist not found at ..."), so
    # returning None here would replace a useful message with a confusing one.
    directory = wordlists_path.get_wordlists_dir()
    assert isinstance(directory, str) and directory
    assert os.path.isabs(directory)


def test_every_caller_gets_the_same_directory():
    # The whole reason this module exists: the UI's picker and the attack modules
    # must not be able to disagree about where the files are.
    assert wordlists_path.get_wordlists_dir() == wordlists_path.get_wordlists_dir()
    a = _resolved("x.txt")
    b = _resolved("x.txt")
    assert a == b


# ── Capability probe ────────────────────────────────────────────────────────

def test_monitor_mode_is_never_reported_as_supported():
    # `supported` may be False (Npcap missing — a fact) or None (undeterminable).
    # True would be a guess, and the whole module exists because of what that
    # guess costs.
    result = capability.check_monitor_mode()
    assert result.get("supported") in (False, None), result
    if result.get("supported") is None:
        assert result.get("determinable") is False
        assert result.get("note"), "an undeterminable answer has to explain itself"
    else:
        assert result.get("reason"), "a negative answer has to say what ruled it out"


def test_the_capability_probe_reports_every_feature_it_gates():
    report = capability.probe()
    assert set(report["features"]) == {
        "wifi_scan", "passive_sigint", "probe_monitor", "handshake_capture",
        "pmkid_capture", "strike_deauth", "mitm",
    }, sorted(report["features"])


def test_unavailable_features_agrees_with_the_feature_table():
    report = capability.probe()
    derived = sorted(name for name, f in report["features"].items() if not f["ready"])
    assert sorted(report["unavailable_features"]) == derived


def test_every_capture_feature_carries_the_null_result_warning():
    # A feature that can silently produce nothing must say so here, because this
    # text is what stops an empty capture being read as evidence of security.
    report = capability.probe()
    for name in ("probe_monitor", "handshake_capture", "pmkid_capture", "strike_deauth", "wifi_scan"):
        assert report["features"][name].get("caveat"), name


def test_wifi_scan_readiness_is_measured_not_assumed():
    fake = types.ModuleType("pywifi")

    class _PyWiFi:
        def interfaces(self):
            return []

    fake.PyWiFi = _PyWiFi
    original = sys.modules.get("pywifi")
    sys.modules["pywifi"] = fake
    try:
        result = capability.check_wifi_scan()
    finally:
        if original is None:
            del sys.modules["pywifi"]
        else:
            sys.modules["pywifi"] = original

    assert result["ready"] is False, "no adapter means no scan, whatever the constant said"
    assert "no wireless interface" in result["error"]
    assert "not the same as there being no access points" in result["hint"]


def test_an_unreadable_interface_list_is_not_ready_either():
    fake = types.ModuleType("pywifi")

    class _PyWiFi:
        def interfaces(self):
            raise OSError("the WLAN AutoConfig service is not running")

    fake.PyWiFi = _PyWiFi
    original = sys.modules.get("pywifi")
    sys.modules["pywifi"] = fake
    try:
        result = capability.check_wifi_scan()
    finally:
        if original is None:
            del sys.modules["pywifi"]
        else:
            sys.modules["pywifi"] = original

    assert result["ready"] is False
    assert "AutoConfig" in result["hint"]


def test_a_missing_pywifi_is_reported_with_a_fix_rather_than_a_crash():
    original = sys.modules.get("pywifi")
    sys.modules["pywifi"] = None  # import raises ImportError for a None entry
    try:
        result = capability.check_wifi_scan()
    finally:
        if original is None:
            del sys.modules["pywifi"]
        else:
            sys.modules["pywifi"] = original

    assert result["ready"] is False
    assert "pip install" in result["hint"]


def test_npcap_on_a_non_windows_platform_is_unknown_not_missing():
    original = capability.sys.platform
    capability.sys.platform = "linux"
    try:
        result = capability.check_npcap()
    finally:
        capability.sys.platform = original

    # False would assert that a Windows-only driver is absent on a platform
    # where the question does not apply.
    assert result["available"] is None
    assert result.get("note")


def test_is_admin_never_raises():
    assert capability.is_admin() in (True, False)


def test_the_probe_is_json_serialisable():
    # It crosses the IPC boundary as JSON. A value that cannot be encoded would
    # take the whole capability response down with it.
    import json
    json.dumps(capability.probe())


# -- The raw-socket probe used to answer about the wrong adapter -------------

"""
`check_raw_socket()` took no interface, so `conf.L2socket()` bound `conf.iface` --
whatever carries the default route, typically the Ethernet port on a docked rig.
Its verdict then drove `ready` for passive_sigint, probe_monitor,
handshake_capture, pmkid_capture, strike_deauth and mitm, all of which sniff the
operator-selected adapter instead (`offensive/capture.py` passes `iface=interface`).

With the capture dongle unplugged, or bound to the wrong driver, while Npcap worked
on Ethernet, the probe reported every one of those features `ready: true`. What that
costs is written in this module's own caveats: "Without monitor mode a capture
returns no EAPOL. That is NOT evidence the target is secure." The gate that exists
to say so in advance was answering about a different adapter.
"""


class _FakeL2Socket:
    """Records the interface it was constructed for."""

    opened = []

    def __init__(self, iface=None):
        type(self).opened.append(iface)
        if iface == "NO-SUCH-ADAPTER":
            raise OSError("failed to set hardware filter to promiscuous mode")

    def close(self):
        pass


def _probe_with_fake_socket(interface):
    """
    `check_raw_socket(interface)` against a stand-in L2 socket.

    Only `conf.L2socket` is swapped. `conf.iface` is left alone and read back,
    because scapy validates an assignment to it against the real adapters on the
    machine and refuses an invented name.
    """
    import scapy.all as scapy_all
    original_cls = scapy_all.conf.L2socket
    _FakeL2Socket.opened = []
    scapy_all.conf.L2socket = _FakeL2Socket
    try:
        return (capability.check_raw_socket(interface),
                list(_FakeL2Socket.opened),
                str(scapy_all.conf.iface))
    finally:
        scapy_all.conf.L2socket = original_cls


def test_the_raw_socket_test_binds_the_interface_it_was_given():
    # The defect in one assertion: the adapter asked about must be the adapter
    # opened, not whatever scapy defaults to.
    _, opened, _default = _probe_with_fake_socket("Wi-Fi 2 (capture dongle)")
    assert opened == ["Wi-Fi 2 (capture dongle)"], opened


def test_a_failure_on_the_chosen_adapter_is_not_ready():
    result, _, _default = _probe_with_fake_socket("NO-SUCH-ADAPTER")
    assert result["available"] is False
    assert result["error"]


def test_the_result_names_the_adapter_it_is_about():
    # A `ready` with nothing attributing it is how this hid for so long.
    result, _, _default = _probe_with_fake_socket("Wi-Fi 2 (capture dongle)")
    assert result["probed_interface"] == "Wi-Fi 2 (capture dongle)"


def test_a_failure_still_names_the_adapter():
    result, _, _default = _probe_with_fake_socket("NO-SUCH-ADAPTER")
    assert result["probed_interface"] == "NO-SUCH-ADAPTER"
    assert "NO-SUCH-ADAPTER" in result["hint"]


def test_with_no_adapter_named_the_default_is_reported_rather_than_implied():
    result, opened, default_iface = _probe_with_fake_socket(None)
    # Opened with no interface, i.e. scapy's default -- and the result says which
    # adapter that was, rather than leaving a bare `ready` to be read as being
    # about the capture dongle.
    assert opened == [None], opened
    assert result["probed_interface"] == default_iface


def test_the_probe_carries_the_capture_interface_through_to_the_report():
    # So the UI and the report can say which adapter the gates are about.
    report = capability.probe("Wi-Fi 2 (capture dongle)")
    assert report["capture_interface_requested"] == "Wi-Fi 2 (capture dongle)"
    assert "capture_interface" in report


def test_a_registered_but_stopped_npcap_service_is_not_available():
    """
    `available` was `bool(found_files) or service_present`, where
    `service_present` means only that `sc query npcap` exited 0 -- true for a
    service that is installed and stopped. `service_state` was parsed one line
    above and read by nothing.
    """
    import subprocess as _sp

    class _Result:
        returncode = 0
        stdout = "SERVICE_NAME: npcap\n        STATE              : 1  STOPPED\n"

    original_run = capability.subprocess.run
    original_exists = capability.os.path.exists
    capability.subprocess.run = lambda *a, **k: _Result()
    capability.os.path.exists = lambda p: False   # no driver files either
    try:
        if capability.sys.platform != "win32":
            return  # the function reports platform-not-applicable off Windows
        out = capability.check_npcap()
    finally:
        capability.subprocess.run = original_run
        capability.os.path.exists = original_exists

    assert out["service_present"] is True
    assert out["service_running"] is False
    assert out["available"] is False, "a stopped service was reported as available"
    assert out.get("note"), "the stopped state has to be stated"
    del _sp


def _main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed.append(name)
            print(f"  FAIL  {name}: {e or 'assertion failed'}")
        except Exception as e:
            failed.append(name)
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
