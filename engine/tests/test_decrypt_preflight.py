"""
The three ways a crack is refused before hashcat is ever launched.

Why this file exists.

`test_decrypt_claims.py` covers what counts as a recovered passphrase — the
PMKID read and the outfile parse. It does not cover the refusals, and the
refusals are the more dangerous half.

A crack that could not start, reported as a crack that found nothing, is
indistinguishable from "the passphrase held". That sentence in a report is the
one that gets somebody to stop worrying about a network they should worry about.
The operator has to be told the difference between "we tried and failed" and "we
never tried", and the `reason` codes below are how the UI tells them apart — so
they are asserted by name, not by shape.

These were inline steps inside a 422-line `_run` whose middle is subprocess
orchestration; nothing could reach them.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from offensive import decryptor  # noqa: E402
from offensive.decryptor import (  # noqa: E402
    check_capture_file,
    check_hashcat,
    check_wordlist,
)


# ── The capture file ─────────────────────────────────────────────────────────

def test_a_missing_capture_is_refused_by_name():
    refusal = check_capture_file(r"C:\nope\missing.pcap")
    assert refusal["reason"] == "pcap_missing"
    assert "missing.pcap" in refusal["message"], "the operator needs to see which path was tried"


def test_no_capture_at_all_is_refused_rather_than_crashing():
    for value in (None, "", "   "):
        refusal = check_capture_file(value)
        assert refusal is not None, repr(value)
        assert refusal["reason"] == "pcap_missing"


def test_a_directory_is_not_a_capture_file():
    with tempfile.TemporaryDirectory() as d:
        refusal = check_capture_file(d)
        assert refusal["reason"] == "pcap_missing"


def test_a_readable_capture_passes():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
        fh.write(b"\xd4\xc3\xb2\xa1")
        path = fh.name
    try:
        assert check_capture_file(path) is None
    finally:
        os.unlink(path)


def test_an_empty_capture_file_still_passes_this_check():
    # Emptiness is the exporter's finding to make ("no usable EAPOL pair or
    # PMKID"), not this one's. Refusing here would report a readable file as
    # unreadable and send the operator looking at permissions.
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
        path = fh.name
    try:
        assert check_capture_file(path) is None
    finally:
        os.unlink(path)


def test_an_unreadable_capture_is_distinguished_from_a_missing_one():
    # Two different problems with two different answers: one is the wrong path,
    # the other is permissions or a lock. They must not collapse into one code.
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
        fh.write(b"x")
        path = fh.name

    # `open` is the builtin here, not a module attribute, so it is patched where
    # the lookup actually happens. Windows will not reliably deny the owner a read
    # through permissions, which is why this is not done with chmod.
    import builtins
    real_open = builtins.open

    def deny(target, *a, **k):
        if target == path:
            raise OSError(13, "Permission denied")
        return real_open(target, *a, **k)

    builtins.open = deny
    try:
        refusal = check_capture_file(path)
    finally:
        builtins.open = real_open
        os.unlink(path)
    assert refusal["reason"] == "pcap_unreadable"
    assert "Permission denied" in refusal["message"]


# ── hashcat ──────────────────────────────────────────────────────────────────

def test_a_missing_hashcat_is_refused_and_says_where_it_looked():
    """
    The refusal carries the searched paths.

    hashcat is not an optional accelerator here, it is the tool for this job.
    "hashcat not found" with no list of locations leaves the operator guessing
    where to put it, and this is the check that is failing on this machine right
    now — so the message is the whole interface.
    """
    real = decryptor.detect_hashcat
    decryptor.detect_hashcat = lambda: {"installed": False}
    try:
        refusal, binary, version = check_hashcat()
        assert refusal["reason"] == "hashcat_missing"
        assert binary is None and version is None
        assert refusal["searched"], "a refusal with no searched paths cannot be acted on"
        assert all(isinstance(p, str) for p in refusal["searched"])
        for p in refusal["searched"]:
            assert p in refusal["message"], f"{p} is searched but not named in the message"
    finally:
        decryptor.detect_hashcat = real


def test_an_installed_hashcat_yields_its_path_and_version():
    real = decryptor.detect_hashcat
    decryptor.detect_hashcat = lambda: {"installed": True, "path": "C:/hashcat/hashcat.exe", "version": " v6.2.6 "}
    try:
        refusal, binary, version = check_hashcat()
        assert refusal is None
        assert binary == "C:/hashcat/hashcat.exe"
        assert version == "v6.2.6", "the version is stamped into the run record; it must be trimmed"
    finally:
        decryptor.detect_hashcat = real


def test_an_installed_hashcat_with_no_path_falls_back_to_the_bare_name():
    # Installed but resolved through PATH rather than a known location.
    real = decryptor.detect_hashcat
    decryptor.detect_hashcat = lambda: {"installed": True}
    try:
        refusal, binary, version = check_hashcat()
        assert refusal is None
        assert binary == "hashcat"
        assert version == ""
    finally:
        decryptor.detect_hashcat = real


# ── The wordlist ─────────────────────────────────────────────────────────────

def test_a_missing_wordlist_is_refused_and_names_where_it_looked():
    real_resolve = decryptor.resolve_wordlist
    real_dir = decryptor.get_wordlists_dir
    decryptor.resolve_wordlist = lambda name: None
    decryptor.get_wordlists_dir = lambda: r"C:\wordlists"
    try:
        refusal, path = check_wordlist("rockyou.txt")
        assert refusal["reason"] == "wordlist_missing"
        assert path is None
        assert "rockyou.txt" in refusal["message"]
        assert r"C:\wordlists" in refusal["message"]
    finally:
        decryptor.resolve_wordlist = real_resolve
        decryptor.get_wordlists_dir = real_dir


def test_a_broken_resolver_is_a_different_failure_from_a_missing_file():
    """
    A packaging fault and an operator fault need different answers.

    `wordlist_module_missing` means this build cannot resolve wordlists at all —
    which is what a mis-specified PyInstaller bundle looks like. Reporting that as
    `wordlist_missing` sent somebody looking for a file when the build was wrong.
    """
    real = decryptor.resolve_wordlist
    decryptor.resolve_wordlist = None
    try:
        refusal, path = check_wordlist("rockyou.txt")
        assert refusal["reason"] == "wordlist_module_missing"
        assert path is None
    finally:
        decryptor.resolve_wordlist = real


def test_a_wordlist_directory_that_raises_does_not_take_the_refusal_down():
    # The refusal is the important part; losing it because the "where we looked"
    # lookup failed would turn a clear message into an exception.
    real_resolve = decryptor.resolve_wordlist
    real_dir = decryptor.get_wordlists_dir

    def boom():
        raise RuntimeError("no bundle dir")

    decryptor.resolve_wordlist = lambda name: None
    decryptor.get_wordlists_dir = boom
    try:
        refusal, path = check_wordlist("rockyou.txt")
        assert refusal["reason"] == "wordlist_missing"
        assert "looked in" not in refusal["message"]
    finally:
        decryptor.resolve_wordlist = real_resolve
        decryptor.get_wordlists_dir = real_dir


def test_a_resolved_wordlist_that_exists_passes_with_its_path():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as fh:
        fh.write(b"password\n")
        path = fh.name
    real = decryptor.resolve_wordlist
    decryptor.resolve_wordlist = lambda name: path
    try:
        refusal, resolved = check_wordlist("mine.txt")
        assert refusal is None
        assert resolved == path
    finally:
        decryptor.resolve_wordlist = real
        os.unlink(path)


def test_a_resolver_that_points_at_nothing_is_still_a_missing_wordlist():
    # A stale index or a deleted file: the resolver answers, the file is gone.
    real = decryptor.resolve_wordlist
    decryptor.resolve_wordlist = lambda name: r"C:\nope\gone.txt"
    try:
        refusal, path = check_wordlist("gone.txt")
        assert refusal["reason"] == "wordlist_missing"
        assert path is None
    finally:
        decryptor.resolve_wordlist = real


# ── The refusals as a set ────────────────────────────────────────────────────

def test_every_refusal_carries_a_reason_and_a_message():
    # The UI switches on `reason` and shows `message`. A refusal missing either is
    # a silent failure in the module whose failures matter most.
    real_hc = decryptor.detect_hashcat
    real_wl = decryptor.resolve_wordlist
    decryptor.detect_hashcat = lambda: {"installed": False}
    decryptor.resolve_wordlist = lambda name: None
    try:
        refusals = [
            check_capture_file(None),
            check_capture_file(r"C:\nope\x.pcap"),
            check_hashcat()[0],
            check_wordlist("x.txt")[0],
        ]
    finally:
        decryptor.detect_hashcat = real_hc
        decryptor.resolve_wordlist = real_wl

    for refusal in refusals:
        assert refusal is not None
        assert isinstance(refusal.get("reason"), str) and refusal["reason"]
        assert isinstance(refusal.get("message"), str) and len(refusal["message"]) > 10


def test_the_reason_codes_are_all_distinct():
    # Two paths sharing a code cannot be told apart by the UI, which is the only
    # reason the codes exist.
    real_hc = decryptor.detect_hashcat
    real_wl = decryptor.resolve_wordlist
    decryptor.detect_hashcat = lambda: {"installed": False}
    decryptor.resolve_wordlist = None
    try:
        codes = {
            check_capture_file(r"C:\nope\x.pcap")["reason"],
            check_hashcat()[0]["reason"],
            check_wordlist("x.txt")[0]["reason"],
        }
    finally:
        decryptor.detect_hashcat = real_hc
        decryptor.resolve_wordlist = real_wl
    assert codes == {"pcap_missing", "hashcat_missing", "wordlist_module_missing"}


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
