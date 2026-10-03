"""
Four checks that reported a finished measurement after measuring nothing.

    python engine/tests/test_incomplete_claims.py
    python -m pytest engine/tests/test_incomplete_claims.py

Why these exist.

Each of these produced an empty result that a reader cannot tell from a clean one.
That is the specific failure this project cares most about: the report's own
`coverage_note` promises that absence is not evidence, and these four quietly broke
that promise in four different sections.

1. **Null-session share enumeration emitted `shares: []`.** The SMB2 exchange in
   `_enumerate_shares` cannot succeed -- the SESSION_SETUP fixed body is 12 bytes
   where the structure is 24, the response carrying the `SessionId` is discarded, and
   TREE_CONNECT is sent with `PathOffset = 0` instead of 72 -- so `accessible` was
   always empty. `shares` was not in the `inconclusive` list either, which named only
   `smbv1_enabled` and `signing_required`. A host with a wide-open null-session share
   was reported as having none, with no caveat. It now returns None until a probe
   reads an NT status, and None joins `inconclusive`.

2. **`bruteforce_exhausted` was emitted when nothing had been judged.**
   `CredentialResult` exists to separate INVALID from UNREACHABLE, and the attack loop
   read `.success` and `.unsupported` and never `.unreachable`. An SSH server with
   fail2ban drops the connection after a handful of failures, so every remaining word
   came back UNREACHABLE -- and a 10,000-word run that tested six credentials reported
   the wordlist exhausted. `sprayer.py` already counted unreachable into
   `never_judged`, which is what makes this a bug and not a difference of opinion.

3. **`dirbuster_completed {complete: True}` for a host that never answered.** Every
   `URLError` was swallowed by a bare `pass`, so a closed or filtered port produced
   4,000 silent failures and then the event that licenses "these paths are not on this
   server".

4. **A concrete CPE version became an unbounded claim over its whole line.**
   `_keys_for_match` returned `(version, None)`, `cve_db._version_match` matches a key
   as a line prefix, and `_is_fixed` treats an absent `fixed_in` as never fixed -- so a
   refresh carrying `cpe:2.3:a:apache:http_server:2.0:*` asserted every 2.0.x host
   vulnerable, including 2.0.65, the final patched release.

No network and no SMB server: the probes are replaced.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cve_feed  # noqa: E402
from scanner import cve_db  # noqa: E402
from offensive.bruteforce import BruteForcer, CredentialResult  # noqa: E402
from scanner.smb_enum import SMBEnumerator  # noqa: E402


class _Ipc:
    def __init__(self):
        self.events = []

    def emit(self, name, payload=None):
        self.events.append((name, payload or {}))

    def named(self, name):
        return [p for n, p in self.events if n == name]

    @property
    def names(self):
        return [n for n, _ in self.events]


# ── 1. Share enumeration ────────────────────────────────────────────────────

def _smb_result(share_answer):
    """
    `smb_enum_completed` for a host whose share probe returns `share_answer`.

    The SMBv1 and signing probes are stubbed to None, which is their own
    already-correct "could not answer" value, so this isolates `shares`.
    """
    enum = SMBEnumerator(_Ipc().emit)
    ipc = _Ipc()
    enum.emit = ipc.emit
    enum._check_smbv1 = lambda *a, **k: (None, None)
    enum._get_ntlm_info = lambda *a, **k: None
    enum._check_smb_signing = lambda *a, **k: None
    enum._enumerate_shares = lambda *a, **k: (share_answer, None)
    enum._run_enum("10.0.0.5", 445)
    return ipc.named("smb_enum_completed")[0]


def test_an_enumeration_that_never_answered_is_inconclusive():
    # The defect: this used to arrive as `shares: []`, which reads as a host with
    # nothing exposed.
    result = _smb_result(None)
    assert result["shares"] is None
    assert "shares" in result["inconclusive"], result["inconclusive"]


def test_a_host_that_genuinely_exposes_nothing_is_not_inconclusive():
    # The distinction has to cut both ways, or the caveat becomes noise.
    result = _smb_result([])
    assert result["shares"] == []
    assert "shares" not in result["inconclusive"]


def test_shares_that_were_found_are_reported_and_not_caveated():
    found = [{"name": "Public", "access": "OPEN"}]
    result = _smb_result(found)
    assert result["shares"] == found
    assert "shares" not in result["inconclusive"]


def test_the_other_two_checks_keep_their_own_inconclusive_handling():
    result = _smb_result(None)
    assert "smbv1_enabled" in result["inconclusive"]
    assert "signing_required" in result["inconclusive"]


# ── 2. Brute force ──────────────────────────────────────────────────────────

def test_the_result_type_still_separates_a_rejection_from_a_silence():
    # The property the fix leans on. If these collapse, the counting below is
    # meaningless.
    assert CredentialResult(CredentialResult.INVALID).unreachable is False
    assert CredentialResult(CredentialResult.UNREACHABLE).unreachable is True
    assert bool(CredentialResult(CredentialResult.UNREACHABLE)) is False
    assert bool(CredentialResult(CredentialResult.SUCCESS)) is True


def test_the_give_up_threshold_is_above_the_common_lockout_limits():
    """
    fail2ban bans after 5 failures by default and OpenSSH's MaxAuthTries is 6.

    A threshold at or below those would abort ordinary runs; the point is to catch
    a host that has stopped judging at all.
    """
    assert BruteForcer.UNREACHABLE_GIVE_UP > 6


def test_the_loop_reads_unreachable_at_all():
    """
    Reads the module source, because driving `_attack_loop` needs a live socket.

    `.unreachable` was defined on `CredentialResult` and referenced nowhere in this
    module, which is the entire defect; a test that cannot see that regression
    return is not worth having.
    """
    import inspect
    import offensive.bruteforce as module

    src = inspect.getsource(module)
    assert "result.unreachable" in src, \
        "the attack loop no longer consults .unreachable"
    assert "bruteforce_aborted" in src, \
        "the give-up path is gone, so a silent host runs to the end of the wordlist"
    assert '"judged"' in src and '"unreachable"' in src, \
        "the terminal event no longer carries its denominator"


# ── 3. Dirbuster ────────────────────────────────────────────────────────────

def test_a_scan_where_nothing_answered_is_not_complete():
    """
    Built by calling `_monitor` with the tallies set, so no HTTP is needed.

    `complete` is the field that licenses "a path's absence means it is not on this
    server". With every request raising URLError it was still True.
    """
    from offensive.dirbuster import DirBuster

    ipc = _Ipc()
    db = DirBuster(ipc.emit)
    db._running = True
    db._base_url = "http://10.0.0.5:80"
    db._answered = 0
    db._no_response = 4000
    db._last_error = "[Errno 111] Connection refused"
    db._monitor()

    event = ipc.named("dirbuster_completed")[0]
    assert event["complete"] is False
    assert event["paths_answered"] == 0
    assert event["caveat"], "a scan that tested nothing has to say so"


def test_a_scan_the_server_answered_is_complete():
    from offensive.dirbuster import DirBuster

    ipc = _Ipc()
    db = DirBuster(ipc.emit)
    db._running = True
    db._base_url = "http://10.0.0.5:80"
    db._answered = 4000
    db._no_response = 0
    db._monitor()

    event = ipc.named("dirbuster_completed")[0]
    assert event["complete"] is True
    assert event["caveat"] is None


def test_a_partly_answered_scan_is_complete_but_caveated():
    # The server was there and talking, so the results mean something -- and the
    # requests that got no answer still have to be named.
    from offensive.dirbuster import DirBuster

    ipc = _Ipc()
    db = DirBuster(ipc.emit)
    db._running = True
    db._base_url = "http://10.0.0.5:80"
    db._answered = 3900
    db._no_response = 100
    db._last_error = "timed out"
    db._monitor()

    event = ipc.named("dirbuster_completed")[0]
    assert event["complete"] is True
    assert "100 of 4000" in event["caveat"]


# ── 4. CVE version keys ─────────────────────────────────────────────────────

import contextlib  # noqa: E402


@contextlib.contextmanager
def _matrix(table):
    """`lookup_cves` reads the matrix through `active_matrix()`; swap it for one."""
    original = cve_db.active_matrix
    cve_db.active_matrix = lambda: table
    try:
        yield
    finally:
        cve_db.active_matrix = original


def test_a_concrete_cpe_version_is_marked_exact():
    keys = cve_feed._keys_for_match("2.0", {})
    assert keys == [("2.0", None, True)], keys


def test_a_range_derived_key_is_not_marked_exact():
    keys = cve_feed._keys_for_match("*", {"versionStartIncluding": "2.4.0",
                                          "versionEndExcluding": "2.4.52"})
    assert keys and keys[0][2] is False, keys


def test_an_exact_entry_does_not_claim_the_rest_of_its_line():
    """
    The defect. `cpe:2.3:a:apache:http_server:2.0:*` keyed `2.0` with no `fixed_in`,
    `_version_match` matched `2.0.65` as a line prefix, and `_is_fixed` returns False
    with no `fixed_in` -- so the final patched release of the 2.0 line was asserted
    vulnerable at NVD's severity.
    """
    matrix = {"apache": {"2.0": [{"cve": "CVE-TEST-0001", "severity": "CRITICAL",
                                 "description": "d", "exact_version": True}]}}
    with _matrix(matrix):
        exact = cve_db.lookup_cves("apache", "2.0")
        assert exact, "the exact version itself must still match"
        later = cve_db.lookup_cves("apache", "2.0.65")
        assert later == [], "a patched release in the same line was reported vulnerable"


def test_a_line_entry_still_covers_its_line():
    # The fix must not turn every key into an exact match, or the matrix stops
    # working for the range-derived entries that are most of it.
    matrix = {"apache": {"2.4": [{"cve": "CVE-TEST-0002", "severity": "HIGH",
                                 "description": "d"}]}}
    with _matrix(matrix):
        assert cve_db.lookup_cves("apache", "2.4.49")


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
