"""Tests that the engine can say which build it is.

    python engine/tests/test_build_stamp.py
    python -m pytest engine/tests/test_build_stamp.py

Why this exists.

The engine reported `version: "0.1.0"` in its `ready` event, a string literal
that has never changed, and the frontend store's `engineVersion` field was
declared and never written. So there was no way — from the UI, from the log, or
from an exported report's provenance — to tell a sidecar compiled days ago from
one compiled a minute ago.

That cost a real debugging session. A `UnicodeDecodeError: 'charmap' codec can't
decode byte 0x90` was arriving from the field every half-minute. Every
`subprocess` call in the source already passed `encoding="utf-8"`; the traceback
had no engine frames in it at all, because the failure is inside
`communicate()`'s own reader thread; and `grep` across the engine found nothing
wrong. The code was correct. The `.exe` was two days old and predated the fix,
and nothing anywhere said so.

The properties these tests hold are the ones that make the stamp worth having:
it is never a guess, it always survives JSON, and a frozen build reports the
time it was *built* rather than the time it was run.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import build_stamp  # noqa: E402


def test_the_stamp_reports_every_field_the_ui_reads():
    stamp = build_stamp.describe()
    assert set(stamp) == {
        "version", "frozen", "built_at", "git_describe", "python", "bundle_dir",
    }, sorted(stamp)


def test_a_source_run_says_it_is_a_source_run():
    # `frozen` is what tells the operator whether "rebuild the sidecar" is even
    # the right advice.
    stamp = build_stamp.describe()
    assert stamp["frozen"] is False
    assert stamp["bundle_dir"] is None


def test_a_source_run_reports_when_the_code_last_changed():
    # The closest honest answer to "what is running" when there is no build.
    stamp = build_stamp.describe()
    assert isinstance(stamp["built_at"], str)
    # ISO 8601 with an offset, so it can be compared against a build time.
    assert stamp["built_at"][4] == "-" and "T" in stamp["built_at"]


def test_the_source_timestamp_follows_the_newest_engine_file():
    import time
    from datetime import datetime

    before = build_stamp.describe()["built_at"]
    marker = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "_stamp_probe.py")
    try:
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write("# temporary file written by test_build_stamp\n")
        future = time.time() + 3600
        os.utime(marker, (future, future))
        after = build_stamp.describe()["built_at"]
    finally:
        if os.path.exists(marker):
            os.remove(marker)

    assert datetime.fromisoformat(after) > datetime.fromisoformat(before), (before, after)


def test_the_stamp_never_guesses_a_revision():
    # None is the answer when git cannot say. A fabricated revision in an
    # exported report's provenance is worse than an absent one: the whole point
    # of recording it is that someone can go and check it.
    stamp = build_stamp.describe()
    assert stamp["git_describe"] is None or isinstance(stamp["git_describe"], str)
    if isinstance(stamp["git_describe"], str):
        assert stamp["git_describe"].strip() == stamp["git_describe"]
        assert stamp["git_describe"] != ""


def test_a_frozen_build_reports_the_recorded_build_time_not_the_run_time():
    """The property the whole mechanism exists for.

    A frozen build must report when it was *compiled*. If it fell back to a
    live filesystem scan it would describe the source tree it happens to be
    sitting next to, which is exactly the confusion this replaces — and on an
    installed copy there is no source tree at all.
    """
    original_frozen = getattr(sys, "frozen", None)
    original_built = build_stamp._BUILT_AT
    original_git = build_stamp._GIT_DESCRIBE
    sys.frozen = True
    build_stamp._BUILT_AT = "2026-09-27T11:46:00+00:00"
    build_stamp._GIT_DESCRIBE = "f724d99"
    try:
        stamp = build_stamp.describe()
    finally:
        if original_frozen is None:
            del sys.frozen
        else:
            sys.frozen = original_frozen
        build_stamp._BUILT_AT = original_built
        build_stamp._GIT_DESCRIBE = original_git

    assert stamp["frozen"] is True
    assert stamp["built_at"] == "2026-09-27T11:46:00+00:00"
    assert stamp["git_describe"] == "f724d99"


def test_a_frozen_build_with_no_stamp_says_unknown_rather_than_inventing_one():
    # A sidecar built before the stamp existed. "Unknown" is the honest answer
    # and the UI prints it as BUILD UNKNOWN; a filesystem scan here would have
    # invented a plausible-looking time.
    original_frozen = getattr(sys, "frozen", None)
    original_built = build_stamp._BUILT_AT
    sys.frozen = True
    build_stamp._BUILT_AT = None
    try:
        stamp = build_stamp.describe()
    finally:
        if original_frozen is None:
            del sys.frozen
        else:
            sys.frozen = original_frozen
        build_stamp._BUILT_AT = original_built

    assert stamp["built_at"] is None


def test_the_stamp_survives_the_ipc_channel():
    # It travels inside the `ready` event. A value that cannot be encoded would
    # take the whole handshake down with it, and the app would never connect.
    #
    # The same dict is encoded and decoded rather than calling describe() twice:
    # `built_at` comes from the filesystem and a file touched between two calls
    # would make the comparison flap.
    stamp = build_stamp.describe()
    assert json.loads(json.dumps(stamp)) == stamp
    for key, value in stamp.items():
        assert value is None or isinstance(value, (str, bool)), (key, type(value))


def test_describing_the_build_never_raises():
    # Called from `main()` before `ready` is emitted. An exception here means
    # the app never connects, which is a far worse failure than a missing stamp.
    for attr, value in (("_BUILT_AT", None), ("_GIT_DESCRIBE", None)):
        original = getattr(build_stamp, attr)
        setattr(build_stamp, attr, value)
        try:
            build_stamp.describe()
        finally:
            setattr(build_stamp, attr, original)


def test_git_describe_returns_none_rather_than_raising_when_git_is_absent():
    import subprocess
    original = subprocess.run

    def missing(*a, **k):
        raise FileNotFoundError("git")

    subprocess.run = missing
    try:
        assert build_stamp._git_describe_live() is None
    finally:
        subprocess.run = original


def test_a_failed_git_call_is_not_treated_as_a_revision():
    import subprocess
    original = subprocess.run

    class _Result:
        returncode = 128
        stdout = "fatal: not a git repository\n"

    subprocess.run = lambda *a, **k: _Result()
    try:
        assert build_stamp._git_describe_live() is None
    finally:
        subprocess.run = original


# ── The identity that reaches the report's method appendix ───────────────────

def test_the_methodology_reports_a_build_identity_not_a_bare_version():
    """
    `get_methodology` answered a hardcoded "0.1.0", which names every build ever
    made.

    The report prefers whatever the engine reports over its own fallback, so the
    build stamp added for exactly this purpose was shadowed in the normal case —
    the engine being reachable — and the method appendix printed "0.1.0" for a
    sidecar compiled days apart from the one that produced the findings. A
    severity traced to a rule set is auditable only if the software that applied
    it can be named.
    """
    import build_stamp

    stamp = build_stamp.describe()
    identity = " · ".join(part for part in (
        stamp.get("version"),
        stamp.get("git_describe"),
        f"built {stamp['built_at']}" if stamp.get("built_at") else None,
        None if stamp.get("frozen") else "from source",
    ) if part)

    assert identity != stamp.get("version"), "the identity must say more than the version"
    assert stamp["version"] in identity
    assert "built " in identity, "the build time is what distinguishes two builds of one version"


def test_a_source_run_says_so_and_a_frozen_one_does_not():
    # "from source" in a report means the findings came from a working tree, not
    # from the sidecar that ships. That is a provenance claim worth making.
    import build_stamp

    stamp = dict(build_stamp.describe())
    for frozen, expected in ((False, True), (True, False)):
        stamp["frozen"] = frozen
        identity = " · ".join(part for part in (
            stamp.get("version"), stamp.get("git_describe"),
            f"built {stamp['built_at']}" if stamp.get("built_at") else None,
            None if stamp.get("frozen") else "from source",
        ) if part)
        assert ("from source" in identity) is expected


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
