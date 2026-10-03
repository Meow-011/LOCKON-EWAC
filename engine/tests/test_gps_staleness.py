"""Tests that a dead GPS receiver stops producing coordinates.

    python engine/tests/test_gps_staleness.py
    python -m pytest engine/tests/test_gps_staleness.py

Why this exists.

`get_position()` returned `self.last_fix` unconditionally and nothing ever aged
it out. When a receiver was unplugged or lost power mid-drive:

  * `is_connected()` kept returning True. It checks that the serial handle is
    open, and that stays open after the hardware goes away.
  * `get_position()` kept handing back the last coordinate the receiver managed
    to send.
  * `_validate_gps`, the outlier filter, saw two identical positions — zero
    distance over any interval, so zero implied speed — and accepted them.
    Rejecting a jump is what it is for; a frozen position is the one thing it
    cannot catch.

So every access point found for the remainder of the drive was recorded at the
spot where the GPS died, the map drew them stacked there, the report printed
those coordinates with error radii derived from them, and the GPS indicator
stayed green throughout.

`timestamp` was already written onto every fix. It was simply never read.

These tests drive `GPSReader` directly with planted fixes, so they need no
serial port and no hardware.
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gps.reader import GPSReader, STALE_FIX_SECONDS  # noqa: E402


def _reader(fix=None):
    """A reader with a planted fix and no serial port."""
    r = GPSReader.__new__(GPSReader)
    r.last_fix = fix
    return r


def _fix(age_seconds=0.0, **over):
    stamped = datetime.now() - timedelta(seconds=age_seconds)
    return {
        "latitude": 13.7563,
        "longitude": 100.5018,
        "hdop": 1.2,
        "satellites": 9,
        "timestamp": stamped.isoformat(),
        **over,
    }


# ── A fresh fix is usable ──────────────────────────────────────────────────

def test_a_fresh_fix_is_returned():
    r = _reader(_fix(age_seconds=0.5))
    pos = r.get_position()
    assert pos is not None
    assert pos["latitude"] == 13.7563
    assert r.has_fix() is True
    assert r.is_stale() is False


def test_a_fix_just_inside_the_window_is_still_usable():
    r = _reader(_fix(age_seconds=STALE_FIX_SECONDS - 1.0))
    assert r.get_position() is not None
    assert r.is_stale() is False


# ── A stale fix is not a fix ───────────────────────────────────────────────

def test_a_fix_past_the_window_is_withheld():
    # The regression. This is the state a receiver is in for the rest of a drive
    # after it is unplugged.
    r = _reader(_fix(age_seconds=STALE_FIX_SECONDS + 5))
    assert r.get_position() is None
    assert r.is_stale() is True


def test_has_fix_agrees_with_get_position():
    # A caller that checks has_fix() and then reads get_position() must not be
    # told yes and handed None.
    for age in (0.0, STALE_FIX_SECONDS - 0.5, STALE_FIX_SECONDS + 30):
        r = _reader(_fix(age_seconds=age))
        assert r.has_fix() == (r.get_position() is not None), f"disagreed at age {age}"


def test_an_hour_old_fix_is_never_offered():
    # The concrete scenario: the receiver died an hour ago and the drive
    # continued. Every AP found since then must carry no position rather than
    # this one.
    r = _reader(_fix(age_seconds=3600))
    assert r.get_position() is None
    assert round(r.fix_age_seconds()) >= 3599


# ── Absence and unusable timestamps fail toward "no position" ──────────────

def test_no_fix_at_all():
    r = _reader(None)
    assert r.get_position() is None
    assert r.has_fix() is False
    assert r.is_stale() is False, "never having had a fix is not staleness"
    assert r.fix_age_seconds() == float("inf")


def test_an_empty_fix_dict_is_not_a_fix():
    r = _reader({})
    assert r.get_position() is None
    assert r.has_fix() is False


def test_a_fix_with_no_timestamp_is_treated_as_infinitely_old():
    # Failing this way costs a coordinate. Failing the other way writes a wrong
    # one into the archive.
    r = _reader({"latitude": 13.7, "longitude": 100.5})
    assert r.fix_age_seconds() == float("inf")
    assert r.get_position() is None
    assert r.is_stale() is True


def test_an_unparseable_timestamp_is_treated_as_infinitely_old():
    r = _reader(_fix(timestamp="not-a-date"))
    assert r.fix_age_seconds() == float("inf")
    assert r.get_position() is None


def test_a_timestamp_in_the_future_is_not_negative_age():
    # A receiver or a clock adjustment can produce this; age must not go below
    # zero and accidentally look fresh forever.
    r = _reader(_fix(age_seconds=-30))
    assert r.fix_age_seconds() >= 0.0
    assert r.get_position() is not None


# ── The window itself ──────────────────────────────────────────────────────

def test_the_window_is_short_enough_to_bound_the_error_and_long_enough_to_survive_a_hiccup():
    # A consumer receiver emits GGA/RMC about once a second. The window has to
    # clear a momentary stall without letting a moving vehicle travel far.
    assert 2.0 <= STALE_FIX_SECONDS <= 30.0, STALE_FIX_SECONDS
    # At 50 km/h, how far wrong can a coordinate be before it is refused?
    metres = (50_000 / 3600) * STALE_FIX_SECONDS
    assert metres < 250, f"a fix may be up to {metres:.0f} m out of date"


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
