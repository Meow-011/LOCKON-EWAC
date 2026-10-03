"""
A fix the receiver does not stand behind is not a position.

    python -m pytest engine/tests/test_gps_fix_quality.py

Why these exist.

`update()` accepted any NMEA sentence whose latitude was not exactly 0.0. Both
sentence types carry their own verdict on whether the position in them is
usable, and neither was read:

  * GGA has `gps_qual`, which is 0 when the receiver has no fix. A receiver in
    that state still emits GGA and still fills in a latitude -- the last one it
    believed, or a partial solution. So a cold start was plotted as a real
    position, and the operator watched the vehicle sit somewhere it had never
    been until the first true fix arrived.
  * RMC has `status`, 'A' for active and 'V' for void. A void sentence was read
    as position, speed and heading like any other, which is also where a heading
    comes from on a vehicle that has not moved.

These drive `update()` with planted serial lines, so they need no GPS hardware.
The sentences are real ones with correct checksums; pynmea2 parses them exactly
as it would off the wire.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from gps.reader import GPSReader  # noqa: E402


class _FakeSerial:
    """A serial port that reads back one planted line."""

    is_open = True

    def __init__(self, line):
        self._line = line.encode('ascii')

    def readline(self):
        return self._line


def _reader(line):
    r = GPSReader.__new__(GPSReader)
    r.last_fix = None
    r.satellites = 0
    r.running = True
    r.serial = _FakeSerial(line)
    return r


# Same position in both, differing only in the quality field.
GGA_FIX = '$GPGGA,123519,1345.3780,N,10030.1080,E,1,09,0.9,10.0,M,46.9,M,,*71'
GGA_NO_FIX = '$GPGGA,123519,1345.3780,N,10030.1080,E,0,00,99.9,10.0,M,46.9,M,,*49'
RMC_ACTIVE = '$GPRMC,123519,A,1345.3780,N,10030.1080,E,0.0,084.4,230394,003.1,W*68'
RMC_VOID = '$GPRMC,123519,V,1345.3780,N,10030.1080,E,0.0,084.4,230394,003.1,W*7F'


# ── GGA ────────────────────────────────────────────────────────────────────

def test_a_gga_with_a_fix_is_accepted():
    r = _reader(GGA_FIX)
    assert r.update() is True
    assert r.last_fix is not None
    assert round(r.last_fix['latitude'], 3) == 13.756


def test_a_gga_reporting_no_fix_is_refused():
    """quality 0 means the receiver has no position, whatever latitude it sent."""
    r = _reader(GGA_NO_FIX)
    assert r.update() is False
    assert r.last_fix is None


def test_the_quality_flag_is_carried_through():
    """So a consumer can tell a DGPS fix from a plain one rather than guess."""
    r = _reader(GGA_FIX)
    r.update()
    assert r.last_fix['fix_quality'] == 1


def test_a_no_fix_gga_cannot_overwrite_a_good_one():
    """
    The failure this really prevents.

    A receiver that loses its fix mid-survey keeps emitting GGA with quality 0.
    Before the gate, each of those replaced the last good position, so the track
    wandered off while the vehicle was standing still.
    """
    r = _reader(GGA_FIX)
    r.update()
    good = dict(r.last_fix)

    r.serial = _FakeSerial(GGA_NO_FIX)
    assert r.update() is False
    assert r.last_fix['latitude'] == good['latitude']
    assert r.last_fix['longitude'] == good['longitude']


# ── RMC ────────────────────────────────────────────────────────────────────

def test_an_active_rmc_is_accepted():
    r = _reader(RMC_ACTIVE)
    assert r.update() is True
    assert r.last_fix is not None


def test_a_void_rmc_is_refused():
    r = _reader(RMC_VOID)
    assert r.update() is False
    assert r.last_fix is None


def test_a_void_rmc_cannot_overwrite_speed_and_heading():
    """
    A void sentence still carries a course field, and it used to be believed.

    That is one of the ways a parked vehicle acquired a heading: not from
    movement, but from a sentence that said in its second field that none of it
    was to be trusted.
    """
    r = _reader(RMC_ACTIVE)
    r.update()
    before = dict(r.last_fix)

    r.serial = _FakeSerial(RMC_VOID)
    assert r.update() is False
    assert r.last_fix['heading'] == before['heading']
    assert r.last_fix['speed'] == before['speed']


# -- A quality that was never measured must not read as an ideal one ---------

"""
`hdop`, `fix_quality` and `satellites` are written only by the GGA branch, and both
branches `update()` the same dict. So a receiver emitting RMC but no parseable GGA
never set `hdop` at all, and `handler.py` read it as `fix.get('hdop', 0)` -- where 0
means "not reported, accept". The `hdop > 5.0` quality gate could therefore never
fire for such a receiver: a gate reading "ideal" for a quality nothing had measured.

The mirror of it is worse. With both sentence types arriving, an HDOP measured by a
GGA seconds ago travelled alongside a position from a later RMC as though the two
had been measured together.
"""


def test_an_rmc_only_receiver_reports_hdop_as_unknown_not_as_zero():
    # The defect. None is "this receiver does not state it"; 0 is "measured, and
    # ideal". The caller now distinguishes them.
    r = _reader(RMC_ACTIVE)
    assert r.update() is True
    assert r.last_fix['hdop'] is None, r.last_fix


def test_an_rmc_only_receiver_reports_no_fix_quality_or_satellite_count():
    r = _reader(RMC_ACTIVE)
    r.update()
    assert r.last_fix['fix_quality'] is None
    assert r.last_fix['satellites'] is None


def test_a_gga_measured_hdop_is_not_erased_by_a_later_rmc():
    # The common mixed case: GGA carries the quality, RMC carries speed and
    # heading. The measurement has to survive, or the gate stops working for
    # receivers that do report it.
    r = _reader(GGA_FIX)
    r.update()
    assert r.last_fix['hdop'] == 0.9

    r.serial = _FakeSerial(RMC_ACTIVE)
    r.update()
    assert r.last_fix['hdop'] == 0.9


def test_the_quality_carries_the_time_it_was_measured():
    # So a consumer can tell whether the HDOP sitting next to a position was
    # measured with it or seconds earlier by a different sentence.
    r = _reader(GGA_FIX)
    r.update()
    assert isinstance(r.last_fix.get('quality_at'), float)


def test_each_sentence_records_which_one_set_the_position():
    r = _reader(GGA_FIX)
    r.update()
    assert r.last_fix['position_from'] == 'GGA'

    r.serial = _FakeSerial(RMC_ACTIVE)
    r.update()
    assert r.last_fix['position_from'] == 'RMC'


def test_get_position_hands_back_a_copy():
    """
    Read from the Wi-Fi scan thread while the GPS thread calls `update()`.

    The caller reads several keys in sequence, so handing back the live dict let a
    latitude from before an update pair with a longitude from after it -- a
    coordinate measured nowhere, and one the outlier filter cannot catch because it
    is a plausible point between two real ones.
    """
    import time as _t
    r = _reader(GGA_FIX)
    r.update()
    r.fix_age_seconds = lambda: 0.0

    snapshot = r.get_position()
    assert snapshot is not None
    assert snapshot is not r.last_fix, 'the live dict was handed out'

    before = snapshot['latitude']
    r.last_fix['latitude'] = 99.0
    assert snapshot['latitude'] == before, 'the snapshot changed under the caller'
    del _t


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
