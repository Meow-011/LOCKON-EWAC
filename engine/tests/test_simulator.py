"""Tests for the field simulator scenario.

    python engine/tests/test_simulator.py
    python -m pytest engine/tests/test_simulator.py

Needs no third-party packages. The one test that depends on scapy's OUI database
skips cleanly when it is absent.

Why these exist.

A simulator is only worth having if a rehearsal on it teaches the operator
something true about a real drive. Three ways that quietly stops being the case,
each locked by a test here:

  1. **The route loses its turn.** A straight route is mirror-ambiguous, so the
     localizer cannot tell which side of the road an AP is on. A scenario
     "simplified" to a straight line would rehearse the estimator at its worst
     while looking like a tidier scenario.
  2. **The radio model drifts from the estimator's.** The simulator is the
     inverse of `src/lib/localization.ts`. If one side changes alone, a
     rehearsal measures the gap between two models rather than the localizer.
  3. **The planted rogue stops being detected by the detector.** The scenario
     must not pre-label it: the rogue is scored by `evil_twin.analyze` like any
     other AP. The paired assertion matters just as much — the legitimate
     WPA2/WPA3 transition APs must stay CLEAR, because accusing them is the
     false positive that would cost a real report its credibility.
"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import evil_twin
from scanner.ap_track import ApTracker
from scanner.simulator import (
    DEFAULT_APS,
    MAX_RSSI_DBM,
    PATH_LOSS_EXPONENT,
    SHADOWING_SIGMA_DB,
    VISIBILITY_FLOOR_DBM,
    Simulator,
    expected_rssi,
    reference_power_dbm,
)

ROGUE_BSSID = "DE:AD:BE:11:22:33"
LEGIT_WPA2 = "00:1B:D4:2A:10:01"
LEGIT_WPA3 = "00:1B:D4:2A:10:02"


def _fixed_clock():
    """A clock the test drives, so nothing here depends on wall time."""
    holder = [0.0]

    def clock():
        return holder[0]

    return holder, clock


def _drive(steps=90, interval=2.0, seed=7):
    """Run a full simulated survey and return the tracked AP records."""
    holder, clock = _fixed_clock()
    sim = Simulator(seed=seed, clock=clock)
    tracker = ApTracker()
    records = {}
    sightings = 0
    for step in range(steps):
        holder[0] = step * interval
        for raw in sim.observe():
            rec = tracker.build(
                bssid=raw["bssid"], ssid=raw["ssid"], vendor=raw["vendor"],
                encryption=raw["encryption"], is_vulnerable=raw["is_vulnerable"],
                rssi=raw["rssi"], frequency=raw["frequency"],
            )
            records[rec["bssid"]] = rec
            sightings += 1
    return sim, records, sightings


# Route geometry.

def test_route_has_a_turn():
    """A straight route cannot resolve which side of the road an AP is on."""
    sim = Simulator()
    assert sim.describe()["route_has_turn"], (
        "the default route is straight; a rehearsal on it would teach the "
        "operator the wrong thing about localization accuracy"
    )


def test_vehicle_actually_moves_along_the_route():
    holder, clock = _fixed_clock()
    sim = Simulator(clock=clock)
    seen = []
    for step in range(12):
        holder[0] = step * 5.0
        seen.append(sim.position_m())
    distinct = {(round(x, 1), round(y, 1)) for x, y, _h in seen}
    assert len(distinct) > 8, f"vehicle barely moved: {len(distinct)} distinct points"


def test_position_never_leaves_the_route():
    """Ping-ponging must stay on the polyline, not run off the end of it."""
    holder, clock = _fixed_clock()
    sim = Simulator(clock=clock)
    route = sim.route_m
    for step in range(400):
        holder[0] = step * 3.0
        x, y, _h = sim.position_m()
        # Distance from the point to the nearest route segment.
        best = min(_point_to_segment(x, y, a, b) for a, b in zip(route, route[1:]))
        assert best < 1e-6, f"off-route at t={holder[0]}: {best:.3f} m from the path"


def _point_to_segment(px, py, a, b):
    (x1, y1), (x2, y2) = a, b
    dx, dy = x2 - x1, y2 - y1
    leg = dx * dx + dy * dy
    if leg == 0:
        return math.hypot(px - x1, py - y1)
    t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / leg))
    return math.hypot(px - (x1 + t * dx), py - (y1 + t * dy))


def test_heading_changes_at_the_turn():
    holder, clock = _fixed_clock()
    sim = Simulator(clock=clock)
    headings = set()
    for step in range(80):
        holder[0] = step * 2.0
        headings.add(round(sim.position_m()[2]))
    assert len(headings) > 1, "heading never changed, so the turn is not driven"


# Radio model — must stay the inverse of src/lib/localization.ts.

def test_rssi_model_inverts_the_localizers_distance_formula():
    """expected_rssi and rssiToDistanceM must be each other's inverse."""
    for freq in (2412, 2437, 2462, 5180, 5580, 6115):
        for distance in (5.0, 20.0, 50.0, 120.0, 300.0):
            rssi = expected_rssi(distance, freq)
            # This is rssiToDistanceM() from localization.ts, transcribed.
            back = 10 ** ((reference_power_dbm(freq) - rssi)
                          / (10 * PATH_LOSS_EXPONENT))
            assert abs(back - distance) < 1e-6, (
                f"{freq} MHz at {distance} m round-tripped to {back:.3f} m"
            )


def test_higher_bands_read_weaker_at_the_same_distance():
    """One reference for every band placed 5 GHz APs 1.80x too far away."""
    p24 = reference_power_dbm(2437)
    p5 = reference_power_dbm(5180)
    p6 = reference_power_dbm(6115)
    assert 6.0 < (p24 - p5) < 7.0, f"5 GHz offset {(p24 - p5):.2f} dB"
    assert 7.0 < (p24 - p6) < 8.5, f"6 GHz offset {(p24 - p6):.2f} dB"


def test_khz_frequencies_match_mhz():
    """Windows reports 2412000; it must not be read as a 2.4 THz carrier."""
    assert abs(reference_power_dbm(5180000) - reference_power_dbm(5180)) < 1e-9


def test_shadowing_is_present_so_accuracy_is_not_flattering():
    """Without noise the estimator inverts the model exactly and looks perfect."""
    assert SHADOWING_SIGMA_DB >= 4.0, "shadowing too low to be a real drive"
    holder, clock = _fixed_clock()
    sim = Simulator(seed=3, clock=clock)
    readings = []
    for step in range(40):
        holder[0] = step * 2.0
        for obs in sim.observe():
            if obs["bssid"] == LEGIT_WPA2:
                readings.append(obs["rssi"] - expected_rssi(
                    obs["true_distance_m"], obs["frequency"]))
    assert len(readings) > 10, "not enough sightings to judge"
    spread = max(readings) - min(readings)
    assert spread > 5.0, f"readings are nearly noise-free (spread {spread:.1f} dB)"


def test_no_reading_escapes_the_reportable_range():
    holder, clock = _fixed_clock()
    sim = Simulator(seed=11, clock=clock)
    for step in range(120):
        holder[0] = step * 2.0
        for obs in sim.observe():
            assert VISIBILITY_FLOOR_DBM <= obs["rssi"] <= MAX_RSSI_DBM, obs


# The scenario itself.

def test_the_survey_sees_many_access_points_not_one():
    """The whole point of replacing the old stub."""
    _sim, records, sightings = _drive()
    assert len(records) >= 8, f"only {len(records)} APs seen across the drive"
    assert sightings > 100, f"only {sightings} sightings; too sparse to localize"


def test_every_ap_is_eventually_seen():
    sim, records, _ = _drive(steps=160)
    missed = [ap.bssid for ap in sim.aps if ap.bssid not in records]
    assert not missed, f"never heard: {missed}"


def test_trend_reaches_peak_so_the_map_can_pin_aps():
    """The frontend pins an AP at rssi_trend == PEAK; without it nothing lands."""
    holder, clock = _fixed_clock()
    sim = Simulator(seed=5, clock=clock)
    tracker = ApTracker()
    peaks = set()
    for step in range(120):
        holder[0] = step * 2.0
        for raw in sim.observe():
            rec = tracker.build(
                bssid=raw["bssid"], ssid=raw["ssid"], vendor=raw["vendor"],
                encryption=raw["encryption"], is_vulnerable=raw["is_vulnerable"],
                rssi=raw["rssi"], frequency=raw["frequency"],
            )
            if rec["rssi_trend"] == "PEAK":
                peaks.add(rec["bssid"])
    assert len(peaks) >= 8, f"only {len(peaks)} APs ever peaked"


def test_scenario_covers_the_risk_range_a_report_needs():
    encryptions = {ap.encryption for ap in DEFAULT_APS}
    for needed in ("OPEN", "WEP", "WPA", "WPA2", "WPA3"):
        assert needed in encryptions, f"no {needed} AP, so the report section is untested"


def test_vulnerable_classification_matches_the_live_scanner():
    """OPEN, WEP and WPA1 are vulnerable; WPA2/WPA3 are not."""
    for ap in DEFAULT_APS:
        expected = ap.encryption in ("OPEN", "WEP", "WPA")
        assert ap.is_vulnerable is expected, f"{ap.ssid} ({ap.encryption})"


def test_both_bands_are_represented():
    freqs = {ap.frequency for ap in DEFAULT_APS}
    assert any(f < 3000 for f in freqs), "no 2.4 GHz AP"
    assert any(f > 5000 for f in freqs), "no 5 GHz AP, so band correction is untested"


def test_ground_truth_is_kept_for_every_ap():
    """Without it the localizer's error cannot be measured, only eyeballed."""
    sim = Simulator()
    truth = sim.ground_truth()
    assert set(truth) == {ap.bssid for ap in sim.aps}
    for entry in truth.values():
        assert entry["latitude"] and entry["longitude"]


def test_hidden_ssid_is_present_and_blank():
    hidden = [ap for ap in DEFAULT_APS if not ap.ssid]
    assert len(hidden) == 1, "expected exactly one hidden-SSID AP in the scenario"


def test_scenario_is_repeatable_for_a_given_seed():
    """A rehearsal you cannot repeat is hard to learn anything from."""
    a = _drive(steps=40, seed=99)[1]
    b = _drive(steps=40, seed=99)[1]
    assert {k: v["rssi"] for k, v in a.items()} == {k: v["rssi"] for k, v in b.items()}


# Rogue-AP scoring — the detector's verdict, not the scenario's claim.

def test_the_planted_rogue_is_caught_by_the_real_detector():
    _sim, records, _ = _drive()
    verdicts = evil_twin.analyze(list(records.values()))
    rogue = verdicts[ROGUE_BSSID]
    assert rogue["verdict"] in ("LIKELY", "CONFIRMED"), rogue
    assert rogue["is_evil_twin"] is True, rogue
    codes = {i["code"] for i in rogue["indicators"]}
    assert "open_clone_of_secured" in codes, codes


def test_the_legitimate_transition_pair_is_not_accused():
    """WPA2 + WPA3 on one SSID is a correct deployment, not an evil twin.

    This is the false positive that would have reported every organisation
    mid-WPA3-rollout as running evil twins.
    """
    _sim, records, _ = _drive()
    verdicts = evil_twin.analyze(list(records.values()))
    for bssid in (LEGIT_WPA2, LEGIT_WPA3):
        v = verdicts[bssid]
        assert v["is_evil_twin"] is False, f"{bssid} accused: {v}"
        assert v["verdict"] == "CLEAR", f"{bssid} scored {v['score']}: {v}"


def test_the_scenario_does_not_pre_label_its_own_rogue():
    """A scenario that asserts the answer cannot show the detector works."""
    for ap in DEFAULT_APS:
        for attr in ("rogue_verdict", "rogue_score", "is_evil_twin"):
            assert not hasattr(ap, attr), f"{ap.bssid} carries {attr}"
    holder, clock = _fixed_clock()
    sim = Simulator(clock=clock)
    for obs in sim.observe():
        assert "rogue_verdict" not in obs and "is_evil_twin" not in obs, obs


def test_declared_vendors_match_their_own_ouis():
    """Guards the scenario drifting from its BSSIDs.

    The vendor-mismatch indicator only fires if the rogue's vendor really does
    differ from the estate's, so a typo'd OUI would silently weaken the test
    above rather than failing.
    """
    try:
        from scanner.oui import lookup_vendor
    except Exception:
        print("  SKIP  scapy OUI database unavailable; vendor check skipped.")
        return
    for ap in DEFAULT_APS:
        assert lookup_vendor(ap.bssid) == ap.vendor, (
            f"{ap.bssid} declares {ap.vendor!r} but its OUI resolves to "
            f"{lookup_vendor(ap.bssid)!r}"
        )


def test_simulation_describes_itself_as_simulated():
    """The report's method appendix reads this; it must never say otherwise."""
    assert Simulator().describe()["simulated"] is True


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
