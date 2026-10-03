"""Ground-truth tests for the GPR signal-field smoother.

    python engine/tests/test_gpr.py
    python -m pytest engine/tests/test_gpr.py

Skips cleanly when scikit-learn is absent, so it can run on a machine that has
not installed the engine's requirements.

These exist because the previous implementation reported 69% confidence while
being 225 m wrong — five times worse than reporting the strongest sighting — and
nothing caught it. The two defects were a prior mean of 0 dBm (stronger than any
real reading, so predictions ran away from the data) and a grid padded 55 m past
the measurements (so the argmax escaped into that padding).
"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import numpy as np
    from scanner.gpr_engine import calculate_gpr_location, GPR_AVAILABLE, reference_power_dbm
except ImportError:
    GPR_AVAILABLE = False

M_PER_DEG_LAT = 111320.0
AP_LAT, AP_LON = 13.756300, 100.501800


def _m_per_deg_lon(lat):
    return 111320.0 * math.cos(math.radians(lat))


M_LON = _m_per_deg_lon(AP_LAT)


def simulate_drive(n=60, off_road_m=40.0, span_m=300.0, sigma_db=6.0, seed=1):
    """Straight pass along a road with the AP off to one side."""
    rng = np.random.default_rng(seed)
    road_lat = AP_LAT - off_road_m / M_PER_DEG_LAT
    half = span_m / 2 / M_LON
    obs = []
    for i in range(n):
        lon = (AP_LON - half) + (2 * half) * i / (n - 1)
        d = max(1.0, math.hypot((road_lat - AP_LAT) * M_PER_DEG_LAT,
                                (lon - AP_LON) * M_LON))
        rssi = -40 - 25 * math.log10(d) + rng.normal(0, sigma_db)
        if rssi >= -95:
            obs.append({"lat": road_lat, "lon": lon, "rssi": float(round(rssi))})
    return obs


def err_m(lat, lon):
    return math.hypot((lat - AP_LAT) * M_PER_DEG_LAT, (lon - AP_LON) * M_LON)


def test_result_stays_inside_the_surveyed_area():
    """The old version escaped into 55 m of grid padding outside the data.

    One deliberate exception: when an axis is degenerate — a perfectly straight
    pass has a single latitude — that axis is widened by 5 m, because a grid
    with zero width on one side is a line, not a surface. The allowance is that
    5 m and no more.
    """
    obs = simulate_drive()
    r = calculate_gpr_location(obs, grid_resolution=60)
    assert r is not None

    lat_lo = min(o["lat"] for o in obs)
    lat_hi = max(o["lat"] for o in obs)
    lon_lo = min(o["lon"] for o in obs)
    lon_hi = max(o["lon"] for o in obs)

    DEGENERATE_AXIS_MARGIN_M = 5.0
    lat_margin = DEGENERATE_AXIS_MARGIN_M / M_PER_DEG_LAT
    lon_margin = DEGENERATE_AXIS_MARGIN_M / M_LON

    assert lat_lo - lat_margin <= r["lat"] <= lat_hi + lat_margin, (
        f"peak escaped the measured latitudes by more than {DEGENERATE_AXIS_MARGIN_M} m"
    )
    assert lon_lo - lon_margin <= r["lon"] <= lon_hi + lon_margin, (
        f"peak escaped the measured longitudes by more than {DEGENERATE_AXIS_MARGIN_M} m"
    )


def test_result_does_not_wander_into_unmeasured_space():
    """A curved route has width on both axes; nothing should leave the hull."""
    rng = np.random.default_rng(5)
    obs = []
    for i in range(80):
        # An L-shaped route, so neither axis is degenerate.
        if i < 40:
            lat = AP_LAT - 40.0 / M_PER_DEG_LAT
            lon = AP_LON + (-150.0 + 210.0 * i / 39) / M_LON
        else:
            lat = AP_LAT + (-40.0 + 200.0 * (i - 40) / 39) / M_PER_DEG_LAT
            lon = AP_LON + 60.0 / M_LON
        d = max(1.0, math.hypot((lat - AP_LAT) * M_PER_DEG_LAT, (lon - AP_LON) * M_LON))
        rssi = -40 - 25 * math.log10(d) + rng.normal(0, 6)
        if rssi >= -95:
            obs.append({"lat": lat, "lon": lon, "rssi": float(round(rssi))})

    r = calculate_gpr_location(obs, grid_resolution=60)
    assert r is not None
    tol = 1e-9
    assert min(o["lat"] for o in obs) - tol <= r["lat"] <= max(o["lat"] for o in obs) + tol
    assert min(o["lon"] for o in obs) - tol <= r["lon"] <= max(o["lon"] for o in obs) + tol


def test_error_is_in_the_same_league_as_peak_rssi():
    """It should smooth the peak, not invent a new location hundreds of metres away."""
    obs = simulate_drive()
    peak = max(obs, key=lambda o: o["rssi"])
    baseline = err_m(peak["lat"], peak["lon"])
    r = calculate_gpr_location(obs, grid_resolution=60)
    e = err_m(r["lat"], r["lon"])
    assert e < baseline * 1.5 + 10, f"GPR error {e:.0f} m against a {baseline:.0f} m baseline"
    assert e < 120, f"GPR error {e:.0f} m (the broken version scored 225 m)"


def test_smoothing_beats_a_noisy_raw_peak():
    """Where noise makes the raw peak jump, the smoothed field should be steadier."""
    improved = 0
    trials = 0
    for seed in range(1, 9):
        obs = simulate_drive(n=120, sigma_db=8.0, seed=seed)
        if len(obs) < 10:
            continue
        trials += 1
        peak = max(obs, key=lambda o: o["rssi"])
        r = calculate_gpr_location(obs, grid_resolution=50)
        if r and err_m(r["lat"], r["lon"]) <= err_m(peak["lat"], peak["lon"]):
            improved += 1
    assert trials > 0
    assert improved >= trials * 0.6, f"smoothing helped in only {improved}/{trials} runs"


def test_predicted_peak_is_not_stronger_than_anything_measured():
    """A prior mean of 0 dBm used to pull predictions above every real reading."""
    obs = simulate_drive()
    strongest = max(o["rssi"] for o in obs)
    r = calculate_gpr_location(obs, grid_resolution=60)
    assert r["peak_rssi"] <= strongest + 3, (
        f"smoothed peak {r['peak_rssi']:.1f} dBm exceeds the strongest measurement {strongest:.1f} dBm"
    )


def test_stated_uncertainty_covers_the_real_error():
    """The number in the report has to be worth something."""
    covered = 0
    trials = 0
    for seed in range(1, 7):
        obs = simulate_drive(seed=seed)
        if len(obs) < 10:
            continue
        trials += 1
        r = calculate_gpr_location(obs, grid_resolution=50)
        if r and err_m(r["lat"], r["lon"]) <= r["error_radius_m"] * 1.3:
            covered += 1
    assert trials > 0
    assert covered >= trials * 0.7, f"radius covered the true error in only {covered}/{trials} runs"


def test_confidence_is_not_inflated():
    """It reported 69% while 225 m wrong. A ~40 m answer must not read as high."""
    obs = simulate_drive()
    r = calculate_gpr_location(obs, grid_resolution=60)
    assert r["confidence"] < 70, f"confidence {r['confidence']:.0f}% for a {err_m(r['lat'], r['lon']):.0f} m error"
    assert r["confidence"] > 0


def test_result_states_what_the_method_can_and_cannot_do():
    obs = simulate_drive()
    r = calculate_gpr_location(obs, grid_resolution=50)
    text = (r.get("method_note", "") + " " + " ".join(r.get("notes", []))).lower()
    assert "not" in text and ("transmitter" in text or "localization" in text), \
        "the result must not let a reader mistake this for a transmitter fix"
    assert "error_radius_m" in r and r["error_radius_m"] > 0


def test_band_correction_matches_the_frontend():
    p24 = reference_power_dbm(2437)
    p5 = reference_power_dbm(5180)
    p6 = reference_power_dbm(5955)
    assert abs(p24 - (-40.0)) < 1e-6
    assert 6.0 < (p24 - p5) < 7.0, f"5 GHz offset {(p24 - p5):.2f} dB"
    assert 7.0 < (p24 - p6) < 8.5, f"6 GHz offset {(p24 - p6):.2f} dB"
    assert abs(reference_power_dbm(2412000) - reference_power_dbm(2412)) < 1e-9


def test_too_few_points_returns_none():
    assert calculate_gpr_location([{"lat": AP_LAT, "lon": AP_LON, "rssi": -50}]) is None


def _main():
    if not GPR_AVAILABLE:
        print("  SKIP  scikit-learn not installed; GPR tests skipped.")
        print("\n0/0 passed (skipped)")
        return 0
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
