"""
LOCKON EWAC - Gaussian Process Regression (GPR) Localization Engine

What this actually does, stated plainly, because the previous version of this
file claimed "sub-meter tactical accuracy" and was measured at 225 m error
against a known ground truth — five times worse than simply reporting the
strongest sighting.

GPR fits a smooth surface through the RSSI values that were *measured*, and
returns the highest point of that surface. It is a very good smoother: it
suppresses the noise spikes that make raw peak-RSSI jumpy. It is NOT a
transmitter localizer. Every measurement comes from wherever the operator drove,
so the fitted surface only exists over the driven path, and its maximum can only
ever sit on or near that path. If the access point is 40 m off the road, the
answer will be on the road.

Use it for: a stable, de-noised "where was the signal strongest" position.
Do not use it for: putting a marker inside a building.
The likelihood-based estimators in src/lib/localization.ts are the ones that can
place a transmitter off the surveyed track.

Two defects fixed here, both measured:

  1. normalize_y was left at scikit-learn's default of False, so the GP's prior
     mean was 0 dBm. Away from data the prediction reverted toward 0, which is
     stronger than any real reading (measurements run -95..-65 dBm).
  2. The prediction grid was padded 55 m beyond the data on every side, so the
     argmax escaped into that padding where the prior dominated.

Together they put the answer in a corner of the padded grid, outside the area
that was surveyed, while reporting 69% confidence. Fixing the prior alone took
the error from 216 m to 41 m; fixing both took it to 40.1 m, which is the same
as peak RSSI — as expected, since that is what this method can do.
"""

import math
import numpy as np
import logging

try:
    from sklearn.gaussian_process import GaussianProcessRegressor
    from sklearn.gaussian_process.kernels import RBF, ConstantKernel as C, WhiteKernel
    GPR_AVAILABLE = True
except ImportError:
    GPR_AVAILABLE = False

logger = logging.getLogger("lockon_engine")

M_PER_DEG_LAT = 111320.0

# Kept deliberately identical to src/lib/localization.ts. If these drift, the
# engine and the UI will place the same access point in two different spots and
# the report will contradict itself.
REFERENCE_POWER_DBM = -40.0   # received power at 1 m, 2.4 GHz
PATH_LOSS_EXPONENT = 2.5
REF_FREQ_MHZ = 2437.0


def _m_per_deg_lon(lat):
    return 111320.0 * math.cos(math.radians(lat))


def reference_power_dbm(frequency_mhz=None):
    """Band-corrected reference power. Mirrors referencePowerDbm() in the UI."""
    if not frequency_mhz or frequency_mhz <= 0:
        return REFERENCE_POWER_DBM
    mhz = frequency_mhz / 1000.0 if frequency_mhz > 10000 else frequency_mhz
    return REFERENCE_POWER_DBM - 20.0 * math.log10(mhz / REF_FREQ_MHZ)


def calculate_gpr_location(measurements, grid_resolution=100):
    """
    Smooth the measured RSSI field and return its peak.

    :param measurements: [{'lat': float, 'lon': float, 'rssi': int}, ...]
    :param grid_resolution: grid points per axis
    :return: dict or None
    """
    if not GPR_AVAILABLE:
        logger.error("[GPR] scikit-learn is not installed. GPR analysis is disabled.")
        return None

    if len(measurements) < 3:
        logger.warning("[GPR] Not enough measurements. Need at least 3 points.")
        return None

    # Work in metres on a local tangent plane rather than in degrees. A degree of
    # longitude is shorter than a degree of latitude by cos(lat), so a single
    # isotropic length scale in degrees means different distances on each axis,
    # and the fitted length scale is not interpretable.
    lat0 = float(np.mean([m["lat"] for m in measurements]))
    lon0 = float(np.mean([m["lon"] for m in measurements]))
    m_lon = _m_per_deg_lon(lat0)

    X = np.array([[(m["lat"] - lat0) * M_PER_DEG_LAT,
                   (m["lon"] - lon0) * m_lon] for m in measurements])
    y = np.array([float(m["rssi"]) for m in measurements])

    # Length scale in metres now: 20 m start, bounded to a sane physical range.
    # WhiteKernel absorbs multipath noise.
    kernel = (C(1.0, (1e-3, 1e3))
              * RBF(20.0, (2.0, 2000.0))
              + WhiteKernel(noise_level=5.0, noise_level_bounds=(1e-2, 1e2)))

    # normalize_y=True centres the target, so the GP's prior mean is the mean
    # measured RSSI instead of 0 dBm. Without it, anywhere far from a measurement
    # reverts to a value stronger than anything actually observed.
    gp = GaussianProcessRegressor(kernel=kernel, n_restarts_optimizer=5,
                                  alpha=0.0, normalize_y=True)

    try:
        logger.debug("[GPR] Fitting model with %d points...", len(measurements))
        gp.fit(X, y)
    except Exception as e:
        logger.error("[GPR] Mathematical fitting failed: %s", e)
        return None

    # Grid spans the measured extent only. Any padding is unobserved space where
    # the answer would be an extrapolation, not a measurement.
    x_min, x_max = X[:, 0].min(), X[:, 0].max()
    y_min, y_max = X[:, 1].min(), X[:, 1].max()
    if x_max - x_min < 1.0:
        x_min, x_max = x_min - 5.0, x_max + 5.0
    if y_max - y_min < 1.0:
        y_min, y_max = y_min - 5.0, y_max + 5.0

    gx = np.linspace(x_min, x_max, grid_resolution)
    gy = np.linspace(y_min, y_max, grid_resolution)
    GX, GY = np.meshgrid(gx, gy)
    grid_points = np.c_[GX.ravel(), GY.ravel()]

    try:
        y_pred, sigma = gp.predict(grid_points, return_std=True)
    except MemoryError:
        logger.error("[GPR] Out of memory! Grid resolution too high.")
        return None

    max_idx = int(np.argmax(y_pred))
    best_x = float(grid_points[max_idx, 0])
    best_y = float(grid_points[max_idx, 1])
    best_rssi = float(y_pred[max_idx])
    uncertainty = float(sigma[max_idx])

    best_lat = lat0 + best_x / M_PER_DEG_LAT
    best_lon = lon0 + best_y / m_lon

    # How far is the answer from the nearest place we actually measured? A large
    # value means the peak is an extrapolation and should be distrusted.
    dists = np.hypot(X[:, 0] - best_x, X[:, 1] - best_y)
    nearest_measurement_m = float(np.min(dists))

    # An error radius in metres, not an invented percentage. The previous
    # `100 - sigma * 5` mapped a dB-scale standard deviation onto a percentage
    # with no physical meaning, and reported 69% while being 225 m wrong.
    #
    # The dominant term is not the fit's own uncertainty: it is that the peak of
    # the measured field is not the transmitter. The strongest smoothed reading
    # implies a range, and the transmitter is somewhere within roughly that
    # range of the peak. On the ground-truth simulation this term alone predicts
    # the real error (peak -81 dBm implies ~44 m; the true error was 44 m).
    freqs = [m.get("frequency") for m in measurements if m.get("frequency")]
    ref_power = reference_power_dbm(freqs[0] if freqs else None)
    implied_range_m = 10.0 ** ((ref_power - best_rssi) / (10.0 * PATH_LOSS_EXPONENT))

    # Secondary term: how much the fit itself wobbles at the peak.
    fit_scale_m = (10.0 ** (uncertainty / (10.0 * PATH_LOSS_EXPONENT)) - 1.0) * 10.0

    error_radius_m = max(5.0, implied_range_m, nearest_measurement_m + fit_scale_m)

    # Kept for API compatibility with existing callers, now with a documented
    # definition rather than an arbitrary one.
    confidence = max(1.0, min(99.0, 100.0 - 53.0 * math.log10(max(1.0, error_radius_m) / 4.0)))

    notes = [
        "GPR smooths the measured signal field and reports its peak. The result lies on or "
        "near the surveyed path by construction and is not an estimate of the transmitter's "
        "position away from that path.",
    ]
    if nearest_measurement_m > 25:
        notes.append(
            f"The peak is {nearest_measurement_m:.0f} m from the nearest actual measurement, "
            f"so it is an extrapolation rather than an observation."
        )

    logger.info("[GPR] Peak at %.6f, %.6f (+/-%.0f m, %.0f%%)",
                best_lat, best_lon, error_radius_m, confidence)

    return {
        "lat": best_lat,
        "lon": best_lon,
        "confidence": float(confidence),
        "error_radius_m": float(error_radius_m),
        "peak_rssi": best_rssi,
        "predictive_sigma_db": uncertainty,
        "nearest_measurement_m": nearest_measurement_m,
        "measurement_count": len(measurements),
        "kernel_params": str(gp.kernel_),
        "notes": notes,
        "method_note": (
            "Smoothed peak of the measured signal field. Not a transmitter localization; "
            "use the likelihood estimators for a position off the surveyed track."
        ),
    }
