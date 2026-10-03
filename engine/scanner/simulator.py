"""LOCKON EWAC — Field simulator (multi-AP, moving along a route).

Why this exists.

The previous simulator emitted one hardcoded access point (`SIMULATED-AP`, rssi
-55) at a fixed coordinate. It was honestly flagged, but it could not rehearse
the thing this tool exists to produce: a report. With one AP at one point there
is no localization to run, no rogue-AP group to score, no coverage to compute
and no risk distribution to review. The operator's first real look at their own
report was in the field, which is the worst possible time to discover that a
section reads badly.

So this drives a *scenario*: a vehicle moving along a route past a set of access
points at known positions, with RSSI derived from the same radio model the
localizer inverts. That makes a simulated mission exercise the real code paths —
`ApTracker` for trend, `evil_twin.analyze` for rogue scoring, `_validate_gps`
for fix quality, and the estimators in `src/lib/localization.ts`.

What this is NOT.

It is not evidence, and nothing here is presented as such. Every access point it
produces is stamped `simulated: True`, which the frontend records on every row
it stores so the report can never present a rehearsal as field work. The reason
a simulator is safe to have at all is that the flag is never optional.

Two properties are deliberate rather than incidental:

  * **The route contains a turn.** A straight route is mirror-ambiguous: the
    estimator cannot tell which side of the road an AP is on, and driving the
    same street twice makes it worse by reinforcing the symmetry. One turn
    resolves it. A scenario without a turn would rehearse an estimator working
    at its worst and teach the operator the wrong thing about its accuracy.
  * **The ground truth is kept.** Each AP carries the position it was placed at,
    so a test (or the operator) can measure the localizer's error in metres
    instead of judging the map by eye.
"""
import math
import random
import time

# Radio model — mirrors src/lib/localization.ts exactly. If these drift apart the
# simulator stops being the inverse of the estimator and a rehearsal measures
# nothing. test_simulator.py asserts the round trip.
REFERENCE_2G4_DBM = -40.0
REF_FREQ_MHZ = 2437.0
PATH_LOSS_EXPONENT = 2.5
SHADOWING_SIGMA_DB = 6.0

#: Below this a managed-mode adapter generally does not report the AP at all.
#: The live scan on this machine saw APs down to -98 dBm, so this is not a
#: convenient fiction to keep the scenario tidy.
VISIBILITY_FLOOR_DBM = -95

#: No modelled reading is reported stronger than this. Standing on top of the
#: transmitter is not a case the path-loss model is meaningful for.
MAX_RSSI_DBM = -28

_EARTH_M_PER_DEG_LAT = 110540.0


def reference_power_dbm(frequency_mhz=None):
    """Received power at 1 m for a frequency, in dBm.

    Free-space loss at 1 m scales as 20*log10(f), so a 5 GHz AP reads about
    6.5 dB weaker than a 2.4 GHz one at the same distance. One reference for all
    bands placed 5 GHz APs 1.80x too far away.
    """
    if not frequency_mhz or frequency_mhz <= 0:
        return REFERENCE_2G4_DBM
    mhz = frequency_mhz / 1000.0 if frequency_mhz > 10000 else float(frequency_mhz)
    return REFERENCE_2G4_DBM - 20.0 * math.log10(mhz / REF_FREQ_MHZ)


def expected_rssi(distance_m, frequency_mhz=None):
    """Noise-free RSSI at a distance. The inverse of rssiToDistanceM()."""
    d = max(1.0, float(distance_m))
    return reference_power_dbm(frequency_mhz) - 10.0 * PATH_LOSS_EXPONENT * math.log10(d)


def m_per_deg_lon(lat):
    return 111320.0 * math.cos(math.radians(lat))


class SimAp:
    """One access point in a scenario, with the position it was placed at."""

    def __init__(self, bssid, ssid, encryption, frequency, vendor,
                 east_m, north_m, note=""):
        self.bssid = bssid
        self.ssid = ssid
        self.encryption = encryption
        self.frequency = frequency
        self.vendor = vendor
        self.east_m = east_m      # ground truth, metres east of the origin
        self.north_m = north_m    # ground truth, metres north of the origin
        self.note = note          # what this AP is in the scenario, for humans

    @property
    def is_vulnerable(self):
        """Matches the live scanner's rule: OPEN, WEP and WPA1 are vulnerable."""
        return self.encryption in ("OPEN", "WEP", "WPA")


# The default scenario.
#
# Origin is the coordinate the old simulator reported, so an operator who had
# the map centred there still recognises the area.
DEFAULT_ORIGIN = (13.7563, 100.5018)

# An L: 320 m east, then 300 m north. The turn is the point of the shape.
DEFAULT_ROUTE_M = [(0.0, 0.0), (320.0, 0.0), (320.0, 300.0)]

DEFAULT_SPEED_MS = 8.3          # ~30 km/h, a realistic survey speed
DEFAULT_SATELLITES = 9
DEFAULT_HDOP = 1.1              # "excellent"; _validate_gps rejects above 5.0

#: The estate. Chosen so a rehearsal report has something in every section:
#: a critical legacy finding, open networks, a genuine rogue AP, a WPA3
#: transition pair that must NOT be accused, and neighbour noise.
DEFAULT_APS = [
    # The legitimate corporate estate: two Cisco APs, one SSID, WPA2 + WPA3.
    # This is WPA3 transition mode and a correct configuration. The rogue-AP
    # scorer must leave both CLEAR; the rule this replaced called them twins.
    SimAp("00:1B:D4:2A:10:01", "NBU-CORP", "WPA2", 2437, "Cisco Systems, Inc",
          90.0, 55.0, "legitimate corporate AP (2.4 GHz)"),
    SimAp("00:1B:D4:2A:10:02", "NBU-CORP", "WPA3", 5180, "Cisco Systems, Inc",
          95.0, 58.0, "legitimate corporate AP (5 GHz, WPA3 transition partner)"),

    # The planted rogue: an OPEN clone of a secured SSID, a different vendor
    # from the estate majority, a locally administered MAC, and squatting on the
    # same channel. Scored by evil_twin.analyze() like any other AP — nothing
    # here pre-labels it, because a scenario that asserts its own answer cannot
    # show whether the detector works.
    SimAp("DE:AD:BE:11:22:33", "NBU-CORP", "OPEN", 2437, "Randomized (Local)",
          150.0, -35.0, "PLANTED ROGUE: open clone of NBU-CORP, across the road"),

    # Real findings an audit would report.
    SimAp("00:1B:D4:2A:10:03", "NBU-GUEST", "OPEN", 2412, "Cisco Systems, Inc",
          88.0, 60.0, "open guest network — legitimate but a finding"),
    SimAp("00:1B:78:55:10:07", "HR-PRINTER", "WEP", 2462, "Hewlett Packard",
          240.0, 40.0, "WEP printer — critical legacy encryption"),
    SimAp("00:14:6C:31:90:2B", "OFFICE-WIFI-2G", "WPA", 2452, "Netgear",
          300.0, -50.0, "WPA1 — deprecated, brute-forceable"),
    SimAp("44:19:B6:0C:71:40", "CCTV-NVR", "WPA2", 2422,
          "Hangzhou Hikvision Digital Technology Co.,Ltd.",
          320.0, 150.0, "camera NVR on the wireless estate"),
    SimAp("00:1B:D4:2A:10:04", "", "WPA2", 5200, "Cisco Systems, Inc",
          360.0, 220.0, "hidden SSID — must not be grouped with other hidden APs"),

    # Neighbour noise. A survey that only sees the target estate is not what a
    # drive looks like, and the report's out-of-scope handling needs exercising.
    SimAp("00:E0:FC:44:81:10", "3BB_HOME_5G", "WPA2", 5220,
          "Huawei Technologies Co.,Ltd", 270.0, 330.0, "neighbour"),
    SimAp("50:C7:BF:09:33:A1", "TRUE-H-GUEST", "OPEN", 2437,
          "Tp-Link Technologies Co.,Ltd.", 200.0, 330.0, "neighbour, open"),
    SimAp("00:14:6C:31:90:5F", "AIS-FIBRE-2G", "WPA2", 2437, "Netgear",
          380.0, 90.0, "neighbour"),
]


def _route_length(route):
    total = 0.0
    for (x1, y1), (x2, y2) in zip(route, route[1:]):
        total += math.hypot(x2 - x1, y2 - y1)
    return total


class Simulator:
    """A vehicle driving a route past a fixed set of access points.

    Position is a pure function of elapsed time rather than a mutable step, so
    the scan loop and the GPS loop — separate threads running at different rates
    — always agree about where the vehicle is.

    The route ping-pongs: on reaching the end the vehicle retraces it. A survey
    that stopped after one pass would end the operator's rehearsal mid-report.
    """

    def __init__(self, origin=None, route_m=None, aps=None,
                 speed_ms=DEFAULT_SPEED_MS, seed=None, clock=time.monotonic):
        self.origin_lat, self.origin_lon = origin or DEFAULT_ORIGIN
        self.route_m = list(route_m or DEFAULT_ROUTE_M)
        self.aps = list(aps if aps is not None else DEFAULT_APS)
        self.speed_ms = float(speed_ms)
        self.clock = clock
        self.started_at = clock()
        self._route_len = _route_length(self.route_m)
        # Seeded so two runs of the same scenario are comparable; a rehearsal you
        # cannot repeat is hard to learn anything from.
        self.random = random.Random(seed if seed is not None else 20260927)

    # Geometry.
    def to_latlon(self, east_m, north_m):
        lat = self.origin_lat + north_m / _EARTH_M_PER_DEG_LAT
        lon = self.origin_lon + east_m / m_per_deg_lon(self.origin_lat)
        return lat, lon

    def _distance_along(self, now=None):
        """How far along the route the vehicle is, ping-ponged into range."""
        elapsed = max(0.0, (now if now is not None else self.clock()) - self.started_at)
        travelled = elapsed * self.speed_ms
        if self._route_len <= 0:
            return 0.0
        cycle = travelled % (2 * self._route_len)
        return cycle if cycle <= self._route_len else 2 * self._route_len - cycle

    def position_m(self, now=None):
        """(east_m, north_m, heading_deg) of the vehicle."""
        target = self._distance_along(now)
        walked = 0.0
        for (x1, y1), (x2, y2) in zip(self.route_m, self.route_m[1:]):
            leg = math.hypot(x2 - x1, y2 - y1)
            if leg <= 0:
                continue
            if walked + leg >= target:
                t = (target - walked) / leg
                heading = (math.degrees(math.atan2(x2 - x1, y2 - y1)) + 360.0) % 360.0
                return x1 + (x2 - x1) * t, y1 + (y2 - y1) * t, heading
            walked += leg
        x, y = self.route_m[-1]
        return x, y, 0.0

    # What the GPS receiver would report.
    def fix(self, now=None):
        east, north, heading = self.position_m(now)
        lat, lon = self.to_latlon(east, north)
        return {
            "latitude": lat,
            "longitude": lon,
            "altitude": 12.0,
            "speed": self.speed_ms * 3.6,
            "heading": heading,
            "satellites": DEFAULT_SATELLITES,
            "hdop": DEFAULT_HDOP,
        }

    # What the radio would hear.
    def observe(self, now=None):
        """Modelled sightings from the current position.

        Returns the raw ingredients of an AP record — the caller runs them
        through `ApTracker` so trend and band derivation come from the same code
        a live scan uses.
        """
        east, north, _heading = self.position_m(now)
        seen = []
        for ap in self.aps:
            distance = math.hypot(ap.east_m - east, ap.north_m - north)
            clean = expected_rssi(distance, ap.frequency)
            # Log-normal shadowing. Without it the estimator would invert the
            # model exactly and report an accuracy no real drive can reach.
            rssi = clean + self.random.gauss(0.0, SHADOWING_SIGMA_DB)
            rssi = min(MAX_RSSI_DBM, rssi)
            if rssi < VISIBILITY_FLOOR_DBM:
                continue
            seen.append({
                "bssid": ap.bssid,
                "ssid": ap.ssid,
                "vendor": ap.vendor,
                "encryption": ap.encryption,
                "is_vulnerable": ap.is_vulnerable,
                "frequency": ap.frequency,
                "rssi": int(round(rssi)),
                "true_distance_m": distance,
            })
        return seen

    # For tests and for the report's method appendix.
    def ground_truth(self):
        """Where each AP actually is, so localizer error can be measured."""
        out = {}
        for ap in self.aps:
            lat, lon = self.to_latlon(ap.east_m, ap.north_m)
            out[ap.bssid] = {
                "ssid": ap.ssid, "latitude": lat, "longitude": lon,
                "east_m": ap.east_m, "north_m": ap.north_m, "note": ap.note,
            }
        return out

    def describe(self):
        """What this scenario is, for the operator and the method appendix."""
        headings = {
            round(math.degrees(math.atan2(x2 - x1, y2 - y1)), 3)
            for (x1, y1), (x2, y2) in zip(self.route_m, self.route_m[1:])
        }
        return {
            "simulated": True,
            "origin": {"latitude": self.origin_lat, "longitude": self.origin_lon},
            "route_m": self.route_m,
            "route_length_m": round(self._route_len, 1),
            "route_has_turn": len(headings) > 1,
            "speed_kmh": round(self.speed_ms * 3.6, 1),
            "ap_count": len(self.aps),
            "radio_model": {
                "reference_dbm_at_1m": REFERENCE_2G4_DBM,
                "reference_frequency_mhz": REF_FREQ_MHZ,
                "path_loss_exponent": PATH_LOSS_EXPONENT,
                "shadowing_sigma_db": SHADOWING_SIGMA_DB,
                "note": ("Mirrors src/lib/localization.ts. Simulated RSSI is the "
                         "model the localizer inverts, plus log-normal shadowing."),
            },
            "aps": [{"bssid": a.bssid, "ssid": a.ssid, "encryption": a.encryption,
                     "frequency": a.frequency, "note": a.note} for a in self.aps],
        }
