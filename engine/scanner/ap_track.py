"""LOCKON EWAC — AP sighting tracker (EMA smoothing, trend, persistence).

Why this is its own module.

The frontend pins an access point on the map at `rssi_trend == "PEAK"`, so the
trend values a scan produces are not cosmetic: they decide which sighting the
localizer treats as the closest approach. This logic used to live inline inside
`WiFiScanner.get_results()`, which imports pywifi at module scope. A simulator
that reimplemented it would rehearse *its own* trend behaviour rather than the
one a real drive produces, and a rehearsal that exercises different code is
worth very little.

Nothing here touches hardware, so it is importable (and testable) on a machine
with no pywifi and no wireless adapter.
"""
from datetime import datetime

from rf import normalize_freq, freq_to_band, freq_to_channel

#: Raw Wi-Fi RSSI fluctuates +/-5 dB even when stationary; this smooths it.
#: Higher = faster response, lower = smoother. 0.6 balances both.
EMA_ALPHA = 0.6

#: How far the smoothed value must move before it counts as a trend rather
#: than noise.
TREND_DELTA_DB = 1.5

#: What a reading below this is treated as when no peak has been recorded yet.
_NO_PEAK_FLOOR = -100


class ApTracker:
    """Per-BSSID smoothing, trend detection and first/last-seen bookkeeping."""

    def __init__(self):
        self.discovered_aps = {}   # {bssid: {first_seen, last_seen}}
        self._prev_rssi = {}       # {bssid: last smoothed rssi}
        self._peak_rssi = {}       # {bssid: best smoothed rssi ever seen}

    def clear(self):
        self.discovered_aps = {}
        self._prev_rssi = {}
        self._peak_rssi = {}

    def trend_for(self, bssid, rssi):
        """Smooth `rssi` for `bssid` and classify the movement.

        Returns `(smoothed, trend)`. The first sighting is deliberately NEW and
        never PEAK: until there is a second reading there is no way to know
        whether this is the closest approach, and calling it PEAK would pin the
        access point at wherever it was first heard.
        """
        prev_ema = self._prev_rssi.get(bssid)
        if prev_ema is None:
            smoothed = rssi
            trend = "NEW"
            # Baseline for future comparison.
            self._peak_rssi[bssid] = smoothed
        else:
            smoothed = EMA_ALPHA * rssi + (1 - EMA_ALPHA) * prev_ema
            if smoothed > prev_ema + TREND_DELTA_DB:
                trend = "RISING"
            elif smoothed < prev_ema - TREND_DELTA_DB:
                trend = "FALLING"
            else:
                trend = "STABLE"

            if smoothed > self._peak_rssi.get(bssid, _NO_PEAK_FLOOR):
                self._peak_rssi[bssid] = smoothed
                trend = "PEAK"   # proven closest approach via EMA

        self._prev_rssi[bssid] = smoothed
        return smoothed, trend

    def mark_seen(self, bssid):
        """Record first/last sighting times and return them."""
        now = datetime.now().isoformat()
        if bssid not in self.discovered_aps:
            self.discovered_aps[bssid] = {"first_seen": now}
        self.discovered_aps[bssid]["last_seen"] = now
        return self.discovered_aps[bssid]

    def build(self, *, bssid, ssid, vendor, encryption, is_vulnerable,
              rssi, frequency=None, extra=None):
        """Assemble one AP record in the shape the UI and database expect.

        `rssi` is reported raw, not smoothed: the smoothed value exists to make
        the trend stable, and publishing it instead would quietly change every
        distance the localizer derives.

        `extra` merges source-specific fields over the record. Only non-None
        values are merged, so an enrichment that could not determine a field
        leaves it absent rather than blanking one the caller already had.
        """
        _smoothed, trend = self.trend_for(bssid, rssi)
        seen = self.mark_seen(bssid)

        # Band is left unknown when the driver reports no frequency.
        #
        # This used to default to "2.4G". `channel` was already correctly left
        # None — `freq_to_channel` returns None rather than a guess — but band was
        # asserted, persisted, and printed in the report as "N access points on
        # 2.4 GHz". It also starved `aps_unknown_band`, the field that exists
        # precisely so a reader can tell "no 6 GHz networks here" from "this
        # adapter cannot see 6 GHz", by filing every unknown under a real band.
        channel = None
        band = None
        if frequency and frequency > 0:
            # normalize_freq also handles Windows reporting kHz (2412000).
            frequency = normalize_freq(frequency)
            band = freq_to_band(frequency)
            channel = freq_to_channel(frequency)

        record = {
            "bssid": bssid,
            "ssid": ssid,
            "vendor": vendor,
            "encryption": encryption,
            "is_vulnerable": is_vulnerable,
            "channel": channel,
            "frequency": frequency,
            "band": band,
            "rssi": rssi,
            "rssi_trend": trend,
            "first_seen": seen["first_seen"],
            "last_seen": seen["last_seen"],
        }
        # Fields a particular source can supply and others cannot — cipher and
        # auth_type from netsh, for instance. Merged rather than declared here
        # so a source that has nothing extra produces exactly the old record.
        if extra:
            record.update({k: v for k, v in extra.items() if v is not None})
        return record
