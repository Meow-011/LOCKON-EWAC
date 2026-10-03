"""LOCKON EWAC — Rogue AP / Evil Twin analysis

Replaces a single-rule heuristic that would have put a false accusation in a
report.

The old rule was "same SSID seen with two different encryption types -> both are
evil twins". Three problems, all of which matter in exactly the environments this
tool is pointed at:

  1. WPA2/WPA3 transition mode is a *correct* modern configuration and presents
     one SSID with two encryption types. Every organisation mid-WPA3-rollout
     would have been reported as running evil twins.
  2. It flagged both the legitimate AP and the impostor identically, so the
     report could not say which was which.
  3. It could not see the actual attack it was named after: a competent evil twin
     clones the SSID *and* the encryption, differing only in BSSID and hardware.

This module scores instead of asserting, and always names the reason. Anything
short of strong evidence is reported as SUSPECTED, because in a document someone
acts on, "we are not sure" is a legitimate and useful finding, while a confident
wrong answer costs the whole report its credibility.

Nothing here transmits. It is pure analysis over already-collected beacon data.
"""

# Encryption families that legitimately coexist on one SSID. A difference inside
# a family is a normal deployment, not an indicator.
_TRANSITION_FAMILIES = [
    {"WPA2", "WPA3"},          # WPA3 transition mode
    {"WPA2", "WPA2PSK"},       # naming variants of the same thing
    {"WPA", "WPA2"},           # legacy mixed mode — weak, but not an evil twin
    {"WPA3", "WPA3SAE"},
]

# Signals and the weight each contributes. Kept explicit so the report can quote
# the methodology rather than presenting a black-box verdict.
WEIGHTS = {
    "open_clone_of_secured": 50,   # strongest single indicator
    "vendor_mismatch": 25,
    "encryption_downgrade": 20,
    "unexpected_encryption_split": 15,
    "channel_conflict": 10,
    "signal_outlier": 10,
    "oui_randomized": 15,
}

SUSPECTED_AT = 25
LIKELY_AT = 45
CONFIRMED_AT = 70


def _norm_enc(value):
    return (value or "").upper().replace("-", "").replace("_", "").strip()


def _oui(bssid):
    if not bssid:
        return ""
    clean = "".join(c for c in bssid.upper() if c in "0123456789ABCDEF")
    return clean[:6]


def _is_locally_administered(bssid):
    """Second nibble of 2/6/A/E means a locally administered (often spoofed) MAC."""
    clean = "".join(c for c in (bssid or "").upper() if c in "0123456789ABCDEF")
    if len(clean) < 2:
        return False
    return clean[1] in ("2", "6", "A", "E")


# Relative strength, used to work out which AP in a group is the baseline and
# which is the deviation. Without this, group-level indicators land on every
# member and the legitimate AP gets accused alongside the impostor — the same
# defect as the heuristic this replaced.
_STRENGTH = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPAPSK": 2,
             "WPA2": 3, "WPA2PSK": 3, "WPA3": 4, "WPA3SAE": 4}


def _strength(encryption):
    return _STRENGTH.get(_norm_enc(encryption), 0)


def _baseline_vendors(group):
    """Which vendors in this SSID group represent the legitimate estate.

    Resolved in order:
      1. The vendor operating the most APs for this SSID — a real deployment
         usually outnumbers an impostor.
      2. Failing a clear majority, the vendor(s) running the strongest
         encryption — an attacker downgrades, they do not upgrade.
      3. Failing both, nothing is baseline. Every member is then treated as a
         deviation, which reports the ambiguity honestly instead of guessing
         which of two identical-looking APs is the real one.
    """
    counts = {}
    for ap in group:
        vendor = ap.get("vendor") or "Unknown"
        counts[vendor] = counts.get(vendor, 0) + 1

    top = max(counts.values())
    leaders = [v for v, c in counts.items() if c == top]
    if len(leaders) == 1:
        return set(leaders)

    strengths = {_strength(ap.get("encryption")) for ap in group}
    if len(strengths) > 1:
        best = max(strengths)
        return {(ap.get("vendor") or "Unknown") for ap in group
                if _strength(ap.get("encryption")) == best}

    return set()


def _encryption_split_is_expected(encryptions):
    """True when a set of encryption types is a known-legitimate coexistence."""
    distinct = {e for e in encryptions if e and e != "UNKNOWN"}
    if len(distinct) <= 1:
        return True
    for family in _TRANSITION_FAMILIES:
        if distinct <= family:
            return True
    return False


def analyze(access_points):
    """Score every AP in a scan for rogue/evil-twin indicators.

    `access_points` is a list of dicts as the scanner emits them (bssid, ssid,
    encryption, vendor, channel, rssi). Returns a dict keyed by BSSID:

        {
          "verdict": "CLEAR" | "SUSPECTED" | "LIKELY" | "CONFIRMED",
          "score": int,
          "indicators": [{"code", "weight", "detail"}],
          "peers": [other BSSIDs sharing the SSID],
          "is_evil_twin": bool,   # kept for the existing UI/DB flag
        }

    The returned `is_evil_twin` is only true at LIKELY or above, so a legitimate
    WPA3 transition deployment no longer trips the flag that reaches the report.
    """
    results = {}

    # Group by SSID. Hidden/blank SSIDs are excluded: two hidden networks sharing
    # "no name" tells us nothing.
    by_ssid = {}
    for ap in access_points:
        ssid = (ap.get("ssid") or "").strip()
        if not ssid or "<Hidden>" in ssid:
            continue
        by_ssid.setdefault(ssid, []).append(ap)

    for ap in access_points:
        bssid = ap.get("bssid", "")
        if not bssid:
            continue
        results[bssid] = {
            "verdict": "CLEAR", "score": 0, "indicators": [],
            "peers": [], "is_evil_twin": False,
        }

    for ssid, group in by_ssid.items():
        if len(group) < 2:
            # A single AP for an SSID cannot be a twin of anything. The only
            # standalone indicator worth noting is a spoofed-looking MAC, and on
            # its own that is far too weak to call anything — modern phones and
            # some APs randomise legitimately.
            continue

        encryptions = [_norm_enc(ap.get("encryption")) for ap in group]
        vendors = {(ap.get("vendor") or "Unknown") for ap in group}
        ouis = {_oui(ap.get("bssid")) for ap in group}
        channels = [ap.get("channel") for ap in group if ap.get("channel") is not None]
        rssis = [ap.get("rssi") for ap in group if isinstance(ap.get("rssi"), (int, float))]

        has_open = any(e == "OPEN" for e in encryptions)
        has_secured = any(e not in ("OPEN", "", "UNKNOWN") for e in encryptions)
        split_unexpected = not _encryption_split_is_expected(encryptions)
        known_vendors = {v for v in vendors if v and v != "Unknown" and "Randomized" not in v}
        vendor_mismatch = len(known_vendors) > 1
        multi_oui = len([o for o in ouis if o]) > 1
        max_strength = max(_strength(ap.get("encryption")) for ap in group)
        baseline = _baseline_vendors(group)

        for ap in group:
            bssid = ap.get("bssid", "")
            if not bssid:
                continue
            entry = results[bssid]
            entry["peers"] = [p.get("bssid") for p in group if p.get("bssid") != bssid]
            enc = _norm_enc(ap.get("encryption"))
            vendor = ap.get("vendor") or "Unknown"

            # Is this AP part of the apparent legitimate estate, or the odd one
            # out? Group-level indicators only attach to the odd one out.
            deviates = bool(baseline) is False or vendor not in baseline

            # The classic karma/captive attack: an open clone alongside a secured
            # network of the same name. Only the open one is suspect.
            if has_open and has_secured and enc == "OPEN":
                entry["indicators"].append({
                    "code": "open_clone_of_secured",
                    "weight": WEIGHTS["open_clone_of_secured"],
                    "detail": f"Broadcasts '{ssid}' with no encryption while another AP serves the same SSID secured.",
                })

            # Same name, different hardware vendor — the shape of a deliberate
            # clone, and the signal the old heuristic could not see at all.
            if vendor_mismatch and multi_oui and deviates:
                others = sorted(known_vendors - {vendor})
                entry["indicators"].append({
                    "code": "vendor_mismatch",
                    "weight": WEIGHTS["vendor_mismatch"],
                    "detail": (f"Serves '{ssid}' on {vendor} hardware while the rest of the SSID "
                               f"is served by {', '.join(others) if others else 'other vendors'}."),
                })

            # Only the weaker side of a split is the finding. An AP running the
            # strongest encryption in its group is not the anomaly.
            if split_unexpected and _strength(enc) < max_strength:
                if enc in ("WEP", "WPA") and any(e in ("WPA2", "WPA3") for e in encryptions):
                    entry["indicators"].append({
                        "code": "encryption_downgrade",
                        "weight": WEIGHTS["encryption_downgrade"],
                        "detail": f"Offers weaker {enc} for '{ssid}' while other APs offer WPA2/WPA3.",
                    })
                else:
                    entry["indicators"].append({
                        "code": "unexpected_encryption_split",
                        "weight": WEIGHTS["unexpected_encryption_split"],
                        "detail": (f"SSID '{ssid}' presents encryption types that are not a recognised "
                                   f"transition pair: {', '.join(sorted(set(encryptions)))}."),
                    })

            if _is_locally_administered(bssid):
                entry["indicators"].append({
                    "code": "oui_randomized",
                    "weight": WEIGHTS["oui_randomized"],
                    "detail": "BSSID is locally administered (randomised or spoofed MAC).",
                })

            # Same SSID on the same channel from different radios is unusual for a
            # planned deployment, which spaces channels to avoid co-channel noise.
            if (ap.get("channel") is not None and channels.count(ap.get("channel")) > 1
                    and multi_oui and deviates):
                entry["indicators"].append({
                    "code": "channel_conflict",
                    "weight": WEIGHTS["channel_conflict"],
                    "detail": f"Shares channel {ap.get('channel')} with another AP broadcasting '{ssid}'.",
                })

            # A clone sitting far closer than the rest of the estate.
            if len(rssis) >= 2 and isinstance(ap.get("rssi"), (int, float)):
                others = [r for r in rssis if r != ap.get("rssi")]
                if others:
                    avg_other = sum(others) / len(others)
                    if ap["rssi"] - avg_other >= 20:
                        entry["indicators"].append({
                            "code": "signal_outlier",
                            "weight": WEIGHTS["signal_outlier"],
                            "detail": (f"Signal {ap['rssi']} dBm is {round(ap['rssi'] - avg_other)} dB stronger "
                                       f"than other APs serving '{ssid}' — physically much closer."),
                        })

    for entry in results.values():
        entry["score"] = sum(i["weight"] for i in entry["indicators"])
        score = entry["score"]
        if score >= CONFIRMED_AT:
            entry["verdict"] = "CONFIRMED"
        elif score >= LIKELY_AT:
            entry["verdict"] = "LIKELY"
        elif score >= SUSPECTED_AT:
            entry["verdict"] = "SUSPECTED"
        else:
            entry["verdict"] = "CLEAR"
        # Only LIKELY and above set the flag that reaches the report.
        entry["is_evil_twin"] = entry["verdict"] in ("LIKELY", "CONFIRMED")

    return results


def describe_methodology() -> dict:
    """Machine-readable methodology, for the report's method appendix.

    A severity label a reader cannot audit is not evidence, so the thresholds and
    weights travel with the finding.
    """
    return {
        "name": "Rogue AP / Evil Twin indicator scoring",
        "version": 2,
        "weights": WEIGHTS,
        "thresholds": {
            "SUSPECTED": SUSPECTED_AT,
            "LIKELY": LIKELY_AT,
            "CONFIRMED": CONFIRMED_AT,
        },
        "reported_as_evil_twin_at": "LIKELY",
        "legitimate_encryption_pairs": [sorted(f) for f in _TRANSITION_FAMILIES],
        "limitations": [
            "Beacon-only analysis; no client-side or over-the-air authentication checks.",
            "WPA2/WPA3 transition mode and legacy mixed mode are treated as legitimate and score nothing.",
            "A competent clone that matches vendor, channel and signal may score below the reporting threshold.",
            "Hidden and blank SSIDs are excluded from twin grouping.",
        ],
    }
