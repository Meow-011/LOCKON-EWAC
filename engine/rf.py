"""LOCKON EWAC — Wi-Fi frequency helpers

Shared so the scanner and the antenna benchmark cannot disagree about what
channel a frequency is. They used to: the benchmark skipped the kHz->MHz
normalization and used a different 2.4 GHz formula, so on Windows (which
commonly reports 2412000) it recorded channel 481210.
"""


#: Above this a value cannot be a Wi-Fi frequency in MHz. Wi-Fi 6E ends at 7125.
MAX_PLAUSIBLE_MHZ = 7250.0
#: Below this it cannot be one either; the lowest 2.4 GHz channel is 2412.
MIN_PLAUSIBLE_MHZ = 2000.0


def normalize_freq(freq):
    """Return the frequency in MHz, or None if unusable.

    Windows' native Wi-Fi API often reports kHz (2412000) where PyWiFi's own
    attribute is MHz (2412), and some drivers report nothing at all.
    """
    try:
        value = float(freq)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    # Divided until it is plausible, and bounded afterwards.
    #
    # This was a single unconditional division, so a driver reporting Hz --
    # 2412000000 -- became 2412000 and was returned as "MHz". `freq_to_channel`
    # then took the 6 GHz branch and produced 481210: the exact number this
    # module's docstring says it exists to prevent, reproduced one unit further
    # out than the case it was written for.
    #
    # Wi-Fi 6E tops out at 7125 MHz, so MAX_PLAUSIBLE_MHZ is the ceiling above
    # which a value cannot be a frequency this tool can reason about. A value
    # still out of range after dividing is unusable, and None is the honest
    # answer -- the one this module already chose over a fabricated channel 1.
    for _ in range(4):
        if value <= MAX_PLAUSIBLE_MHZ:
            break
        value = value / 1000
    if value > MAX_PLAUSIBLE_MHZ or value < MIN_PLAUSIBLE_MHZ:
        return None
    return value


def freq_to_band(freq):
    """'2.4G' | '5G' | '6G', or None when the frequency is unknown."""
    mhz = normalize_freq(freq)
    if mhz is None:
        return None
    if mhz >= 5925:
        return "6G"
    if mhz >= 4900:
        return "5G"
    return "2.4G"


def freq_to_channel(freq):
    """Channel number for a frequency, or None when it cannot be derived.

    Returns None rather than a guess: a fabricated channel 1 for every AP whose
    driver reported no frequency made the benchmark's channel histogram lie
    about the spectrum.
    """
    mhz = normalize_freq(freq)
    if mhz is None:
        return None
    if mhz >= 5925:
        # 6 GHz, per IEEE 802.11ax-2021 Annex E.
        #
        # Two anchors, not one. The 20 MHz channels are centred at
        # `5950 + 5n` for n = 1, 5, 9, ... 233 -- and channel 2 is a deliberate
        # exception, defined against a channel starting frequency of 5925 MHz, so
        # it sits at `5925 + 5*2 = 5935`, *below* the 5950 anchor every other
        # channel is measured from.
        #
        # The formula was applied unguarded with only the 5950 anchor, so the one
        # channel that does not use it came back negative: 5935 MHz returned -3,
        # and 5950 -- which is the anchor itself and not a channel centre at all
        # -- returned 0. `freq_to_band` meanwhile called both "6G", so the band
        # and the channel contradicted each other.
        #
        # Channel 2 is named explicitly rather than derived, because it is an
        # exception in the standard and not a pattern.
        if mhz == 5935:
            return 2
        channel = int(round((mhz - 5950) / 5))
        # n = 0 is the anchor, and anything below it is not in the band's
        # numbering. None is what this function already promises for a frequency
        # it cannot place, and it is a better answer than an invented channel.
        return channel if channel >= 1 else None
    if mhz >= 5000:
        return int((mhz - 5000) // 5)
    if 2412 <= mhz <= 2484:
        if mhz == 2484:
            return 14
        return int((mhz - 2412) // 5 + 1)
    return None
