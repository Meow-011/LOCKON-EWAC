"""Tests for the shared Wi-Fi frequency helpers.

    python engine/tests/test_rf.py
    python -m pytest engine/tests/test_rf.py

The benchmark and the scanner used to derive channels with different formulas,
and only one of them normalized kHz. On Windows (which reports 2412000) the
benchmark recorded channel 481210, so its channel histogram was meaningless.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rf import normalize_freq, freq_to_band, freq_to_channel  # noqa: E402


def test_normalize_handles_khz_and_mhz():
    assert normalize_freq(2412) == 2412
    assert normalize_freq(2412000) == 2412      # Windows native API reports kHz
    assert normalize_freq(5180000) == 5180


def test_normalize_rejects_unusable_values():
    for bad in (None, 0, -1, "", "abc"):
        assert normalize_freq(bad) is None


def test_24ghz_channels():
    assert freq_to_channel(2412) == 1
    assert freq_to_channel(2437) == 6
    assert freq_to_channel(2462) == 11
    assert freq_to_channel(2484) == 14          # Japan, irregular spacing


def test_5ghz_channels():
    assert freq_to_channel(5180) == 36
    assert freq_to_channel(5320) == 64
    assert freq_to_channel(5745) == 149


def test_6ghz_channels():
    assert freq_to_channel(5955) == 1
    assert freq_to_channel(6175) == 45


def test_khz_input_gives_the_same_channel_as_mhz():
    # The exact regression that produced channel 481210.
    assert freq_to_channel(2412000) == freq_to_channel(2412) == 1
    assert freq_to_channel(5180000) == freq_to_channel(5180) == 36


def test_unknown_frequency_returns_none_rather_than_guessing():
    # The old benchmark defaulted a missing frequency to channel 1, which put
    # invented 2.4 GHz readings into the spectrum histogram.
    assert freq_to_channel(None) is None
    assert freq_to_channel(0) is None
    assert freq_to_channel(3000) is None


def test_bands():
    assert freq_to_band(2437) == "2.4G"
    assert freq_to_band(5180) == "5G"
    assert freq_to_band(5955) == "6G"
    assert freq_to_band(None) is None


# -- Units out by a thousand, and channels below one --------------------------

"""
Two things this module's docstring already promised and did not deliver.

`normalize_freq` divided by 1000 exactly once, so a driver reporting Hz --
2412000000 -- became 2412000 and was returned as "MHz". `freq_to_channel` then took
the 6 GHz branch and produced 481210: the number the docstring says this module exists
to prevent, reproduced one unit further out than the case it was written for.

And the 6 GHz channel formula was unguarded. Channel n is centred at 5950 + 5n with n
starting at 1, so the band's lowest frequencies sit *below* the anchor: 5935 MHz came
back as -3 and 5950 as 0, while `freq_to_band` correctly called both "6G". A negative
channel is worse than the None this function already promises for a frequency it
cannot place.
"""


def test_a_driver_reporting_hz_is_normalised_all_the_way():
    assert normalize_freq(2412000000) == 2412.0
    assert normalize_freq(5180000000) == 5180.0


def test_the_channel_from_a_hz_frequency_is_the_real_channel():
    # The regression in the docstring: this used to be 481210.
    assert freq_to_channel(2412000000) == 1
    assert freq_to_channel(5180000000) == 36


def test_khz_still_normalises_as_it_did():
    assert normalize_freq(2412000) == 2412.0
    assert freq_to_channel(2412000) == 1


def test_a_value_that_is_not_a_frequency_at_any_scale_is_refused():
    # Dividing is bounded; a value still out of range afterwards is unusable, and
    # None is the answer this module already prefers to a guess.
    assert normalize_freq(99999999999) is None
    assert freq_to_channel(99999999999) is None


def test_a_frequency_below_the_wifi_bands_is_refused():
    assert normalize_freq(900) is None


def test_six_gigahertz_channels_are_never_negative():
    # 5935 is a real 6 GHz frequency and used to come back as channel -3.
    for mhz in (5935, 5940, 5945, 5950):
        ch = freq_to_channel(mhz)
        assert ch is None or ch >= 1, f"{mhz} MHz gave channel {ch}"


def test_the_six_gigahertz_channel_two_exception_is_handled():
    """
    Channel 2 is defined against a 5925 MHz starting frequency, not 5950.

    IEEE 802.11ax-2021 Annex E: 20 MHz channels are centred at `5950 + 5n` for
    n = 1, 5, 9 ... 233, and channel 2 is a deliberate exception at
    `5925 + 5*2 = 5935` -- below the anchor every other channel is measured from.
    It is the reason the unguarded formula produced a negative number at all.
    """
    assert freq_to_channel(5935) == 2


def test_the_anchor_itself_is_not_a_channel():
    # 5950 is the channel starting frequency, not a channel centre. n = 0 does not
    # exist in the numbering, and None is the answer this module promises for a
    # frequency it cannot place.
    assert freq_to_channel(5950) is None


def test_the_rest_of_the_six_gigahertz_plan_matches_the_standard():
    # Spot checks across the band, from Annex E.
    assert freq_to_channel(5975) == 5
    assert freq_to_channel(5995) == 9
    assert freq_to_channel(7115) == 233


def test_the_six_gigahertz_channels_that_can_be_placed_are_correct():
    # Channel n is centred at 5950 + 5n.
    assert freq_to_channel(5955) == 1
    assert freq_to_channel(6175) == 45


def test_the_band_and_the_channel_no_longer_contradict_each_other():
    """
    `freq_to_band` called 5935 "6G" while `freq_to_channel` returned -3.

    A figure keyed by one and labelled by the other is the shape this module was
    extracted to prevent.
    """
    # 5935 is now placed as channel 2, so the band and the channel agree on it.
    assert freq_to_band(5935) == "6G"
    assert freq_to_channel(5935) == 2
    # 5950 is the anchor: "6G" is right about the band, and there is no channel
    # there to name. Both statements are true, and neither is a negative number.
    assert freq_to_band(5950) == "6G"
    assert freq_to_channel(5950) is None


def test_the_ordinary_bands_are_untouched():
    # The fix must not move any channel that was already right.
    assert freq_to_channel(2412) == 1
    assert freq_to_channel(2437) == 6
    assert freq_to_channel(2484) == 14
    assert freq_to_channel(5180) == 36
    assert freq_to_channel(5500) == 100


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
