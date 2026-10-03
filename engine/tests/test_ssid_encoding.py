"""Tests that a non-ASCII network name survives the scanner.

    python engine/tests/test_ssid_encoding.py
    python -m pytest engine/tests/test_ssid_encoding.py

Why this exists.

A Thai network called `ฟุฟุฟ` appeared in the report as `à¸Ÿà¸¸à¸Ÿà¸¸à¸Ÿ`.

An 802.11 SSID is 32 raw octets with no declared encoding, and in practice
everything non-ASCII is UTF-8. pywifi builds the string one byte at a time
(`pywifi/_wifiutil_win.py`):

    ssid += "%c" % networks[i].dot11Ssid.ucSSID[j]

`"%c" % n` is `chr(n)`, which is Latin-1 decoding. The three octets `E0 B8 9F`
— UTF-8 for `ฟ` — therefore arrive as three separate characters, and every
non-ASCII SSID is mangled: Thai, Chinese, Japanese, Cyrillic, and any Latin
name carrying an accent.

Three reasons that is worse than an ugly table:

  * the SSID is how the report names the network, so the document identifies
    the wrong thing to whoever has to act on it;
  * it goes into the CSV and the audit trail in that state; and
  * an engagement scope can authorise an access point **by SSID**, so an
    allowlist entry typed in Thai never matches the access point it was
    written for — the gate refuses work that was authorised.

`wps_detect.py` reads the same field straight off the beacon with
`decode('utf-8')` and gets it right, which is what settles the question of
which encoding to assume.

No radio is used: the octets are constructed here and pushed through the same
transformation pywifi performs.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.wifi import repair_ssid  # noqa: E402


def as_pywifi_sees_it(name: str) -> str:
    """Exactly what `"%c" % byte` does to a UTF-8 SSID, byte by byte."""
    return "".join("%c" % b for b in name.encode("utf-8"))


# ── The premise ─────────────────────────────────────────────────────────────

def test_the_premise_pywifi_mangles_a_thai_name():
    # If this ever stops being true, the repair below is operating on something
    # that no longer needs it, and that should be visible rather than assumed.
    mangled = as_pywifi_sees_it("ฟุฟุฟ")
    assert mangled != "ฟุฟุฟ"
    assert mangled.startswith("à¸"), repr(mangled)
    # And this is the string that was on screen.
    assert "à¸\u009f" in mangled


# ── The repair ──────────────────────────────────────────────────────────────

def test_a_thai_name_is_recovered_exactly():
    assert repair_ssid(as_pywifi_sees_it("ฟุฟุฟ")) == "ฟุฟุฟ"


def test_names_in_several_scripts_are_recovered():
    for name in (
        "ฟุฟุฟ",                 # Thai — the one that was reported
        "บ้านคุณแม่",             # Thai with tone marks and a long vowel
        "カフェ",                  # Japanese
        "办公室网络",               # Chinese
        "Сеть",                   # Cyrillic
        "Café Wi-Fi",             # Latin with an accent
        "Büro-Gast",              # German umlaut
        "MAISON—ÉTAGE 3",         # em dash and an accent
        "🛰 Satellite",            # outside the BMP
    ):
        assert repair_ssid(as_pywifi_sees_it(name)) == name, name


def test_an_ascii_name_is_returned_unchanged():
    for name in ("CORP-WIFI", "Guest", "eduroam", "TP-Link_5G", "", "  spaced  "):
        assert repair_ssid(name) == name, repr(name)


def test_an_ascii_name_is_not_even_re_encoded():
    # The fast path matters: this runs once per access point per scan cycle,
    # and the overwhelming majority of SSIDs are ASCII.
    name = "CORP-WIFI"
    assert repair_ssid(name) is name


# ── What it must not do ─────────────────────────────────────────────────────

def test_octets_that_are_not_utf8_are_left_alone():
    """A guess at another codepage would be inventing a name.

    An SSID in, say, cp874 or Shift-JIS is not UTF-8 underneath, so the decode
    fails. Keeping pywifi's version is honest: it is wrong, but it is the bytes
    that were actually broadcast, and a plausible-looking name conjured from
    the wrong codepage is worse than a visibly odd one.
    """
    thai_cp874 = "".join("%c" % b for b in "ฟุฟ".encode("cp874"))
    assert repair_ssid(thai_cp874) == thai_cp874


def test_a_lone_high_byte_is_left_alone():
    # A single 0xFF is not the start of any UTF-8 sequence.
    assert repair_ssid("ÿ") == "ÿ"
    assert repair_ssid("plainÿ") == "plainÿ"


def test_a_truncated_sequence_is_left_alone():
    # 32 octets is the SSID limit, so a multi-byte character can be cut in half
    # by the radio itself. Half a character is not decodable and must not throw.
    full = as_pywifi_sees_it("ฟุฟุฟ")
    for cut in range(1, len(full)):
        truncated = full[:cut]
        result = repair_ssid(truncated)
        assert isinstance(result, str)
        # Either it decoded cleanly, or the original came back untouched.
        assert result == truncated or result.encode("utf-8") == truncated.encode("latin-1")


def test_a_string_already_above_latin1_is_left_alone():
    """Not everything reaching this function came from pywifi.

    A name that already contains characters above U+00FF cannot have come from
    the byte-by-byte path, and `encode('latin-1')` on it would raise. It is
    returned as it is rather than being put through a transformation that was
    never meant for it.
    """
    for name in ("ฟุฟุฟ", "カフェ", "Сеть"):
        assert repair_ssid(name) == name, name


def test_repairing_twice_changes_nothing():
    # The call site is one place today, but an SSID that has already been
    # repaired must not be mangled by a second pass.
    once = repair_ssid(as_pywifi_sees_it("ฟุฟุฟ"))
    assert repair_ssid(once) == once == "ฟุฟุฟ"


def test_it_never_raises_on_anything_a_radio_could_produce():
    import random
    random.seed(20260929)
    for _ in range(300):
        raw = bytes(random.randrange(256) for _ in range(random.randrange(0, 33)))
        candidate = "".join("%c" % b for b in raw)
        result = repair_ssid(candidate)
        assert isinstance(result, str)


# ── The consequence that is not cosmetic ────────────────────────────────────

def test_a_scope_entry_in_thai_matches_the_repaired_name():
    """The security-relevant half.

    `ScopePolicy` can authorise an access point by SSID, and the operator types
    that entry in the real script. Against the mangled name it never matches,
    so an access point that *was* authorised is refused — and the audit trail
    records a block that the engagement did not intend.
    """
    from policy import ScopePolicy

    events = []
    policy = ScopePolicy(lambda event, data=None: events.append((event, data)))
    policy.load({
        "scope_id": 1,
        "engagement_name": "ACME",
        "authorized_by": "CISO",
        "operator": "nat",
        "mode": "ALLOWLIST",
        "valid_until": None,
        "targets": [{"kind": "SSID", "value": "ฟุฟุฟ"}],
    })

    mangled = as_pywifi_sees_it("ฟุฟุฟ")
    assert policy.authorize_ap("start_strike", "AA:BB:CC:DD:EE:01", ssid=mangled) is False, \
        "the premise: the mangled name does not match the scope"
    assert policy.authorize_ap("start_strike", "AA:BB:CC:DD:EE:01",
                               ssid=repair_ssid(mangled)) is True


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
