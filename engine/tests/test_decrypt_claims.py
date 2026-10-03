"""Tests for the two claims the decrypt pipeline makes about a network.

    python engine/tests/test_decrypt_claims.py
    python -m pytest engine/tests/test_decrypt_claims.py

`engine/offensive/hashcat_export.py` and `engine/offensive/decryptor.py` are 966
lines that had no test coverage at all, and they are where the pipeline's two
strongest statements are produced:

    "recovered the passphrase X"
    "exhausted the wordlist without recovering the key"

Both were being asserted from unverified material.

**The PMKID was guessed.** `_extract_pmkid_from_key_data` took the last 16 bytes
of the RSN IE — the code's own comment read "Simple heuristic ... The structure
varies" — and rejected only all-zeros. The PMKID Count field was never read. On
any access point with 802.11w (so, most of them) the IE is long enough to clear
the old length gate and the last 16 bytes are cipher-suite and capability bytes,
which were emitted as a PMKID. That is a syntactically valid hash for a capture
containing no PMKID, and hashcat then ran the whole wordlist against something
that cannot match and exited "exhausted" — so the tool reported that a network's
passphrase was not in the tested list, for a target where nothing was tested.
When a real PMKID *was* present, a trailing Group Management Cipher Suite
shifted the window by four bytes, so it was wrong then too.

**The recovered password was any non-empty remainder.** `_read_outfile` stripped
a prefix when it recognised one and reported what was left, with the acceptance
test being `if rest:`. hashcat's own error text, a line truncated mid-write, and
a four-field outfile layout all came back as passphrases. The layout was not
pinned, so which one you got depended on the installed build.

These tests fix both claims in place. No hashcat process is launched and no
capture file is needed: the hash-file parser and the outfile parser are pure
functions over bytes and strings.
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive.hashcat_export import (  # noqa: E402
    _extract_pmkid_from_key_data,
    _pmkid_from_rsn_ie,
)
from offensive.decryptor import DecryptorModule  # noqa: E402


class _SilentIPC:
    def emit(self, *a, **k):
        pass


def _rsn_body(pmkids=(), group_mgmt=True, capabilities=True):
    """An RSN IE body built to spec, so the parser is tested against real shapes."""
    b = struct.pack('<H', 1)                         # version
    b += b'\x00\x0f\xac\x04'                         # group data cipher (CCMP)
    b += struct.pack('<H', 1) + b'\x00\x0f\xac\x04'  # 1 pairwise cipher
    b += struct.pack('<H', 1) + b'\x00\x0f\xac\x02'  # 1 AKM (PSK)
    if capabilities:
        b += struct.pack('<H', 0x00cc)               # RSN capabilities (MFP bits)
    if pmkids or group_mgmt:
        b += struct.pack('<H', len(pmkids))          # PMKID count
    for p in pmkids:
        b += p
    if group_mgmt:
        b += b'\x00\x0f\xac\x06'                     # group management cipher
    return b


def _ie(body):
    return bytes([0x30, len(body)]) + body


REAL_PMKID = bytes(range(16))
REAL_HEX = REAL_PMKID.hex()


# ── The PMKID must be read, not guessed ────────────────────────────────────

def test_an_ap_with_no_pmkid_yields_no_pmkid():
    # The regression that mattered most: an 802.11w access point advertises RSN
    # capabilities and a group management cipher, which is enough length for the
    # old heuristic to return cipher-suite bytes as a PMKID.
    body = _rsn_body(pmkids=(), group_mgmt=True)
    assert len(body) >= 24, "fixture must be long enough to have tripped the old gate"
    assert _extract_pmkid_from_key_data(_ie(body)) is None


def test_a_real_pmkid_is_read_exactly_even_with_fields_after_it():
    # A group management cipher suite follows the PMKID list, which shifted the
    # old last-16-bytes window by four.
    body = _rsn_body(pmkids=(REAL_PMKID,), group_mgmt=True)
    assert _extract_pmkid_from_key_data(_ie(body)) == REAL_HEX


def test_a_real_pmkid_is_read_when_it_is_last():
    body = _rsn_body(pmkids=(REAL_PMKID,), group_mgmt=False)
    assert _extract_pmkid_from_key_data(_ie(body)) == REAL_HEX


def test_a_pmkid_count_of_zero_is_honoured():
    # The field exists and says none. That is an answer, not a reason to look
    # elsewhere in the buffer.
    body = _rsn_body(pmkids=(), group_mgmt=False)
    assert _pmkid_from_rsn_ie(body) is None


def test_an_ie_that_ends_before_the_pmkid_count_yields_none():
    body = _rsn_body(pmkids=(), group_mgmt=False, capabilities=False)
    assert _pmkid_from_rsn_ie(body) is None


def test_an_all_zero_pmkid_is_a_placeholder_not_a_value():
    body = _rsn_body(pmkids=(bytes(16),), group_mgmt=False)
    assert _extract_pmkid_from_key_data(_ie(body)) is None


def test_a_count_that_promises_bytes_the_ie_does_not_have_yields_none():
    # Truncated capture. Reading whatever follows is how a hash gets fabricated.
    body = _rsn_body(pmkids=(REAL_PMKID,), group_mgmt=False)
    assert _pmkid_from_rsn_ie(body[:-8]) is None


def test_multiple_pmkids_return_the_first():
    other = bytes([0xAA] * 16)
    body = _rsn_body(pmkids=(REAL_PMKID, other), group_mgmt=True)
    assert _extract_pmkid_from_key_data(_ie(body)) == REAL_HEX


def test_several_pairwise_and_akm_suites_do_not_shift_the_read():
    # Variable-length lists are exactly what a fixed offset cannot survive.
    b = struct.pack('<H', 1) + b'\x00\x0f\xac\x04'
    b += struct.pack('<H', 3) + b'\x00\x0f\xac\x04' * 3
    b += struct.pack('<H', 2) + b'\x00\x0f\xac\x02' * 2
    b += struct.pack('<H', 0x00cc)
    b += struct.pack('<H', 1) + REAL_PMKID
    b += b'\x00\x0f\xac\x06'
    assert _pmkid_from_rsn_ie(b) == REAL_HEX


def test_garbage_and_empty_key_data_yield_none():
    for blob in (b'', b'\x30', b'\x30\x40ab', b'\xff' * 40, bytes(64)):
        assert _extract_pmkid_from_key_data(blob) is None


def test_a_tag_length_running_past_the_buffer_yields_none():
    # Declared length longer than what is there.
    assert _extract_pmkid_from_key_data(b'\x30\x50' + b'\x00' * 8) is None


def test_the_rsn_ie_is_found_after_other_elements():
    filler = bytes([0xDD, 4]) + b'\x01\x02\x03\x04'      # vendor specific
    body = _rsn_body(pmkids=(REAL_PMKID,), group_mgmt=True)
    assert _extract_pmkid_from_key_data(filler + _ie(body)) == REAL_HEX


# ── A recovered password must be attributable to this run ──────────────────

HASH = 'WPA*02*abc*001122334455*aabbccddeeff*4d794e6574*d*e*f'


def _outfile(content):
    """Run _read_outfile against a file holding `content`."""
    d = DecryptorModule(_SilentIPC())
    with tempfile.TemporaryDirectory() as t:
        p = os.path.join(t, 'cracked.txt')
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(content)
        return d._read_outfile(p, [HASH])


def test_a_well_formed_line_reports_its_passphrase():
    results, unparsed = _outfile(f'{HASH}:Summer2024!\n')
    assert unparsed == []
    assert [r['password'] for r in results] == ['Summer2024!']


def test_a_passphrase_containing_colons_survives_intact():
    # A passphrase may contain ':'. Splitting on sight would corrupt it, so the
    # hash prefix is what bounds the field — not the first colon.
    results, unparsed = _outfile(f'{HASH}:my:pass:word\n')
    assert unparsed == []
    assert results[0]['password'] == 'my:pass:word'


def test_hashcat_error_text_is_not_a_passphrase():
    # This was reported as the recovered password, into the report and into
    # cracking_history.
    results, unparsed = _outfile(
        "Hashfile 'capture.hc22000' on line 2: Token length exception\n"
    )
    assert results == []
    assert len(unparsed) == 1


def test_a_line_truncated_mid_write_is_refused():
    results, unparsed = _outfile(f'{HASH}:\n')
    assert results == []
    assert len(unparsed) == 1


def test_a_hash_from_another_run_is_refused():
    other = 'WPA*02*OTHER*001122334455*aabbccddeeff*4d794e6574*d*e*f'
    results, unparsed = _outfile(f'{other}:Summer2024!\n')
    assert results == []
    assert len(unparsed) == 1


def test_a_bare_plaintext_line_is_refused():
    # What an unpinned `--outfile-format` could produce. Without a hash prefix
    # there is nothing to attribute the passphrase to.
    results, unparsed = _outfile('Summer2024!\n')
    assert results == []
    assert len(unparsed) == 1


def test_a_four_field_layout_is_refused_rather_than_mis_split():
    # `<hash>:<plain>:<hex_plain>:<crack_pos>`. The command pins
    # `--outfile-format 1,2`; if a build ignores that, our assumption about the
    # shape is void and guessing produced
    # "Summer2024!:53756d6d657232303234:0" as a password.
    plain = 'Summer2024!'
    results, unparsed = _outfile(f'{HASH}:{plain}:{plain.encode().hex()}:0\n')
    assert results == []
    assert len(unparsed) == 1


def test_the_network_comes_from_the_matched_hash():
    # Identity is read out of the hash line the outfile pointed at, so a
    # passphrase cannot be attributed to a different access point in the same
    # capture.
    results, _ = _outfile(f'{HASH}:pw\n')
    assert results[0]['bssid'] is not None
    assert results[0]['essid'] is not None


def test_a_missing_or_unreadable_outfile_is_not_a_result():
    d = DecryptorModule(_SilentIPC())
    assert d._read_outfile(None, [HASH]) == ([], [])
    with tempfile.TemporaryDirectory() as t:
        assert d._read_outfile(os.path.join(t, 'nope.txt'), [HASH]) == ([], [])


def test_blank_lines_are_ignored_without_becoming_refusals():
    results, unparsed = _outfile(f'\n\n{HASH}:pw\n\n')
    assert [r['password'] for r in results] == ['pw']
    assert unparsed == []


def test_several_cracks_are_all_reported():
    h2 = 'WPA*02*def*001122334455*aabbccddeeff*4f74686572*d*e*f'
    d = DecryptorModule(_SilentIPC())
    with tempfile.TemporaryDirectory() as t:
        p = os.path.join(t, 'c.txt')
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(f'{HASH}:one\n{h2}:two\n')
        results, unparsed = d._read_outfile(p, [HASH, h2])
    assert sorted(r['password'] for r in results) == ['one', 'two']
    assert unparsed == []


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
