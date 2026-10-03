"""Tests for the TLS inspection module's claims.

    python engine/tests/test_ssl_check.py
    python -m pytest engine/tests/test_ssl_check.py

Why this exists.

`ssl_check.py` had no tests and four ways of stating something it had not
observed. It is not yet reachable from the UI, so none of this has reached a
report — which is exactly why it is worth fixing now rather than after someone
wires the panel.

1. **HSTS was reported as disabled on any failure.** `check_hsts` returned
   `{"enabled": False}` for a refused connection, a timeout, a bad handshake, a
   host that does not exist. `deep_ssl_scan` turned that into a MEDIUM finding:
   "HSTS not enabled. Susceptible to SSL stripping attacks." A remediation task,
   for a server the tool never spoke to.

2. **Deprecated TLS acceptance was tested with `except OSError: pass  # Good —
   server refused`.** `OSError` covers connection refused, timeout, reset and
   unreachable, so a host that was down produced an empty list, and the report
   credited it with refusing TLS 1.0 and 1.1. On a modern OpenSSL the *client*
   usually cannot offer those protocols at all, which produced the same false
   pass — on most installs, not as an edge case.

3. **SHA-1 was detected by searching the whole DER for eleven OID bytes.** Those
   bytes can appear inside a modulus, an extension, an embedded SCT; their
   presence somewhere in the file does not make them the signature algorithm.
   The same shape as reading a PMKID off the tail of an information element: a
   confident HIGH finding from a substring match. It also missed SHA-1 with
   ECDSA or DSA entirely.

4. **`expired` and `self_signed` defaulted to False**, so a host that refused
   the connection came back looking like one with a valid CA-issued certificate;
   and `self_signed` compared four fields that are all empty on a partially
   parsed certificate, making `"" == ""` into a MEDIUM finding.

No networking: the DER parsing is exercised on constructed bytes, and the
failure paths on stubbed sockets.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import ssl_check  # noqa: E402


# ── DER helpers, to build certificates by hand ──────────────────────────────

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, value):
    return bytes([tag]) + _der_len(len(value)) + value


def _seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunks = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunks.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body += bytes(reversed(chunks))
    return _tlv(0x06, body)


def _certificate(sig_oid_dotted, tbs_extra=b""):
    """A minimal Certificate whose signatureAlgorithm is `sig_oid_dotted`."""
    tbs = _seq(_tlv(0x02, b"\x01"), tbs_extra)
    algid = _seq(_oid(sig_oid_dotted), _tlv(0x05, b""))
    signature = _tlv(0x03, b"\x00" + b"\xab" * 16)
    return _seq(tbs, algid, signature)


SHA256_RSA = "1.2.840.113549.1.1.11"
SHA1_RSA = "1.2.840.113549.1.1.5"
SHA1_ECDSA = "1.2.840.10045.4.1"


# ── OID decoding ────────────────────────────────────────────────────────────

def test_oid_round_trips_through_the_decoder():
    for dotted in (SHA256_RSA, SHA1_RSA, SHA1_ECDSA, "1.2.840.10040.4.3", "1.3.14.3.2.29"):
        raw = _oid(dotted)
        decoded = ssl_check._oid_to_string(raw[2:])
        assert decoded == dotted, f"{dotted} -> {decoded}"


def test_a_truncated_oid_decodes_to_none_rather_than_a_wrong_number():
    # Last byte with the continuation bit set means more bytes were expected.
    assert ssl_check._oid_to_string(b"\x2a\x86\x48\x86") is None
    assert ssl_check._oid_to_string(b"") is None
    assert ssl_check._oid_to_string(None) is None


# ── Length parsing ──────────────────────────────────────────────────────────

def test_short_and_long_form_lengths_are_both_read():
    short = _tlv(0x04, b"x" * 10)
    tag, start, end = ssl_check._read_tlv(short, 0)
    assert (tag, end - start) == (0x04, 10)

    long = _tlv(0x04, b"x" * 300)
    tag, start, end = ssl_check._read_tlv(long, 0)
    assert (tag, end - start) == (0x04, 300)


def test_a_truncated_value_is_rejected_rather_than_read_past_the_buffer():
    # Declares 100 bytes, carries 3.
    assert ssl_check._read_tlv(b"\x04\x64abc", 0) is None


def test_the_indefinite_length_form_is_rejected():
    # 0x80 is BER's indefinite form and is not legal DER. Accepting it would
    # mean walking a structure whose extent is unknown.
    assert ssl_check._read_tlv(b"\x30\x80\x00\x00", 0) is None


def test_an_absurd_length_prefix_is_rejected():
    assert ssl_check._read_tlv(b"\x04\x88" + b"\xff" * 8, 0) is None


# ── Signature algorithm ─────────────────────────────────────────────────────

def test_the_signature_algorithm_is_read_from_the_field_that_holds_it():
    assert ssl_check.signature_algorithm_oid(_certificate(SHA256_RSA)) == SHA256_RSA
    assert ssl_check.signature_algorithm_oid(_certificate(SHA1_RSA)) == SHA1_RSA


def test_the_sha1_oid_appearing_elsewhere_is_not_a_sha1_signature():
    # This is the defect, reproduced: the SHA-1 OID bytes are placed inside the
    # tbsCertificate — where they could plausibly sit in a key or an extension
    # — while the actual signatureAlgorithm is SHA-256. The old substring search
    # raised a HIGH finding on this certificate.
    der = _certificate(SHA256_RSA, tbs_extra=_tlv(0x04, _oid(SHA1_RSA)))
    assert _oid(SHA1_RSA) in der, "the bytes really are present in the file"
    assert ssl_check.signature_algorithm_oid(der) == SHA256_RSA
    assert ssl_check.signature_algorithm_oid(der) not in ssl_check._SHA1_SIGNATURE_OIDS


def test_sha1_with_ecdsa_and_dsa_are_recognised():
    # The substring search looked for one RSA OID, so these were invisible.
    for dotted in (SHA1_ECDSA, "1.2.840.10040.4.3"):
        assert ssl_check.signature_algorithm_oid(_certificate(dotted)) in ssl_check._SHA1_SIGNATURE_OIDS


def test_garbage_yields_none_not_a_verdict():
    for der in (b"", b"\x00", b"not a certificate", None, _tlv(0x04, b"just an octet string")):
        assert ssl_check.signature_algorithm_oid(der) is None


def test_a_certificate_missing_its_algorithm_identifier_yields_none():
    # Two elements where three are required.
    der = _seq(_seq(_tlv(0x02, b"\x01")), _tlv(0x03, b"\x00\xab"))
    assert ssl_check.signature_algorithm_oid(der) is None


# ── HSTS ────────────────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, headers):
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _with_urlopen(fn):
    original = ssl_check.urllib.request.urlopen
    ssl_check.urllib.request.urlopen = fn
    try:
        return ssl_check.check_hsts("10.0.0.1")
    finally:
        ssl_check.urllib.request.urlopen = original


def test_hsts_present_is_reported_with_its_value():
    r = _with_urlopen(lambda *a, **k: _FakeResponse({"Strict-Transport-Security": "max-age=31536000"}))
    assert r["enabled"] is True
    assert r["value"] == "max-age=31536000"


def test_hsts_absent_from_a_real_answer_is_a_finding():
    r = _with_urlopen(lambda *a, **k: _FakeResponse({}))
    assert r["enabled"] is False, "the server answered and the header was not there"
    assert r["error"] is None


def test_a_failed_request_is_unknown_and_not_absent():
    # The whole point. This used to be enabled=False, which deep_ssl_scan then
    # turned into "HSTS not enabled — susceptible to SSL stripping".
    def refuse(*a, **k):
        raise ConnectionRefusedError("refused")

    r = _with_urlopen(refuse)
    assert r["enabled"] is None
    assert "ConnectionRefusedError" in r["error"]


def test_a_timeout_is_unknown_too():
    def timeout(*a, **k):
        raise TimeoutError("timed out")

    assert _with_urlopen(timeout)["enabled"] is None


def test_an_http_error_response_still_counts_as_an_answer():
    # A 401 on an admin console is an answer from the server, and it carries the
    # header. Treating it as a failed measurement would lose a real observation.
    import urllib.error

    def unauthorised(*a, **k):
        raise urllib.error.HTTPError(
            "https://10.0.0.1/", 401, "Unauthorized",
            {"Strict-Transport-Security": "max-age=600"}, None
        )

    r = _with_urlopen(unauthorised)
    assert r["enabled"] is True
    assert r["value"] == "max-age=600"


# ── Deprecated TLS ──────────────────────────────────────────────────────────

def _with_connect(raiser):
    original = ssl_check.socket.create_connection
    ssl_check.socket.create_connection = raiser
    try:
        return ssl_check.check_deprecated_tls("10.0.0.1")
    finally:
        ssl_check.socket.create_connection = original


def test_an_unreachable_host_leaves_both_versions_untested():
    # The defect: `except OSError: pass  # Good — server refused`. A host that
    # is down does not refuse anything.
    def refuse(*a, **k):
        raise ConnectionRefusedError("refused")

    r = _with_connect(refuse)
    assert r["accepted"] == []
    assert r["refused"] == [], "nothing was refused; nothing was reached"
    assert len(r["untested"]) == 2, r
    assert all("could not connect" in u["reason"] or "cannot offer" in u["reason"]
               for u in r["untested"]), r["untested"]


def test_a_timeout_leaves_the_version_untested_rather_than_refused():
    def timeout(*a, **k):
        raise TimeoutError("timed out")

    r = _with_connect(timeout)
    assert r["refused"] == []
    assert len(r["untested"]) == 2


def test_the_three_lists_are_always_present():
    def refuse(*a, **k):
        raise ConnectionRefusedError("refused")

    r = _with_connect(refuse)
    assert set(r) == {"accepted", "refused", "untested"}


# ── deep_ssl_scan composition ───────────────────────────────────────────────

def _stub_deep(cert=None, tls=None, ciphers=None, hsts=None):
    originals = (ssl_check.check_certificate, ssl_check.check_deprecated_tls,
                 ssl_check.check_weak_ciphers, ssl_check.check_hsts)
    ssl_check.check_certificate = lambda *a, **k: (cert if cert is not None else
                                                   {"findings": [], "ip": "10.0.0.1"})
    ssl_check.check_deprecated_tls = lambda *a, **k: (tls if tls is not None else
                                                      {"accepted": [], "refused": [], "untested": []})
    ssl_check.check_weak_ciphers = lambda *a, **k: (ciphers if ciphers is not None else
                                                    {"weak": [], "strong": [], "error": None,
                                                     "caveat": "negotiated only"})
    ssl_check.check_hsts = lambda *a, **k: (hsts if hsts is not None else
                                            {"enabled": True, "value": "max-age=1", "error": None})
    try:
        return ssl_check.deep_ssl_scan("10.0.0.1")
    finally:
        (ssl_check.check_certificate, ssl_check.check_deprecated_tls,
         ssl_check.check_weak_ciphers, ssl_check.check_hsts) = originals


def _findings_text(report):
    return " | ".join(f.get("finding", "") for f in report["findings"])


def test_an_unknown_hsts_state_raises_no_finding():
    report = _stub_deep(hsts={"enabled": None, "value": None, "error": "ConnectionRefusedError: refused"})
    assert "HSTS" not in _findings_text(report), report["findings"]
    assert any(i["check"] == "hsts" for i in report["inconclusive"]), report["inconclusive"]


def test_hsts_genuinely_absent_still_raises_a_finding():
    report = _stub_deep(hsts={"enabled": False, "value": None, "error": None})
    assert "HSTS not enabled" in _findings_text(report)


def test_an_untested_tls_version_is_named_rather_than_passed_over():
    report = _stub_deep(tls={
        "accepted": [], "refused": [],
        "untested": [{"version": "TLSv1.0", "reason": "this client cannot offer TLSv1.0"}],
    })
    assert "Deprecated" not in _findings_text(report)
    assert any(i["check"] == "deprecated_tls/TLSv1.0" for i in report["inconclusive"])


def test_an_accepted_deprecated_version_is_a_high_finding():
    report = _stub_deep(tls={
        "accepted": [{"version": "TLSv1.0", "negotiated": "TLSv1"}],
        "refused": [], "untested": [],
    })
    high = [f for f in report["findings"] if f["severity"] == "HIGH"]
    assert len(high) == 1 and "TLSv1.0" in high[0]["finding"]


def test_the_cipher_caveat_always_travels_with_the_result():
    # An empty `weak` list means "the one suite we negotiated was strong", not
    # "no weak suites are enabled". If that distinction is not in the payload it
    # cannot be in the report.
    report = _stub_deep()
    assert any(i["check"] == "cipher_audit/enumeration" for i in report["inconclusive"]), \
        report["inconclusive"]


def test_a_failed_cipher_check_is_inconclusive_not_clean():
    report = _stub_deep(ciphers={"weak": [], "strong": [], "error": "timed out", "caveat": "x"})
    assert any(i["check"] == "cipher_audit" and i["reason"] == "timed out"
               for i in report["inconclusive"])


def test_the_placeholder_ok_finding_does_not_sit_beside_real_ones():
    report = _stub_deep(
        cert={"findings": [{"severity": "OK", "finding": "Certificate appears valid"}]},
        hsts={"enabled": False, "value": None, "error": None},
    )
    assert all(f["severity"] != "OK" for f in report["findings"]), report["findings"]


def test_a_clean_scan_keeps_its_ok_finding():
    report = _stub_deep(cert={"findings": [{"severity": "OK", "finding": "Certificate appears valid"}]})
    assert [f["severity"] for f in report["findings"]] == ["OK"]


# ── Defaults ────────────────────────────────────────────────────────────────

def test_an_unreachable_host_does_not_look_like_a_valid_certificate():
    original = ssl_check.socket.create_connection

    def refuse(*a, **k):
        raise ConnectionRefusedError("refused")

    ssl_check.socket.create_connection = refuse
    try:
        info = ssl_check.check_certificate("10.0.0.1")
    finally:
        ssl_check.socket.create_connection = original

    # These were False by default, which reads as "checked, and fine".
    assert info["expired"] is None
    assert info["self_signed"] is None
    assert info["signature_algorithm"] is None
    assert info["findings"], "the failure itself must be reported"


# -- A certificate that cannot be parsed must not void the other checks ------

#: Any non-empty DER is enough. The module only needs `der` to be truthy to
#: reach the signature-algorithm branch; nothing here asserts on its contents.
_SOME_DER = bytes([0x30, 0x82, 0x01, 0x0A])


class _FakeSSock:
    """A TLS socket whose certificate will not parse into a dict."""

    def __init__(self, version, cipher, der):
        self._version = version
        self._cipher = cipher
        self._der = der

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def version(self):
        return self._version

    def cipher(self):
        return self._cipher

    def getpeercert(self, binary_form=False):
        # The real CERT_NONE behaviour this module's own comment records: the
        # DER is there, the parsed dict is empty.
        return self._der if binary_form else {}


class _FakeSock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _check_with_unparseable_cert(version="TLSv1", cipher=("AES256-SHA", "TLSv1", 256)):
    """
    Drive `check_certificate` against a self-signed host.

    The first connection succeeds and hands back an empty parsed certificate;
    the CERT_REQUIRED retry raises, which is what any self-signed or
    internal-CA certificate does on a machine that does not trust the issuer.
    """
    orig_conn = ssl_check.socket.create_connection
    orig_ctx = ssl_check.ssl.SSLContext
    calls = {"n": 0}

    def create_connection(*a, **k):
        calls["n"] += 1
        if calls["n"] > 1:
            raise ssl_check.ssl.SSLCertVerificationError("self signed certificate")
        return _FakeSock()

    class FakeContext:
        def __init__(self, *a, **k):
            self.check_hostname = False
            self.verify_mode = None
            self.minimum_version = None

        def load_default_certs(self):
            pass

        def wrap_socket(self, sock, server_hostname=None):
            return _FakeSSock(version, cipher, _SOME_DER)

    ssl_check.socket.create_connection = create_connection
    ssl_check.ssl.SSLContext = FakeContext
    try:
        return ssl_check.check_certificate("10.0.0.7")
    finally:
        ssl_check.socket.create_connection = orig_conn
        ssl_check.ssl.SSLContext = orig_ctx


def test_an_unparseable_certificate_does_not_raise_into_the_error_handler():
    """
    `not_before` was bound inside `if cert:` and read outside it.

    Every self-signed host therefore raised `NameError: not_before` into the
    blanket `except Exception`, which recorded the crash as an INFO finding.
    """
    info = _check_with_unparseable_cert()
    crashes = [f for f in info["findings"]
               if "not defined" in str(f.get("finding", ""))
               or "not_before" in str(f.get("finding", ""))]
    assert not crashes, "the scan crashed and logged it as a finding: %r" % (crashes,)


def test_a_weak_protocol_is_still_reported_when_the_certificate_will_not_parse():
    """
    The real cost of the NameError: four checks sit after the line that raised.

    A self-signed appliance on TLSv1 reported the self-signed MEDIUM and an INFO
    about an undefined name, and the report read "no weak protocol" about a host
    this check never ran against.
    """
    info = _check_with_unparseable_cert(version="TLSv1")
    weak = [f for f in info["findings"] if "Weak protocol" in str(f.get("finding", ""))]
    assert weak, "TLSv1 was not reported; findings were %r" % (info["findings"],)
    assert weak[0]["severity"] == "HIGH"


def test_a_weak_cipher_is_still_reported_when_the_certificate_will_not_parse():
    info = _check_with_unparseable_cert(
        version="TLSv1.2", cipher=("DES-CBC3-SHA", "TLSv1.2", 112))
    weak = [f for f in info["findings"] if "Weak cipher" in str(f.get("finding", ""))]
    assert weak, "a 112-bit cipher was not reported; findings were %r" % (info["findings"],)


def test_the_self_signed_finding_is_not_lost_either():
    """The one finding that did survive has to keep surviving."""
    info = _check_with_unparseable_cert()
    assert any("Self-signed or untrusted" in str(f.get("finding", ""))
               for f in info["findings"])


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
