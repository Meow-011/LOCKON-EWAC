"""LOCKON EWAC — SSL/TLS Certificate Analyzer
Inspects certificates on HTTPS services to detect security misconfigurations.
"""
import ssl
import socket
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone

logger = logging.getLogger("SSLCheck")


# ── Signature algorithm, read from the certificate structure ────────────────
#
# SHA-1 used to be detected by searching the whole DER for the
# sha1WithRSAEncryption OID bytes:
#
#     if b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05' in der: ...HIGH
#
# Eleven bytes can appear anywhere in a certificate — inside a public key
# modulus, an extension value, an embedded signed certificate timestamp — and
# their presence anywhere does not make them the *signature algorithm*. It is
# the same defect as reading a PMKID off the tail of an information element:
# a confident HIGH finding produced by a substring match. It also missed
# SHA-1 with ECDSA or DSA entirely, because those are different OIDs.
#
# So the field is read from where the structure says it is. X.509 (RFC 5280):
#
#     Certificate ::= SEQUENCE {
#         tbsCertificate       TBSCertificate,
#         signatureAlgorithm   AlgorithmIdentifier,   <- this one
#         signatureValue       BIT STRING }
#
#     AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, ... }

_SHA1_SIGNATURE_OIDS = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10040.4.3": "dsa-with-SHA1",
    "1.3.14.3.2.29": "sha1WithRSASignature",
    "1.3.14.3.2.27": "dsaWithSHA1",
}


def _read_tlv(data, offset):
    """One DER tag-length-value at `offset` -> (tag, value_start, value_end).

    None for anything malformed, truncated, or using an indefinite or
    absurdly long length. Certificates are definite-length by rule.
    """
    if data is None or offset < 0 or offset + 2 > len(data):
        return None
    tag = data[offset]
    length_byte = data[offset + 1]
    if length_byte < 0x80:
        length = length_byte
        header = 2
    else:
        count = length_byte & 0x7F
        # 0 is the indefinite form (not legal in DER); >4 would be a length no
        # certificate has, and is the shape a truncated buffer takes.
        if count == 0 or count > 4 or offset + 2 + count > len(data):
            return None
        length = int.from_bytes(data[offset + 2:offset + 2 + count], "big")
        header = 2 + count
    start = offset + header
    end = start + length
    if end > len(data):
        return None
    return tag, start, end


def _oid_to_string(raw):
    """DER OBJECT IDENTIFIER contents -> dotted string, or None.

    The first byte packs the first two arcs. The `// 40` / `% 40` split is only
    correct while the first arc is 0, 1, or 2 with a second arc below 40, which
    covers every signature OID in use (they all start 1.2 or 1.3).
    """
    if not raw:
        return None
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    value = 0
    trailing = False
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        trailing = bool(byte & 0x80)
        if not trailing:
            parts.append(str(value))
            value = 0
    if trailing:
        # Last byte had the continuation bit set: the encoding is truncated.
        return None
    return ".".join(parts)


def signature_algorithm_oid(der):
    """The certificate's signatureAlgorithm OID, or None if it cannot be read.

    None means "could not determine", which is not the same as "not SHA-1".
    """
    outer = _read_tlv(der, 0)
    if not outer or outer[0] != 0x30:
        return None
    tbs = _read_tlv(der, outer[1])
    if not tbs or tbs[0] != 0x30:
        return None
    algid = _read_tlv(der, tbs[2])
    if not algid or algid[0] != 0x30:
        return None
    oid = _read_tlv(der, algid[1])
    if not oid or oid[0] != 0x06:
        return None
    return _oid_to_string(der[oid[1]:oid[2]])


def check_certificate(ip, port=443, timeout=3):
    """Analyze SSL/TLS certificate for security issues.
    
    Returns a dict with certificate metadata and a list of findings.
    """
    findings = []
    info = {
        "ip": ip,
        "port": port,
        "protocol": None,
        "cipher_name": None,
        "cipher_bits": None,
        "issuer": None,
        "cn": None,
        "sans": [],
        "expires": None,
        # None until the certificate's dates were actually read. These were
        # False by default, so a host that refused the connection came back
        # looking like a host with a valid, CA-issued certificate.
        "expired": None,
        "self_signed": None,
        "signature_algorithm": None,
        "signature_algorithm_oid": None,
        "findings": [],
    }

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Enable all protocols to detect weak ones
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                # Protocol & cipher info
                info["protocol"] = ssock.version()  # e.g. "TLSv1.3"
                cipher = ssock.cipher()              # (name, version, bits)
                if cipher:
                    info["cipher_name"] = cipher[0]
                    info["cipher_bits"] = cipher[2]

                # Get certificate (parsed dict + DER for binary analysis)
                # Note: With CERT_NONE, getpeercert(False) returns {} on many Python versions
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert(binary_form=False)

                # Bound here, not inside `if cert:` below.
                #
                # The not-yet-valid check reads this name from *outside* that
                # block, so on any path where the certificate could not be
                # parsed it raised `NameError: not_before` into the blanket
                # `except Exception` at the bottom of this function. That is the
                # normal path for a LAN appliance: `getpeercert(False)` returns
                # {} under CERT_NONE, and the CERT_REQUIRED retry below fails for
                # anything self-signed or signed by an internal CA.
                #
                # What it cost was not one check but five. The weak-protocol,
                # weak-cipher, wildcard-CN and SHA-1 findings all sit after that
                # line, so a self-signed host serving TLSv1.0 with a SHA-1
                # certificate reported the self-signed MEDIUM, an INFO reading
                # "Error: name 'not_before' is not defined", and nothing else.
                # `protocol` and `cipher_*` are populated above, so the result
                # looked complete, and `deep_ssl_scan` had nothing to put in its
                # `inconclusive` list — the report read "no weak protocol, no
                # SHA-1" about a host those checks never ran against.
                not_before = None

                # If parsed cert is empty (common with CERT_NONE), try DER route
                if not cert:
                    if der:
                        # Try to get parsed cert via a second verify-enabled attempt
                        try:
                            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            ctx2.check_hostname = False
                            ctx2.verify_mode = ssl.CERT_REQUIRED
                            ctx2.load_default_certs()
                            with socket.create_connection((ip, port), timeout=timeout) as sock2:
                                with ctx2.wrap_socket(sock2, server_hostname=ip) as ssock2:
                                    cert = ssock2.getpeercert(binary_form=False)
                        except Exception:
                            # Self-signed or untrusted — can't parse, report what we have
                            info["cn"] = "(Certificate present — details unavailable with CERT_NONE)"
                            findings.append({"severity": "MEDIUM", "finding": "Self-signed or untrusted certificate (cannot verify)"})
                    else:
                        findings.append({"severity": "INFO", "finding": "No certificate presented"})
                        info["findings"] = findings
                        return info

                if cert:
                    # Expiry
                    not_after = cert.get("notAfter")
                    not_before = cert.get("notBefore")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
                            info["expires"] = not_after
                            info["days_until_expiry"] = (expiry - now_utc).days
                            info["expired"] = expiry < now_utc
                        except ValueError:
                            # The date is there but in a form this cannot read.
                            # `expired` stays None: silence, not a pass.
                            info["expires"] = not_after
                            findings.append({
                                "severity": "INFO",
                                "finding": "Certificate expiry could not be read",
                                "detail": f"notAfter was {not_after!r}, which did not parse. "
                                          "Validity was not assessed.",
                            })

                    # Issuer & Subject
                    issuer_dict = {}
                    for rdn in cert.get("issuer", []):
                        for attr_type, attr_value in rdn:
                            issuer_dict[attr_type] = attr_value

                    subject_dict = {}
                    for rdn in cert.get("subject", []):
                        for attr_type, attr_value in rdn:
                            subject_dict[attr_type] = attr_value

                    info["issuer"] = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown"))
                    info["cn"] = subject_dict.get("commonName", "Unknown")

                    # Self-signed detection
                    issuer_cn = issuer_dict.get("commonName", "")
                    subject_cn = subject_dict.get("commonName", "")
                    issuer_org = issuer_dict.get("organizationName", "")
                    subject_org = subject_dict.get("organizationName", "")
                    # At least one side has to actually name something. Comparing
                    # two empty strings to two empty strings is True, so a
                    # certificate with neither a CN nor an O — which is what a
                    # partially parsed one looks like — was reported self-signed.
                    if not (issuer_cn or issuer_org or subject_cn or subject_org):
                        info["self_signed"] = None
                    else:
                        info["self_signed"] = (issuer_cn == subject_cn and issuer_org == subject_org)

                    # SANs (Subject Alternative Names)
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    info["sans"] = sans

                    # Serial number
                    info["serial"] = cert.get("serialNumber")

                # === Build Findings ===

                # Expired certificate
                if info.get("expired"):
                    findings.append({"severity": "HIGH", "finding": "Certificate EXPIRED", "detail": f"Expired: {info['expires']}"})
                elif info.get("days_until_expiry") is not None and info["days_until_expiry"] < 30:
                    findings.append({"severity": "MEDIUM", "finding": f"Certificate expires in {info['days_until_expiry']} days"})

                # Not yet valid. `not_before` was read and then never used, so a
                # certificate with a future start date — a mis-set server clock,
                # or one issued ahead of a cutover — passed as valid.
                if not_before:
                    try:
                        starts = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                        info["valid_from"] = not_before
                        if starts > datetime.now(timezone.utc).replace(tzinfo=None):
                            info["not_yet_valid"] = True
                            findings.append({
                                "severity": "MEDIUM",
                                "finding": "Certificate is not valid yet",
                                "detail": f"Valid from {not_before}. Clients will reject it until then; "
                                          "a server or client clock may also be wrong.",
                            })
                        else:
                            info["not_yet_valid"] = False
                    except ValueError:
                        info["valid_from"] = not_before

                # Self-signed
                if info.get("self_signed"):
                    findings.append({"severity": "MEDIUM", "finding": "Self-signed certificate", "detail": f"Issuer = Subject: {info['cn']}"})

                # Weak TLS version
                proto = info.get("protocol", "")
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append({"severity": "HIGH", "finding": f"Weak protocol: {proto}", "detail": "TLSv1.2+ required for compliance"})

                # Weak cipher
                if cipher and cipher[2] < 128:
                    findings.append({"severity": "MEDIUM", "finding": f"Weak cipher: {cipher[0]} ({cipher[2]}-bit)"})

                # Wildcard certificate (informational)
                if info.get("cn", "").startswith("*"):
                    findings.append({"severity": "INFO", "finding": f"Wildcard certificate: {info['cn']}"})

                # Signature algorithm, read from the field that holds it.
                if der:
                    sig_oid = signature_algorithm_oid(der)
                    info["signature_algorithm_oid"] = sig_oid
                    info["signature_algorithm"] = _SHA1_SIGNATURE_OIDS.get(sig_oid) or sig_oid
                    if sig_oid in _SHA1_SIGNATURE_OIDS:
                        findings.append({
                            "severity": "HIGH",
                            "finding": f"Certificate signed with SHA-1 ({_SHA1_SIGNATURE_OIDS[sig_oid]})",
                            "detail": "SHA-1 is not collision resistant and modern browsers reject "
                                      "these certificates. Re-issue with SHA-256."
                        })
                    elif sig_oid is None:
                        # Not a pass. The structure could not be walked, so the
                        # algorithm is unknown — which the caller has to be able
                        # to tell apart from "checked, and it is fine".
                        info["signature_algorithm"] = None

                # No findings = clean
                if not findings:
                    findings.append({"severity": "OK", "finding": "Certificate appears valid"})

    except ssl.SSLError as e:
        findings.append({"severity": "HIGH", "finding": f"SSL Error: {str(e)[:100]}"})
    except ConnectionRefusedError:
        findings.append({"severity": "INFO", "finding": "Connection refused"})
    except socket.timeout:
        findings.append({"severity": "INFO", "finding": "Connection timed out"})
    except Exception as e:
        findings.append({"severity": "INFO", "finding": f"Error: {str(e)[:100]}"})

    info["findings"] = findings
    return info


# ── Phase 7: Weak Cipher Suite Detection ──
WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5", "RC2"]

def check_weak_ciphers(ip, port=443, timeout=3):
    """The cipher suite this client and server actually negotiated.

    **Not** an enumeration, despite what the name and the old docstring
    promised. It opens one connection and reads `ssock.cipher()`, which is the
    single suite the two sides agreed on — the server's preferred one, chosen
    from what this Python's OpenSSL was willing to offer. A server that still
    accepts RC4 but prefers AES-GCM reports `weak: []`.

    So the result now says what it is. `enumerated` is False, and `error`
    carries the reason when no connection happened at all — which used to be
    logged at debug level and returned as `{"weak": [], "strong": []}`, a value
    indistinguishable from "audited, nothing weak found".

    A real enumeration means one handshake per suite with `set_ciphers()`, and
    it cannot cover suites this OpenSSL build has compiled out. Until that
    exists, the report must not claim the ciphers were audited.
    """
    weak = []
    strong = []
    error = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    name, _, bits = cipher
                    is_weak = any(kw.lower() in name.lower() for kw in WEAK_CIPHER_KEYWORDS) or bits < 128
                    entry = {"name": name, "bits": bits}
                    if is_weak:
                        weak.append(entry)
                    else:
                        strong.append(entry)
                else:
                    error = "the connection reported no cipher suite"
    except Exception as e:
        error = f"{type(e).__name__}: {str(e)[:120]}"
        logger.debug("Cipher scan failed for %s:%d: %s", ip, port, e)
    return {
        "weak": weak,
        "strong": strong,
        "enumerated": False,
        "negotiated_only": True,
        "error": error,
        "caveat": "Only the suite this client and server negotiated was observed. "
                  "Suites the server would also accept were not tested, so an empty "
                  "'weak' list is not evidence that none are enabled.",
    }


# ── Phase 7: Deprecated TLS Version Probing ──
def check_deprecated_tls(ip, port=443, timeout=3):
    """Whether the server accepts TLS 1.0 or TLS 1.1.

    Returns `{"accepted": [...], "refused": [...], "untested": [...]}`.

    The three lists exist because the old version had one, and everything that
    was not an acceptance was silently treated as a refusal:

      * `except (ssl.SSLError, OSError): pass  # Good — server refused` — but
        `OSError` covers ConnectionRefusedError, socket.timeout, a reset and an
        unreachable host. A host that is simply down produced an empty list,
        which the report read as "no deprecated TLS versions accepted". That is
        a security control credited to a machine nobody reached.
      * On a modern OpenSSL the *client* often cannot offer TLS 1.0/1.1 at all
        (`minimum_version` raises, or the security level rejects it). Same empty
        list, same false pass — and this is the common case on a current build,
        not an edge case.

    A refusal is now only recorded when the connection was established and the
    handshake was rejected at the protocol layer. Everything else is untested,
    and the caller must not report an untested version as a refused one.
    """
    accepted = []
    refused = []
    untested = []

    for proto_name, proto_ver in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        sock = None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = proto_ver
                ctx.maximum_version = proto_ver
                # OpenSSL's default security level forbids these on most modern
                # builds; without this the handshake fails on the client side
                # and the server never gets a say.
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except (ValueError, ssl.SSLError, OSError) as e:
                untested.append({
                    "version": proto_name,
                    "reason": f"this client cannot offer {proto_name} ({type(e).__name__}: {str(e)[:80]})",
                })
                continue

            # Connection and handshake are separated deliberately: a failure to
            # connect says nothing about which protocols the server accepts.
            try:
                sock = socket.create_connection((ip, port), timeout=timeout)
            except OSError as e:
                untested.append({
                    "version": proto_name,
                    "reason": f"could not connect to {ip}:{port} ({type(e).__name__}: {str(e)[:80]})",
                })
                continue

            try:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    sock = None  # wrap_socket owns it now
                    negotiated = ssock.version()
                    if negotiated:
                        accepted.append({"version": proto_name, "negotiated": negotiated})
                    else:
                        untested.append({
                            "version": proto_name,
                            "reason": "handshake completed but reported no protocol version",
                        })
            except ssl.SSLError as e:
                # The server was reached and rejected the handshake. This is the
                # only outcome that earns the word "refused".
                refused.append({"version": proto_name, "detail": str(e)[:120]})
            except OSError as e:
                untested.append({
                    "version": proto_name,
                    "reason": f"connection dropped during handshake ({type(e).__name__}: {str(e)[:80]})",
                })
        except Exception as e:
            untested.append({"version": proto_name, "reason": f"{type(e).__name__}: {str(e)[:80]}"})
            logger.debug("Deprecated TLS check failed for %s:%d %s: %s", ip, port, proto_name, e)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    return {"accepted": accepted, "refused": refused, "untested": untested}


# ── Phase 7: HSTS Header Check ──
def check_hsts(ip, port=443, timeout=3):
    """Whether the server sends Strict-Transport-Security.

    Three outcomes, and the third is the point: `enabled` is None when the check
    could not run.

    This returned `{"enabled": False}` for *every* failure — connection refused,
    timeout, a handshake the client could not complete, a host that does not
    exist. `deep_ssl_scan` then raised a MEDIUM finding, "HSTS not enabled —
    susceptible to SSL stripping attacks", about a server it had never spoken
    to. That is a fabricated finding in a document someone acts on, and it is
    the most expensive kind of error this tool can make: a remediation task
    invented out of a failed measurement.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            f"https://{ip}:{port}/",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            hsts = resp.headers.get("Strict-Transport-Security")
            return {"enabled": bool(hsts), "value": hsts or None, "error": None}
    except urllib.error.HTTPError as e:
        # An HTTP error response is still an answer from the server, and the
        # header is carried on it. 401 on an admin console is the common case.
        hsts = None
        try:
            hsts = e.headers.get("Strict-Transport-Security") if e.headers else None
        except Exception:
            pass
        return {"enabled": bool(hsts), "value": hsts or None, "error": None}
    except Exception as e:
        return {"enabled": None, "value": None, "error": f"{type(e).__name__}: {str(e)[:120]}"}


def deep_ssl_scan(ip, port=443, timeout=3):
    """Run every TLS check and combine them into one report.

    The rule applied throughout: a check that did not run produces an entry in
    `inconclusive`, never a finding. Every finding here is supposed to become a
    remediation task for somebody, and a task invented from a failed measurement
    costs real time and real credibility.
    """
    report = check_certificate(ip, port, timeout)
    report["deprecated_tls"] = check_deprecated_tls(ip, port, timeout)
    report["cipher_audit"] = check_weak_ciphers(ip, port, timeout)
    report["hsts"] = check_hsts(ip, port, timeout)

    # Named checks that could not answer. The report prints these instead of
    # letting their silence read as a pass.
    inconclusive = []

    tls = report["deprecated_tls"]
    for dep in tls.get("accepted", []):
        report["findings"].append({
            "severity": "HIGH",
            "finding": f"Deprecated {dep['version']} accepted",
            "detail": "PCI-DSS and NIST require TLS 1.2 as a minimum."
        })
    for miss in tls.get("untested", []):
        inconclusive.append({
            "check": f"deprecated_tls/{miss['version']}",
            "reason": miss.get("reason", "unknown"),
        })

    audit = report["cipher_audit"]
    for wc in audit.get("weak", []):
        report["findings"].append({
            "severity": "MEDIUM",
            "finding": f"Weak cipher negotiated: {wc['name']} ({wc['bits']}-bit)",
            "detail": "Disable this suite in the server configuration."
        })
    if audit.get("error"):
        inconclusive.append({"check": "cipher_audit", "reason": audit["error"]})
    else:
        # Not a finding, but it bounds what the absence of findings means, so it
        # travels with the result rather than living only in a docstring.
        inconclusive.append({
            "check": "cipher_audit/enumeration",
            "reason": audit.get("caveat", "only the negotiated suite was observed"),
        })

    hsts = report["hsts"]
    if hsts.get("enabled") is False:
        report["findings"].append({
            "severity": "MEDIUM",
            "finding": "HSTS not enabled",
            "detail": "The server answered without a Strict-Transport-Security header, "
                      "so a client can be downgraded to plain HTTP before the first redirect."
        })
    elif hsts.get("enabled") is None:
        # The defect this replaces: any failure to reach the server used to
        # produce the MEDIUM finding above.
        inconclusive.append({
            "check": "hsts",
            "reason": hsts.get("error") or "the HTTPS request did not complete",
        })

    report["inconclusive"] = inconclusive

    # "Certificate appears valid" is a placeholder for "nothing was raised". It
    # must not sit alongside actual findings.
    if any(f.get("severity") != "OK" for f in report["findings"]):
        report["findings"] = [f for f in report["findings"] if f.get("severity") != "OK"]

    return report
