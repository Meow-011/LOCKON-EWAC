import socket
import struct
import json
import uuid
import logging
import threading
import time

logger = logging.getLogger("SMBEnum")

class SMBEnumerator:
    def __init__(self, emit_callback):
        self.emit = emit_callback
        self._active = set()  # Targets with an enum already in flight
        self._active_lock = threading.Lock()

    def start_enum(self, target_ip, port=445):
        # Enum takes 30-60s; run it off the IPC thread so stop_* commands stay responsive
        with self._active_lock:
            if target_ip in self._active:
                self.emit("smb_enum_error", {
                    "target": target_ip,
                    "message": f"SMB enumeration already running for {target_ip}"
                })
                return
            self._active.add(target_ip)

        threading.Thread(target=self._run_enum, args=(target_ip, port), daemon=True).start()

    def _run_enum(self, target_ip, port):
        self.emit("smb_enum_started", {"target": target_ip})

        results = {
            # The payload names its own subject. Without this the frontend had to
            # guess the target from whichever host happened to be selected when
            # the result arrived, which mislabels the evidence if the operator
            # clicked another host in the meantime.
            "target": target_ip,
            "port": port,
            # None until a check actually answers. False is a finding; absent is not.
            "smbv1_enabled": None,
            "signing_required": None,
            "computer_name": "Unknown",
            "domain_name": "Unknown",
            "os_version": "Unknown",
            # None until the question is answered. `[]` would assert that this host
            # exposes no accessible shares.
            "shares": None,
            # Why `shares` reads the way it does -- the refusal, or the reason the
            # check could not conclude. Printed beside the result rather than left
            # for a reader to infer from an empty section.
            "shares_note": None,
            # The same for SMBv1: a bare `false` does not say whether the host
            # refused the dialect or the probe was never answered.
            "smbv1_note": None
        }

        error = None
        try:
            # 1. Test for SMBv1 Support (EternalBlue indicator)
            #
            # Three states. True is the finding, False is also a measurement -- the
            # host was asked and refused -- and None means it could not be asked. All
            # three used to be None, because the request was malformed and every call
            # landed in the exception handler.
            results["smbv1_enabled"], results["smbv1_note"] =                 self._check_smbv1(target_ip, port)
            
            # 2. Extract NTLM Info (Computer Name, Domain, OS) via SMB2
            ntlm_info = self._get_ntlm_info(target_ip, port)
            if ntlm_info:
                results.update(ntlm_info)

            # 3. SMB Signing Check via SMB2 Negotiate
            results["signing_required"] = self._check_smb_signing(target_ip, port)

            # 4. Null Session Share Enumeration
            #
            # None means the question was not answered, which is a different statement
            # from "this host exposes no shares" -- it stays None so the inconclusive
            # list below picks it up. An empty list is a real result: either a session
            # was established and nothing was reachable, or the server refused the
            # null session outright. `shares_note` says which.
            results["shares"], results["shares_note"] =                 self._enumerate_shares(target_ip, port)

        except Exception as e:
            error = str(e)
        finally:
            with self._active_lock:
                self._active.discard(target_ip)

        # Always report: partial share/NTLM intel is still useful on failure
        if error:
            results["error"] = error
        # Name the checks that could not answer, so a reader never reads an
        # unreached check as a clean one.
        # `shares` belongs here too. It was absent, so an enumeration that never
        # ran reported as a host with no accessible shares.
        results["inconclusive"] = [
            name for name, value in (("smbv1_enabled", results["smbv1_enabled"]),
                                     ("signing_required", results["signing_required"]),
                                     ("shares", results["shares"]))
            if value is None
        ]
        self.emit("smb_enum_completed", results)

    def _speaks_smb2(self, ip, port):
        """
        Does an SMB service actually answer here? Used to qualify an SMBv1 refusal.

        This is the step that lets "SMBv1 is disabled" be told apart from "this host
        could not be asked". A TCP reset on an SMBv1 negotiate means nothing on its
        own -- a firewall, a dropped route and a hardened server all look the same --
        but a reset from a host whose SMB2 negotiate succeeded on the same port is the
        server declining that dialect.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((ip, port))
            sock.sendall(_negotiate_request())
            response = _read_message(sock)
            return bool(response) and _status_of(response) == _STATUS_SUCCESS
        except Exception as e:
            logger.debug("SMB2 reachability check failed for %s:%s: %s", ip, port, e)
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _check_smbv1(self, ip, port):
        """
        Is SMBv1 available? `(verdict, note)` where verdict is True, False or None.

        True is the finding -- SMBv1 is what EternalBlue needs. False is also a
        measurement: this host was asked and refused. None means it could not be asked,
        and the caller puts that in `inconclusive`.

        **All three were None before, for every host.** The request was pasted hex
        whose NetBIOS header declared 45 bytes over a 47-byte payload, so the server
        waited for two bytes that never arrived and reset the connection; every call
        landed in the `except` clause. The comment there was right about why it must not
        return False on a failure -- that would report a clean security posture for a
        host that was merely unreachable -- but the result was the opposite extreme: a
        host that genuinely has SMBv1 disabled got no credit for it, a caveat was
        printed for every host in every report, and the EternalBlue finding, whose
        condition is `smbv1_enabled == True`, could never fire at all.

        Even had the frame been right, the response parse read offsets 36:38 of the
        framed packet -- `WordCount` and the low byte of `DialectIndex` -- so the number
        compared against 0xFFFF was not the dialect index.

        The refusal is qualified rather than assumed. A reset or a close is only read as
        "disabled" when the same host answered an SMB2 negotiate, which establishes that
        an SMB service is there and reachable. `note` records which evidence produced
        the verdict, because "false" on its own does not say whether the host refused or
        the probe was never answered -- and this reading is strong evidence, not proof:
        a middlebox can reset a connection too.
        """
        if not self._speaks_smb2(ip, port):
            return None, (
                "SMBv1 could not be determined: this host did not complete an SMB2 "
                "negotiate either, so there is no evidence that an SMB service was "
                "reachable to refuse it."
            )

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((ip, port))
            sock.sendall(_smb1_negotiate_request())
            # 33 bytes: a 32-byte SMB1 header plus at least a WordCount.
            response = _read_message(sock, min_length=33)

            if response is None:
                return False, (
                    "SMBv1 is not available: the server closed the connection without "
                    "answering an SMB_COM_NEGOTIATE, while answering SMB2 on the same "
                    "port. (A middlebox resetting the connection would look the same.)"
                )

            if response[:4] == b"\xfeSMB":
                # It replied in SMB2 to an SMB1 request, which is a refusal with a
                # return address.
                return False, (
                    "SMBv1 is not available: the server answered an SMB1 negotiate with "
                    "an SMB2 header."
                )

            index = _smb1_dialect_index(response)
            if index is None:
                return None, (
                    "SMBv1 could not be determined: the reply to SMB_COM_NEGOTIATE was "
                    "not a form this check reads."
                )
            if index == _SMB1_DIALECT_REFUSED:
                return False, (
                    "SMBv1 is not available: the server accepted the negotiate and "
                    "refused the NT LM 0.12 dialect."
                )
            return True, (
                "SMBv1 is ENABLED: the server accepted the NT LM 0.12 dialect "
                "(index %d). This is the protocol EternalBlue targets." % index
            )

        except ConnectionResetError:
            return False, (
                "SMBv1 is not available: the server reset the connection on an "
                "SMB_COM_NEGOTIATE, while answering SMB2 on the same port. (A middlebox "
                "resetting the connection would look the same.)"
            )
        except socket.timeout:
            return None, (
                "SMBv1 could not be determined: the SMB_COM_NEGOTIATE timed out, which "
                "is not the same as being refused."
            )
        except Exception as e:
            logger.debug("SMBv1 check failed for %s:%s: %s", ip, port, e)
            return None, (
                "SMBv1 could not be determined: the probe failed (%s)."
                % type(e).__name__
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _get_ntlm_info(self, ip, port):
        """
        Computer name, domain and OS, read out of the NTLMSSP challenge.

        The server volunteers all of it in the CHALLENGE message's TargetInfo and
        Version block, so this needs no credential: NEGOTIATE, then one SESSION_SETUP
        carrying an NTLMSSP NEGOTIATE_MESSAGE, and the reply is parsed.

        This used to send a hand-assembled NEGOTIATE whose NetBIOS header declared 104
        bytes over a 96-byte payload, with a 32-byte NEGOTIATE body where MS-SMB2 2.2.3
        defines 36 plus two per dialect. The server sat waiting for the eight bytes that
        never came, the read timed out, and the method returned `{}` -- so
        `computer_name`, `domain_name` and `os_version` were "Unknown" for every host
        this tool has ever enumerated. The same request was pasted into
        `_check_smb_signing`, with the same result.

        It builds the request from `_negotiate_request()` now, which is verified against
        a live server and asserted against the specification by test.
        """
        info = {}
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((ip, port))

            sock.sendall(_negotiate_request())
            negotiated = _read_message(sock)
            if not negotiated or _status_of(negotiated) != _STATUS_SUCCESS:
                return info

            sock.sendall(_session_setup_request(1, _ntlm_negotiate()))
            challenged = _read_message(sock)
            if not challenged:
                return info
            # STATUS_MORE_PROCESSING_REQUIRED is the expected answer: the server is
            # asking for a credential, and the challenge it sends to do so is what
            # carries the identity fields.
            if _status_of(challenged) != _STATUS_MORE_PROCESSING_REQUIRED:
                return info

            blob_start = challenged.find(b"NTLMSSP\x00")
            if blob_start < 0:
                return info
            blob = challenged[blob_start:]
            if len(blob) < 48 or struct.unpack("<I", blob[8:12])[0] != 2:
                return info

            # MS-NLMP 2.2.1.2: TargetInfo length and offset are at 40 and 44, both
            # relative to the start of the NTLMSSP message.
            ti_len, _, ti_off = struct.unpack("<HHI", blob[40:48])
            if ti_len and ti_off + ti_len <= len(blob):
                info.update(self._parse_target_info(blob[ti_off:ti_off + ti_len]))

            # MS-NLMP 2.2.2.10: the Version block sits at offset 48 when
            # NTLMSSP_NEGOTIATE_VERSION (0x02000000) is set in the challenge's flags.
            flags = struct.unpack("<I", blob[20:24])[0]
            if flags & 0x02000000 and len(blob) >= 56:
                major, minor, build = struct.unpack("<BBH", blob[48:52])
                info["os_version"] = "Windows %d.%d build %d" % (major, minor, build)

        except Exception as e:
            logger.debug("NTLM info probe failed for %s:%s: %s", ip, port, e)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        return info

    def _parse_target_info(self, data):
        info = {}
        idx = 0
        while idx < len(data):
            if idx + 4 > len(data): break
            av_id = struct.unpack('<H', data[idx:idx+2])[0]
            av_len = struct.unpack('<H', data[idx+2:idx+4])[0]
            idx += 4
            if av_id == 0: # MsvAvEOL
                break
            av_value = data[idx:idx+av_len]
            if av_id == 1: # MsvAvNbComputerName
                info["computer_name"] = av_value.decode('utf-16le', errors='ignore')
            elif av_id == 2: # MsvAvNbDomainName
                info["domain_name"] = av_value.decode('utf-16le', errors='ignore')
            elif av_id == 3: # MsvAvDnsComputerName
                info["dns_computer_name"] = av_value.decode('utf-16le', errors='ignore')
            elif av_id == 4: # MsvAvDnsDomainName
                info["dns_domain_name"] = av_value.decode('utf-16le', errors='ignore')
            idx += av_len
        return info

    def _asn1_len(self, length):
        if length < 128:
            return bytes([length])
        else:
            length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
            return bytes([0x80 | len(length_bytes)]) + length_bytes

    def _check_smb_signing(self, ip, port):
        """
        Whether the server *requires* SMB signing. True, False, or None if unknown.

        False is the finding: signing enabled but not required is the state an SMB
        relay exploits. None means the question was not answered, and the caller puts
        that in `inconclusive`.

        This answered None for every host. It sent a hand-assembled NEGOTIATE whose
        NetBIOS header declared 104 bytes over a 96-byte payload, with a 32-byte
        NEGOTIATE body where MS-SMB2 2.2.3 defines 36 plus two bytes per dialect -- so
        the server waited for eight bytes that never arrived and the read timed out.
        `signing_required` is one of the two inputs the SMB relay finding depends on,
        and it has never once been measured. (`_get_ntlm_info` carried a copy of the
        same request, with the same result.)

        The request comes from `_negotiate_request()` now, which is verified against a
        live server, and `SecurityMode` is read from the response body where MS-SMB2
        2.2.4 puts it rather than from an offset counted by hand.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((ip, port))
            sock.sendall(_negotiate_request())
            response = _read_message(sock)
            if not response or _status_of(response) != _STATUS_SUCCESS:
                return None
            # NEGOTIATE response body, MS-SMB2 2.2.4: StructureSize at 0, SecurityMode
            # at 2 -- so offsets 64 and 66 once the NetBIOS frame is stripped.
            if len(response) < 68:
                return None
            security_mode = struct.unpack("<H", response[66:68])[0]
            # SMB2 SecurityMode: 0x01 signing enabled, 0x02 signing required.
            return bool(security_mode & 0x02)
        except Exception as e:
            logger.debug("SMB signing check failed for %s:%s: %s", ip, port, e)
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _null_session(self, sock, ip):
        """
        Establish an anonymous SMB2 session. Returns `(session_id, status)`.

        `session_id` is None when no session was established, and `status` is the
        server's own NTSTATUS so the caller can tell a refusal from a failure to ask.
        """
        sock.sendall(_negotiate_request())
        negotiated = _read_message(sock)
        if not negotiated:
            return None, None
        if _status_of(negotiated) != _STATUS_SUCCESS:
            return None, _status_of(negotiated)

        sock.sendall(_session_setup_request(1, _ntlm_negotiate()))
        challenged = _read_message(sock)
        if not challenged:
            return None, None
        status = _status_of(challenged)
        session_id = _session_id_of(challenged)
        # The first leg is expected to be refused *pending* the second one. Anything
        # else -- including an immediate success, which no Windows server gives for a
        # bare NEGOTIATE_MESSAGE -- is not an exchange this code understands.
        if status != _STATUS_MORE_PROCESSING_REQUIRED or not session_id:
            return None, status

        sock.sendall(_session_setup_request(2, _ntlm_authenticate_anonymous(), session_id))
        authenticated = _read_message(sock)
        if not authenticated:
            return None, None
        status = _status_of(authenticated)
        if status != _STATUS_SUCCESS:
            return None, status
        return session_id, status

    def _enumerate_shares(self, ip, port):
        """
        Which shares a null session can reach. `(shares, note)`.

        `shares` is None when the question was not answered, and a list when it was --
        including an empty list, which is the finding that this host exposes nothing
        anonymously. `note` carries the reason whenever there is one worth printing.

        Three outcomes, and the distinction between them is the whole point:

          * **A session was established.** Each share name is probed with a
            TREE_CONNECT and the NTSTATUS read: success means reachable, ACCESS_DENIED
            means the share exists and is refused, BAD_NETWORK_NAME means it is not
            there. An empty list here is a real result.
          * **The server refused anonymous access.** ACCESS_DENIED or LOGON_FAILURE on
            the session setup is the server answering the question: there is no
            null-session access to this host. That is a measurement, so `shares` is an
            empty list with a note saying why, not an inconclusive.
          * **Anything else** -- no response, a status this code does not model, a
            socket error -- is None. The caller puts that in `inconclusive`.

        What the previous implementation did was none of these. Its SESSION_SETUP body
        was 12 bytes where the structure is 24, it threw away the response carrying the
        `SessionId` with the comment "just prime the session", and its TREE_CONNECT
        carried `PathOffset = 0` instead of 72 -- so `nt_status` could never be 0 or
        0xC0000022, `accessible` was always empty, and `shares: []` went out as a
        clean result for every host on the network.

        **How much of this is verified.** The NEGOTIATE and both SESSION_SETUP legs
        were run against a live Windows SMB server during development, which is how the
        NTLMSSP Version block turned out to be required -- without it the server
        answers STATUS_INVALID_PARAMETER rather than evaluating anything. That server
        refuses anonymous sessions, which is the Windows default, so it exercised the
        refusal path and not the enumeration path. The TREE_CONNECT packet layout is
        asserted against MS-SMB2 2.2.9 by test and its responses are parsed from
        planted bytes, but the share loop has not been run against a server that
        accepts a null session. If it is still wrong, this reports None and the report
        says the check was inconclusive -- which is the failure mode worth having.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((ip, port))
            session_id, status = self._null_session(sock, ip)

            if session_id is None:
                if status in _NULL_SESSION_REFUSED:
                    return [], (
                        "The server refused an anonymous (null) session, so no share is "
                        "reachable without credentials. This is a result, not a failed "
                        "check."
                    )
                if status is None:
                    return None, (
                        "The server stopped responding during the SMB2 session setup, so "
                        "share access could not be determined."
                    )
                return None, (
                    "The SMB2 session setup ended with status 0x%08X, which this check "
                    "does not interpret, so share access could not be determined." % status
                )

            accessible = []
            answered = False
            # MessageId advances per request.
            #
            # It was the literal 3 for all ten probes. MS-SMB2 3.3.5.2.3 has the
            # server validate MessageId against its sequence window and disconnect
            # on a reuse, and Windows does -- so the second TREE_CONNECT killed the
            # connection, the loop broke, and because `answered` was already True
            # from the first probe the function returned a *confident* result for
            # nine share names it had never asked about. Exactly the failure this
            # rewrite exists to prevent.
            for index, share_name in enumerate(_COMMON_SHARES):
                path = "\\\\%s\\%s" % (ip, share_name)
                try:
                    sock.sendall(_tree_connect_request(3 + index, session_id, path))
                    response = _read_message(sock)
                except Exception as e:
                    logger.debug("TREE_CONNECT for %s failed: %s", path, e)
                    break
                if not response:
                    break
                answered = True
                tree_status = _status_of(response)
                if tree_status == _STATUS_SUCCESS:
                    accessible.append({"name": share_name, "access": "OPEN"})
                elif tree_status == _STATUS_ACCESS_DENIED:
                    # The share is there; the null session is not allowed into it.
                    accessible.append({"name": share_name, "access": "DENIED"})
                # BAD_NETWORK_NAME and anything else: this host does not have it.

            if not answered:
                return None, (
                    "An anonymous session was established but no share probe got a "
                    "reply, so share access could not be determined."
                )
            if not accessible:
                return [], (
                    "An anonymous session was established and none of the probed share "
                    "names was reachable."
                )
            return accessible, None

        except socket.timeout:
            return None, "The SMB2 share probe timed out, so share access could not be determined."
        except Exception as e:
            logger.debug("share enumeration failed for %s:%s: %s", ip, port, e)
            return None, (
                "The SMB2 share probe failed (%s), so share access could not be "
                "determined." % type(e).__name__
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

# ── SMB2 wire format ────────────────────────────────────────────────────────
#
# Built as module-level functions rather than inline, so every packet's layout can be
# asserted against the specification without a server. That is the lesson of what was
# here before: the old `_enumerate_shares` packed the SESSION_SETUP fixed body as
# `<HBBIHH` -- 12 bytes where MS-SMB2 2.2.5 defines 24 -- put `Channel` in an `H` so
# `SecurityBufferOffset` landed inside it, discarded the response carrying the
# `SessionId`, and sent TREE_CONNECT with `PathOffset = 0` instead of 72. Every one of
# those is a structural error a test can catch, and none of them was visible by reading
# the code, which is why they survived.
#
# Verified against a live Windows SMB server while this was written. What that run
# established, and what it could not, is recorded on `_enumerate_shares`.

#: MS-SMB2 2.2.1.2. 64 bytes.
_SMB2_HEADER = "<4sHHIHHIIQIIQ16s"
_CMD_NEGOTIATE = 0x0000
_CMD_SESSION_SETUP = 0x0001
_CMD_TREE_CONNECT = 0x0003

#: NTSTATUS values this exchange distinguishes. MS-ERREF 2.3.1.
_STATUS_SUCCESS = 0x00000000
_STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
_STATUS_ACCESS_DENIED = 0xC0000022
_STATUS_LOGON_FAILURE = 0xC000006D
_STATUS_ACCOUNT_RESTRICTION = 0xC000006E
_STATUS_BAD_NETWORK_NAME = 0xC00000CC

#: The statuses that mean the server considered anonymous access and said no.
#:
#: That is a measurement, not a failure to measure: it establishes that this host
#: exposes nothing over a null session, which is the question being asked.
_NULL_SESSION_REFUSED = frozenset((
    _STATUS_ACCESS_DENIED, _STATUS_LOGON_FAILURE, _STATUS_ACCOUNT_RESTRICTION,
))

#: MS-NLMP 2.2.2.5. UNICODE | REQUEST_TARGET | NTLM | ANONYMOUS | EXTENDED_SESSIONSECURITY
_NTLM_NEGOTIATE_FLAGS = 0x00000001 | 0x00000004 | 0x00000200 | 0x00000800 | 0x00080000
#: UNICODE | NTLM | ANONYMOUS on the authenticate leg.
_NTLM_AUTH_FLAGS = 0x00000001 | 0x00000200 | 0x00000800

#: Shares worth asking about. Administrative shares first, then the names a
#: misconfigured host most often exposes.
_COMMON_SHARES = (
    "IPC$", "C$", "ADMIN$", "D$", "NETLOGON", "SYSVOL",
    "Users", "Public", "print$", "Share",
)


def _nb_frame(payload):
    """NetBIOS session service framing: type 0, then a 3-byte big-endian length."""
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _smb2_header(command, message_id, session_id=0, tree_id=0):
    """A 64-byte SMB2 request header. Unsigned: this exchange never obtains a key."""
    return struct.pack(
        _SMB2_HEADER,
        b"\xfeSMB",     # ProtocolId
        64,             # StructureSize
        0,              # CreditCharge
        0,              # Status / ChannelSequence on a request
        command,
        1,              # CreditRequest
        0,              # Flags
        0,              # NextCommand
        message_id,
        0,              # Reserved (PID)
        tree_id,
        session_id,
        b"\x00" * 16,   # Signature
    )


def _negotiate_request():
    """SMB2 NEGOTIATE, MS-SMB2 2.2.3. Offers dialects 2.0.2 through 3.0.2."""
    dialects = (0x0202, 0x0210, 0x0300, 0x0302)
    body = struct.pack(
        "<HHHHI16sQ",
        36,             # StructureSize
        len(dialects),  # DialectCount
        0x01,           # SecurityMode: signing enabled
        0,              # Reserved
        0,              # Capabilities
        b"\x00" * 16,   # ClientGuid
        0,              # ClientStartTime
    )
    body += b"".join(struct.pack("<H", d) for d in dialects)
    return _nb_frame(_smb2_header(_CMD_NEGOTIATE, 0) + body)


def _ntlm_negotiate(flags=_NTLM_NEGOTIATE_FLAGS):
    """NTLMSSP NEGOTIATE_MESSAGE, MS-NLMP 2.2.1.1. 32 bytes, no payload."""
    return struct.pack(
        "<8sIIHHIHHI",
        b"NTLMSSP\x00", 1, flags,
        0, 0, 32,   # DomainName: absent
        0, 0, 32,   # Workstation: absent
    )


def _ntlm_authenticate_anonymous(flags=_NTLM_AUTH_FLAGS):
    """
    NTLMSSP AUTHENTICATE_MESSAGE for an anonymous session. MS-NLMP 2.2.1.3.

    Per MS-NLMP 3.1.5.1.2 an anonymous authentication sets the ANONYMOUS flag and an
    `LmChallengeResponse` of one zero byte, and leaves the NT response, user, domain,
    workstation and session key empty.

    **The Version block is not optional in practice.** Without it the fixed header is
    64 bytes and a Windows server answers `STATUS_INVALID_PARAMETER`; with it the
    header is 72 and the server goes on to actually evaluate the credential. That came
    from sending both to a live server, not from the specification, which describes
    Version as present when NTLMSSP_NEGOTIATE_VERSION is set. Sending it always costs
    nothing and is the difference between a malformed request and an answer.

    Empty fields carry offset 0 rather than an offset one past the end of the message.
    """
    lm_response = b"\x00"
    header_len = 72
    fields = (
        (len(lm_response), len(lm_response), header_len),  # LmChallengeResponse
        (0, 0, 0),   # NtChallengeResponse
        (0, 0, 0),   # DomainName
        (0, 0, 0),   # UserName
        (0, 0, 0),   # Workstation
        (0, 0, 0),   # EncryptedRandomSessionKey
    )
    head = struct.pack("<8sI", b"NTLMSSP\x00", 3)
    for length, maxlen, offset in fields:
        head += struct.pack("<HHI", length, maxlen, offset)
    head += struct.pack("<I", flags)
    # Version: MS-NLMP 2.2.2.10 -- major, minor, build, 3 reserved, NTLMRevision.
    head += struct.pack("<BBHBBBB", 10, 0, 19041, 0, 0, 0, 15)
    assert len(head) == header_len, "NTLM auth header is %d, must be %d" % (len(head), header_len)
    return head + lm_response


def _session_setup_request(message_id, blob, session_id=0):
    """
    SMB2 SESSION_SETUP, MS-SMB2 2.2.5.

    `StructureSize` is 25 while the fixed body is 24 bytes -- that is what the
    specification says for a structure with a trailing buffer, and the old code's
    `<HBBIHH` reduced the body to 12 while still claiming 25.
    """
    body = struct.pack(
        "<HBBIIHHQ",
        25,          # StructureSize
        0,           # Flags
        0x01,        # SecurityMode: signing enabled
        0,           # Capabilities
        0,           # Channel  (I, not H -- where the old packing went wrong)
        64 + 24,     # SecurityBufferOffset: past the header and this body
        len(blob),   # SecurityBufferLength
        0,           # PreviousSessionId  (Q, not I)
    )
    assert len(body) == 24, "session setup body is %d, must be 24" % len(body)
    return _nb_frame(_smb2_header(_CMD_SESSION_SETUP, message_id, session_id) + body + blob)


def _tree_connect_request(message_id, session_id, path):
    """SMB2 TREE_CONNECT, MS-SMB2 2.2.9. `PathOffset` is 72, not 0."""
    encoded = path.encode("utf-16-le")
    body = struct.pack(
        "<HHHH",
        9,               # StructureSize
        0,               # Flags / Reserved
        64 + 8,          # PathOffset
        len(encoded),    # PathLength
    )
    assert len(body) == 8, "tree connect body is %d, must be 8" % len(body)
    return _nb_frame(_smb2_header(_CMD_TREE_CONNECT, message_id, session_id) + body + encoded)


#: Whole-message budget. The socket timeout is per `recv`, so without this a peer
#: sending one byte just inside the timeout could hold the reader for days -- and
#: `start_enum` keeps the target in `self._active` until the run returns, so that host
#: could never be enumerated again for the life of the process.
_READ_DEADLINE_SECONDS = 12.0


def _read_message(sock, min_length=64):
    """
    One NetBIOS-framed message, or None if the peer closed or framed nonsense.

    `min_length` is 64 for SMB2, whose header alone is that long. An SMB1 negotiate
    response can legitimately be shorter -- its header is 32 bytes and an error reply
    carries almost nothing after it -- so that caller passes its own floor.
    """
    deadline = time.monotonic() + _READ_DEADLINE_SECONDS
    head = b""
    while len(head) < 4:
        if time.monotonic() > deadline:
            return None
        chunk = sock.recv(4 - len(head))
        if not chunk:
            return None
        head += chunk
    remaining = int.from_bytes(head[1:4], "big")
    if remaining < min_length or remaining > 0x100000:
        return None
    body = b""
    while len(body) < remaining:
        if time.monotonic() > deadline:
            return None
        chunk = sock.recv(remaining - len(body))
        if not chunk:
            return None
        body += chunk
    return body


def _status_of(message):
    """The NTSTATUS from an SMB2 response header."""
    return struct.unpack("<I", message[8:12])[0]


def _session_id_of(message):
    """The SessionId from an SMB2 response header. Zero until one is granted."""
    return struct.unpack("<Q", message[40:48])[0]


#: MS-CIFS 2.2.3.1. 32 bytes.
_SMB1_HEADER = "<4sBIBHH8sHHHHH"
_SMB1_CMD_NEGOTIATE = 0x72
#: The dialect that makes a host EternalBlue-relevant.
_SMB1_DIALECT = b"NT LM 0.12"
#: MS-CIFS 2.2.4.52.2: no dialect from the list was acceptable.
_SMB1_DIALECT_REFUSED = 0xFFFF


def _smb1_negotiate_request():
    """
    SMB_COM_NEGOTIATE offering only `NT LM 0.12`. MS-CIFS 2.2.4.52.1.

    Built rather than pasted. The hand-assembled version of this was the third copy of
    the same defect in this module: its NetBIOS header declared 45 bytes over a 47-byte
    payload, so the server waited for two bytes that never came and reset the
    connection. Every call therefore landed in `_check_smbv1`'s `except` clause and
    returned None -- `smbv1_enabled` was "could not determine" for every host this tool
    has ever enumerated, and the EternalBlue finding that depends on it being True could
    never fire.
    """
    header = struct.pack(
        _SMB1_HEADER,
        b"\xffSMB",            # Protocol
        _SMB1_CMD_NEGOTIATE,   # Command
        0,                     # Status
        0x18,                  # Flags: CASE_INSENSITIVE | CANONICALIZED_PATHS
        0xC853,                # Flags2: unicode, NT status, extended security
        0,                     # PIDHigh
        b"\x00" * 8,           # SecurityFeatures
        0,                     # Reserved
        0xFFFF,                # TID
        0xFEFF,                # PIDLow
        0,                     # UID
        0,                     # MID
    )
    assert len(header) == 32, "SMB1 header is %d, must be 32" % len(header)
    # Dialect buffer: each entry is a 0x02 buffer-format byte then a NUL-terminated
    # ASCII name.
    dialects = b"\x02" + _SMB1_DIALECT + b"\x00"
    body = struct.pack("<BH", 0, len(dialects)) + dialects
    return _nb_frame(header + body)


def _smb1_dialect_index(message):
    """
    The accepted dialect index from an SMB_COM_NEGOTIATE response, or None.

    The response body starts after the 32-byte header: `WordCount`, then
    `DialectIndex`. The old code read offsets 36:38 of the *framed* packet, which is
    `WordCount` and the low half of `DialectIndex` -- so even had the request been
    well-formed, the number it compared against 0xFFFF was not the dialect index.
    """
    if len(message) < 35 or message[:4] != b"\xffSMB":
        return None
    if message[32] == 0:          # WordCount 0: an error response carries no body
        return None
    return struct.unpack("<H", message[33:35])[0]
