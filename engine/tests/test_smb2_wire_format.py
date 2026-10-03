"""
The SMB2 packets this engine puts on the wire, against the specification.

    python engine/tests/test_smb2_wire_format.py
    python -m pytest engine/tests/test_smb2_wire_format.py

Why this exists.

Three of the four SMB2 exchanges in `smb_enum.py` could not work, and none of the
faults was visible by reading the code -- which is why they survived to a release.

  * `_enumerate_shares` packed the SESSION_SETUP fixed body as `<HBBIHH`: 12 bytes
    where MS-SMB2 2.2.5 defines 24. `Channel` was an `H` instead of an `I`, so
    `SecurityBufferOffset` landed inside it and the server read the NTLM blob's
    position from the wrong bytes. It then discarded the response that carries the
    `SessionId` ("just prime the session"), so the TREE_CONNECT that followed was
    unauthenticated -- and that TREE_CONNECT set `PathOffset = 0` where it must be 72.
    `nt_status` could therefore never be 0 or 0xC0000022, `accessible` was always
    empty, and `shares: []` went out as a clean result for every host swept.
  * `_check_smb_signing` sent a hand-assembled NEGOTIATE whose NetBIOS header declared
    104 bytes over a 96-byte payload, with a 32-byte NEGOTIATE body where the structure
    is 36 plus two per dialect. The server waited for eight bytes that never came and
    the read timed out, so it returned None -- for every host, always. That value is
    one of the two inputs the SMB relay finding depends on.
  * `_get_ntlm_info` carried a copy of the same request, so `computer_name`,
    `domain_name` and `os_version` were "Unknown" on every host ever enumerated.

Every one of those is a structural error, and a structural error is exactly what a test
can pin without a server. So the packets are asserted field by field against MS-SMB2 and
MS-NLMP, and the response handling is driven from planted bytes.

What was verified live, during development, against a Windows SMB server: NEGOTIATE and
both SESSION_SETUP legs. That is how the NTLMSSP Version block turned out to be
required -- without it the server answers STATUS_INVALID_PARAMETER rather than
evaluating the credential at all. That server refuses anonymous sessions, which is the
Windows default, so the refusal path was exercised and the share-enumeration path was
not. These tests cover its structure and its branching; they cannot prove a server
accepts it.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import smb_enum  # noqa: E402
from scanner.smb_enum import SMBEnumerator  # noqa: E402


def _unframe(packet):
    """`(declared_length, smb2_message)` from a NetBIOS-framed packet."""
    assert packet[0] == 0x00, "NetBIOS message type must be 0 (session message)"
    return int.from_bytes(packet[1:4], "big"), packet[4:]


# ── NetBIOS framing ─────────────────────────────────────────────────────────

def test_the_declared_length_matches_the_payload():
    """
    The fault that stopped two checks working, in one assertion.

    A header declaring more bytes than follow leaves the server blocked waiting for
    the remainder, and the client times out reading a reply that will never come.
    """
    for packet in (smb_enum._negotiate_request(),
                   smb_enum._session_setup_request(1, smb_enum._ntlm_negotiate()),
                   smb_enum._tree_connect_request(3, 1, "\\\\10.0.0.1\\IPC$")):
        declared, message = _unframe(packet)
        assert declared == len(message), f"declared {declared}, carried {len(message)}"


# ── SMB2 header, MS-SMB2 2.2.1.2 ────────────────────────────────────────────

def test_the_header_is_sixty_four_bytes_and_says_so():
    header = smb_enum._smb2_header(smb_enum._CMD_NEGOTIATE, 0)
    assert len(header) == 64
    assert header[:4] == b"\xfeSMB"
    assert struct.unpack("<H", header[4:6])[0] == 64


def test_the_command_and_message_id_land_where_the_server_reads_them():
    header = smb_enum._smb2_header(smb_enum._CMD_TREE_CONNECT, 7)
    assert struct.unpack("<H", header[12:14])[0] == smb_enum._CMD_TREE_CONNECT
    assert struct.unpack("<Q", header[24:32])[0] == 7


def test_the_session_id_lands_where_the_server_reads_it():
    # Offset 40, and eight bytes wide. Read back by `_session_id_of` from the same
    # place, so a mistake here would cancel out in a test that used only our own
    # reader -- hence the literal offset.
    header = smb_enum._smb2_header(smb_enum._CMD_TREE_CONNECT, 3, session_id=0x0002480000000001)
    assert struct.unpack("<Q", header[40:48])[0] == 0x0002480000000001


# ── NEGOTIATE, MS-SMB2 2.2.3 ────────────────────────────────────────────────

def test_the_negotiate_body_is_thirty_six_bytes_plus_its_dialects():
    _, message = _unframe(smb_enum._negotiate_request())
    body = message[64:]
    structure_size, dialect_count = struct.unpack("<HH", body[:4])
    assert structure_size == 36
    assert len(body) == 36 + 2 * dialect_count, (len(body), dialect_count)


def test_the_negotiate_offers_the_dialects_it_claims_to():
    _, message = _unframe(smb_enum._negotiate_request())
    body = message[64:]
    count = struct.unpack("<H", body[2:4])[0]
    offered = struct.unpack("<" + "H" * count, body[36:36 + 2 * count])
    assert 0x0202 in offered and 0x0302 in offered, offered


# ── SESSION_SETUP, MS-SMB2 2.2.5 ────────────────────────────────────────────

def test_the_session_setup_body_is_twenty_four_bytes():
    # The old `<HBBIHH` produced 12. This is the defect that made the whole exchange
    # unparseable by the server.
    _, message = _unframe(smb_enum._session_setup_request(1, b"\x00" * 10))
    body_and_blob = message[64:]
    assert len(body_and_blob) == 24 + 10


def test_the_session_setup_structure_size_is_twenty_five():
    # 25 for a 24-byte body: that is what the specification says for a structure with
    # a trailing buffer, and the old code claimed 25 over 12 bytes.
    _, message = _unframe(smb_enum._session_setup_request(1, b"\x00"))
    assert struct.unpack("<H", message[64:66])[0] == 25


def test_the_security_buffer_offset_points_at_the_blob():
    blob = b"NTLMSSP\x00" + b"\x01\x02\x03"
    _, message = _unframe(smb_enum._session_setup_request(1, blob))
    offset, length = struct.unpack("<HH", message[64 + 12:64 + 16])
    assert offset == 88, offset
    assert length == len(blob)
    assert message[offset:offset + length] == blob, "the offset does not address the blob"


def test_the_previous_session_id_is_eight_bytes_not_four():
    # It was packed as part of a short body; getting its width wrong shifts every
    # field after it.
    _, message = _unframe(smb_enum._session_setup_request(1, b"\x00"))
    assert struct.unpack("<Q", message[64 + 16:64 + 24])[0] == 0


# ── TREE_CONNECT, MS-SMB2 2.2.9 ─────────────────────────────────────────────

def test_the_tree_connect_path_offset_is_seventy_two():
    # It was 0, so the server read the share name from the start of the message.
    _, message = _unframe(smb_enum._tree_connect_request(3, 1, "\\\\10.0.0.1\\C$"))
    structure_size, _, path_offset, path_length = struct.unpack("<HHHH", message[64:72])
    assert structure_size == 9
    assert path_offset == 72, path_offset
    assert path_length == len("\\\\10.0.0.1\\C$") * 2


def test_the_tree_connect_offset_addresses_the_path():
    path = "\\\\10.0.0.1\\ADMIN$"
    _, message = _unframe(smb_enum._tree_connect_request(3, 1, path))
    _, _, offset, length = struct.unpack("<HHHH", message[64:72])
    assert message[offset:offset + length].decode("utf-16-le") == path


def test_the_path_is_utf_16_little_endian():
    _, message = _unframe(smb_enum._tree_connect_request(3, 1, "\\\\1.1.1.1\\IPC$"))
    _, _, offset, length = struct.unpack("<HHHH", message[64:72])
    # Two bytes per character, and the ASCII ones have a zero high byte.
    assert length % 2 == 0
    assert message[offset + 1] == 0


# ── NTLMSSP, MS-NLMP 2.2.1.1 and 2.2.1.3 ───────────────────────────────────

def test_the_ntlm_negotiate_is_a_type_one_message():
    blob = smb_enum._ntlm_negotiate()
    assert blob[:8] == b"NTLMSSP\x00"
    assert struct.unpack("<I", blob[8:12])[0] == 1
    assert len(blob) == 32


def test_the_ntlm_authenticate_is_a_type_three_message():
    blob = smb_enum._ntlm_authenticate_anonymous()
    assert blob[:8] == b"NTLMSSP\x00"
    assert struct.unpack("<I", blob[8:12])[0] == 3


def test_the_ntlm_authenticate_carries_the_version_block():
    """
    72 bytes of header, not 64.

    This is the one thing here that no reading of the specification would have given:
    sent with a 64-byte header, a live Windows server answers
    STATUS_INVALID_PARAMETER; with the Version block it proceeds to evaluate the
    credential and answers ACCESS_DENIED. Found by sending both.
    """
    blob = smb_enum._ntlm_authenticate_anonymous()
    assert len(blob) == 73, f"header 72 + one LM byte, got {len(blob)}"
    # MS-NLMP 2.2.1.3: the six field triplets end at 59, NegotiateFlags occupies
    # 60-63, and Version follows at 64. (In the CHALLENGE message it is at 48, which
    # is a different structure -- mixing the two is how this test first failed.)
    major, minor, build = struct.unpack("<BBH", blob[64:68])
    assert (major, minor) == (10, 0), (major, minor)
    assert build > 0


def test_the_authenticate_asks_for_an_anonymous_session():
    # NTLMSSP_NEGOTIATE_ANONYMOUS. Without it the server would be asked to
    # authenticate an empty credential as a real one.
    flags = struct.unpack("<I", smb_enum._ntlm_authenticate_anonymous()[60:64])[0]
    assert flags & 0x00000800, f"0x{flags:08X}"


def test_the_anonymous_lm_response_is_one_zero_byte():
    # MS-NLMP 3.1.5.1.2: Z(1), and the NT response empty.
    blob = smb_enum._ntlm_authenticate_anonymous()
    lm_len, _, lm_off = struct.unpack("<HHI", blob[12:20])
    nt_len, _, _ = struct.unpack("<HHI", blob[20:28])
    assert (lm_len, lm_off) == (1, 72)
    assert blob[lm_off:lm_off + lm_len] == b"\x00"
    assert nt_len == 0


def test_empty_fields_do_not_point_past_the_end_of_the_message():
    """
    A zero-length field at an offset one byte past the message is what the first
    attempt sent, and it is a plausible reading of the structure. It is also rejected.
    """
    blob = smb_enum._ntlm_authenticate_anonymous()
    for field_start in (20, 28, 36, 44, 52):
        length, _, offset = struct.unpack("<HHI", blob[field_start:field_start + 8])
        if length == 0:
            assert offset <= len(blob), f"field at {field_start} points to {offset}"


# ── Reading responses ───────────────────────────────────────────────────────

def _response(status, session_id=0, body=b""):
    """A plausible SMB2 response message, NetBIOS frame already stripped."""
    header = struct.pack(
        smb_enum._SMB2_HEADER,
        b"\xfeSMB", 64, 0, status, 0, 1, 0x00000001, 0,
        1, 0, 0, session_id, b"\x00" * 16,
    )
    return header + body


def test_the_status_is_read_from_the_right_offset():
    assert smb_enum._status_of(_response(0xC0000022)) == 0xC0000022


def test_the_session_id_is_read_from_the_right_offset():
    assert smb_enum._session_id_of(_response(0, session_id=0xDEADBEEF)) == 0xDEADBEEF


class _ScriptedSocket:
    """Replays framed replies in order and records what was sent."""

    def __init__(self, replies):
        self._pending = b"".join(
            b"\x00" + len(r).to_bytes(3, "big") + r for r in replies)
        self.sent = []

    def settimeout(self, _):
        pass

    def connect(self, _):
        pass

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        chunk, self._pending = self._pending[:n], self._pending[n:]
        return chunk

    def close(self):
        pass


def test_a_message_is_read_whole_across_short_reads():
    body = _response(0, body=b"x" * 200)
    sock = _ScriptedSocket([body])
    assert smb_enum._read_message(sock) == body


def test_a_closed_connection_reads_as_nothing():
    assert smb_enum._read_message(_ScriptedSocket([])) is None


def test_an_implausible_frame_length_is_refused():
    """A length below a header or above a megabyte is not a message to wait for."""
    class _Bad:
        def __init__(self, n):
            self._data = b"\x00" + n.to_bytes(3, "big")

        def recv(self, k):
            out, self._data = self._data[:k], self._data[k:]
            return out

    assert smb_enum._read_message(_Bad(8)) is None
    assert smb_enum._read_message(_Bad(0x200000)) is None


# ── The three outcomes of a share probe ─────────────────────────────────────

def _enumerator_against(replies):
    """Run `_enumerate_shares` with a scripted server. Returns `(shares, note)`."""
    sock = _ScriptedSocket(replies)
    enum = SMBEnumerator(lambda *a, **k: None)
    original = smb_enum.socket.socket
    smb_enum.socket.socket = lambda *a, **k: sock
    try:
        return enum._enumerate_shares("10.0.0.1", 445)
    finally:
        smb_enum.socket.socket = original


#: The NTLM challenge leg: the server asks for a credential and grants a session id.
_CHALLENGE = _response(0xC0000016, session_id=0x1234,
                       body=b"\x00" * 8 + b"NTLMSSP\x00" + b"\x02" + b"\x00" * 40)


def test_a_server_that_refuses_anonymous_is_a_result_not_a_gap():
    """
    ACCESS_DENIED on the session setup answers the question being asked.

    There is no null-session access to this host, which is a finding. Reporting it as
    inconclusive would waste the measurement; reporting it as `[]` with no explanation
    would read as "a session was established and nothing was shared".
    """
    shares, note = _enumerator_against([
        _response(0),            # NEGOTIATE
        _CHALLENGE,              # SESSION_SETUP 1
        _response(0xC0000022),   # SESSION_SETUP 2 -- anonymous refused
    ])
    assert shares == []
    assert "refused an anonymous" in note


def test_a_logon_failure_is_the_same_kind_of_answer():
    shares, note = _enumerator_against([
        _response(0), _CHALLENGE, _response(0xC000006D),
    ])
    assert shares == []
    assert note


def test_a_server_that_stops_answering_is_undetermined():
    # None, so `_run_enum` puts `shares` in `inconclusive`.
    shares, note = _enumerator_against([_response(0)])
    assert shares is None
    assert "could not be determined" in note


def test_a_status_this_code_does_not_model_is_undetermined():
    shares, note = _enumerator_against([
        _response(0), _CHALLENGE, _response(0xC0000001),
    ])
    assert shares is None
    assert "0xC0000001" in note


def test_a_first_leg_that_grants_no_session_id_is_undetermined():
    no_session = _response(0xC0000016, session_id=0)
    shares, note = _enumerator_against([_response(0), no_session])
    assert shares is None


def test_an_established_session_reports_the_shares_it_reached():
    """
    The path a live server on this machine would not permit, driven from script.

    0 means the share was reached, ACCESS_DENIED means it exists and refused the null
    session, and BAD_NETWORK_NAME means the host does not have it.
    """
    replies = [_response(0), _CHALLENGE, _response(0)]
    # Ten share names are probed, in `_COMMON_SHARES` order.
    outcomes = [0x00000000, 0xC0000022] + [0xC00000CC] * (len(smb_enum._COMMON_SHARES) - 2)
    replies += [_response(code) for code in outcomes]

    shares, note = _enumerator_against(replies)
    assert shares is not None, note
    names = {s["name"]: s["access"] for s in shares}
    assert names == {smb_enum._COMMON_SHARES[0]: "OPEN",
                     smb_enum._COMMON_SHARES[1]: "DENIED"}, names


def test_an_established_session_that_reached_nothing_is_an_empty_result():
    replies = [_response(0), _CHALLENGE, _response(0)]
    replies += [_response(0xC00000CC)] * len(smb_enum._COMMON_SHARES)
    shares, note = _enumerator_against(replies)
    assert shares == []
    assert "none of the probed share" in note


def test_a_session_whose_share_probes_go_unanswered_is_undetermined():
    # The session was established but nothing came back, so nothing is known about
    # shares -- as against knowing that none was reachable.
    shares, note = _enumerator_against([_response(0), _CHALLENGE, _response(0)])
    assert shares is None
    assert "no share probe got a reply" in note


def test_every_probed_share_is_addressed_to_the_host_being_scanned():
    """
    The share path carries the target, so a wrong one attributes the result elsewhere.

    The first version of this test was vacuous: it scripted a *refused* session, so no
    TREE_CONNECT was ever sent, and the assertion sat inside a `for packet in sock.sent`
    guard that never matched. It passed with `_tree_connect_request` rewritten to send
    every path to 9.9.9.9. The session is established here, and the probes are counted
    before anything is asserted about them.
    """
    replies = [_response(0), _CHALLENGE, _response(0)]
    replies += [_response(0xC00000CC)] * len(smb_enum._COMMON_SHARES)
    sock = _ScriptedSocket(replies)
    enum = SMBEnumerator(lambda *a, **k: None)
    original = smb_enum.socket.socket
    smb_enum.socket.socket = lambda *a, **k: sock
    try:
        enum._enumerate_shares("10.1.2.3", 445)
    finally:
        smb_enum.socket.socket = original

    # Three session packets, then one per share name.
    tree_connects = sock.sent[3:]
    assert len(tree_connects) == len(smb_enum._COMMON_SHARES), len(tree_connects)
    target = "10.1.2.3".encode("utf-16-le")
    for packet in tree_connects:
        assert target in packet, "a share probe did not name the host being scanned"


def test_each_share_probe_uses_its_own_message_id():
    """
    MessageId was the literal 3 for all ten probes.

    MS-SMB2 3.3.5.2.3 has the server validate it against the sequence window and
    disconnect on a reuse, and Windows does -- so the second probe killed the
    connection and the loop broke with `answered` already True, returning a confident
    result for nine share names that were never asked about. `_ScriptedSocket` does not
    model the sequence window, so only an assertion on what was sent can see this.
    """
    replies = [_response(0), _CHALLENGE, _response(0)]
    replies += [_response(0xC00000CC)] * len(smb_enum._COMMON_SHARES)
    sock = _ScriptedSocket(replies)
    enum = SMBEnumerator(lambda *a, **k: None)
    original = smb_enum.socket.socket
    smb_enum.socket.socket = lambda *a, **k: sock
    try:
        enum._enumerate_shares("10.1.2.3", 445)
    finally:
        smb_enum.socket.socket = original

    ids = []
    for packet in sock.sent[3:]:
        _, message = _unframe(packet)
        ids.append(struct.unpack("<Q", message[24:32])[0])
    assert len(ids) == len(set(ids)), f"MessageId reused: {ids}"
    assert ids == sorted(ids), f"MessageId did not advance: {ids}"


def test_a_whole_message_read_has_a_deadline():
    """
    The socket timeout is per `recv`, not per message.

    A peer dribbling one byte just inside the timeout could hold the reader for days,
    and `start_enum` keeps the target in `_active` until the run returns -- so that host
    could never be enumerated again for the life of the process.
    """
    assert smb_enum._READ_DEADLINE_SECONDS > 0

    class _Dribbler:
        """Answers one byte at a time, slowly enough to exhaust the budget."""

        def __init__(self):
            self.calls = 0

        def recv(self, _n):
            self.calls += 1
            # Simulated by moving the clock rather than sleeping.
            smb_enum.time.monotonic = lambda base=self.calls: base * 10.0
            return bytes([0])

    original = smb_enum.time.monotonic
    try:
        assert smb_enum._read_message(_Dribbler()) is None
    finally:
        smb_enum.time.monotonic = original



# ── SMBv1, and telling "disabled" from "could not ask" ──────────────────────

"""
`_check_smbv1` returned None for every host, always. The request was pasted hex whose
NetBIOS header declared 45 bytes over a 47-byte payload -- the third copy of that
defect in this module -- so the server waited for two bytes that never came and reset
the connection, and every call landed in the `except` clause.

The comment there was right that returning False on a failure would report a clean
security posture for a host that was merely unreachable. The result was the opposite
extreme: a host with SMBv1 genuinely disabled got no credit for it, every report
carried an SMBv1 caveat for every host, and the EternalBlue finding -- whose condition
is `smbv1_enabled == True` -- could never fire at all.

The distinction is observable, which is the part the old code gave up on. A reset on an
SMBv1 negotiate means nothing by itself; a reset from a host whose **SMB2** negotiate
succeeded on the same port is that server declining the dialect. That is checked
against a live server for the refusal case: this machine answers SMB2 and resets SMBv1,
and is reported False with the reason. The True path is driven from planted bytes,
because enabling SMBv1 on a machine to test it is not a reasonable thing to do to it.
"""


def test_the_smb1_frame_length_matches_its_payload():
    # The defect, in one assertion. Declared 45 over 47 bytes.
    packet = smb_enum._smb1_negotiate_request()
    declared, message = _unframe(packet)
    assert declared == len(message), f"declared {declared}, carried {len(message)}"


def test_the_smb1_header_is_thirty_two_bytes():
    _, message = _unframe(smb_enum._smb1_negotiate_request())
    assert message[:4] == b"\xffSMB"
    assert message[4] == smb_enum._SMB1_CMD_NEGOTIATE


def test_the_dialect_buffer_is_counted_correctly():
    # WordCount then ByteCount then the buffer; a wrong ByteCount is the other way to
    # leave a server waiting.
    _, message = _unframe(smb_enum._smb1_negotiate_request())
    word_count, byte_count = struct.unpack("<BH", message[32:35])
    assert word_count == 0
    assert byte_count == len(message) - 35, (byte_count, len(message))


def test_the_dialect_is_the_one_that_matters():
    _, message = _unframe(smb_enum._smb1_negotiate_request())
    buffer = message[35:]
    # Buffer-format byte 0x02, then a NUL-terminated name.
    assert buffer[0] == 0x02
    assert buffer[1:-1] == smb_enum._SMB1_DIALECT
    assert buffer[-1] == 0x00


def _smb1_response(word_count=1, dialect_index=0):
    """An SMB_COM_NEGOTIATE reply, NetBIOS frame already stripped."""
    header = struct.pack(
        smb_enum._SMB1_HEADER,
        b"\xffSMB", smb_enum._SMB1_CMD_NEGOTIATE, 0, 0x98, 0xC853, 0,
        b"\x00" * 8, 0, 0xFFFF, 0xFEFF, 0, 0,
    )
    body = struct.pack("<B", word_count)
    if word_count:
        body += struct.pack("<H", dialect_index)
    return header + body


def test_the_dialect_index_is_read_from_the_right_offset():
    """
    Offsets 33:35 of the message, not 36:38 of the framed packet.

    The old read took `WordCount` and the low byte of `DialectIndex`, so even with a
    well-formed request the number compared against 0xFFFF was not the dialect index.
    """
    assert smb_enum._smb1_dialect_index(_smb1_response(dialect_index=0)) == 0
    assert smb_enum._smb1_dialect_index(_smb1_response(dialect_index=0xFFFF)) == 0xFFFF


def test_a_reply_with_no_body_has_no_dialect_index():
    # WordCount 0 is an error response; there is no index to read.
    assert smb_enum._smb1_dialect_index(_smb1_response(word_count=0)) is None


def test_a_reply_that_is_not_smb1_has_no_dialect_index():
    assert smb_enum._smb1_dialect_index(b"\x00" * 4 + b"\xfeSMB" + b"\x00" * 60) is None


class _ResettingSocket:
    """Accepts the request, then resets -- what a hardened Windows host does."""

    def settimeout(self, _):
        pass

    def connect(self, _):
        pass

    def sendall(self, _):
        pass

    def recv(self, _):
        raise ConnectionResetError("forcibly closed by the remote host")

    def close(self):
        pass


def _smbv1_verdict(sock, speaks_smb2=True):
    """`_check_smbv1` with the SMB2 reachability stage and the socket both controlled."""
    enum = SMBEnumerator(lambda *a, **k: None)
    enum._speaks_smb2 = lambda ip, port: speaks_smb2
    original = smb_enum.socket.socket
    smb_enum.socket.socket = lambda *a, **k: sock
    try:
        return enum._check_smbv1("10.0.0.1", 445)
    finally:
        smb_enum.socket.socket = original


def test_a_host_that_does_not_answer_smb2_is_undetermined():
    """
    The guard that makes False safe to report.

    Without it a reset is ambiguous: a firewall, a dropped route and a hardened server
    all look identical, and calling that "SMBv1 disabled" would be the clean-posture
    claim the old comment warned about.
    """
    verdict, note = _smbv1_verdict(_ResettingSocket(), speaks_smb2=False)
    assert verdict is None
    assert "did not complete an SMB2 negotiate" in note


def test_a_reset_from_a_host_that_speaks_smb2_is_a_refusal():
    verdict, note = _smbv1_verdict(_ResettingSocket(), speaks_smb2=True)
    assert verdict is False
    assert "reset the connection" in note
    # The limit of the inference is stated, not glossed over.
    assert "middlebox" in note


def test_a_server_answering_smb2_to_an_smb1_request_is_a_refusal():
    reply = b"\x00" * 4 + b"\xfeSMB" + b"\x00" * 90
    verdict, note = _smbv1_verdict(_ScriptedSocket([reply[4:]]))
    assert verdict is False
    assert "SMB2 header" in note


def test_a_refused_dialect_is_a_refusal():
    verdict, note = _smbv1_verdict(
        _ScriptedSocket([_smb1_response(dialect_index=0xFFFF)]))
    assert verdict is False
    assert "refused the NT LM 0.12 dialect" in note


def test_an_accepted_dialect_is_the_finding():
    """
    The path that could never be reached, and the reason the check exists.

    Driven from planted bytes: enabling SMBv1 on a machine to test this is not a
    reasonable thing to do to it, and this is the protocol WannaCry spread over.
    """
    verdict, note = _smbv1_verdict(_ScriptedSocket([_smb1_response(dialect_index=0)]))
    assert verdict is True
    assert "ENABLED" in note
    assert "EternalBlue" in note


def test_a_closed_connection_without_a_reply_is_a_refusal():
    verdict, note = _smbv1_verdict(_ScriptedSocket([]))
    assert verdict is False
    assert "closed the connection" in note


def test_every_verdict_carries_its_reason():
    # A bare boolean does not say whether the host refused or was never asked, and the
    # report prints the reason beside the result.
    for sock, smb2 in ((_ResettingSocket(), False), (_ResettingSocket(), True),
                       (_ScriptedSocket([_smb1_response(dialect_index=0)]), True),
                       (_ScriptedSocket([]), True)):
        _, note = _smbv1_verdict(sock, speaks_smb2=smb2)
        assert note and len(note) > 20, note


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
