"""LOCKON EWAC — Hashcat Export Module

Converts captured PCAP handshake files to Hashcat-compatible .hc22000 format.
Supports both PMKID (mode 22000 type 01) and full 4-way handshake (type 02).

Output format spec: https://hashcat.net/wiki/doku.php?id=hc22000
"""
import os
import struct
import logging
import threading

logger = logging.getLogger(__name__)


def _bytes_to_hex(data: bytes) -> str:
    """Convert bytes to lowercase hex string."""
    return data.hex()


def _pmkid_from_rsn_ie(rsn_data: bytes) -> str | None:
    """
    Walk an RSN IE body and return its first PMKID, or None.

    Every field is consumed in order, per IEEE 802.11 (RSNE):

        version                 2
        group data cipher       4
        pairwise count          2   + 4 * count
        AKM count               2   + 4 * count
        RSN capabilities        2       (optional, and everything after it too)
        PMKID count             2   + 16 * count
        group management cipher 4       (optional)

    The trailing fields are genuinely optional, so the *only* way to know
    whether a PMKID is present is to parse up to the PMKID Count field and read
    it. Anything that runs out of bytes on the way returns None.

    This replaces a heuristic that took the last 16 bytes of the IE:

        pmkid_candidate = rsn_data[-16:]
        if pmkid_candidate != b'\\x00' * 16:
            return _bytes_to_hex(pmkid_candidate)

    with the comment "Simple heuristic ... The structure varies". It was wrong in
    both directions, and the consequences ran all the way into the report:

      * **It invented a PMKID where there was none.** An RSN IE carrying RSN
        Capabilities and a Group Management Cipher (i.e. any AP with 802.11w,
        which is most of them) is long enough to clear the old `>= 24` gate, so
        the last 16 bytes — cipher-suite and capability bytes — were emitted as
        a PMKID. That produced a syntactically valid hash line for a capture
        containing no PMKID at all. hashcat then ran the whole wordlist against
        a hash that cannot match and exited "exhausted", and the pipeline
        reported *"hashcat exhausted the wordlist without recovering the key"* —
        a confident statement that a network's passphrase is not in the tested
        list, about a target where nothing was ever tested.
      * **It was wrong even when a PMKID was present**, because a Group
        Management Cipher Suite after the PMKID List shifted the window by four
        bytes.

    Refusing is the correct failure here, and it is what the project's own rule
    requires: a missed PMKID is a gap the report already declares, while a
    fabricated one silently converts "not measured" into "measured and secure".
    """
    off = 0
    n = len(rsn_data)

    def need(count: int) -> bool:
        return off + count <= n

    if not need(2):
        return None
    off += 2                                   # version

    if not need(4):
        return None
    off += 4                                   # group data cipher suite

    if not need(2):
        return None
    pairwise_count = struct.unpack_from('<H', rsn_data, off)[0]
    off += 2
    if not need(4 * pairwise_count):
        return None
    off += 4 * pairwise_count

    if not need(2):
        return None
    akm_count = struct.unpack_from('<H', rsn_data, off)[0]
    off += 2
    if not need(4 * akm_count):
        return None
    off += 4 * akm_count

    # From here on the fields are optional. Absent means no PMKID, which is the
    # common case and is not an error.
    if not need(2):
        return None
    off += 2                                   # RSN capabilities

    if not need(2):
        return None
    pmkid_count = struct.unpack_from('<H', rsn_data, off)[0]
    off += 2
    if pmkid_count == 0:
        return None
    if not need(16 * pmkid_count):
        # Count says there is a PMKID but the bytes are not there: a truncated
        # or malformed IE. Refuse rather than read whatever follows.
        return None

    pmkid = rsn_data[off:off + 16]
    # An all-zero PMKID is a placeholder, not a value.
    if pmkid == b'\x00' * 16:
        return None
    return _bytes_to_hex(pmkid)


def _extract_pmkid_from_key_data(key_data: bytes) -> str | None:
    """Extract the PMKID from the RSN IE (tag 0x30) in an EAPOL Key Data field."""
    offset = 0
    while offset + 2 <= len(key_data):
        tag_id = key_data[offset]
        tag_len = key_data[offset + 1]
        if offset + 2 + tag_len > len(key_data):
            # Declared length runs past the buffer — stop rather than parse
            # whatever happens to be there.
            return None

        if tag_id == 0x30 and tag_len > 0:      # RSN IE
            pmkid = _pmkid_from_rsn_ie(key_data[offset + 2:offset + 2 + tag_len])
            if pmkid:
                return pmkid

        offset += 2 + tag_len

    return None


def _parse_eapol_key_info(raw_bytes: bytes) -> dict:
    """Parse EAPOL-Key frame fields from raw bytes."""
    if len(raw_bytes) < 99:  # Minimum EAPOL-Key frame size
        return {}
    
    # EAPOL header: version(1) + type(1) + length(2)
    # Key descriptor: type(1) + key_info(2) + key_length(2) + replay_counter(8) + nonce(32) + iv(16) + rsc(8) + reserved(8) + mic(16) + key_data_length(2) + key_data(variable)
    
    result = {}
    
    try:
        # Key Info is at offset 5-6 (after EAPOL header + key descriptor type)
        key_info = struct.unpack('!H', raw_bytes[5:7])[0]
        
        # Determine message number from key_info flags
        pairwise = bool(key_info & 0x0008)
        install = bool(key_info & 0x0040)
        ack = bool(key_info & 0x0080)
        mic_flag = bool(key_info & 0x0100)
        
        # Key Data Length (2 bytes at offset 97) — needed to tell M2 from M4.
        key_data_len = struct.unpack('!H', raw_bytes[97:99])[0]
        result['key_data_length'] = key_data_len

        if pairwise and ack and not mic_flag:
            result['message'] = 1  # M1: AP -> STA (ANonce, no MIC)
        elif pairwise and ack and mic_flag and install:
            result['message'] = 3  # M3: AP -> STA (ANonce, MIC, Install)
        elif pairwise and mic_flag and not ack:
            # M2 and M4 share pairwise=1, mic=1, ack=0, install=0. The only
            # reliable discriminator is Key Data Length: M2 carries the RSN IE
            # (len > 0), M4 carries no key data (len == 0).
            if key_data_len > 0:
                result['message'] = 2  # M2: STA -> AP (SNonce, MIC, RSN IE)
            else:
                result['message'] = 4  # M4: STA -> AP (MIC, no key data)

        # Key Length (2 bytes at offset 7)
        result['key_length'] = struct.unpack('!H', raw_bytes[7:9])[0]
        
        # Replay Counter (8 bytes at offset 9)
        result['replay_counter'] = raw_bytes[9:17]
        
        # Nonce (32 bytes at offset 17)
        result['nonce'] = raw_bytes[17:49]
        
        # MIC (16 bytes at offset 81)
        result['mic'] = raw_bytes[81:97]
        
        # Key Data
        result['key_data'] = raw_bytes[99:99 + key_data_len]
        
        # Full EAPOL frame (needed for hashcat)
        result['eapol_frame'] = raw_bytes
        
    except Exception as e:
        logger.debug(f"EAPOL parse error: {e}")
    
    return result


def pcap_to_hc22000(pcap_path: str, output_path: str = None) -> dict:
    """Convert a PCAP file containing WPA handshakes to .hc22000 format.
    
    Returns:
        dict with keys: success, output_path, hash_count, hashes, error
    """
    try:
        from scapy.all import rdpcap, EAPOL, Dot11, Dot11Beacon, Dot11Elt
    except ImportError:
        return {"success": False, "error": "Scapy not available"}
    
    if not os.path.exists(pcap_path):
        return {"success": False, "error": f"File not found: {pcap_path}"}
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        return {"success": False, "error": f"Failed to read PCAP: {str(e)}"}
    
    # Collect beacon frames for ESSID lookup
    essid_map = {}  # bssid -> essid
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            try:
                bssid = pkt[Dot11].addr2
                if bssid:
                    bssid = bssid.lower().replace(':', '')
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 0:  # SSID
                            essid_map[bssid] = elt.info
                            break
                        elt = elt.payload if hasattr(elt, 'payload') and hasattr(elt.payload, 'ID') else None
            except Exception:
                pass
    
    # Collect EAPOL frames grouped by AP-STA pair
    handshakes = {}  # (mac_ap, mac_sta) -> {m1, m2, m3, m4, essid}

    # Why each handshake that produced no hash produced none.
    #
    # Returned to the caller rather than logged, so a partial conversion cannot
    # be mistaken for a complete one. `hash_count` alone was being read as the
    # full inventory of what the capture held.
    from collections import Counter
    skipped = Counter({
        "eapol_errors": 0,
        "no_essid": 0,
        "no_m1": 0,
        "no_usable_reply": 0,
        "missing_nonce_or_mic": 0,
        "eapol_too_short": 0,
        "handshakes_dropped": 0,
    })
    
    for pkt in packets:
        if not pkt.haslayer(EAPOL):
            continue
        
        try:
            # Get MAC addresses
            addr1 = pkt.addr1.lower().replace(':', '') if pkt.addr1 else None
            addr2 = pkt.addr2.lower().replace(':', '') if pkt.addr2 else None
            addr3 = pkt.addr3.lower().replace(':', '') if pkt.addr3 else None
            
            if not addr1 or not addr2:
                continue
            
            # Extract raw EAPOL bytes
            eapol_raw = bytes(pkt[EAPOL])
            key_info = _parse_eapol_key_info(eapol_raw)
            
            if not key_info.get('message'):
                continue
            
            msg_num = key_info['message']
            
            # Determine AP and STA MACs
            # M1/M3: AP -> STA (addr2=AP, addr1=STA)
            # M2/M4: STA -> AP (addr2=STA, addr1=AP)
            if msg_num in (1, 3):
                mac_ap = addr2
                mac_sta = addr1
            else:
                mac_ap = addr1
                mac_sta = addr2
            
            pair_key = (mac_ap, mac_sta)
            if pair_key not in handshakes:
                handshakes[pair_key] = {}
            
            handshakes[pair_key][f'm{msg_num}'] = key_info
            
            # Try to find ESSID
            if mac_ap in essid_map:
                handshakes[pair_key]['essid'] = essid_map[mac_ap]
            elif addr3 and addr3 in essid_map:
                handshakes[pair_key]['essid'] = essid_map[addr3]
                
        except Exception as e:
            logger.debug(f"EAPOL processing error: {e}")
            skipped["eapol_errors"] += 1
            continue

    # Generate .hc22000 hash lines
    hash_lines = []

    for (mac_ap, mac_sta), data in handshakes.items():
        produced_before = len(hash_lines)
        essid_bytes = data.get('essid', b'')
        essid_hex = _bytes_to_hex(essid_bytes) if essid_bytes else ''
        if not essid_hex:
            # hashcat can refuse a line with an empty ESSID field. Counted so a
            # rejection at the other end is traceable to a capture with no
            # beacon for this AP rather than looking like a mystery.
            skipped["no_essid"] += 1
        
        # Try PMKID first (from M1 key data)
        if 'm1' in data:
            m1 = data['m1']
            if m1.get('key_data'):
                pmkid = _extract_pmkid_from_key_data(m1['key_data'])
                if pmkid:
                    # WPA*01*PMKID*MAC_AP*MAC_STA*ESSID_HEX***
                    line = f"WPA*01*{pmkid}*{mac_ap}*{mac_sta}*{essid_hex}***"
                    hash_lines.append(line)
        
        # Full handshake: ANonce comes from M1, MIC + EAPOL from the station's
        # reply. Message pair: 00 = M1+M2, 01 = M1+M4, 02 = M2+M3, etc.
        # Prefer M2; fall back to M4 when only M4 was captured.
        if 'm1' in data:
            m1 = data['m1']
            if 'm2' in data:
                reply, message_pair = data['m2'], "00"
            elif 'm4' in data:
                reply, message_pair = data['m4'], "01"
            else:
                reply, message_pair = None, None

            if reply is not None:
                anonce = _bytes_to_hex(m1.get('nonce', b''))
                mic = _bytes_to_hex(reply.get('mic', b''))

                if anonce and mic:
                    # Build the station's EAPOL frame with MIC zeroed out
                    eapol_frame = bytearray(reply.get('eapol_frame', b''))
                    if len(eapol_frame) >= 97:
                        # Zero out MIC field (offset 81-97) for hash computation
                        eapol_zeroed = bytes(eapol_frame[:81] + b'\x00' * 16 + eapol_frame[97:])
                        eapol_hex = _bytes_to_hex(eapol_zeroed)

                        # WPA*02*MIC*MAC_AP*MAC_STA*ESSID_HEX*ANONCE*EAPOL*MESSAGE_PAIR
                        line = f"WPA*02*{mic}*{mac_ap}*{mac_sta}*{essid_hex}*{anonce}*{eapol_hex}*{message_pair}"
                        hash_lines.append(line)
                    else:
                        skipped["eapol_too_short"] += 1
                else:
                    skipped["missing_nonce_or_mic"] += 1
            else:
                skipped["no_usable_reply"] += 1
        elif 'm1' not in data:
            # Only pairs containing M1 are ever emitted, so an M2+M3 capture
            # produces nothing. That is a refusal rather than a wrong answer,
            # but it needs counting or "no handshakes found" reads as "no
            # handshake occurred".
            skipped["no_m1"] += 1

        if len(hash_lines) == produced_before:
            skipped["handshakes_dropped"] += 1

    if not hash_lines:
        return {
            "success": False,
            "error": "No valid handshakes or PMKIDs found in PCAP",
            "hash_count": 0,
            "skipped": dict(skipped),
            "caveat": (
                "No hash could be built from this capture. That is a statement about the capture, "
                "not about the networks in it: only handshake pairs containing message 1 can be "
                "converted, and a pair whose beacon was never seen has no ESSID to build with."
            ),
        }
    
    # Write output file
    if not output_path:
        base = os.path.splitext(pcap_path)[0]
        output_path = f"{base}.hc22000"
    
    try:
        with open(output_path, 'w') as f:
            for line in hash_lines:
                f.write(line + '\n')
    except Exception as e:
        return {"success": False, "error": f"Failed to write output: {str(e)}"}
    
    return {
        "success": True,
        "output_path": os.path.abspath(output_path),
        "hash_count": len(hash_lines),
        "hashes": hash_lines,
        # What the conversion could not use.
        #
        # Every per-packet failure used to go into `logger.debug` or a bare
        # `pass`, and the returned dict had no counter at all — so a capture
        # whose five handshakes were cut to one by dissector quirks reported
        # `hash_count: 1` and that number was presented as the complete
        # inventory. A confident "not cracked" then meant "most of this was
        # never tested", with no channel to say so.
        "skipped": dict(skipped),
        "handshake_pairs_seen": len(handshakes),
    }


def pmkid_to_hc22000(pmkid: str, mac_ap: str, mac_sta: str, essid: str) -> str:
    """Create a single .hc22000 PMKID hash line.
    
    Args:
        pmkid: 32-char hex PMKID
        mac_ap: AP MAC (hex, no colons)
        mac_sta: Station MAC (hex, no colons)
        essid: Network name (plaintext)
    
    Returns:
        Hashcat-compatible hash line
    """
    essid_hex = essid.encode('utf-8').hex()
    mac_ap_clean = mac_ap.lower().replace(':', '')
    mac_sta_clean = mac_sta.lower().replace(':', '')
    return f"WPA*01*{pmkid}*{mac_ap_clean}*{mac_sta_clean}*{essid_hex}***"


def _no_window_kwargs() -> dict:
    """creationflags=CREATE_NO_WINDOW on Windows, nothing elsewhere.

    Keeps a console window from flashing when the sidecar shells out.
    """
    import sys
    if sys.platform == "win32":
        return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
    return {}


def detect_hashcat() -> dict:
    """Check if hashcat is installed and accessible."""
    import subprocess
    try:
        result = subprocess.run(
            ['hashcat', '--version'],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5,
            **_no_window_kwargs()
        )
        if result.returncode == 0:
            return {"installed": True, "version": result.stdout.strip()}
    except (OSError, subprocess.SubprocessError):
        # FileNotFoundError / PermissionError / TimeoutExpired / anything else
        # the platform throws when the binary cannot be launched.
        pass

    # Try common Windows paths
    common_paths = [
        r"C:\hashcat\hashcat.exe",
        r"C:\Tools\hashcat\hashcat.exe",
        os.path.expanduser(r"~\hashcat\hashcat.exe"),
    ]
    for path in common_paths:
        if os.path.exists(path):
            try:
                result = subprocess.run(
                    [path, '--version'],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5,
                    **_no_window_kwargs()
                )
                if result.returncode == 0:
                    return {"installed": True, "version": result.stdout.strip(), "path": path}
            except Exception:
                pass

    # Report where we looked so the UI can tell the operator exactly what to fix
    # rather than just "not found".
    return {"installed": False, "searched": ["PATH"] + common_paths}


class HashcatExporter:
    """IPC-connected wrapper for hashcat export operations."""

    def __init__(self, emit_fn):
        self.emit = emit_fn

    def export(self, pcap_path: str, output_path: str = None):
        """Export PCAP to .hc22000 in a background thread."""
        def _run():
            self.emit("hashcat_export_started", {"pcap_path": pcap_path})
            result = pcap_to_hc22000(pcap_path, output_path)
            
            if result.get("success"):
                self.emit("hashcat_exported", {
                    "output_path": result["output_path"],
                    "hash_count": result["hash_count"],
                    "hashes": result["hashes"],
                })
            else:
                self.emit("hashcat_export_error", {
                    "pcap_path": pcap_path,
                    "message": result.get("error", "Unknown error"),
                })
        
        threading.Thread(target=_run, daemon=True).start()

    def check_hashcat(self):
        """Check if hashcat is installed."""
        try:
            result = detect_hashcat()
        except OSError as e:
            # Never let a platform-level launch failure escape as a generic
            # `error` event — the UI is waiting on hashcat_status.
            result = {"installed": False, "error": str(e)}
        self.emit("hashcat_status", result)
