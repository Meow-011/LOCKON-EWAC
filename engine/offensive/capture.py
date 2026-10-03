"""LOCKON EWAC — Handshake & PMKID Capture Module

Captures WPA/WPA2 4-way handshake EAPOL packets and PMKID from M1 frames
for offline cracking via Hashcat or the built-in Decryptor.

Requirements: Npcap + Monitor Mode Wi-Fi adapter.
"""
import os
import time
import struct
import threading
import logging
from scapy.all import sniff, EAPOL, Dot11, Dot11Beacon, Dot11Elt, wrpcap

logger = logging.getLogger(__name__)


def _extract_pmkid(eapol_raw: bytes) -> str | None:
    """Extract PMKID from an EAPOL M1 frame's Key Data RSN IE.
    
    EAPOL-Key layout (after 4-byte EAPOL header):
      [1-2]   Key Information
      [3-4]   Key Length
      [5-12]  Replay Counter
      [13-44] Key Nonce (ANonce for M1)
      [45-60] Key IV
      [61-68] Key RSC
      [69-76] Reserved
      [77-92] Key MIC (zeros in M1)
      [93-94] Key Data Length
      [95+]   Key Data (contains RSN IE with PMKID)
    """
    if len(eapol_raw) < 99:
        return None
    
    # Check Key Info: Pairwise(bit3) + Ack(bit7), no MIC(bit8) => M1
    key_info = struct.unpack('!H', eapol_raw[5:7])[0]
    pairwise = bool(key_info & 0x0008)
    ack = bool(key_info & 0x0080)
    mic_flag = bool(key_info & 0x0100)
    
    if not (pairwise and ack and not mic_flag):
        return None  # Not M1
    
    # Key Data Length at offset 97-98
    key_data_len = struct.unpack('!H', eapol_raw[97:99])[0]
    if key_data_len == 0:
        return None
    
    key_data = eapol_raw[99:99 + key_data_len]
    
    # Parse IEs in Key Data looking for RSN IE (tag 0x30) with PMKID
    offset = 0
    while offset + 2 <= len(key_data):
        tag_id = key_data[offset]
        tag_len = key_data[offset + 1]
        
        if offset + 2 + tag_len > len(key_data):
            break
        
        if tag_id == 0x30 and tag_len >= 20:  # RSN IE
            rsn_body = key_data[offset + 2:offset + 2 + tag_len]
            pos = 0
            
            if len(rsn_body) < 2:
                offset += 2 + tag_len
                continue
            
            # Version (2)
            pos += 2
            # Group Cipher Suite (4)
            if pos + 4 > len(rsn_body):
                offset += 2 + tag_len
                continue
            pos += 4
            # Pairwise Cipher Suite Count (2)
            if pos + 2 > len(rsn_body):
                offset += 2 + tag_len
                continue
            pw_count = struct.unpack('<H', rsn_body[pos:pos+2])[0]
            pos += 2
            # Pairwise Cipher Suites (4 * count)
            pos += 4 * pw_count
            # AKM Suite Count (2)
            if pos + 2 > len(rsn_body):
                offset += 2 + tag_len
                continue
            akm_count = struct.unpack('<H', rsn_body[pos:pos+2])[0]
            pos += 2
            # AKM Suites (4 * count)
            pos += 4 * akm_count
            # RSN Capabilities (2)
            if pos + 2 > len(rsn_body):
                offset += 2 + tag_len
                continue
            pos += 2
            # PMKID Count (2)
            if pos + 2 > len(rsn_body):
                offset += 2 + tag_len
                continue
            pmkid_count = struct.unpack('<H', rsn_body[pos:pos+2])[0]
            pos += 2
            
            if pmkid_count > 0 and pos + 16 <= len(rsn_body):
                pmkid = rsn_body[pos:pos+16]
                if pmkid != b'\x00' * 16:
                    return pmkid.hex()
        
        offset += 2 + tag_len
    
    return None


def _eapol_message_number(eapol_raw: bytes) -> int | None:
    """Identify which WPA 4-way handshake message an EAPOL-Key frame is.

    Uses the same Key Information bits that ``_extract_pmkid`` parses:
      bit 3  (0x0008) Pairwise
      bit 6  (0x0040) Install
      bit 7  (0x0080) Key Ack
      bit 8  (0x0100) Key MIC
      bit 9  (0x0200) Secure

      M1: Pairwise, Ack, no MIC          (AP -> STA, carries ANonce/PMKID)
      M2: Pairwise, MIC, not Secure      (STA -> AP, carries SNonce)
      M3: Pairwise, Ack, MIC             (AP -> STA)
      M4: Pairwise, MIC, Secure, no Ack  (STA -> AP)

    Returns 1-4, or None if this is not a pairwise EAPOL-Key frame.
    """
    if len(eapol_raw) < 99:
        return None

    key_info = struct.unpack('!H', eapol_raw[5:7])[0]
    pairwise = bool(key_info & 0x0008)
    ack = bool(key_info & 0x0080)
    mic_flag = bool(key_info & 0x0100)
    secure = bool(key_info & 0x0200)

    if not pairwise:
        return None

    if ack and not mic_flag:
        return 1
    if ack and mic_flag:
        return 3
    if mic_flag and secure:
        return 4
    if mic_flag:
        return 2
    return None


# A usable handshake needs a real message pair, not merely two frames.
_USABLE_PAIRS = ({1, 2}, {2, 3})


class HandshakeCapture:
    def __init__(self, ipc_handler):
        self.ipc = ipc_handler
        self.capturing = False
        self.pmkid_capturing = False
        self.capture_thread = None
        self.packets = []

    def start_capture(self, bssid, interface=None, timeout=15):
        """Capture WPA 4-way handshake EAPOL packets."""
        if self.capturing:
            self.ipc.emit("capture_error", {"bssid": bssid, "message": "Capture already in progress"})
            return

        self.capturing = True
        self.packets = []
        bssid_lower = bssid.lower()

        self.ipc.emit("capture_started", {"bssid": bssid, "interface": interface})

        def _sniff_loop():
            seen_raw = set()        # raw frame bytes — an identical frame never counts twice
            seen_messages = set()   # distinct EAPOL handshake message numbers (M1..M4)
            # Every frame the interface hands us, before any filtering.
            #
            # This is the difference between "we listened and the target produced
            # no handshake" and "this adapter never delivered a single 802.11
            # frame". Both used to end in the same sentence — "no usable
            # handshake pair detected" — which reads as a finding about the
            # target when it is actually a finding about the rig. On a managed-
            # mode Windows adapter, which is most of them, the second case is
            # what happens every time.
            stats = {"frames": 0, "eapol": 0}

            def _has_usable_pair():
                return any(pair <= seen_messages for pair in _USABLE_PAIRS)

            # prn: side effects only, never decides when to stop
            def packet_handler(pkt):
                if not self.capturing:
                    return
                stats["frames"] += 1
                if not pkt.haslayer(EAPOL):
                    return
                stats["eapol"] += 1

                # Simple check if it involves our target BSSID
                addrs = {(getattr(pkt, f"addr{i}", None) or "").lower() for i in (1, 2, 3)}
                if bssid_lower not in addrs:
                    return

                raw = bytes(pkt)
                if raw in seen_raw:
                    return  # exact duplicate frame — cannot help build a handshake
                seen_raw.add(raw)

                msg = _eapol_message_number(bytes(pkt[EAPOL]))
                self.packets.append(pkt)
                if msg is not None:
                    seen_messages.add(msg)

                self.ipc.emit("capture_packet", {
                    "bssid": bssid,
                    "count": len(self.packets),
                    "eapol_message": msg,
                    "messages_seen": sorted(seen_messages),
                })

            # stop_filter: a pure predicate — it only decides whether to stop
            def stop_filter(pkt):
                return (not self.capturing) or _has_usable_pair()

            try:
                # In Windows without Npcap in monitor mode, this might fail or not capture anything.
                # But the architecture is sound for when run on Linux/Kali or with proper Npcap.
                # Sniff in short slices so stop_capture() is honoured on a quiet channel too.
                deadline = time.time() + timeout
                while self.capturing and not _has_usable_pair():
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    sniff(
                        iface=interface,
                        prn=packet_handler,
                        stop_filter=stop_filter,
                        timeout=min(1, remaining),
                        store=0,
                    )

                # Exactly one terminal event on every path
                if _has_usable_pair():
                    # Written into the evidence directory and hashed on the spot.
                    # This used to land in whatever CWD the sidecar had, unhashed
                    # and unrecorded, so the file backing a "handshake captured"
                    # claim could not be tied to the finding or shown unaltered.
                    from evidence import build_path, register
                    filepath = build_path("handshake", bssid.replace(":", ""), ".pcap")
                    wrpcap(filepath, self.packets)
                    record = register(
                        filepath, "handshake_pcap", emit=self.ipc.emit,
                        bssid=bssid, messages=sorted(seen_messages),
                        packet_count=len(self.packets),
                    )
                    self.ipc.emit("capture_success", {
                        "bssid": bssid,
                        "file": filepath,
                        "sha256": record.get("sha256"),
                        "size_bytes": record.get("size_bytes"),
                        "messages": sorted(seen_messages),
                    })
                elif not self.capturing:
                    self.ipc.emit("capture_aborted", {
                        "bssid": bssid,
                        "packets": len(self.packets),
                        "messages_seen": sorted(seen_messages),
                        "frames_seen": stats["frames"],
                        "message": "Capture cancelled before a usable handshake was seen",
                    })
                elif stats["frames"] == 0:
                    # Nothing arrived at all. Whatever this says, it is not about
                    # the target: the radio never handed us a frame to judge.
                    self.ipc.emit("capture_failed", {
                        "bssid": bssid,
                        "packets": 0,
                        "messages_seen": [],
                        "frames_seen": 0,
                        "inconclusive": True,
                        "reason": (
                            f"No 802.11 frames were captured at all in {timeout}s — not one, "
                            "from any network. The adapter is almost certainly in managed mode, "
                            "where it cannot see other stations' traffic."
                        ),
                        "caveat": (
                            "This says nothing about the target. It is not evidence that the "
                            "network is secure, that no client is connected, or that no handshake "
                            "occurred. Re-run with an adapter in monitor mode before recording "
                            "any conclusion."
                        ),
                    })
                else:
                    self.ipc.emit("capture_failed", {
                        "bssid": bssid,
                        "packets": len(self.packets),
                        "messages_seen": sorted(seen_messages),
                        "frames_seen": stats["frames"],
                        "inconclusive": False,
                        "reason": (
                            f"Timeout ({timeout}s): {stats['frames']} frame(s) were captured but no "
                            "usable handshake pair (M1+M2 or M2+M3) for this BSSID."
                        ),
                        "caveat": (
                            "A handshake is only transmitted when a client joins. Absence over one "
                            "short window is not evidence that the network is unused or secure."
                        ),
                    })

            except Exception as e:
                self.ipc.emit("capture_error", {"bssid": bssid, "message": str(e)})
            finally:
                self.capturing = False

        self.capture_thread = threading.Thread(target=_sniff_loop, daemon=True)
        self.capture_thread.start()

    def start_pmkid_capture(self, bssid, interface=None, timeout=30):
        """Capture PMKID from EAPOL M1 frame — no full handshake needed.
        
        PMKID is embedded in the first EAPOL message (M1) sent by the AP.
        Unlike traditional capture, this only needs a single frame and
        doesn't require an active client to be connected.
        
        The captured PMKID is exported directly to .hc22000 format.
        """
        if self.pmkid_capturing:
            self.ipc.emit("pmkid_error", {"bssid": bssid, "message": "PMKID capture already in progress"})
            return
        
        self.pmkid_capturing = True
        bssid_lower = bssid.lower()
        bssid_clean = bssid.lower().replace(':', '')
        
        self.ipc.emit("pmkid_started", {"bssid": bssid})
        
        def _pmkid_worker():
            essid = ""
            eapol_count = 0
            pmkid_found = False

            try:
                # prn: side effects only, never decides when to stop
                def _handle_packet(pkt):
                    nonlocal essid, eapol_count, pmkid_found

                    if not self.pmkid_capturing or pmkid_found:
                        return

                    # Extract ESSID from beacon frames
                    if pkt.haslayer(Dot11Beacon):
                        try:
                            beacon_bssid = pkt[Dot11].addr2
                            if beacon_bssid and beacon_bssid.lower() == bssid_lower:
                                elt = pkt[Dot11Elt]
                                while elt:
                                    if elt.ID == 0:
                                        essid = elt.info.decode('utf-8', errors='ignore')
                                        break
                                    next_elt = elt.payload if hasattr(elt, 'payload') else None
                                    elt = next_elt if isinstance(next_elt, Dot11Elt) else None
                        except Exception:
                            pass
                        return
                    
                    # Look for EAPOL frames targeting our BSSID
                    if not pkt.haslayer(EAPOL):
                        return
                    
                    addr1 = (pkt.addr1 or "").lower()
                    addr2 = (pkt.addr2 or "").lower()
                    addr3 = (pkt.addr3 or "").lower()
                    
                    if bssid_lower not in (addr1, addr2, addr3):
                        return
                    
                    eapol_count += 1
                    self.ipc.emit("pmkid_eapol_seen", {
                        "bssid": bssid,
                        "count": eapol_count,
                    })
                    
                    # Try to extract PMKID
                    eapol_raw = bytes(pkt[EAPOL])
                    pmkid = _extract_pmkid(eapol_raw)
                    
                    if pmkid:
                        # M1 is AP -> STA: addr2 (transmitter) = AP
                        mac_ap = addr2.replace(':', '')
                        mac_sta = addr1.replace(':', '')
                        
                        if mac_ap != bssid_clean:
                            mac_ap = bssid_clean
                            mac_sta = addr2.replace(':', '') if addr2.replace(':', '') != bssid_clean else addr1.replace(':', '')
                        
                        essid_hex = essid.encode('utf-8').hex() if essid else ''
                        hash_line = f"WPA*01*{pmkid}*{mac_ap}*{mac_sta}*{essid_hex}***"
                        
                        # Mark found first so the frame can never be processed twice
                        pmkid_found = True

                        # Save .hc22000 into the evidence directory and hash it,
                        # so the artifact behind this finding is registered like
                        # any other piece of evidence.
                        from evidence import build_path, register
                        output_file = build_path("pmkid", bssid_clean, ".hc22000")
                        saved = True
                        write_error = None
                        try:
                            with open(output_file, 'w') as f:
                                f.write(hash_line + '\n')
                        except Exception as e:
                            saved = False
                            write_error = str(e)
                            logger.warning("Failed to write PMKID file: %s", e)

                        record = {}
                        if saved:
                            record = register(
                                output_file, "pmkid_hc22000", emit=self.ipc.emit,
                                bssid=bssid, ssid=essid,
                            )

                        self.ipc.emit("pmkid_captured", {
                            "bssid": bssid,
                            "ssid": essid,
                            "pmkid": pmkid,
                            "mac_ap": mac_ap,
                            "mac_sta": mac_sta,
                            "hash_line": hash_line,
                            "output_file": os.path.abspath(output_file),
                            "sha256": record.get("sha256"),
                            "saved": saved,
                            "error": write_error,
                        })

                # stop_filter: a pure predicate — it only decides whether to stop
                def _should_stop(pkt):
                    return (not self.pmkid_capturing) or pmkid_found

                # Sniff in short slices so stop_pmkid() is honoured on a quiet channel too.
                deadline = time.time() + timeout
                while self.pmkid_capturing and not pmkid_found:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    sniff(
                        iface=interface,
                        prn=_handle_packet,
                        stop_filter=_should_stop,
                        timeout=min(1, remaining),
                        store=0
                    )

                # Exactly one terminal event on every path
                # (pmkid_captured is the terminal event for the success path)
                if not pmkid_found:
                    if not self.pmkid_capturing:
                        self.ipc.emit("pmkid_aborted", {
                            "bssid": bssid,
                            "eapol_seen": eapol_count,
                            "message": "PMKID capture cancelled by operator",
                        })
                    else:
                        msg = (
                            f"EAPOL frames seen ({eapol_count}) but no PMKID found"
                            if eapol_count > 0
                            else "No EAPOL frames detected. Ensure Npcap + Monitor Mode are active."
                        )
                        self.ipc.emit("pmkid_timeout", {
                            "bssid": bssid,
                            "eapol_seen": eapol_count,
                            "message": f"Timeout ({timeout}s): {msg}"
                        })

            except Exception as e:
                self.ipc.emit("pmkid_error", {"bssid": bssid, "message": str(e)})
            finally:
                self.pmkid_capturing = False
        
        threading.Thread(target=_pmkid_worker, daemon=True).start()

    def stop_capture(self):
        self.capturing = False

    def stop_pmkid(self):
        """Stop an active PMKID capture."""
        self.pmkid_capturing = False
