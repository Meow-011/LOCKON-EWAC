import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import IPy
import queue
import time
import platform
import subprocess
import re
from scanner.cve_db import annotate_host_inferences, lookup_cves

#: `_read_arp_cache`'s `except Exception` handler called `logger.debug` with no
#: `logger` in this module. A NameError raised inside an `except` block is not
#: caught by that block, so it escaped `_read_arp_cache` -- past the
#: `return arp_cache` it never reached -- and on out through `_run_scan` into
#: `run_scan`'s own handler. The whole sweep aborted with
#: `intrusion_error: "Scan failed: name 'logger' is not defined"`, and the
#: `arp_read_error` the handler had just written one line earlier was discarded
#: with the object.
#:
#: So the one path the ARP-read reporting exists for -- `arp.exe` failing with
#: anything other than a timeout, which on a localised Windows includes a decode
#: error -- was the path on which none of it ran.
logger = logging.getLogger("ewac.lan")

OUI_DB = {
    "00:10:83": "Hewlett-Packard",
    "00:17:f2": "Apple",
    "00:03:93": "Apple",
    "d4:61:9d": "Apple",
    "80:be:05": "Apple",
    "f0:18:98": "Apple",
    "c4:2c:03": "Apple",
    "bc:d0:74": "Apple",
    "18:fe:34": "Espressif",
    "24:6f:28": "Espressif",
    "c8:2b:96": "Espressif",
    "c4:4f:33": "Tuya",
    "50:04:b8": "Tuya",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:11:32": "Synology",
    "00:24:e4": "Withings",
    "00:1a:11": "Google",
    "3c:5a:b4": "Google",
    "f4:f5:e8": "Google",
    "00:00:0c": "Cisco",
    "00:01:42": "Cisco",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "c8:14:79": "Samsung",
    "fc:f1:36": "Samsung",
    "00:15:b7": "HTC",
    "f8:e6:1a": "Xiaomi",
    "d0:22:be": "Oppo",
    "60:ab:67": "Vivo",
    "e0:b9:a5": "Huawei",
    "a8:5b:78": "LG Electronics",
    "00:04:19": "Sony Interactive",
    "f8:d0:ac": "Sony Interactive",
    "00:22:68": "Nintendo",
    "98:b6:e9": "Nintendo",
    "50:1a:c5": "Microsoft Xbox",
    "d8:13:99": "Roku",
    "8c:49:b5": "TCL",
    "14:dd:a9": "ASUS",
    "04:42:1a": "ASUS",
    "ac:22:0b": "ASUS",
    "fc:34:97": "ASUS",
    "30:5a:3a": "ASUS",
    "c0:25:e9": "TP-Link",
    "e8:48:b8": "TP-Link",
    "50:c7:bf": "TP-Link",
    "28:10:7b": "D-Link",
    "a0:c5:89": "Intel",
    "00:15:17": "Intel",
    "00:01:29": "Netgear",
    "00:09:5b": "Netgear",
    "00:14:bf": "Cisco Linksys",
    # Extended Intel entries
    "40:d1:33": "Intel",
    "48:51:b7": "Intel",
    "34:cf:f6": "Intel",
    "80:86:f2": "Intel",
    "b4:d5:bd": "Intel",
    "7c:b2:7d": "Intel",
    "cc:d9:ac": "Intel",
    # Realtek
    "00:e0:4c": "Realtek",
    "52:54:00": "Realtek (QEMU)",
    # Broadcom
    "20:e5:2a": "Broadcom",
    # MediaTek
    "00:0c:e7": "MediaTek",
    # Qualcomm
    "00:03:7f": "Qualcomm",
    # TP-Link Extended
    "b0:be:76": "TP-Link",
    "a0:f3:c1": "TP-Link",
    # D-Link Extended
    "1c:7e:e5": "D-Link",
    # Xiaomi Extended
    "64:cc:2e": "Xiaomi",
    "28:6c:07": "Xiaomi",
    # Huawei Extended
    "48:46:fb": "Huawei",
    "70:8c:b6": "Huawei",
    # Microsoft
    "00:15:5d": "Microsoft Hyper-V",
    # Amazon
    "f0:f0:a4": "Amazon Devices",
    "74:c2:46": "Amazon Devices",
    # Generic routers
    "00:1e:58": "D-Link",
    "1c:87:2c": "ASUS"
}
# Common ports to scan indicating specific services
#: Hard ceiling on concurrent TCP connect probes, across every host being
#: scanned at once.
#:
#: DEEP runs 100 host workers and each host used to spawn one thread per
#: port - 36 in DEEP - so the scanner could ask the OS for roughly 3,600
#: threads at once. They share one pool instead: the number of sockets in
#: flight is a property of the scanner now, not of the subnet's size.
MAX_PORT_PROBE_THREADS = 128

#: How long to wait after the UDP ping sweep before reading the ARP table.
#:
#: The sweep fires one datagram per address to force ARP resolution and the OS
#: fills its table as replies land. Half a second was not enough for a whole
#: /24: a host that answered late was missing from the cache, so the pre-filter
#: skipped it and the sweep reported a clean result for an address it had
#: never probed.
ARP_SETTLE_SECONDS = 1.5

#: Most addresses the UDP ping sweep will touch in one subnet.
#:
#: The sweep exists to populate the ARP table, and every datagram it sends to an
#: unused address produces an ARP broadcast that every station on the segment
#: has to process. A /24 is 254 of those, which is unremarkable. A /16 is 65,534,
#: and firing that many is a broadcast storm — it would degrade the network
#: being assessed, which is the one thing a tool like this must not do. The ARP
#: table cannot hold that many neighbours either, so most of the work would be
#: discarded before it was read.
#:
#: When a range is larger than this the sweep covers the first
#: MAX_UDP_SWEEP_ADDRESSES addresses and says so, and `intrusion_scope` reports
#: it, because "never asked" and "asked and got no answer" are different
#: statements about a host.
MAX_UDP_SWEEP_ADDRESSES = 1024

#: Per-connection timeout for STEALTH mode. Longer than the default so the
#: traffic looks less like a scanner, and passed explicitly to scan_port —
#: mutating the shared attribute raced across the mode's ten worker threads.
STEALTH_TIMEOUT = 1.5

TARGET_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    139: "NetBIOS",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class LANScanner:
    def __init__(self, ipc_handler):
        self.ipc = ipc_handler
        self.scanning = False
        self.target_subnet = None
        self.max_threads = 50
        self.timeout = 0.5
        self.previous_scan = {}  # Scan history for diff detection
        # One shared pool for every port probe, built on first use. See
        # MAX_PORT_PROBE_THREADS for why this is not a thread per port.
        self._port_pool = None
        self._port_pool_lock = threading.Lock()
        # Per-run tallies, so the terminal event can describe every subnet
        # swept rather than only the primary one.
        self._sweep_totals = {}
        self._sweep_totals_lock = threading.Lock()
        self.advanced_intel = {}
        self._intel_lock = threading.Lock()  # Guards advanced_intel (SSDP/NetBIOS/mDNS threads)
        # Set per run from the scope preflight. False by default so a code path
        # that reaches scan_host without going through _run_scan attempts no
        # logins: the gate fails closed.
        self._sweep_credentials_allowed = False
        
    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def get_subnet(self):
        local_ip = self.get_local_ip()
        if local_ip == '127.0.0.1':
            return None
        
        # Assume /24 subnet for local networks
        ip_parts = local_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    def _default_route_subnet(self):
        """The /24 carrying this machine's default route, if it has one.

        Used to decide which subnet a sweep treats as primary. Never fatal:
        returns None and the caller falls back to interface order.
        """
        try:
            from . import net_context
            local_ip = net_context.default_route().get("local_ip")
        except Exception:
            return None
        if not local_ip or local_ip.count(".") != 3:
            return None
        a, b, c, _d = local_ip.split(".")
        return f"{a}.{b}.{c}.0/24"

    def get_all_subnets(self):
        """Discover all active network interfaces and return their /24 subnets.

        Ordered so the subnet carrying the default route comes first, because
        the caller sweeps `subnets[0]` as primary and hands the rest to
        background threads.

        Interface order put a VMware virtual adapter first on the development
        machine: the full sweep — UDP ping, advanced intel, the lot — went to an
        empty 192.168.198.0/24 while the network the operator was actually on
        was scanned as an afterthought. The result read as "swept the subnet, 0
        hosts", which is true of the wrong subnet.
        """
        subnets = []
        try:
            kwargs = {}
            if platform.system().lower() == "windows":
                kwargs["creationflags"] = 0x08000000
                result = subprocess.run(["ipconfig"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5, **kwargs)
                ips = re.findall(r'IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)', result.stdout)
            else:
                result = subprocess.run(["hostname", "-I"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
                ips = result.stdout.strip().split()
            
            for ip in ips:
                if ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                # Filter out VPN/overlay networks that produce noise
                first_octet = int(ip.split('.')[0])
                if first_octet == 100 and int(ip.split('.')[1]) >= 64:
                    continue  # Tailscale CGNAT range (100.64.0.0/10)
                if ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31:
                    if ip.startswith('172.31.'):
                        continue  # WSL/Docker overlay
                parts = ip.split('.')
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                if subnet not in subnets:
                    subnets.append(subnet)
        except Exception:
            fallback = self.get_subnet()
            if fallback:
                subnets.append(fallback)

        # Promote the routed subnet. Virtual adapters (VMware, Hyper-V, VPN
        # taps) answer ipconfig just as readily as the real NIC and often come
        # first, so interface order is not a statement about which network
        # matters.
        primary = self._default_route_subnet()
        if primary:
            if primary in subnets:
                subnets.remove(primary)
            subnets.insert(0, primary)
        return subnets

    def probe_ttl(self, ip):
        """Probe TTL via a single ICMP ping to guess OS."""
        ttl = None

        # Use ping to reliably read TTL
        try:
            kwargs = {}
            if platform.system().lower() == "windows":
                kwargs["creationflags"] = 0x08000000
                ping_cmd = ["ping", "-n", "1", "-w", "300", ip]
            else:
                ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(ping_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=2, **kwargs)
            ttl_match = re.search(r'TTL[=:]\s*(\d+)', result.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
        except Exception:
            pass
        return ttl

    def ttl_to_os_hint(self, ttl):
        """Convert TTL value to an OS family hint."""
        if ttl is None:
            return None
        if ttl <= 64:
            return "Linux"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Router"
        return None

    def _port_probe_pool(self):
        """The shared probe pool, built on first use and kept for the process."""
        if self._port_pool is None:
            with self._port_pool_lock:
                if self._port_pool is None:
                    self._port_pool = ThreadPoolExecutor(
                        max_workers=MAX_PORT_PROBE_THREADS,
                        thread_name_prefix="ewac-port",
                    )
        return self._port_pool

    def _note_sweep(self, scan_id, in_range, probed):
        """Record what one subnet contributed to this run."""
        with self._sweep_totals_lock:
            totals = self._sweep_totals.setdefault(
                scan_id, {"in_range": 0, "probed": 0, "subnets": 0})
            totals["in_range"] += in_range
            totals["probed"] += probed
            totals["subnets"] += 1

    def _sweep_summary(self, scan_id):
        with self._sweep_totals_lock:
            totals = self._sweep_totals.get(scan_id)
            return dict(totals) if totals else None

    def scan_port(self, ip, port, open_ports, lock, timeout=None):
        """Probe one TCP port.

        `timeout` is a parameter rather than a read of `self.timeout` because
        STEALTH mode used to raise the shared attribute for the duration of a
        host and put it back afterwards — while ten worker threads were each
        doing the same thing to the same object. One thread's "restore" wrote
        another thread's raised value, so the scanner could be left permanently
        at the stealth timeout and every later QUICK sweep ran three times
        slower, with no way to tell from the outside.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout if timeout is None else timeout)
        result = s.connect_ex((ip, port))
        
        banner = ""
        server_header = ""
        if result == 0:
            # Grab banner for accurate OS detection
            try:
                if port in [80, 8080, 8000, 8888, 9090]:
                    s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    resp = s.recv(2048).decode('utf-8', errors='ignore')
                    # Extract Server header
                    srv_match = re.search(r'(?i)Server:\s*(.+?)\r?\n', resp)
                    if srv_match:
                        server_header = srv_match.group(1).strip()
                    # Look for title tag
                    title_match = re.search(r'(?i)<title>(.*?)</title>', resp)
                    if title_match:
                        banner = title_match.group(1).strip()
                    else:
                        banner = resp.split('\r\n')[0] # Fallback to HTTP status/server line
                elif port in [443, 8443, 9443, 5986, 6443]:
                    import ssl
                    context = ssl._create_unverified_context()
                    s_ssl = None
                    raw_ssl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        raw_ssl.settimeout(self.timeout)
                        s_ssl = context.wrap_socket(raw_ssl, server_hostname=ip)
                        s_ssl.connect((ip, port))
                        s_ssl.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                        resp = s_ssl.recv(2048).decode('utf-8', errors='ignore')
                        srv_match = re.search(r'(?i)Server:\s*(.+?)\r?\n', resp)
                        if srv_match:
                            server_header = srv_match.group(1).strip()
                        title_match = re.search(r'(?i)<title>(.*?)</title>', resp)
                        if title_match:
                            banner = title_match.group(1).strip()
                        else:
                            banner = resp.split('\r\n')[0]
                    finally:
                        # wrap_socket detaches raw_ssl, so close whichever owns the fd
                        try:
                            (s_ssl or raw_ssl).close()
                        except Exception:
                            pass
                elif port in [22, 21, 23, 25, 110, 143, 1433]:
                    banner = s.recv(256).decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
            
            # Parse structured version info from banner / server header
            svc_name, svc_version = self._parse_service_version(port, banner, server_header)
                
            with lock:
                port_entry = {
                    "port": port,
                    "service": TARGET_PORTS.get(port, "Unknown"),
                    "banner": banner,
                }
                if server_header:
                    port_entry["server_header"] = server_header
                if svc_name:
                    port_entry["service_name"] = svc_name
                if svc_version:
                    port_entry["service_version"] = svc_version
                
                # Offline CVE Matching
                cve_hits = lookup_cves(svc_name, svc_version)
                if cve_hits:
                    port_entry["cves"] = cve_hits
                
                open_ports.append(port_entry)
        s.close()

    def _parse_service_version(self, port, banner, server_header=""):
        """Extract structured service name and version from banner/header."""
        if not banner and not server_header:
            return None, None
        
        combined = (banner + " " + server_header).strip()
        
        # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        ssh_match = re.search(r'SSH-[\d.]+-([\w]+)[_\s]([\d.p]+)', combined)
        if ssh_match:
            return ssh_match.group(1), ssh_match.group(2)
        
        # FTP: "220 (vsFTPd 3.0.3)" or "220 ProFTPD 1.3.5" or "220 FileZilla Server 0.9.60"
        ftp_match = re.search(r'(vsFTPd|ProFTPD|Pure-FTPd|FileZilla\s*Server?)\s*([\d.]+)', combined, re.I)
        if ftp_match:
            return ftp_match.group(1).strip(), ftp_match.group(2)
        
        # HTTP Server header: "Apache/2.4.49" or "nginx/1.18.0" or "Microsoft-IIS/10.0"
        http_match = re.search(r'(Apache|nginx|Microsoft-IIS|lighttpd|LiteSpeed|Caddy|Tomcat|Jetty)[/\s]*([\d.]+)', combined, re.I)
        if http_match:
            return http_match.group(1), http_match.group(2)
        
        # OpenSSL in server header: "OpenSSL/1.1.1"
        ssl_match = re.search(r'(OpenSSL)[/\s]*([\d.a-z]+)', combined, re.I)
        if ssl_match:
            return ssl_match.group(1), ssl_match.group(2)

        # SMTP: "220 mail.example.com ESMTP Postfix" or "Microsoft ESMTP MAIL Service"
        smtp_match = re.search(r'(Postfix|Exim|Sendmail|Microsoft ESMTP)', combined, re.I)
        if smtp_match:
            return smtp_match.group(1), None

        # MySQL: "5.7.42-0ubuntu0.18.04.1"
        if port == 3306:
            ver_match = re.search(r'([\d]+\.[\d]+\.[\d]+)', combined)
            if ver_match:
                return "MySQL", ver_match.group(1)

        # MSSQL: version from banner
        if port == 1433:
            mssql_match = re.search(r'(Microsoft SQL Server|MSSQL)', combined, re.I)
            if mssql_match:
                ver = re.search(r'([\d]+\.[\d]+\.[\d]+)', combined)
                return "MSSQL", ver.group(1) if ver else None

        # Telnet: return trimmed banner
        if port == 23 and banner.strip():
            return "Telnet", banner.strip()[:50]
        
        return None, None

    def _reverse_dns(self, ip):
        """Attempt reverse DNS lookup for hostname."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname and hostname != ip:
                return hostname
        except (socket.herror, socket.gaierror, OSError):
            pass
        try:
            fqdn = socket.getfqdn(ip)
            if fqdn and fqdn != ip:
                return fqdn
        except Exception:
            pass
        return None

    # ── Phase 6 Sprint B: UDP Scanning ──
    UDP_SERVICE_MAP = {
        53: "DNS", 67: "DHCP", 123: "NTP", 137: "NetBIOS-NS",
        161: "SNMP", 500: "IKE/VPN", 1900: "SSDP", 5353: "mDNS",
    }

    def _scan_udp_port(self, ip, port, results, lock):
        """Send a service-specific UDP probe and check for response."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)

            # Service-specific probes for reliable detection
            if port == 53:
                # DNS query: version.bind TXT CH
                probe = (b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                         b'\x07version\x04bind\x00\x00\x10\x00\x03')
            elif port == 123:
                # NTP version request (mode 3, version 3)
                probe = b'\x1b' + b'\x00' * 47
            elif port == 137:
                # NetBIOS Name query
                probe = (b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                         b'\x20\x43\x4b' + b'\x41' * 30 + b'\x00\x00\x21\x00\x01')
            elif port == 161:
                # SNMPv1 GET sysDescr.0 with community "public"
                probe = self._build_snmp_get("public", [1, 3, 6, 1, 2, 1, 1, 1, 0])
            elif port == 500:
                # IKE SA_INIT (minimal probe)
                probe = b'\x00' * 28
            elif port == 1900:
                # SSDP M-SEARCH
                probe = (b'M-SEARCH * HTTP/1.1\r\n'
                         b'Host: 239.255.255.250:1900\r\n'
                         b'Man: "ssdp:discover"\r\n'
                         b'ST: ssdp:all\r\nMX: 1\r\n\r\n')
            elif port == 5353:
                # mDNS query for _services
                probe = (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                         b'\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01')
            else:
                probe = b'\x00'

            s.sendto(probe, (ip, port))
            data, _ = s.recvfrom(1024)

            # We got a response — port is open
            banner = ""
            if port == 123 and len(data) >= 48:
                banner = "NTP Server"
            elif port == 161:
                banner = self._parse_snmp_value(data) or "SNMP Agent"
            elif port == 53:
                banner = "DNS Server"
            elif port == 137 and len(data) > 57:
                name = data[57:57+15].decode('ascii', errors='ignore').strip()
                banner = f"NetBIOS: {name}" if name else "NetBIOS"
            elif data:
                banner = data[:64].decode('utf-8', errors='ignore').strip()

            with lock:
                results.append({
                    "port": port,
                    "protocol": "UDP",
                    "service": self.UDP_SERVICE_MAP.get(port, "Unknown"),
                    "banner": banner,
                })
        except socket.timeout:
            pass  # No response = filtered/closed
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    # ── Phase 6 Sprint B: SNMP Community String Testing ──
    SNMP_COMMUNITIES = ["public", "private", "community", "snmp", "monitor", "admin"]

    def _build_snmp_get(self, community, oid_parts):
        """Build a minimal SNMPv1 GET-REQUEST packet."""
        # Encode OID
        oid_bytes = bytes([0x2b])  # 1.3 prefix
        for part in oid_parts[2:]:
            if part < 128:
                oid_bytes += bytes([part])
            else:
                # Multi-byte BER encoding
                high = (part >> 7) | 0x80
                low = part & 0x7f
                oid_bytes += bytes([high, low])

        oid_tlv = bytes([0x06, len(oid_bytes)]) + oid_bytes
        # NULL value
        value_tlv = b'\x05\x00'
        # VarBind
        varbind = oid_tlv + value_tlv
        varbind_seq = bytes([0x30, len(varbind)]) + varbind
        # VarBindList
        varbind_list = bytes([0x30, len(varbind_seq)]) + varbind_seq
        # Request ID (simple)
        req_id = b'\x02\x01\x01'
        error = b'\x02\x01\x00'
        error_idx = b'\x02\x01\x00'
        # PDU: GET-REQUEST (0xA0)
        pdu_content = req_id + error + error_idx + varbind_list
        pdu = bytes([0xa0, len(pdu_content)]) + pdu_content
        # Community string
        comm_bytes = community.encode('ascii')
        comm_tlv = bytes([0x04, len(comm_bytes)]) + comm_bytes
        # Version: SNMPv1 = 0
        version = b'\x02\x01\x00'
        # Full message
        msg_content = version + comm_tlv + pdu
        msg = bytes([0x30, len(msg_content)]) + msg_content
        return msg

    def _parse_snmp_value(self, data):
        """Extract the string value from an SNMP GET-RESPONSE."""
        try:
            # Look for an OctetString (tag 0x04) in the response
            idx = data.find(b'\x04', 20)  # Skip headers
            if idx >= 0 and idx + 1 < len(data):
                length = data[idx + 1]
                if idx + 2 + length <= len(data):
                    value = data[idx + 2:idx + 2 + length]
                    return value.decode('utf-8', errors='ignore').strip()
        except Exception:
            pass
        return None

    def _test_snmp_communities(self, ip, timeout=2):
        """Test common SNMP community strings and return successful ones."""
        results = []
        for community in self.SNMP_COMMUNITIES:
            try:
                packet = self._build_snmp_get(community, [1, 3, 6, 1, 2, 1, 1, 1, 0])
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(packet, (ip, 161))
                data, _ = s.recvfrom(4096)
                s.close()

                # If we got a response, the community string is valid
                sys_descr = self._parse_snmp_value(data) or "(response received)"
                results.append({
                    "community": community,
                    "sys_descr": sys_descr
                })
            except socket.timeout:
                continue
            except Exception:
                continue
        return results if results else None

    # ── Phase 6 Sprint C: Default Credential Check ──
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", ""),
        ("root", "root"),
        ("root", "toor"),
        ("root", "password"),
        ("user", "user"),
    ]

    def _quick_credential_check(self, ip, open_ports):
        """Non-intrusive test of common default credentials on SSH/FTP/HTTP.
        Returns a list of successful credential findings.
        """
        findings = []
        tcp_ports = {p["port"] for p in open_ports if p.get("protocol") != "UDP"}

        # SSH (port 22)
        if 22 in tcp_ports:
            cred = self._try_ssh_creds(ip, 22)
            if cred:
                findings.append({**cred, "port": 22, "service": "SSH"})

        # FTP (port 21)
        if 21 in tcp_ports:
            cred = self._try_ftp_creds(ip, 21)
            if cred:
                findings.append({**cred, "port": 21, "service": "FTP"})

        # HTTP Basic Auth (port 80/8080)
        for http_port in [80, 8080, 8000]:
            if http_port in tcp_ports:
                cred = self._try_http_creds(ip, http_port)
                if cred:
                    findings.append({**cred, "port": http_port, "service": "HTTP"})
                break  # Only test one HTTP port

        return findings if findings else None

    def _try_ssh_creds(self, ip, port):
        """Test SSH default credentials using paramiko."""
        try:
            import paramiko
        except ImportError:
            return None

        for user, pwd in self.DEFAULT_CREDS:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=user, password=pwd,
                               timeout=2, banner_timeout=2, auth_timeout=2,
                               allow_agent=False, look_for_keys=False)
                client.close()
                return {"username": user, "password": pwd}
            except Exception:
                continue
        return None

    def _try_ftp_creds(self, ip, port):
        """Test FTP default credentials."""
        from ftplib import FTP
        for user, pwd in self.DEFAULT_CREDS:
            try:
                ftp = FTP()
                ftp.connect(ip, port, timeout=2)
                ftp.login(user=user, passwd=pwd)
                ftp.quit()
                return {"username": user, "password": pwd}
            except Exception:
                continue
        return None

    def _try_http_creds(self, ip, port):
        """
        Test HTTP Basic Auth default credentials.

        A credential is only demonstrated if the server refused the request
        *without* it and accepted it *with* it. Both halves are required.

        This used to send `Authorization: Basic admin:admin` and accept any
        response under 400 as proof the login worked. A server with no
        authentication on `/` answers 200 whatever is in that header — it never
        looks at it — so the first pair in DEFAULT_CREDS came back as a
        recovered credential for essentially every web server on the network.

        That is not a cosmetic error. `archive.ts` promotes this into the
        strongest claim the tool can publish: risk 100, CRITICAL, CONFIRMED,
        "A working credential was recovered ... This is demonstrated access, not
        a theoretical weakness." A clean appliance was reported as owned.

        So the unauthenticated baseline is established first and nothing is
        attempted unless the server actually demands credentials. 401 is the
        challenge we can answer; 403 is a refusal that Basic auth does not
        address, and a server that returns it unauthenticated is not guarding
        `/` with a password. Anything else — 200, a redirect, a 500, a
        connection error — means there is no Basic auth gate here to defeat, and
        the honest result is None rather than a guess.
        """
        import urllib.request
        import urllib.error
        import base64

        url = f"http://{ip}:{port}/"

        def _status_without_credentials():
            """The server's answer to an anonymous request, or None if it had none."""
            try:
                return urllib.request.urlopen(
                    urllib.request.Request(url), timeout=2
                ).status
            except urllib.error.HTTPError as e:
                return e.code
            except Exception:
                return None

        if _status_without_credentials() != 401:
            return None

        for user, pwd in self.DEFAULT_CREDS:
            try:
                b64 = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                req = urllib.request.Request(url)
                req.add_header("Authorization", f"Basic {b64}")
                resp = urllib.request.urlopen(req, timeout=2)
                # The anonymous request was challenged and this one was not.
                if resp.status < 400:
                    return {"username": user, "password": pwd}
            except urllib.error.HTTPError:
                # 401 again is a rejected password; anything else is a server
                # that stopped answering the way it did a moment ago. Neither is
                # a demonstrated login.
                continue
            except Exception:
                continue
        return None

    def _get_all_local_ips(self):
        """Get all IPs assigned to local network interfaces."""
        local_ips = set()
        try:
            if platform.system().lower() == "windows":
                kwargs = {"creationflags": 0x08000000}
                result = subprocess.run(["ipconfig"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5, **kwargs)
                for match in re.findall(r'IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)', result.stdout):
                    local_ips.add(match)
            else:
                result = subprocess.run(["hostname", "-I"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
                for ip in result.stdout.strip().split():
                    local_ips.add(ip)
        except Exception:
            pass
        local_ips.add(self.get_local_ip())
        return local_ips
    
    def _get_local_mac_for_ip(self, ip):
        """Get the MAC of a local interface by matching its IP via ipconfig/ifconfig."""
        try:
            if platform.system().lower() == "windows":
                kwargs = {"creationflags": 0x08000000}
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5, **kwargs)
                # Split by adapter sections (lines that start with non-whitespace character)
                sections = re.split(r'\r?\n(?=\S)', result.stdout)
                for section in sections:
                    if ip in section:
                        mac_match = re.search(r'Physical Address[\s.]*:\s*([0-9A-Fa-f-]{17})', section)
                        if mac_match:
                            return mac_match.group(1).replace('-', ':').lower()
            else:
                import uuid
                mac_int = uuid.getnode()
                return ':'.join(['{:02x}'.format((mac_int >> elements) & 0xff) for elements in range(0, 2*6, 2)][::-1])
        except Exception:
            pass
        return None

    def _lookup_vendor(self, mac):
        """Lookup hardware vendor from MAC, handling locally-administered MACs."""
        oui = mac[:8]
        vendor = OUI_DB.get(oui, None)
        if vendor:
            return vendor
        
        # If not found, try stripping the locally-administered bit (bit 1 of first octet)
        # e.g. 42:d1:33 -> 40:d1:33 (Intel), 4a:xx -> 48:xx
        first_byte = int(mac[:2], 16)
        is_local = (first_byte & 0x02) != 0  # Check LA bit
        if is_local:
            real_byte = first_byte & 0xFD  # Clear LA bit
            real_oui = f"{real_byte:02x}" + mac[2:8]
            vendor = OUI_DB.get(real_oui, None)
            if vendor:
                return vendor
        
        # Check for randomized mobile MACs (second hex char is 2, 6, A, E)
        if len(mac) > 1 and mac[1].lower() in '26ae':
            return "Randomized MAC (Mobile Device)"
        
        return None

    def get_mac_and_vendor(self, ip):
        try:
            # Check if the IP belongs to this machine (any local NIC)
            if not hasattr(self, '_local_ips_cache'):
                self._local_ips_cache = self._get_all_local_ips()
            
            if ip in self._local_ips_cache:
                mac = self._get_local_mac_for_ip(ip)
                if mac:
                    vendor = self._lookup_vendor(mac)
                    return mac, vendor

            # Lookup from global ARP cache
            if hasattr(self, 'arp_cache') and ip in self.arp_cache:
                mac = self.arp_cache[ip]
                vendor = self._lookup_vendor(mac)
                return mac, vendor
            
            # Last resort: try direct ARP lookup for this single IP (Windows)
            if platform.system().lower() == "windows":
                kwargs = {"creationflags": 0x08000000}
                result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=2, **kwargs)
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        mac_candidate = parts[1]
                        if re.match(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", mac_candidate):
                            mac = mac_candidate.replace('-', ':').lower()
                            vendor = self._lookup_vendor(mac)
                            return mac, vendor
        except Exception:
            pass
        return None, None

    def determine_os(self, open_ports, vendor=None, ttl_hint=None, hostname=None):
        ports = [p["port"] for p in open_ports]
        banners = " ".join([p.get("banner", "") for p in open_ports if "banner" in p]).lower()
        # Include server headers and service versions in analysis
        server_headers = " ".join([p.get("server_header", "") for p in open_ports]).lower()
        svc_versions = " ".join([f'{p.get("service_name", "")} {p.get("service_version", "")}' for p in open_ports]).lower()
        combined_intel = banners + " " + server_headers + " " + svc_versions
        vendor_lower = (vendor or "").lower()
        hostname_lower = (hostname or "").lower()

        # ──────────────────────────────────────────────
        # 0. Banner / Header / Version Based (Highest Accuracy)
        # ──────────────────────────────────────────────

        # Docker / Container
        if "docker" in combined_intel or "container" in combined_intel:
            return "Docker Container"

        # Kubernetes
        if "kubernetes" in combined_intel or "k8s" in combined_intel:
            return "Kubernetes Node"

        # Hypervisor
        if "esxi" in combined_intel or "vmware esx" in combined_intel:
            return "Hypervisor (ESXi)"
        if "proxmox" in combined_intel or "pve" in combined_intel:
            return "Hypervisor (Proxmox)"

        # Firewall appliances
        if "pfsense" in combined_intel or "opnsense" in combined_intel or "freebsd" in combined_intel:
            return "Firewall (pfSense/BSD)"
        if "fortinet" in combined_intel or "fortigate" in combined_intel:
            return "Firewall (FortiGate)"
        if "mikrotik" in combined_intel or "routeros" in combined_intel:
            return "Network Router (MikroTik)"

        # Router / Gateway — FIX A1: require router-like context, not just "gateway" keyword
        if "openwrt" in combined_intel or "boa" in combined_intel or "lighttpd" in combined_intel:
            return "Network Router"
        if "asus" in combined_intel and any(kw in combined_intel for kw in ["router", "firmware", "wrt"]):
            return "Network Router"
        if "tp-link" in combined_intel and any(kw in combined_intel for kw in ["router", "firmware", "tl-"]):
            return "Network Router"
        if "router" in combined_intel and "api" not in combined_intel and "payment" not in combined_intel:
            return "Network Router"

        # Linux Distros
        if "ubuntu" in combined_intel or "debian" in combined_intel or "centos" in combined_intel or "alpine" in combined_intel or "fedora" in combined_intel or "arch linux" in combined_intel or "rocky" in combined_intel or "almalinux" in combined_intel:
            return "Linux Server"
        if "microsoft-iis" in combined_intel or ("windows" in combined_intel and "server" in combined_intel):
            return "Windows Server"
        if "windows" in combined_intel:
            return "Windows"
        if "nginx" in combined_intel and "kubernetes" not in combined_intel:
            return "Linux Server (nginx)"
        if "android" in combined_intel:
            return "Android Device"

        # IP Camera / NVR / DVR
        if "camera" in combined_intel or "nvr" in combined_intel or "dvr" in combined_intel or "hikvision" in combined_intel or "dahua" in combined_intel or "webcam" in combined_intel or "axis" in combined_intel or "amcrest" in combined_intel:
            return "IP Camera / NVR"
        # NAS
        if "nas" in combined_intel or "synology" in combined_intel or "qnap" in combined_intel or "freenas" in combined_intel or "truenas" in combined_intel:
            return "Storage / NAS"
        # Elasticsearch
        if "elasticsearch" in combined_intel:
            return "Linux Server (Elasticsearch)"
        # Jupyter
        if "jupyter" in combined_intel:
            return "Linux Server (Jupyter)"
        # Smart Speaker
        if "sonos" in combined_intel:
            return "Smart Speaker (Sonos)"
        if "alexa" in combined_intel or "amazon echo" in combined_intel:
            return "Smart Speaker (Alexa)"
        # IPMI / iLO / iDRAC
        if "ilo" in combined_intel or "idrac" in combined_intel or "ipmi" in combined_intel or "supermicro" in combined_intel:
            return "Server Management (IPMI/iLO)"

        # ──────────────────────────────────────────────
        # 1. Vendor Based Heuristics
        # ──────────────────────────────────────────────
        if vendor:
            if "Apple" in vendor:
                return "macOS / iOS Device"
            if any(v in vendor for v in ["Samsung", "Xiaomi", "Oppo", "Vivo", "HTC", "Huawei", "OnePlus", "Realme"]):
                return "Android Device"
            if "Randomized" in vendor:
                return "Mobile Phone (Random MAC)"
            if any(v in vendor for v in ["Sony Interactive", "Nintendo", "Xbox"]):
                return "Gaming Console"
            if any(v in vendor for v in ["LG", "TCL", "Roku"]):
                return "Smart TV"
            if any(v in vendor for v in ["ASUS", "TP-Link", "D-Link", "Netgear", "Cisco Linksys"]):
                return "Network Router"
            if any(v in vendor for v in ["Espressif", "Tuya"]):
                return "IoT Smart Device"
            if "Raspberry Pi" in vendor:
                return "Linux (Raspberry Pi)"
            if any(v in vendor for v in ["Hewlett-Packard", "HP Inc"]):
                return "Network Printer"
            if "Cisco" in vendor and "Linksys" not in vendor:
                return "Cisco Network Device"
            if any(v in vendor for v in ["VMware", "VirtualBox", "Hyper-V"]):
                return "Virtual Machine"
            if "Amazon" in vendor:
                return "Smart Speaker (Alexa)"
            if "Sonos" in vendor:
                return "Smart Speaker (Sonos)"
            if "Google" in vendor:
                # Google devices: Chromecast, Nest, Pixel
                if 8008 in ports or 8009 in ports or 9000 in ports:
                    return "Smart TV / Chromecast"
                return "Android Device"

        # ──────────────────────────────────────────────
        # 1.5 Hostname-based OS hint (FIX D2)
        # ──────────────────────────────────────────────
        if hostname_lower:
            if hostname_lower.startswith("desktop-") or hostname_lower.startswith("win-") or hostname_lower.startswith("pc-"):
                return "Windows"
            if "macbook" in hostname_lower or "imac" in hostname_lower or "mac-" in hostname_lower:
                return "macOS / iOS Device"
            if "iphone" in hostname_lower or "ipad" in hostname_lower:
                return "macOS / iOS Device"
            if "-nas" in hostname_lower or "synology" in hostname_lower or "diskstation" in hostname_lower:
                return "Storage / NAS"

        # ──────────────────────────────────────────────
        # 2. Port Based Heuristics (reordered for accuracy)
        # ──────────────────────────────────────────────

        # Domain Controller (very specific combo)
        if 88 in ports and 389 in ports and 445 in ports:
            return "Windows Server (Domain Controller)"

        # Docker API
        if 2375 in ports or 2376 in ports:
            return "Docker Container"

        # Kubernetes API / Kubelet
        if 6443 in ports or 10250 in ports:
            return "Kubernetes Node"

        # Hypervisors
        if 902 in ports and 443 in ports:
            return "Hypervisor (ESXi)"
        if 8006 in ports:
            return "Hypervisor (Proxmox)"

        # IPMI / Out-of-band management
        if 623 in ports or 17988 in ports:
            return "Server Management (IPMI/iLO)"

        # FIX C1: RTSP check moved BEFORE web server check
        if 554 in ports:
            return "IP Camera / NVR"

        # Printers
        if 9100 in ports or 631 in ports or 515 in ports:
            return "Network Printer"

        # Database Servers
        if 3306 in ports or 5432 in ports or 27017 in ports or 6379 in ports:
            if 22 in ports:
                return "Linux Server (Database)"
            return "Database Server"

        # Web Servers
        if (80 in ports or 443 in ports or 8080 in ports) and 22 in ports:
            return "Linux Server (Web)"

        if (80 in ports or 443 in ports) and 445 in ports:
            return "Windows Server (Web / IIS)"

        # Smart TV / Chromecast / Media Player
        if 8008 in ports or 8009 in ports or 7000 in ports or 9080 in ports:
            return "Smart TV / Media Player"

        # Smart Speaker (Sonos)
        if 1400 in ports or 1443 in ports:
            return "Smart Speaker (Sonos)"

        # Windows Remote Management
        if 5985 in ports or 5986 in ports:
            return "Windows Server (WinRM)"
        # MSSQL
        if 1433 in ports:
            if 445 in ports or 3389 in ports:
                return "Windows Server (MSSQL)"
            return "Database Server (MSSQL)"
        # Elasticsearch / Monitoring
        if 9200 in ports:
            return "Linux Server (Elasticsearch)"
        if 9090 in ports and 22 in ports:
            return "Linux Server (Monitoring)"
        # Jupyter Notebook
        if 8888 in ports:
            return "Linux Server (Jupyter)"
        # Memcached
        if 11211 in ports:
            return "Cache Server (Memcached)"

        # General Windows
        if 445 in ports or 3389 in ports:
            return "Windows"

        # General Linux
        if 22 in ports and 445 not in ports:
            return "Linux/Unix"

        # IoT fallback (few ports, only HTTP)
        if 80 in ports and len(ports) <= 2:
            return "IoT Device / Router"

        # Apple Devices
        if 5000 in ports or 62078 in ports:
            return "Apple Device"

        # ──────────────────────────────────────────────
        # 3. TTL-based fallback (last resort)
        # ──────────────────────────────────────────────
        if ttl_hint:
            # FIX A2: chipset vendors (Intel, Realtek, Broadcom) use TTL as co-signal
            if vendor and any(v in vendor for v in ["Intel", "Realtek", "Broadcom", "Qualcomm", "MediaTek"]):
                if ttl_hint == "Windows":
                    return "Windows"
                elif ttl_hint == "Linux":
                    return "Linux/Unix"

            if ttl_hint == "Linux":
                return "Linux/Unix"
            elif ttl_hint == "Windows":
                return "Windows"
            elif ttl_hint == "Router":
                return "Network Router"

        return "Unknown"

    def _udp_ping_sweep(self, target_cidr):
        """
        Send one datagram per address in `target_cidr` to force ARP resolution.

        Returns a dict describing what it actually did. Nothing about this is
        inferred by the caller, because every part of it used to be invisible:

            subnet_prefix = '.'.join(target_cidr.split('/')[0].split('.')[:3])
            for i in range(1, 255):
                s.sendto(b'', (f"{subnet_prefix}.{i}", 53))

        That took the first three octets and swept 1-254 regardless of the
        prefix length it had been given. Two consequences:

          * **It left the range.** A /25 such as 192.168.1.0/25 covers .0-.127,
            and this sent datagrams to .128-.254 as well — addresses outside the
            subnet the operator asked for.
          * **It under-covered anything larger than a /24.** On a /16 it touched
            254 of 65,534 addresses, so the ARP pre-filter could only ever find
            hosts in that one slice, and the sweep reported a clean result for
            the 65,280 addresses it had never asked about.

        The whole body was also wrapped in `except Exception: pass`, so a sweep
        that failed outright was indistinguishable from a quiet network — and the
        socket leaked on the way out.
        """
        stats = {
            "addresses_in_range": 0,
            "attempted": 0,
            "sent": 0,
            "failed": 0,
            "truncated": False,
            "cap": MAX_UDP_SWEEP_ADDRESSES,
            "error": None,
        }

        try:
            ips = IPy.IP(target_cidr)
        except Exception as e:
            stats["error"] = f"invalid CIDR: {e}"
            return stats

        local_ip = self.get_local_ip()   # once, not once per address
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Enumerated from the range itself, so the sweep cannot leave it.
            # Network and broadcast are excluded the same way the port-probe
            # path excludes them, so the two agree on what "in range" means.
            addresses = []
            for ip in ips:
                addresses.append(str(ip))
                # Stop materialising a /16 once past the cap plus the two
                # endpoints we are about to drop.
                if len(addresses) > MAX_UDP_SWEEP_ADDRESSES + 2:
                    stats["truncated"] = True
                    break
            hosts = addresses[1:-1] if len(addresses) > 2 else []
            stats["addresses_in_range"] = max(0, len(ips) - 2)
            if len(hosts) > MAX_UDP_SWEEP_ADDRESSES:
                hosts = hosts[:MAX_UDP_SWEEP_ADDRESSES]
                stats["truncated"] = True
            stats["truncated"] = stats["truncated"] or len(hosts) < stats["addresses_in_range"]

            for host in hosts:
                if not self.scanning:
                    break
                stats["attempted"] += 1
                if host == local_ip:
                    continue
                try:
                    s.sendto(b'', (host, 53))
                    stats["sent"] += 1
                except OSError:
                    # One unreachable address is normal on a segment with holes
                    # in it; counted rather than ignored so a sweep where *every*
                    # send failed is visible.
                    stats["failed"] += 1
        except Exception as e:
            stats["error"] = str(e)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

        return stats

    def start_advanced_intel(self, subnet_prefix, broadcast=None):
        with self._intel_lock:
            self.advanced_intel = {}

        def run_ssdp():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                msg = b'M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: "ssdp:all"\r\nST: ssdp:all\r\nMX: 1\r\n\r\n'
                s.sendto(msg, ('239.255.255.250', 1900))
                while self.scanning:
                    try:
                        data, addr = s.recvfrom(1024)
                        ip = addr[0]
                        text = data.decode('utf-8', errors='ignore')
                        server_match = re.search(r'(?i)Server:\s*(.+)', text)
                        if server_match:
                            with self._intel_lock:
                                if ip not in self.advanced_intel: self.advanced_intel[ip] = {}
                                self.advanced_intel[ip]["ssdp"] = server_match.group(1).strip()
                    except socket.timeout:
                        pass
            except Exception:
                pass
                
        def run_netbios():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(2)
                payload = b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
                # Send to the subnet's real broadcast address.
                #
                # This was `{subnet_prefix}.255`, which is only the broadcast
                # address of a /24. On a /25 it is an address in the *other*
                # half of the range, and on a /16 it is one of 256 per-/24
                # broadcast addresses, so the query reached a fraction of the
                # segment. The caller now computes it from the CIDR.
                s.sendto(payload, (broadcast or f"{subnet_prefix}.255", 137))
                while self.scanning:
                    try:
                        data, addr = s.recvfrom(1024)
                        ip = addr[0]
                        if len(data) > 57:
                            name = data[57:57+15].decode('ascii', errors='ignore').strip()
                            if name and all(c.isalnum() or c in '-_' for c in name):
                                with self._intel_lock:
                                    if ip not in self.advanced_intel: self.advanced_intel[ip] = {}
                                    self.advanced_intel[ip]["netbios"] = name
                    except socket.timeout:
                        pass
            except Exception:
                pass
                
        def run_mdns():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                payload = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01'
                s.sendto(payload, ('224.0.0.251', 5353))
                while self.scanning:
                    try:
                        data, addr = s.recvfrom(1024)
                        ip = addr[0]
                        matches = re.findall(b'([A-Za-z0-9-]{3,30})\x05local', data)
                        if matches:
                            name = matches[0].decode('utf-8', errors='ignore')
                            with self._intel_lock:
                                if ip not in self.advanced_intel: self.advanced_intel[ip] = {}
                                self.advanced_intel[ip]["mdns"] = name
                    except socket.timeout:
                        pass
            except Exception:
                pass
                
        t1 = threading.Thread(target=run_ssdp, daemon=True)
        t2 = threading.Thread(target=run_netbios, daemon=True)
        t3 = threading.Thread(target=run_mdns, daemon=True)
        t1.start(); t2.start(); t3.start()

    def _run_is_current(self, scan_id):
        """
        Is `scan_id` still the active run?

        `self.scanning` is not the right question for anything below the primary
        subnet: `_run_scan` clears it when the primary drains, while secondary subnets
        are still working. `current_scan_id` is what `stop()` changes, so it is what
        distinguishes an operator stop from another subnet merely finishing.

        With no scan id -- a caller outside a run -- it falls back to `self.scanning`,
        which is the only signal such a caller has.
        """
        if scan_id is None:
            return bool(self.scanning)
        return getattr(self, "current_scan_id", None) == scan_id

    def scan_host(self, ip, scan_mode="QUICK", scan_id=None):
        # First ICMP ping or initial 80/445 check to see if host is alive
        # A full ICMP ping library requires admin on Windows, so we use a quick port grab
        # Try port 80, 443, 445, or 22 as a generic is-alive check
        is_alive = False
        open_ports = []
        lock = threading.Lock()
        threads = []
        
        target_ports = TARGET_PORTS.copy()
        
        if scan_mode == "DEEP":
            target_ports.update({
                25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP",
                3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC",
                6379: "Redis", 8443: "HTTPS-Alt", 27017: "MongoDB",
                # Phase 6 — Extended VA coverage
                88:    "Kerberos",
                135:   "MSRPC",
                389:   "LDAP",
                636:   "LDAPS",
                1433:  "MSSQL",
                1521:  "Oracle DB",
                2049:  "NFS",
                5000:  "Docker/Flask",
                5985:  "WinRM",
                5986:  "WinRM-HTTPS",
                6443:  "Kubernetes API",
                8000:  "HTTP-Dev",
                8888:  "Jupyter",
                9090:  "Prometheus",
                9200:  "Elasticsearch",
                9443:  "vSphere",
                11211: "Memcached",
            })
            
        port_list = list(target_ports.keys())
        
        if scan_mode == "STEALTH":
            import random
            random.shuffle(port_list)
            # Serialized, shuffled, and spaced out. The longer timeout is passed
            # down rather than assigned to self: ten of these run concurrently.
            # Guarded on the run, not on `self.scanning`.
            #
            # `_run_scan` clears `self.scanning` when the *primary* subnet drains, and
            # `_scan_single_subnet` was taught not to read that as a stop -- but this
            # loop still did. So on a STEALTH multi-subnet sweep every secondary host
            # after that moment probed zero ports while `probed_here` still counted it,
            # which made the "stopped after N of M" caveat silent and left the run
            # affirmatively claiming coverage of addresses it had contacted on no port.
            # Worse than the behaviour the fix replaced.
            for port in port_list:
                if not self._run_is_current(scan_id):
                    break
                self.scan_port(ip, port, open_ports, lock, timeout=STEALTH_TIMEOUT)
                time.sleep(random.uniform(0.1, 0.5))  # Random inter-port jitter
        else:
            # Submitted to the shared pool rather than a thread each: with
            # 100 host workers in DEEP this was asking the OS for thousands
            # of threads at once.
            pool = self._port_probe_pool()
            futures = [pool.submit(self.scan_port, ip, port, open_ports, lock)
                       for port in port_list]
            for future in futures:
                try:
                    future.result()
                except Exception:
                    # One refused socket must not abandon the rest of the host.
                    pass

        # Try to get MAC and Vendor from ARP cache
        mac, vendor = self.get_mac_and_vendor(ip)
        
        # Probe TTL for OS hint (lightweight, only if host appears alive)
        ttl_hint = None
        if open_ports or mac is not None:
            ttl = self.probe_ttl(ip)
            ttl_hint = self.ttl_to_os_hint(ttl)
            
        if open_ports or mac is not None:
            # DNS Reverse Lookup — try to resolve hostname from IP
            dns_hostname = self._reverse_dns(ip)
            
            # Fallback hostname chain: DNS → NetBIOS → mDNS → Web Title → generic
            hostname = dns_hostname or f"Unknown Host ({ip.split('.')[-1]})"
                
            # Merge Advanced Intel (snapshot under lock — discovery threads keep writing)
            with self._intel_lock:
                intel = dict(self.advanced_intel.get(ip, {}))
            
            # Hostname override from discovery protocols (higher confidence than DNS)
            if "netbios" in intel:
                hostname = intel["netbios"]
            elif "mdns" in intel:
                hostname = intel["mdns"] + ".local"
            else:
                # Fallback to Web Title if available and hostname is Unknown
                if hostname.startswith("Unknown"):
                    web_title = next((p.get("banner") for p in open_ports if p.get("port") in [80, 443, 8080] and p.get("banner")), None)
                    if web_title and len(web_title) > 3 and not web_title.startswith("HTTP/"):
                        hostname = web_title
                
            os_guess = self.determine_os(open_ports, vendor, ttl_hint, hostname)
            
            # OS Guess Override based on Advanced Intel
            if "ssdp" in intel:
                ssdp_str = intel["ssdp"].lower()
                if "linux" in ssdp_str and "upnp" in ssdp_str:
                    os_guess = "Network Router"
                elif "roku" in ssdp_str or "webos" in ssdp_str or "tizen" in ssdp_str:
                    os_guess = "Smart TV"
            if "netbios" in intel and os_guess in ["Unknown", "Unknown Host", "Linux/Unix"]:
                os_guess = "Windows"
            if "mdns" in intel:
                mdns_str = intel["mdns"].lower()
                if "apple" in mdns_str or "macbook" in mdns_str or "iphone" in mdns_str or "ipad" in mdns_str:
                    os_guess = "macOS / iOS Device"
                elif "appletv" in mdns_str:
                    os_guess = "Smart TV"
            
            # Map port numbers back to service names
            for p in open_ports:
                p["service"] = target_ports.get(p["port"], "Unknown")

            # ── Phase 6 Sprint B: DEEP-mode advanced analysis ──
            if scan_mode == "DEEP":
                # B1: SSL/TLS Deep Analysis on HTTPS ports (Phase 7 upgrade)
                ssl_cert = None
                https_ports = [p["port"] for p in open_ports if p["port"] in (443, 8443, 9443, 5986, 6443)]
                if https_ports:
                    try:
                        from scanner.ssl_check import deep_ssl_scan
                        ssl_cert = deep_ssl_scan(ip, port=https_ports[0], timeout=3)
                    except Exception:
                        pass

                # B2: UDP Port Scanning
                udp_results = []
                udp_lock = threading.Lock()
                udp_threads = []
                for uport in [53, 123, 137, 161, 500, 1900, 5353]:
                    ut = threading.Thread(target=self._scan_udp_port, args=(ip, uport, udp_results, udp_lock), daemon=True)
                    ut.start()
                    udp_threads.append(ut)
                for ut in udp_threads:
                    ut.join(timeout=3)
                # Append UDP results to open_ports
                open_ports.extend(udp_results)

                # B3: SNMP Community String Testing (if UDP 161 responded)
                snmp_communities = None
                if any(u["port"] == 161 for u in udp_results):
                    snmp_communities = self._test_snmp_communities(ip)

                # C1: Default Credential Check (auto-test top 8 creds)
                #
                # Gated per host. This makes eight real login attempts against
                # somebody's machine, which is the act `policy.py` draws its line
                # at -- the same act as `start_bruteforce`, which has always been
                # gated and audited for one operator-chosen target. Here it was
                # neither, and it ran against every host a DEEP sweep found,
                # across every subnet the sweep reached. `permits_host` audits the
                # decision without raising a notification per host; the operator
                # was told once, at the start of the run, if the gate is shut.
                default_creds = None
                if self._sweep_credentials_allowed and self.ipc.policy.permits_host(
                    "sweep_credential_check", ip,
                    {"scan_id": getattr(self, "current_scan_id", None)},
                ):
                    default_creds = self._quick_credential_check(ip, open_ports)

            # Emit finding
            emit_data = {
                "ip": ip,
                "hostname": hostname,
                "os": os_guess,
                "mac": mac,
                "vendor": vendor,
                "open_ports": open_ports,
                "timestamp": time.time() * 1000,
                "isGateway": ip.endswith('.1') or ip.endswith('.254')
            }

            # Advisories that follow from the operating system rather than from a
            # version a service reported about itself — EternalBlue on 445,
            # BlueKeep on 3389. Applied here and not during the port scan because
            # the OS is derived from the ports and banners that scan collects.
            #
            # They are marked `inferred` so the rule set reports them at
            # SUSPECTED rather than CONFIRMED. This knowledge used to live only
            # in the intrusion screen, which meant an operator saw a CRITICAL the
            # exported report never mentioned.
            annotate_host_inferences(emit_data)
            # Attach Phase 6 Sprint B + C data if available
            if scan_mode == "DEEP":
                if ssl_cert and ssl_cert.get("findings"):
                    emit_data["ssl_cert"] = ssl_cert
                if snmp_communities:
                    emit_data["snmp_communities"] = snmp_communities
                if default_creds:
                    emit_data["default_creds"] = default_creds
            self.ipc.emit("intrusion_host_found", emit_data)

    def _read_arp_cache(self):
        """
        Read the OS ARP table into a fresh dict (never mutated in place).

        Sets `self.arp_read_error` on failure instead of returning an empty dict
        and leaving the caller to guess.

        This was `except Exception: pass; return {}`, and an empty ARP table is
        not a harmless outcome: `_filter_alive_ips` then finds nothing alive and
        falls back to probing the two addresses ending `.1` and `.254`. The
        sweep proceeded normally and reported "1 host found" on a subnet with
        forty live machines, which reads as a clean result.

        The failures that land here are ordinary: `arp.exe` taking longer than
        the five-second timeout, or a decoding error. Text-mode subprocess
        output used to be decoded as the ANSI codepage, strictly, so a single
        byte outside cp1252 in a localised adapter description raised
        `UnicodeDecodeError` from inside `subprocess.run`. The encoding is now
        stated explicitly on every such call in the engine, which stops that
        one happening at all.
        """
        arp_cache = {}
        self.arp_read_error = None
        try:
            kwargs = {}
            if platform.system().lower() == "windows":
                kwargs["creationflags"] = 0x08000000
                arp_cmd = ["arp", "-a"]
            else:
                arp_cmd = ["arp", "-n"]

            result = subprocess.run(
                arp_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=5, **kwargs
            )
            if result.returncode != 0:
                self.arp_read_error = (
                    f"'{' '.join(arp_cmd)}' exited {result.returncode}"
                    + (f": {(result.stderr or '').strip()[:200]}" if result.stderr else "")
                )
                return arp_cache

            for line in (result.stdout or "").split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    ip_addr = parts[0]
                    mac = parts[1]
                    if re.match(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", mac):
                        arp_cache[ip_addr] = mac.replace('-', ':').lower()

            if not arp_cache:
                # The command ran and parsed, and there was nothing in it. On a
                # segment that was just swept with a UDP ping this is itself
                # suspicious — it usually means the output format was not what
                # the parser expects, which a localised Windows can produce.
                self.arp_read_error = (
                    "the ARP table was read successfully but contained no entries the parser "
                    "recognised"
                )
        except subprocess.TimeoutExpired:
            self.arp_read_error = "the ARP table read timed out after 5s"
        except Exception as e:
            self.arp_read_error = f"{type(e).__name__}: {e}"
            logger.debug("ARP cache read failed: %s", e)
        return arp_cache

    def _filter_alive_ips(self, ip_list, scan_mode="QUICK"):
        """Pre-filter: Only scan IPs confirmed alive via ARP cache or known local IPs."""
        if not hasattr(self, '_local_ips_cache'):
            self._local_ips_cache = self._get_all_local_ips()

        arp_cache = getattr(self, 'arp_cache', {})
        alive_ips = []
        for ip in ip_list:
            if ip in arp_cache or ip in self._local_ips_cache:
                alive_ips.append(ip)

        # If no alive hosts found via ARP, fall back to scanning a small sample
        # (this can happen if the network is truly empty or ARP didn't populate)
        if not alive_ips and scan_mode == "DEEP":
            alive_ips = ip_list  # Deep scan forces full range
        elif not alive_ips:
            # Try pinging a few key addresses (gateway, DHCP range start)
            alive_ips = [ip for ip in ip_list if ip.endswith('.1') or ip.endswith('.254')]

        return alive_ips

    def _emit_terminal(self, scan_id, total_ips, aborted=False, range_size=None):
        """Emit exactly one terminal event (progress 100 + intrusion_complete) per run.

        Only the scan being torn down speaks: either we are still the active scan
        (normal completion) or stop() explicitly killed us (aborted). A scan that
        was superseded by a newer one stays silent — the newer scan emits instead.
        """
        current = getattr(self, 'current_scan_id', None)
        is_current = current == scan_id
        # Stopped by the user: only speak if no newer scan has taken over meanwhile
        was_stopped = current is None and getattr(self, 'stopped_scan_id', None) == scan_id
        if not (is_current or was_stopped):
            return

        if not hasattr(self, '_terminated_scans'):
            self._terminated_scans = set()
        if scan_id in self._terminated_scans:
            return
        self._terminated_scans.add(scan_id)

        # Release the UI progress bar before the completion event
        self.ipc.emit("intrusion_progress", {"progress": 100, "scanned": total_ips, "total": total_ips})
        payload = {"scanned_count": total_ips}
        # The size of the range this was drawn from, so "scanned 6" can never be
        # read as "the subnet holds 6 addresses".
        if range_size is not None:
            payload["addresses_in_range"] = range_size
            payload["skipped_by_arp_filter"] = max(0, range_size - total_ips)

        # Totals across every subnet this run touched. `scanned_count` is the
        # primary subnet alone, which did not match the host count whenever a
        # background subnet contributed hosts of its own.
        summary = self._sweep_summary(scan_id)
        if summary:
            payload["subnets_swept"] = summary["subnets"]
            payload["addresses_probed_all_subnets"] = summary["probed"]
            payload["addresses_in_range_all_subnets"] = summary["in_range"]
            payload["skipped_by_arp_filter_all_subnets"] = max(
                0, summary["in_range"] - summary["probed"])
        if aborted:
            payload["aborted"] = True
        self.ipc.emit("intrusion_complete", payload)

    def run_scan(self, target_cidr=None, scan_id=None, scan_mode="QUICK", extra_subnets=None):
        """Thin wrapper guaranteeing a terminal event on every exit path."""
        try:
            self._run_scan(target_cidr, scan_id, scan_mode, extra_subnets)
        except Exception as e:
            self.ipc.emit("intrusion_error", {"message": f"Scan failed: {e}"})
            self.scanning = False
            self._emit_terminal(scan_id, 0, aborted=True)

    def _run_scan(self, target_cidr=None, scan_id=None, scan_mode="QUICK", extra_subnets=None):
        """
        Sweep `target_cidr`, plus `extra_subnets` in background threads.

        `extra_subnets` exists so the caller can decide what gets swept.
        Previously this method always rediscovered the subnet list itself and
        swept everything it found, which meant the operator's subnet selection
        in the UI had no effect at all — `_handle_start_intrusion` resolved a
        list, and then this threw it away and called `get_all_subnets()` a second
        time. Two calls could also disagree: an adapter coming up between them
        changed what got swept.

        Passing None keeps the old auto-discovery behaviour, which is what a
        caller with no opinion should get.
        """
        # Whether this run may attempt default credentials, decided once.
        #
        # Only DEEP reaches that code at all, so a QUICK or STEALTH sweep is not
        # worth a notification about a gate it was never going to open. Asked
        # before any host is probed, so the operator learns the probe is off at
        # the start of the run rather than inferring it from an empty column in
        # the report.
        self._sweep_credentials_allowed = (
            scan_mode == "DEEP"
            and self.ipc.policy.sweep_credentials_preflight({"scan_id": scan_id})
        )

        # Multi-Subnet Auto Discovery
        extra_subnets = list(extra_subnets or [])
        if target_cidr is None:
            subnets = self.get_all_subnets()
            if subnets:
                # Emit all discovered subnets info
                self.ipc.emit("intrusion_subnets_found", {"subnets": subnets})
                target_cidr = subnets[0]  # Primary subnet
                # Scanned in background threads once the ARP cache exists (see below)
                extra_subnets = subnets[1:]
            else:
                target_cidr = self.get_subnet()
        else:
            # The caller chose the list. Announce it anyway: this event is how
            # the UI learns which subnet a session is against, and skipping it
            # on this path left archived intrusion reports labelled
            # 'UNKNOWN SUBNET' — the same defect the event was added to fix.
            self.ipc.emit("intrusion_subnets_found", {
                "subnets": [target_cidr] + extra_subnets,
            })

        if not target_cidr:
            self.scanning = False
            self._emit_terminal(scan_id, 0)
            return

        self.scanning = True
        
        # 1. Fast UDP Ping Sweep to populate the ARP table.
        #
        # Bounded by the actual CIDR rather than by an assumed /24, and it
        # reports what it covered — see _udp_ping_sweep for what the old version
        # did instead.
        subnet_prefix = '.'.join(target_cidr.split('/')[0].split('.')[:3])
        try:
            broadcast = str(IPy.IP(target_cidr).broadcast())
        except Exception:
            # /31, /32 and malformed ranges have no usable broadcast address.
            broadcast = None

        # Start Advanced Intel Gatherers (NetBIOS, mDNS, SSDP)
        self.start_advanced_intel(subnet_prefix, broadcast=broadcast)

        udp_sweep = self._udp_ping_sweep(target_cidr)
        time.sleep(ARP_SETTLE_SECONDS)  # Let replies land before reading ARP
            
        # 2. Global ARP Cache Population (built locally, rebound in one statement so
        #    threads from an earlier scan never read a half-filled dict)
        self.arp_cache = self._read_arp_cache()

        # Additional subnets start now — they ARP pre-filter off the cache above
        for extra_subnet in extra_subnets:
            t = threading.Thread(target=self._scan_single_subnet, args=(extra_subnet, scan_id, scan_mode), daemon=True)
            t.start()

        # 3. Queue IPs for port scanning
        try:
            ips = IPy.IP(target_cidr)
        except Exception as e:
            self.ipc.emit("intrusion_error", {"message": f"Invalid CIDR: {e}"})
            self.scanning = False
            # Still emit a terminal event, otherwise the UI stays "active" forever
            self._emit_terminal(scan_id, 0, aborted=True)
            return

        ip_list = [str(ip) for ip in ips][1:-1] # Exclude network and broadcast

        scan_ips = self._filter_alive_ips(ip_list, scan_mode)     # Only scan alive hosts

        # How many addresses were actually probed. This number is reported, so it
        # has to be the truth.
        #
        # It used to be `len(scan_ips) if len(scan_ips) > 0 else 1`, which made a
        # run that probed *nothing* report `scanned_count: 1`. The `else 1` was
        # only ever guarding a division, and that division is guarded on its own
        # line below. Zero probed addresses is exactly the case where the count
        # matters most: it happens when the ARP pre-filter comes back empty,
        # including when `_read_arp_cache` failed rather than the network being
        # quiet.
        probed_count = len(scan_ips)
        # Denominator for the progress percentage only. Never reported.
        progress_total = max(1, probed_count)

        # Say how much of the range was actually probed.
        #
        # The ARP pre-filter can cut 253 addresses down to a handful, and until
        # now the only number that left this module was the filtered one. A
        # report then said "swept the subnet, 6 hosts" when what happened was
        # "probed the 6 addresses that answered ARP within half a second" — a
        # false negative wearing the clothes of a clean result. The operator has
        # to be able to tell those apart.
        self._note_sweep(scan_id, len(ip_list), len(scan_ips))

        # "Never asked" and "asked and got no answer" are different statements
        # about a host, and only the second one is a result. The ARP pre-filter
        # can only find a host the UDP sweep reached, so when the sweep was
        # capped the caveat has to say which addresses were never contacted at
        # all rather than lumping them in with the silent ones.
        never_swept = max(0, len(ip_list) - udp_sweep.get("attempted", 0))
        arp_error = getattr(self, "arp_read_error", None)
        caveat = ("Addresses that did not answer ARP in time were not probed. "
                  "A host that is powered on but silent, firewalled against "
                  "ARP, or simply slow will be absent from these results — "
                  "absence here is not evidence that nothing is there.")
        if arp_error:
            # The pre-filter decides what gets probed, so a failed read is the
            # most consequential failure in the sweep and the least visible: the
            # fallback quietly narrows 253 addresses to two and the run
            # completes looking normal.
            caveat = (
                f"The ARP table could not be read ({arp_error}), so the pre-filter that decides "
                "which addresses to probe had nothing to work from. This sweep covered only a "
                "fallback sample. Treat this subnet as unsurveyed rather than quiet, and re-run "
                "in DEEP mode, which ignores the pre-filter entirely."
            )
        elif udp_sweep.get("error"):
            caveat = (f"The UDP ping sweep that populates the ARP table failed "
                      f"({udp_sweep['error']}), so the pre-filter had little or nothing to work "
                      "from. Treat this subnet as unsurveyed rather than quiet.")
        elif never_swept > 0:
            caveat = (f"{never_swept} of the {len(ip_list)} addresses in this range were never "
                      f"contacted: the ARP-populating sweep is capped at {udp_sweep.get('cap')} "
                      "addresses per subnet to avoid flooding the segment with broadcasts. "
                      "Nothing in this result describes those addresses. Of the rest, any that "
                      "did not answer ARP in time were also not probed.")

        self.ipc.emit("intrusion_scope", {
            "subnet": target_cidr,
            "addresses_in_range": len(ip_list),
            "addresses_probed": len(scan_ips),
            "skipped_by_arp_filter": max(0, len(ip_list) - len(scan_ips)),
            "addresses_never_swept": never_swept,
            "arp_read_error": arp_error,
            "udp_sweep": udp_sweep,
            "scan_mode": scan_mode,
            "discovery": ("ARP cache after a UDP ping sweep"
                          if scan_mode != "DEEP" or len(scan_ips) != len(ip_list)
                          else "full range (DEEP ignores the ARP pre-filter)"),
            "caveat": caveat,
        })
        
        q = queue.Queue()
        for ip in scan_ips:
            q.put(ip)
            
        completed = 0
        completed_lock = threading.Lock()

        # Emit initial progress
        if getattr(self, 'current_scan_id', None) == scan_id:
            self.ipc.emit("intrusion_progress", {"progress": 0, "scanned": 0, "total": probed_count})
        
        # Adjust threads based on mode
        actual_threads = self.max_threads
        if scan_mode == "DEEP":
            actual_threads = 100 # Speed up deep scan
        elif scan_mode == "STEALTH":
            actual_threads = 10 # Slow down stealth scan
            
        def worker():
            nonlocal completed
            import random as _rnd
            while self.scanning and getattr(self, 'current_scan_id', None) == scan_id:
                # Blocking get with a timeout — a `not q.empty()` pre-check is
                # check-then-act and strands every loser on the last item forever
                try:
                    ip = q.get(timeout=0.2)
                except queue.Empty:
                    break
                self.scan_host(ip, scan_mode, scan_id)
                with completed_lock:
                    completed += 1
                    done = completed

                # Emit progress frequently
                if done % max(1, progress_total // 20) == 0 or done == probed_count:
                    progress = int((done / progress_total) * 100)
                    if getattr(self, 'current_scan_id', None) == scan_id:
                        self.ipc.emit("intrusion_progress", {"progress": progress, "scanned": done, "total": probed_count})
                q.task_done()
                
                # STEALTH: Randomized inter-host delay to avoid burst patterns
                if scan_mode == "STEALTH":
                    time.sleep(_rnd.uniform(0.5, 2.0))
                
        threads = []
        for _ in range(actual_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
            
        for t in threads:
            t.join()

        # Only run diff/history bookkeeping if we are still the active scan
        if getattr(self, 'current_scan_id', None) == scan_id:
            self._emit_scan_diff(scan_id)
            self.scanning = False

        # Terminal event: normal completion, or aborted if stop() tore us down
        self._emit_terminal(scan_id, probed_count,
                            aborted=getattr(self, 'current_scan_id', None) != scan_id,
                            range_size=len(ip_list))

    def _emit_scan_diff(self, scan_id):
        """
        Compare this sweep's ARP cache with the previous one and report the change.

        Extracted from `_run_scan` so it can be tested. It was inline, and what it
        does on a failed ARP read -- the case that produced a "every device left the
        network" event out of a local command timing out -- was unreachable from a
        test without running a real sweep.
        """
        if getattr(self, 'current_scan_id', None) != scan_id:
            return
        # Scan History Diff Detection
        #
        # The diff is built from the ARP cache, so it is only meaningful when the
        # ARP read worked. `_read_arp_cache` returns {} on failure -- a timeout, a
        # non-zero exit, output a localised Windows prints in a shape the parser
        # does not recognise -- and this block had no guard, so `current_ips` was
        # empty and `disappeared_devices` became *every device seen last time*.
        # An `intrusion_diff {type: "disappeared"}` naming the whole LAN: a claim
        # that those machines left the network, manufactured out of a failed local
        # command, emitted while the sibling `intrusion_scope` event was correctly
        # reporting that the ARP table could not be read.
        #
        # The history is left alone in that case too. Overwriting it with {} would
        # have left the next sweep comparing against nothing, so the genuinely new
        # devices it found would go unannounced as well -- a second sweep's worth
        # of silent diff detection paid for one failed read.
        arp_failed = getattr(self, 'arp_read_error', None) is not None
        if arp_failed:
            self.ipc.emit("intrusion_diff", {
                "type": "unavailable",
                "devices": [],
                "count": 0,
                "reason": (
                    "The ARP table could not be read, so no comparison with the previous "
                    f"sweep was possible ({self.arp_read_error}). Nothing is claimed about "
                    "devices arriving or leaving."
                ),
            })
        else:
            current_ips = set(self.arp_cache.keys()) if hasattr(self, 'arp_cache') else set()
            previous_ips = set(self.previous_scan.keys()) if self.previous_scan else set()

            new_devices = current_ips - previous_ips
            disappeared_devices = previous_ips - current_ips

            if self.previous_scan:  # Only emit diff if we have a previous scan to compare
                if new_devices:
                    self.ipc.emit("intrusion_diff", {
                        "type": "new",
                        "devices": list(new_devices),
                        "count": len(new_devices)
                    })
                if disappeared_devices:
                    self.ipc.emit("intrusion_diff", {
                        "type": "disappeared",
                        "devices": list(disappeared_devices),
                        "count": len(disappeared_devices)
                    })

            # Save current scan as history for next comparison
            self.previous_scan = dict(self.arp_cache) if hasattr(self, 'arp_cache') else {}


    def _scan_single_subnet(self, target_cidr, scan_id, scan_mode):
        """
        Lightweight scanner for additional subnets (no duplicate UDP sweep).

        Runs on its own thread, started by `_run_scan` and never joined. Two things
        here used to cost the run its honesty.

        **The primary subnet's completion stopped it.** `_run_scan` sets
        `self.scanning = False` when it finishes, and the loop below read that as a
        stop signal and broke. The primary runs 50 workers (100 in DEEP) while this
        probes sequentially, so the primary finishes first essentially always -- and
        `intrusion_scope` and `_note_sweep` have already claimed every one of these
        addresses as probed, which `_emit_terminal` folds into
        `addresses_probed_all_subnets`. On a multi-NIC host the report stated that
        the secondary subnets had been swept when most of their addresses were never
        contacted. The loop now watches `current_scan_id`, which is what actually
        identifies this run, and `stop()` changes it -- so an operator stop still
        halts it while another subnet merely finishing does not.

        **Every failure was invisible.** The body ended in `except Exception: pass`,
        wrapping the IPy parse, the pre-filter and every `scan_host` -- after the
        scope claim had already been emitted. A subnet that died halfway was
        indistinguishable from one that was swept clean.
        """
        probed_here = 0
        try:
            ips = IPy.IP(target_cidr)
            ip_list = [str(ip) for ip in ips][1:-1]
            # Same ARP pre-filter as the primary path — scanning all 254 addresses
            # sequentially turns a QUICK scan on a second NIC into hours of work
            probed = self._filter_alive_ips(ip_list, scan_mode)
            # Background subnets count toward the run too. Without this the
            # terminal event described the primary subnet alone, so a report
            # could read "scanned 2 addresses, found 6 hosts".
            self._note_sweep(scan_id, len(ip_list), len(probed))
            self.ipc.emit("intrusion_scope", {
                "subnet": target_cidr,
                "addresses_in_range": len(ip_list),
                "addresses_probed": len(probed),
                "skipped_by_arp_filter": max(0, len(ip_list) - len(probed)),
                "scan_mode": scan_mode,
                "discovery": "ARP cache from the primary subnet's sweep",
                "caveat": ("Additional subnet. Addresses that did not answer "
                           "ARP were not probed; absence here is not evidence "
                           "that nothing is there."),
            })
            ip_list = probed
            for ip in ip_list:
                # `current_scan_id` only. `self.scanning` is cleared by whichever
                # subnet finishes first, which is not a stop and must not read as one.
                if getattr(self, 'current_scan_id', None) != scan_id:
                    break
                self.scan_host(ip, scan_mode, scan_id)
                probed_here += 1
        except Exception as e:
            logger.exception("secondary subnet sweep failed for %s", target_cidr)
            self.ipc.emit("intrusion_scope", {
                "subnet": target_cidr,
                "addresses_probed": probed_here,
                "scan_mode": scan_mode,
                "error": f"{type(e).__name__}: {e}",
                "caveat": (
                    f"This subnet's sweep stopped early after {probed_here} address(es): "
                    f"{type(e).__name__}: {e}. The coverage figures reported for it above "
                    "describe what was planned, not what was reached, and no absence of "
                    "findings in it means anything."
                ),
            })
            return

        # Said plainly when the run was cut short rather than finishing. The figures
        # emitted before the loop describe what was planned.
        if probed_here < len(ip_list):
            self.ipc.emit("intrusion_scope", {
                "subnet": target_cidr,
                "addresses_probed": probed_here,
                "scan_mode": scan_mode,
                "caveat": (
                    f"This subnet's sweep was stopped after {probed_here} of "
                    f"{len(ip_list)} planned address(es). The rest were never contacted."
                ),
            })

    def start(self, target_cidr=None, scan_mode="QUICK", extra_subnets=None):
        """
        Begin a sweep.

        `target_cidr` / `extra_subnets` let the caller decide what is swept.
        Leaving both None keeps auto-discovery. See `_run_scan` for why the
        caller's choice has to be carried rather than rediscovered here.
        """
        self.scanning = False # Signal any old threads to die
        self.current_scan_id = time.time() # Unique ID for this run
        self.scanning = True

        t = threading.Thread(
            target=self.run_scan,
            args=(target_cidr, self.current_scan_id, scan_mode, extra_subnets),
            daemon=True,
        )
        t.start()
        
    def stop(self):
        self.scanning = False
        # Remember who was torn down so run_scan can still emit its terminal event
        self.stopped_scan_id = getattr(self, 'current_scan_id', None)
        self.current_scan_id = None
