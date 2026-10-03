import threading
import time
import socket
import struct
import logging
import urllib.request
import urllib.error
from ftplib import FTP

#: Ports this engine actually has a check for. Anything else in a scan result
#: is simply not examined, which the completion event now says out loud.
_CHECKED_PORTS = {21, 22, 23, 80, 443, 445, 3306, 6379, 8000, 8080, 8443, 9090}


#: Paths whose content is validated individually above. The HTML catch-all skips
#: these, because one of them legitimately *is* an HTML page.
_CONTENT_CHECKED_PATHS = frozenset((
    "/.env", "/.git/config", "/docker-compose.yml", "/.htpasswd",
    "/server-status", "/config.json", "/wp-config.php.bak",
))


def _looks_like_json(text):
    """
    Whether `text` plausibly begins a JSON document.

    Deliberately shallow: the body is read 1 KB at a time, so a real config file is
    usually truncated mid-structure and `json.loads` would reject it. All this has to
    rule out is a server answering with its index page.
    """
    stripped = (text or "").lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


class VulnEngine:
    def __init__(self, emit_cb):
        self.emit = emit_cb
        self.logger = logging.getLogger("VulnEngine")

    def run_checks(self, target_ip, open_ports):
        """Run modular vulnerability checks against open ports on a target."""
        findings = []
        
        self.emit("vuln_scan_started", {"target": target_ip, "message": "Initializing vulnerability checks..."})

        for port in open_ports:
            if port == 21:
                res = self.check_ftp_anon(target_ip)
                if res: findings.append(res)
            elif port == 22:
                res = self.check_ssh_config(target_ip)
                if res: findings.append(res)
            elif port == 6379:
                res = self.check_redis_auth(target_ip)
                if res: findings.append(res)
            elif port == 3306:
                res = self.check_mysql_auth(target_ip)
                if res: findings.append(res)
            elif port == 23:
                res = self.check_telnet(target_ip)
                if res: findings.append(res)
            
            # SMB Signing check
            if port == 445:
                res = self.check_smb_signing(target_ip)
                if res: findings.append(res)
            
            # Web Secrets Scanner + Header Leak
            if port in [80, 443, 8000, 8080, 8443, 9090]:
                web_res = self.check_web_secrets(target_ip, port)
                if web_res: findings.extend(web_res)
                header_res = self.check_server_headers(target_ip, port)
                if header_res: findings.extend(header_res)
                
        # What was examined, not only what was found.
        #
        # Every check returns None both when the service is clean and when it
        # could not be reached, so an empty `findings` list covered two very
        # different statements: "we checked and it is fine" and "nothing
        # answered". Naming the ports at least bounds the claim — a reader can
        # see that a host with one open port was not given a clean bill of
        # health for the other forty.
        examined = sorted({p for p in open_ports if p in _CHECKED_PORTS})
        skipped = sorted({p for p in open_ports if p not in _CHECKED_PORTS})
        self.emit("vuln_scan_completed", {
            "target": target_ip,
            "findings": findings,
            "ports_examined": examined,
            "ports_without_a_check": skipped,
            "caveat": (
                "Only the ports listed in ports_examined have a check behind them, and a "
                "check that could not reach its service is indistinguishable here from one "
                "that found nothing. An empty result is not a clean bill of health."
            ),
        })

    def check_ftp_anon(self, ip):
        """
        Check if FTP allows anonymous login.

        The finding is built the moment `login()` returns, before the disconnect.

        It used to be sequenced after `ftp.quit()`, which sends QUIT and then calls
        `voidresp()` -- raising `error_perm`, `error_temp` or `error_reply` on a
        non-2xx reply, and `OSError`/`EOFError` when the server simply drops the
        connection. Embedded and NAS FTP daemons do both routinely. The blanket
        `except Exception: return None` then swallowed a *demonstrated* anonymous
        login, and the host was reported as clean -- indistinguishable from one that
        refused the credential.
        """
        ftp = None
        try:
            ftp = FTP()
            ftp.connect(ip, timeout=3)
            ftp.login()  # Default is anonymous
            finding = {
                "vuln": "Anonymous FTP Login",
                "code": "ftp_anonymous",
                "severity": "HIGH",
                "port": 21,
                "description": "The FTP server allows unauthenticated 'anonymous' login. Attackers could read or write files to the server.",
                "cve": "CWE-284"
            }
        except Exception:
            return None
        finally:
            # Closing the session is tidiness; it cannot cost the finding.
            if ftp is not None:
                try:
                    ftp.quit()
                except Exception:
                    try:
                        ftp.close()
                    except Exception:
                        pass
        return finding

    def check_ssh_config(self, ip):
        """Check SSH for weak configuration indicators."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, 22))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            
            if not banner:
                return None
            
            banner_lower = banner.lower()
            if "ssh-1" in banner_lower:
                return {
                    "vuln": "SSH Protocol v1 Enabled",
                    "code": "ssh_protocol_v1",
                    "severity": "CRITICAL",
                    "port": 22,
                    "description": f"SSH server supports deprecated protocol v1 which is vulnerable to MITM attacks. Banner: {banner}",
                    "cve": "CWE-327"
                }
            
            if "openssh" in banner_lower:
                import re
                ver_match = re.search(r'openssh[_\s](\d+\.\d+)', banner_lower)
                if ver_match:
                    version = float(ver_match.group(1))
                    if version < 7.4:
                        return {
                            "vuln": f"Outdated OpenSSH ({banner})",
                            "code": "ssh_openssh_outdated",
                            "severity": "HIGH",
                            "port": 22,
                            "description": f"OpenSSH version {ver_match.group(1)} is significantly outdated and may be vulnerable to username enumeration, authentication bypass, or other known exploits.",
                            "cve": "CVE-2018-15473"
                        }
                    elif version < 8.0:
                        return {
                            "vuln": f"Aging OpenSSH Version ({banner})",
                            "code": "ssh_openssh_aging",
                            "severity": "MEDIUM",
                            "port": 22,
                            "description": f"OpenSSH version {ver_match.group(1)} should be upgraded. Older versions may have known vulnerabilities.",
                            "cve": "N/A"
                        }
            
            if "dropbear" in banner_lower:
                return {
                    "vuln": f"Dropbear SSH Detected ({banner})",
                    "code": "ssh_dropbear",
                    "severity": "LOW",
                    "port": 22,
                    "description": "Dropbear SSH is commonly used in embedded/IoT devices. These often have weak or default credentials.",
                    "cve": "N/A"
                }
            
            return None
        except Exception:
            return None

    def check_redis_auth(self, ip):
        """Check if Redis is open without authentication."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, 6379))
            s.sendall(b"INFO\r\n")
            data = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            
            if "redis_version" in data and "NOAUTH" not in data:
                return {
                    "vuln": "Unauthenticated Redis Database",
                    "code": "redis_no_auth",
                    "severity": "CRITICAL",
                    "port": 6379,
                    "description": "Redis database does not require authentication. An attacker could execute arbitrary Lua scripts or write SSH keys.",
                    "cve": "CWE-287"
                }
        except Exception as e:
            self.logger.debug("Redis auth check failed for %s: %s", ip, e)
        return None

    def check_mysql_auth(self, ip):
        """Check if MySQL is reachable (and optionally allows empty root)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, 3306))
            data = s.recv(1024)
            s.close()
            if b"mysql_native_password" in data or b"caching_sha2_password" in data:
                 return {
                    "vuln": "Exposed MySQL Interface",
                    "code": "mysql_exposed",
                    "severity": "LOW",
                    "port": 3306,
                    "description": "MySQL database interface is publicly accessible. It is vulnerable to brute-force attacks.",
                    "cve": "N/A"
                }
        except Exception as e:
            self.logger.debug("MySQL auth check failed for %s: %s", ip, e)
        return None

    def check_telnet(self, ip):
        """Check if Telnet is running and responds with a prompt."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, 23))
            data = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            
            if "login" in data.lower() or "password" in data.lower():
                 return {
                    "vuln": "Cleartext Telnet Service",
                    "code": "telnet_cleartext",
                    "severity": "MEDIUM",
                    "port": 23,
                    "description": "Telnet transmits all data, including credentials, in cleartext. It should be disabled and replaced with SSH.",
                    "cve": "CWE-319"
                }
        except Exception as e:
            self.logger.debug("Telnet check failed for %s: %s", ip, e)
        return None

    def check_smb_signing(self, ip):
        """Check if SMB signing is disabled (vulnerable to relay attacks)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, 445))
            
            netbios_header = b'\x00\x00\x00\x85'
            smb_header = (
                b'\xff\x53\x4d\x42'
                b'\x72'
                b'\x00\x00\x00\x00'
                b'\x18'
                b'\x53\xc8'
                b'\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00'
                b'\x00\x00'
                b'\xff\xfe'
                b'\x00\x00'
                b'\x00\x00'
            )
            negotiate = (
                b'\x00'
                b'\x62\x00'
                b'\x02'
                b'PC NETWORK PROGRAM 1.0\x00'
                b'\x02'
                b'LANMAN1.0\x00'
                b'\x02'
                b'Windows for Workgroups 3.1a\x00'
                b'\x02'
                b'LM1.2X002\x00'
                b'\x02'
                b'LANMAN2.1\x00'
                b'\x02'
                b'NT LM 0.12\x00'
            )
            
            packet = netbios_header + smb_header + negotiate
            s.sendall(packet)
            response = s.recv(1024)
            s.close()
            
            if len(response) > 39:
                if response[4:8] == b'\xff\x53\x4d\x42':
                    security_mode = response[39]
                    # MS-CIFS 2.2.4.52.2, SMB_COM_NEGOTIATE SecurityMode:
                    #   0x01 user-level authentication
                    #   0x02 encrypted passwords (challenge/response)
                    #   0x04 security signatures ENABLED
                    #   0x08 security signatures REQUIRED
                    #
                    # These masks were 0x02 and 0x04 — the SMB2 bit positions,
                    # one bit low for SMBv1. The byte offset was right, so the
                    # check looked like it worked.
                    #
                    # It inverted the answer for the configuration this finding
                    # exists to catch. A Windows member server or workstation
                    # defaults to SecurityMode = 0x07: user security, encrypted
                    # passwords, signing enabled but not required — precisely the
                    # ntlmrelayx-exploitable state. `0x07 & 0x04` is truthy, so
                    # `signing_required` came out True, the guard below was
                    # skipped, and no finding was raised. Conversely 0x03
                    # (signatures off, encrypted passwords on) was downgraded
                    # from "disabled" to "enabled but not required".
                    #
                    # `smb_enum._check_smb_signing` reads SMB2, where 0x01/0x02
                    # are correct, so one host answered two different ways
                    # depending on which module reached it first.
                    signing_enabled = bool(security_mode & 0x04)
                    signing_required = bool(security_mode & 0x08)
                    
                    if not signing_required:
                        severity = "HIGH" if not signing_enabled else "MEDIUM"
                        status = "disabled" if not signing_enabled else "enabled but not required"
                        return {
                            "vuln": f"SMB Signing {status.title()}",
                            "code": "smb_signing",
                            "severity": severity,
                            "port": 445,
                            "description": f"SMB message signing is {status}. This makes the host vulnerable to SMB relay attacks (e.g., ntlmrelayx) where an attacker can intercept and relay authentication to gain unauthorized access.",
                            "cve": "CWE-294"
                        }
        except Exception as e:
            self.logger.debug("SMB signing check failed for %s: %s", ip, e)
        return None

    def check_server_headers(self, ip, port):
        """Check HTTP response headers for information leakage."""
        findings = []
        protocol = "https" if port in [443, 8443] else "http"
        
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(f"{protocol}://{ip}:{port}/", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
                headers = dict(response.headers)
                
                server = headers.get("Server", "")
                if server:
                    import re
                    if re.search(r'/\d+\.', server):
                        findings.append({
                            "vuln": f"Server Version Disclosure",
                            "code": "http_server_version",
                            "severity": "LOW",
                            "port": port,
                            "description": f"HTTP Server header reveals version: '{server}'. This helps attackers identify known vulnerabilities for this specific version.",
                            "cve": "CWE-200"
                        })
                
                powered_by = headers.get("X-Powered-By", "")
                if powered_by:
                    findings.append({
                        "vuln": f"X-Powered-By Header Leak",
                        "code": "http_powered_by",
                        "severity": "LOW",
                        "port": port,
                        "description": f"X-Powered-By header reveals technology stack: '{powered_by}'. This helps attackers fingerprint the application framework.",
                        "cve": "CWE-200"
                    })
                
                if not headers.get("X-Frame-Options") and not headers.get("Content-Security-Policy"):
                    findings.append({
                        "vuln": "Missing Clickjacking Protection",
                        "code": "http_missing_frame_options",
                        "severity": "LOW",
                        "port": port,
                        "description": "Neither X-Frame-Options nor Content-Security-Policy frame-ancestors directive is set. The page may be vulnerable to clickjacking attacks.",
                        "cve": "CWE-1021"
                    })
                    
        except urllib.error.HTTPError as e:
            server = e.headers.get("Server", "") if hasattr(e, 'headers') else ""
            if server:
                import re
                if re.search(r'/\d+\.', server):
                    findings.append({
                        "vuln": f"Server Version Disclosure",
                        "code": "http_server_version",
                        "severity": "LOW",
                        "port": port,
                        "description": f"HTTP Server header reveals version: '{server}'.",
                        "cve": "CWE-200"
                    })
        except Exception as e:
            self.logger.debug("Server header check failed for %s:%d: %s", ip, port, e)
        
        return findings

    def check_web_secrets(self, ip, port):
        """Check for common exposed web secrets (.env, .git)."""
        findings = []
        protocol = "https" if port in [443, 8443] else "http"
        base_url = f"{protocol}://{ip}:{port}"
        
        secrets = [
            ("/.env", "CRITICAL", "Exposed .env file containing environment variables and potentially API keys or database credentials."),
            ("/.git/config", "HIGH", "Exposed .git directory allowing attackers to download the entire source code repository."),
            ("/docker-compose.yml", "MEDIUM", "Exposed Docker configuration revealing internal architecture and service layouts."),
            ("/config.json", "HIGH", "Exposed application configuration file."),
            ("/.htpasswd", "CRITICAL", "Exposed Apache password file containing hashed credentials."),
            ("/wp-config.php.bak", "CRITICAL", "Exposed WordPress configuration backup containing database credentials."),
            ("/server-status", "MEDIUM", "Apache server-status page is publicly accessible, revealing active connections and request details."),
        ]
        
        for path, severity, desc in secrets:
            try:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                req = urllib.request.Request(f"{base_url}{path}", headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=2, context=ctx) as response:
                    if response.getcode() == 200:
                        content = response.read(1024).decode('utf-8', errors='ignore')
                        if path == "/.env" and ("=" not in content or "<html" in content.lower()):
                            continue
                        if path == "/.git/config" and "[core]" not in content:
                            continue
                        if path == "/docker-compose.yml" and "version:" not in content and "services:" not in content:
                            continue
                        if path == "/.htpasswd" and (":" not in content or "<html" in content.lower()):
                            continue
                        if path == "/server-status" and "Apache Server Status" not in content:
                            continue
                        # Every path needs a content check, not five of seven.
                        #
                        # `/config.json` (HIGH) and `/wp-config.php.bak` (CRITICAL)
                        # had none, so any server that answers 200 with its index
                        # page for an unknown path -- an nginx `try_files ...
                        # /index.html`, an SPA catch-all, a custom 200 error page, a
                        # captive portal -- produced "Exposed Web Secret:
                        # /wp-config.php.bak ... containing database credentials" at
                        # CRITICAL, for a file that does not exist. The content was
                        # already read into `content` one line above; it simply was
                        # not consulted for these two.
                        if path == "/config.json" and not _looks_like_json(content):
                            continue
                        if path == "/wp-config.php.bak" and "<?php" not in content:
                            continue
                        # A catch-all for anything added later -- but only for paths
                        # that have no positive check of their own.
                        #
                        # Written unconditionally, it killed `/server-status`: Apache's
                        # mod_status page *is* an HTML document, so the specific check
                        # above passed and this one then threw the finding away. A guard
                        # that silences a real finding is worse than the gap it was
                        # added to cover.
                        if path not in _CONTENT_CHECKED_PATHS and (
                            "<html" in content.lower()
                            or "<!doctype html" in content.lower()
                        ):
                            continue
                        findings.append({
                            "vuln": f"Exposed Web Secret: {path}",
                            "code": "http_exposed_secret",
                            "severity": severity,
                            "port": port,
                            "description": desc,
                            "cve": "CWE-200"
                        })
            except urllib.error.HTTPError:
                pass  # Expected for non-existent paths
            except Exception as e:
                self.logger.debug("Web secret check failed for %s%s: %s", base_url, path, e)
                
        return findings

    def start_scan(self, target_ip, open_ports):
        """Starts the scan in a background thread."""
        thread = threading.Thread(target=self.run_checks, args=(target_ip, open_ports), daemon=True)
        thread.start()
