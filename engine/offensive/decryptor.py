"""LOCKON EWAC — WPA/WPA2 Decryptor

Drives a real hashcat process (mode 22000) against a real handshake extracted
from the operator's capture file. Nothing here is simulated: every number the
UI receives is parsed out of hashcat's own machine readable status output, and
the recovered passphrase is read back from hashcat's outfile.

Flow:
    pcap/pcapng -> hashcat_export.pcap_to_hc22000() -> .hc22000
                -> hashcat -m 22000 -a 0 ... -o cracked.txt <wordlist>
                -> parse --status-json lines for progress
                -> parse the outfile for the recovered key

If any step cannot be done honestly (no capture, no hashcat, no crackable hash,
no wordlist) the module says so and stops. It never degrades into a simulation.
"""
import os
import json
import time
import logging
import shutil
import tempfile
import platform
import subprocess
import threading
from collections import deque

from offensive.hashcat_export import pcap_to_hc22000, detect_hashcat

#: Three exception handlers in this module called `logger.warning` / `logger.debug`
#: with no `logger` anywhere in it, so each raised `NameError` from inside the
#: handler that was supposed to contain the failure.
#:
#: Two of them sit in `_destroy_work_dir`, in exactly the Windows case its own
#: docstring was written for -- hashcat still holding `cracked.txt` when the
#: cleanup runs. The NameError escaped the `finally`, `shutil.rmtree` was never
#: reached, and the recovered passphrase stayed in `%TEMP%\\ewac_decrypt_*\\cracked.txt`
#: with the warning that would have said so never emitted. The third turned an
#: unreadable outfile into `decrypt_error: "Decrypt failed: name 'logger' is not
#: defined"`, which tells the operator nothing about their capture.
logger = logging.getLogger("ewac.decryptor")

# Canonical wordlist resolution lives in engine/wordlists_path.py. It is guarded
# so a missing/broken module degrades into a clear decrypt_error instead of
# taking the whole engine down at import time.
try:
    from wordlists_path import resolve_wordlist, get_wordlists_dir
    _WORDLIST_IMPORT_ERROR = None
except Exception as _e:  # pragma: no cover - defensive
    resolve_wordlist = None
    get_wordlists_dir = None
    _WORDLIST_IMPORT_ERROR = str(_e)

# Windows: keep the hashcat console window hidden (same flag the rest of the
# engine uses for its subprocesses).
CREATE_NO_WINDOW = 0x08000000

# Where detect_hashcat() looks, quoted back to the operator when it finds nothing.
_HASHCAT_LOCATIONS = (
    "hashcat on PATH",
    r"C:\hashcat\hashcat.exe",
    r"C:\Tools\hashcat\hashcat.exe",
    r"%USERPROFILE%\hashcat\hashcat.exe",
)

# hashcat --status-json "status" field (device_status_t). Anything unknown is
# reported as its raw number rather than guessed at.
_HASHCAT_STATUS = {
    0: "init", 1: "autotune", 2: "selftest", 3: "running", 4: "paused",
    5: "exhausted", 6: "cracked", 7: "aborted", 8: "quit", 9: "bypass",
    10: "aborted_checkpoint", 11: "aborted_runtime", 12: "autodetect",
}

# hashcat process exit codes
_RC_CRACKED = 0
_RC_EXHAUSTED = 1

#: Longest a single hashcat run may take before the engine stops it.
#:
#: Nothing bounded a run, and `DecryptorPage` has no watchdog: it sets CRACKING
#: and waits for a terminal event. A hashcat that produced no output and did not
#: exit — a wedged driver, a GPU reset — left the UI in that state forever with
#: no record written, and only a manual abort recovered it.
#:
#: Six hours is past any wordlist an operator would sit through and far short of
#: leaving a machine stuck overnight with no explanation. Reaching it is
#: reported as a deadline, never as an exhausted wordlist: a run that was cut
#: off tested part of the list, and saying otherwise is the same false negative
#: the rest of this module was fixed to stop making.
_MAX_RUN_SECONDS = 6 * 60 * 60

#: Things hashcat says on plain stdout when it refuses part of the hash file.
#:
#: These never reached a terminal event except on the error paths, so a run that
#: loaded one hash out of three still ended in "exhausted" with the two
#: rejections invisible — and the UI had already announced three.
_HASH_REJECTION_MARKERS = (
    "token length exception",
    "line-length exception",
    "line length exception",
    "separator unmatched",
    "signature unmatched",
    "hash-encoding exception",
    "salt-value exception",
    "salt-length exception",
    "no hashes loaded",
)


def _redact_cracked(lines, hash_lines) -> str:
    """
    hashcat's recent output, with any recovered passphrase removed.

    The `output` field exists so a rejected hash line or a `No hashes loaded`
    reaches the operator instead of being folded into "exhausted". But hashcat
    prints cracked lines to stdout as well as to the outfile, so this buffer
    could contain the passphrase — and it was shipped verbatim in the
    `parse_failed` and `hashcat_failed` payloads and rendered into the UI log.
    The module reported that it could not parse a result while publishing the
    secret in the same message.

    Redaction is by hash prefix, which is exact: a cracked line begins with one
    of the hashes this run submitted, and everything after that prefix is the
    passphrase. A line that merely mentions a hash keeps its text.
    """
    out = []
    for line in lines or ():
        text = str(line)
        matched = None
        for h in sorted(hash_lines or (), key=len, reverse=True):
            if h and text.startswith(h + ":"):
                matched = h
                break
        if matched:
            out.append(f"{matched}:[REDACTED — recovered key, reported separately]")
        else:
            out.append(text)
    return "\n".join(out)


def _count_rejected_hashes(lines) -> int:
    """
    How many hash lines hashcat reported refusing.

    Counted from its own text output rather than inferred, because there is no
    machine-readable channel for it: `--status-json` carries progress, not load
    errors. `No hashes loaded` is counted once and means the whole file was
    refused, which is the case most worth surfacing — the pipeline otherwise
    reports a clean "exhausted" for a run that tested nothing at all.
    """
    count = 0
    for line in lines or ():
        lowered = str(line).lower()
        for marker in _HASH_REJECTION_MARKERS:
            if marker in lowered:
                count += 1
                break
    return count


# ── Preflight: the three ways a crack is refused before anything runs ─────────
#
# These were inline steps 1, 2 and 4 of `_run`, a 422-line method whose middle is
# subprocess orchestration. Pulled out because they are the paths that matter
# most and were the only ones nothing could reach: a refusal has to be a refusal.
#
# The alternative to refusing clearly is the failure this whole tool is built to
# avoid. A crack that could not start, reported as a crack that found nothing, is
# indistinguishable from "the passphrase is strong" — and that sentence in a
# report is the one that gets somebody to stop worrying about a network they
# should worry about. So each check returns the operator-facing `reason` and
# `message` verbatim, and `_run` emits them unchanged.
#
# Each returns None when there is nothing wrong.


def check_capture_file(pcap_file):
    """Refusal dict if the capture cannot be read, else None."""
    if not pcap_file or not os.path.isfile(pcap_file):
        return {
            "reason": "pcap_missing",
            "message": f"Capture file not found: {pcap_file}",
        }
    try:
        with open(pcap_file, "rb") as fh:
            fh.read(1)
    except OSError as e:
        return {
            "reason": "pcap_unreadable",
            "message": f"Capture file is not readable: {pcap_file} ({e})",
        }
    return None


def check_hashcat():
    """
    `(refusal, binary, version)`.

    hashcat being absent is not an error state to work around — it is the whole
    tool for this job, and the searched locations travel with the refusal so the
    operator knows where to put it rather than guessing.
    """
    hc = detect_hashcat()
    if not hc.get("installed"):
        return ({
            "reason": "hashcat_missing",
            "message": ("hashcat not found. Install hashcat, then make it reachable at one of: "
                        + ", ".join(_HASHCAT_LOCATIONS)),
            "searched": list(_HASHCAT_LOCATIONS),
        }, None, None)
    return (None, hc.get("path") or "hashcat", (hc.get("version") or "").strip())


def check_wordlist(wordlist_name):
    """
    `(refusal, path)`.

    Two separate failures, kept apart: the resolver module itself failing to
    import (a packaging fault) and the named list not being on disk (an operator
    one). They need different answers, and collapsing them sent somebody looking
    for a missing file when the build was wrong.
    """
    if resolve_wordlist is None:
        return ({
            "reason": "wordlist_module_missing",
            "message": f"Wordlist resolver unavailable (wordlists_path import failed: {_WORDLIST_IMPORT_ERROR})",
        }, None)

    wordlist_path = resolve_wordlist(wordlist_name)
    if not wordlist_path or not os.path.isfile(wordlist_path):
        where = ""
        if get_wordlists_dir is not None:
            try:
                where = f" (looked in {get_wordlists_dir()})"
            except Exception:
                where = ""
        return ({
            "reason": "wordlist_missing",
            "message": f"Wordlist not found: {wordlist_name}{where}",
        }, None)
    return (None, wordlist_path)


class DecryptorModule:
    def __init__(self, ipc_handler):
        self.ipc = ipc_handler
        self.decrypting = False
        self._lock = threading.Lock()
        self._run_id = 0            # bumped per run, guards late events from a dead run
        self._proc = None           # live hashcat subprocess
        self._abort_requested = False
        self._terminal_sent = False
        self._last_counts = {}      # last real {tested,total} seen from hashcat

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start_decrypt(self, pcap_file, wordlist_name, mangling=None):
        with self._lock:
            if self.decrypting:
                # Match the dirbuster pattern: complain loudly, never no-op silently.
                self.ipc.emit("decrypt_error", {
                    "reason": "already_running",
                    "message": "A decrypt session is already running.",
                })
                return
            self.decrypting = True
            self._run_id += 1
            run_id = self._run_id
            self._proc = None
            self._abort_requested = False
            self._terminal_sent = False
            self._last_counts = {}

        t = threading.Thread(
            target=self._run,
            args=(run_id, pcap_file, wordlist_name, mangling),
            daemon=True,
        )
        t.start()

    def stop_decrypt(self):
        """Kill the running hashcat process and close the run out as aborted."""
        with self._lock:
            if not self.decrypting:
                return
            run_id = self._run_id
            self._abort_requested = True
            proc = self._proc

        if proc is not None and proc.poll() is None:
            # Ask nicely, then insist. The reader thread notices the process is
            # gone and emits decrypt_aborted from the single terminal path.
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                pass
            return

        # No process yet (still validating/converting): the worker can be stuck
        # inside scapy for a while, so close the run out here. _finish() keeps
        # this to exactly one decrypt_aborted.
        self._finish(run_id, "decrypt_aborted", {
            "message": "Decrypt aborted by operator.",
            "tested": self._last_counts.get("tested", 0),
            "total": self._last_counts.get("total", 0),
        })

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------
    def _run(self, run_id, pcap_file, wordlist_name, mangling):
        work_dir = None
        started_at = time.time()

        try:
            # --- 1. The capture file must exist and be readable -------------
            refusal = check_capture_file(pcap_file)
            if refusal:
                self._finish(run_id, "decrypt_error", refusal)
                return

            # --- 2. hashcat must be installed -------------------------------
            refusal, hashcat_bin, hashcat_version = check_hashcat()
            if refusal:
                self._finish(run_id, "decrypt_error", refusal)
                return

            if self._aborted(run_id):
                return

            # --- 3. Convert the capture to .hc22000 -------------------------
            work_dir = tempfile.mkdtemp(prefix="ewac_decrypt_")
            hash_file = os.path.join(work_dir, "capture.hc22000")
            export = pcap_to_hc22000(pcap_file, hash_file)

            if not export.get("success"):
                # hash_count == 0 is the exporter's "nothing crackable in here"
                # signal; anything else is a real failure (scapy missing, unreadable pcap...).
                if export.get("hash_count") == 0:
                    self._finish(run_id, "decrypt_failed", {
                        "reason": "no_hash_in_capture",
                        "message": export.get("error", "No usable EAPOL pair or PMKID in capture."),
                        "file": pcap_file,
                        "tested": 0,
                        "total": 0,
                    })
                else:
                    self._finish(run_id, "decrypt_error", {
                        "reason": "convert_failed",
                        "message": f"Handshake extraction failed: {export.get('error', 'unknown error')}",
                        "file": pcap_file,
                    })
                return

            hash_lines = export.get("hashes") or []
            targets = [self._parse_hash_line(line) for line in hash_lines]
            targets = [t for t in targets if t]
            target = next((t for t in targets if t.get("essid")), targets[0] if targets else {})

            if self._aborted(run_id):
                return

            # --- 4. Resolve the wordlist ------------------------------------
            refusal, wordlist_path = check_wordlist(wordlist_name)
            if refusal:
                self._finish(run_id, "decrypt_error", refusal)
                return

            if self._aborted(run_id):
                return

            # --- 5. Build and launch the hashcat command --------------------
            outfile = os.path.join(work_dir, "cracked.txt")
            cmd = [
                hashcat_bin,
                "-m", "22000",              # WPA-PBKDF2-PMKID+EAPOL
                "-a", "0",                  # straight dictionary attack
                "--potfile-disable",        # never resolve a hash from a previous run
                "--restore-disable",
                # Pin the outfile layout to "<hash>:<plain>".
                #
                # This was left to the installed build's default, which has not
                # been constant across hashcat versions — so whether a line came
                # back as "<plain>", "<hash>:<plain>" or
                # "<hash>:<plain>:<hex>:<crackpos>" was decided by the operator's
                # machine. `_read_outfile` then reported whatever it could not
                # account for as the passphrase, which turned a format
                # difference into a wrong password in the report and in
                # `cracking_history`. Pinning it means the parser knows the
                # shape it is reading and can refuse anything else.
                "--outfile-format", "1,2",

                "--status", "--status-json", "--status-timer", "1",
                "-o", outfile,              # recovered keys land here, not in stdout scraping
                hash_file,
                wordlist_path,
            ]

            popen_kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,   # merged so a startup error is never lost
                "stdin": subprocess.DEVNULL,   # hashcat otherwise waits on keypresses
                "text": True,
                "encoding": "utf-8",
                "errors": "ignore",
                "bufsize": 1,
            }
            if platform.system().lower() == "windows":
                popen_kwargs["creationflags"] = CREATE_NO_WINDOW
            hashcat_dir = os.path.dirname(hashcat_bin)
            if hashcat_dir and os.path.isdir(hashcat_dir):
                # hashcat resolves its OpenCL kernels relative to its own folder.
                popen_kwargs["cwd"] = hashcat_dir

            started_payload = {
                "file": pcap_file,
                "simulated": False,
                "wordlist": wordlist_name,
                "wordlist_path": wordlist_path,
                "hash_count": export.get("hash_count", len(hash_lines)),
                "essid": target.get("essid"),
                "bssid": target.get("bssid"),
                "hash_mode": target.get("hash_mode"),
                "targets": targets,
                "hashcat_path": hashcat_bin,
                "hashcat_version": hashcat_version,
                "command": cmd,
            }
            if mangling:
                # The old module faked "smart mangling" in Python. There is no
                # rules file shipped with this project to map it onto, so it is
                # reported as not applied rather than pretended.
                started_payload["mangling"] = mangling
                started_payload["mangling_applied"] = False
                started_payload["mangling_note"] = (
                    "Keyword mangling is not implemented for the hashcat backend "
                    "(no rules file ships with LOCKON-EWAC); the wordlist is used as-is."
                )

            self.ipc.emit("decrypt_started", started_payload)
            started_at = time.time()

            try:
                proc = subprocess.Popen(cmd, **popen_kwargs)
            except Exception as e:
                self._finish(run_id, "decrypt_error", {
                    "reason": "launch_failed",
                    "message": f"Failed to launch hashcat: {e}",
                })
                return

            with self._lock:
                if run_id != self._run_id:
                    proc.kill()
                    return
                self._proc = proc

            if self._abort_requested:
                # stop_decrypt() landed between the checks above and the spawn.
                try:
                    proc.terminate()
                except Exception:
                    pass

            # --- 6. Stream hashcat's output ---------------------------------
            tail = deque(maxlen=25)   # last non-JSON lines, used for error reporting
            last_status = None
            # Accounting for the status stream itself.
            #
            # A `except ValueError: continue` used to swallow every unparsed
            # status line with no event and no flag, so `_last_counts` kept the
            # last good pair — or stayed empty — and `_finish` published those
            # stale values as the run's authoritative tested/total. Three real
            # triggers: a hashcat build whose JSON shape differs, interleaved
            # output splicing a line, and `errors="replace"` altering a byte
            # inside one. The `startswith("{")` gate also means a build that
            # indents its JSON yields zero parsed status for the entire run.
            #
            # Counting them is what lets the terminal event say the progress
            # figures are not trustworthy instead of quietly presenting them.
            stream = {"status_lines": 0, "status_parsed": 0, "text_lines": 0}
            try:
                for raw in proc.stdout:
                    line = raw.strip()
                    if not line:
                        continue
                    if line.startswith("{"):
                        stream["status_lines"] += 1
                        try:
                            status = json.loads(line)
                        except ValueError:
                            tail.append(line)
                            continue
                        stream["status_parsed"] += 1
                        last_status = status
                        self._emit_progress(run_id, status)
                    else:
                        stream["text_lines"] += 1
                        tail.append(line)
                    # Nothing bounds a hashcat run, and the UI has no watchdog
                    # either — it sets CRACKING and waits for an event. A
                    # process that produces no output and does not exit left the
                    # panel in that state indefinitely with no record written,
                    # recoverable only by a manual abort. This bounds it, and
                    # says plainly that it was bounded rather than finishing.
                    if time.time() - started_at > _MAX_RUN_SECONDS:
                        self._run_deadline_hit = True
                        try:
                            proc.terminate()
                        except Exception:
                            pass
                        break
            except Exception as e:
                tail.append(f"status reader error: {e}")
            finally:
                try:
                    proc.stdout.close()
                except Exception:
                    pass

            # True when hashcat's own progress cannot be relied on: it sent
            # status lines we could not read, or never sent any at all.
            progress_unreliable = (
                stream["status_parsed"] == 0
                or stream["status_parsed"] < stream["status_lines"]
            )

            rc = proc.wait()
            duration = round(time.time() - started_at, 2)

            # --- 7. Exactly one terminal event ------------------------------
            cracked, unparsed = self._read_outfile(outfile, hash_lines)
            counts = dict(self._last_counts)
            status_name = _HASHCAT_STATUS.get((last_status or {}).get("status"), None)

            if cracked:
                first = cracked[0]
                # The network is whatever the matched hash line says it is, and
                # nothing else.
                #
                # This used to fall back to `target`, which is "the first hash
                # line in the file that happened to carry an ESSID" — so with
                # several access points in one capture, a passphrase recovered
                # for network B could be reported, and persisted, as belonging
                # to network A. Now that the outfile line must begin with a hash
                # from this run, the identity always comes from that hash; a
                # line whose hash carries no ESSID reports None rather than
                # borrowing someone else's.
                self._finish(run_id, "decrypt_success", {
                    "password": first.get("password"),
                    "essid": first.get("essid"),
                    "bssid": first.get("bssid"),
                    "hash_mode": first.get("hash_mode"),
                    "tested": counts.get("tested", 0),
                    "total": counts.get("total", 0),
                    "results": cracked,
                    "unparsed_lines": len(unparsed),
                    "file": pcap_file,
                    "wordlist": wordlist_name,
                    "duration_seconds": duration,
                    "caveat": (
                        f"{len(unparsed)} line(s) in hashcat's outfile could not be attributed to a "
                        "hash from this run and were not reported. A recovered key may be missing "
                        "from this result."
                    ) if unparsed else None,
                })
            elif self._abort_requested:
                self._finish(run_id, "decrypt_aborted", {
                    "message": "Decrypt aborted by operator.",
                    "tested": counts.get("tested", 0),
                    "total": counts.get("total", 0),
                    "file": pcap_file,
                    "duration_seconds": duration,
                })
            elif getattr(self, "_run_deadline_hit", False):
                # Checked before the exhausted branch: hashcat exits 1 when it
                # is terminated, so without this a deadline stop would be
                # reported as a clean exhaustion.
                self._run_deadline_hit = False
                self._finish(run_id, "decrypt_failed", {
                    "reason": "run_deadline",
                    "message": (
                        f"The run was stopped after {_MAX_RUN_SECONDS // 3600} hours without "
                        "recovering a key. Part of the wordlist was not tested, so this says "
                        "nothing about whether the passphrase is in it."
                    ),
                    "tested": counts.get("tested", 0),
                    "total": counts.get("total", 0),
                    "progress_corroborated": False,
                    "file": pcap_file,
                    "wordlist": wordlist_name,
                    "duration_seconds": duration,
                    "output": _redact_cracked(tail, hash_lines),
                })
            elif rc == _RC_EXHAUSTED or status_name == "exhausted":
                # "Exhausted the wordlist" is the strongest negative claim this
                # tool makes — a reader takes it to mean the passphrase is not in
                # the tested list. It used to rest on an exit code alone, with
                # its own supporting evidence thrown away: this was the one
                # branch that did not carry `output`, so hashcat's account of
                # what it actually loaded and rejected was discarded at exactly
                # the moment it mattered.
                #
                # Two ways the bare exit code lies. On Windows `TerminateProcess`
                # yields code 1, so any externally killed hashcat looked like a
                # clean exhaustion. And if no status line ever parsed, the event
                # shipped `tested: 0, total: 0` while claiming the list was
                # exhausted.
                tested = counts.get("tested", 0)
                total = counts.get("total", 0)
                # Corroborated only when hashcat's own progress says it got to
                # the end — and only when that progress was actually readable.
                # A run whose status lines never parsed has no progress to
                # corroborate anything with, however confident the exit code is.
                corroborated = (
                    not progress_unreliable and bool(total) and tested >= total
                )
                rejected = _count_rejected_hashes(tail)
                if rejected:
                    # A rejected hash was never tested, so whatever the wordlist
                    # did or did not finish says nothing about that target.
                    message = (
                        f"hashcat refused {rejected} of the {len(hash_lines)} hash(es) from this "
                        "capture and stopped without recovering a key. The refused target(s) were "
                        "never tested; this is not a result for them."
                    )
                    reason = "hashes_rejected"
                elif corroborated:
                    message = (
                        f"hashcat exhausted the wordlist ({tested} of {total} candidates) "
                        "without recovering the key."
                    )
                    reason = "exhausted"
                else:
                    message = (
                        "hashcat stopped without recovering a key, but its own progress does not "
                        "confirm the wordlist was finished. Do not read this as the passphrase "
                        "being absent from the list."
                    )
                    reason = "stopped_without_result"

                self._finish(run_id, "decrypt_failed", {
                    "reason": reason,
                    "message": message,
                    "tested": tested,
                    "total": total,
                    "progress_corroborated": corroborated,
                    "progress_unreliable": progress_unreliable,
                    "unparsed_lines": len(unparsed),
                    # How many hashes this run handed hashcat, against how many
                    # it said it loaded.
                    #
                    # hashcat reports `Token length exception` / `Line-length
                    # exception` / `No hashes loaded` on plain stdout, which was
                    # only surfaced in the error branches — so a capture that
                    # produced three hash lines of which hashcat accepted one
                    # still logged "HASHES EXTRACTED: 3" at the start and
                    # "exhausted" at the end, with no trace of the two rejects.
                    # A reader concluded three targets survived the wordlist when
                    # one had been tested.
                    "hashes_submitted": len(hash_lines),
                    "hashes_rejected_by_hashcat": rejected,
                    # Kept so a rejected hash line or a "No hashes loaded" is
                    # visible instead of being silently folded into "exhausted".
                    "output": _redact_cracked(tail, hash_lines),
                    "exit_code": rc,
                    "file": pcap_file,
                    "wordlist": wordlist_name,
                    "duration_seconds": duration,
                })
            elif rc == _RC_CRACKED:
                # hashcat says cracked but the outfile gave us nothing usable.
                self._finish(run_id, "decrypt_error", {
                    "reason": "parse_failed",
                    "message": "hashcat reported a recovered key but its outfile could not be parsed.",
                    "output": _redact_cracked(tail, hash_lines),
                })
            else:
                self._finish(run_id, "decrypt_error", {
                    "reason": "hashcat_failed",
                    "message": f"hashcat exited with code {rc}"
                               + (f" ({status_name})" if status_name else ""),
                    "exit_code": rc,
                    "output": _redact_cracked(tail, hash_lines),
                })

        except Exception as e:
            self._finish(run_id, "decrypt_error", {
                "reason": "hashcat_failed",
                "message": f"Decrypt failed: {e}",
            })
        finally:
            with self._lock:
                if run_id == self._run_id:
                    self._proc = None
                    self.decrypting = False
            if work_dir:
                self._destroy_work_dir(work_dir)

    @staticmethod
    def _destroy_work_dir(work_dir):
        """
        Remove the working directory, overwriting the outfile first.

        `shutil.rmtree(..., ignore_errors=True)` on its own was not enough. The
        outfile holds the recovered passphrase in cleartext, and on Windows a
        file still held open by a dying hashcat cannot be unlinked — so
        `ignore_errors` silently left `%TEMP%\\ewac_decrypt_*\\cracked.txt`
        behind with the key in it, and nothing reported that it had.
        Deleting a file does not erase its contents either.

        So: overwrite the bytes, then truncate, then try to remove. Overwriting
        works even when unlinking does not, which is the case that actually
        happens.
        """
        outfile = os.path.join(work_dir, "cracked.txt")
        try:
            if os.path.isfile(outfile):
                size = os.path.getsize(outfile)
                with open(outfile, "r+b") as fh:
                    fh.write(b"\x00" * size)
                    fh.flush()
                    os.fsync(fh.fileno())
                    fh.truncate(0)
        except OSError as e:
            # Worth knowing about: it means a recovered key may still be on disk.
            logger.warning("could not overwrite %s before deleting it: %s", outfile, e)

        shutil.rmtree(work_dir, ignore_errors=True)
        if os.path.exists(work_dir):
            logger.warning(
                "working directory %s could not be removed; it may still hold a recovered key",
                work_dir,
            )

    # ------------------------------------------------------------------
    # Progress / result parsing
    # ------------------------------------------------------------------
    def _emit_progress(self, run_id, status):
        """Turn one hashcat --status-json line into a decrypt_progress event.

        Every field is optional: whatever hashcat did not report is left out
        rather than filled with a placeholder.
        """
        if run_id != self._run_id or self._terminal_sent:
            return

        payload = {}

        progress = status.get("progress")
        done = total = None
        if isinstance(progress, (list, tuple)) and len(progress) >= 2:
            try:
                done = int(progress[0])
                total = int(progress[1])
            except (TypeError, ValueError):
                done = total = None
        if done is not None:
            payload["tested"] = done
        if total:
            payload["total"] = total
            if done is not None:
                payload["progress"] = round(min(done / total, 1.0) * 100, 2)
        if done is not None or total:
            self._last_counts = {"tested": done or 0, "total": total or 0}

        # Real hash rate / temperature, summed across the devices hashcat used.
        speed = 0
        temps = []
        device_name = None
        for dev in status.get("devices") or []:
            if not isinstance(dev, dict):
                continue
            try:
                dev_speed = int(dev.get("speed") or 0)
            except (TypeError, ValueError):
                dev_speed = 0
            if dev_speed > 0:
                speed += dev_speed
                if device_name is None:
                    device_name = dev.get("device_name")
            try:
                temp = int(dev.get("temp"))
            except (TypeError, ValueError):
                temp = -1
            if temp > 0:  # hashcat reports -1 when the device has no sensor
                temps.append(temp)
        if speed > 0:
            payload["hashes_per_sec"] = speed
        if device_name:
            payload["device"] = device_name
        if temps:
            payload["temperature_c"] = max(temps)

        # ETA straight from hashcat's own estimate.
        try:
            estimated_stop = int(status.get("estimated_stop") or 0)
        except (TypeError, ValueError):
            estimated_stop = 0
        if estimated_stop > 0:
            eta_seconds = int(estimated_stop - time.time())
            if eta_seconds >= 0:
                payload["eta_seconds"] = eta_seconds
                payload["eta"] = self._format_eta(eta_seconds)

        recovered = status.get("recovered_hashes")
        if isinstance(recovered, (list, tuple)) and len(recovered) >= 2:
            try:
                payload["recovered"] = int(recovered[0])
                payload["hashes_total"] = int(recovered[1])
            except (TypeError, ValueError):
                pass

        status_name = _HASHCAT_STATUS.get(status.get("status"))
        if status_name:
            payload["status"] = status_name

        if payload:
            self.ipc.emit("decrypt_progress", payload)

    @staticmethod
    def _format_eta(seconds):
        hours, rem = divmod(int(seconds), 3600)
        minutes, secs = divmod(rem, 60)
        if hours:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"

    @staticmethod
    def _parse_hash_line(line):
        """Pull ESSID/BSSID out of a .hc22000 line produced from the capture.

        Layout: WPA*<01|02>*<pmkid|mic>*<mac_ap>*<mac_sta>*<essid_hex>*...
        """
        info = {}
        if not line:
            return info
        parts = line.split("*")
        if len(parts) < 6 or parts[0] != "WPA":
            return info

        info["hash_mode"] = "PMKID" if parts[1] == "01" else "EAPOL"

        mac_ap = parts[3]
        if len(mac_ap) == 12:
            info["bssid"] = ":".join(mac_ap[i:i + 2] for i in range(0, 12, 2)).upper()
        mac_sta = parts[4]
        if len(mac_sta) == 12:
            info["client"] = ":".join(mac_sta[i:i + 2] for i in range(0, 12, 2)).upper()

        essid_hex = parts[5]
        if essid_hex:
            try:
                info["essid"] = bytes.fromhex(essid_hex).decode("utf-8", errors="replace")
            except ValueError:
                pass
        return info

    def _read_outfile(self, outfile, hash_lines):
        """
        Read the keys hashcat recovered, and refuse anything it cannot account
        for.

        The command pins `--outfile-format 1,2`, so every line is exactly
        `<hash>:<plain>` where `<hash>` is one of the lines this run handed
        hashcat. A line that does not begin with one of those hashes is not a
        result, and is not treated as one.

        That check is the whole point. The previous version stripped a prefix
        when it recognised one and reported **whatever remained** as the
        passphrase, with the acceptance test being only `if rest:`. Measured
        against real outfile contents, that reported:

            <hash>:Summer2024!                      -> "Summer2024!"          ok
            <hash>:Summer2024!:53756d…:0            -> "Summer2024!:53756d…:0"
            <hash>:Summ         (truncated mid-write) -> "Summ"
            Hashfile '…' on line 2: Token length…   -> that whole sentence

        The last one is hashcat's own error text reported as a recovered
        passphrase, into the report and into `cracking_history`. Rows two and
        three were reachable because the outfile layout was left to the
        installed build's default and because a partially flushed line passed
        the emptiness test.

        A recovered passphrase is the strongest claim this tool makes about a
        network. Dropping a line we cannot parse costs a true positive at worst;
        accepting one we cannot parse puts a fabricated secret in front of a
        client. `unparsed` is returned so the caller can say a line was refused
        rather than silently reporting nothing.
        """
        if not outfile or not os.path.isfile(outfile):
            return [], []

        try:
            with open(outfile, "r", encoding="utf-8", errors="ignore") as f:
                lines = [ln.rstrip("\r\n") for ln in f if ln.strip()]
        except OSError as e:
            logger.debug("could not read hashcat outfile %s: %s", outfile, e)
            return [], []

        results = []
        unparsed = []
        for line in lines:
            # Must begin with a hash from *this* run. Longest first, so a hash
            # that is a prefix of another cannot claim the line.
            matched = None
            for h in sorted(hash_lines, key=len, reverse=True):
                if line.startswith(h + ":"):
                    matched = h
                    break
            if matched is None:
                unparsed.append(line)
                continue

            password = line[len(matched) + 1:]
            if not password:
                # `<hash>:` with nothing after it is not an empty passphrase, it
                # is a line that was not finished being written.
                unparsed.append(line)
                continue

            # Guard against a build that ignored `--outfile-format 1,2` and gave
            # us `<hash>:<plain>:<hex_plain>:<crack_pos>` anyway.
            #
            # A passphrase is allowed to contain colons, so the remainder cannot
            # be split on sight. But `hex_plain` is by definition the hex of
            # `plain`, and that relationship is exact — when it holds, the line
            # is the four-field layout and our assumption about the format was
            # wrong. Refusing is the right answer there: if the format is not
            # what we pinned, we do not know which part is the passphrase, and
            # guessing produced `Summer2024!:53756d6d657232303234:0` as a
            # reported password.
            if password.count(":") >= 2:
                parts = password.split(":")
                for cut in range(1, len(parts) - 1):
                    plain = ":".join(parts[:cut])
                    try:
                        if bytes.fromhex(parts[cut]).decode("utf-8") == plain:
                            unparsed.append(line)
                            password = None
                            break
                    except (ValueError, UnicodeDecodeError):
                        continue
            if password is None:
                continue

            info = self._parse_hash_line(matched)
            results.append({
                "password": password,
                "essid": info.get("essid"),
                "bssid": info.get("bssid"),
                "hash_mode": info.get("hash_mode"),
            })
        return results, unparsed

    # ------------------------------------------------------------------
    # Run bookkeeping
    # ------------------------------------------------------------------
    def _aborted(self, run_id):
        """True (and closes the run out) if the operator stopped us mid-setup."""
        if run_id != self._run_id:
            return True
        if self._abort_requested:
            self._finish(run_id, "decrypt_aborted", {
                "message": "Decrypt aborted by operator.",
                "tested": 0,
                "total": 0,
            })
            return True
        return False

    def _finish(self, run_id, event, payload):
        """Emit exactly one terminal event per run."""
        with self._lock:
            if run_id != self._run_id or self._terminal_sent:
                return
            self._terminal_sent = True
            self.decrypting = False
        self.ipc.emit(event, payload)
