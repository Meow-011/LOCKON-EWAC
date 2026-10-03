import os
import sys
import threading
import urllib.request
import urllib.error
import ssl
import queue

from wordlists_path import resolve_wordlist

class DirBuster:
    def __init__(self, emit_callback):
        self.emit = emit_callback
        self._running = False
        self._queue = queue.Queue()
        self._active_threads = []
        self._base_url = None
        # How many requests the server answered, as against how many were sent.
        # Written from every worker thread, so it takes a lock.
        self._tally_lock = threading.Lock()
        self._answered = 0
        self._no_response = 0
        self._last_error = None
        # Ignore SSL certificate errors for self-signed pentest targets
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _get_wordlist_path(self, wordlist_name):
        # Canonical resolution lives in engine/wordlists_path.py so every module
        # (handler, bruteforce, dirbuster) looks in exactly the same place.
        return resolve_wordlist(wordlist_name)

    def start_attack(self, target_ip, port, is_https, wordlist_name, threads=10):
        if self._running:
            self.emit("dirbuster_error", {"message": "A DirBuster attack is already running."})
            return

        wordlist_path = self._get_wordlist_path(wordlist_name)
        if not wordlist_path or not os.path.exists(wordlist_path):
            self.emit("dirbuster_error", {"message": f"Wordlist not found: {wordlist_name}"})
            return

        self._running = True
        # Per run, or a quiet host would inherit the previous target's answers and
        # report `complete: True` on the strength of them.
        with self._tally_lock:
            self._answered = 0
            self._no_response = 0
            self._last_error = None
        protocol = "https" if is_https or port == 443 or port == 8443 else "http"
        base_url = f"{protocol}://{target_ip}:{port}"
        # Kept on the instance so the completion event can name its own target.
        # It used to carry only a message, which left the frontend matching
        # results to whatever host was selected when the event landed.
        self._base_url = base_url

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            self.emit("dirbuster_error", {"message": f"Failed to read wordlist: {e}"})
            self._running = False
            return

        total_paths = len(paths)
        for p in paths:
            self._queue.put(p)

        self.emit("dirbuster_started", {
            "target": base_url,
            "total_paths": total_paths
        })

        self._active_threads = []
        for _ in range(threads):
            t = threading.Thread(target=self._worker, args=(base_url, total_paths), daemon=True)
            t.start()
            self._active_threads.append(t)

        # Monitor thread
        threading.Thread(target=self._monitor, daemon=True).start()

    def _worker(self, base_url, total_paths):
        while self._running and not self._queue.empty():
            try:
                path = self._queue.get_nowait()
            except queue.Empty:
                break
                
            # Emit progress occasionally
            remaining = self._queue.qsize()
            if remaining % 50 == 0:
                self.emit("dirbuster_progress", {
                    "current_path": path,
                    "progress": ((total_paths - remaining) / total_paths) * 100
                })

            target_url = f"{base_url}/{path.lstrip('/')}"
            
            try:
                req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0 (LOCKON-EWAC Pentest)'})
                # Attempt to open URL
                with urllib.request.urlopen(req, context=self.ctx, timeout=3) as response:
                    status_code = response.getcode()
                    if status_code in [200, 204, 301, 302]:
                        self.emit("dirbuster_finding", {
                            "url": target_url,
                            "path": path,
                            "status": status_code,
                            "size": len(response.read())
                        })
            except urllib.error.HTTPError as e:
                # An HTTP status is an answer from the server, including a 404. It is
                # the only outcome that makes a path's absence meaningful.
                with self._tally_lock:
                    self._answered += 1
                # 403 Forbidden is a valid finding (means path exists but no access)
                if e.code in [403, 401]:
                    self.emit("dirbuster_finding", {
                        "url": target_url,
                        "path": path,
                        "status": e.code,
                        "size": 0
                    })
            except urllib.error.URLError as e:
                # Counted, not merely swallowed.
                #
                # This was a bare `pass`, so a connection refused, a timeout or a
                # DNS failure was indistinguishable from a genuine 404 -- and
                # `dirbuster_completed` then said `complete: True`. Against a host
                # whose port was closed or filtered, every single request failed and
                # the event stream reported that the wordlist had been exhausted
                # with no findings.
                #
                # That field's documented purpose is to license the statement that a
                # path's absence from the results says something about the server. It
                # cannot do that if nothing was ever asked.
                with self._tally_lock:
                    self._no_response += 1
                    self._last_error = str(getattr(e, "reason", e) or e)
            except Exception as e:
                with self._tally_lock:
                    self._no_response += 1
                    self._last_error = f"{type(e).__name__}: {e}"
            else:
                with self._tally_lock:
                    self._answered += 1
            finally:
                self._queue.task_done()

    def _monitor(self):
        for t in self._active_threads:
            t.join()
        if self._running:
            self._running = False
            with self._tally_lock:
                answered = self._answered
                no_response = self._no_response
                last_error = self._last_error
            attempted = answered + no_response
            # `complete` distinguishes a wordlist that was exhausted from one
            # that was cut short. Only the first makes "no other paths respond"
            # a statement about the server rather than about the scan -- and only
            # if the server was answering at all, which is what `answered` adds.
            self.emit("dirbuster_completed", {
                "target": self._base_url,
                "message": (
                    "DirBuster scan completed."
                    if answered else
                    f"DirBuster got no response to any of {attempted} request(s)."
                ),
                # False when nothing answered: the wordlist was sent, not tested.
                "complete": bool(answered),
                "paths_attempted": attempted,
                "paths_answered": answered,
                "paths_no_response": no_response,
                "last_error": last_error,
                "caveat": (
                    None if no_response == 0 else
                    f"{no_response} of {attempted} request(s) got no response"
                    + (f" ({last_error})" if last_error else "")
                    + ". Those paths were never tested, so their absence from the "
                      "results says nothing about the server."
                ),
            })

    def stop_attack(self):
        self._running = False
        with self._queue.mutex:
            self._queue.queue.clear()
        self.emit("dirbuster_completed", {
            "target": self._base_url,
            "message": "DirBuster scan halted by user.",
            "complete": False,
        })
