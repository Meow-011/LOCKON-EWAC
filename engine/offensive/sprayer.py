"""Credential spraying — one credential against many hosts.

Why the shape of this module matters.

Spraying exists to avoid account lockout: one password against many accounts or
hosts, slowly, rather than many passwords against one. The previous version did
the opposite of that. It started **one thread per target** and the only delay in
the code was a `time.sleep(0.5)` at the *end* of each worker, after the attempt
had already been made. Since each worker handled exactly one target, every
target was hit simultaneously and the sleep only kept a finished thread alive.
On a domain that is the fastest way to trip every lockout policy at once — the
precise outcome the technique is chosen to prevent — and on a /24 it was 254
operating-system threads.

The `queue` import was already at the top of the file and unused, which suggests
the pool was always the intent.

The second problem was the report. A malformed target dict raised `KeyError`
inside a daemon thread, which dies silently: no event, no log, and `join()`
returns normally. The run then emitted "Credential spray finished." with no
counts at all, so a spray where nothing was ever actually judged by a host was
indistinguishable from one where every host judged the credential and rejected
it. Those are opposite findings. The completion event now carries the
denominators.
"""
import queue
import threading
import time


class CredentialSprayer:
    #: Concurrent attempts. A spray is deliberately slow; this is a ceiling on
    #: threads, not a throughput target.
    MAX_WORKERS = 8

    #: Seconds between attempts *within* a worker. With MAX_WORKERS this gives
    #: roughly 16 attempts a minute across the whole run.
    DELAY_BETWEEN_ATTEMPTS = 0.5

    #: How long a stop waits for the monitor to report real counts before the
    #: watchdog emits a terminal event of its own.
    STOP_GRACE_SECONDS = 5.0

    def __init__(self, emit_callback, bruteforcer):
        self.emit = emit_callback
        self.bruteforcer = bruteforcer
        self._running = False
        self._active_threads = []
        self._lock = threading.Lock()
        self._completed = True  # No run in flight yet
        self._counts = {}

    def _finish(self, message, counts_complete=True):
        """Emit spray_completed exactly once per spray run, with its counts."""
        with self._lock:
            if self._completed:
                return
            self._completed = True
            self._running = False
            counts = dict(self._counts)

        never_judged = counts.get("unreachable", 0) + counts.get("malformed", 0) \
            + counts.get("errored", 0) + counts.get("not_attempted", 0)
        if not counts_complete:
            caveat = ("The run was stopped and the workers did not report back in time, so "
                      "these counts are a floor, not a total. Treat every target not listed "
                      "as a success as untested.")
        elif never_judged:
            caveat = ("A target counted under never_judged did not evaluate the credential: "
                      "it was unreachable, its service is unsupported, the attempt errored, or "
                      "the run stopped before reaching it. No absence of a success applies to "
                      "those hosts.")
        elif not counts.get("succeeded"):
            caveat = "Every target evaluated the credential and rejected it."
        else:
            caveat = "Every target evaluated the credential."

        payload = {
            "message": message,
            **counts,
            # The number that decides what the absence of a success means. Said
            # here rather than left for the reader to add up, because the
            # completion event is what the UI turns into a result.
            "never_judged": never_judged,
            # False when the counts were emitted by the stop watchdog rather
            # than by the run itself. A floor presented as a total is the same
            # defect as an unmeasured field presented as a zero.
            "counts_complete": counts_complete,
            "caveat": caveat,
        }
        self.emit("spray_completed", payload)

    def _bump(self, key, amount=1):
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + amount

    @staticmethod
    def _normalise(target):
        """A target dict, or None when it does not describe a host and a port.

        A malformed entry used to raise `KeyError` inside a daemon thread, which
        dies without an event and without a log line — so the target was
        silently dropped and the run still reported success.
        """
        if not isinstance(target, dict):
            return None
        ip = str(target.get("ip") or "").strip()
        service = str(target.get("service_type") or "").strip()
        try:
            port = int(str(target.get("port")).strip())
        except (TypeError, ValueError):
            return None
        if not ip or not service or not (1 <= port <= 65535):
            return None
        return {"ip": ip, "port": port, "service_type": service}

    def start_spray(self, username, password, targets):
        """
        targets: list of dicts {"ip": str, "port": int, "service_type": str}
        """
        with self._lock:
            if self._running:
                self.emit("spray_error", {"message": "A spray attack is already running."})
                return

            if not isinstance(targets, (list, tuple)) or not targets:
                self.emit("spray_error", {"message": "No targets provided for spraying."})
                return

            usable = []
            malformed = 0
            for raw in targets:
                normalised = self._normalise(raw)
                if normalised is None:
                    malformed += 1
                else:
                    usable.append(normalised)

            if not usable:
                self.emit("spray_error", {
                    "message": f"None of the {len(targets)} target(s) named a host, a port and a "
                               "service, so nothing was sprayed.",
                })
                return

            self._running = True
            self._completed = False
            self._counts = {
                "total_targets": len(targets),
                "attempted": 0,
                "judged": 0,
                "succeeded": 0,
                "unreachable": 0,
                "errored": 0,
                "malformed": malformed,
                "not_attempted": 0,
            }

        if malformed:
            # Named rather than dropped: a target that was never sprayed must not
            # sit inside a count of targets that rejected the credential.
            self.emit("spray_error", {
                "message": f"{malformed} target(s) did not name a host, a port and a service "
                           "and were not sprayed.",
            })

        work = queue.Queue()
        for target in usable:
            work.put(target)

        self.emit("spray_started", {
            "total_targets": len(targets),
            "usable_targets": len(usable),
            "username": username,
            "workers": min(self.MAX_WORKERS, len(usable)),
            "delay_between_attempts": self.DELAY_BETWEEN_ATTEMPTS,
        })

        def worker():
            while self._running:
                try:
                    target = work.get_nowait()
                except queue.Empty:
                    return
                try:
                    self._attempt(target, username, password)
                finally:
                    work.task_done()
                # Between attempts, not after the last one's result: this is the
                # rate limit, and it is the whole point of spraying rather than
                # brute forcing.
                if self._running and not work.empty():
                    time.sleep(self.DELAY_BETWEEN_ATTEMPTS)

        def monitor():
            threads = []
            try:
                for _ in range(min(self.MAX_WORKERS, len(usable))):
                    th = threading.Thread(target=worker, daemon=True)
                    th.start()
                    threads.append(th)
                self._active_threads = threads
                for th in threads:
                    th.join()
            finally:
                # Whatever is left in the queue was never tried, which happens
                # when the operator stops the run. Counted, not forgotten.
                remaining = work.qsize()
                if remaining:
                    self._bump("not_attempted", remaining)
                self._finish("Credential spray finished." if self._running
                             else "Credential spray stopped before every target was tried.")

        threading.Thread(target=monitor, daemon=True).start()

    def _attempt(self, target, username, password):
        ip = target["ip"]
        port = target["port"]
        svc = target["service_type"]

        self._bump("attempted")
        self.emit("spray_progress", {"target": f"{ip}:{port} ({svc})"})
        try:
            result = self.bruteforcer.test_credential(ip, port, svc, username, password)
        except Exception as e:
            self._bump("errored")
            self.emit("spray_error", {"message": f"{ip}:{port} ({svc}) spray failed: {e}"})
            return

        if getattr(result, "success", bool(result)):
            self._bump("judged")
            self._bump("succeeded")
            self.emit("spray_success", {
                "ip": ip,
                "port": port,
                "service": svc,
                "username": username,
                "password": password
            })
        elif getattr(result, "unreachable", False) or getattr(result, "unsupported", False):
            # Not a miss — the credential was never actually judged by the host.
            self._bump("unreachable")
            self.emit("spray_unreachable", {
                "ip": ip,
                "port": port,
                "service": svc,
                "reason": getattr(result, "detail", "") or "host unreachable"
            })
        else:
            # The host evaluated the credential and rejected it. This is the only
            # outcome that makes "the password does not work here" a finding.
            self._bump("judged")

    def stop_spray(self):
        """Stop the run.

        The completion event is left to the monitor thread, which is the only
        thing that knows how many queued targets were never reached. Emitting it
        from here would have produced a `spray_completed` whose `never_judged`
        omitted every untried target — and then the caveat would read "every
        target evaluated the credential and rejected it", which is a false
        statement about hosts nobody contacted.

        A watchdog covers the case where the monitor never reports: the UI gets
        a terminal event either way, and when it comes from here it says the
        counts are a floor.
        """
        self._running = False

        def watchdog():
            time.sleep(self.STOP_GRACE_SECONDS)
            self._finish("Credential spray aborted.", counts_complete=False)

        threading.Thread(target=watchdog, daemon=True).start()
