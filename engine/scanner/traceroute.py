"""LOCKON EWAC — Traceroute / Hop Analysis Module

Performs ICMP and TCP-based traceroute to map the network path to a target,
identifying routers, firewalls, and NAT boundaries along the way.
"""

import socket
import struct
import time
import threading
import platform
import subprocess
import re


_IPV4_LITERAL = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
# A latency the tool reported only as an upper bound, e.g. "<1 ms".
_SUB_MS = re.compile(r'<\s*\d+(?:\.\d+)?\s*ms')


class TracerouteEngine:
    # Shared wall-clock budget for reverse DNS across the whole path.
    RDNS_BUDGET_SECONDS = 3.0

    def __init__(self, emit_cb):
        self.emit = emit_cb
        # The running child, so stop() has something to kill. There was no
        # cancellation path at all: a trace is one blocking `subprocess.run`
        # whose timeout is derived from the caller's own parameters, so a long
        # one simply held its thread until it finished.
        self._proc = None
        self._proc_lock = threading.Lock()
        #: Set by `stop()`, so the reader can tell "the operator stopped this" from
        #: "the host did not answer". Without it, `communicate()` returned normally
        #: after the kill, `error` stayed None, and the event said `ok: True` --
        #: whereupon `_analyze_path` appended "The trace did not reach <ip> - the
        #: host may be filtered ... or down". A claim about somebody's network,
        #: manufactured out of a button press.
        self._stopped = False

    def stop(self):
        """
        Terminate a running trace, and record that it was a stop.

        Killing the child is the only way to stop this — the work happens
        inside `tracert`/`traceroute`, not in Python — and the reader below
        treats a killed process as a trace that ended, so it still emits a
        terminal event rather than leaving the UI waiting.
        """
        with self._proc_lock:
            proc = self._proc
            self._stopped = True
        if proc is None:
            return
        try:
            proc.terminate()
        except Exception:
            pass

    def run_traceroute(self, target_ip, max_hops=30, timeout=2):
        """Execute traceroute and emit results per-hop via IPC.

        Uses the OS-native traceroute/tracert command for reliability
        across Windows and Linux without raw-socket privileges.
        """
        self.emit("traceroute_started", {
            "target": target_ip,
            "max_hops": max_hops,
            "message": f"Tracing route to {target_ip}..."
        })

        hops = []
        error = None
        returncode = None
        stderr_text = ""

        # The address the hops will be compared against.
        #
        # `is_target` used to compare a hop's dotted quad to the caller's
        # `target_ip` verbatim. Handed a hostname, that comparison can never be
        # true, so every trace to a name reported "target was not reached" — a
        # claim about the network produced by a string mismatch. None means the
        # address is unknown, and the analysis then declines to rule either way
        # rather than defaulting to the alarming answer.
        target_addr = target_ip if _IPV4_LITERAL.match(str(target_ip or "")) else None
        if target_addr is None:
            try:
                target_addr = socket.gethostbyname(str(target_ip))
            except OSError:
                target_addr = None

        try:
            if platform.system().lower() == "windows":
                cmd = ["tracert", "-d", "-w", str(timeout * 1000), "-h", str(max_hops), target_ip]
                kwargs = {"creationflags": 0x08000000}
            else:
                cmd = ["traceroute", "-n", "-w", str(timeout), "-m", str(max_hops), target_ip]
                kwargs = {}

            # Popen rather than run(), so stop() has a handle to terminate.
            #
            # `encoding`/`errors` are explicit: the default decodes the
            # console's bytes as the ANSI codepage strictly, and one byte
            # outside it raises UnicodeDecodeError from inside the call — which
            # the caller would report as a failed trace rather than as a
            # decoding problem.
            # Cleared *before* the spawn, so a stop arriving while the child is
            # starting is not wiped by this run's own bookkeeping. Clearing it after
            # the Popen left a window in which `stop()` was silently lost, and the
            # trace then reported `ok: True` with the analysis claiming the host was
            # filtered or down.
            with self._proc_lock:
                self._stopped = False

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
                **kwargs
            )
            # `self._proc` was a single shared slot written straight from here and
            # nulled in the `finally`, so two concurrent traces made each other
            # unkillable: the second overwrote the slot, then the first's cleanup
            # emptied it. The local handle is what this call waits on; the slot is
            # only what `stop()` reaches for.
            with self._proc_lock:
                self._proc = proc
                stopped_during_spawn = self._stopped
            if stopped_during_spawn:
                # The operator stopped it between the reset and here; `stop()` had no
                # child to terminate at that moment, so this run does it.
                try:
                    proc.terminate()
                except Exception:
                    pass
            try:
                stdout, stderr_text = proc.communicate(
                    timeout=max_hops * (timeout + 1) + 10
                )
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                # Do not leave the child running after giving up on it.
                try:
                    proc.kill()
                    stdout, stderr_text = proc.communicate(timeout=5)
                except Exception:
                    stdout, stderr_text = "", ""
                raise
            finally:
                with self._proc_lock:
                    if self._proc is proc:
                        self._proc = None

            # A stop, or a non-zero exit, is not a trace that reached a conclusion.
            #
            # `returncode` was read nowhere in this file and stderr went to a
            # discard name, so neither could reach `error` -- and `stop()` made
            # `communicate()` return normally, leaving `error` None and the event
            # saying `ok: True`. `_analyze_path` then appended "The trace did not
            # reach <ip> - the host may be filtered, behind a device that does not
            # forward the probes, or down", which is a statement about the network
            # produced by the operator pressing Stop. The "reached hop N; the target
            # was not among them" finding fired for the same reason.
            if self._stopped:
                error = "Traceroute stopped by the operator"
            elif returncode not in (0, None):
                detail = (stderr_text or "").strip().splitlines()
                error = (f"tracert exited with code {returncode}"
                         + (f": {detail[0][:160]}" if detail else ""))

            # Parsed either way: the hops it did reach were measured, and discarding
            # them turns a partial trace into no trace at all. `error` is what stops
            # the analysis making a claim about the ones it never got to.
            self._parse_output(stdout, target_addr, hops)

        except subprocess.TimeoutExpired:
            error = "Traceroute timed out"
            # The child was killed above and whatever it had already printed is
            # in `stdout`. Parse it: the hops it did reach were measured, and
            # discarding them turned a partial trace into no trace at all.
            self._parse_output(stdout, target_addr, hops)
        except FileNotFoundError:
            error = "traceroute/tracert command not found"
        except Exception as e:
            error = f"Traceroute error: {str(e)[:200]}"

        if error:
            self.emit("traceroute_error", {"target": target_ip, "message": error})

        analysis = self._analyze_path(hops, target_addr, error=error)

        self.emit("traceroute_completed", {
            "target": target_ip,
            "target_address": target_addr,
            "hops": hops,
            "total_hops": len(hops),
            "analysis": analysis,
            # Whether the trace itself ran to a conclusion.
            #
            # This event used to be emitted unconditionally, *after* an error
            # event, with an empty hop list and an analysis that read "target was
            # not reached". The frontend's error handler resets to IDLE and its
            # completion handler sets DONE, so the completion won. A trace that
            # never ran therefore looked identical to a trace that ran and found
            # the target unreachable — one is a statement about the network, the
            # other is a statement about the tool.
            "ok": error is None,
            "error": error,
        })

        return hops

    def _parse_output(self, stdout, target_addr, hops):
        """Parse tracert/traceroute stdout into `hops`, emitting each one."""
        lines = (stdout or "").strip().split("\n")

        # Reverse DNS is a blocking lookup per hop and a dead resolver can cost
        # seconds each, so the whole path shares one budget. Past it, hops keep
        # their address and simply carry no name — the comment here used to
        # claim the lookup was non-blocking, which it never was.
        rdns_deadline = time.monotonic() + self.RDNS_BUDGET_SECONDS

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Hop lines, with `-d`/`-n` so no names appear:
            #   Windows: "  1    <1 ms    <1 ms    <1 ms  192.168.31.1"
            #   Linux:   "  1  0.456 ms  0.389 ms  0.312 ms  192.168.31.1"
            #   Either:  "  5     *        *        *     Request timed out."
            hop_match = re.match(r'^\s*(\d+)\s', line)
            if not hop_match:
                continue

            hop_num = int(hop_match.group(1))

            ip_match = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
            hop_ip = ip_match[-1] if ip_match else None

            # "<1 ms" is the tool declining to give a figure: the true value is
            # somewhere in [0, 1). It was recorded as 0.5 ms — a number no
            # measurement produced — and the naive `(\d+)\s*ms` pattern also
            # matched the "1 ms" *inside* "<1 ms", so the average came out as a
            # confident 1.0. Both are inventions, so the bound is stripped out
            # before any figure is read and recorded as a flag instead.
            is_sub_ms = bool(_SUB_MS.search(line))
            rtt_values = re.findall(r'(\d+(?:\.\d+)?)\s*ms', _SUB_MS.sub(' ', line))
            rtts = [float(r) for r in rtt_values] if rtt_values else []

            is_timeout = "*" in line and not hop_ip

            hostname = None
            if hop_ip and time.monotonic() < rdns_deadline:
                try:
                    hostname, _, _ = socket.gethostbyaddr(hop_ip)
                except (socket.herror, socket.gaierror, OSError):
                    pass

            hop_data = {
                "hop": hop_num,
                "ip": hop_ip,
                "hostname": hostname,
                "rtt_ms": rtts,
                "avg_rtt": round(sum(rtts) / len(rtts), 2) if rtts else None,
                # Set when the tool reported "<1 ms" and gave no figure. A
                # reader can print "< 1 ms"; nothing can print an average.
                "rtt_below_1ms": is_sub_ms and not rtts,
                "timeout": is_timeout,
                # False when the target address is unknown, which is not the
                # same as "this hop is not the target" — see `_analyze_path`,
                # which refuses to rule on reachability in that case.
                "is_target": bool(hop_ip) and target_addr is not None and hop_ip == target_addr,
            }

            hops.append(hop_data)
            self.emit("traceroute_hop", hop_data)

            if hop_data["is_target"]:
                break

    def _analyze_path(self, hops, target_addr, error=None):
        """Observations about the path. Context for a report, not findings.

        Every statement here has to survive a reader asking "how do you know
        that?", so a measurement that did not happen produces no claim.
        """
        findings = []
        valid_hops = [h for h in hops if h.get("ip")]

        # A trace that did not run says nothing about the network, and the one
        # thing this must not do is let that read as a routing observation.
        if error:
            findings.append({
                "type": "error",
                "message": f"The trace did not complete: {error}. "
                           "Nothing below describes the path to this host.",
            })
            if not hops:
                return findings

        # 1. Distance.
        #
        # This counted answering hops and called the result the distance to the
        # target, so a path with two filtered routers in the middle reported the
        # target two hops closer than it is. The distance is the hop number the
        # target answered at; without that, the honest statement is how far the
        # trace got.
        target_hop = next((h for h in hops if h.get("is_target")), None)
        if target_hop is not None:
            silent = sum(1 for h in hops if not h.get("ip"))
            findings.append({
                "type": "info",
                "message": f"Target answered at hop {target_hop['hop']}"
                           + (f" ({silent} hop(s) along the way did not answer)" if silent else ""),
            })
        elif valid_hops:
            findings.append({
                "type": "info",
                "message": f"The trace reached hop {max(h['hop'] for h in hops)}; "
                           f"{len(valid_hops)} hop(s) answered. The target was not among them.",
            })

        # 2. Detect firewall / filtering (consecutive timeouts)
        consecutive_timeouts = 0
        for h in hops:
            if h.get("timeout"):
                consecutive_timeouts += 1
                if consecutive_timeouts >= 3:
                    findings.append({
                        "type": "firewall",
                        "message": f"Possible firewall/filter detected at hop {h['hop'] - 2}+"
                    })
                    break
            else:
                consecutive_timeouts = 0

        # 3. Private-to-public transition.
        #
        # Reported once, for the first crossing. It fired per crossing before,
        # and a path that transits a carrier's own 10.0.0.0/8 crosses back and
        # forth — producing several "NAT boundary detected" lines for one
        # boundary. Reported as "leaves private address space", because that is
        # what was observed; NAT is the usual reason but it is an inference.
        prev_was_private = None
        for h in valid_hops:
            is_private = self._is_private(h["ip"])
            if prev_was_private and not is_private:
                findings.append({
                    "type": "nat",
                    "message": f"The path leaves private address space at hop {h['hop']} "
                               f"({h['ip']}) — typically a NAT or perimeter boundary",
                })
                break
            prev_was_private = is_private

        # 4. Latency spikes.
        #
        # Compared against the previous *answering* hop, and only when both
        # actually produced a figure. A hop that reported "<1 ms" has no
        # average, and treating its absent value as 0 made the next hop's
        # comparison meaningless.
        prev_rtt = None
        for h in valid_hops:
            rtt = h.get("avg_rtt")
            if isinstance(rtt, (int, float)) and prev_rtt is not None and rtt > prev_rtt * 3 and rtt > 50:
                findings.append({
                    "type": "latency",
                    "message": f"Latency rises sharply at hop {h['hop']} ({rtt} ms, "
                               f"up from {prev_rtt} ms) — congestion or a long physical leg",
                })
            if isinstance(rtt, (int, float)):
                prev_rtt = rtt

        # 5. Reachability.
        #
        # Three states, not two. "Not reached" is a statement about the network
        # and needs a known target address to stand on; without one the trace
        # cannot tell whether any hop was the target, and saying "not reached"
        # would be a guess dressed as a measurement.
        if target_addr is None:
            findings.append({
                "type": "warning",
                "message": "The target's address could not be determined, so this trace "
                           "cannot say whether the target was reached.",
            })
        elif not any(h.get("is_target") for h in hops):
            findings.append({
                "type": "warning",
                "message": f"The trace did not reach {target_addr} — the host may be filtered, "
                           "behind a device that does not forward the probes, or down.",
            })

        return findings

    @staticmethod
    def _is_private(ip):
        """RFC 1918 address test, on a dotted quad that came from the parser."""
        try:
            octets = [int(o) for o in ip.split(".")]
        except (ValueError, AttributeError):
            return False
        if len(octets) != 4:
            return False
        a, b = octets[0], octets[1]
        return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)

    def start_traceroute(self, target_ip, max_hops=30, timeout=2):
        """Run traceroute in a background thread."""
        t = threading.Thread(
            target=self.run_traceroute,
            args=(target_ip, max_hops, timeout),
            daemon=True
        )
        t.start()
