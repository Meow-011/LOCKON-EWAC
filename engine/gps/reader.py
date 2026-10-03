"""LOCKON EWAC — GPS Reader Module (PySerial / NMEA)

Reads NMEA 0183 sentences from a USB GPS Receiver.
"""
import logging
import time
import serial
import serial.tools.list_ports
import pynmea2
from datetime import datetime

logger = logging.getLogger("ewac.gps")

#: How old a fix may be and still be used to place a sighting, in seconds.
#:
#: A consumer-grade receiver emits GGA and RMC roughly once a second, so
#: anything past a few seconds means the stream has stopped — the device was
#: unplugged, lost power, or the port died. `is_connected()` cannot see any of
#: that: it checks that the serial handle is open, which stays true after the
#: hardware goes away.
#:
#: Eight seconds is chosen to be past any plausible hiccup (a slow fix under
#: cover, a momentary buffer stall) while being far short of the distance a
#: moving vehicle covers. At 50 km/h eight seconds is about 110 m, which is the
#: most a coordinate can be wrong by before this refuses it — and refusing is
#: the right trade, because the alternative was stamping every access point for
#: the rest of the drive with the spot where the receiver died.
STALE_FIX_SECONDS = 8.0

def describe_serial_error(port: str, error: Exception) -> str:
    """Turn a serial exception into something an operator can act on.

    `PermissionError(13, 'Access is denied.')` on a COM port is the common one
    and the least informative: on Windows a serial port is exclusive, so it
    almost always means the port is already open — very often by this very
    application, because a scan is running and already holds the GPS.
    """
    text = str(error)
    lowered = text.lower()

    if "permission" in lowered or "access is denied" in lowered:
        return (
            f"{port} is already open by another program. A serial port can only be held by one "
            f"process at a time. Most often this is LOCKON itself: stop the active scan before "
            f"running a hardware test. Otherwise close any GPS or serial terminal application "
            f"(u-center, PuTTY, Arduino IDE) and retry."
        )
    if "could not be found" in lowered or "filenotfounderror" in lowered or "no such file" in lowered:
        return (
            f"{port} does not exist. The receiver may have been unplugged, or Windows may have "
            f"reassigned it to a different COM number - click SCAN PORTS to re-detect."
        )
    if "semaphore" in lowered or "timeout" in lowered:
        return f"{port} did not respond in time. Check the cable and that the receiver has power."
    return f"{port} could not be opened: {text}"


class GPSReader:
    """Reads GPS coordinates from a COM Port.
    
    Supports dynamic port configuration via UI.
    """

    def __init__(self):
        self.port = None
        self.baudrate = 9600
        self.running = False
        self.serial = None
        self.last_fix = None
        self.satellites = 0
        # Why the port could not be opened, if it could not. Previously the
        # exception was swallowed and `serial` was simply left as None, so a GPS
        # that failed to connect looked exactly like a GPS that had no fix yet —
        # the operator drove for an hour and got no track and no explanation.
        self.last_error = None

    @staticmethod
    def get_available_ports() -> list[dict]:
        """Returns a list of available serial ports with descriptions."""
        try:
            ports = serial.tools.list_ports.comports()
            return [{"device": p.device, "description": p.description} for p in ports]
        except Exception:
            return []

    def start(self, port: str = "COM3", baudrate: int = 9600):
        """Open the serial port. Returns (ok, message).

        The message is written for the operator, not for a log: "access denied"
        from the OS means almost nothing, while "another program is holding the
        port" tells them what to do about it.
        """
        self.port = port
        self.baudrate = baudrate
        self.running = True
        self.last_error = None

        try:
            self.serial = serial.Serial(self.port, self.baudrate, timeout=1)
            return True, f"Opened {port} at {baudrate} baud."
        except Exception as e:
            self.serial = None
            self.last_error = describe_serial_error(port, e)
            return False, self.last_error

    def stop(self):
        """Close the connection."""
        self.running = False
        if self.serial and self.serial.is_open:
            self.serial.close()
            self.serial = None

    def is_connected(self) -> bool:
        return self.serial is not None and self.serial.is_open

    def update(self):
        """Read a line from the serial port and parse NMEA.
        This should be called periodically in a background thread.
        """
        if not self.is_connected() or not self.running:
            return False

        try:
            line = self.serial.readline().decode('ascii', errors='ignore').strip()
            if not line:
                return False

            if line.startswith('$GPGGA') or line.startswith('$GNGGA'):
                msg = pynmea2.parse(line)
                # GGA carries its own verdict on whether it is usable, and this
                # never read it. `gps_qual` is 0 when the receiver has no fix. A
                # receiver in that state still emits GGA and still fills in a
                # latitude -- the last one it believed, or a partial solution --
                # and `latitude != 0.0` is true for all of it. So a cold start
                # was plotted as a position, and the operator saw the vehicle
                # sitting somewhere it had never been before the first real fix.
                # A fix the receiver does not stand behind is not a position.
                qual = int(getattr(msg, 'gps_qual', 0) or 0)
                if qual > 0 and msg.latitude != 0.0:
                    self.satellites = int(getattr(msg, 'num_sats', 0) or 0)
                    # HDOP = Horizontal Dilution of Precision (lower = better)
                    # <1 Ideal, 1-2 Excellent, 2-5 Good, 5-10 Moderate, >10 Poor
                    hdop = float(getattr(msg, 'horizontal_dil', 0) or 0)
                    if not self.last_fix:
                        self.last_fix = {}
                    self.last_fix.update({
                        "latitude": msg.latitude,
                        "longitude": msg.longitude,
                        "altitude": float(msg.altitude) if getattr(msg, 'altitude', None) else 0.0,
                        "satellites": self.satellites,
                        "hdop": hdop,
                        "fix_quality": qual,
                        # When the quality above was measured, so a consumer can
                        # tell whether it describes the position it is sitting
                        # next to. GGA and RMC both update this one dict, and only
                        # GGA carries quality -- so without this an HDOP read
                        # seconds ago travelled alongside a position from a later
                        # RMC as though it had been measured with it.
                        "quality_at": time.time(),
                        "position_from": "GGA",
                        "timestamp": datetime.now().isoformat()
                    })
                    return True
            elif line.startswith('$GPRMC') or line.startswith('$GNRMC'):
                msg = pynmea2.parse(line)
                # RMC says the same thing in one character, and it was ignored
                # too. `status` is 'A' for active and 'V' for void. A void
                # sentence is the receiver stating that what it contains is not
                # to be trusted, and it was being read as position, speed and
                # heading like any other -- which is also where a heading comes
                # from on a vehicle that has not moved.
                status = str(getattr(msg, 'status', '') or '').upper()
                if status == 'A' and msg.latitude != 0.0:
                    if not self.last_fix:
                        self.last_fix = {}
                    # RMC carries no HDOP, no satellite count and no fix quality.
                    #
                    # Those three keys are written only by the GGA branch above,
                    # and both branches `update()` the same dict, so an RMC-only
                    # receiver never set `hdop` at all. `handler.py` read it as
                    # `fix.get('hdop', 0)`, and 0 means "not reported, accept" --
                    # so the `hdop > 5.0` quality gate could never fire. A gate
                    # reading "ideal" for a quality that was never measured.
                    #
                    # `hdop` is therefore set to None rather than left absent:
                    # "this receiver does not report it" and "it was measured as
                    # excellent" are different statements, and the caller now
                    # distinguishes them. `quality_at` is left as the GGA set it,
                    # so a stale quality is visible as stale instead of being
                    # silently attributed to this position.
                    self.last_fix.setdefault("hdop", None)
                    self.last_fix.setdefault("fix_quality", None)
                    self.last_fix.setdefault("satellites", None)
                    self.last_fix.update({
                        "latitude": msg.latitude,
                        "longitude": msg.longitude,
                        "speed": float(msg.spd_over_grnd) if getattr(msg, 'spd_over_grnd', None) else 0.0,
                        "heading": float(msg.true_course) if getattr(msg, 'true_course', None) else 0.0,
                        "position_from": "RMC",
                        "timestamp": datetime.now().isoformat()
                    })
                    return True
        except Exception as e:
            logger.debug("GPS line could not be parsed: %s", e)

        return False

    def get_position(self) -> dict | None:
        """
        The latest fix, or None once it is too old to stamp anything with.

        This used to return `self.last_fix` unconditionally, and nothing ever
        aged it out. When a receiver was unplugged or lost power mid-drive,
        `is_connected()` kept returning True — it only checks that the serial
        handle is open, which survives the device going away — and every access
        point found for the rest of the drive was stamped with the coordinate
        where the GPS had stopped.

        The outlier filter could not catch it either: two identical positions
        imply zero movement, which is exactly what it is built to accept. So a
        dead receiver produced a map and a report placing an hour of findings on
        one spot, with a green GPS indicator the whole time.

        `timestamp` was already being recorded on every fix. It was simply never
        read.
        """
        fix = self.last_fix
        if not fix:
            return None
        if self.fix_age_seconds() > STALE_FIX_SECONDS:
            return None
        # A copy, not the live dict.
        #
        # This is read from the Wi-Fi scan thread while the GPS thread calls
        # `update()`, and the caller reads several keys from the result in
        # sequence. Handing back the live object let a latitude from before an
        # update be paired with a longitude from after it -- a coordinate that was
        # never measured anywhere, and one the outlier filter cannot catch because
        # it is a plausible point between two real ones.
        return dict(fix)

    def fix_age_seconds(self) -> float:
        """
        Seconds since the last fix, or infinity when there has never been one.

        A fix whose timestamp cannot be parsed is treated as infinitely old:
        failing toward "no position" costs a coordinate, while failing toward
        "position is current" writes a wrong one into the archive.
        """
        fix = self.last_fix
        if not fix:
            return float("inf")
        raw = fix.get("timestamp")
        if not raw:
            return float("inf")
        try:
            stamped = datetime.fromisoformat(str(raw))
        except (TypeError, ValueError):
            return float("inf")
        return max(0.0, (datetime.now() - stamped).total_seconds())

    def is_stale(self) -> bool:
        """True when a fix exists but is too old to attribute a sighting to."""
        return bool(self.last_fix) and self.fix_age_seconds() > STALE_FIX_SECONDS

    def has_fix(self) -> bool:
        """
        Whether a *usable* fix exists.

        Deliberately the same staleness test as `get_position()`: a caller that
        checks this and then reads the position must not be told yes and handed
        None, and a stale fix is not a fix.
        """
        return self.get_position() is not None
