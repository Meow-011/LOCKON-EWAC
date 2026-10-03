"""LOCKON EWAC Engine — Sidecar Entry Point"""
import sys
import json
import signal
import logging

# File logging first, before anything can fail. Until now the engine logged to
# stderr only, which Tauri swallows, so a failure in the field left no artifact
# behind and "it stopped working" was unanswerable. Third-party log levels are
# tuned inside logging_setup; stdout is never touched because it is the IPC
# channel and a stray line there is a protocol violation.
import logging_setup

# Before anything reads or writes the IPC pipes. Tauri sends UTF-8; Python would
# otherwise decode stdin with the Windows ANSI codepage and mangle every
# non-ASCII engagement name, operator and SSID on its way into the audit trail.
_stdio_failed = logging_setup.force_utf8_stdio()

_log_info = logging_setup.configure()
logger = logging.getLogger("ewac.main")

from ipc.handler import IPCHandler

# Again, after the imports. pywifi resets its own logger to NOTSET when its
# package __init__ runs, which makes it inherit the root level and flood the log
# with a beacon dump per scan cycle.
logging_setup.silence_noisy_loggers()


def main():
    handler = IPCHandler()
    logging_setup.install_excepthook(handler.emit)

    logger.info("Engine starting (log: %s)", _log_info.get("path"))
    if _stdio_failed:
        # Say so rather than let non-ASCII quietly corrupt later.
        logger.warning("Could not force UTF-8 on: %s. Non-ASCII text on "
                       "the IPC channel may be mangled.", ", ".join(_stdio_failed))

    # Graceful shutdown
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    # Send ready signal. The log path travels with it so the UI can point the
    # operator at the file without having to know the platform's conventions.
    # The build stamp travels with `ready`.
    #
    # `version` was a hardcoded "0.1.0" and nothing else, so a sidecar compiled
    # days earlier was indistinguishable from a fresh one — which is how a
    # decoding bug already fixed in the source went on being reported from the
    # field. `build` answers "is this the code I think it is?".
    import build_stamp
    stamp = build_stamp.describe()
    logger.info("Engine build: %s", stamp)
    handler.emit("ready", {
        "version": stamp["version"],
        "platform": sys.platform,
        "build": stamp,
        "log_path": _log_info.get("path"),
        "log_error": _log_info.get("error"),
    })

    # Main loop — read JSON commands from stdin
    for line in sys.stdin:
        try:
            message = json.loads(line.strip())
            handler.handle(message)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON on stdin: %s", line.strip()[:200])
            handler.emit("error", {"message": f"Invalid JSON: {line.strip()}"})
        except Exception as e:
            logger.exception("Command dispatch failed")
            handler.emit("error", {"message": str(e)})

    logger.info("stdin closed; engine exiting")


if __name__ == "__main__":
    main()
