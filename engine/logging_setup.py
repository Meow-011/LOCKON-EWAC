"""LOCKON EWAC — Engine file logging

Until now the engine logged to stderr only. Tauri swallows the sidecar's stderr
into the dev console, so a failure in the field left nothing behind: the operator
came back with "it stopped working" and there was no artifact to look at.

Design points that matter for this particular tool:

  - Logs go to a fixed, discoverable directory next to the database, not the
    process CWD, so the operator can attach them to a bug report.
  - Rotating, size-capped files. A wardriving session emits a lot of lines and
    the rig may be running for hours on a laptop with little disk.
  - stdout is NEVER touched. stdout is the IPC channel to the app: a stray log
    line there is a protocol violation that would show up as a JSON parse error.
  - Log records carry the thread name. Almost everything in this engine runs on a
    worker thread, and "which scan was this" is the first question when reading
    a failure after the fact.
  - Secrets are not logged. Credential material is deliberately kept out; call
    sites log the target and the outcome, not the password that worked.
"""
import logging
import logging.handlers
import os
import sys

LOG_FILENAME = "ewac-engine.log"
MAX_BYTES = 2 * 1024 * 1024  # 2 MB per file
BACKUP_COUNT = 3             # ~8 MB total ceiling

_configured = False
_log_path = None

# Third-party loggers that would otherwise drown the file.
#
# pywifi is the reason this exists and the reason it has to be applied twice:
# it logs seven INFO lines for every BSS it sees, so one scan cycle in a dense
# area writes hundreds of lines and rolls the 2 MB log over within minutes,
# destroying the diagnostic record the file exists to keep. paramiko does the
# same during a brute-force run, logging a banner per connection attempt.
NOISY_LOGGERS = (
    "pywifi", "pywifi.iface",
    "comtypes", "comtypes.client",
    "paramiko", "paramiko.transport",
    "scapy", "scapy.runtime", "scapy.loading",
    "urllib3", "urllib3.connectionpool",
    "matplotlib", "PIL", "sklearn", "asyncio",
)


def silence_noisy_loggers(level=logging.WARNING):
    """Hold the third-party loggers down.

    Call this again after the modules have been imported. pywifi's package
    __init__ runs `set_loglevel()` with a default of NOTSET, which means "inherit
    from the root logger" — so importing it silently undoes whatever was set
    beforehand, and the engine log fills with beacon dumps.
    """
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(level)


def log_dir() -> str:
    """Where logs live. Mirrors the OS convention so it is findable.

    Windows:  %LOCALAPPDATA%\\LOCKON-EWAC\\logs
    Linux:    ~/.local/share/LOCKON-EWAC/logs
    macOS:    ~/Library/Logs/LOCKON-EWAC
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "LOCKON-EWAC", "logs")
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Logs", "LOCKON-EWAC")
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "LOCKON-EWAC", "logs")


def log_path() -> str:
    return os.path.join(log_dir(), LOG_FILENAME)


def configure(level=logging.INFO) -> dict:
    """Install the file handler. Safe to call more than once.

    Never raises: if the log directory cannot be created the engine still has to
    start, so this degrades to stderr-only and reports that in its return value.
    """
    global _configured, _log_path

    if _configured:
        return {"configured": True, "path": _log_path}

    root = logging.getLogger()
    root.setLevel(level)

    silence_noisy_loggers()

    # Route Python warnings through logging instead of letting them write
    # straight to stderr, so they are captured in the file with a timestamp and
    # a thread name like everything else.
    logging.captureWarnings(True)

    # Silence one specific, unactionable third-party deprecation: scapy's TLS
    # layer imports a Diffie-Hellman primitive that `cryptography` has
    # deprecated. It fires on every engine start, it is not our code, and there
    # is nothing to do about it until scapy changes — but it looks alarming in
    # the console next to real failures. Everything else still warns.
    try:
        import warnings
        warnings.filterwarnings(
            "ignore", category=DeprecationWarning, module=r"scapy\..*")
        try:
            from cryptography.utils import CryptographyDeprecationWarning
            warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
        except Exception:
            # Older/newer cryptography may not expose the class; match the text.
            warnings.filterwarnings("ignore", message=".*Diffie-Hellman.*deprecated.*")
    except Exception:
        pass

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-8s [%(threadName)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    result = {"configured": False, "path": None, "error": None}

    try:
        directory = log_dir()
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, LOG_FILENAME)
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
        )
        handler.setFormatter(formatter)
        handler.setLevel(level)
        root.addHandler(handler)
        _log_path = path
        result.update(configured=True, path=path)
    except Exception as e:
        result["error"] = str(e)

    # stderr as well, so `tauri dev` still shows problems live. Explicitly
    # stderr — stdout belongs to the IPC protocol.
    try:
        stream = logging.StreamHandler(stream=sys.stderr)
        stream.setFormatter(formatter)
        stream.setLevel(logging.WARNING)
        root.addHandler(stream)
    except Exception:
        pass

    _configured = True
    return result


def install_excepthook(emit=None):
    """Make sure an unhandled exception is written down somewhere.

    Worker threads in this engine are daemons; without this, a thread dying takes
    its traceback with it and the UI just sees the feature stop.
    """
    logger = logging.getLogger("ewac.unhandled")

    def _hook(exc_type, exc_value, exc_tb):
        logger.critical("Unhandled exception", exc_info=(exc_type, exc_value, exc_tb))
        if emit:
            try:
                emit("engine_error", {
                    "message": f"{exc_type.__name__}: {exc_value}",
                    "log_path": _log_path,
                })
            except Exception:
                pass

    sys.excepthook = _hook

    # threading.excepthook exists from 3.8; this engine already requires 3.10.
    try:
        import threading

        def _thread_hook(args):
            logger.critical(
                "Unhandled exception in thread %s", args.thread.name if args.thread else "?",
                exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
            )
            if emit:
                try:
                    emit("engine_error", {
                        "message": f"{args.exc_type.__name__}: {args.exc_value}",
                        "thread": args.thread.name if args.thread else None,
                        "log_path": _log_path,
                    })
                except Exception:
                    pass

        threading.excepthook = _thread_hook
    except Exception:
        pass


def tail(lines: int = 200) -> dict:
    """Read back the end of the log, so the UI can show it without file access."""
    path = _log_path or log_path()
    if not os.path.exists(path):
        return {"path": path, "exists": False, "lines": []}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.readlines()
        return {
            "path": path,
            "exists": True,
            "total_lines": len(content),
            "lines": [line.rstrip("\n") for line in content[-lines:]],
        }
    except Exception as e:
        return {"path": path, "exists": True, "error": str(e), "lines": []}


def force_utf8_stdio():
    """Make the IPC pipes UTF-8, whatever the OS codepage is.

    Tauri writes this process's stdin as UTF-8, but Python opens it with the
    Windows ANSI codepage — cp1252 on a Thai-locale machine's English build,
    cp874 elsewhere. Every non-ASCII character therefore arrived mangled: an
    em-dash in an engagement name came through as "a€"" and a Thai operator
    name became mojibake. Both of those strings go into the audit trail, which
    is the one record in this tool that has to be exact.

    `errors="replace"` rather than strict on purpose: a malformed byte should
    surface as a visible replacement character in one field, not kill the
    engine in the middle of an engagement.

    Returns the list of streams it could not reconfigure, so a caller can log
    the fact rather than assume it worked.
    """
    failed = []
    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            failed.append(name)
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            failed.append(name)
    return failed
