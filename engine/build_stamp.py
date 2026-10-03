"""What this engine build actually is.

Why this exists.

The engine reported `version: "0.1.0"` in its `ready` event — a string literal
that has never changed and never will. So a sidecar compiled two days ago was
indistinguishable, from the UI and from the log, from one compiled a minute ago.

That cost a debugging session. A `UnicodeDecodeError: 'charmap' codec can't
decode byte 0x90` was appearing every half-minute in the field. Every
`subprocess` call in the source already passed `encoding="utf-8"`, the traceback
had no engine frames in it (the failure is inside `communicate()`'s own reader
thread), and the log gave no hint that the running binary predated the fix. The
code was right; the `.exe` was old, and nothing anywhere said so.

`git_describe` and `built_at` are written at build time by the PyInstaller spec.
Running from source they resolve live, which is the honest answer for a source
run. Neither is ever a guess: when the value cannot be established it is `None`
and the UI says "unknown", because an unknown build is a thing an operator needs
to be told rather than a blank to fill in.
"""
import os
import subprocess
import sys

#: Semantic version of the engine's IPC contract and behaviour. Bumped by hand.
VERSION = "1.0.0"

# Written into a generated module by the build. Absent on a source run.
try:  # pragma: no cover - only present in a frozen build
    from _build_info import BUILT_AT as _BUILT_AT, GIT_DESCRIBE as _GIT_DESCRIBE
except Exception:
    _BUILT_AT = None
    _GIT_DESCRIBE = None


def _git_describe_live():
    """The working tree's revision, for a source run. None if git cannot say."""
    try:
        out = subprocess.run(
            ["git", "describe", "--always", "--dirty", "--tags"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=5,
            **({"creationflags": 0x08000000} if sys.platform == "win32" else {}),
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return None


def _source_mtime():
    """Newest mtime across the engine's own .py files, as an ISO timestamp.

    For a source run this is the closest honest answer to "when was this code
    last changed", and it is what makes a stale *frozen* build visible by
    contrast: the UI shows the build stamp beside it.
    """
    root = os.path.dirname(os.path.abspath(__file__))
    newest = 0.0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".venv", "__pycache__", "tests", "build", "dist")]
        for name in filenames:
            if name.endswith(".py"):
                try:
                    newest = max(newest, os.path.getmtime(os.path.join(dirpath, name)))
                except OSError:
                    continue
    if newest == 0.0:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(newest, timezone.utc).isoformat(timespec="seconds")


def describe():
    """Everything needed to answer "is this the code I think it is?"."""
    frozen = bool(getattr(sys, "frozen", False))
    return {
        "version": VERSION,
        "frozen": frozen,
        # For a frozen build this is when the .exe was produced; for a source
        # run it is when the newest .py was last touched.
        "built_at": _BUILT_AT if frozen else _source_mtime(),
        "git_describe": _GIT_DESCRIBE if frozen else _git_describe_live(),
        "python": sys.version.split()[0],
        # Present only in a frozen build, and worth reporting: a stale one-file
        # extraction directory has caused its own class of confusion.
        "bundle_dir": getattr(sys, "_MEIPASS", None),
    }
