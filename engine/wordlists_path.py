"""LOCKON EWAC — Canonical wordlist path resolution.

Single source of truth for locating the bundled `wordlists/` directory across the
three ways this engine gets executed:

  1. Plain source run (dev / `python -m engine.main`)  -> <engine>/wordlists
  2. Frozen sidecar shipped next to the installed app  -> <exe_dir>/wordlists
  3. Frozen sidecar run from a Tauri dev target dir    -> <src-tauri>/binaries/wordlists
     (`src-tauri/target/{debug,release}/ewac-engine.exe` has no sibling
     `wordlists/`, the files live in `src-tauri/binaries/wordlists/`)

Every module that opens a wordlist must go through here so the UI's wordlist
picker and the attack modules can never disagree about where the files are.
"""
import os
import sys

_WORDLIST_SUBDIR = "wordlists"


def _frozen_candidates():
    """Candidate wordlist directories for a frozen (PyInstaller) build."""
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    candidates = [os.path.join(exe_dir, _WORDLIST_SUBDIR)]

    # Tauri dev/release sidecar: <src-tauri>/target/<profile>/engine.exe
    # -> <src-tauri>/binaries/wordlists
    parent_dir = os.path.dirname(os.path.dirname(exe_dir))
    candidates.append(os.path.join(parent_dir, "binaries", _WORDLIST_SUBDIR))

    # PyInstaller one-file extraction dir (datas bundled into the exe)
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        candidates.append(os.path.join(meipass, _WORDLIST_SUBDIR))

    return candidates


def get_wordlists_dir():
    """Return the absolute path of the *bundled* wordlists directory.

    The first existing candidate wins. If none exist the primary candidate is
    returned anyway, so callers still get a usable path to create or to report
    in an error message.

    This is the directory that ships with the build, and on an installed copy it
    is under %ProgramFiles% — readable by everyone, writable by nobody without
    elevation. Uploads go to `writable_wordlists_dir()` instead; see its comment.
    """
    if getattr(sys, 'frozen', False):
        candidates = _frozen_candidates()
    else:
        # This file lives in <engine>/, so the wordlists dir is a direct sibling.
        candidates = [os.path.join(os.path.dirname(os.path.abspath(__file__)), _WORDLIST_SUBDIR)]

    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return candidates[0]


def writable_wordlists_dir():
    """Where a list uploaded through the UI is stored: a per-user directory.

    The bundled directory is not usable for this. `lockon-ewac.iss` installs to
    `{autopf}` while its own comment says the wordlists directory "has to stay
    writable by whoever runs the app" — under %ProgramFiles% it is not, so
    `upload_wordlist` failed for any operator not running elevated. It failed
    honestly, emitting `wordlist_error`, but the feature simply did not work on
    an installed copy.

    So writes go beside the logs and the CVE snapshot, which already resolve a
    per-user directory for exactly this reason (`logging_setup.log_dir()`,
    `cve_feed._data_dir()`). Reads still see both — see `wordlist_dirs()`.

    Windows:  %LOCALAPPDATA%\\LOCKON-EWAC\\wordlists
    Linux:    $XDG_DATA_HOME/LOCKON-EWAC/wordlists
    macOS:    ~/Library/Application Support/LOCKON-EWAC/wordlists
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "LOCKON-EWAC", _WORDLIST_SUBDIR)
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library",
                            "Application Support", "LOCKON-EWAC", _WORDLIST_SUBDIR)
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "LOCKON-EWAC", _WORDLIST_SUBDIR)


def wordlist_dirs():
    """Every directory a wordlist may be read from, in precedence order.

    The user directory comes first, so a list an operator uploaded under a
    bundled name replaces it rather than being shadowed by it — uploading a file
    is an instruction, and silently preferring the shipped copy would ignore it.
    """
    return [writable_wordlists_dir(), get_wordlists_dir()]


def list_wordlists():
    """Every readable `.txt` wordlist, newest location winning on a name clash.

    Each entry carries `origin` so the UI can say which lists came with the build
    and which the operator added — and so `delete_wordlist` can refuse a bundled
    one instead of failing on a permission error.
    """
    seen = {}
    for origin, directory in (("user", writable_wordlists_dir()),
                              ("bundled", get_wordlists_dir())):
        if not os.path.isdir(directory):
            continue
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            if not name.endswith(".txt") or name in seen:
                continue
            path = os.path.join(directory, name)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            seen[name] = {"name": name, "size": size,
                          "origin": origin, "path": path}
    return [seen[n] for n in sorted(seen)]


def resolve_wordlist(name):
    """Resolve a wordlist file name to an absolute path inside the wordlists dir.

    Only a bare file name is honoured: any directory component is stripped with
    os.path.basename so a caller (or the UI) cannot escape the wordlists
    directory with "../" or an absolute path.

    Returns None if `name` is empty or resolves to nothing usable.
    """
    if not name:
        return None
    safe_name = os.path.basename(str(name).strip().replace('\\', '/').rstrip('/'))
    if not safe_name or safe_name in ('.', '..'):
        return None

    # An uploaded list and a bundled one can share a name; the first existing
    # match in `wordlist_dirs()` order decides, so an upload takes effect.
    for directory in wordlist_dirs():
        candidate = os.path.join(directory, safe_name)
        if os.path.isfile(candidate):
            return candidate

    # Nothing exists under that name. Return the bundled path so the caller's
    # "wordlist not found at ..." message names the directory an operator is most
    # likely looking at, which is what it did before there were two of them.
    return os.path.join(get_wordlists_dir(), safe_name)
