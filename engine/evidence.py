"""LOCKON EWAC — Evidence file registry

Captures used to be written into whatever directory the sidecar happened to be
running from, named `handshake_<bssid>_<epoch>.pcap`, with no digest and no
record anywhere. The file that backs a "handshake captured" claim in the report
was therefore an unreferenced loose file that nobody could tie to the finding,
and that nobody could show was unaltered.

This module gives every artifact three things it needs to function as evidence:

  1. **A known home.** One evidence directory per install, beside the logs, so
     artifacts are findable months later instead of scattered across whatever
     CWD the app was launched with.
  2. **A digest.** SHA-256 computed at the moment of writing, before anything
     else touches the file. A report can then cite the hash, and the holder of
     the file can verify it still matches.
  3. **A record.** The engine emits `evidence_recorded`, the app writes it to
     the `evidence_files` table, and the finding can reference the artifact by
     id rather than by a filename that may have moved.

The engine deliberately does not write to SQLite — the Tauri SQL plugin is the
single writer — so registration is an emitted event, the same pattern used for
the audit trail.
"""
import hashlib
import os
import sys
from datetime import datetime, timezone


def evidence_dir() -> str:
    """Where artifacts live. Mirrors the log directory convention."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "LOCKON-EWAC", "evidence")
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support",
                            "LOCKON-EWAC", "evidence")
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "LOCKON-EWAC", "evidence")


def ensure_dir() -> str:
    path = evidence_dir()
    os.makedirs(path, exist_ok=True)
    return path


def sha256_file(path: str) -> str:
    """Digest of a file, streamed so a large capture does not load into memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(value: str) -> str:
    """Filename-safe fragment, so a BSSID or SSID cannot escape the directory."""
    cleaned = "".join(c if (c.isalnum() or c in "-_") else "-" for c in str(value or ""))
    return cleaned[:60] or "unknown"


def build_path(prefix: str, identifier: str, extension: str) -> str:
    """Full path for a new artifact, inside the evidence directory.

    Timestamp is UTC and sortable, so artifacts from one operation group together
    when the directory is listed.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"{safe_name(prefix)}_{safe_name(identifier)}_{stamp}{extension}"
    return os.path.join(ensure_dir(), name)


def register(path: str, kind: str, emit=None, **context) -> dict:
    """Hash an artifact and announce it for the evidence registry.

    `kind` is what the artifact is ("handshake_pcap", "pmkid_hc22000", ...).
    `context` carries whatever ties it to a finding: bssid, ssid, session_id,
    mission_id. Returns the record; emits `evidence_recorded` when given an emit.

    Never raises: failing to register must not lose a capture that succeeded.
    The record then carries the error so the gap is visible rather than silent.
    """
    record = {
        "path": os.path.abspath(path),
        "filename": os.path.basename(path),
        "kind": kind,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "sha256": None,
        "size_bytes": None,
        "error": None,
    }
    record.update({k: v for k, v in context.items() if v is not None})

    try:
        record["size_bytes"] = os.path.getsize(path)
        record["sha256"] = sha256_file(path)
    except Exception as e:
        record["error"] = f"Could not hash artifact: {e}"

    if emit:
        try:
            emit("evidence_recorded", record)
        except Exception:
            pass
    return record


def verify(path: str, expected_sha256: str) -> dict:
    """Re-hash an artifact and compare. Used to show a file is unaltered."""
    result = {"path": path, "expected": expected_sha256, "actual": None,
              "exists": os.path.exists(path), "matches": False, "error": None}
    if not result["exists"]:
        result["error"] = "File is missing from the evidence directory."
        return result
    try:
        result["actual"] = sha256_file(path)
        result["matches"] = (result["actual"].lower() == (expected_sha256 or "").lower())
    except Exception as e:
        result["error"] = str(e)
    return result
