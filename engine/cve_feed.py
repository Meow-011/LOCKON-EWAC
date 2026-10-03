"""LOCKON EWAC — CVE snapshot management

Design note, because the obvious approach is wrong for this tool.

An always-on scanner can stream a live vulnerability feed. This is a wardriving
rig: it is offline in the field, opened occasionally, and its output is a report
someone acts on months later. Chasing "always fresh" would mean the tool is
silently stale whenever the update failed, which is worse than being stale on
purpose.

So the contract here is:
  - A snapshot always ships with the build. The tool is never empty and works
    fully offline on day one.
  - The snapshot carries the date it was generated, and that date is surfaced in
    the UI and stamped into the exported report. A reader can then judge the
    findings for themselves instead of assuming currency.
  - Updates happen when the operator asks for them, with a network, before going
    out — not on a timer that will fire at the wrong moment.
  - A stale snapshot warns loudly but never blocks: a 6-month-old CVE list still
    finds 6-month-old holes.

What this file does NOT claim: the bundled snapshot is a small curated set keyed
to the services the scanner fingerprints. It is not a complete view of NVD, and
`describe()` says so, so the report cannot imply coverage the tool does not have.
"""
import json
import os
import sys
from datetime import datetime, timezone

# Snapshot older than this is called out as stale in the UI and the report.
STALE_AFTER_DAYS = 30

# Products an update pulls *in addition* to everything the seed already covers.
#
# This list used to be the whole set, under a comment claiming it was "keyed to
# the top-level keys of CVE_MATRIX". It was not: `openssl` and `iis` were missing
# from it, so a refresh could not cover Heartbleed or the IIS WebDAV RCEs even in
# principle. The seed's own keys are now always included — see tracked_products().
_UPDATE_EXTRA_PRODUCTS = [
    "dropbear", "exim", "lighttpd", "mongodb", "postfix", "postgresql",
]


def tracked_products():
    """Every product an update asks NVD about, the seed's own keys included.

    Derived rather than written down, so a product added to the seed cannot be
    left out of updates — which is how `openssl` came to be un-updatable while
    the seed carried two OpenSSL CVEs.

    The import is lazy because `cve_db` imports this module, and the seed is
    optional here: a feed that cannot read it still pulls the extra products
    rather than failing.
    """
    try:
        from scanner.cve_db import CVE_MATRIX
        seed = set(CVE_MATRIX)
    except Exception:
        seed = set()
    return sorted(seed | set(_UPDATE_EXTRA_PRODUCTS))

_snapshot_cache = None


def _data_dir() -> str:
    """Where a downloaded snapshot lives: a per-user, writable directory.

    It deliberately does not sit beside the executable, which is where this used
    to put it. An installed copy lives under %ProgramFiles%, so `save_snapshot`
    could not create the file without elevation — the operator-initiated refresh
    this whole module exists to serve failed on exactly the machines where it
    matters, and the only sign of it was a `cve_update_error` the operator had to
    read. `logging_setup.log_dir()` already resolves a per-user directory for the
    same reason; this mirrors it, so logs and data sit side by side.

    Only the *update* layer is per-user. The seed in `cve_db.CVE_MATRIX` ships
    with the build, so the tool is still never empty and still works offline on
    day one, which is the contract in this module's docstring.

    Windows:  %LOCALAPPDATA%\\LOCKON-EWAC\\data
    Linux:    $XDG_DATA_HOME/LOCKON-EWAC/data
    macOS:    ~/Library/Application Support/LOCKON-EWAC/data
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "LOCKON-EWAC", "data")
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library",
                            "Application Support", "LOCKON-EWAC", "data")
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "LOCKON-EWAC", "data")


def snapshot_path() -> str:
    return os.path.join(_data_dir(), "cve_snapshot.json")


def load_snapshot(force: bool = False):
    """Return the on-disk snapshot, or None when only the built-in seed exists.

    Never raises: a corrupt snapshot degrades to the built-in seed rather than
    taking the engine down at import time.
    """
    global _snapshot_cache
    if _snapshot_cache is not None and not force:
        return _snapshot_cache

    path = snapshot_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data.get("matrix"), dict):
            return None
        _snapshot_cache = data
        return data
    except Exception:
        return None


def _age_days(generated_at: str):
    if not generated_at:
        return None
    try:
        ts = datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - ts).days)


def describe(seed_entry_count: int = 0, seed_generated_at: str = None) -> dict:
    """Provenance of the CVE data currently in use.

    This is what gets stamped into the PDF, so it states the limits of the data
    as plainly as its contents.
    """
    snap = load_snapshot()
    if snap:
        generated_at = snap.get("generated_at")
        source = snap.get("source", "NVD")
        entries = int(snap.get("entry_count") or 0)
        products = len(snap.get("matrix") or {})
        origin = "snapshot"
    else:
        generated_at = seed_generated_at
        source = "Built-in seed list (hand-curated)"
        entries = seed_entry_count
        products = len(tracked_products())
        origin = "builtin"

    age = _age_days(generated_at)

    # What the pull could not establish, carried through to the report. A product
    # the update failed to retrieve must not read as a product with nothing
    # against it — that is the one way this data can mislead while looking fresh.
    empty = list((snap or {}).get("empty_products") or [])
    truncated = list((snap or {}).get("truncated_cpes") or [])
    unmapped = list((snap or {}).get("unmapped_products") or [])

    note = ("Curated subset covering the services this scanner fingerprints. "
            "Absence of a CVE here is not evidence that a host is unaffected.")
    if empty or unmapped:
        names = sorted(set(empty) | set(unmapped))
        note += (" This snapshot carries no entries for " + ", ".join(names)
                 + "; those services were not covered by the update and findings "
                   "for them rest on the built-in seed alone.")
    if truncated:
        note += (" The result set was capped for " + ", ".join(sorted(set(truncated)))
                 + ", so coverage of those is partial.")

    return {
        "origin": origin,
        "source": source,
        "generated_at": generated_at,
        "age_days": age,
        "stale": (age is None or age > STALE_AFTER_DAYS),
        "entry_count": entries,
        "product_count": products,
        "tracked_products": tracked_products(),
        "stale_after_days": STALE_AFTER_DAYS,
        "empty_products": empty,
        "truncated_cpes": truncated,
        "unmapped_products": unmapped,
        "coverage_note": note,
    }


def save_snapshot(matrix: dict, source: str, empty_products=None,
                  truncated_cpes=None, unmapped_products=None) -> dict:
    """Persist a freshly fetched matrix and return its new description.

    The three optional lists are what the pull could *not* establish, and they
    are stored rather than logged because they belong in the report: a product
    that came back empty is indistinguishable, in the matrix alone, from one with
    nothing known against it, and that is the difference between "we looked and
    found nothing" and "we never managed to look".
    """
    global _snapshot_cache
    os.makedirs(_data_dir(), exist_ok=True)
    entry_count = sum(len(v) for versions in matrix.values() for v in versions.values())
    payload = {
        "schema": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "entry_count": entry_count,
        "product_count": len(matrix),
        "empty_products": sorted(empty_products or []),
        "truncated_cpes": sorted(truncated_cpes or []),
        "unmapped_products": sorted(unmapped_products or []),
        "matrix": matrix,
    }
    tmp = snapshot_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    os.replace(tmp, snapshot_path())  # atomic, so a failed write cannot corrupt the live file
    _snapshot_cache = payload
    return describe()


# ── Pulling a snapshot from NVD ───────────────────────────────────────────────
#
# The first version of this asked NVD for `keywordSearch=<product>` — a free-text
# search over every CVE — and then filed the version literals out of each result's
# CPE configurations under that product name. It did not check that the CPE it was
# reading described the product being asked about, and it ignored version ranges
# entirely. The data it produced was not merely incomplete, it was wrong:
#
#     apache 2.4.6  -> CVE-2004-0700  "mod_ssl before 2.8.19"
#     apache 2.4.29 -> CVE-2004-0492  "mod_proxy in Apache 1.3.25 to 1.3.31"
#     apache 2.2.22 -> seven CVEs, every one keyed to a 1.3.x or 2.0.x release
#
# The `apache` table came back with 440 version keys including `9.0.2`, `9.2` and
# `9.1.0_r85` — Apache httpd has no 9.x — and `CVE-2004-0490`, a cPanel flaw,
# filed under `apache`. Apache 2.4.6 is the stock RHEL/CentOS 7 build, so this
# was not an edge case: it put a false HIGH at LIKELY confidence, captioned
# "matched from the service banner", into an ordinary report. By this project's
# own standard one false assertion like that discards every other number in the
# document, so the refresh was worse than no refresh at all.
#
# So the query is now by CPE, and every match is filtered to the vendor:product
# actually being asked about.

#: CPE 2.3 `vendor:product` names for each product this scanner fingerprints.
#:
#: Written out rather than guessed from the product key, because the two rarely
#: agree — OpenSSH is `openbsd:openssh`, vsftpd is `beasts:vsftpd` — and a guess
#: that misses returns an empty result, which is the failure mode that looks like
#: success. `fetch_from_nvd` reports any product that came back with nothing so a
#: wrong name here cannot pass as "no known vulnerabilities".
_CPE_PRODUCTS = {
    "apache": ["apache:http_server"],
    "nginx": ["nginx:nginx", "f5:nginx"],
    "openssh": ["openbsd:openssh"],
    "openssl": ["openssl:openssl"],
    "vsftpd": ["beasts:vsftpd"],
    "proftpd": ["proftpd:proftpd"],
    "samba": ["samba:samba"],
    "mysql": ["oracle:mysql"],
    "postgresql": ["postgresql:postgresql"],
    "redis": ["redis:redis", "redislabs:redis"],
    "mongodb": ["mongodb:mongodb"],
    "elasticsearch": ["elastic:elasticsearch", "elasticsearch:elasticsearch"],
    "tomcat": ["apache:tomcat"],
    "jenkins": ["jenkins:jenkins"],
    "phpmyadmin": ["phpmyadmin:phpmyadmin"],
    "microsoft-iis": ["microsoft:internet_information_services",
                      "microsoft:internet_information_server"],
    "iis": ["microsoft:internet_information_services",
            "microsoft:internet_information_server"],
    "dropbear": ["dropbear_ssh_project:dropbear_ssh", "matt_johnston:dropbear"],
    "lighttpd": ["lighttpd:lighttpd"],
    "exim": ["exim:exim"],
    "postfix": ["postfix:postfix"],
}

#: Pages of 200 results to take per CPE before giving up on the rest. A cap is
#: needed because NVD rate-limits anonymous callers to roughly five requests per
#: thirty seconds, so an uncapped pull over twenty products is an hour-long
#: operation. Whatever it leaves behind is named in the snapshot rather than
#: quietly dropped — see `truncated` in `fetch_from_nvd`.
_MAX_PAGES_PER_CPE = 5

_RESULTS_PER_PAGE = 200


def _cpe_parts(criteria):
    """`(vendor, product, version)` from a CPE 2.3 string, or None if it is not one."""
    parts = (criteria or "").split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return parts[3], parts[4], parts[5]


def _next_version_after(version):
    """The smallest version above `version`, for turning `<= X` into `< Y`.

    NVD states an upper bound either exclusively (`versionEndExcluding`) or
    inclusively (`versionEndIncluding`), while an entry's `fixed_in` is always
    exclusive — `_is_fixed` treats "at or past" as safe. Bumping the last numeric
    component converts the one into the other exactly, for the dotted-numeric
    versions these products use. Returns None when there is no numeric component
    to bump, in which case the caller keeps no upper bound rather than inventing
    one.
    """
    bits = (version or "").split(".")
    for i in range(len(bits) - 1, -1, -1):
        digits = ""
        for ch in bits[i]:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits:
            bits[i] = str(int(digits) + 1)
            return ".".join(bits[: i + 1])
    return None


def _line_key(version):
    """The matrix key naming the line `version` sits in: `2.4.52` -> `2.4`.

    A key stands for a line (`_version_match` matches `2.4` against `2.4.6`), so
    two components is the natural width: it is what `fixed_in` was designed to
    narrow, and it is how the hand-curated seed entries are keyed.
    """
    bits = [b for b in (version or "").split(".") if b]
    if not bits:
        return None
    return ".".join(bits[:2])


def _keys_for_match(version, match):
    """The `(key, fixed_in)` pairs one `cpeMatch` justifies.

    Three shapes, and the third is the one the old code got wrong by ignoring it:

      * a concrete version in the CPE (`...:http_server:2.4.49:...`) names that one
        release. It is returned with `exact=True`, because a key in this matrix is
        otherwise matched as a *line* by `cve_db._version_match` — so without the
        flag `2.0` claimed every 2.0.x host, including the patched 2.0.65;
      * a bare `*` with no bounds names the whole product, which cannot be pinned
        to a build. Skipped, because a finding nobody can check against a version
        is a finding that cannot be defended;
      * a range becomes the line of its lower bound plus a `fixed_in` from its
        upper bound, which is exactly what this matrix already expresses.

    Two limits worth stating because they are deliberate. A range spanning more
    than one line (`1.3.0` to `2.4.52`) is narrowed to the line of its lower
    bound, so older lines are missed — this matcher errs toward missing, and
    `coverage_note` already says absence is not evidence. And an *exclusive*
    lower bound (`> 2.4.0`) widens to its line, which includes the boundary
    release the range excludes; the overstatement is one release, and the matrix
    has no way to express a lower bound.
    """
    if version not in ("*", "-", ""):
        # Marked exact, because the matrix keys *lines*.
        #
        # This returned `(version, None)`, and a key in that matrix is matched as a
        # prefix by `cve_db._version_match` while `_is_fixed` treats an absent
        # `fixed_in` as "never fixed". So `...:http_server:2.0:*:*:*` became an
        # unbounded claim over the whole 2.0 line, and a host on 2.0.65 -- the final,
        # fully patched release of it -- was asserted vulnerable at NVD's severity.
        #
        # NVD carries many two- and one-component concrete versions, so this is the
        # ordinary case rather than a corner of the data.
        return [(version, None, True)]

    start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
    end_excluding = match.get("versionEndExcluding")
    end_including = match.get("versionEndIncluding")

    fixed_in = end_excluding
    if not fixed_in and end_including:
        fixed_in = _next_version_after(end_including)

    # A range with no lower bound — "everything before 1.21.0" — spans an unknown
    # number of lines, and this matrix keys lines. Anchoring on the upper bound
    # instead produced an entry that excluded its own line: nginx came back keyed
    # to `1.21` with `fixed_in: 1.21.0`, so every 1.21.x host was "already fixed"
    # and the key existed only to shadow others. Skipped, which errs toward
    # missing — the direction `coverage_note` already declares.
    if not start:
        return []

    key = _line_key(start)
    if not key:
        return []
    # Not exact: a range-derived key genuinely names a line, which is what the
    # matrix's prefix matching is for.
    return [(key, fixed_in, False)]


def _severity_of(cve):
    """The CVSS base severity NVD reports, preferring the newest metric present."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            sev = data.get("baseSeverity") or entries[0].get("baseSeverity")
            if sev:
                return str(sev).upper()
    return "UNKNOWN"


def entries_from_cve(item, cpe_products):
    """`(version_key, entry)` pairs this CVE justifies for one product.

    `cpe_products` is the set of `vendor:product` names the caller asked about,
    and every match is tested against it. That single check is what stops a
    cPanel or mod_ssl advisory being filed under `apache` because the words
    matched: NVD returns a CVE when *any* of its configurations matches, and the
    other configurations in it describe entirely different software.

    Pure, so it can be tested against recorded NVD payloads without a network.
    """
    cve = item.get("cve") or item
    cve_id = cve.get("id")
    if not cve_id:
        return []

    descriptions = cve.get("descriptions") or []
    text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
    severity = _severity_of(cve)

    out = []
    seen = set()
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parsed = _cpe_parts(match.get("criteria"))
                if not parsed:
                    continue
                vendor, product, version = parsed
                if f"{vendor}:{product}".lower() not in cpe_products:
                    continue
                for key, fixed_in, exact in _keys_for_match(version, match):
                    # `exact` is part of the identity: the same key can arrive once
                    # as a concrete version and once as the lower bound of a range,
                    # and those are different claims about the same line.
                    if (key, fixed_in, exact) in seen:
                        continue
                    seen.add((key, fixed_in, exact))
                    entry = {
                        "cve": cve_id,
                        "severity": severity,
                        "description": (text[:300] if text
                                        else "No description supplied by NVD."),
                    }
                    if fixed_in:
                        entry["fixed_in"] = fixed_in
                    if exact:
                        # Read by `cve_db.lookup_cves`, which otherwise treats every
                        # key as a line and would extend this one over all of it.
                        entry["exact_version"] = True
                    out.append((key, entry))
    return out


def fetch_from_nvd(emit=None, api_key: str = None, products=None) -> dict:
    """Pull a fresh snapshot from NVD for the tracked products.

    Operator-initiated only — see the module docstring. Returns the new
    description on success and raises on failure, so the caller can report the
    reason rather than silently leaving the old data in place.

    Queries by CPE (`virtualMatchString`), not by keyword, and keeps only the
    matches whose vendor and product are the ones being asked about. See the
    comment above `_CPE_PRODUCTS` for what the keyword version did instead.

    NVD rate-limits anonymous callers to roughly five requests per thirty
    seconds, so this is deliberately slow and sequential rather than parallel.
    """
    import time
    import urllib.parse
    import urllib.request

    products = products or tracked_products()
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent": "LOCKON-EWAC/0.1"}
    if api_key:
        headers["apiKey"] = api_key
    pause = 1 if api_key else 6

    matrix = {}
    per_product = {}
    truncated = []
    unmapped = []
    total = len(products)
    requests_made = 0

    def _get(url):
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))

    for idx, product in enumerate(products, 1):
        if emit:
            emit("cve_update_progress", {
                "product": product, "current": idx, "total": total,
                "progress": int(idx / total * 100),
            })

        cpes = _CPE_PRODUCTS.get(product)
        if not cpes:
            # No CPE name for a tracked product: say so rather than returning an
            # empty table that reads as "nothing known about it".
            unmapped.append(product)
            continue
        wanted = {c.lower() for c in cpes}

        for cpe in cpes:
            page = 0
            while page < _MAX_PAGES_PER_CPE:
                params = urllib.parse.urlencode({
                    "virtualMatchString": f"cpe:2.3:a:{cpe}",
                    "resultsPerPage": _RESULTS_PER_PAGE,
                    "startIndex": page * _RESULTS_PER_PAGE,
                    "noRejected": "",
                })
                if requests_made:
                    time.sleep(pause)
                try:
                    data = _get(f"{base}?{params}")
                except Exception as e:
                    raise RuntimeError(f"NVD request failed for '{cpe}': {e}")
                requests_made += 1

                for item in data.get("vulnerabilities") or []:
                    for key, entry in entries_from_cve(item, wanted):
                        bucket = matrix.setdefault(product, {}).setdefault(key, [])
                        if not any(e["cve"] == entry["cve"] for e in bucket):
                            bucket.append(entry)
                            per_product[product] = per_product.get(product, 0) + 1

                total_results = int(data.get("totalResults") or 0)
                page += 1
                if page * _RESULTS_PER_PAGE >= total_results:
                    break
            else:
                truncated.append(cpe)

    if not matrix:
        raise RuntimeError(
            "NVD returned no version-pinned entries; keeping the existing snapshot.")

    empty = sorted(p for p in products if not per_product.get(p))
    return save_snapshot(
        matrix,
        source="NVD CVE API 2.0 (CPE-matched)",
        empty_products=empty,
        truncated_cpes=sorted(set(truncated)),
        unmapped_products=sorted(set(unmapped)),
    )
