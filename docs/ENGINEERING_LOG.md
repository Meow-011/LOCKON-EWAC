# Engineering log

> **[← Back to the README](../README.md)** ·
> [Install](INSTALL.md) · [Architecture](ARCHITECTURE.md) · [Testing](TESTING.md) · [Troubleshooting](TROUBLESHOOTING.md) ·
> [Engineering log](ENGINEERING_LOG.md) · [Playbook](PLAYBOOK.md) · [AP location methods](AP_LOCATION_METHODS.md) · [GPS & survey](GPS_AND_SURVEY.md)


What has been built, what is deliberately not built, and what is known to be
missing. Carried openly because a tool whose job is producing evidence should
not overstate itself.

## Development roadmap

### Phase 2 (Completed)
- [x] Multi-Subnet Auto Discovery
- [x] TTL-Based OS Fingerprinting
- [x] Web Title Grabbing for device identification
- [x] Scan History Diff Detection (NEW TARGET badges)
- [x] Context-Aware CVE Vulnerability Matrix
- [x] MAC Address & Vendor Resolution (with LA-bit stripping)
- [x] ARP-Based False Positive Filtering
- [x] VPN/Overlay Subnet Filtering
- [x] Interactive Subnet Selector UI

### Phase 3 (Completed)
- [x] **Persistent Asset Database:** Full SQLite persistence layer with historical scan sessions and intelligence archiving.
- [x] **STRIKE (Countermeasures):** Active defensive engagement module enabling targeted IEEE 802.11 Deauthentication (Deauth Jamming) against unauthorized nodes.
- [x] **Dashboard UI/UX Polish:** Intelligent risk scoring (CVE-based), high-value port glowing badges, Gateway node detection, and Map interaction stability (Auto-follow toggling).
- [x] **Rust System Integration:** Direct Tauri command execution to fetch real-time Windows network data (e.g., Connected Wi-Fi SSID) directly to the UI.

### Phase 4 (Completed)
- [x] **BRUTE FORCE Module:** Multi-threaded dictionary and password spraying attacks against LAN targets (FTP, SSH, HTTP).
- [x] **DECRYPTOR Module:** Offline WPA/WPA2 handshake cracking from intercepted PCAP files.
- [x] **Dictionary Arsenal (Global State):** Centralized dictionary management with support for custom `.txt` uploads and adaptive path resolution in PyInstaller.
- [x] **Antenna Benchmarking:** Signal strength (RSSI) distribution testing and hardware validation module.

### Phase 5 (Completed)
- [x] **GPS Quality Pipeline:** HDOP-based quality filtering and Haversine speed outlier detection for rock-solid coordinate accuracy.
- [x] **Tri-Mode Location Engine:** Configurable AP positioning algorithms (Bayesian Grid, Weighted Centroid, Trilateration) via Settings → RF Tuning.
- [x] **OUI Vendor Lookup:** vendor identification from the BSSID via Scapy's bundled `manufdb` (~35,000 IEEE OUI assignments). There is no local vendor table in this repository; `engine/scanner/oui.py` calls `conf.manufdb`.
- [x] **Evil Twin Detection:** SSID-level heuristic for detecting conflicting encryption types across same-name networks.
- [x] **Passive SIGINT Radar:** Zero-emission intelligence gathering via ARP, DHCP, mDNS broadcasts, and Wi-Fi Probe Request tracking.

### Phase 6: Deep Enumeration & Exploitation (Completed)
- [x] **GLOBAL CREDENTIAL VAULT:** Centralized, persistent storage for acquired credentials.
- [x] **CREDENTIAL SPRAYING:** Automated credential spraying across compromised subnet.
- [x] **SMB DEEP ENUMERATION:** Direct port 445 Null-session enumeration, OS/Domain extraction, Share Discovery, SMB Signing verification, and SMBv1/EternalBlue detection.
- [x] **WEB DIRBUSTER:** Multi-threaded web path enumeration engine.
- [x] **PROFESSIONAL REPORTING:** Native PDF generation with Multi-Report Aggregation, Interactive Table of Contents, and an In-App PDF Viewer Modal.
- [x] **MITM & PACKET INSPECTION:** Live ARP Spoofing to intercept and extract unencrypted DNS and HTTP traffic.
- [x] **VULNERABILITY ENGINE:** Modular active checks for Anonymous FTP, Unauthenticated Redis/MySQL, and Cleartext Telnet.

### Phase 7: System Hardening & Advanced Recon (Completed)
- [x] **SSL/TLS CERTIFICATE DEEP SCAN:** Full chain analysis with expiry/self-signed detection, weak cipher audit, deprecated TLS 1.0/1.1 probing, and HSTS verification.
- [x] **VISUAL TRACEROUTE:** hop-by-hop path mapping with per-hop latency, reverse DNS and a path analysis (NAT boundary, filtered hops, latency spike, target not reached).
- [x] **VLAN DETECTION:** 802.1Q tagged frame analysis to discover network segmentation.
- [x] **COLLAPSIBLE ACTION PANELS:** Toggle-style UI for scan action buttons to declutter the tactical interface.
- [x] **VEHICLE ICON SELECTOR:** Arrow/vehicle icon preferences for the wardriving map overlay.
- [x] **TACTICAL CONFIRM MODAL:** Replaced all native `confirm()` dialogs with branded, animated modal component.
- [x] **KEYBOARD SHORTCUTS:** `Ctrl+1-5`, `Esc`, `Ctrl+B`, `Ctrl+,`, `Ctrl+S`, `F11` — see [Key Capabilities](../README.md#key-capabilities).
- [x] **ENGINE AUTO-RECONNECT:** Exponential backoff reconnection with real-time UI feedback (toast notifications).
- [x] **CONFIG PERSISTENCE:** Zustand `persist` middleware preserving engine settings across app restarts.
- [x] **ENGINE COMMAND TYPE SAFETY:** `EngineCommand` and the `handlers` dict in `handler.py` hold the same 58 keys, so a typo is a compile error. Nine of those handlers have no caller in the UI — see the known gaps.
- [x] **ERROR BOUNDARY:** React ErrorBoundary wrapper preventing white-screen crashes.
- [x] **NON-BLOCKING TOASTS:** Replaced all `alert()` calls with professional toast notification system.
- [x] **REPORT DB SYNC:** `clearAll()` now deletes from SQLite in addition to clearing UI state.
- [x] **PASSIVE SIGINT PERSISTENCE:** Session state migrated to `sessionStorage` to prevent data loss during navigation.
- [x] **PYTHON DEBUG LOGGING:** Replaced 40+ bare `except: pass` blocks with `logger.debug()` across `vuln_engine.py`, `ssl_check.py`, and `smb_enum.py`.

### Phase 8: WiFi Attack Enhancement (Completed)
- [x] **PMKID CAPTURE:** Clientless WPA/WPA2 handshake capture (RSN PMKID) directly from the AP.
- [x] **HASHCAT INTEGRATION:** Direct export of captured PMKIDs to Hashcat-compatible `.hc22000` formats.
- [x] **WPS DETECTION:** Extraction of WPS locked/unlocked state and version from 802.11 beacon tags.

### Phase 9: Autonomous Execution & Spectrum Awareness (Completed)
- [x] **AUTO-ATTACK CHAIN:** Background orchestrator that automatically sequences WPS Scans → PMKID Captures on vulnerable high-signal targets (RSSI ≥ -75dBm) without user intervention.
- [x] **5GHz / 6GHz AWARENESS:** Dynamic frequency-to-band calculation and UI badging (2.4G/5G/6G) with dashboard filtering.
- [x] **WPA3 IDENTIFICATION:** Enhanced PyWiFi parsing to correctly map SAE/OWE constants to WPA3 in the UI.

### Phase 10: Advanced Fleet Management (Planned)
- [ ] **WATCHLIST (Radar Lock):** Input custom BSSIDs or MAC addresses of High-Value Targets to trigger massive visual/audio alarms.
- [ ] **FLEET (Friendly Asset Protection):** Register allied devices to trigger warnings if they connect to vulnerable or unauthorized access points.
- [ ] **IntrusionPage Modularization:** Split the 150KB monolith into sub-components (HostGrid, NodeIntelDrawer, BruteForcePanel, etc.).

### Phase 11: Maintainability

The project was built exploratorily and a few files carried most of the weight.
Measured before and after, so the next person starts from facts rather than an
impression:

| file | before | now | what changed |
|---|---|---|---|
| `src/components/layout/AppShell.tsx` | 1,107 | **166** | 61 `engineIPC.on()` handlers moved to `src/lib/engineRouter.ts` |
| `src/pages/ReportsPage.tsx` | 5,865 | **4,575** | data assembly, page furniture and the three largest document sections extracted |
| `buildAndSavePDF` (inside it) | 3,548 | **2,689** | what is left is jsPDF drawing and report prose |
| `src/pages/SettingsPage.tsx` | 3,065 | 3,065 | five unrelated panels in one component; JSX, not logic |
| `src/pages/IntrusionPage.tsx` | 2,733 | 2,764 | its own CVE table and risk ladder removed; see Phase 10 |
| `engine/scanner/lan.py` | 1,843 | 1,854 | discovery, port probing, CVE matching and the UDP sweep |
| `engine/ipc/handler.py` | 1,551 | 1,574 | 58 command handlers in one class |

**The split follows a line the comments already drew**, and every step was
verified by producing the report before and after and diffing the rendered text
page by page — 101 text streams, 16,000+ strings — rather than by review. Code
was moved by script rather than retyped: retyping 450 lines of report prose is
how a refactor silently changes what a document claims.

- [x] **Archive reading split out of the Reports page** → `src/lib/report/archive.ts`
  (578 lines, 32 exports). Moved verbatim so the compiler verified the move. Two further clusters left it later — `src/lib/apRisk.ts` and `src/lib/position.ts`, each re-exported from here so again no call site changed. See Phase 24.
  It then sat untested for three days, which is the more useful half of this
  story: **73 tests** were written before anything else moved, because nearly
  every function in it encodes a distinction the project has already been burned
  by — absent is not zero, unmeasured is not negative.
- [x] **Data assembly split out of the PDF builder** → `src/lib/report/assemble.ts`
  (546 lines, **25 tests**). The builder opened with seven labelled blocks that
  read the database and reconcile the numbers, and only then started drawing —
  nothing above the cover page touched `doc`. That is where every figure a
  manager reads is decided, including the deduplication that stops one access
  point surveyed twice from doubling the headline risk figure.
- [x] **Page furniture** → `src/lib/report/layout.ts`. `fit`, `sectionHeading`,
  `paragraph` and `callout` enforce the one rule every section depends on —
  nothing runs off the bottom of a page — and were unreachable inside the closure.
- [x] **Every document section** → `src/lib/report/sections/`. This began with
  the three largest — method appendix, subnet sweep coverage, position quality —
  and the entry used to end "the other sixteen are still inline", which was true
  for nine phases. All nineteen are modules now and `buildAndSavePDF` is 267
  lines; see Phase 25 for the method and for what the two archive baselines
  caught. The builder still lists them by number, because a reader looking for a
  section should not have to guess which file it is in.
- [x] **The three text exports** → `src/lib/report/exports/`. CSV, KML and
  GeoJSON were ~450 lines of string building inside the page, and unlike the
  jsPDF sections they are pure functions from an archive to text — so extracting
  them bought testability rather than only navigability. Doing it found that the
  three disagreed about which access points have a position.
- [x] **The record-to-rule-set bridge** → `src/lib/apRisk.ts`, and **a position,
  what it is worth and how to draw it** → `src/lib/position.ts`. Both left
  `src/lib/report/archive.ts`, which reaches `engineIPC` and `scopeDB`, so formatting a
  radius no longer pulls the sidecar bridge into the dashboard. No component or
  shared module imports it any more.
- [x] **The layers both maps draw** → `src/lib/map/surveyLayers.ts`, after the
  same fix had to be made twice in two files three thousand lines apart.
- [x] **The engine event router** → `src/lib/engineRouter.ts` (1,134 lines,
  **16 tests**). 62 subscriptions and 62 unsubscribes; the 32 handlers that
  genuinely touch the UI go through a `hooks` object, so the module imports no
  React and touches no DOM — which is the only reason the routing is testable.
  It is where the engine's vocabulary meets this app's schema, and therefore
  where a field renamed on one side and not the other stops being stored
  silently. This project has paid for that twice.
- [x] **One source per visual encoding**, because these were not cosmetic
  duplications. Six places decided a severity's colour and they disagreed: the
  archive telemetry tables drew **HIGH in CRITICAL's red** at a lighter opacity,
  and the CVE chips tested for CRITICAL and painted everything else as HIGH, so
  a MEDIUM CVE carried HIGH's border beside its own MEDIUM label. Five places
  banded RSSI and **no two agreed** - the live feed and the archive table were
  offset by a whole band, and the map popup drew signal strength in the *risk*
  palette, so -75 dBm came out the colour of a warning for being far away. Now
  `src/lib/severityStyle.ts` (15 tests) and `src/lib/signalStyle.ts` (9 tests),
  with `npm run check:severity-css` guarding the shipped stylesheet.
- [x] **The LAN/host side stopped keeping its own rule set.** `IntrusionPage`
  held a private CVE table (`getPortIntel`: eight ports, six CVE ids, its own
  severities and colours, no data vintage) and its own host risk ladder, and
  never called `assessHost` - while the report did. Two answers for the same
  host. The OS-inferred advisories moved into the engine where they can reach
  the report, flagged `inferred` and reported at SUSPECTED; the page now makes
  the identical `assessHost(toHostInput(...))` call the report makes. The
  port-number heuristic `[445, 21, 23, 3389, 5900, 22]` appeared in five places
  - including the `criticalNodes` figure **persisted to `intel_reports`** - and
  is gone from all of them. `riskEngine` has no rule for port 22 at all, so a
  host whose only open port was SSH used to be HIGH on screen and absent from
  the report.
- [ ] **The remaining 2,689 lines of `buildAndSavePDF`** are drawing calls and
  report prose, not logic. Splitting them further buys navigability, not
  correctness — a unit test against "draws a table" asserts nothing, and the
  page-by-page text diff already covers whether the output changed. The testable
  half is out.
- [ ] **Split `handler.py` by domain.** One class with 58 handlers; the dispatch
  table and the validation helpers (`_bounded_int`, `_bounded_float`,
  `_port_or_none`) are the reusable parts, and the handlers group naturally into
  scanning / offensive / diagnostics.
- [ ] **Split `SettingsPage.tsx` by panel.** Unlike the two above there is no
  shared state to untangle — the panels are already independent. Same trade as
  the remaining PDF sections: navigability, not correctness.

### Phase 12: the CVE refresh was a coverage regression

Found while verifying that the operator-run CVE update actually worked. It ran,
reported **30,392 entries across 18 products, `age_days: 0`, `stale: false`** —
and detected *less* than the 27-entry seed it replaced.

- **`active_matrix()` substituted the snapshot for the seed instead of merging
  it.** A real NVD pull returned none of **14 of the seed's 23 entries**, because
  NVD's version-pinned results simply do not contain them: Heartbleed
  (`openssl 1.0.1`), the Apache 2.4.49 and 2.4.50 traversals, both IIS WebDAV
  RCEs, the wormable HTTP.sys RCE, the Redis Lua sandbox escape, the phpMyAdmin
  LFI, two Tomcat RCEs, two Jenkins RCEs, the MySQL auth bypass and the OpenSSL
  padding oracle. A successful refresh switched all of them off.
- **`TRACKED_PRODUCTS` was not the seed's key set**, despite a comment saying it
  was "keyed to the top-level keys of CVE_MATRIX". `openssl` and `iis` were
  missing from it, so those four findings could never be refreshed even in
  principle. It is now derived from `CVE_MATRIX` (`cve_feed.tracked_products()`),
  so a product added to the seed cannot be left out of updates.

The reason this is the worst shape a defect can take here: the report would have
looked **more** authoritative — current data, nothing stale — while asserting
less. Nobody reading it could have told. The invariant now is that **a refresh
may only ever add**: the seed is a floor, the snapshot merges over it,
deduplicated by CVE id with the seed's hand-curated entry kept. Nine tests in
`test_cve_matching.py` lock it, each verified to fail against the old behaviour.

`describe_source()` now reports the **merged** counts and says
`origin: "snapshot+seed"` with "merged over the built-in seed" in `source`,
because those strings are printed verbatim in the method appendix and the
snapshot's own figures understate what the findings came from.

**The snapshot also moved out of the install directory.** `cve_feed._data_dir()`
resolved to `dirname(sys.executable)/data`, so on an installed copy under
`%ProgramFiles%` the refresh could not create the file without elevation — the
operator-initiated update this module exists for failed on exactly the machines
where it matters, reporting `cve_update_error` and retaining the 1,005-day seed.
It now resolves `%LOCALAPPDATA%\LOCKON-EWAC\data`, mirroring
`logging_setup.log_dir()`, which had solved the same problem already. Only the
update layer is per-user; the seed still ships with the build, so the tool is
still never empty offline.

### Phase 13: the NVD pull rewritten, the wordlist directory split, the PDF net rebuilt

**The CVE refresh queried NVD by keyword, and that was not a precision problem,
it was a correctness one.** `keywordSearch=apache` is a free-text search over
every CVE; the pull then filed the version literals out of each result's CPE
configurations under `apache`, without checking the CPE described Apache and
without honouring version ranges. Against the live API:

```
apache 2.4.6  -> CVE-2004-0700  "mod_ssl before 2.8.19"
apache 2.4.29 -> CVE-2004-0492  "mod_proxy in Apache 1.3.25 to 1.3.31"
apache 2.2.22 -> seven CVEs, every one keyed to a 1.3.x or 2.0.x release
```

The `apache` table had 440 version keys including `9.0.2`, `9.2` and
`9.1.0_r85` --- httpd has no 9.x --- and `CVE-2004-0490`, a cPanel flaw, filed
under Apache. 2.4.6 is the stock RHEL/CentOS 7 build, so this was an ordinary
host getting a false HIGH at LIKELY confidence captioned "matched from the
service banner".

Now the query is `virtualMatchString=cpe:2.3:a:<vendor>:<product>` and **every
match is filtered to the vendor:product actually asked about** --- the one check
that stops a cPanel advisory landing under Apache, since NVD returns a CVE when
*any* of its configurations matches and the others describe different software.
`_CPE_PRODUCTS` names them explicitly rather than guessing from the product key,
because OpenSSH is `openbsd:openssh` and vsftpd is `beasts:vsftpd`, and a guess
that misses returns an empty table that reads as "nothing known".

Version ranges are honoured: a concrete CPE version becomes an exact key, a range
becomes the line of its lower bound plus a `fixed_in` from its upper bound (an
inclusive bound is converted by bumping the last component, since `fixed_in` is
exclusive), and an unbounded product-wide match is **skipped** because it names no
build. Results are paginated, capped at five pages per CPE, and the cap, the
products that came back empty and any product with no CPE name are all recorded
in the snapshot and named in `coverage_note` --- a product the update failed to
retrieve must not read as a product with nothing against it.

Verified against the live API: `apache` came back with **206 version keys, no 9.x
keys**, and 2.4.6 / 2.4.29 / 2.2.22 / 2.4.49 each now match only genuine httpd
advisories with correct ranges. Eleven tests in `test_evidence_and_cve.py` run the
extraction against recorded payloads with no network.

**Three tests were green only because nobody had ever run a successful update.**
The engine suite passes with no snapshot and failed three files with one in force.
Two were a real isolation gap --- `test_age_and_staleness_are_computed_from_the_snapshot_date`
and `test_unknown_date_is_treated_as_stale` asserted the *builtin* branch while
`describe()` read the machine's real data directory; they now use a `no_snapshot()`
helper. The third, `test_a_version_that_merely_contains_a_key_never_matches`, was
a test artifact and **not** a matcher defect: it probes `"9." + key` and skipped
only an exact collision, so against 440 real keys the probe legitimately
prefix-matched `9.2`. The skip now covers a prefix hit. Run the engine suite
**both** ways after touching this area.

**The wordlist directory had the same bug as the CVE data directory.**
`upload_wordlist` wrote to `<exe_dir>/wordlists`, and `lockon-ewac.iss` installs
to `{autopf}` while its own comment says that directory "has to stay writable by
whoever runs the app" --- under %ProgramFiles% it is not, so the upload button did
nothing for any operator not running elevated. It failed honestly, but it failed.
Uploads now go to `writable_wordlists_dir()` (`%LOCALAPPDATA%\LOCKON-EWAC\wordlists`),
reads search both locations with the user one winning a name clash, the listing
carries an `origin` so the UI marks shipped lists BUNDLED, and deleting a bundled
list is **refused with a sentence** rather than failing on a permission error.
The traversal-containment tests now check against both directories.

**The PDF regression net is in the repository again.** `pdfdiff.mjs` and
`export-smoke-test.mjs` existed during the report refactor, lived only in a
session scratchpad, and were lost --- so for several days the one product path no
test reaches had no end-to-end check at all. Both are now committed, along with
`cdp.mjs`, which holds the CDP plumbing both app harnesses share so a fix to one
cannot leave the other with the bug. See **The PDF regression net** in
`docs/TESTING.md` for how it works and the two limits it accepts.

Writing it surfaced a defect in the harness pair itself: `app.kill()` does not
reap what `npm run tauri dev` spawns, so the webview and the sidecar survived and
the *next* run was refused for having no debugging port. Two consecutive runs
could never both work. `shutdownApp()` now reaps the tree.

### Phase 13b: three more defects, all found by running the suite with a real snapshot in force

Installing the corrected pull and re-running the engine suite failed three files.
None of the failures was in the new code; each was something the seed alone had
never been rich enough to expose.

- **A narrower version key shadowed a wider one it sits inside.** `lookup_cves`
  took a single winning key --- the exact version if present, otherwise the longest
  prefix. With only the curated seed no product had both a line key and an exact
  key within it, so this never showed. A snapshot has both routinely: `apache`
  carried CVE-1999-1199 at line `1.3` and a separate exact key `1.3.1`, and a host
  reporting 1.3.1 matched only `1.3.1`, dropping the 1.3-line advisory. **A
  refresh that merely added a key therefore removed a finding** --- exactly what the
  merge was built to prevent, arriving by a different route. A lookup now collects
  every matching key, most specific first so the `version_match` label still
  reports the strongest match.
- **A range with no lower bound keyed itself out of existence.** `< 1.21.0` with
  no start was anchored on its upper bound, giving nginx a key of `1.21` with
  `fixed_in: 1.21.0` --- so every 1.21.x host was "already fixed" and the key
  existed only to shadow others. Such a range spans an unknown number of lines and
  this matrix keys lines, so it is now skipped, erring toward missing.
- **NVD contradicts itself about fixing releases, and the unsafe reading was
  winning.** It describes OpenSSH CVE-2003-0190 both as a range fixed before 3.6.1
  *and* as exact version 3.6.1 affected. The unbounded entry won, so a host on the
  release containing the fix was reported vulnerable to the bug it fixes. A
  `fixed_in` is now a property of the CVE **within a version line**, earliest
  winning, which also lets the seed's hand-reviewed bound govern the snapshot's
  rawer data. Scoped to the line and not the product on purpose: a flaw fixed in
  1.0.5 that also affects exactly 2.0.3 would otherwise have the 1.0.5 bound
  applied to the 2.0.3 entry, deleting a genuine finding while fixing the first
  problem. Both directions are now locked by a test.

**A performance regression in the merge, which was also a correctness risk.**
`active_matrix()` deepcopies the seed and walks the snapshot --- 0.195 s against a
41,596-entry pull --- and `lookup_cves` calls it once per service per host. A LAN
sweep paid that per lookup, and the matrix-derived tests took eleven minutes. Now
memoised against the snapshot object's identity, holding the reference so the id
cannot be reused after a collection; a stale hit would serve the wrong CVE data,
which is worse than being slow. Measured at 193,000x faster on subsequent calls,
and two tests hold both the caching and its invalidation.

**The matrix-derived tests are now scoped to the seed.** They derive their cases
*from* the matrix and then assert a property of the matcher over it, which is only
meaningful against data this project controls --- against a 41,596-entry NVD pull
they assert NVD's internal consistency, and that has counter-examples in the data
rather than in the code. A `seed_only()` helper puts the seed in force so they
mean the same thing on every machine, and the merged-snapshot behaviour is covered
separately against synthetic snapshots, so nothing was left unchecked. The whole
engine suite now passes **both** with and without a snapshot in force.

### Phase 13c: the fix for Phase 13b deleted Heartbleed, and a worse defect was behind it

Checking seed survival against the installed snapshot, rather than trusting the
merge, found two more. Both are in the same chain, and the second is the more
serious.

- **A downloaded `fixed_in` was being applied to a curated seed entry.** NVD
  carries Heartbleed as a range over openssl line `1.0` fixed in `1.0.1g`, and
  `_apply_known_fixes` stamped that bound onto the seed's own `openssl 1.0.1`
  entry --- so **CVE-2014-0160 stopped being reported at all**. The seed is a
  floor: the *absence* of a `fixed_in` on a curated entry is as deliberate as its
  presence. Seed entries are now exempt, while the seed's own bounds still govern
  the snapshot's rawer data. One-way, on purpose.
- **`_version_tuple` dropped release letters, so `1.0.1g` compared equal to
  `1.0.1`.** Behind the first bug sat a worse one: a host on **1.0.1f, which is
  genuinely vulnerable to Heartbleed, read as sitting at the fixing release** and
  was not reported. A bare alphabetic tail directly on the digits is now part of
  the ordering (`1.0.1g` -> ...1, 7); a packaging tail is still noise
  (`4.6.16-Debian`, `1.2.3+deb11u1`, `1.2.3~rc1` all reduce to upstream). The
  distinction has to be narrow in both directions --- treat `-Debian` as an ordinal
  and a patched Samba host stops being excluded, which is the bug `fixed_in` was
  introduced to kill.

Worth recording as a pattern rather than three incidents: the merge fix, the
shadowing fix and the fix-bound fix each corrected a real under- or over-report
**and each introduced or exposed the next one**. None of it was safe to reason
about on its own; every step needed the real 40,000-entry pull installed and the
named seed CVEs re-checked by hand. The engine suite now passes both with and
without a snapshot in force, which is the property that makes the next change to
this area checkable at all.

### Phase 14: v1.0.0, and the defects only an installed copy could show

The user installed the build and reported two things in one message: the basemap
had degraded to the offline grid on a machine with working internet, and the icon
was not the LOCKON logo. Both had passed every automated check.

**`tauri dev` does not apply the policy that ships.** Tauri v2 injects
`app.security.devCsp` in development and `app.security.csp` in a build. `devCsp`
was unset, which does not mean "the same policy" --- it means **no policy at all**
in development. `npm run test:csp` runs under `tauri dev`, so every PASS it had
ever printed said nothing about the shipped policy. The harness written
specifically to prevent CSP problems was the vacuous check.

Two defects were hiding behind it, both absent on every developer machine and
present in every installed copy:

- **The basemap.** `csp` allowed `https://basemaps.cartocdn.com`; the style served
  from there loads its tiles, glyphs *and* sprite from
  `tiles.basemaps.cartocdn.com`. CSP host matching is exact without a wildcard, so
  the style document fetched and everything it referenced was blocked.
- **The webfonts.** `index.html` loaded the Google Fonts stylesheet `media="print"`
  so it would not block the first paint, then flipped it to `all` with an `onload`
  attribute. That is an inline event handler, governed by `script-src-attr`, which
  falls back to `script-src`, which allows nothing inline --- so the flip never ran,
  the sheet stayed print-only and the fonts never applied. The app simply rendered
  on the fallback stack. Found by the new release harness within a minute of it
  working; the flip now lives in `src/main.tsx` and needs no inline script.

  **And then the fonts were brought into the build, because fixing the flip only
  fixed the half that could be seen from a desk.** With the request working, the
  typeface still depended on the machine having a connection, and this is a tool
  whose own log says it "is offline in the field and opened occasionally".
  Measured inside the shipped WebView2 rather than reasoned about: online, all
  four families resolved and were used; offline the stack fell through to Segoe
  UI, Cascadia Mono and Bahnschrift Condensed. Legible, and a different
  application than the one on the desk.

  The stronger argument is the other one. A security assessment tool that opens a
  connection to a third party every time it starts is making a request somebody
  will have to explain -- in an air-gapped assessment it is a policy breach, and
  on any engagement it is an outbound record of when the tool ran. Nothing about
  drawing a heading needs that.

  This repository had recorded self-hosting as impossible here, on the evidence
  of a `curl` that returned a stylesheet with zero `woff2` URLs. The cause was
  the User-Agent: Google's css2 endpoint serves TrueType to clients it does not
  recognise, so the fetch succeeded and the conclusion drawn from it was wrong.
  With a browser agent it returns 57 faces across eight subsets.

  21 of those are kept -- `latin` and `latin-ext`, which is exactly the set the
  browser was already choosing to download. They are variable fonts, so one body
  covers every weight of a family within a subset: naming the files by weight
  committed ten duplicate binaries that Vite silently deduplicated back down, so
  the waste never reached a user and sat in the repository instead. Named by
  content instead, it is 11 files and 268 KB.

  `csp` and `devCsp` now name no font host at all, which is what turns "we happen
  not to request it" into "the policy refuses it". `npm run check:fonts` resolves
  every declared face against a file and fails on a CDN reference or a leftover
  grant; `npm run check:fonts:runtime` drives the built app and asserts both
  halves of the claim -- that Inter, JetBrains Mono, Rajdhani and Share Tech Mono
  are the families actually in use, and that not one of the requests the app
  makes while starting goes to a font host. It also settled a detail no file
  could: `'Segoe UI Variable'` has been in `--font-sans` all along and has never
  once resolved, because Windows registers `Segoe UI Variable Display`, `Text`
  and `Small` and never the bare name.

Three layered guards, because none alone is enough: `devCsp` set to the production
policy plus the dev server's origins; `checkPolicyDrift()`, which refuses to run
when `devCsp` is absent or allows anything `csp` does not (verified against all
three states, including the one that shipped the bug); and
`npm run test:csp:release`, which drives the built binary. The dev policy
legitimately needs `'unsafe-inline'` for Vite, so inline-script faults cannot be
caught in dev **by construction** --- which is exactly what the release mode is for.

**The icons had never been replaced.** Everything in `src-tauri/icons/` still
carried the scaffolding date: the default Tauri logo had been the app, shortcut
and taskbar icon the whole time. Regenerated from `public/LOCKON_logo.svg`.

**Installer review, and two of the findings were in the fix for the first one.**
`StopEngine()` killed only the sidecar --- but `ipc.ts` keeps a reconnect loop, so
the app immediately started a new one and re-locked `_internal\`; the window has
to go first. The uninstaller stopped nothing at all, so uninstalling with the app
open left the executable behind *and reported success*. `[Run]` lacked
`runasoriginaluser`, so a per-machine install launched the app with the installer's
elevated token --- and if the operator had elevated with a different administrator
account, the first session wrote the survey database, the credential vault, the CVE
snapshot and uploaded wordlists into **that account's** profile, leaving the
operator's own copy empty. Also added: `SetupIconFile`, version metadata,
`MinVersion=10.0`, `CloseApplications`, an `[UninstallDelete]` for the legacy
`{app}\data` an older build wrote, a WebView2 confirmation, and an uninstall prompt
that states what is kept and where.

**Two traps worth not re-learning.** In Inno Setup, `{ }` delimits a Pascal
comment, so an Inno constant written inline inside one ends the comment early and
the rest parses as code. And `launchApp()` spawning the built `.exe` through a
shell silently broke it --- the relative path uses forward slashes, `cmd` did not
launch it, and the harness waited out its full fifteen-minute attach timeout
looking exactly like WebView2 refusing the debugging port. Spawned directly with an
absolute path, it attaches in about a second.

**Two environment failures, diagnosed rather than assumed.** Several builds were
reaped by the harness for low memory; a leftover `rustc.exe` holding 1.4 GB was the
real pressure, and running PyInstaller in the foreground avoided the reaper
entirely. Then a build failed at the WiX linker, which looked like a WiX fault and
was `os error 112` --- **the disk had 0.21 GB free**. `src-tauri/target/debug` was
13.07 GB; removing it returned the drive to 10 GB.

Version bumped to **1.0.0** across `package.json`, `tauri.conf.json`, `Cargo.toml`,
`constants.ts`, `build_stamp.py` and the `.iss`. Verified after: `test:csp:release`
PASS with 0 violations and 0 blocked loads across five screens with the map panned
to force real tile requests.

### Phase 15: the report was laid out from nowhere in particular

Reported from a printed copy: parts of the document ran off the page, the
spacing was inconsistent, and some sections did not look designed at all.
Measuring the PDF turned the vague half of that into numbers.

**The WiFi telemetry table was drawn 6 mm off the paper.** Eleven columns summing
to 202 mm on a 178 mm content column. Nothing objected, because nothing checked.
The last column --- the severity verdict, the one figure a reader most needs ---
began at 198.1 mm on a 210 mm sheet and printed entirely off the page, on eleven
pages, for as long as that table had existed. **372 rectangles** fell outside the
printable area.

**The cause was that the page had no single definition.** `14`, `182`, `196`,
`287`, `292` and `25` were typed out by hand across four files with nothing
connecting them, so they drifted --- and the drift is exactly what reads as "this
was not laid out". `geometry.ts` now measures the page being drawn and everything
derives from it. That includes `TABLE_MARGIN`: twenty-four tables had been left
on jspdf-autotable's 14 mm default while the text column sat elsewhere.

With one geometry in place the rest was small. Side margins to 16 mm. The WiFi
annexe turns **landscape**, where eleven columns fit with room --- and the header
and footer read the page they are on, which hardcoded numbers could not do (a
portrait footer on a landscape sheet lands 77 mm below the paper). Six further
portrait tables that summed to exactly 182 mm are trimmed to 178. `Score` goes
from 11 mm to 14: it was narrower than its own heading, so every findings page
printed "Scor / e".

Section headings now carry a vector glyph from `icons.ts`, in the rule's own
colour so the two cannot drift apart, and set in the margin gutter so every
heading's text stays aligned with the body beneath it. Line art rather than
images: a few hundred bytes against tens of kilobytes, crisp on paper, and it
takes the palette rather than baking it in.

**`npm run check:margins` is the guard.** It reads the `re` operators out of a
built PDF and measures each against its own page box. Verified both ways: it
fails on the pre-fix document naming 372 items, and passes on the current one.
A column width is a number somebody typed; it was always checkable.

**Two defects found while verifying, neither of them layout.**

- **Every BSSID carried a trailing separator.** `00:00:5E:00:53:48:` --- read as a
  truncated MAC, in the telemetry table and the evidence register. It looked like
  a wrapping artifact and was not: `wifi.py` normalised only the bare
  twelve-character form and passed anything else through, and PyWiFi returns a
  trailing separator on this platform. So the value went into the database that
  way. It also meant the stored key and the key used to match netsh enrichment
  were different strings, with only the lookup side normalised. Now through
  `netsh_wlan.normalize_bssid`, with tests.
- **The export harness was comparing different documents.** It exported "the
  first archived report", which is only stable while the archive is. A newer scan
  put a different survey on top and the run reported 77 differences that had
  nothing to do with the code. The baseline now pins its report id. A net that
  cannot tell "the build changed the document" from "a different document" is
  worse than none, because every real difference after it reads as noise.

Also fixed while here: the Decryptor's scan-line overlay translated by `100vh`
--- the viewport height, not the element's --- and its cards do not clip, so the
sweep left its container and drew a line across the page. Removed there; the map
keeps it and does clip, and the requirement is now written where the effect is
defined. And the installer's readiness page sets one space between a status and
its subject with the explanation flush left, rather than padding both into
columns that did not line up.

### Phase 16: two figures that spent their space on a constant

Both defects in this phase have the same shape. A channel that a reader relies
on --- colour in one case, a column of the findings table in the other --- was
carrying a value that barely varied, while the thing they actually needed was
either absent or crowded out. Neither was a crash, and neither would ever appear
in a test suite; both were obvious the moment somebody looked at the output.

**The survey map was almost entirely one colour.** Hue encoded positional
certainty --- amber for mirror-ambiguous, blue for resolved. On the real survey
**165 of 172 positions are ambiguous**, so the figure came out uniformly amber
and the most legible channel on paper was spent telling the reader something
that is true of nearly every dot. Severity, which is what a reader opens the
figure to find, was not shown at all.

Hue is severity now, resolved through the report's own `worstFor` so the figure
cannot disagree with the findings table about how bad something is. Certainty
moved to shape, which suits it better: an ambiguous position already draws two
marks, so it is drawn as what it is --- a filled dot with a hollow twin, one
radio with two candidate positions. That reads without a key and cannot be
mistaken for two radios the way two filled dots could.

**The figure is light, and the application is dark, deliberately.**
`SEVERITY_RGB` is tuned for ink on white; on a near-black basemap CRITICAL's
`[153,27,27]` is close to invisible. `REPORT_MAP_STYLE` is therefore a light
basemap and the operator's map preference does not apply to the report. That
preference is about working at night in a vehicle; it is not a statement about
how a document should print.

**Print LOW was teal while screen LOW was green.** Found while checking the
above. The scale has to read as safe-to-dangerous at a glance and it did not:
the same level was `#22c55e` in the app and `[13,148,136]` on paper. Print LOW is
now green-700 --- the screen's hue, carried down to a weight that survives a
monochrome printer. INFO stays neutral slate on purpose: it is the absence of a
judgment, not the safe end of the scale, and colouring it green would state a
conclusion the rule set never reached.

**The report claimed a drive that never happened.** Found by counting green
pixels in the rendered figure --- there were none, while the caption read "the
route shown is the recorded GPS track" and the key listed "route driven". The
test behind both was `route.length > 1`, which counts *fixes*. The survey had
**280 fixes spanning 9.9 metres**: a receiver sitting still, logging its own GPS
jitter.

This is not a cosmetic defect. Every position in the document is trilaterated
from signal strength measured along the route, and deciding which side of the
receiver a transmitter sits on requires movement across a baseline. There was
none --- which is the direct and complete explanation for **165 of 172**
positions coming back mirror-ambiguous, a number the report prints prominently
and previously left unexplained. `routeSpan()` now measures the bounding-box
diagonal in metres (not path length, which accumulates out of noise and would
report exactly the movement that is not there), `MIN_ROUTE_SPAN_M` is 25 m, and
below it the figure says what happened and why it matters instead of drawing a
line too short to see.

**The findings table printed the same paragraph forty-two times.** `rationale`
belongs to the *rule*, not to the finding, so every unencrypted network carried
an identical five-line explanation. About eight rows fitted a page; seventy
findings ran to nine pages, the overwhelming majority of which was one paragraph
photocopied down the right-hand side.

The cost was not only paper. The constant held **64 mm** of a 178 mm content
column, which squeezed the columns a reader actually scans into the remainder
and wrapped the subject line --- the one cell that differs on every row --- to
three lines. Each distinct rationale now gets a code, the reasons are listed
once below the table with the number of findings sharing each, and the column
becomes that code at 16 mm. Nothing is removed: every finding still states its
reason, and the count makes the repetition legible as a fact about the survey
("42 findings share this") rather than something the reader infers by reading
the same words over and over.

### Phase 17: the bundle was not the thing that was built

Rebuilding the stale artifacts should have been bookkeeping. It produced an
installer whose engine would not start, and the defect is worth recording
because nothing in the project reported it and the sidecar itself was correct.

**`tauri build` copies resources into `target/release/_internal` without
clearing it.** A file that belonged to a previous sidecar build and not to the
current one stays behind and ships. This rebuild orphaned **244 files** --- 207
of them matplotlib, plus PIL, contourpy, kiwisolver, and a `numpy-2.3.4`
dist-info sitting beside an installed numpy 2.5.3.

One of them was fatal. PyYAML had left the virtualenv, so the new sidecar
contains no `yaml` at all --- which is fine, because paramiko guards that import
with `except ImportError` and degrades. But the stale tree still held
`_internal/yaml/` containing exactly one file, `_yaml.cp313-win_amd64.pyd`, the
optional C accelerator, with no `__init__.py`. Python reads a directory without
an `__init__.py` as a **namespace package**, so `import yaml` *succeeded* and
handed back an empty module. paramiko's guard never fired, and the engine died
at startup on `AttributeError: module 'yaml' has no attribute 'error'`.

The orphan did not break something that worked. It converted an absence the code
already handled into a crash it could not.

**It was invisible everywhere except in a bundle.** The sidecar in `binaries/`
started correctly and reported the right build stamp when tested directly,
because there the absence was a real absence. 675 engine tests pass, because
they run against source in a virtualenv. The only symptom was an engine that
refused to start after installing --- and it surfaced here only because
`npm run test:csp:release` drives the built binary and prints the engine's
stderr, where the traceback repeated between restart attempts.

**Two corrections to the first reading of this, both found by measuring.**

Deleting the stale directory is not a sufficient fix. Tauri does not re-copy
resources when its build script is fingerprint-clean, so the rebuild after the
deletion left `target/release` with no engine at all --- a different broken
artifact, arrived at by following the instruction this log originally gave.

And `target/release/_internal` is narrower than it first appeared. It is the
staging copy used when `target/release/lockon-ewac.exe` is run **directly**,
which is what every release-mode harness does and is how the crash surfaced. It
is also what the installer used to source from. Tauri's own MSI and NSIS bundles
do *not* use it: `tauri.conf.json` names `binaries/ewac-engine/_internal` as a
resource, so they read the sidecar from its build output and were never
affected. The evidence is a build made with that directory absent still
producing a 124 MB MSI, within 8 KB of the build that had it.

So `installer/lockon-ewac.iss` now sources the engine, its `_internal` and the
wordlists from `src-tauri/binaries/` --- where PyInstaller and
`sync:wordlists` actually write them --- and renames the executable on the way
in, since Tauri strips the target triple and `StopLockon()` kills
`ewac-engine.exe`. That makes the whole class unrepresentable for the artifact
that ships.

`npm run check:sidecar` covers what remains. It starts the frozen engine and
requires its `ready` event, which is the only check in the project that runs the
frozen engine at all --- the 675 engine tests import source inside a virtualenv,
where a missing dependency is a clean `ImportError` and a half-collected package
cannot exist. Then it compares the staging tree against the sidecar and fails on
a file either side is missing, naming an entirely-orphaned package explicitly,
because that is the shape that shadows rather than merely wasting space. Proved
in both directions: it passes clean, and planting a `yaml/` directory holding one
file makes it fail and say why.

### Phase 18: the map was animating noise

Reported from use: "I was standing still, but the car moved by itself, it
started in the wrong place, and the access points never settle." All three were
real, none of them was a rendering fault, and the causes were separate. What
they had in common is that nowhere between the NMEA sentence and the plotted dot
did anything ask whether the position was good enough to draw.

**The vehicle started in central Bangkok.** `MapView` created the ego marker at
`MAP_DEFAULT_CENTER` --- `[100.5018, 13.7563]` --- and left it visible. On a
survey anywhere else that is a vehicle drawn somewhere it has never been, and
nothing on screen distinguishes it from a real fix. The marker is now hidden
until a fix exists, so "we do not know yet" is drawn as nothing at all.

**Both NMEA sentences say whether they can be trusted, and neither was read.**
`update()` accepted anything whose latitude was not exactly `0.0`. GGA carries
`gps_qual`, which is 0 when the receiver has no fix; RMC carries `status`, 'V'
for void. Both still fill in a latitude --- the last one believed, or a partial
solution --- so a cold start was plotted as a position. Worse, a receiver that
loses lock mid-survey keeps emitting those sentences, and each one *overwrote*
the last good fix. That is one way a parked rig acquires a moving track, and the
heading on a vehicle that never moved came from the course field of sentences
that declared themselves void. HDOP was being read and forwarded to the UI all
along, and gated nothing.

**A fix is not a step.** Every accepted fix was appended to the route. Consumer
GPS scatters a few metres while stationary, so standing still wrote that scatter
into the track as travel --- the archived survey holds 280 fixes spanning 9.9 m.
`GPS_STEP_M` (5 m) is now the floor for calling something movement.

That one is not cosmetic, because the track **is** the localizer's baseline.
The scatter was being offered to the estimators as survey geometry.

**And the estimators solved it.** This is the defect behind "the access points
never settle", and it was already half-diagnosed in the code. `assessGeometry`
computes `insufficientBaseline` below `MIN_ALONG_TRACK_M`, and that flag was
used only to set `mirrorAmbiguous`, write a note and tint a label in Settings.
The solver ran regardless and its answer was published.

Trilateration fixes a position where ranges taken from different places
intersect; from one place they do not intersect, they merely agree. Solving for
a transmitter a hundred metres away from a cluster of sightings ten metres
across is ill-conditioned, so a few dB of fading moves the solution by tens of
metres and every re-estimate puts the access point somewhere new. The solver was
not wrong. The question had no stable answer and it was being asked anyway ---
which is also why selecting MULTILATERATION appeared to scatter the points
rather than tighten them.

`estimateLocation` now gates before dispatch, because this is not a property of
the method chosen: no estimator can recover a position the geometry does not
contain, and three estimators failing in three different ways produced three
wrong answers instead of one honest refusal. Below the threshold it reports the
mean of where the receiver stood --- a mean, so it does not hop between scatter
points as the signal flickers --- with a radius from the strongest reading, and
`resolved: false`. The map draws those hollow: risk keeps the colour, certainty
gets the shape, the same rule the report's survey map uses.

**The radius needed a correction the code had already written down.**
`estimatePeak` carries a note saying the strongest of N readings is the luckiest
one, short by roughly `sqrt(2 ln N)` sigma, and that *"if this is ever promoted
to a selectable method, that correction has to come with it."* Promoting it to a
forty-sighting parked survey is exactly that case, and the first measurement
said so: the stated radius covered the true position in **4 runs in 10**.
`peakDistanceCorrection` applies the order-statistic bias before the spread, and
coverage is now 10 in 10 --- asserted, because a refusal is only honest if the
circle it draws actually contains the answer.

**Then the opposite failure, caught by measuring the radius rather than only its
coverage.** The first correction applied `SINGLE_READING_DISTANCE_FACTOR_95` on
top of the bias correction, which double-counts: once the bias is removed what
remains is the uncertainty of the *maximum* of n samples, and that is tighter
than one sample by about `sqrt(2 ln n)`. The result covered 100% of the time at a
median radius **4.2 times** the error it was covering --- "somewhere within
1.4 km" for a transmitter 279 m away. True, and not a finding anyone can act on.
`peakSpreadFactor95` uses the max-of-n spread: measured over 400 parked surveys,
99.5% coverage at 2.3 times the error, against a field documented as "roughly
95%". Both sides are now asserted, because they pull against each other and any
radius covers if it is made large enough.

### Phase 19: what to draw when there is nothing to draw

Refusing to estimate left a second question, and the measurement answered it.
Simulated twelve transmitters 30 to 300 m from a parked receiver: every estimate
came back unresolved, and the twelve marks landed **1.6 m apart**. That is
correct --- from one spot the honest statement about all of them is the same
one --- and it is unreadable. Stacked, they are one pile that still implies
twelve distinct positions. Dropped, the map is empty, and an empty map reads as
"nothing was there".

So they are grouped: one marker per place the operator stood, carrying the
number of access points heard from it and how many were flagged. That says the
true thing without inviting a false reading of it.

Three details are deliberate. The grouping is a **~30 m grid, not a centroid**,
because an operator who stops twice has two stationary clusters and one averaged
marker would sit between them, where nothing was ever measured. The markers are
**DOM elements rather than a MapLibre symbol layer**, because a symbol layer
with text needs `glyphs` and the offline style has none --- the count would
disappear in exactly the degraded conditions where it matters most. And the
hollow-dot paint that briefly existed on the access-point layers was removed
rather than left as a fallback: once unresolved points stopped reaching that
source, `tsc` pointed out that the property could no longer be `false`, and dead
paint with a confident comment next to it is worse than none.

The report's figure needed no equivalent change. Overlapping identical hollow
circles render as one circle, so it degrades to a single mark rather than a
blob, and the caption already states the span of the track in metres and why
nothing could be placed. A static figure has prose next to it; a live map does
not.

### Phase 20: the map was more confident than the report made from it

Five defects, one theme. The estimators have published an uncertainty radius and,
on a straight pass, a second equally good position since migration 011. Four
different places then failed to carry that honestly, and in every case the
failure direction was the same: the number that survived was the confident one.

**A second candidate that was the same point.** `estimateTrilateration` reflected
its answer across the track axis and offered the result whenever the geometry was
ambiguous. On a straight pass that solver takes no step --- `JᵀJ` is singular, the
first iteration breaks, the answer is still the strongest sighting, which is *on*
the track --- and reflecting a point across an axis it already lies on returns the
point itself. The separation came out around `1e-10 m` and every consumer
downstream treated it as a real second position: the PDF flagged the access point
AMBIGUOUS with "two candidates, 0 m apart", the position-quality table listed
candidate B at the same coordinates, and the KML wrote a duplicate placemark
joined by a zero-length line described as "the two equally good positions". The
likelihood grid had guarded this since it was written, with a one-metre threshold;
the threshold is now `MIRROR_MIN_SEPARATION_M`, shared.

A test existed for this and asserted `mirrorDistanceM > 0`. `7.9e-10 > 0` is true.

**The stated radius covered one of the two modes.** The comment above the
covariance claimed that "the ill-conditioning that *causes* the mirror ambiguity
is exactly what inflates the radius --- which is the behaviour a reader of the
report is entitled to assume the number already had", and `AP_LOCATION_METHODS.md`
§4 said the same. It was not true. A covariance is a *per-mode* spread: it says
how far the transmitter may be from the mode that was solved for, and nothing
about the other mode. Measured over 200 runs of a realistic straight pass, the
solver picked the wrong side of the road **48%** of the time and the per-mode
radius contained the transmitter in **52%** of runs, printed under a heading
saying 95%. The grid solves this in one line; multilateration now does the same
--- `max(radius, mirrorDistance + modeRadius)` --- which covers it in 200 out of
200. `modeRadiusM` is published as well, because the report's "Per-mode" column
read `n/r` for every multilaterated access point while its header explained what
the column meant.

The fixture is why this lasted. `STRAIGHT` put all sixty sightings at one exact
latitude, which makes `JᵀJ` *exactly* singular, so multilateration produced no
second candidate on it at all and every mirror assertion took the `continue` and
passed without running. A metre and a half of lateral wobble --- less than any
real receiver's scatter, and still well inside `MIN_CROSS_TRACK_M`, so the
geometry is correctly still called ambiguous --- makes all forty seeds exercise
the branch. Reverting each of the three changes turns one of the new tests red.

**Two columns the store dropped.** `wardrivingDB` wrote `location_mode_error_m`
and `location_mirror_distance_m`; `missionStore` did not. So a mission replayed
from SQLite printed the per-mode spread and the separation between the two
candidates, and a live survey exported from memory printed `n/r` for each --- the
same mission, read two ways, producing two different documents. This is the second
time that exact shape has been found in this file, in the same function.

**The live map read none of it.** Every access point on the tactical map was a 5
or 7 pixel dot, and a dot is an assertion. `location_error_m`,
`geometry_ambiguous` and `location_mirror_lat`/`lon` reached `MapView` on every
feature and were never looked at, while the PDF, CSV and KML made from the same
mission all printed them. A transmitter known to ±90 m that could equally well be
across the street looked exactly like one pinned to five metres --- on the screen
the operator uses to decide where to drive next, which makes it the worse of the
two places to be silent.

`src/lib/mapUncertainty.ts` now builds the overlay from the same `circlePolygon`,
`apMirror`, `isMirrorAmbiguous` and `RING_LIMIT_M` the report figure uses, rather
than its own copies, because two implementations is how the screen and the
document came to disagree. Rings are drawn without fill, for the reason the report
figure already found out: real surveys put a hundred and sixty radii within a few
streets, overlapping hundreds deep, and at 3.5% fill that reaches 99.9% opacity.
The mirror candidate is hollow and joined to its access point by a dashed line,
because an unlabelled ring 90 m away reads as another radio on the next street
when it is the same one.

What the overlay cannot draw, it says. A radius wider than `RING_LIMIT_M`, a
position carrying no radius at all, and an access point flagged ambiguous whose
second candidate was never stored are three different states that all render as a
clean dot; they are counted and stated in one line at the bottom of the map. The
line renders only when there is something to qualify --- a permanent "0 omitted"
is a line an operator stops reading, and the only survey it matters on is the one
where it is not zero.

**The report described an implementation the code does not have.**
`LOCATION_METHOD_NOTE.trilateration` said "range is derived from received power
using free-space path loss and the three strongest observations intersected".
`AP_LOCATION_METHODS.md` §3 carries an explicit retraction of both: the FSPL
formula appears nowhere in the codebase, and using only the strongest readings is
specifically the mistake §2 of that document exists to warn about, because the
weak distant readings are what carry the range information. The doc was corrected
and this table --- which is what the exported PDF, CSV and KML actually print ---
was not, so the retraction reached the reader who went looking for it and not the
reader holding the document.

`weighted_centroid` described itself as "biased toward the route travelled",
which invites a reader to picture a position that leans toward the road. It cannot
leave it: a weighted average of the sighting positions is a convex combination of
them, and the measured off-track displacement with the transmitter 40 m from a
single road was **0.0 m in every trial**. The labels were also two names for one
method --- an operator selects MULTILATERATION and TRACK POSITION in Settings and
the report named them "FSPL trilateration" and "RSSI-weighted centroid". The keys
are unchanged, because they are in the database; what is printed now matches both
the UI and the code, and three tests hold it there, one of them tied to
`PATH_LOSS_EXPONENT` so changing the model fails loudly instead of leaving the
document quoting an exponent nothing uses.

### Phase 21: re-reading the map after changing it

Phase 20 was audited again rather than declared finished, and the audit found
eight more things, three of them introduced by Phase 20 itself.

**The caveat line was printed on top of the scale bar.** MapLibre's
`ScaleControl` is added to `bottom-left`, and that container places it at
`bottom: 10px; left: 10px` at up to 200px wide. The new line was at `bottom-2
left-2`, so amber text sat directly over a white scale bar on every survey with
anything to qualify. Moved to `bottom-12`, which clears it and lets the block grow
upward as the text wraps.

**Switching the heatmap on hid the entire uncertainty overlay.** The heatmap is
inserted with `beforeId: 'aps-low-risk'` under a comment reading "insert below the
circle layers", which was true and not sufficient: the rings and the second
candidates are registered *before* the circles, so `beforeId` put the heatmap above
them. At `heatmap-opacity: 0.8` that erased the overlay, and the dots survived
because they are drawn higher still --- so the one thing left visible was the
confident mark. Now inserted before `ap-uncertainty-ring`.

**"47 with no stated radius" was the wrong sentence.** `estimateTrackPosition`
returns `errorRadiusM: null` by construction --- a weighted average of the
sighting positions has no uncertainty model behind it --- and `assessGeometry`
still reports a straight route as mirror-ambiguous, which is true of the route
while that estimator has no second candidate to offer. So with TRACK POSITION
selected on a straight drive, every access point on the map landed in both counts
and the caveat read as damage to the data on every single survey. A caveat that
cries wolf on every run is wallpaper by the second one. It now names the estimator
when one accounts for all of it, and refuses to name "not recorded" when a row does
not say which estimator produced it --- that would be a missing field offered as
the explanation for itself.

**The map had no key, and Phase 20 added three symbols to it.** A filled dot, a
hollow dashed circle with a number in it and a blue line are three different kinds
of claim, and nothing on screen said which was which; the report's figure has
carried a KEY since it was written. There are now seven rows, each swatch built
from the same colour and dash pattern as the layer it describes, collapsed behind a
KEY button because the map is the content. Each row says what the mark *claims*
rather than what it looks like, which is the part an operator cannot infer.

**Two popups described the same access point differently.** Hovering a dot stated
the estimator, the radius and the ambiguity; selecting the same radio from the scan
feed --- which is how an operator usually arrives at a specific one --- showed none
of it. And for an unresolved access point the selection popup was worse than
incomplete: there is no dot at that coordinate, because unresolved marks are
grouped into counted markers, so the popup was the only thing on screen there and
it asserted a position the tool had explicitly refused to state. One
`positionQualifier` at module scope now serves both, and it has a branch for
`resolved === false` that says so.

**An access point with no reading was the brightest thing on the heatmap.** The
weight interpolates `rssi` over -100..-40 dBm and `interpolate` clamps outside its
domain, so a null reading --- which the popup code three hundred lines away already
handles explicitly --- was clamped to the *top* of the scale. A radio whose signal
was never recorded was drawn as the strongest signal on a map of signal strength.
The layer is now filtered on a `hasReading` property rather than coalescing to
-100, because substituting the floor is the same invention in the other direction.

**Three truthiness tests on coordinates.** `latitude && longitude` for the map
centre, the vehicle marker and the recenter button, and `ap.latitude &&
ap.longitude` for target selection. `numbers.ts` already carries this project's one
rule --- the equator and the prime meridian are real places, only exactly `0, 0` is
the absent value, and an out-of-range pair is not a position either --- so all four
now call `coordinatePair`.

**Three Settings descriptions had drifted.** TRACK POSITION was still described as
a "signal-weighted average" when the weight has been inverse modelled range since
Phase 11, and said "no error radius" without saying that the map would therefore
report an absence for every access point. MULTILATERATION said nothing about the
two candidates and the widened radius it now reports. And the heatmap toggle said
"visualize signal density", which reads as coverage measured along the route; it
renders the density of *estimated transmitter positions* shaded by their latest
reading, which is a different thing, and it shrinks the markers and covers the
rings while it is on.

Two findings were left as they are, deliberately. A newly-seen access point sits on
the vehicle as an ordinary dot until its second sighting, because the first batch
creates the record before any estimator has run; the window is one scan interval,
it self-corrects, and the popup already says "estimator not recorded, no stated
radius" --- withholding the mark would mean a radio the operator just heard does
not appear. And changing the location method in Settings does not re-estimate what
is already on the map: each access point switches on its next batch, and nothing
switches at all while scanning is stopped. That is honest --- `location_method`
travels with each position, so the popup and the report name the estimator that
actually produced it --- but it is a surprise worth knowing about, and it is written
here rather than fixed because invalidating every cached estimate on a settings
change would re-run the grid over the whole mission on a keystroke.

### Phase 22: the same mistake in five more places, and one of them was the recorder

A third pass over the map, this time starting from the two things Phase 21 had
asserted rather than measured. Both held --- the track really is built from
accepted fixes, and the bearing really is the great-circle initial bearing --- and
checking them turned up a family of defects that had nothing to do with the map
layers.

**`latitude && longitude` was the gate on recording, not just on drawing.** In
`engineRouter`, a GPS fix that failed a truthiness test was never appended to the
track and `logGps` never ran, so it was absent from the database and from every
document made afterwards. On the equator or the prime meridian the survey silently
recorded nothing. `numbers.ts` has carried this project's one rule since it was
written --- a single zero component is a real place, only exactly `0, 0` is the
absent value a NULL column decays into, and an out-of-range pair is not a position
--- and five surfaces each had their own version of the question instead: the map
centre, the vehicle marker, the recenter button, the report's interactive map and
its focus flyTo, the target drawer's compass, and the recorder. All of them now
call `coordinatePair`.

The ordering is the uncomfortable part. A display bug shows the operator something
wrong while they can still see the truth beside it; this one removed the truth
before anything was written down.

**The coordinate readout contradicted itself.** The top bar printed
`${latitude.toFixed(4)}°N ${longitude.toFixed(4)}°E` with the hemisphere letters
written in, so a southern or western fix read as "-13.7563°N" --- a minus sign and
a letter saying opposite things, in the readout checked most often. The
offline-basemap card had been fixed for precisely this ("hemispheres rather than
minus signs, since a careless formatter prints -0.13°E") and the fix did not travel,
because `describeBounds` had its own local `ew`/`ns` pair. One
`degreesWithHemisphere` now serves both, with five tests, one of which simply
asserts that no `-` survives in any output on either axis.

**The bearing arrow was the last surface that qualified nothing.** It is also the
most actionable thing in the application: it is read by someone deciding which way
to walk. For an access point no estimator could place, `ap.latitude` is the
receiver's own position --- so the dial pointed at the operator's feet, steadily,
with a crisp bearing and no hint that it was doing so. For a mirror-ambiguous one it
points at whichever of two equally good candidates the estimator reported, and
walking the wrong way is the entire cost of that ambiguity. Both now say so under
the dial, and the absent state distinguishes "no GPS fix" from "no position for
this radio" --- two different problems, one solved by waiting for satellites and the
other by driving, which were shown with the same label.

**The key panel opened across the filter buttons.** 252px wide and about 200px
tall, opening upward from inside the left-hand cell of a row whose next cell holds
the MAP FILTER buttons. The overlap depended on the panel's height, which is the
kind that survives a look at one viewport. The cluster is now a column with the
panel on its own row, so the collision is impossible rather than unlikely.

Nothing was found this round in the estimators, the gate, the sighting merge, the
throttle budget or the uncertainty overlay itself.

### Phase 23: the drift was arithmetic, and the glow was a habit

**The vehicle drifted again, and the previous fix was not wrong --- it was
calibrated against a number nobody had put beside it.** `setGpsFix` gates the
accepted position at `GPS_STEP_M`, a flat 5 m. The engine accepts any fix up to
**HDOP 5.0** (`_validate_gps` in `engine/ipc/handler.py`). At HDOP 5 the
horizontal error is roughly `5 x 5 = 25 m` at one sigma, so a receiver standing
still on a mediocre fix produces jumps several times the floor, and every one of
them was accepted as travel. Both numbers were defensible on their own and
together they left a gate that a poor fix walks straight through.

`gpsStepFloorM(hdop)` derives the floor from the fix being judged:
`max(GPS_STEP_M, GPS_UERE_M x HDOP)`, with `GPS_UERE_M = 5` written down as the
conventional figure for a single-frequency consumer receiver and labelled as an
assumption rather than a measurement of this hardware. A fix good enough to be
worth 5 m of precision has HDOP near 1 and behaves exactly as it did before; a
poor fix now has to travel as far as its own stated error. The same floor gates
the recorded track, where it matters more: the marker crawling is a nuisance for
as long as someone is looking at it, while a track that records scatter as route
is handed to the localizer as the baseline it multilaterates from and then to the
report as the distance surveyed.

One sigma, not two. At two sigma a vehicle genuinely moving at walking pace under
a poor fix would never register, and the floor would be deciding the survey
rather than filtering it. The cost in the other direction is real and is stated
in the code: on a slow walk with a bad fix the marker holds still longer than it
used to. That is the correct direction for this tool to be wrong in, and the
quality it is reacting to is already on screen in the GPS tile as "HDOP n.n".
Five tests, three of which go red against the flat floor.

**Sixty-four glows, and none of them arrived in one change.** Zero-offset
shadows across thirteen files, three CSS tokens, a `glow` keyframe, a `boxShadow`
animation breathing around the engine-status pill, two blurred MapLibre line
layers, a `drop-shadow` filter under the vehicle and an `animate-ping` disc
expanding out of it twice a second. That is what a dark tactical theme becomes
when each new control is given a halo because the one beside it has one, and
nothing anywhere says whether that is a convention or an accident.

Removing them cost no information, and that was checked rather than assumed:
every glow sat on an element that *also* changed its colour or its border with
its state, so the dot, the text and the word were already saying what the halo
was saying. Two places were given a stronger non-glow signal anyway, because the
glow had been doing real work at a glance: the engine pill's border was `/30` in
all three states and is `/70` while scanning, and the vehicle's scanning
indicator is now a static ring instead of a pulse --- it was the largest moving
thing on the map, animating over exactly the ground the operator is reading.

The map lost the most. The track was a 4px line with a 12px blurred copy beneath
it at 0.2 opacity, which on a dark basemap spread the route into a soft band
several times its own width --- a width that means nothing, on a map whose entire
subject is where things are. One 3px line now, and the same change in the report's
interactive map, which had the same pair.

`npm run check:glow` keeps it out, and draws the line where the complaint was: a
shadow with an *offset* is depth, so `shadow-lg` and the `drop-shadow-md` that
keeps a label legible over a map are not flagged. The first version of the check
failed on its own rationale --- it skipped comment lines beginning with `*` or
`//`, which is not how the block comments in this codebase are written, so the
paragraph explaining the removed `animate-ping` was read as an `animate-ping`.

### Phase 24: refactoring, starting with what the duplication was costing

Measuring the codebase for a refactor found two defects rather than two
inconveniences, which settled the order: close the leaks first, tidy second.

**There were two definitions of "is this access point the one to look at
first?"** The report's map derived it from the rule set --- `assessAccessPoint`
then `worstOf`, HIGH or above --- under a comment reading *"so a marker's colour
and its row's severity cannot disagree"*. The live map asked
`is_vulnerable || encryption === 'OPEN'`. Those are different questions, and the
gap is not a corner case: it is every access point the rule set judges on
evidence the engine never set a boolean for. A WEP network was **green on the
screen the operator surveys from and red in the document made from the same
data**, and MAP FILTER → RISK kept different sets on the two maps. The report map
had been fixed and the live map was never brought along, which is what happens
when a rule lives at the call site --- it was spelled out seven times across two
files in three versions. `isHighRiskAp` is the one call now, with six tests built
from rows where the two definitions *disagree*, because a fixture of rows where
they agree would have passed throughout.

**There were two uncertainty overlays, and this log wrote the second one.**
Phase 20 added `src/lib/mapUncertainty.ts` for the live map, with a header saying
its whole point was that the live map and the report "cannot drift into
disagreeing about the same mission again". `ReportMap` had carried a complete
overlay since before that: different layer ids, a fill the live one deliberately
omits, its own feature builder, and a different answer to the overlapping-rings
problem --- `RING_LIMIT_M` against an OFF / HOVER / ALL control. Nobody noticed
because the two files are three thousand lines apart and each looked right alone.

One builder now, with the limit as a parameter: the report passes `Infinity`
because it has the control, the live map keeps the constant because every ring is
on screen at once. Both reasons are written down, because this is a real
disagreement between two surfaces and not an accident to be flattened.

Merging it immediately surfaced a defect neither copy could have shown on its
own. `ap-mirror-point` is a circle layer over a source holding the joining lines
as well as the candidates, and **MapLibre draws a circle layer at every vertex,
not only at Point features** --- so a 7px hollow candidate ring sat on the
*primary* pin of every ambiguous access point, in the figure whose job is to tell
the two apart. It is one `filter` line, and it was only available because the
shared builder tags each feature with its `kind`; the inline version carried no
such tag, so there was nothing to filter on and nowhere for the bug to be caught.

**`src/lib/report/archive.ts` had become the place everything lived.** 905 lines and 55
exports, of which the live map, the target drawer and the uncertainty overlay
needed a dozen --- and reaching them meant importing a module that pulls
`engineIPC` and `scopeDB`, so formatting a radius dragged the sidecar bridge and
the SQL plugin into the dashboard, and testing the overlay needed both stubbed.

Two clusters left it, each moved verbatim and re-exported so the compiler
verified the move and no call site changed:

  * `src/lib/apRisk.ts` --- turning a stored row into the rule set's input and
    reading its output back. That is a bridge to `riskEngine`, not archive
    wording, and it is where `isHighRiskAp` belongs.
  * `src/lib/position.ts` --- a position, what it is worth, and how to draw it:
    which estimator produced it, the radius, the second candidate, the ring.
    `RING_LIMIT_M` came here too, out of `src/lib/report/surveyMap.ts`, which was pulling
    MapLibre's stylesheet into the overlay module for one number.

Neither touches Tauri, MapLibre, jsPDF or the DOM, and that is the property worth
keeping --- it is what lets the screen and the document describe one position the
same way. `archive.ts` is 578 lines, and no component or shared module imports it
any more.

**What was deliberately not done.** `buildAndSavePDF` is still 2,715 lines inside
a 5,308-line file, and `scripts/pdfdiff.mjs` was written for exactly that split
and documents the method --- extract a section, check the document is
byte-equivalent, repeat. Three of nineteen sections are out. It is the largest
win available and it was not started here, because the two leaks above were
shipping wrong colours and a spurious ring today. `IntrusionPage.tsx` (3,527
lines, one function) and `SettingsPage.tsx` (3,452) are untouched for the opposite
reason: they are the biggest files with the weakest safety net, since neither has
a component test, and churning them buys structure at the cost of the only kind
of defect this project cannot tolerate.

### Phase 25: the PDF builder, one section at a time

`buildAndSavePDF` was 2,715 lines inside a 5,308-line file. It is **267 lines**,
and all nineteen of the document's sections are modules under
`src/lib/report/sections/`. `ReportsPage.tsx` is 5,308 → 2,893.

**The gate was validated before it was trusted.** `scripts/pdfdiff.mjs` was
written for this refactor and says so; its `--self-test` compares a file with
itself, expects IDENTICAL, then flips one character and expects that to be caught,
because *a diff tool that always says IDENTICAL is worse than no diff tool*. Then
`export-smoke-test.mjs --write-baseline` drove the real application --- dev build,
sidecar online, a report selected from the archive, PDF REPORT clicked, the file
caught through CDP's download behaviour --- and captured the current output as the
baseline. The committed one predated Phases 20 to 24 and would have reported
legitimate changes as regressions.

Then, **before changing anything**, the harness was run again without
`--write-baseline` and reported IDENTICAL. That round trip is what makes the rest
of this mean anything: it proves the loop can say "nothing changed" about code
that did not change.

Eleven cycles followed, each extract → `tsc` → build → export → compare, every one
IDENTICAL: cover (358 lines), executive summary (404), engagement scope (159),
audit trail (125), survey coverage (272), evidence register (92), prioritised
findings (158), rogue assessment (184), WPS exposure (116), per-archive detail
(230), credentials (106), retest delta (125), footer (59), table of contents (89),
integrity stamp (34).

**Half of it was being verified against a document that did not contain it.** The
pinned baseline archive was `NODE-192-168-137-1-...`, which is an `INTRUSION`
report --- so survey coverage, the rogue assessment, WPS exposure, position
quality and the wireless half of the per-archive detail were never drawn in any of
those comparisons. Six extractions had `tsc` behind them and nothing else, and the
gap was *documented* in this entry before it was noticed to be load-bearing, which
is the kind of note that reads as rigour right up until someone checks it.

Closing it needed a before-and-after on a wireless archive. The pre-extraction
`ReportsPage.tsx` was restored from the working copy kept at the start, a wireless
baseline captured from it (36 text streams, 5,285 strings, against the LAN
report's 16 and 1,547), the refactored file restored, and the comparison run:
**IDENTICAL**. Both document shapes are now verified, and the committed baseline is
the wireless one because it is the larger net. The LAN shape has to be re-checked
with its own baseline when this is next touched:

    node scripts/export-smoke-test.mjs --report <an INTRUSION archive> --write-baseline

**Three sections return something a later one needs**, and those were the real
finding rather than the line count. `credentialsPageNum` (section 11 → the footer,
which stamps a page carrying real secrets differently), `saveName` (section 15 →
the save, the evidence note and the notification) and the pre-stamp digest
(section 16 → the archive record) were `let`s and `const`s in a 2,700-line
closure, set in one place and read several hundred lines away. They are parameters
and return values now. `reportIdStr` was the same shape and worse: it was computed
*inside* the cover block and read afterwards by the page headers and the filename,
so extracting the cover took a shared value with it.

`discloseCredentials` and `baselineId` became parameters rather than `ReportData`
fields for a different reason: they are properties of *this export* and not of the
archive. The same data exports masked or disclosed, with or without a comparison
baseline, and a reader has to be able to see which one they are holding.

**This reverses a decision that was written down.** The builder's own note read:
the remaining sections "were left here deliberately --- what remains is jsPDF
drawing calls and report prose, so moving them buys navigability and not
testability". The first half is right and the second half stopped being the point.
Navigability *is* the maintenance cost in a 2,700-line function. The note now lists
all nineteen and says what the gate was.

### Phase 26: the other three documents, and what they disagreed about

The PDF was never the only thing a client receives. The CSV, the KML and the
GeoJSON came out of `ReportsPage` as ~450 lines of string building that nothing
could assert against --- and unlike the jsPDF sections, these are pure functions
from an archive to text, so extracting them buys testability rather than only
navigability.

**They disagreed about which access points have a position.** Three
implementations of one question, written at three call sites:

| export | rule | an access point at `0, 0` |
|---|---|---|
| KML | `coordinatePair` | dropped |
| GeoJSON | `typeof === 'number' && Number.isFinite` | **placed in the Gulf of Guinea** |
| CSV | none; `lat.toFixed(6)` whenever the field was a number | **printed as `0.000000`** |

`0, 0` is the value a NULL latitude decays into, and this project has drawn 189
access points into the Atlantic over it once already --- that is what
`coordinatePair`'s own comment is about. The fix reached the KML and both maps and
never reached the other two exports, because the rule lived at the call site. It
lives in `exports/apRows.ts` now: the position is resolved once, the row carries
`fix`, and all three formatters read it. The GeoJSON would also have exported a
corrupted latitude of 95; it no longer does.

The CSV still lists every access point, positioned or not --- an inventory should
--- but its coordinate columns come from `fix`, so a row the geospatial exports
refuse to draw is blank there instead of claiming `0.000000, 0.000000` as a
measurement.

**Four modules, one suite.** `exports/apRows.ts` (the shared rows, severity, rogue
verdict and position), `exports/csv.ts`, `exports/kml.ts`, `exports/geojson.ts`,
and `tests/exports.test.mjs`. The two geospatial builders return **null** rather
than an empty document when nothing can be placed, because a `FeatureCollection`
with no features and a `<kml>` with no placemarks both open as an empty map, which
reads as "nothing was there" rather than "nothing could be located". The caller
says which.

Two of the fourteen tests were wrong on their first run and the code was right,
which is worth recording. A KML has no bare geometry, so the line joining an
ambiguous pair is a `<Placemark>` of its own and the count is three, not two ---
the assertion now counts `<Point>` and `<LineString>` separately, which is the
claim that actually matters. And WEP is `CRITICAL` in this rule set rather than
`HIGH`; the export reports what the rule set says, which is the whole point of the
test, so the test was corrected to the rule set rather than the other way round.

`ReportsPage.tsx` is 2,893 → 2,587. The PDF gate was re-run afterwards: IDENTICAL.

### Phase 27: two maps, and the fixes that only reached one of them

Measuring the map duplication for a refactor proposal found that the duplication
had already cost something, twice.

**The report's map still weighted a missing reading as the strongest signal.**
The heatmap interpolates `rssi` over -100..-40 dBm, `interpolate` clamps outside
its domain, and `['get', 'rssi']` yields null for an access point with no reading
--- so that access point was clamped to the *top* of the scale and drawn as the
brightest thing on a map of signal strength. Phase 21 fixed this on the live map
by filtering on a `hasReading` property. `grep -c hasReading src/pages/ReportsPage.tsx`
returned **0**: the figure that goes into the document kept the defect for six
phases.

**And the same heatmap was still drawn over the uncertainty rings.** Inserted
with `beforeId: 'aps-low-risk'`, which is under the dots and *over* the rings
registered before them, so at `heatmap-opacity: 0.8` switching it on erased the
overlay and left the confident mark as the only thing visible. Also fixed on the
live map in Phase 21, also never carried across. Both corrections are now in the
report's map, in the same words.

**A third difference appeared while this session was editing both files.** The
track line is `line-opacity` 0.9 on the live map and was 0.8 on the report's,
because Phase 23 removed the glow from each by hand and typed a different number
into the second one. That is the whole mechanism, observed in a single change.

So `npm run check:map` compares every layer the two files define under the same
id --- comments and layout normalised away, since one file wraps every expression
and the other does not --- and fails on any difference not declared in `ALLOWED`
with a reason. There are seven declared entries and they are all the uncertainty
overlay, where the two maps genuinely answer different questions: the live map has
every ring on screen at once and leaves the widest out, while the report has an
OFF / HOVER / ALL control and can afford a fill. Four shared layers are now
byte-identical after normalisation.

It is a stopgap. One implementation is the real fix and that is the next piece of
work; until then this is what notices, and reverting the `hasReading` filter turns
it red with the layer named and the direction stated.

### Phase 28: one definition for the layers both maps draw

`src/lib/map/surveyLayers.ts` owns the track, the access-point dots, the heatmap
and the terrain. Both maps call it; neither defines them any more, and
`check:map` reports `0 still defined in both pages`.

What it does **not** own is as deliberate as what it does. The uncertainty overlay
stays split, because the two maps genuinely answer different questions there --
the live map has every ring on screen at once and leaves the widest out, the
report has an OFF / HOVER / ALL control and can afford a fill -- and
`uncertaintyFeatures` already builds the geometry for both. Interaction stays
where it belongs too: filters, auto-follow, the vehicle and the grouped
unresolved markers are the live map's, `fitBounds`, `focusBssid` and the ring
control are the report's.

**The popups were examined and left split, which is the honest answer.** They are
different designs for different contexts: the live one shows the vendor and the
position qualifier, the report's shows the severity and says "estimated position,
not a surveyed one". Forcing one HTML blob would have been merging presentation
to make a number go down. What *was* shared is the claims, and two of them had
not reached the report's popup:

  * the reading printed as `${escapeHtml(props.rssi)} dBm`, and `escapeHtml` maps
    null to the empty string --- so an access point with no reading showed
    " dBm", a blank where a measurement goes. It is `n/r` now, as everywhere else;
  * the ambiguity said there were two candidates without saying how far apart,
    which is the number that tells a reader what the ambiguity costs.

**The check changed its own premise halfway through, and the first version of
that change lied.** Once a layer lives in the shared module it is identical by
construction, so `check:map` had to stop comparing those and start counting them.
The first attempt computed "still duplicated" as the intersection of the two
pages --- which read **0** the moment the live map was rewired and the report's
had not been. A progress number that says "done" half way through is worse than
none. It counts the shared module's layers that either page still defines for
itself.

`MapView.tsx` 1,457 → 1,297. `ReportsPage.tsx` is 2,510 with the map still inside
it; pulling `ReportMap` out into its own file is the obvious next step and was not
done here, because it is a move rather than a merge and this entry is about the
duplication.

**What is still not verified.** `MapView` and `ReportMap` have no component test
and MapLibre does not run under jsdom. The report's map is covered end to end by
`export-smoke-test` because it reaches the PDF, and that reported IDENTICAL after
every step here. The live map has `check:map`, `tsc` and the build, and nothing
that draws it --- so the layer definitions are proven equal to the ones that were
there before, and that they still render is not proven by anything but opening it.

### Phase 29: a move, and a net that turned out not to be there

Two pieces, and the second one is mostly about being wrong.

**`ReportMap` is its own file.** 620 lines that were the last fifth of a page
about exporting documents, with nothing to say to the rest of it. A move rather
than a merge --- the layers it shares with the live map went to `surveyLayers.ts`
in Phase 28 --- and what is left in it is what makes this map the report's:
framing the archive with `fitBounds`, flying to a selected access point, the
OFF / HOVER / ALL ring control and the paint that control makes affordable.
`ReportsPage.tsx` is 2,510 → 1,881.

`check:map` passed immediately afterwards, and should not have: it was still
reading `ReportsPage.tsx` for the report's layers, found none, compared nothing
and reported PASS. **A check that is satisfied by its subject disappearing is
worse than one that fails.** It asserts each file defines at least one layer
before comparing anything, and pointing it back at the wrong file now produces
`defines no map layers at all / Comparing nothing is not a pass`.

**The TLS certificate panel came out of `IntrusionPage`,** which is the first cut
into the 3,527-line file. It was chosen by measurement: of the forty-odd JSX
blocks in that component, this one references almost nothing from the page around
it --- it is a function of one object --- and `IntrusionPage` has three component
tests rendering it, so the move looked like it had a net under it.

It did not. The module header was written saying
`tests/components/tlsPanel.test.tsx` already covered it. That file drives the
*TLS inspection* panel --- the button, the NEGOTIATING state, the inconclusive
checks --- which is a different block three hundred lines away in the same drawer.
Feeding the extracted panel an empty object left **all 76 component tests green**.

That was found the only way it could be: by deliberately breaking the extraction
to watch the net catch it, which is the same discipline the PDF refactor used and
the reason it is worth doing on every move rather than on the ones that feel
risky. The claim was removed from the header and replaced with what happened.

`tests/components/tlsCertificatePanel.test.tsx` is the net now, and it exists
because the panel became a function of one prop --- which is the whole return on
the move. Eleven tests: the grade bands A+ to D, pinned because nothing else
states them and a summary a reader trusts without opening the findings underneath
it must not drift; that an **empty findings list is not a clean certificate**, so
the grade drops to A rather than staying at A+; that an absent expiry figure
renders no badge rather than a zero, since 0 there reads as "expires today"; and
that an absent cipher audit renders nothing rather than an empty bar that reads as
clean. Breaking the `isClean` branch turns one red.

One assertion in it was wrong on the first run and the code was right: the panel
counts weak ciphers and flags them without naming them. That is a deliberate limit
of the card --- the operator opens the engine's own output for which cipher --- so
the test now asserts the limit rather than inventing a feature.

`IntrusionPage.tsx` is 3,527 → 3,408. The remaining blocks were measured for
coupling at the same time: the traceroute rendering (~100 lines, one reference
each) and the SMB share enumeration (148 lines, seven) are the next clean cuts;
the subnet selector (109, seventeen) and the dirbuster block (188, nineteen) are
not, and would need state moved before the JSX is worth touching.

### Phase 30: closing the thing that kept producing the same defect

Asked whether the code was in good shape now, the honest answer was that every
time this session measured something for a refactor it found a live defect --- and
measuring once more, to answer that question, found a fifth. It was the same
defect, in the two surfaces the previous fix had not reached.

**The scan feed's HIGH RISK filter excluded the radios the map was drawing in
red.** It gated on `entry.ap.is_vulnerable`, so an access point the rule set rates
CRITICAL without the engine having set that flag was a red dot on the map, a red
row in the exported document, and **absent from the list** when the operator
filtered for the ones worth looking at. Its SSID colour and its own RISK badge
disagreed with each other for the same reason.

**The target drawer refused to act on it.** Status dot green, the warning
paragraph about an immediately exploitable protocol not rendered, and the AUDIT
button `disabled` --- for a radio the rest of the application was treating as
critical.

And the file that had just been fixed still had three more. `ScanFeed.tsx` was
corrected, the build was green, and a grep afterwards found the compact view
carrying the same flag in three more places. **Fixing instances does not
converge.**

So `npm run check:risk-claims` makes the next one a failed build. It flags a read
of `is_vulnerable` or `wps_enabled` that lands in an expression picking a risk
colour, assigning a severity, disabling a control or answering "is this high
risk"; `riskEngine.ts`, `apRisk.ts` and the modules that *write* the columns are
exempt, and reading these fields to state an observation stays fine --- "this
access point advertises WPS" is a fact the engine measured.

It was validated the only way that means anything: all four historical defects
were reintroduced at once, and it produced four failures, each naming what the
read was being used to decide.

**Its first version was too broad, and both of its hits were correct code.** It
also watched `rogue_verdict` and `rogue_score`, and flagged the scan feed for
rendering the engine's own rogue verdict as a badge, and `assemble.ts` for
carrying a score into a struct whose `severity` on the next line comes from the
rule set. A verdict the engine computed and the document prints is a measurement,
not a judgement made at the call site; and the three-line window was blaming a
struct literal for its own next field. The field list narrowed to the two booleans
that invite `flag ? red : grey`, and the window now extends only across lines that
end in an operator.

That is roughly the rate for guards written in this session --- one correction
each, almost always on the first run or when deliberately broken to see whether
they bite. The checks earn their place anyway: this one turns a defect that took
four phases and a refactor to notice into a build failure.

### Phase 31: the maps become testable

The two maps had no component test between them, and the reason was structural
rather than neglectful: the real MapLibre needs WebGL, jsdom has none, so the
pages holding a map threw on construction. Every claim those two surfaces make to
an operator was checkable only by opening the application.

`tests/components/stubs/maplibre-gl.ts` **records calls and draws nothing.** That
distinction is the whole design. It does not simulate tiles, projection, layer
ordering or hit testing, because a stub that pretends to render gives confidence
in the stub. What it does is keep every `addSource`, `addLayer`, `setData`,
`setFilter`, `setHTML` and `setStyle`, and let a test fire `error`, `load` and
`styledata` by hand --- which is what makes a state machine driven by events that
never arrive in jsdom into an ordinary assertion.

`vitest.config.ts` already stated the rule this has to satisfy: the only things a
component test may stand in for are the ones a browser cannot provide. WebGL
qualifies; the risk rule set, the archive readers and the palettes stay real.

**Six popup builders had zero assertions between them.** The only mention of
`setHTML` anywhere under `tests/` was a sentence in a comment. A popup is where
this application makes its most specific claims --- this radio is here, to within
this radius, and there is or is not a second position that fits equally well ---
and two defects were found in those builders this session by reading them, which
is not a method that scales. Nine tests now cover what the live map says: that a
reading which does not exist is `n/r` and never a blank before " dBm"; that a
position with no radius says so; that an ambiguous one states how far apart the
candidates are rather than only that there are two; that an SSID cannot close a
tag; that an unresolved access point is not plotted as a position; that the dot
carries the rule set's verdict rather than the engine's boolean; and that `0, 0`
is an absent column.

**The basemap fallback had four paths into degraded state and no test on any of
them.** A start with no network, a style-level failure, a source-level failure
with a 1.5-second grace period, and an 8-second watchdog for a request that hangs
instead of failing --- the conditions this tool is built for, verified until now
by taking it somewhere with bad signal. Eight tests with a fake clock cover them,
including the two that are easiest to get wrong in opposite directions: one bad
tile must **not** drop a working basemap, and a style that will never load must
**not** be given a grace period, because the operator would be staring at a blank
panel through it.

The property asserted most deliberately is the banner's second line. A degraded
basemap is a broken picture, not a broken scan, and an operator who reads
"BASEMAP DEGRADED" and stops surveying has been misled by this application.

Both files were validated by breaking what they watch: removing the null-reading
guard fails the popup test, lengthening the watchdog fails the hang test, and
dropping the grace period to zero fails the bad-tile test.

**The stub recursed into itself on first run.** `export const Map = FakeMap`
shadows the global `Map` inside that module, so `new Map()` in the recorder
constructed a FakeMap, which constructed a FakeMap. The error pointed at a field
initialiser rather than at the name, and it took a stack trace to see. The native
constructor is captured before the export now.

Component tests: 12 files / 87 tests → **14 / 104**.

**What this does not do.** The stub proves the component asked for the right
layers with the right paint and said the right things in its popups. It cannot
prove any of it appears on a screen, in the right place, in a readable colour ---
jsdom has no layout engine, so the two layout defects this session found by
screenshot (a caveat line over the scale bar, a key panel over the filter buttons)
would still have shipped. That gap is real and is not closed by this.

### Phase 32: one baseline per document shape

The PDF net held one baseline, pinned to one archive, and a wireless survey and a
LAN sweep draw different halves of the document. So it checked about half the
builder, and which half depended on which archive happened to be pinned.

That was not theoretical. Eleven sections were extracted in Phase 25 against a
pinned `INTRUSION` report, so the survey figure, the rogue assessment, WPS
exposure, position quality and the wireless half of the per-archive detail were
compared against a document that did not contain them --- six moves with `tsc`
behind them and nothing else. Closing it needed a second baseline captured by
hand, which is a step that gets forgotten, and had already been forgotten once.

**The measurement, now that both exist:** the wireless document holds **1,455
strings the LAN one does not**. That is what a single pinned archive was leaving
unwatched.

`scripts/baselines/` holds one PDF per archive and an index of the pins. Every
pin is exported in a single app launch --- the launch and the sidecar wait are the
expensive parts, not the export, so the second shape costs about a minute rather
than doubling the run --- and a difference in any of them fails. `--report <id>`
now requires `--write-baseline`, because on its own it meant "compare against a
different survey", which is the outcome the pin exists to prevent.

Three things were checked by making them happen rather than by reading the code:

  * **A change to a wireless-only section is invisible to the LAN archive.**
    Renaming the POSITION QUALITY heading produced `1 DIFFERENCE` on the wireless
    baseline and `IDENTICAL` on the LAN one. That is the whole case for the
    change, demonstrated rather than argued.
  * **A pin with no recorded baseline is not a pass.** It reports
    `NO BASELINE RECORDED` and exits 3 --- the same code the harness already used
    for "nothing to compare against", because a release script reading exit 0 for
    a comparison that never happened is the worst outcome available here. The
    condition is not hypothetical: it is the state the moment the pin set grows.
  * **Each export waits for its own file.** Taking the newest PDF in the download
    directory would hand the second comparison the first document whenever the
    second had not been written yet --- a difference reported against the wrong
    archive, which is worse than a timeout.

One thing the first attempt got wrong: the demonstration was tried first by
renaming the **WPS EXPOSURE** heading, and *both* documents differed. The LAN
report carries a WPS entry in its table of contents even though the section body
is wireless. The two shapes overlap more than "half the document each" suggests,
and a demonstration has to pick a string that is genuinely in only one of them.

### Phase 33: nets under the two surfaces that were changed without one

Phases 22 and 30 corrected four claims in the scan feed and the target drawer ---
the HIGH RISK filter, the SSID colour, the DIRECTION dial's caveats and the AUDIT
control --- and all four shipped with nothing checking them. `check:risk-claims`
stops the same mistake being *made* again; it says nothing about whether the fix
was right.

Writing the tests found a sixth instance of the family.

**The feed substituted -90 dBm for a reading it did not have.**
`rssi: ap.rssi || -90` --- and `||` is worse than `??`, because it discards a
genuine 0 as well. The map popup was fixed for exactly this, and its comment calls
it "the display-side twin of the `rssi ?? -90` write bug the signal-band tests
exist to hold". The feed kept it, and the feed is the list an operator reads while
driving.

It was not only a label. That value **sorts the list**, so a radio heard without a
usable reading was ranked among the weakest signals rather than held apart from
them. The reading is `number | null` now, the sort puts nulls last because "not
measured" is not a position on the scale, and the figure reads `n/r`.

**Two things the tests got wrong before the code did.**

The feed has two views and they do not say the same things: the compact list is
what is on screen while driving and carries the name, the security and the
reading; the table is the expanded view and adds the modelled range and the
position radius. Assertions written against one were failing against the other.

And the rows are wrapped in `AnimatePresence`, so a filtered-out row stays in the
document while it animates away --- an animation jsdom never finishes. Counting
present elements therefore reports the pre-filter list for ever, which reads as
"the filter does not work" and is a test artifact. The assertions use the feed's
own `N entries` count, which is both reliable and the number an operator reads.

**The drawer needed a router.** `useNavigate` is called at the top of the
component because the AUDIT control navigates to the intrusion page. It is
rendered inside a `MemoryRouter` rather than having `useNavigate` stubbed away,
since stubbing it would stop the test covering the one thing that button does.

Sixteen tests across the two files, each validated by putting the defect back:
restoring `|| -90` fails the reading test, restoring `is_vulnerable` fails three
of the feed's filter tests and two of the drawer's, and removing the unresolved
caveat fails the dial test. The drawer's AUDIT control is asserted in both
directions, including the label --- a button reading **SECURE** is a claim about
the radio, and it was being made from a boolean the engine happened to set.

Component tests: 14 files / 104 tests → **16 / 120**. Of the twenty-five
components, seven now have one.

### Phase 34: the vault and the report's map

The last two surfaces on the list an operator acts on.

**The credential vault had no test, and being wrong there is the most expensive
kind of wrong this application can be.** Its careful distinctions are all one
family: a password cell is empty for four different reasons, and they lead a
reader to opposite conclusions. "The vault is locked" and "nothing was recovered"
are opposite statements about the same network. A row whose ciphertext fails to
authenticate has been *altered*, which is not a row that was never stored. And a
vault that looked uniformly encrypted while some rows were still cleartext on disk
would be, in the drawer's own words, "the same kind of untruth as an unflagged
simulation".

Nine tests cover those four states and the controls that follow them --- reveal
and copy are withheld where there is nothing to read, because a copy button that
silently puts an empty string on the clipboard is a way to lose a finding between
the tool and the report.

Two things about how they are written. The fixtures are **rows**, not hydrated
credentials: `hydrate` in `credentialDB` is what decides readable / locked /
absent / altered, from the key being in memory and the ciphertext
authenticating, and handing the drawer a pre-decided `locked: true` would assert
only that it renders what it is given. And the **crypto is real** --- the altered
case needs an unlocked vault, so the test derives a key with PBKDF2 at 600k
iterations, seals a secret and then hands the drawer a mismatched IV. A stubbed
crypto layer would be deciding the answers the test is checking. It costs a few
hundred milliseconds once.

**The report's map now has the data coverage `check:map` cannot give it.** That
check holds the two maps' layer definitions to each other; it says nothing about
which access points reach the source, with what properties, under which filter.
Nine tests: the rule set's verdict rather than the engine's boolean, the
`hasReading` filter this map carried the defect on for six phases, `0, 0` as an
absence while the equator stays a place, rings and the second candidate in their
separate sources tagged by `kind`, and a mirror flag with no stored coordinates
drawing no second candidate.

One of them pins a difference rather than a sameness: this map draws **every**
radius however wide, because it has an OFF / HOVER / ALL control, while the live
map leaves the widest out. That is why `uncertaintyFeatures` takes the limit as a
parameter, and it is worth a test so the parameter is not "simplified" away.

**The stub was missing `isEmpty` on its bounds**, which the report map asks before
framing --- an archive with nothing positioned must not be fitted to an empty box.
Nine failures with one cause, and a reminder that a recording stub still has to
model the few methods a component *asks questions of* rather than only the ones it
commands.

Each file was validated by putting a defect back: collapsing the four password
reasons to a blank cell fails five of the vault's nine; removing the `hasReading`
filter and applying the ring limit each fail one of the map's.

Component tests: 16 files / 120 tests → **18 / 138**. Nine of the twenty-five
components have one, and the four surfaces an operator acts on most --- the live
map, the scan feed, the target drawer and the vault --- are all covered now.

**What is left uncovered** is mostly furniture: `TopBar`, `Sidebar`, `KpiGrid`,
`StatusBadge`, `ConfirmModal`, `ExportMenu`, `MissionArchiveDrawer`. `TopBar` is
the one worth doing next --- it holds the coordinate readout, which Phase 22 found
printing "-13.7563°N".

### Phase 35: the coordinate readout and the menu that decides what a document claims

Two more surfaces, chosen because each holds a claim rather than a control.

**The top bar prints where the rig is.** Phase 22 found it rendering
`${latitude.toFixed(4)}°N ${longitude.toFixed(4)}°E` with the hemisphere letters
written in, so a fix south of the equator or west of Greenwich read as
**"-13.7563°N"** — a minus sign and a letter saying opposite things, in the figure
an operator checks most often. `degreesWithHemisphere` has had tests since then;
what had none is that *this bar calls it*. The defect was never in the formatting.

Nine tests: Sydney and New York for the two axes, no readout at all before there
is a fix rather than a zero, `0, 0` as an absence while the equator stays a place,
the three engine states, and the scan controls — pausing sends `stop_scan` and not
a fresh start, because the two are not recoverable from each other by an operator
watching the screen. Restoring the hardcoded `°N °E` fails two.

Writing them surfaced the component's own rule: the WPS button and the pause /
resume controls live inside `{activeMission ? ...}`, so without a mission the bar
offers only "Start Scan" and the archive. Encoding that stopped the tests
asserting against a state the application never shows.

**`ExportMenu` looks like a list of export buttons and is not only that.** It
carries the retest baseline, which is a *setting*: picking one decides what the
next PDF contains. `null` — "No comparison" — is a first-class choice and has to
be visibly selected, because an operator who cannot see that their export compares
against nothing is about to hand someone a document whose silence reads as
progress.

Six tests, including the two halves that give the design its meaning: choosing a
baseline leaves the menu open (`keepOpen`, so the choice can be seen taking
effect) while taking an export closes it, and an unavailable row states **why**
rather than vanishing — an empty list and an unreadable one look identical in a
menu, and the difference decides whether "No comparison" means "you have not taken
a baseline" or "this export may be missing one you did".

**One test could not tell which of two guards was doing the work.** The
unavailable row is protected twice: `disabled` on the element, and an early return
in `choose`. Removing the early return left the test green; removing the attribute
turned it red. Both are now asserted, which is the honest version — a test that
passes because of a mechanism it does not name is a test that will go quiet when
that mechanism is removed and the other one is the only thing left.

Two assertions were wrong before the code was, again: the selected mark is a dot
in a fixed-width gutter rather than an icon, and "disabled" is a `disabledReason`
string rather than a boolean — which is the design, since the row has to carry the
reason.

Component tests: 18 files / 138 tests → **20 / 153**. Eleven of twenty-five
components have one. No application defect was found this round, which is the
second round in a row.

### Phase 36: the documentation caught up, and two of its claims were wrong

A sweep over every document against the current repository. `check:docs` already
passed throughout, which is the point worth taking from this: it holds the
*mechanically checkable* claims, and everything found here was prose outside their
reach.

**The README said Inno Setup 7.** Phase 14 found that number wrong, corrected the
`.iss` header and INSTALL.md, and missed the README --- so it went on telling
every reader to install the wrong toolchain for nine phases, costing nothing until
somebody reaches `ISCC.exe`. It also said "48 test files", which is 75.

That is now `check:installer`'s problem rather than a reader's: the Inno version
has to agree across the README, INSTALL.md and the script. Its first run flagged
the `.iss` for disagreeing with *itself*, correctly --- the file records the
mistake in a sentence containing both numbers, and a check that forced that
sentence out would be deleting the explanation to make itself pass. Lines marked
as history are skipped, with an explicit marker rather than a guess at tense.

**The Phase 11 checklist still said sixteen document sections were inline.** True
when written, false since Phase 25, and it reads as present tense because it is a
checklist rather than a dated narrative. The phase entries themselves were left
alone: they are what happened, and Phase 29 saying "`ReportMap` has no component
test" is accurate about the day it was written and is answered two paragraphs
later in Phase 31.

**Two gaps had no entry.** Both were recorded inside phase narratives, which is
where a reader does not look:

  * **nothing checks that anything appears in the right place.** jsdom has no
    layout engine, so the component suite proves what a surface *says* and nothing
    about where it is drawn --- the two defects found from screenshots this session
    would still ship. The report's figures are the exception, since `check:margins`
    reads the produced PDF.
  * **the accuracy figures come from a simulator**, whose radio model is the
    inverse of the estimator's own. That round trip is what makes the comparisons
    between methods meaningful; it is not knowing what any of them does in a real
    street.

**The component suites were documented as a number.** "76 across eleven files"
told a reader nothing about what any of them held, while every node and engine
test file had a row explaining the defect it exists for. They have rows now, and
writing them exposed the second-order problem: those per-file counts were prose
nothing checked, and **two of the figures were transposed within an hour of being
written**.

So `check:docs` counts them too. That took separating three populations rather
than two --- the component suites were being read as node suites, reporting 43
suites against 23 scripts and a total of 832 against a real 679. They run under a
different runner and have their own total, which is now checked the same way.

The net effect is that `npm run check:docs` verifies 75 per-file counts and three
headline totals where it verified 55 and two, and the documented toolchain version
is held across three files where it was held in none.

### Phase 37: the toolchain number became true, and it still isn't tested

Inno Setup 7 was installed, `installer/lockon-ewac.iss` compiled under it, and the
three documents that name the version now say 7 because that is what happened ---
not because 7 is recommended.

**What the compile establishes.** `ISCC.exe` ran clean: no warnings, no
deprecations, 97 seconds the first time and 58 the second, producing the same
114.1 MB `lockon-ewac-setup.exe` that 6 produced. `MinVersion=10.0` was already
declared, so nothing was given up at the bottom end. Every directive, every
`Source:` line and every path in the script is parsed by that run, which is the
part `check:installer` cannot do from text.

**What it does not establish, and this is the whole point of the entry.**
Everything under `[Code]` --- the prerequisite page, the detection of what the
machine is missing, the uninstall prompt --- runs *during an install* and not
during a compile. The eight manual steps in `docs/TESTING.md` have never been run
against a v1.0.0 build, and they have not been run against a 7-built one either.
So Inno 7 sits at **exactly** the verification level Inno 6 sat at, no higher. A
newer number reads as better-tested, and here it is not.

Noted because the honest version of this is the version that was wrong before:
Phase 14 found the `.iss` header and INSTALL.md claiming Inno Setup 7 while 6 was
what was installed and what the script had been verified against, and nobody had
noticed because nobody had run it. The number is now a record of a compile rather
than an aspiration, and the header says so in the file itself.

**`check:installer` passed while one of its three files was stale.** Phase 36 put
the version under a check precisely so a reader would not be the one to catch
drift, and this change exercised it: dropping one file back to 6 made it fail
correctly. Then it passed with INSTALL.md's prerequisites paragraph --- forty
lines above the build command the rule reads --- still saying 6, because there the
product name is a markdown link and `Inno Setup (\d+)` stops matching the moment
the digits are not adjacent to the name.

The rule was looking for one spelling of a claim prose is free to spell several
ways. Same shape as the brace trap in the same file counting a *mention* of
`[Code]` as the section header: a guard that recognises a pattern rather than a
meaning passes on the first variant nobody wrote a case for. The version now
appears in the summary line on a **pass** as well, since the failure mode both
times was that the number went unread rather than unargued.

That makes the running count four claims across three files, and the second guard
this session to be wrong on its first encounter with real input rather than on a
deliberately broken one.

#### And then `check:margins` turned out to be reading a file nothing writes

Running the whole sweep after the version change is what surfaced it. `check:margins`
passed, as it has every time. It was measuring `scripts/baseline-report.pdf` --- the
single-baseline file the export harness **stopped writing** in Phase 33 when baselines
became one per archive shape. The file stayed on disk, timestamped before the
`scripts/baselines/` directory that replaced it, and the check went on reading it.

This is a worse failure than a vacuous pass, because a vacuous pass usually looks
like one: zero comparisons, zero items, an obviously empty summary. This printed 36
content streams, 11 landscape pages and a widest drawn edge of 281.0 mm against a
281 mm limit --- a detailed, plausible, confident report **about a PDF produced
before any of the last four phases of report work existed**. Nothing about the
output distinguished it from a measurement of the current build. Any column width
typed into the report builder since Phase 33 was unmeasured and would have reported
as clean.

It also exposed a gap older than the staleness: the wireless report was the only
shape this check had ever seen. The LAN document draws subnet sweep coverage and
host tables the wireless one does not --- sixteen pages of tables whose column
widths nothing had ever measured, in the exact class of defect this script was
written for. Both documents measure clean now, which is a result rather than an
assumption: 52 pages across two documents, where the number was 36 across one and
the 36 were historical.

Two refusals were added and both verified by breaking them: a pin whose PDF was
never recorded exits 2 instead of passing on a document it cannot read, and a PDF
with no content streams is a failure rather than the quietest pass available ---
no streams, no rectangles, nothing outside anything.

Pulling the thread found three more stale claims around the same file. The
`test:pdfdiff` self-test was pinned to the deleted PDF by path, so the one check
that validates the comparator before anything trusts it would have begun failing
on a clean machine; it now finds whichever baseline is pinned, since any PDF will
do for a self-test. The CI comment and `check-docs`'s own rationale both still
narrated the single baseline. And `.gitignore` and `docs/TESTING.md` both justified
not tracking it as "a ~17 MB binary", which is wrong by a factor of ten --- the two
baselines together come to **2.3 MB**.

That last one is worth not papering over, because the stated reason was doing work
the real reason should have been doing. 2.3 MB of binary is not an argument against
committing something. The actual reason is that a baseline **is survey data**: it is
the report built from one archived scan on this rig, and committing it would commit
somebody's radio measurements of somebody's street to a public repository. That
reason holds at any size, and it is what both files say now.

**Four stale references, one of them a check reporting confidently on a frozen
file, and all four were downstream of a file move three phases earlier that `tsc`
and fourteen checks all passed over.** A path in a default argument, a path in a
package script, and a size in a comment are not type-checked and not counted. The
sweep that found it was run for an unrelated reason, which is the argument for
running the whole sweep rather than the part that relates to the change.

### Phase 38: a build to actually install, and five things in the way of it

Asked for a 7-built installer to test. Producing one meant building the chain
rather than recompiling the script, and every stage of that chain had something
wrong with it.

**The sidecar was an hour older than its source.** `engine/scanner/vlan_detect.py`
was rewritten at 00:04 and the frozen engine dates from 23:09 the evening before,
so the sidecar carried the *pre-fix* VLAN arithmetic --- the version that reported
10.0.0.255 as the broadcast address of 10.0.0.0/8. Handing over an installer
built from it would have meant handing over a build whose engine disagrees with
the repository, to be tested as though it agreed. Rebuilt from the spec: same 121
`_internal` entries, 1,978 files, and the engine starts and identifies itself.

**`check:sidecar` called a stale copy an exact match.** It compared the sidecar
against Tauri's staging copy by walking both and diffing the *relative paths*, then
printed "Tauri's bundle copy matches the sidecar exactly." Names, not bytes --- and
a stale copy has exactly the same names as a fresh one, which is the only way for
it to be stale. Tauri's build script does not refresh that copy when it is
fingerprint-clean, so rebuilding the engine and not rebuilding the app produces
precisely that state, and this reported a match in it.

It compares digests now, and the executable as well as `_internal`, which was
outside the comparison altogether despite being the one file whose staleness
changes behaviour on its own. First run after the change: `base_library.zip`
differing at identical size, and the staging exe **1,254 bytes smaller than the
one just built**. The release harnesses drive that copy, so until it was refreshed
`test:export:release` and `test:csp:release` were exercising last night's engine
while a passing check said otherwise.

#### The .iss carried a 0x08 byte

The readiness page's offline-basemap probe read

    {userappdata}\com.lockon.ewac<0x08>asemap.pmtiles

--- a literal backspace, in the string and in two comments, from a `\b` escape that an
editing pass interpreted instead of writing. Three bytes, all in this file, none
anywhere else in the repository.

Every layer was satisfied. Inno compiles it, because a control character inside a
string literal is a valid string. `tsc` does not read this file. And *reading* it
finds nothing wrong, because a terminal performs the backspace and renders exactly
the path the author meant --- the defect was invisible by the normal method of
looking. What Inno actually compiled was a probe for a file whose name contains a
control character, which nothing creates, so `OfflineBasemapInstalled` could only
ever return False.

Verified rather than reasoned about: this machine has one, 6.6 MB at
`%APPDATA%\com.lockon.ewac\basemap.pmtiles`, and the wizard would have told its owner
there was no basemap installed. A readiness page that reports a present component
as missing is the same failure as a report claiming a clean result it never took.

The same byte was in the uninstall notes, where it did second damage: it put the
basemap *beside* the identifier directory rather than inside it, which is the
difference between a file `DelTree` leaves alone and one it removes with the
parent. It is inside it, so Yes deletes it, and the prompt never said so --- a
planet extract is tens of gigabytes. The prompt says so now.

`check:installer` grew two rules, both broken on purpose to confirm they bite:
every control character other than tab, CR and LF is refused outright, and the
path the wizard probes is derived from `tauri.conf.json`'s identifier and the file
name `basemap.rs` joins, so a renamed archive or a changed identifier fails here
rather than in a wizard that quietly reports every machine as empty. Four
deliberate breaks, four refusals.

#### Two more, in the same file

**A function named for something it does not check.** `NpcapServiceRunning` ran
`sc query npcap`, which exits 0 when the service *exists* in any state. The
behaviour is right and deliberately so --- Npcap's driver is demand-start, so
stopped is the normal resting state and testing for RUNNING would raise an alarm on
every healthy install. The name was the problem, in the one file whose job is
telling an operator what is actually on their machine. Renamed to
`NpcapServiceRegistered`.

**The kill was issued and the copy began.** `StopLockon` taskkills the window and
then the engine, in that order and for a good documented reason. But `taskkill`
returns when the kill has been *issued*; teardown and the release of the handles the
engine holds on the DLLs inside `_internal` happen after that, and Inno started
copying over them immediately --- so the locked-file failure the whole procedure
exists to prevent was still reachable, in a window too narrow to reproduce on
demand and wide enough to hit somebody once. It now polls the process list, bounded
at two seconds because a wait that outlasts the operator's patience is its own
failure.

#### And the installer shipped a GPL binary with no licence in it

The engine statically bundles scapy, which is GPL-2.0-only; that is why this
project is GPL-2.0-only, and `THIRD-PARTY-NOTICES.md` explains it at length. The
`[Files]` section installed the app, the engine, `_internal` and the wordlists. Not
`LICENSE`. Not the notices. So every installed copy was a GPLv2 distribution
carrying no copy of its licence, and an operator handed this on a USB stick had no
way to learn what their rights to it were, or that paramiko's LGPL relinking
obligation and Npcap's separate proprietary terms existed at all.

Both files ship now, the licence as `.txt` so a double-click opens it, and
`AppPublisherURL` names the repository so the Programs-and-Features entry points at
the corresponding source. Deliberately *not* wired to `LicenseFile=`: Inno's
licence page is an accept-or-quit gate, and section 5 of the GPL says the opposite
--- that nothing requires you to accept it, because it governs copying rather than
use. Shipping the file is the obligation; gating the install on it would misstate
what the file says.

#### What the build is, and what it still is not

`dist-installer/lockon-ewac-setup.exe`, 114.1 MiB, compiled clean under Inno Setup
7 in 67 seconds with no warnings, from a frontend, a Rust binary and a sidecar all
built today, with the staging copy proven byte-identical to the sidecar.

The eight manual install steps in `docs/TESTING.md` have still never been run.
Nothing in this phase changes that, and three of the five fixes above are in
`[Code]`, which is the part a compile cannot reach: the basemap path, the Npcap
rename and the process wait all run during an install and nowhere else. They are
reasoned and reviewed, not observed. The licence files and the uninstall prompt
wording are the parts the compile does confirm.

**Six defects, found by building something rather than by reading it**, in a file
that fourteen checks and a clean compile had passed over for nine phases. The
0x08 byte is the one worth remembering: it was unreadable precisely *because*
reading is how the file gets reviewed.

### Phase 39: a benchmark that measured other people's software

Three questions from a first real install: tidy the readiness page's wording, find
out whether old survey results had been carried into the installer, and put a
measured minimum specification into `docs/INSTALL.md`.

**The readiness page.** The hashcat block wedged a three-line parenthetical
between the first path and the second, so the list of three places to unpack it
did not read as a list. The caveat now follows the list instead of splitting it,
and the basemap block, which had the same shape, was given the same treatment.

**Nothing of the operator's ships.** Worth checking properly rather than
asserting, so the six `Source:` lines were expanded against the filesystem: 1,990
files, 260.8 MB, filtered for anything resembling a database, a capture, an export,
an evidence file or a log. Nineteen matched and every one is third-party sample
data --- matplotlib's toolbar icons, which are `.pdf`, and scikit-learn's iris and
breast-cancer sets. The installed directory confirms it from the other end: no
database anywhere under it. The eleven archives that appeared on first run are the
operator's own `%APPDATA%\com.lockon.ewac\ewac.db`, 121.6 MB of it, which predates
the install and which the installer never touches --- by design, since the
uninstaller asks before removing it.

#### The benchmark was wrong twice, in opposite directions

**First: a mechanism I believed and had not measured.** The archive list is drawn
by `getAllReports`, which runs `SELECT *` and `JSON.parse`s every row's `raw_data`
to render a list of names and dates. That is the right shape for an explanation of
a slow list, and the first run of the harness had just died on a thirty-second
main-thread stall at exactly that screen. So I wrote it down as the cause.

Then I measured it. All eleven archives' `raw_data` comes to **1.94 MB**. Parsing
that is milliseconds. The 121.6 MB database is 414,867 `scan_logs` rows and 29,971
`gps_logs` rows, none of which that query reads. The explanation was plausible,
matched the symptom, and was wrong --- and the stall has not recurred in four
subsequent runs, so what caused it remains unknown rather than solved. `SELECT *`
there is still a design that scales with total archive size rather than with the
list, which is worth knowing and is not what was observed.

**Second, and worse: the harness measured other applications.** The process set is
`lockon-ewac.exe`, `ewac-engine.exe` and WebView2 --- and the sampler selected
WebView2 **by process name**. WebView2 is the operating system's web runtime.
Office, Teams, Widgets and a dozen ordinary programs each run their own, and this
machine had **thirty of them already resident, holding 1,063 MB**, before the
benchmark started.

All of it went into the answer. The harness reported a 2.6 GB peak, twice, with
stable phase-to-phase figures and a tidy breakdown, and roughly 1 GB of that
belonged to software that had nothing to do with this project. Nothing in the
output suggested it. It was caught by checking what was still running after the
run finished and noticing that thirty WebView2 processes had start times from the
previous day.

The sampler now asks Windows for each candidate's `ParentProcessId` and keeps only
what descends from the executable it launched itself, re-derived every tick because
WebView2 spawns renderers as the app runs. It also prints how much it excluded, so
the condition that caused the error is visible rather than silently handled. Peak
on the corrected harness: **1,631 MB**, against 2,639 MB before --- and
2,639 − 1,063 = 1,576, which is the arithmetic working out.

#### What the numbers are

Two runs on the largest survey available, 183 access points, agreeing to **0.3%**:

| | working set | private |
|---|---|---|
| idle | 1.04 GB | 0.78 GB |
| tactical map | 0.96 GB | 0.68 GB |
| **PDF export (peak)** | **1.63 GB** | **1.10 GB** |

Both are published because they answer different questions: working set is what
Task Manager shows, private bytes is what belongs to this application alone. The
sidecar sat at **exactly 141 MB in every phase of every run** --- it loads scipy,
numpy and scikit-learn at start-up and does not grow with the survey. The Tauri
shell is 35-39 MB. Everything else is WebView2.

It is **not CPU-bound**: 1.13 cores at launch and 0.3-0.7 during the export, on a
sixteen-core machine. So the minimum is 8 GB of RAM and a dual-core, and the
reasoning is written down beside it rather than the number alone.

`docs/INSTALL.md` now also carries what the measurement does *not* cover: no live
scan was measured, because that needs radio hardware and somewhere to drive to;
one machine, one configuration; and a start-up figure of 2.2 seconds that is a
*warm* figure, taken on a machine where WebView2 was already resident.

**Two stale size claims fell out of it.** The document said the engine's onedir
output was 162 MB; it is 205 MB, the whole installation is 270 MB and the installer
115 MB. And 27 MB of that 205 MB is unreachable: PyInstaller's scikit-learn hook
pulls in `matplotlib` and `PIL` as optional plotting dependencies, the spec
excludes nothing, and neither appears in `sys.modules` after importing sklearn and
its gaussian process module. Disk and download only, never memory. Not changed
during this phase, because the installer being tested would have stopped matching
the one measured.

**The lesson is the one the project keeps relearning, in a new place.** A
measurement that produces a plausible number, reproducibly, is not thereby a
measurement of the right thing. Both errors here passed every internal consistency
check available --- stable across runs, sensible breakdowns, arithmetic that added
up --- and both were caught only by looking outside the harness at what was
actually on the machine.

### Phase 40: CI failed on two things this machine could not see

The first push went red in both jobs. Neither failure reproduced locally, and that
is the whole character of the phase: both were differences between what CI runs and
what this working copy runs, and both were therefore invisible to every check that
had just passed here.

#### Four source files were never in the repository

`npx tsc --noEmit` passed here and failed in CI with four `TS2307`s naming modules
the Reports page imports --- `src/lib/report/exports/{apRows,csv,kml,geojson}.ts`,
extracted during the Phase 2x refactor and exercised by the `test:exports` suite.

`.gitignore` carried `exports/`. **A gitignore pattern containing no slash matches
at every depth**, so that entry --- written for a top-level output directory ---
meant "any directory called exports, anywhere", and it swallowed a directory of
TypeScript source. Every signal agreed the repository was healthy:

  * `git add -A` skipped them without a word, because adding an ignored file is
    not an error;
  * `git status` was clean, because an ignored file is not an untracked one;
  * `tsc`, the 679 node tests, the 153 component tests and fourteen `check:`
    scripts all passed, because the files are on disk.

The only tool that would have said otherwise is `git check-ignore`, which nobody
runs. `archives/` on the next line had the identical flaw, waiting for the first
`src/.../archives/`. Both are anchored now.

#### The pyflakes step had four branches that had never executed

GitHub runs `shell: bash` as `bash --noprofile --norc -eo pipefail {0}`. The step
began:

    set -o pipefail
    python -m pyflakes engine > pyflakes.txt
    status=$?

`-e` was already on --- the `set -o pipefail` was restating half of what GitHub had
already set --- so the pyflakes line **aborted the step** the moment pyflakes
exited non-zero, and `status=$?` and the four branches below it distinguishing "pyflakes
crashed" from "pyflakes found style issues" from "pyflakes found undefined names"
were unreachable. They had never run.

pyflakes exits 1 for any finding at all. The engine has 39 --- unused imports and
f-strings without placeholders, exactly the categories `requirements.txt` records
as deliberately not gated on --- and **zero undefined names**. So the build failed
under a step titled "No undefined names" because there were unused imports.

Reproducing it needed CI's shell, not this one: run under plain `bash`, the step
passes. Run under `bash --noprofile --norc -eo pipefail`, it dies before the first
`echo`. Written `|| status=$?`, it passes, and still catches a deliberately planted
`logger` NameError inside an `except` block --- which is the exact defect this step
exists for and which once aborted an entire LAN sweep.

#### A check for the class, not the two instances

`npm run check:ci` holds both, and both were verified by putting the defect back:

  * **No source file is invisible to git.** `git ls-files --others --ignored` is
    asked for anything under `src/`, `engine/`, `scripts/`, `tests/`, `installer/`
    with a source extension, minus a named allowlist of genuinely generated files.
    A hit prints the offending `.gitignore` line, because the useful question is
    never "which file" but "which rule".
  * **No `$?` that `-e` will not let you read.** Every exit-code capture in every
    workflow must be written `|| var=$?` or follow a `set +e` in the same step.

Its first version reported "0 exit-code capture(s) checked" and passed --- true,
since the broken form and the safe form are different shapes and the file had
already been fixed. A rule that reports having examined nothing is not a passing
rule, so it counts the safe captures too and says so.

The check runs **in CI** as well as locally, placed first among the repository
checks: a source file hidden from a fresh clone makes every step after it compile a
different program from the one the author has, so it is the finding that explains
the others.

The fix was confirmed the direct way rather than by reasoning: the staged tree was
extracted with `git archive $(git write-tree)` into an empty directory and
type-checked there. Clean. That is the tree CI will see.

**Everything that passed on this machine kept passing while the repository could
not build.** The gap was never in what the checks examined; it was that they
examined a working copy, and CI does not have one.

### Phase 41: the installer gets a home, and two checks were wrong about where they run

The request was to commit `dist-installer/lockon-ewac-setup.exe` so that people who
want the easy path can take it.

**That could not have worked.** The file is 119,685,790 bytes --- 114.1 MiB ---
and GitHub refuses any single file over 100 MiB. Not a warning; the push is
rejected. The second reason outlives the first: git keeps every version of every
file for ever, so an installer rebuilt per release adds its whole size to the clone
permanently, and this repository is already 234 MB. `.gitignore` line 44 records
that 92 MB of build output was once committed before anybody noticed.

A release asset was the better answer to the actual goal anyway. "Easy" means a
download link, and a link is easier than cloning 234 MB of source to find a binary
inside it.

**The build was byte-identical.** Recompiling `installer/lockon-ewac.iss` from the
same application, sidecar and wordlists produced the same SHA-256 as the previous
compile --- `7527db67…` both times. That is worth recording rather than assuming:
it means the digest published for a release identifies the *inputs*, not the minute
the compiler ran, so a reader who rebuilds from the same tree can confirm they got
what was shipped.

`v1.0.0` now carries the installer, and the whole path was verified end to end
rather than trusted: the asset was downloaded back from the release and hashed, and
it matched the digest printed in `docs/INSTALL.md` and in the release notes.

**The digest is checked, because an unchecked one is worse than none.** INSTALL.md
tells a reader to verify the SHA-256 before running a Wi-Fi scanner with a
password-recovery front end that carries no code signature. If that printed value
goes stale at the next build, the reader gets a mismatch on a good download, is
told "do not run it", and learns to skip the step --- which is the single habit
this project cannot afford to teach. `check:installer` compares the documented
digest and size against the built file, and reports **NOT CHECKED** rather than
PASS where the artifact is absent, which is every fresh clone.

#### Two checks had opinions about where they were running

CI went red on the first push, and twice more after that, each time for something
no local run could see.

**The pyflakes step and the hidden source files** are Phase 40's subject and were
fixed there. What Phase 40 could not see is that **fixing them revealed a third
failure that had been queued behind them**: `check:installer` had never actually
run in CI, because the Type check failed first and every later step was skipped.

**And the third one was mine.** `check:installer` resolves the paths in `[Files]`
and skips that when the tree has not been built --- correct, since CI does not build
the app and a check that needs a twenty-minute build is a check nobody runs. It
detected "not built" by asking whether *any* `[Files]` path resolved, which held
exactly as long as every entry was build output.

Adding `LICENSE` and `THIRD-PARTY-NOTICES.md` to `[Files]` in Phase 38 --- committed
files, present in every clone --- made that answer two instead of zero. The skip
stopped firing and CI failed demanding a Tauri binary and a PyInstaller sidecar it
had never been asked to produce.

The flaw is worth naming precisely, because it is not a typo: **the check asked a
proxy instead of the question.** "Did anything resolve" stood in for "is there a
build" and the two agreed only by accident of the file list. They are separated
now --- a committed file must always be present, build output is resolved only when
there is a build --- and the summary states which of the two it did, so a run that
checked nothing says so. Verified in a `git archive` of HEAD with no `target/` and
no `binaries/`.

**Three CI failures, three different mechanisms, one shape.** A gitignore rule that
matched at every depth, a shell option set by the runner rather than the script, and
a presence test standing in for a build test. None was visible from a working copy,
and the fix for each only became visible once the one before it stopped masking it.

### Known gaps, stated plainly

Carrying these openly because a tool whose job is producing evidence should not
overstate itself:

- **Offline cartography: the archive reads, and the last link is unconfirmed.** With no network the map was a flat grey background — markers and track on nothing. A PMTiles archive is now read straight off disk: `basemap_status` and `read_basemap_range` in the Rust host serve byte ranges from one fixed path, the `pmtiles://` protocol feeds MapLibre, and the style is generated from `protomaps-themes-base` against glyphs carried in `public/basemap-glyphs/`. Two narrow commands rather than a filesystem permission, because this renderer holds `sql:allow-execute` and spawns the sidecar, and the project has been removing capabilities rather than adding them — the renderer never supplies a path and cannot influence one. **What is verified:** `test:basemap` (8 tests) proves the style names no host at all, checked over the serialised document rather than over known fields, since the layers come from a package that could introduce a URL anywhere; that tiles come from the protocol rather than a TileJSON URL nobody serves; that the source `maxzoom` is the archive's own; and that every glyph block the style can request is committed. `test:basemap:runtime` drives the built application with all three tile hosts blocked and the HTTP cache disabled, and the app reports `[basemap] archive ready: z0-z15` — so the host, the byte ranges and the header parse are proven end to end on the shipped binary. Two Rust tests cover the base64 encoder, the first Rust tests in this project. **What is NOT verified, and should not be read as working:** that the style reaches the canvas. The honest attempts at that are recorded in `check-basemap-runtime.mjs` because the second looked like it had succeeded — a screenshot pixel passed on a dark map, and then passed again with the archive moved aside, because the map area is dark either way. Settling it needs the map pointed at ground the archive covers, and moving the map needs a handle this application deliberately does not expose. Until that is closed, treat the offline basemap as plumbing that is proven to the data source and no further. `INSTALL.md` says how to produce an extract; the archive is not shipped because the right one depends on where the work is, and the Settings card states whether one is installed, where it goes, and what it covers — "installed" and "covers where you are standing" being different claims.
  **The Settings card printed the coverage as `11.22, 43.75, 11.29, 43.79`** — four bare floats in the order PMTiles stores them, with nothing saying which was which. The one question that figure exists to answer is "does this cover where I am working", and displayed that way it was not information. `describeBounds` gives hemispheres rather than signs and an approximate extent in kilometres, labelled "about" because it is the equirectangular approximation rather than a measurement. Six tests, including the one that keeps longitude scaled by the cosine of the latitude — without it a small northern extract reads as continental.
- [x] **The Inno installer had never compiled, and nothing had ever tried.** `installer/lockon-ewac.iss` is documented in INSTALL.md as a build step and is 511 lines of carefully reasoned script — and `ISCC.exe` refused it with `Error on line 242: Syntax error. Compile aborted.` The cause is a trap the file itself warns about, in one of its own comments: a Pascal brace comment ends at the **first** closing brace, so an Inno constant written inside one terminates it early and the remainder is parsed as code. The hashcat probe's comment contained `{`+`%USERPROFILE}`. Nothing caught it because nothing compiled it: Inno Setup is not on a GitHub runner, so CI cannot, and no human had run the documented command. It compiles now, and produces a 114 MB setup executable. **The second finding is what the uninstall prompt was describing.** It offers to delete `%LOCALAPPDATA%\LOCKON-EWAC` and described it as "CVE snapshot, engine log, and wordlists you uploaded" — omitting `\evidence`, which holds the captured .pcap and handshake files every SHA-256 in every issued report refers to. `DelTree` takes the parent, so Yes has always removed them. An operator passing a machine on would reasonably have said Yes to caches and logs. The prompt now names all four directories and says what the first one is. **And the documented version was wrong**: both the script header and INSTALL.md said Inno Setup 7, while what is installed and what this was verified against is 6. `npm run check:installer` covers the parts a compiler cannot: the version agreeing across four files, every `externalBin` and `resource` Tauri bundles also appearing in `[Files]` — three installers for one product means a second file list maintained by hand, and Inno fails on a `Source:` it cannot find but never on one nobody wrote — the uninstall prompt naming every directory the engine writes to, and that brace-comment trap, statically. Each rule was verified by reintroducing the fault.
- **CVE coverage.** The bundled snapshot is a curated set keyed to the services the scanner fingerprints, not a full view of NVD. Absence of a CVE is not evidence a host is unaffected, and the report says so.
- **Text-mode subprocess output is now decoded explicitly.** Every `subprocess.run`/`Popen` in the engine passes `encoding="utf-8", errors="replace"`. Without it Python decodes a child's bytes as the console's ANSI codepage — cp1252 on a typical install — *strictly*, so one byte outside that range raises `UnicodeDecodeError` from inside the call. That is a `ValueError`, so it slipped past handlers written for `OSError`/`SubprocessError`: it made `_read_arp_cache` return an empty table (narrowing a sweep from 253 addresses to two while reporting normally), and it let the hashcat availability check fail *open*, leaving the Start button enabled with hashcat's state unknown. A Thai or German adapter description is enough to trigger it.
- **Monitor mode cannot be auto-detected on Windows** without disrupting the adapter, so it is reported as unknown. Confirm with a test capture.
- **WPS needs a monitor-mode adapter, and says so instead of reporting zero.** `scan_wps` is now reachable — **SCAN WPS** in the top bar — and WPS is a three-state field: `wps_scanned_at` (migration 013) records that a scan parsed an access point's beacon, which is what makes a `wps_enabled = false` meaningful rather than the column default it used to be. Because WPS is read from the beacon information element, the scan needs monitor mode; on a managed-mode adapter no beacon arrives, and the engine reports the scan **inconclusive** with a frame count rather than returning an empty result. Nothing is written in that case. Only access points whose beacon was actually parsed are marked measured, so the report can state its denominator: "N of M access points were covered by a WPS scan".
- [x] **One engine command is deliberately unreachable; the other five are wired.** This entry spent several revisions describing six dark commands and dismissing three of them as redundant -- "a second source for a number the UI already has". **That dismissal was wrong for two of the three, and wrong in the direction this tool exists not to be wrong in.** `probe_monitor` emits `probe_detected` only when `is_new_client or is_new_ssid`, so a device that probes five hundred times for one network emits once and the PROBES figure frozen on screen is its value at that first sighting; `passive.get_summary` is documented in the engine as "the authoritative record: the feed is rate limited per host, so `event_count` here can exceed the number of lines that reached the UI"; and `get_feed_stats` exists, in its own words, "so a quiet feed is never read as a quiet network". The engine had said all of this plainly and the gaps list had read none of it. Both summaries are now polled every 15 seconds while a capture runs -- the interval the per-host rate limit drifts against -- and once more before the operator stops, so the final figures left on screen are the engine's rather than whatever the last event happened to carry. A client present in the summary with no row on screen is **not** added: its probes were suppressed as repeats of a sighting already listed under another SSID, so inventing a row would show a probe event that never happened, and the corrected counts are what say the activity was higher. Nine tests cover it, and disabling the correction turns three of them red. `reset_auto_attack` is wired too, as a quiet control beside the AUTO-ATTACK CHAIN toggle: it clears `_attacked_bssids`, the set the chain filters against, and without it the only way to retry a target was to restart the engine -- a real dead end, because the usual reason to retry is that the first attempt was made from a worse position and the operator has since moved. **`get_client_summary` is the one left, and this time the redundancy was checked rather than asserted.** `findingsDB.getClientSummary` computes the same four figures with one `SELECT` over the `clients` table that the engine itself writes, which makes the database version strictly better: it survives an engine restart and the in-memory set does not. The only thing the engine's version carries that the query does not is a constant caveat string, and the report already states that distinction in better words -- "Probing means present; it does not mean connected, and the two are never combined in this document." It stays in the handler table and in `EngineCommand` because those two are kept in step so a typo is a compile error, not because anything is expected to call it.
- [x] **`verify_evidence` has a caller now, so the evidence register can say more than "never re-checked".** The command was implemented and hardened engine-side (it refuses a path outside the evidence directory, including a sibling whose name shares a prefix), `verifyAllEvidence` was implemented in `findingsDB`, and the PDF printed a VERIFIED column for a value that was NULL on every row, because the button had been removed from the Reports page as clutter. The missing piece on the real path was a way to consume the reply: the engine echoes back the row id precisely so a caller verifying a whole register can match each answer to its artifact, and nothing could. `engineIPC.awaitKeyed` does that, and rejects on timeout rather than resolving with a default -- a default here would be written down as a verification result, and an artifact that was never checked must not appear in the document as one that was; the caller counts it as `failed` and the card states that separately. The control is an EVIDENCE INTEGRITY card in Settings rather than a report toolbar button, because the register is installation-wide -- the evidence table carries no reliable link back to an archive, which the PDF says in as many words -- so an action scoped to one report would misstate what it did.
  **The card had no state of its own until a run**, which was reported as it looking wrong and turned out to be content rather than layout: a paragraph and a button beside two cards that each show their condition in a badge. Its standing sentence — "until this is run, the report can only state that an artifact was never re-checked" — is true and about nothing when the register is empty, and about a great deal when it is not, with nothing saying which. `getEvidenceSummary` counts the four figures in one query and the card badges them, with `NO ARTIFACTS` as a real answer; a failed verification outranks everything else, because a mismatched digest means a finding rests on an artifact that no longer matches what was recorded. Unhashed files are listed apart from unchecked ones, since a file with no digest can never be verified and counting it as waiting would promise that a run will clear it.
  **The card stopped being a card.** It, the CVE snapshot and the offline basemap were three full-width slabs, each about 400px tall for four to six short facts — and the Settings page has no width constraint, so on a 1920px display that is nearly 1900px wide holding a two-character entry count. Constraining the *content* to a reading column was the first attempt and made it worse: the values lined up and the emptiness beside them became the obvious thing on the screen. The container was wrong, not the contents. They are also one subject — what this rig holds offline and how current it is — so they are one `LOCAL DATA` card of three rows, about 320px, and a row is the shape a wide viewport is good for. Every qualification the three carried is still there, under the row it belongs to. **And the icons were a convention that was only a habit:** three of fourteen Settings headings had one, eleven did not. `check:icons` enforces it, scoped to that page after a first version reported ten more across the app that were all correct — an empty state carries a 64px icon above its heading, and a drawer's sub-section label is not a card title, so `<h3>` does not mean "card heading" and a check that assumed it did was inventing a convention for pages that have their own.
- [x] **The retest / remediation delta is reachable again.** `compareToBaseline` and `createBaseline` were implemented and covered by the database suite, the PDF builder kept its RETEST / REMEDIATION DELTA section, and `baselineId` was a null constant with a comment saying the control had been removed -- so the branch never ran and the document simply did not claim remediation progress, which is the correct failure mode for a missing control. `ExportMenu` turned out to have been built for this and left holding the parts: its `selected` and `keepOpen` fields are documented as existing *for* the retest baseline, and nothing used them. Restoring it was the menu group they were waiting for. It is a setting rather than an export -- each item decides what the next PDF contains, so the group marks the current choice and stays open -- and `null` is a first-class choice shown as selected, because an operator has to be able to see that the export they are about to take claims nothing. Recording a baseline deliberately does not select it: a set of findings compared against a baseline taken from those same findings produces a delta of zero, a true statement that reads as "nothing changed" on the day the work starts. A read failure appears as a disabled row rather than an absence, since an empty list and an unreadable one look identical in a menu and the difference decides whether "No comparison" means "you have not taken a baseline" or "this export may be missing one you did".
- **Deep-inspection results now reach the report.** `vuln_scan`, `smb_enum`, `dirbuster` and `traceroute` all travel the full distance: scored by the one rule set in `assessServiceObservations`, written to `findings` by a listener in `AppShell`, and frozen into the archive's `rawData` so the PDF — which derives every finding from that blob, not from the table — actually raises them. Previously they lived in React component state, and an operator could watch an SMBv1 host appear on screen and then export a document that never mentioned it.
  Three judgments are worth stating. **Traceroute is context, not findings:** "NAT boundary detected at hop 4" describes the shape of the path, not a weakness in it, so it gets a *Network Path Context* section instead of rows in the findings table — the number of findings is a figure management acts on and padding it with routing facts makes the report look worse without making anything safer. **The subject of a dirbuster finding is the host, and the path is a discriminator** (`ServiceObservation.detail`): keying by URL would make one web server appear as one host per responding path in every count the report prints, and *not* discriminating would collapse twenty hits into one fingerprint so nineteen vanish on upsert. **Completeness is carried separately from results:** `dirbuster_completed` now reports whether the wordlist was exhausted, and a scan that was stopped early earns a callout, because a path's absence from the list means something only if it was actually requested. The same applies to `smb_enum`'s `inconclusive` list — a check that never completed is named in the report rather than passing as silence.
  Both engine payloads also name their own target now (`smb_enum_completed` carried none, which made the persist listener dead code and made the report label the result with whichever host happened to be selected — a factual claim about the wrong machine). Covered by `engine/tests/test_result_targets.py` and eleven new cases in `tests/riskEngine.test.mjs`.
  Both are routed now. `deep_ssl_scan` is a TLS panel in the host drawer and `vlan` is a network-level segmentation panel beside the recon summary — see the engine-command entry above for what each needed beyond a button.
  **The segmentation panel's first layout cost the host list its viewport**, which is worth recording because of how it was reported and what it turned out to be. Four subnets came to roughly 470px, and the cards sit in a `flex-1 overflow-y-auto` sibling inside a fixed-height column — so every pixel the panel took came out of their scroll area, leaving the bottom edge of two cards visible. It was reported as the panel covering them. It was not covering them; squeezing looks identical, and a screenshot cannot tell the two apart. The largest single thing on that screen was "(basis not stated)" written out once per value, eight times for four subnets, which I had added for honesty and which was repetition rather than information. It is a one-line summary now — subnet count, gateways answered, whether anything routes between them, and any HIGH finding — opening to a table that caps at about 200px with its own scroll, so a dozen subnets cannot repeat what four did. The qualification is carried once, in a column header and a footnote built from the `vlan_id_basis` and `gateway_basis` strings the engine sends rather than written in the page: a test changes one to "read from LLDP" and requires the footnote to follow. Nine tests pin both directions, because "make it smaller" is exactly the pressure that removes a qualification and the compact version is only an improvement if an inferred VLAN id still cannot be read as a measured one. Leaving the table open turns three red; dropping the footnote turns two. **A HOSTS column was added afterwards and carries the same trap in a new place.** A sweep covers one subnet at a time, so the map routinely lists three ranges nothing has probed — and `0 found` for those would read as "we looked and the VLAN is empty", a claim about somebody's network made from no measurement. A range with no sweep scope says `not swept`, and the count travels with the denominator the sweep recorded, because "2 found" means very different things out of 254 addresses probed and out of 6. Making an unswept range report a count turns one test red. Counting hosts per range also needed a correct answer to which range an address is in, which the page did not have: it compared the first three octets as text, right for a /24 and wrong for everything else in both directions. `src/lib/cidr.ts` replaces it, with nine tests, and `subnetHosts` uses it too.
- [x] **`getEvidenceForBssid` has a caller now: the target drawer.** This entry used to carry a longer list of things that turned out to have been fixed without it moving -- `evidence_refs` is written by `linkEvidenceToFindings`, `getEvidence` and `markEvidenceVerified` have callers, and the PDF has an EVIDENCE REGISTER with filename, SHA-256 and a VERIFIED column. What was genuinely left was the per-access-point view. The register in the document lists every artifact this rig holds and tells the reader to match them to findings by their subject, which is a reasonable instruction for a document and no use at the moment it matters -- standing in front of an access point deciding whether to capture again. That question had no answer anywhere in the interface. It is read on selection rather than cached, because a cached copy would go stale exactly when the operator looks, which is the moment a capture completes; the effect is keyed on the capture state for the same reason. A late answer for a previously selected BSSID is discarded rather than rendered under the current one's heading -- the same mislabelling the deep-scan panels needed an ownership gate for. A read failure says so instead of reporting zero: nothing recorded and a register that could not be read lead to opposite decisions. And the row status has four states, not two, because a NULL `verify_status` is the normal one and means this installation has never re-hashed the file, which Settings -> Evidence Integrity is what changes.
  The register is scoped to the missions in the export now, which it was not: `getEvidence` took only a limit and returned every row in the table, so one engagement's document listed another's captures — path, SSID, BSSID and hash — as the artifacts behind its own findings.
- **Credential vault key handling.** Secrets are now encrypted at rest (AES-256-GCM, key from an operator passphrase via PBKDF2-SHA256, 600k iterations), the key is only ever held in memory, and sealing now runs a `VACUUM` so the cleartext is gone from the file and not merely from the column — it previously survived in freed pages, measured at 300 of 300 recoverable. A database sealed by an earlier build is reclaimed once on the next unlock, and the operator is told, because if that file already left the premises the credentials in it should be treated as exposed. Two limits worth stating: the key is readable by anything that can read this process's memory while the vault is unlocked, and there is no recovery — a forgotten passphrase means the credentials are gone. Rows written before encryption existed stay cleartext until the operator seals them, and the vault counts them so that is visible rather than assumed.
  The vault now covers **both** tables that hold a recovered secret. `cracking_history.cracked_password` — the WPA passphrase hashcat recovered — was written in cleartext, shown in the Decryptor's history table, and untouched by sealing, so the banner could report "no unprotected rows" while every cracked passphrase sat in the file. Migration 017 brings it behind the same AES-256-GCM, `getVaultStatus` counts both tables and breaks the figure out by kind, one "seal the vault" seals both, and deleting a cracking record reclaims its pages immediately — deleting a cracked passphrase is the moment an operator expects it gone. A run that recovered nothing is still recordable with the vault locked, because "this wordlist was exhausted and did not crack it" is a finding with no secret in it; a run that *did* recover one is refused rather than stored in the clear, and the operator is warned **before** the run starts rather than after hours of work.
- **The CSP needs a smoke test before you ship it.** `security.csp` was `null` — no Content-Security-Policy at all — while the renderer holds `sql:allow-execute` (arbitrary SQL, including `ATTACH`) and `shell:allow-spawn`, and renders attacker-chosen strings throughout: SSIDs, hostnames, service banners. Current exposure is low (there is no `dangerouslySetInnerHTML`, `innerHTML`, `eval` or `new Function` anywhere in `src/`), but a policy is the one control standing between a future one of those and full database plus sidecar access. A real policy is now set, allowing exactly the origins the app uses: `basemaps.cartocdn.com` and `*.basemaps.cartocdn.com`, `server.arcgisonline.com`, `s3.amazonaws.com` (tiles) and, until the fonts were brought into the build, `fonts.googleapis.com` and `fonts.gstatic.com`, plus `blob:` workers for MapLibre and `ipc:` for the Tauri bridge. `npm run test:csp` launches the app with WebView2's remote debugging port open, attaches over the Chrome DevTools Protocol, visits every screen, pans the map to force real tile requests, and fails if the policy blocked anything or if a console error appeared. And `src/lib/cspReporter.ts` listens for `securitypolicyviolation` in the app itself, so a violation on a path the harness does not walk still produces a console line naming the directive and the blocked URI rather than a feature that quietly stops working.

  **Corrected in Phase 14, because this entry claimed coverage it did not have.** It said the policy *was* covered and listed two honest limits — a smoke test misses unvisited paths, and it is Windows-only. Both true, and neither was the real one: `npm run test:csp` runs under `tauri dev`, Tauri injects `devCsp` there rather than `csp`, and `devCsp` was unset. So the harness exercised the app with **no policy at all** and reported PASS. Two defects shipped behind that claim — the basemap blocked on a subdomain the policy did not cover, and the webfonts never applying because an inline `onload` is refused by `script-src-attr`. `npm run test:csp:release` drives the built binary and is the only check that touches the shipped policy; `checkPolicyDrift()` refuses to run when `devCsp` is absent or more permissive than `csp`. The limits that remain are the two originally stated, plus this: the dev policy needs `'unsafe-inline'` for Vite, so inline-script faults cannot be caught by `test:csp` by construction.
- **Rebuild the sidecar after every change under `engine/`.** This is in the build instructions, and it is worth repeating here because of what happened when it was missed. A `UnicodeDecodeError: 'charmap' codec can't decode byte 0x90` arrived from the field every half-minute. Every `subprocess` call in the source already passed `encoding="utf-8"`; the traceback contained no engine frames at all, because the failure is inside `subprocess.communicate()`'s own reader thread; and grep across the engine found nothing to fix. The code was correct. The compiled `.exe` was two days old and still contained `subprocess.run(["ipconfig"], capture_output=True, text=True)` with no encoding — `ipconfig` output runs to tens of kilobytes and carries bytes that are not valid cp1252. Nothing in the app, the log or an exported report could say the running binary predated the fix, because the engine reported a hardcoded `"0.1.0"`. There is now a build stamp, and Settings shows it; the two-day gap is the reason it exists.
- [x] **Webfonts are carried in the build.** This line read "still fetched from Google Fonts ... self-hosting the four woff2 files removes the last cosmetic network dependency", and both halves have since been overtaken: they are self-hosted now, and it was never only cosmetic. The full account is in the webfont entry above — what the tool fell back to offline, measured in the shipped WebView2; why a security tool opening a third-party connection at startup is the stronger argument; and the User-Agent that had made this look impossible.
- **CI covers the checks that do not need a built application**, which is most of them: `.github/workflows/ci.yml` runs `tsc`, the frontend suites, the build, `check:severity-css`, `check:docs`, and the engine suite on every push and pull request — 23, 32 files and thirteen `check:` scripts as of this writing, and the counts are deliberately not repeated here because `check:docs` already holds the ones in TESTING.md to the repository and a second copy is a second thing to drift. Both jobs run on `windows-latest` — the engine requires it (`comtypes` is Windows-only and `engine/scanner/wifi.py` imports pywifi at module scope) and the frontend runs there too so CI matches the platform these checks were verified on. **Three checks still need a built application, and all three have now been run against one.** `test:csp:release` and `test:export:release` drive the built binary over the DevTools Protocol, which needs a full `tauri build` plus the PyInstaller sidecar, and `check:margins` reads a baseline PDF that is gitignored because a baseline belongs to the survey it was taken from. Until Phase 15 they had never been executed in this project, which is a different thing from being documented. They were, on `tauri build --no-bundle` plus a PyInstaller sidecar: `check:sidecar` PASS (the only check that starts the frozen engine at all), `test:csp:release` PASS across five screens with zero violations — which is also what confirmed the narrowed `s3.amazonaws.com` path grant against the shipped policy — `test:export:release` IDENTICAL over 1,466 extracted strings, and `check:margins` PASS. A note recorded here when those checks were first run said `check:margins` had "passed with no headroom" at 194.0mm against a 194mm limit, and called it one layout change away from failing. **That was wrong, and is corrected here rather than quietly deleted.** `MARGIN_X` is 16mm and the page is 210mm, so the content box is 16mm to 194mm: a full-width table's right edge is 194.0mm *by construction*, and the checker allows 0.5mm of slack besides. The number was the expected one, not a near miss. The lesson is the one this project keeps relearning in the other direction -- a figure read without the arithmetic behind it is a guess with a convincing shape, and it is no better when the guess is pessimistic.
- **Nothing checks that anything appears in the right place on the screen.**
  jsdom has no layout engine: `getBoundingClientRect` returns zeros, CSS is never
  applied, and two elements that overlap are indistinguishable from two that do
  not. The component suite proves what a surface *says* — that a reading with no
  value reads `n/r`, that an unresolved radio is not offered as a bearing — and
  proves nothing about where it is drawn.

  This is not theoretical. Two defects in this project were found by someone
  looking at a screenshot and would still be: a caveat line printed on top of the
  scale bar, and a key panel opening across the filter buttons. Both were
  arithmetic on CSS values after the fact, which is the weakest form of
  verification used anywhere here. The report's figures are the exception —
  `check:margins` reads the produced PDF and `test:export` compares the document
  string by string — so the gap is specifically the live interface.

- **The accuracy figures come from a simulator, not from field measurement.**
  Every number in the localization section — median error by route shape, the
  share of runs where the radius covered the truth, the 48% wrong-side rate on a
  straight pass — is measured against `engine/scanner/simulator.py`, whose radio
  model is the inverse of the estimator's own. `test_simulator.py` asserts that
  round trip, which is what makes the comparisons meaningful *between* methods;
  it is not the same as knowing what any of them does against real transmitters
  in a real street. The model's own assumptions — a fixed path-loss exponent,
  log-normal shadowing, a transmit power the estimator has to infer — are stated
  in `AP_LOCATION_METHODS.md` §4 and are where the difference would show.

- **The LAN sweep only probes what answers ARP.** A UDP ping sweep forces resolution and the engine waits 1.5 s, but a host that is powered on and silent, firewalled against ARP, or simply slow is never probed. The sweep now reports `addresses_in_range` against `addresses_probed` per subnet so this is visible, and DEEP mode ignores the pre-filter entirely — but on a wireless guest network a /24 still routinely reduces to a handful of addresses.
- [x] **The KML export is a KMZ, and carries its own pins.** The two `IconStyle` hrefs pointed at Google's map-shape images over plain HTTP, so a client opening the assessment weeks later sent a cleartext request to a third party at that moment — an outbound record of when a security report was read. KMZ is the format that exists for this: a zip holding `doc.kml` beside the images it names, opened natively by every viewer and needing no network. The zip writer is in this repository rather than a dependency, because a KMZ needs the oldest and smallest corner of the specification and adding a package for one export path in a tool whose supply chain is part of what it assesses is the wrong trade. Deflate comes from `CompressionStream`; an entry is stored where that is absent, which is a larger file rather than a failed export; Zip64 is refused rather than silently truncated. Twelve tests, and the decisive ones hand the bytes to **Python's `zipfile`** — a writer this project's own code can parse proves nothing, because the bug and the check would share an assumption. Two of those tests exist because earlier ones missed something: corrupting the local header's size left every test green, since an ordinary unzip reads the central directory instead, and the data-URI decode passed with its own branch deleted, because Node's `fetch` accepts `data:` URLs. **That second one was not academic.** Vite inlines an asset below `assetsInlineLimit` as a `data:` URI, both icons are under it, and `fetch()` of a `data:` URI is governed by `connect-src` — which lists `'self' ipc:` and three tile hosts. The first version of this export would therefore have worked under `tauri dev` and been refused in every shipped copy, reported as "icon could not be read" in front of whoever first exported a map. `assetBytes` decodes the inlined form without a request and fetches a file URL, so neither path widens the policy. The artwork is drawn by `scripts/make-kml-icons.py` rather than taken from Google: carrying someone else's map files inside a document handed to a client is a licence question with no good answer. `npm run check:kmz` compares the three places the icon names live — the `<href>`, the archive entry and the file on disk — because a rename touches one and a viewer that cannot resolve a path draws a default pin and says nothing.
- [x] **Bundle size: the main chunk is 1,617 KB, down from 2,510 KB.** Every route was imported statically, so launching to the dashboard parsed and evaluated the whole PDF builder, the report section renderers and the credential vault screen before anything could be drawn. Four of the five screens are `React.lazy` now. The dashboard stays eager -- it is the landing route, so splitting it would move the work rather than defer it, and it owns the map the operator is usually here to look at. The figure rose by 28 KB when the PMTiles reader arrived, which is the whole of that library and the price of the offline basemap. `ReportsPage` is the one that mattered: 594 KB, because it pulls jsPDF and the autotable plugin in at module scope, and it is reached only when somebody exports. IntrusionPage is 148 KB, SettingsPage 129 KB, DecryptorPage 36 KB. The point is startup work rather than bandwidth -- this is a desktop application reading from its own install directory, and a chunk arrives in milliseconds either way. Each route gets its own Suspense boundary rather than one around the shell, which would unmount the navigation and blink the chrome on every move between tabs. `html2canvas` (196 KB) and `purify` (24 KB) were already split out by the exporter's dynamic imports.
- **`src/pages/MissionsPage.tsx` was dead code, and is now deleted.** It was never imported or routed from `src/App.tsx` — a placeholder whose only control was a disabled button under the words "Coming in Phase 2" — so it compiled and shipped in the bundle while being unreachable. Deleting it was chosen over wiring it up because there was nothing behind it to wire. The same sweep removed three unused assets: `public/LOCKON_logo2.svg` (2.0 MB, while all four real uses point at `LOCKON_logo.svg`), and `public/tauri.svg` and `src/assets/react.svg`, both scaffold left over from `create-tauri-app`.
  Worth recording is how nearly the sweep got this wrong in both directions. Searching for a module's name with a leading word boundary hides every relative import, because `'../coverageDB'` puts a `/` immediately before it — which reported a dozen live modules as orphans. And searching by stem rather than by file name hid `public/tauri.svg` entirely, because "tauri" appears in a thousand places that have nothing to do with that file. The 18 files in `public/intrusion_icons/` are the opposite trap: they are loaded as `` `/intrusion_icons/${icon}.svg` ``, so no search for their names can find them. They were cleared by comparing the icon map in `IntrusionPage.tsx` against the directory — 18 against 18, with no name in the map lacking a file, which would have rendered as a broken image.
- **The LAN sweep's ARP pre-filter cannot distinguish a quiet network from a failed read.** `_read_arp_cache` returns `{}` on any exception — `arp.exe` timing out, or a byte outside the console codepage in a localized adapter name — and the sweep then falls back to probing two addresses out of 253 and reports normally. The per-subnet coverage figures make the *narrowness* visible, and the read now reports its own failure: `arp_read_error` is set on a timeout, a non-zero exit and the read-succeeded-but-parsed-nothing case, travels in the sweep's payload, and raises a toast telling the operator to treat that subnet as unsurveyed rather than quiet.
  One thing was still wrong behind that. The device diff is built from the same cache, and it had no guard — so a failed read made `disappeared_devices` every machine seen on the previous sweep: an `intrusion_diff {type: "disappeared"}` naming the whole LAN, manufactured out of a local command timing out, emitted beside the scope event that correctly said the table could not be read. It reports that no comparison was possible, and leaves the history alone — overwriting it with `{}` also cost the *next* sweep its diff, because the emit is gated on the previous scan being non-empty.
- **The ARP-populating sweep is capped at 1,024 addresses per subnet.** Every datagram it sends to an unused address causes an ARP broadcast the whole segment must process, so sweeping a `/16` in full would degrade the network being assessed. Beyond the cap, addresses are never contacted, and that is reported separately from "asked and stayed silent" — in the live feed, in `intrusion_scope`, and as its own column in the report's SUBNET SWEEP COVERAGE table. A `/16` is therefore surveyed at about 1.5% of its range unless it is split into smaller targets.
- [x] **The elevation-tile grant is narrowed to one bucket, and that is now confirmed against the shipped policy.** `csp` and `devCsp` allowed `https://s3.amazonaws.com` outright for a single raster-DEM source, `MAP_TERRAIN_TILES`. That host is S3's shared path-style endpoint: every public bucket in the region answers on it as `s3.amazonaws.com/<bucket>/...`, including one an attacker creates — so the grant was not "a tile provider", it was a large slice of a public namespace, in `img-src` *and* `connect-src`, in the renderer that holds `sql:allow-execute`. CSP source expressions match paths and a trailing slash is a prefix match, so the policy names `https://s3.amazonaws.com/elevation-tiles-prod/` and the rest of the endpoint is closed. **That reasoning stayed reasoning through four release-mode CSP runs**, all of which passed without ever reaching the directive: the terrain source is added only when `enable3DBuildings` is on, and it is off by default. A policy run that blocks nothing proves nothing if nothing was requested. `csp-smoke-test.mjs` now sets the stored config, reloads, and records requests as well as failures — **37 elevation tiles requested, zero violations**, so the path match behaves as read. When no elevation tile is requested at all it says so rather than letting the PASS be quoted as confirmation.
- **The null-session share enumeration's success path has not been exercised against a real server.** The SMB2 exchange is written against MS-SMB2 and MS-NLMP and asserted field by field by `engine/tests/test_smb2_wire_format.py`, and NEGOTIATE plus both SESSION_SETUP legs were verified end to end against a live Windows SMB server during development — which is how the NTLMSSP Version block turned out to be required at all; without it the server answers `STATUS_INVALID_PARAMETER` rather than evaluating anything. That server refuses anonymous sessions, which is the Windows default, so what was exercised live is the *refusal* path. The share loop itself — TREE_CONNECT per share name, reading NTSTATUS for reachable, denied and absent — is verified structurally and from a scripted server, not against a host that accepts a null session. If it is still wrong it returns None and the document says the check was inconclusive, which is the failure mode worth having; it is not the same as knowing it works. Enabling guest access on a machine to find out is not a reasonable thing to do to it.
- [x] **The component-rendering harness covers every interface fix that had no automated test.** `npm run test:components` runs vitest under jsdom against the real components, with only the Tauri boundary stubbed — the SQL plugin, the shell plugin, the dialog and `invoke`, because a browser cannot provide those. Nothing else is: the risk rule set, the archive readers and the palettes are the real ones, since a component test that stubs the rule set proves only that the component calls something. The SQL stub throws on an unscripted query rather than returning `[]`, because `[]` is a *result* in this application and a stub that hands one back would let a test pass against a fabricated clean answer.
  It stays separate from `npm test` rather than replacing it. Those suites drive pure modules, stores and real SQLite under `node --test`; putting jsdom underneath them would make the thing they exist to prove — that the SQL is right against a real engine — harder to trust, and would spend a minute of environment setup on every run.
  Covered: the Passive SIGINT start guard (6 tests), the PMKID terminal listeners (5), the `resultOwner` gate (8), the TLS panel's separation of "nothing was wrong" from "nothing was established" (8), the authoritative passive and probe counts (9), the imported-archive provenance stamp (5), the streaming wordlist decode (5), the BUNDLED badge and its delete guard (6), and the PDF blob-URL lifecycle (4), and the segmentation panel's collapsed summary and its host counts (13), and three Settings cards' state (7) — 76 across eleven files at the time. **It is 153 across twenty now**, and what was added is the part that was missing rather than more of the same: the two maps (through a MapLibre stub, since WebGL is a thing jsdom cannot provide), the scan feed, the target drawer, the credential vault, the TLS certificate card, the top bar's coordinate readout and the export menu's retest-baseline setting — which is to say the surfaces an operator acts on. Phases 31 to 35 have the detail. Every one was verified by restoring the original defect and watching the suite go red, and three of those runs were worth more than the tests they confirmed. **The PMKID pair were vacuous on the first attempt**, asserting that an error releases the button without ever putting the button into the listening state, so they passed with the listeners deleted; they type a BSSID and click now, which is what an operator does. **The passive-SIGINT interface test was named for the interface and asserted only command names**, so the defect it existed to guard — the interface omitted, the engine picking a default adapter while the header claimed otherwise — would have gone straight past it; it records payloads now, and dropping the interface from one call turns it red. **And the shared setup's object-URL recorder had never recorded anything.** It installed itself only when `URL.createObjectURL` was absent, under a comment asserting jsdom implements neither — which is not true of this jsdom — so `objectUrls` stayed empty for every test and any blob-lifecycle assertion would have passed by observing nothing. It wraps unconditionally now and delegates to the real implementation. Writing the blob test also found a latent hang in the application: the cover artwork was awaited on `onload` or `onerror` and nothing else, so a load that settles neither leaves the export pending for ever at RENDERING with no message. A browser fires `onerror` promptly for a missing local file, which is why it had never been seen — but it gates the only control the operator has, and it now has a five-second deadline falling back to a path the export already supports.
- [x] **The dozen interface fixes that had no automated test now have one.** Every suite outside the component harness drives pure modules, stores and real SQLite, which is why the database and risk layers are covered to the degree they are — and it meant a fix living in a page was held up by `tsc` and nothing else. What was pinned instead was the contract each one depended on at the store or library layer, which is weaker than testing the component, and the entry said so. The gap is closed; the list above says what each test covers and what restoring the defect does to it.
