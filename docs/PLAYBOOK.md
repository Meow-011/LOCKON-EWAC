# LOCKON EWAC - Operational Playbook

> **[← Back to the README](../README.md)** ·
> [Install](INSTALL.md) · [Architecture](ARCHITECTURE.md) · [Testing](TESTING.md) · [Troubleshooting](TROUBLESHOOTING.md) ·
> [Engineering log](ENGINEERING_LOG.md) · [Playbook](PLAYBOOK.md) · [AP location methods](AP_LOCATION_METHODS.md) · [GPS & survey](GPS_AND_SURVEY.md)


This playbook documents the internal architecture, data flow, and logic sequences for the core operational modes of the LOCKON EWAC system. Use this as a reference guide when troubleshooting, extending functionality, or understanding how the React frontend interacts with the Python/Rust backend.

---

## 0. READ FIRST — THE ENGAGEMENT SCOPE GATE

**Every flow diagram in this document omits a step.** Before any targeted
command reaches its module, `ScopePolicy.authorize()` runs in
`engine/policy.py`. This section exists because the rest of the playbook did not
mention the gate at all, and a developer following one of the sequences below to
add a module would have shipped it ungated.

**What it does.** Five commands are gated — `auto_attack`, `start_strike`,
`start_mitm`, `start_spray`, `start_bruteforce` — the ones that can disrupt a
network, authenticate against it, or intercept its traffic. Reconnaissance and
capture are deliberately not gated; the reasoning is written out in
`engine/policy.py` above `GATED_COMMANDS`. For each gated command the handler calls
`self.policy.authorize(command, targets, context)` — or `authorize_ap(...)` for
access-point commands, which accepts a BSSID *or* an SSID as the subject. A
denied call emits `scope_denied` plus an `audit_event` row and **returns without
running the module**.

**The properties that matter, all covered by `test_policy.py` (37 tests):**

- **Deny by default.** No scope record means nothing targeted runs.
- **Expiry fails closed.** A scope past `valid_until` denies rather than allows.
- **CIDR containment is subset, not overlap.** `10.0.0.0/24` does not authorize
  `10.0.0.0/8`.
- **Every target must pass.** `authorize()` takes a list; one out-of-scope
  target denies the whole call.
- **Scanning and reconnaissance are deliberately ungated.** Passive observation
  is not a targeted act, and a misdirected port sweep does no harm. Two
  consequences the report now states out loud: an ungated command writes **no
  audit row**, so the audit trail is evidence about the gated set rather than a
  complete log; and findings are not filtered by scope, so a neighbouring
  tenant's access point can appear in a report with nothing marking it as
  out of scope.

**If you add a module that can disrupt, authenticate or intercept**, add its
command to `GATED_COMMANDS` and call `authorize()` before anything leaves the
machine. `describe()` publishes the set and the report generates its claim about
refusals from it, so the document follows automatically. `test_policy.py` pins
both halves of the boundary. A module that emits its own
terminal event only on success will also strand the UI on a denial — the denial
path emits `scope_denied` and nothing module-specific, so either handle that
event or give the UI a watchdog.

---

## 1. WARDRIVING (SCAN)
**Objective:** Passive 802.11 Access Point Discovery & Geolocation mapping with GPS-validated coordinate pinning.

### Flow Sequence
1. **Trigger (`TopBar.tsx`)**: 
   - User clicks **"Start Scan"**.
   - `startMission` is called in `missionStore.ts` to initialize a new SQLite Mission record.
   - IPC payload `{"cmd": "start_scan"}` is sent via `engineIPC`.
2. **Backend Execution (`engine/ipc/handler.py`)**:
   - Python spawns two background daemon threads: `_wifi_loop` and `_gps_loop`.
   - `engine/scanner/wifi.py` continuously triggers active/passive scans on the Wi-Fi adapter via `pywifi`.
   - `engine/gps/reader.py` continuously parses NMEA 0183 sentences from the Serial COM port (e.g., U-blox receiver), extracting lat, lon, altitude, HDOP, satellites, speed, and heading.
3. **GPS Quality Pipeline (`reader.py`, then `handler.py → _validate_gps`)**:
   - Four stages, each of which exists because it was once missing and something wrong was drawn on the map:
     - **Stage 0: Fix validity** (`engine/gps/reader.py`) — GGA's `gps_qual` (0 = no fix) and RMC's `status` ('V' = void) are read. Nothing read them until v1.0.0, and both sentences still carry a latitude and a course when they are saying the position is unusable. A receiver that *loses* lock keeps emitting them and overwrote the last good fix each time, which is where a parked vehicle got both a moving track and a heading.
     - **Stage 1: HDOP Quality Filter** — Rejects readings with HDOP > 5.0 (poor satellite geometry). HDOP of 0 ("not reported") is accepted, which is why Stage 0 matters: a receiver with no fix often reports no HDOP either.
     - **Stage 2: Speed Outlier Detection** — Uses Haversine distance to calculate implied speed between consecutive valid readings. Rejects readings implying > 200 km/h (GPS multipath/jump).
     - **Stage 3: Movement threshold** (`src/lib/engineRouter.ts`) — a validated fix joins the **track** only once it is `GPS_STEP_M` (5 m) from the last recorded one. Consumer GPS scatters several metres while stationary, and one archived survey holds 280 fixes spanning 9.9 m end to end.
   - Only validated GPS coordinates are stamped onto AP results and emitted to the map trail.
   - **Stage 3 is not cosmetic, and operators should understand why.** The track is the baseline the estimators trilaterate from. Recording scatter as travel does not merely draw a messy line — it hands the localizer a survey geometry that does not exist.
4. **WiFi Signal Processing (`engine/scanner/wifi.py`)**:
   - **EMA Smoothing**: Raw RSSI values are smoothed using Exponential Moving Average (`EMA_ALPHA = 0.6`, in `engine/scanner/ap_track.py`) to reduce jitter from Windows WiFi cache.
   - **Trend Detection**: Each AP is classified as `RISING`, `FALLING`, `STABLE`, or `PEAK` based on consecutive EMA deltas.
   - **OUI Vendor Lookup** (`engine/scanner/oui.py`): The BSSID is matched against Scapy's built-in `manufdb`, providing offline lookup for over 35,000+ IEEE MAC manufacturer assignments. Capable of detecting Randomized MACs.
   - **Timestamps**: `first_seen` and `last_seen` ISO timestamps are tracked per AP.
5. **Data Pipeline**:
   - WiFi results (BSSID, SSID, RSSI, Encryption, Vendor, Trend, Timestamps) and validated GPS coordinates are merged in `handler.py`.
   - Python emits the `aps_batch` event to the Tauri frontend over stdout/stdin.
6. **Location Estimators (`src/lib/localization.ts`)**:
   - Three methods, selectable in Settings → RF Tuning. All are regression-tested against simulated ground truth in `tests/localization.test.mjs` (`npm test`) — read that file before changing any of the maths.
   - **Likelihood Grid** (`bayesian_grid`, recommended) — coarse-to-fine grid search for the position that best explains every reading, in local metres. Expands the search when the peak lands on a boundary, and derives an **error radius** from the posterior spread instead of discarding it.
     - The **only** method that can place a transmitter off the surveyed path.
     - Detects the mirror ambiguity (below) and reports both candidates.
     - **Does not assume it knows the transmitter's power.** `-40 dBm at 1 m` is one constant for every access point in the world, and real EIRP spans well over 10 dB. A power error scales every modelled range by the same factor, so the fit slides the transmitter toward or away from the road to absorb it: median error on an L-route went 9.3 m → 18.1 m at 6 dB of spread, and the stated 95% radius covered the truth **52%** of the time. The power is now given 2 dB of slack (`POWER_PRIOR_DB`, chosen by sweep) and the radius is widened by what 6 dB of unmodelled difference would cost, proportional to the estimate's distance from the nearest sighting. Coverage at 6 dB is now 94%. Fitting the power *freely* was measured and is worse — see `docs/AP_LOCATION_METHODS.md` §4b-iii before revisiting it.
   - **Track Position** (`weighted_centroid`) — signal-weighted average of sighting positions. A convex combination, so it **cannot leave the path that was driven** (measured: 0.0 m off-track in every trial). Fast; a baseline, not a fix.
   - **Multilateration** (`trilateration`) — Levenberg-Marquardt least squares over modelled ranges, run **to convergence**. The previous implementation ran ten fixed gradient steps and stopped at ~65% of its correction, and seeded from a hash of the BSSID so part of every coordinate came from the MAC address. Both are gone; the fix improved accuracy 66–79% where route geometry allows.
   - **Route geometry decides what is possible.** With all sightings on one straight line the likelihood is symmetric about that line, so which side the AP is on cannot be determined. Measured over five seeds: a single straight pass landed on the wrong side 2 times in 5; **driving the same street twice got it wrong 5 times in 5**, because a second pass reinforces the symmetry. A route with one turn: 0 in 5, and the median error dropped from 31 m to 5 m. Tell operators to turn a corner.
   - **No baseline, no estimate — and this is the one to brief operators on.** Below `MIN_ALONG_TRACK_M` (25 m of travel) `estimateLocation` refuses **before** dispatching to any method. It is not a limitation of one estimator: no search can recover a position the geometry does not contain, and three of them failing in three different ways produced three wrong answers instead of one honest refusal. Until v1.0.0 they ran anyway, and the result was not merely imprecise but *unstable* — solving for a transmitter a hundred metres away from a cluster of sightings ten metres across is ill-conditioned, so a few dB of fading moved the answer tens of metres and the access points visibly crawled around the map. Selecting Multilateration made it worse, because the most geometry-hungry method degrades furthest when there is no geometry.
     - What the operator sees instead: **one numbered marker per place they stood**, giving the count of access points heard from there. Grouped on a ~30 m grid rather than averaged, so two stops stay two markers rather than one between them where nothing was measured.
     - What resolves it: **move.** Drive or walk past the access points. The marker's tooltip says so.
   - **Cost is bounded.** The grid search is ~6 ms per AP (down from 40 ms). Live scanning is limited by a per-second estimation budget so a dense block cannot saturate the render thread; archive post-processing yields to the event loop as it runs.
7. **Rendering (`MapView.tsx`)**:
   - Renders AP markers as GeoJSON points with null-safe coordinate filtering. Access points whose position could not be resolved are **not** in that source — they are grouped into counted DOM markers instead, because every one of them lands on the receiver (measured at 1.6 m apart across twelve transmitters 30 to 300 m away) and would otherwise stack into one unreadable pile that still implies that many distinct positions.
     - DOM markers rather than a MapLibre symbol layer on purpose: symbol text needs `glyphs`, and the flat-grid fallback has none, so the count would disappear in exactly the degraded conditions where it matters most. (A DOM marker is also unaffected by which basemap is underneath, which matters more now that an installed PMTiles archive is one of the possibilities.)
   - Vehicle position (ego marker) follows validated GPS trail, and is **hidden until a fix exists**. It used to be created at `MAP_DEFAULT_CENTER` and left visible, which drew a vehicle in central Bangkok on a survey anywhere else.
   - Map uses `useRef` imperatively to bypass React re-renders for 60FPS performance.
8. **Persistence & Post-Processing (`wardrivingDB.ts`)**:
   - Every AP observation is logged as a `scan_log` (bssid, rssi, lat, lon, mission_id) for future replay.
   - GPS trail points are logged as `gps_log` entries for route reconstruction.
   - **Gaussian Process Regression (GPR) Smoothing (Post-Processing)**: On archive load the history cap rises to **100 sightings** per AP, selected for spatial and signal diversity rather than raw strength. The operator can then run GPR, which fits a smooth surface through the measured RSSI and returns its peak. It is a de-noised "where was the signal strongest" — **not** a transmitter fix, because the fitted surface only exists over the path that was driven and its maximum lies on or near that path. It reports an error radius in metres. See `docs/AP_LOCATION_METHODS.md` for the measurements behind this.
---

> **Everything above is what the software does.** What *you* do decides more
> about a survey's quality than any setting in it: an access point's position is
> fixed by where ranges taken from **different places** intersect, so a parked
> survey locates nothing and a straight route cannot tell which side of it a
> radio sits on. See **[GPS and survey technique](GPS_AND_SURVEY.md)**.

---

## 2. INTRUSION / LAN RECON (INITIATE SWEEP)
**Objective:** Deep scanning of local subnets to identify active hosts, open ports, OS variants, and vulnerabilities.

### Flow Sequence
1. **Trigger (`IntrusionPage.tsx`)**: 
   - User clicks **"INITIATE SWEEP"**.
   - `startIntrusion` updates `intrusionStore` to an active state, generating a unique `SCAN-[timestamp]` Session ID.
   - IPC payload `{"cmd": "start_intrusion", "scan_mode": "QUICK"}` is sent.
2. **Backend Execution (`engine/scanner/lan.py`)**:
   - **Phase 0 (Which subnet)**: `get_all_subnets()` promotes the subnet carrying the **default route** to primary; the rest are swept in background threads. Interface order alone used to decide this, which on a machine with VMware adapters gave the full sweep to an empty `192.168.198.0/24` while the operator's real network was scanned as an afterthought — reported as "swept the subnet, 0 hosts", true of the wrong subnet.
   - **Phase 1 (Host Discovery)**: Fires a UDP datagram at each address in the range (port 53) to force ARP resolution — not ICMP, which needs admin on Windows — then waits `ARP_SETTLE_SECONDS` (1.5 s) and reads the OS ARP table. Only addresses in that table are probed.
     - **The range is the CIDR, not an assumed /24.** `_udp_ping_sweep` enumerates the actual network. It previously took the first three octets and swept 1-254 regardless of prefix length, which sent datagrams *outside* a `/25` and covered 254 of 65,534 addresses on a `/16`.
     - **Capped at `MAX_UDP_SWEEP_ADDRESSES` (1,024) per subnet.** Each datagram to an unused address causes an ARP broadcast the whole segment must process, so sweeping a `/16` in full would degrade the network under assessment. Addresses beyond the cap are never contacted.
     - **This narrows the sweep, and it is reported.** On a wireless guest network 254 addresses routinely reduce to 2. The engine emits `intrusion_scope` per subnet with `addresses_in_range`, `addresses_probed`, `skipped_by_arp_filter` and `addresses_never_swept`, plus the raw `udp_sweep` counters; `intrusion_complete` carries the totals across every subnet. Two different caveats, kept apart on purpose: a host that is powered on but silent, firewalled against ARP, or slow is **asked and absent**, while an address past the cap was **never asked**. Only the first is even a weak observation, and **absence in either case is not evidence that nothing is there**.
   - **Phase 2 (Service Enumeration)**: TCP connect scans against the live hosts. **QUICK and STEALTH = 9 ports** (`TARGET_PORTS`); **DEEP = 36 TCP + 7 UDP**. Grabs service banners and HTTP `<title>` tags for context. The counts shown in the Sweep Configurator have to match these lists — they describe the scope of the sweep in the report, and they drifted once already.
     - Probes run through one shared pool capped at `MAX_PORT_PROBE_THREADS` (128). DEEP runs 100 host workers and each host used to spawn a thread per port, so the scanner could ask the OS for roughly 3,600 threads at once.
     - **STEALTH** shuffles the port order, probes one port at a time with a 0.1-0.5 s gap and 0.5-2.0 s between hosts, and uses a longer per-connection timeout. It is quieter and far less bursty than a normal sweep — but a full-subnet scan is still a pattern an IDS correlates. Describe it as lower-noise, never as evasion. Its timeout is passed to `scan_port` as a parameter: it used to be assigned to `self.timeout` while ten workers raced, which could leave the scanner permanently slow.
   - **Phase 3 (OS Fingerprinting)**: Analyzes ICMP TTL return values (e.g., `128` = Windows, `64` = Linux/Unix, `255` = Cisco/Router) and retrieves MAC OUI by stripping Locally-Administered bits.
3. **Vulnerability Mapping & UI Polish**:
   - Python emits discovered hosts to the frontend.
   - **Offline CVE Intelligence (`cve_db.py`)**: During parsing, the engine cross-references open ports, service banners, and OS with an offline matrix of known CVEs (e.g., flagging Apache 2.4.49 for CVE-2021-41773).
     - The matrix in force is the hand-curated seed **with any downloaded snapshot merged over it**, never replaced by it. Replacing it was a real defect: a successful NVD pull returned none of 14 of the seed's 23 entries — Heartbleed among them — and switched those findings off while reporting the data as current. A refresh may only ever add. `active_matrix()` owns that, and memoises the merge because `lookup_cves` is called once per service per host.
     - A lookup collects **every** version key that matches, most specific first, not just the narrowest. With only the seed loaded no product had both a line key and an exact key inside it, so taking a single winner looked correct; a snapshot has both routinely, and the narrower key silently shadowed the wider one's advisory.
     - `fixed_in` is a property of the CVE **within a version line**, earliest winning, and seed entries are exempt from a downloaded bound. NVD describes some flaws both as a range fixed before version X and as X itself affected; taken literally that reports a host running the release that contains the fix.
     - Updates query NVD **by CPE** (`virtualMatchString`) and keep only matches whose vendor and product are the ones asked about. A keyword search pulled a cPanel advisory into the Apache table and told a stock RHEL 7 host it was vulnerable to a mod_ssl flaw. What a pull could not establish — products that came back empty, result sets that hit the page cap — is recorded in the snapshot and named in `coverage_note`, because a product nobody could retrieve must not read as a product with nothing against it.
   - **Advisories that cannot be banner-matched (`OS_INFERRED_CVES` in `cve_db.py`)**: SMB and RDP publish no patch level, so EternalBlue (445) and BlueKeep (3389) can only be inferred from the OS fingerprint plus an open port. `annotate_host_inferences()` adds them **after** OS detection — the port scan does not yet know the OS, because the OS is derived from the ports it collects. Every one carries `inferred: true` and a `basis`, and the rule set reports them at **SUSPECTED, not LIKELY**: a patched host is indistinguishable from an unpatched one by this method. Severity is unchanged — the flaw is as serious as it is; only the confidence differs, which is why severity and confidence are separate fields.
     - This used to live in the frontend as `getPortIntel`, a private table of six CVE ids with its own severities and colours. Two of them could never reach the report, because the engine's matcher works from banner versions — so an operator saw "CVE-2019-0708 BlueKeep CRITICAL" on screen and the exported document said nothing about it. **There is no CVE knowledge in the frontend any more.**
   - **Risk scoring in the UI comes from the same rule set as the report.** `IntrusionPage` calls `assessHost(toHostInput(host, [], false))` — the identical call the report makes — and colours borders, text and port badges from `severityStyle`. It used to run its own ladder with a fallback that scored by port number alone, where any of 445/21/23/3389/5900/**22** open made a host HIGH; `riskEngine` has no rule for port 22 at all, so an SSH-only host was HIGH on screen and absent from the report. That heuristic appeared in five places, including the `criticalNodes` figure persisted to `intel_reports`, and is gone from all of them.

4. **Deep inspection, per host and per network.**
   The sweep tells you what answered. These say what is wrong with it, and each is
   started by the operator rather than run automatically, because every one of
   them talks to the target.

   - **Per host, behind OFFENSIVE MODULES & ACTIONS in the drawer:** vulnerability
     scan, SMB enumeration, directory enumeration, route trace, and **TLS /
     certificate inspection**. The TLS panel is offered on whichever implicit-TLS
     port the sweep actually found open — 443, 8443, 465, 636, 993, 995 — and
     deliberately not on 80, because this scanner does not speak STARTTLS and a
     failure there would read like a result.
   - **Every panel is gated on which host it belongs to.** The engine names the
     subject in each payload, and the drawer renders a result only under that
     host. Without the gate, scanning host A and then opening host B showed A's
     CRITICAL finding under B's header, with the button reading SCAN COMPLETED.
   - **An inconclusive check is shown beside the findings, not instead of them.**
     `ssl_check.py` builds an explicit `inconclusive` list on a stated rule — "a
     check that did not run produces an entry in `inconclusive`, never a finding" —
     and the panel prints it with the sentence that its absence from the findings
     is not a pass. A TLS check that could not complete looks exactly like one
     that found nothing wrong.

   - **Per network, beside the recon summary: ANALYSE NETWORK SEGMENTATION.**
     Reads every subnet the sweep found and probes for inter-VLAN reachability,
     shared gateway MACs and rogue DHCP.
   - **Most of what it reports is inferred, and it says which.** A VLAN id here is
     the third octet of the range and a gateway is the first usable address by
     convention; only the gateway's reachability is measured. The engine ships
     `vlan_id_basis` and `gateway_basis` alongside the values so no screen can
     render one as the other, and the report's table prints the basis inside the
     cell rather than in the column header — a header can be skimmed past.
   - **It is carried as context, not as findings**, like the traceroute path: a
     findings count is a figure management acts on, and this check cannot tell a
     deliberate flat network from an accidental one. The one measured result —
     two DHCP servers answering one discover — travels in the engine's own
     findings list, where it belongs.

   Results from all of these are frozen into the archive when the sweep is saved.
   The PDF derives every finding from that blob rather than from the database, so
   a result left in component state would be watched on screen and absent from the
   document.

---

## 3. ORBITAL STRIKE (ACTIVE COUNTERMEASURES)
**Objective:** Forcefully disconnect unauthorized, rogue, or compromised devices from the network.

### Flow Sequence
1. **Trigger (`TargetDrawer.tsx` / `IntrusionPage.tsx`)**:
   - User clicks **"AUTHORIZE STRIKE"**.
   - Frontend validates that the target possesses a valid MAC address.
2. **Execution**: 
   - IPC payload `{"cmd": "start_strike", "target_mac": "xx:xx:xx:xx:xx:xx"}` is dispatched.
3. **Backend Execution (`engine/scanner/strike.py`)**:
   - *Requirement: Monitor-Mode Wi-Fi adapter & Npcap.*
   - Python constructs raw IEEE 802.11 Deauthentication management frames using `Scapy`.
   - Spams deauth packets targeting the specific MAC address (or broadcast address) to sever the handshake between the client and the AP.
4. **UI Feedback**: 
   - `strikeStore` updates state.
   - Target drawer pulses red; TopBar displays a flashing `STRIKE ACTIVE` badge.

---

## 4. ANTENNA BENCHMARK
**Objective:** Evaluate the performance, gain, and channel distribution of the attached Wi-Fi adapter/antenna.

### Flow Sequence
1. **Trigger (`SettingsPage.tsx`)**:
   - User clicks **"START BENCHMARK"**.
   - IPC payload `{"cmd": "run_benchmark"}` is sent.
2. **Backend Execution (`handler.py`)**:
   - Performs a Multi-Pass Sweep (e.g., 3 passes, 4 seconds each) across all 2.4GHz, 5GHz, and 6GHz channels to ensure it captures beacon frames from sleeping/hidden APs.
   - Heuristically determines the frequency/channel and retains only the *absolute highest RSSI* per BSSID seen across all passes.
3. **Data Return**: 
   - Emits `benchmark_result` containing an array of RSSI values and channel distributions.
4. **Visualization (`SettingsPage.tsx`)**: 
   - Frontend parses the data and renders the breakdown inline (no charting library is used; `recharts` is not a dependency):
     - **Signal Distribution (Histogram)**: Groups RSSI into buckets (e.g., -40dBm to -90dBm) to visualize overall antenna gain.
     - **Spectrum Density (Scatter Plot)**: Maps the density of networks across Wi-Fi channels to detect interference zones.

---

## 5. STATE & PERSISTENCE ARCHITECTURE (DATA LAYER)
**Objective:** Manage high-frequency data streams without UI freezing, while ensuring long-term data persistence.

### Components
1. **Zustand Stores (Real-time State)**:
   - `missionStore.ts` — Wardriving AP state and sighting history. The estimator maths lives in `src/lib/localization.ts`; a state container is the wrong place for numerical code that needs testing.
   - `engineStore.ts` — GPS position, config (locationMethod, scanInterval, HDOP threshold), hardware status. **Uses `persist` middleware** to save user config (COM port, map style, etc.) across app restarts.
   - `intrusionStore.ts`, `strikeStore.ts` — LAN recon and countermeasure state.
   - `reportStore.ts` — Intel reports with full SQLite synchronization (add, delete, rename, **clearAll**).
   - `passiveSigintStore.ts` — SIGINT radar session state (persisted to `sessionStorage` to survive navigation).
   - `uiStore.ts` — UI preferences (vehicle icon, visual toggles).
   - This decouples the UI from the database overhead. React components only subscribe to specific slices of the state to minimize re-renders.
2. **SQLite via Tauri Plugin (Persistent Database)**:
   - Built on `tauri-plugin-sql` and managed via `wardrivingDB.ts` / `intrusionDB.ts` / `benchmarkDB.ts`.
   - **Wardriving Tables**: `missions`, `access_points`, `scan_logs` (every AP observation), `gps_logs` (GPS trail points).
   - **Intrusion Tables**: `scan_sessions`, `intrusion_hosts`, `intrusion_ports`.
   - **Benchmark Table**: `antenna_benchmarks` (antenna performance records).
   - **Intel Tables**: `intel_reports` (generated PDF reports with metadata).
   - **Credential Tables**: `credentials` (compromised credentials from brute force/spraying) and `vault_meta` (the KDF parameters and verifier for the vault passphrase). Secrets are encrypted at rest with AES-256-GCM; `enc_version = 0` marks rows written before encryption existed, whose passwords are still cleartext until the operator seals them.
   - Data is explicitly flushed to the DB at strategic intervals (e.g., `completeMission()` when stopping a scan, or `createSession()` when archiving a sweep).
   - This ensures that if the app crashes, the UI reloads gracefully without losing archived intelligence.

---

## 6. IPC BRIDGE PROTOCOL (RUST ↔ PYTHON ↔ REACT)
**Objective:** Maintain a highly decoupled system where Python handles network packet sniffing and React handles UI, bridged by Rust.

### How it Works
1. **Tauri Shell Plugin (Sidecar)**:
   - The Python engine (`ewac-engine.exe`) is spawned by Rust as a sidecar process.
2. **Standard I/O JSON Protocol**:
   - React sends commands via `engineIPC.send()`: e.g., `{"cmd": "start_scan"}`.
   - Every command is typed via the `EngineCommand` union in `src/types/engine.ts` for compile-time safety. The union and the `handlers` dict in `handler.py` currently hold the same **58** keys. (Nine of those handlers have no caller in the UI — see the known-gaps list in [ENGINEERING_LOG.md](ENGINEERING_LOG.md#known-gaps-stated-plainly).)
   - Rust forwards this to Python's `stdin`.
   - Python processes the command and emits data back via `stdout`: e.g., `{"event": "aps_batch", "payload": [...]}`.
   - **Auto-Reconnect**: If the sidecar crashes, the IPC layer automatically retries with exponential backoff, emitting `reconnecting`/`reconnected`/`reconnect_failed` events.
3. **Simulator Mode** (`engine/scanner/simulator.py`):
   - Drives a scenario: a vehicle moving along a route past 11 access points at known positions, with RSSI from the same path-loss model `src/lib/localization.ts` inverts, plus 6 dB log-normal shadowing.
   - Sightings go through `ApTracker` and `evil_twin.analyze` — the same code a live scan uses — so trend, map pinning and rogue verdicts behave as they will in the field.
   - The route contains a turn on purpose. A straight route is mirror-ambiguous, so a scenario without one would rehearse the localizer at its worst; `test_simulator.py` fails if the turn is ever removed.
   - The scenario plants a rogue AP (an open clone of a secured SSID) and a legitimate WPA2/WPA3 transition pair. It does not label either: the detector has to reach the verdict, and the pair must stay CLEAR.
   - *Why?* So a report can be rehearsed before the field. The old mode emitted one hardcoded AP at a fixed point, which exercised no localization, no rogue grouping and no coverage — the operator's first real look at their own report was on the road.
   - Every row it produces is stamped `simulated`, and the report refuses to present it as field evidence. Auto-attack is never triggered on simulated APs.

---

## 7. AUDIO TELEMETRY SYSTEM (SONAR)
**Objective:** Provide situational awareness without requiring line-of-sight to the dashboard.

### Logic (inline in `src/components/layout/AppShell.tsx`)

> There is no `AudioEngine.ts`. `playSonarPing` is defined and called inside `AppShell.tsx`.
- Uses the HTML5 Web Audio API to synthesize sine/triangle waves dynamically.
- The `playSonarPing` function alters its pitch and playback frequency based on the surrounding threat landscape.
- **Dynamic Scaling**: If the `highRiskCount` (from `missionStore`) increases, the interval between pings decreases (faster beeping), simulating the tension of a Geiger counter or submarine sonar detecting an imminent threat.

---

## 8. THE INTELLIGENCE MATRIX (RISK SCORING)
**Objective:** Accurately classify threats to reduce alert fatigue and highlight true vulnerabilities.

> **Single source of truth: `src/lib/riskEngine.ts`.** Do not restate the scale here or recompute it per view. Five separate rule sets used to coexist, and they disagreed badly enough that one PDF counted a WPA1 network in its headline "vulnerable" figure while printing that same network as `[LOW]` in the table below it. The rules, the bands and the confidence definitions are exported by `describeMethodology()` and printed in the report's method appendix, so a reader can audit any label.

### Shape of the scale
- **Five levels** — `CRITICAL / HIGH / MEDIUM / LOW / INFO` — derived from a 0-100 score through documented bands.
- **Confidence is a separate axis** from severity. `CONFIRMED` was directly observed; `LIKELY` was inferred from strong evidence such as a version banner but not exercised; `SUSPECTED` needs manual verification. A suspected rogue AP is a high-severity finding at low confidence, **not** a low-severity one.
- **Every finding records its reason** (`rationale`) and the rule version that produced it (`methodology`), and carries a stable `fingerprint` so a retest recognises the same issue instead of reporting it as new.

### What drives the score
- **Wi-Fi:** encryption (OPEN and WEP dominate; WPA1/TKIP is materially weaker than WPA2), **WPS exposure** — an unlocked WPS PIN undermines an otherwise sound WPA2 network, which is exactly why an encryption-only verdict was not enough — and **rogue-AP verdicts** from the indicator scoring in `engine/scanner/evil_twin.py`.
- **LAN:** recovered credentials (demonstrated access, the strongest finding the tool can produce), CVEs matched from service banners (recorded as `LIKELY`, since they were not exploited), exposed services, and SNMP answering a default community string.

Ports and CVE identifiers are inputs to those rules, not a scale of their own. Read the file for the current values rather than trusting a copy here.

---

## 9. THE BUILD PIPELINE & SIDECAR PATTERN
**Objective:** Seamlessly package a multi-language application into a single distributable executable.

### The Sidecar Process
- Tauri officially supports "Sidecars" (embedding external binaries). We leverage this to package our Python engine.
- **PyInstaller Pipeline**: Before building the React/Tauri app, the Python code in `engine/` is compiled into a standalone Windows `.exe` using PyInstaller.
- **File Placement**: The resulting `.exe` must be placed in `src-tauri/binaries/` and named to match the target triple (e.g., `ewac-engine-x86_64-pc-windows-msvc.exe`).
- **CRITICAL DEV NOTE**: Changes to the `engine/` python scripts will **NOT** reflect in the Tauri app until you re-run PyInstaller. The Tauri Dev server only hot-reloads the React frontend and Rust backend.

---

## 10. HARDWARE & PRIVILEGE REQUIREMENTS
**Objective:** Maximize functionality without requiring unnecessary OS-level permissions.

### Privilege Mapping
- **Passive Wardriving & Quick LAN Scans**: Requires **No Administrator Privileges**. The app uses standard user-level APIs (`arp -a`, `ipconfig`, standard TCP connect sockets) to gather intelligence. This makes deployment highly frictionless.
- **Active STRIKE (Deauth Jamming)**: 
  - Requires **Npcap** installed (with raw 802.11 packet capture enabled).
  - Requires a specialized **Monitor-Mode capable Wi-Fi Adapter** (e.g., Alfa AWUS036ACH).
  - The Python sidecar may require elevation to inject raw frames via Scapy, depending on the Windows environment.

---

## 11. DATABASE SCHEMA & MIGRATION FLOW
**Objective:** Ensure backward compatibility and robust data structuring as the app updates.

### Migration Engine (`tauri-plugin-sql`)
- When the Rust backend initializes, it checks the `ewac.db` SQLite file.
- It sequentially runs `.sql` files found in `src-tauri/migrations/` (e.g., `001_initial_schema.sql`, `002_intrusion_schema.sql`). This guarantees the schema is always up-to-date.

### Relational Structure

**Wardriving Module:**
- `missions` (1) ↔ (N) `access_points`: Every Wardriving session is a unique mission. APs discovered during that session are linked via `mission_id`.
- `missions` (1) ↔ (N) `scan_logs`: Every individual AP observation is archived with RSSI, GPS coordinates, and timestamp. Used for archive replay with the corrected MAX(rssi) subquery.
- `missions` (1) ↔ (N) `gps_logs`: GPS trail points are stored for route reconstruction on the tactical map.

**Intrusion Module:**
- `scan_sessions` (1) ↔ (N) `intrusion_hosts` (1) ↔ (N) `intrusion_ports`: Every LAN Sweep generates a session. Hosts found are linked, allowing the app to diff results between sessions (detecting "NEW TARGETS").

**Benchmark Module:**
- `antenna_benchmarks`: Standalone records for antenna performance comparisons.

---

## 12. MAPGL & WEBGL RENDERING ARCHITECTURE
**Objective:** Maintain 60FPS fluid mapping while rendering thousands of dynamic geospatial points.

### The React ↔ MapLibre Bottleneck
- Standard React state updates (`setState`) trigger component re-renders. If we bound map markers directly to React State while receiving 10 GPS updates per second, the map would freeze or flicker.

### The `useRef` Optimization (`MapView.tsx`)
- The MapLibre instance is stored in a React `useRef` hook.
- **Access points are not DOM markers.** They are a single `geojson` source updated with `source.setData(...)`, which is what keeps a dense spectrum cheap to draw. The only DOM `Marker` in this file is the **ego marker** (the vehicle), which is moved imperatively with `setLngLat()`.
- Either way the React render cycle is bypassed for position updates.
- This creates an ultra-smooth map panning and marker updating experience, essential for high-speed vehicular Wardriving operations.
- **Null-safe filtering**: GeoJSON sources filter out APs with null coordinates to prevent rendering errors.

---

## 13. BRUTE FORCE MODULE (OFFENSIVE)
**Objective:** Active credential testing against discovered network services using dictionary-based and spray attacks.

### Flow Sequence
1. **Trigger (`IntrusionPage.tsx` → Target Drawer)**:
   - User selects a discovered host with vulnerable services (SSH/FTP/HTTP).
   - Chooses a wordlist from the Dictionary Arsenal and clicks **"START ATTACK"**.
   - IPC payload: `{"cmd": "start_bruteforce", "target_ip": "...", "port": 22, "service_type": "ssh", "wordlist_name": "default-passwords.txt"}`.
     Note the keys are **`service_type`** and **`wordlist_name`**; `service` and `wordlist` are not read.
2. **Backend Execution (`engine/offensive/bruteforce.py`)**:
   - Spawns a daemon thread per target:port combination (keyed by `target_ip:port` to prevent duplicate attacks).
   - **Adaptive Path Resolution**: Uses `sys._MEIPASS` (frozen) or `os.path.dirname(__file__)` (dev) to locate wordlist files.
   - **Word Parsing**: Supports both `password` format (uses target_user, default: `admin`) and `user:password` format.
3. **Service-Specific Handlers**:
   - **SSH** (Paramiko): `client.connect()` with 2s timeout. Auto-accepts host keys.
   - **FTP** (ftplib): `ftp.connect()` + `ftp.login()` with 2s timeout.
   - **HTTP/HTTPS** (Requests): Basic Auth `GET /` with status code validation (< 400 = success). Auto-switches protocol based on port.
4. **IPC Events**:
   - `bruteforce_progress` → every 10 attempts (progress %, current word).
   - `bruteforce_success` → credential pair found (`user:password`).
   - `bruteforce_exhausted` → wordlist completed without success.
   - `bruteforce_error` → exception occurred.
5. **Cancellation**: `stop_attack(target_ip, port)` sets the active flag to `False`, causing the thread to break on next iteration.

---

## 14. HANDSHAKE CAPTURE (WPA INTERCEPTION)
**Objective:** Intercept WPA/WPA2 four-way handshake EAPOL packets for offline cracking.

### Flow Sequence
1. **Trigger (`DecryptorPage.tsx`)**:
   - User targets a specific BSSID and clicks **"START CAPTURE"**.
   - IPC payload: `{"cmd": "start_capture", "bssid": "AA:BB:CC:DD:EE:FF"}`.
2. **Backend Execution (`engine/offensive/capture.py`)**:
   - Uses Scapy's `sniff()` with an EAPOL layer filter on the target BSSID.
   - **Packet Matching**: Checks `pkt.addr1`, `pkt.addr2`, and `pkt.addr3` against the target BSSID (case-insensitive).
   - **Completion Criteria**: Capture succeeds on a **usable EAPOL message pair** — M1+M2 or M2+M3 (`_USABLE_PAIRS` / `_eapol_message_number` in `capture.py`). Any two EAPOL frames is not enough: two copies of the same message prove nothing.
   - **Timeout**: Default 15 seconds. If no handshake is detected, emits `capture_failed`.
3. **Output**:
   - On success: written into the fixed **evidence directory** via `evidence.build_path(...)`, SHA-256'd at the moment of writing and registered in `evidence_files`. It is not written to the sidecar's working directory.
   - `capture_packet` → real-time count of intercepted EAPOL frames.
   - `capture_success` → filename of saved PCAP.
4. **Requirements**:
   - Npcap with raw 802.11 capture enabled.
   - Monitor-mode capable Wi-Fi adapter (e.g., Alfa AWUS036ACH).
   - On standard Windows without monitor mode, capture will timeout with no packets.

---

## 15. DECRYPTOR (OFFLINE HASH CRACKING)
**Objective:** Offline WPA/WPA2 password recovery from captured handshake PCAP files.

> **Rewritten.** This section previously described a pure-Python `PBKDF2-HMAC-SHA1`
> loop running at "~200 hashes/sec per core" and called the module a
> proof-of-concept. That implementation no longer exists: there is no PBKDF2 code
> in `decryptor.py` at all. Anyone reading the old text would have expected a
> demonstration pipeline and got a tool that refuses to start without hashcat.

### Flow Sequence
1. **Trigger (`DecryptorPage.tsx`)**:
   - User selects a captured `.pcap`/`.pcapng` file and a wordlist, then clicks **"START DECRYPT"**.
   - IPC payload: `{"cmd": "start_decrypt", "pcap_file": "...", "wordlist_name": "rockyou-wpa-optimized.txt"}`.
     Note the key is **`wordlist_name`**, not `wordlist` (`handler.py:_handle_start_decrypt`). An
     optional `mangling` parameter is also accepted.
2. **Backend Execution (`engine/offensive/decryptor.py`)**:
   - Converts the capture with `hashcat_export.pcap_to_hc22000()`, then drives a **real hashcat
     process** in mode 22000 (`hashcat -m 22000 -a 0 --status --status-json -o cracked.txt <wordlist>`).
   - Progress is parsed out of hashcat's own `--status-json` output; the recovered passphrase is read
     back from hashcat's outfile. Nothing is simulated.
   - **It refuses to run rather than approximate.** No capture, no hashcat binary on the system, no
     crackable hash in the file, or no wordlist — each stops the run with an explanatory error. The
     module never degrades into a simulation, because a cracked-password claim that was not produced
     by a real crack is the single worst thing this tool could put in a report.
3. **IPC Events**: `decrypt_started`, `decrypt_progress`, `decrypt_error`.
4. **Prerequisite**: hashcat must be installed and discoverable. `decryptor.py` searches a small set
   of known paths; if none match, the operation reports that rather than falling back to anything.

---

## 16. AUTO-ATTACK CHAIN & PMKID CAPTURE (WIFI OFFENSIVE)
**Objective:** Autonomous, clientless interception of WPA/WPA2 PMKID hashes and automated workflow sequencing.

### Flow Sequence
1. **Trigger (`AppShell.tsx` / `auto_attack.py`)**:
   - User enables **"AUTO-ATTACK CHAIN"** in Settings.
   - During the wardriving scan (`wifi.py`), the background orchestrator receives the `aps_batch` data.
2. **Target Filtering (`AutoAttackChain`)**:
   - Extracts targets that are `WPA/WPA2` and have an `RSSI >= -75dBm` (strong signal requirement for reliable frame interception).
   - Ensures the target hasn't already been attacked during the current session (maintains an `_attacked_bssids` cache).
3. **Execution Sequence**:
   - **Step 1:** Automatically initiates a PMKID Capture (`start_pmkid_capture`) targeting the BSSID.
   - **Step 2:** Listens for the first EAPOL frame (M1) containing the PMKID hash. Unlike traditional handshakes, PMKID capture is *clientless* (does not require a connected client to deauth).
   - **Step 3:** Limits to processing up to 3 targets sequentially per scan loop to prevent thread exhaustion.
4. **Hashcat Integration**:
   - If a PMKID is successfully captured, the PCAP can be automatically converted to the `.hc22000` format (`export_hashcat`), making it instantly ready for high-speed GPU cracking on external rigs.

---

## 17. 5GHz/6GHz SPECTRUM AWARENESS
**Objective:** Detect and visualize advanced Wi-Fi frequency bands (5GHz and Wi-Fi 6E/6GHz) alongside traditional 2.4GHz networks.

### Logic (`wifi.py`)
- Extracts the native `frequency` attribute from the PyWiFi profile.
- **Kilohertz Normalization:** Windows Native API often returns frequencies in kHz (e.g., `2412000`). The engine divides any value > `10000` by `1000` to normalize to MHz.
- **Band Classification:**
  - `freq >= 5925` → `6G`
  - `freq >= 4900` → `5G`
  - `freq < 4900` → `2.4G`
- **Channel Derivation:** Calculates the exact Wi-Fi channel mathematically from the frequency (e.g., `(freq - 5000) // 5` for 5GHz bands).
- The frontend dynamically displays purple (`5G`) and pink (`6G`) badges on the Scan Feed.

---

## 18. EVIL TWIN DETECTION
**Objective:** Identify potentially malicious access points masquerading as legitimate networks.

> **Rewritten.** The rule described here previously — "same SSID, conflicting
> encryption types, therefore evil twin" — was removed because it accuses every
> WPA2/WPA3 transition-mode deployment, which is the standard way to roll out
> WPA3. A report that calls a correctly configured corporate network a rogue
> access point is worse than one that says nothing, and it was documented here
> as the current method long after the code stopped using it.

### Detection (`engine/scanner/evil_twin.py`)

Scoring is done in the engine over the **whole session cache**, not per scan batch:
a twin is only visible relative to its peers, so a per-batch view would miss a
pair split across two scans. This is why a verdict can be upgraded on a later
cycle than the first sighting.

**Seven weighted indicators**, kept explicit so the report can quote the
methodology instead of presenting a black-box verdict:

| Indicator | Weight | What it means |
|---|---|---|
| `open_clone_of_secured` | 50 | An open network sharing an SSID with a secured one. The strongest single signal. |
| `vendor_mismatch` | 25 | The BSSID's OUI differs from its same-SSID peers. |
| `encryption_downgrade` | 20 | Weaker encryption than its peers advertise. |
| `unexpected_encryption_split` | 15 | An encryption pair that is not a known-legitimate combination. |
| `oui_randomized` | 15 | A locally-administered (randomised) MAC. |
| `channel_conflict` | 10 | Same SSID, conflicting channel usage. |
| `signal_outlier` | 10 | Signal strength inconsistent with its peers. |

**Verdict thresholds**: `SUSPECTED` at 25, `LIKELY` at 45, `CONFIRMED` at 70. Below 25 the AP is
`CLEAR` and raises nothing.

**Legitimate pairs are never accused.** `{WPA2, WPA3}` (transition mode), `{WPA2, WPA2PSK}` (naming
variants of one thing), `{WPA, WPA2}` (legacy mixed mode — weak, but not a twin) and
`{WPA3, WPA3SAE}` all score zero. `test_simulator.py` asserts that the scenario's legitimate
transition pair is never accused, alongside asserting the planted rogue is caught.

**Reporting**: `missionStore` counts `ap.is_evil_twin` as supplied by the engine and does not
recompute it. The verdict, its score and its indicator list travel with the AP into the archive, and
`riskEngine` turns a non-CLEAR verdict into a finding whose rationale quotes the indicators that
fired. Severity scales with the verdict (`SUSPECTED` 45, `LIKELY` 75, `CONFIRMED` 90) — see the note
in `riskEngine.ts` on why this one rule lets the verdict scale severity as well as confidence.

---

## 19. DICTIONARY ARSENAL (WORDLIST MANAGEMENT)
**Objective:** Centralized management of password dictionaries used across Brute Force and Decryptor modules.

### Architecture
1. **Two locations, not one.** The lists that ship with the build sit beside the
   sidecar (`engine/wordlists/` in a source run); anything the operator uploads
   goes to a per-user directory, `%LOCALAPPDATA%\LOCKON-EWAC\wordlists`.
   They used to be the same directory, and that was a real defect: on an
   installed copy the bundled directory is under `%ProgramFiles%`, so the upload
   button could not write there without elevation and simply failed for an
   ordinary operator. `wordlists_path.wordlist_dirs()` is the one place that
   knows both.
2. **Discovery**: `wordlists_path.list_wordlists()` merges the two, and
   `handler.py` emits `wordlists_list` with filename, size and an `origin` of
   `bundled` or `user`. A name present in both resolves to the operator's copy —
   uploading a file is an instruction, and preferring the shipped one would
   ignore it. It is still listed once.
3. **Upload**: the Settings page reads the file with the `FileReader` API and
   sends it over IPC as `upload_wordlist`, which writes to
   `wordlists_path.writable_wordlists_dir()` — never the bundled directory.
   Deleting a bundled list is **refused with a sentence** rather than attempted
   and failed on a permission error, and the UI disables the button and marks
   those rows `BUNDLED`.
4. **Path Resolution**: `resolve_wordlist()` sanitises the name to a bare
   filename — it cannot be walked out of the wordlist directories with `..`, an
   absolute path or a UNC path — then returns the first existing match across
   both locations. For a frozen build the bundled directory is found from
   `sys.executable`, with `sys._MEIPASS` as a fallback; a source run uses the
   sibling of `wordlists_path.py`. A name that matches nothing still returns the
   bundled path, so "not found at ..." names the directory an operator is most
   likely looking at.
5. **Pre-loaded Dictionaries**: Ships with common password lists (RockYou subset, Mirai default credentials, CIRT router defaults).

---

## 20. PASSIVE SIGINT RADAR (ZERO-EMISSION RECON)
**Objective:** Gather network intelligence without transmitting any packets at all. Unlike STEALTH mode in the active sweep, this genuinely emits nothing, so there is no traffic for an IDS to correlate — the limit is what happens to drift past the antenna.

### Flow Sequence
1. **Trigger (`PassiveSigintView.tsx`)**:
   - User clicks **"START PASSIVE MONITOR"**.
   - Two IPC payloads are sent, not one: `{"cmd": "start_passive", "interface": "..."}`
     and `{"cmd": "start_probe_monitor", "interface": "..."}` (step 3).
2. **Backend Execution (`engine/scanner/passive.py`)**:
   - Initializes a raw packet sniffer using Scapy (`sniff(store=0)`).
   - **LAN Host Discovery**: Inspects `ARP`, `DHCP` (UDP 67/68), and `mDNS` (UDP 5353) packets. Extracts IPs, MACs, Hostnames, and Vendors.
   - Emits `passive_started`, then `passive_host` per discovered host, and
     `passive_stopped` or `passive_error` when it ends.
3. **WiFi Probe Monitoring (`engine/scanner/probe_monitor.py`)**:
   - A **separate module and a separate command**. `passive.py` contains no
     802.11 handling at all; this one inspects Probe Requests
     (`type=0, subtype=4`) and extracts client MACs and requested SSIDs.
   - Emits `probe_monitor_started`, `probe_detected` per request, and
     `probe_monitor_stopped` / `probe_monitor_error`.
   - The two are separate on the wire and joined in the UI: one button in
     `PassiveSigintView.tsx` sends `start_passive` **and**
     `start_probe_monitor`, and stopping sends both stops. Sending only
     `start_passive` gives you hosts and no probes.
4. **Frontend Integration**:
   - The UI updates in real-time, displaying a "ghost" matrix of network activity without ever alerting the target network.

---

## 21. SMB DEEP ENUMERATION
**Objective:** Interrogate port 445 using raw sockets to extract OS, Domain info, and test for EternalBlue/SMBv1 without authentication.

### Flow Sequence
1. **Trigger (`IntrusionPage.tsx`)**:
   - User clicks **"SMB DEEP ENUMERATION"** on a host with port 445 open.
   - IPC payload `{"cmd": "start_smb_enum", "target_ip": "..."}` is sent.
   - **Frontend Guard**: A 15-second `setTimeout` is initialized to prevent UI locking. If the engine hangs on a heavily firewalled target, the UI gracefully aborts and resets state.
2. **Backend Execution (`engine/scanner/smb_enum.py`)**:
   - **NTLMSSP Challenge**: Connects to port 445, negotiates SMB dialects, and sends an NTLM Negotiate request.
   - Parses the server's NTLM Challenge response to extract the exact `Windows OS Build`, `Domain Name`, and `DNS Hostname`.
   - **Null Session Test**: Attempts to bind to `IPC$` anonymously.
   - **EternalBlue Check**: Checks if the server accepts the SMBv1 dialect `NT LM 0.12`.
   - **SecurityMode & Signing**: Evaluates the `SecurityMode` flag in the SMB2 Negotiate Protocol Response to determine if SMB Signing is `Required` (Safe) or `Not Required` (Relay Risk).
   - **Share Discovery**: If the Null Session is established, it iterates through a list of 10 common administrative and public share names (e.g., `C$`, `ADMIN$`, `Users`, `public`). It issues a `Tree Connect` request for each to determine access levels (`OPEN` vs `ACCESS DENIED`).
3. **Data Return**:
   - Emits `smb_enum_completed` with the extracted metadata, share lists, and
     signing status. The payload names its own target, so the result cannot be
     labelled with whichever host happens to be selected when it arrives.

---

## 22. CREDENTIAL SPRAYING & GLOBAL VAULT
**Objective:** Store compromised credentials and reuse them across the entire network to achieve lateral movement.

### Flow Sequence
1. **The Vault (`credentialDB.ts`)**:
   - A successful brute force or spray writes the credential into the SQLite `credentials` table with the password encrypted (`saveCredential`). This was aspirational until 2026-09-27: nothing called the write path, so the vault was always empty and `spray_success` reloaded a list nothing had written.
   - Writing requires the vault to be unlocked. There is deliberately no cleartext fallback — if it is locked the write throws and the UI says the credential was **not** stored, rather than silently keeping it readable on disk.
   - Report snapshots embed the **ciphertext** (`getCredentialsForArchive`), never the decrypted value. Archiving used to call `getAllCredentials()` and write the result into `intel_reports.raw_data` as JSON, which put every recovered password back on disk in cleartext and undid the encryption entirely. The PDF decrypts once at export via `revealArchivedCredentials`.
2. **Spraying Trigger (`VaultDrawer.tsx`)**:
   - User clicks **"SPRAY ACROSS LAN"**.
   - Frontend collects all hosts from the current session and dispatches them to the engine along with the vault credentials.
   - IPC payload `{"cmd": "start_spray", "targets": [...], "username": "...", "password": "..."}`.
3. **Backend Execution (`engine/offensive/sprayer.py`)**:
   - Executes a highly parallelized attack, testing every credential pair against every applicable open port (SSH/FTP/HTTP) across all targets simultaneously.
   - If a new machine is compromised using an existing credential, it emits a `spray_success` event, and the frontend stores the new compromise in the Vault (encrypted).

---

## 23. WEB DIRECTORY ENUMERATION (DIRBUSTER)
**Objective:** Uncover hidden administrative panels, configuration files, and API endpoints on web servers.

### Flow Sequence
1. **Trigger (`IntrusionPage.tsx`)**:
   - User targets an HTTP/HTTPS service (Port 80/443/8080) and initiates **"DIRBUSTER"**.
2. **Backend Execution (`engine/offensive/dirbuster.py`)**:
   - Uses a multi-threaded `ThreadPoolExecutor` to send fast `HEAD` or `GET` HTTP requests using a caller-supplied wordlist resolved through `engine/wordlists_path.resolve_wordlist` (the bundled default-directory list is `common-dirs.txt`).
   - Evaluates HTTP response codes (`200 OK`, `401 Unauthorized`, `301 Redirect`) to determine path existence.
   - Bypasses basic WAFs with custom User-Agent strings and ignores generic 404s.
3. **Result Mapping**:
   - Discovered paths are instantly relayed to the UI and appended to the target's node report.

---

## 24. TRAFFIC INTERCEPTION (MITM / ARP SPOOFING)
**Objective:** Reroute and sniff network traffic between a target node and the network gateway to extract intelligence (DNS, HTTP headers).

### Flow Sequence
1. **Trigger (`IntrusionPage.tsx` / `TargetDrawer`)**:
   - User targets a host and clicks **"INTERCEPT TRAFFIC (MITM)"**.
   - UI identifies the Gateway IP from the active subnet.
   - IPC payload `{"cmd": "start_mitm", "target_ip": "...", "gateway_ip": "..."}` is sent.
2. **Backend Execution (`engine/offensive/mitm.py`)**:
   - Uses `scapy` to resolve the MAC addresses for both the Target and the Gateway.
   - **Spoofing Thread**: Continuously sends crafted ARP replies. It tells the Target "I am the Gateway" and tells the Gateway "I am the Target" every 2 seconds.
   - **Sniffing Thread**: Uses `scapy.sniff()` filtering for packets involving the Target's IP.
3. **Packet Extraction & PCAP Export**:
   - Evaluates packet layers. If `DNS`, it extracts the queried domain names.
   - If `TCP/80` with a payload, it searches for the HTTP `Host:` header and requested URI.
   - For `TCP/443`, it registers the packet as encrypted traffic.
   - **PCAP Evidence**: If `save_pcap` is enabled, all intercepted packets are appended to a `.pcap` file in the `captures/` directory using Scapy's `PcapWriter` for deep forensic analysis in Wireshark.
4. **Data Return**:
   - Discovered packets are emitted via `mitm_packet` events.
   - The UI displays a live, streaming terminal-style output of the intercepted traffic.

---

## 25. MODULAR VULNERABILITY ENGINE
**Objective:** Automatically verify the existence of known vulnerabilities or misconfigurations on discovered open ports.

### Flow Sequence
1. **Trigger (`IntrusionPage.tsx`)**:
   - User clicks **"ANALYZE VULNERABILITIES"** on a scanned host.
   - IPC payload `{"cmd": "start_vuln_scan", "target_ip": "...", "open_ports": [21, 80, 3306...]}` is sent.
2. **Backend Execution (`engine/scanner/vuln_engine.py`)**:
   - The engine iterates through the `open_ports` list and fires specific modular tests:
     - **Port 21 (FTP):** Uses Python's `ftplib` to test `anonymous` login.
     - **Port 6379 (Redis):** Sends raw `INFO` command over socket to check for `NOAUTH` exposure.
     - **Port 3306 (MySQL):** Analyzes the raw connection banner for native password exposure.
     - **Port 23 (Telnet):** Connects and checks for a cleartext login prompt.
     - **Web Secrets (HTTP/HTTPS):** Checks for leaked configurations by probing for `/.env`, `/.git/config`, `/docker-compose.yml`, and `/config.json`, analyzing the returned payloads to prevent false-positives from generic 404 pages.
3. **Result Mapping**:
   - Returns a structured array of findings containing the `vuln` name, `description`, `severity` (CRITICAL/HIGH/MEDIUM/LOW), and `cve`.
   - The UI parses these findings and prominently displays them in the "Advanced Intel Blocks" of the Target Drawer, styling the borders based on severity.

---

## 26. INTELLIGENCE ARCHIVE (SCAN HISTORY)
**Objective:** Provide a fast, queryable, and context-rich database of all historical network sweeps.

### Flow Sequence & Features
1. **Dynamic Context Population (`intrusionDB.ts`)**:
   - Scans triggered via "Auto-detect" initialize their database record as `Auto-detecting...`.
   - Once the Rust backend resolves the active subnet and connected Wi-Fi SSID (e.g., `192.168.1.0/24 [Starbucks_WiFi]`), `updateSessionSubnet()` is called to dynamically rename the historical record in the background.
2. **Tactical UI Rendering (`IntrusionPage.tsx`)**:
   - **Zero-Node Dimming**: Sweeps that returned 0 hosts are visually deprioritized (`opacity-50 grayscale`) to draw the operator's eye towards successful reconnaissance data.
   - **Inline Accordions**: Clicking a session fetches the associated `intrusion_hosts` via `getSessionHosts()`. Instead of scrolling to a separate panel, the discovered nodes animate open inline directly beneath the session card using `framer-motion`.
   - **Quick Re-Scan**: A dedicated `RE-SCAN` button strips the SSID context, loads the original scan parameters (e.g., `DEEP` mode), and immediately primes the Sweep Configurator for re-engagement.
   - **Purge All**: Allows bulk deletion of the `scan_sessions` table for OPSEC clearing.

---

## 27. COMPREHENSIVE REPORTING ENGINE
**Objective:** Consolidate tactical intelligence into professional, executive-ready deliverables with interactive navigation.

### Flow Sequence & Features
> **Where this code lives.** Reading an archive and wording its values for a
> document is in `src/lib/report/archive.ts` — `apsOf`, `credentialsOf`,
> `smbEnumOf`, `assessReport`, `worstBySubject`, `formatMetres`,
> `positionCaveats`, `wpsLabel` and about forty more, most of them pure and now
> reachable from a test. The PDF builder itself is still `buildAndSavePDF`
> inside the `ReportsPage` component, but it is now 2,689 lines rather than
> 3,524: data preparation moved to `src/lib/report/assemble.ts`, the drawing
> primitives to `src/lib/report/layout.ts`, and three of the longest sections
> to `src/lib/report/sections/`. The characterization test that Phase 11 in
> [ENGINEERING_LOG.md](ENGINEERING_LOG.md) asked for first exists: `pdfdiff`
> compares the text streams of two exported documents, and every extraction
> was verified byte-identical against it before being kept.

1. **Multi-Report Aggregation (`ReportsPage.tsx`)**: 
   - Users can multi-select any combination of Wardriving Missions and LAN Recon Sweeps using the global archive checklist.
   - The engine iterates through the `reportsArray` and seamlessly constructs a unified document containing all targeted intelligence.
2. **Interactive Table of Contents**:
   - For multi-mission exports, the PDF generator dynamically builds a Table of Contents (TOC).
   - Uses `jspdf` internal link annotations (`doc.link()`) mapped to specific page coordinates, allowing stakeholders to click a TOC entry and jump instantly to the respective mission debrief.
3. **Executive Summary Branding**:
   - The cover page is styled using a "Dark Tactical" palette, mapping to the LOCKON (White) and EWAC (Blue/Pink) aesthetics.
   - A multi-paragraph operational summary details the attack surface, confidentiality protocols, and tactical findings.
4. **Three controls, not eight.** The header row is a credential-disclosure
   toggle, an `EXPORT` menu (`src/components/reports/ExportMenu.tsx`, grouped
   DOCUMENT / DATA / SPATIAL / EVIDENCE) and `PURGE`. The toggle is outside the
   menu because it is a *mode* that changes what the PDF contains and its state
   has to be legible at the moment of export — it is repeated on the PDF row
   inside the menu for the same reason. `PURGE` is outside because it is
   irreversible, and a destructive action one row below "JSON to clipboard" in
   a list of exports is how an engagement gets deleted by someone who meant to
   send it. The menu panel is rendered through a portal: the card it sits in is
   `overflow-hidden`, so an absolutely positioned dropdown is clipped at the
   card edge and how much survives depends on the window height.
5. **In-App PDF Viewer (Modal Overlay)**:
   - When a PDF export completes, instead of forcing the user into restrictive OS-level PDF viewer flows (which are often blocked by Tauri's webview sandbox), the application captures the `blob:` URL.
   - The notification toast becomes fully interactive. Clicking the popup triggers a full-screen `iframe`-based modal, rendering the generated PDF natively within the React interface.

---

## 28. SSL/TLS CERTIFICATE DEEP SCAN
**Objective:** Audit the cryptographic posture of HTTPS services by inspecting certificate metadata, cipher suites, and protocol versions.

### Flow Sequence
1. **Trigger (`IntrusionPage.tsx`)**: User clicks **"SSL/TLS SCAN"** on a host with port 443/8443 open.
2. **Backend Execution (`engine/scanner/ssl_check.py`)**:
   - **Certificate Inspection**: Connects via `ssl.SSLContext` with `CERT_NONE` mode to retrieve the full certificate chain without validation.
   - Extracts: Common Name (CN), Subject Alternative Names (SANs), Issuer, Expiry Date, Protocol Version, Cipher Name & Bit Strength.
   - **Self-Signed Detection**: Compares Issuer CN to Subject CN.
   - **Weak Cipher Audit (`check_weak_ciphers`)**: Enumerates all server-supported ciphers and flags those containing `RC4`, `DES`, `NULL`, `EXPORT`, or `MD5`, or with < 128-bit key length.
   - **Deprecated TLS Probing (`check_deprecated_tls`)**: Attempts handshakes with `TLS 1.0` and `TLS 1.1` to verify if the server accepts them.
   - **HSTS Check (`check_hsts`)**: Inspects the `Strict-Transport-Security` response header.
3. **Combined Report (`deep_ssl_scan`)**: Aggregates all findings into a unified report with severity-tagged entries.

---

## 29. VISUAL TRACEROUTE
**Objective:** Map the network path to a target host with hop-by-hop latency and TTL analysis.

### Flow Sequence
1. **Trigger (`IntrusionPage.tsx`)**: User clicks **"TRACEROUTE"** on a discovered host.
2. **Backend Execution (`engine/scanner/traceroute.py`)**:
   - Sends ICMP Echo Requests with incrementing TTL values (1 → 30).
   - Measures round-trip latency for each hop.
   - Resolves hostnames via reverse DNS where available.
3. **Real-time Streaming**: Each hop is emitted as a `traceroute_hop` event, rendered progressively in the UI.

---

## 30. VLAN DETECTION
**Objective:** Discover 802.1Q VLAN tagging on the local network segment.

### Flow Sequence
1. **Trigger (`IntrusionPage.tsx`)**: User clicks **"VLAN DETECT"** on a host.
2. **Backend Execution (`engine/scanner/vlan_detect.py`)**:
   - Sends crafted 802.1Q tagged frames and analyzes responses.
   - Identifies VLAN IDs, trunk ports, and cross-segment access opportunities.
3. **Data Return**: Emits `vlan_scan_started`, then `vlan_scan_completed` with
   the discovered VLAN topology. Nothing in the UI sends `vlan` yet, so this
   path is unrouted — see the known-gaps list in
   [ENGINEERING_LOG.md](ENGINEERING_LOG.md#known-gaps-stated-plainly).

---

## 31. SYSTEM HARDENING ARCHITECTURE
**Objective:** Ensure long-term reliability and maintainability of the application through defensive coding patterns.

### Key Components
1. **Engine Auto-Reconnect (`src/lib/ipc.ts`)**:
   - If the Python sidecar crashes or becomes unresponsive, the IPC layer automatically attempts reconnection using exponential backoff, `min(1000 * 2^n, 30000)` ms over at most 10 attempts — 1s, 2s, 4s, 8s, 16s, then capped at 30s.
   - Emits `reconnecting`, `reconnected`, and `reconnect_failed` events to the frontend.
   - `AppShell.tsx` displays an animated banner during reconnection and a toast on success/failure.
2. **Config Persistence (`engineStore.ts`)**:
   - Uses Zustand's `persist` middleware with `partialize` to save only the `config` object (COM port, baud rate, map style, location method, 3D/heatmap toggles) to `localStorage`.
   - Runtime state (GPS coordinates, connection status) is explicitly excluded from persistence.
3. **Tactical Confirm Modal (`src/components/common/ConfirmModal.tsx`)**:
   - Replaces all native `window.confirm()` calls with a branded, animated modal supporting `danger`, `warning`, and `info` variants.
   - Uses Framer Motion for spring-based entrance/exit animations with a blurred backdrop.
4. **Error Boundary (`App.tsx`)**:
   - React ErrorBoundary wrapper prevents white-screen crashes by catching component-level errors and displaying a recovery UI.
5. **Non-Blocking Toast System (`AppShell.tsx`)**:
   - Engine errors, disconnections, and reconnection events use color-coded toasts (red/amber/green) that auto-dismiss after 3-5 seconds.
6. **Type-Safe IPC (`src/types/engine.ts`)**:
   - All 58 engine commands are mapped to the `EngineCommand` union type, ensuring compile-time safety for every IPC call.
7. **Report DB Sync (`reportStore.ts` + `reportDB.ts`)**:
   - `clearAll()` action now executes `DELETE FROM intel_reports` before clearing UI state, preventing zombie reports on reload.

---

## 32. KEYBOARD SHORTCUTS
**Objective:** Enable fast, keyboard-driven navigation for tactical operators.

### Implementation (`src/hooks/useKeyboardShortcuts.ts`)
- Registered globally in `AppShell.tsx` via the `useKeyboardShortcuts()` hook.
- **Input Guard**: Shortcuts are disabled when focus is inside `<input>`, `<textarea>`, or `contentEditable` elements.

### Shortcut Map

| Shortcut | Action |
|---|---|
| `Ctrl + 1` | Navigate to Dashboard |
| `Ctrl + 2` | Navigate to Intrusion |
| `Ctrl + 3` | Navigate to Decryptor |
| `Ctrl + 4` | Navigate to Reports |
| `Ctrl + 5` | Navigate to Settings |
| `Escape` | Close active drawer/modal (dispatches `lockon:escape` event) |

---

## 33. TRAFFIC INTERCEPT & DEEP PROTOCOL PARSING
**Objective:** Capture and analyze target network traffic in real-time while ensuring 100% routing stability on Windows environments.

### Architecture (`engine/offensive/mitm.py`)
- **ARP Spoofing Engine:** Deploys continuous Layer-2 ARP poisoning against the target node and network gateway, placing the LOCKON engine physically inline.
- **Deep Protocol Parser:** Instead of using Scapy's resource-heavy protocol decoders (e.g., `scapy.layers.tls`), the engine uses high-speed manual byte-slicing to analyze raw TCP payloads. This keeps CPU usage negligible even under heavy network load.
  - **SNI Harvester:** Extracts the `Server Name Indication` (SNI) from TLS Client Hello packets (HTTPS/Port 443), revealing domains visited despite encryption.
  - **Credential Sniper:** Deeply inspects unencrypted traffic (Port 80 HTTP, Port 21 FTP, Port 23 Telnet) for `Authorization: Basic` headers, form data (`user=`, `pass=`), and plain-text login prompts. Flags findings with the `[CREDENTIALS]` tag.
- **Live Intelligence Radar UI:** The frontend (`IntrusionPage.tsx`) dynamically parses intercepted packets into a color-coded Matrix stream (DNS = Gray, SNI = Neon, Creds = Red). Features a sticky "Loot Vault" to pin captured passwords.

### 3-Layer Routing Fallback (Windows Stability)
Scapy's `sendp()` function natively requires WinPcap/Npcap `\Device\NPF_{GUID}` interfaces on Windows. Passing human-readable adapter names (e.g., "TP-Link USB") often fails during active transmission or ARP restoration. To prevent the engine from crashing or leaving the target's ARP table corrupted, LOCKON employs a **3-Layer Fallback**:
1. **Targeted Layer 2:** Attempts `sendp(..., iface=interface)`.
2. **Auto-Routed Layer 2:** If the interface name fails resolution, attempts `sendp(...)` without the `iface` argument, relying on Scapy's default MAC routing table.
3. **OS-Level Layer 3:** If Scapy's Layer-2 engine fails completely, attempts `send(ARP(...))`, delegating route determination to the native Windows IP routing table.
This guarantees that Spoofing and Restoring phases always execute, preventing target network disconnection.
