# Architecture and project layout

> **[← Back to the README](../README.md)** ·
> [Install](INSTALL.md) · [Architecture](ARCHITECTURE.md) · [Testing](TESTING.md) · [Troubleshooting](TROUBLESHOOTING.md) ·
> [Engineering log](ENGINEERING_LOG.md) · [Playbook](PLAYBOOK.md) · [AP location methods](AP_LOCATION_METHODS.md) · [GPS & survey](GPS_AND_SURVEY.md)


How the three stacks fit together, where every file lives, and the two
pipelines whose behaviour is easiest to get wrong.

## System architecture

LOCKON utilizes a **"Decoupled Triple-Stack Architecture"**:

```
┌────────────────────────────────────────────────────────┐
│  Frontend (React 19 + Tailwind 4 + Zustand + Framer)   │
│  "Dark Tactical" UI - Unidirectional data flow for     │
│   high-frequency state updates (GPS ticks, AP batches) │
│  Location: Likelihood Grid / Track Pos / Multilateration│
└─────────────────────────┬──────────────────────────────┘
                          │ IPC (stdout/stdin JSON)
┌─────────────────────────┴──────────────────────────────┐
│  Core (Tauri v2 / Rust)                                │
│  Ultra-fast IPC bridge, Window management,             │
│  SQLite plugin, Shell plugin for sidecar spawning      │
└─────────────────────────┬──────────────────────────────┘
                          │ Sidecar Process
┌─────────────────────────┴──────────────────────────────┐
│  Engine (Python 3.13 - PyInstaller .exe)               │
│  ├─ scanner/wifi.py     → PyWiFi + EMA + Trend Detect  │
│  ├─ scanner/oui.py      → Scapy Manufdb (35k+ mfg)     │
│  ├─ scanner/lan.py      → LAN Recon (ARP, Ports, TTL)  │
│  ├─ scanner/smb_enum.py → NTLMSSP & EternalBlue checks │
│  ├─ scanner/ssl_check.py→ TLS Certificate Deep Scan    │
│  ├─ scanner/traceroute.py→ Visual Hop-by-Hop Trace     │
│  ├─ scanner/vlan_detect.py→ 802.1Q VLAN Discovery      │
│  ├─ scanner/cve_db.py   → Offline Threat Intelligence  │
│  ├─ scanner/passive.py  → SIGINT Radar (ARP, Probes)   │
│  ├─ scanner/probe_monitor.py → WiFi Probe Requests     │
│  ├─ scanner/strike.py   → Deauth Jamming Module        │
│  ├─ scanner/vuln_engine.py → Web Secrets & Exploits    │
│  ├─ scanner/gpr_engine.py  → GPR Deep Analysis (scikit)│
│  ├─ offensive/          → Bruteforce, Sprayer, MITM    │
│  │   ├─ capture.py      → WPA handshake interception   │
│  │   ├─ decryptor.py    → Offline PCAP hash cracking   │
│  │   └─ mitm.py         → ARP Spoofing & Sniffing      │
│  ├─ gps/reader.py       → NMEA 0183 + HDOP extraction  │
│  └─ ipc/handler.py      → GPS validation + event emit  │
│       ├─ HDOP Quality Filter (>5.0 = reject)           │
│       ├─ Haversine Speed Outlier (>200km/h = reject)   │
│       └─ Auto-Reconnect (exponential backoff)          │
└────────────────────────────────────────────────────────┘
```

## Project structure

> 📖 **[View the Operational Playbook (PLAYBOOK.md)](PLAYBOOK.md)** for detailed technical workflows on how SCAN, INTRUSION, STRIKE, and ANTENNA BENCHMARK logic execute under the hood.

> 📡 **[View the AP Location Methods Encyclopedia (AP_LOCATION_METHODS.md)](AP_LOCATION_METHODS.md)** for a deep dive into the mathematical models behind our Wardriving GPS tracking (Centroid, FSPL, Bayesian, and Machine Learning GPR).

```
LOCKON-EWAC/
├── docs/                         # Technical documentation & Playbooks
│   ├── PLAYBOOK.md               # Architecture and Logic Flows
│   └── AP_LOCATION_METHODS.md    # Geolocation Algorithm Encyclopedia
├── src/                          # React Frontend
│   ├── components/
│   │   ├── layout/               # AppShell, Sidebar, TopBar
│   │   ├── dashboard/            # MapView, ScanFeed, KpiGrid, Drawers
│   │   ├── intrusion/            # VaultDrawer, PassiveSigintView
│   │   ├── reports/              # ExportMenu (grouped export actions)
│   │   └── common/               # ConfirmModal (shared UI components)
│   ├── hooks/                    # useKeyboardShortcuts
│   ├── pages/                    # Dashboard, Intrusion, Decryptor, Reports, Settings
│   ├── stores/                   # Zustand state (7 stores; 3 use persist middleware)
│   │   ├── engineStore.ts        # Engine config (persisted to localStorage)
│   │   ├── missionStore.ts       # Wardriving APs & GPS trail
│   │   ├── intrusionStore.ts     # LAN recon hosts & sessions
│   │   ├── strikeStore.ts        # Active deauth operations
│   │   ├── reportStore.ts        # Intel reports (SQLite-synced)
│   │   ├── passiveSigintStore.ts # SIGINT session state
│   │   └── uiStore.ts            # UI preferences & visual settings
│   ├── types/                    # TypeScript types (59 EngineCommands)
│   └── lib/                      # IPC, engine routing, persistence, rules, report building
│       ├── ipc.ts                # Engine IPC with auto-reconnect
│       ├── engineRouter.ts       # All 62 engine events -> stores (no React, no DOM)
│       ├── scopeSync.ts          # Pushes the engagement scope to the engine
│       ├── database.ts           # SQLite helper (getDb, query, execute)
│       ├── wardrivingDB.ts       # Mission & AP persistence
│       ├── intrusionDB.ts        # Scan session & host persistence
│       ├── credentialDB.ts       # Credential vault operations
│       ├── vaultCrypto.ts        # AES-256-GCM, key from an operator passphrase
│       ├── reportDB.ts           # Intel report CRUD + export stamping
│       ├── findingsDB.ts         # Findings, evidence register, retest baselines
│       ├── scopeDB.ts            # Engagement scope, targets and the audit trail
│       ├── coverageDB.ts         # Survey coverage, frozen into the archive
│       ├── crackingDB.ts         # Cracking history (sealed alongside the vault)
│       ├── benchmarkDB.ts        # Antenna benchmark records
│       ├── riskEngine.ts         # The one rule set behind every severity
│       ├── localization.ts       # The AP position estimators
│       ├── severityStyle.ts      # One colour per severity: screen and print
│       ├── signalStyle.ts        # One set of RSSI bands (reception, never risk)
│       ├── numbers.ts            # Numeric reads that refuse to invent a measurement
│       ├── cidr.ts               # Which range an address is in; not three octets of text
│       ├── csv.ts                # RFC 4180 cells, neutralised against formula injection
│       ├── constants.ts          # App and map constants (no thresholds; see the note in it)
│       ├── cspReporter.ts        # Names a Content-Security-Policy violation
│       ├── html.ts               # Escaping between an SSID and a map popup
│       ├── basemap.ts            # Offline basemap: pmtiles:// over two narrow Rust commands
│       ├── basemapStyle.ts       # The offline style; names no host, which a test enforces
│       ├── mapUncertainty.ts     # The radius and the second candidate, on the live map too
│       ├── map/
│       │   └── surveyLayers.ts   # The layers both maps draw, defined once
│       ├── position.ts           # A position, what it is worth, and how to draw it
│       ├── apRisk.ts             # Between a stored record and the one risk rule set
│       └── report/
│           ├── archive.ts        # Reading an archive and wording it for a document
│           ├── assemble.ts       # Every figure the report states, gathered before drawing
│           ├── geometry.ts       # One definition of where things sit on a page
│           ├── icons.ts          # Vector glyphs drawn beside each section heading
│           ├── layout.ts         # Page furniture: fit, headings, paragraphs, callouts
│           ├── surveyMap.ts      # The drive and its access points, rendered offscreen
│           ├── kmz.ts            # A zip writer, so an exported map carries its own pins
│           ├── sections/         # All 19 document sections, one module each
│           └── exports/          # CSV, KML, GeoJSON: archive in, document text out
├── engine/                       # Python Backend (Sidecar)
│   ├── scanner/
│   │   ├── wifi.py               # 802.11 WiFi scanning (PyWiFi + EMA)
│   │   ├── oui.py                # OUI Vendor Lookup (35k+ manufacturers)
│   │   ├── lan.py                # LAN Recon (ARP, Ports, TTL, MAC, CVE)
│   │   ├── ssl_check.py          # TLS Certificate Deep Scan
│   │   ├── traceroute.py         # Visual Hop-by-Hop Traceroute
│   │   ├── vlan_detect.py        # 802.1Q VLAN Discovery
│   │   ├── smb_enum.py           # NTLMSSP & EternalBlue checks
│   │   ├── cve_db.py             # Offline CVE Intelligence Matrix
│   │   ├── passive.py            # SIGINT Radar (ARP, DHCP, mDNS)
│   │   ├── probe_monitor.py      # WiFi Probe Request Tracker
│   │   ├── strike.py             # Active Countermeasures (Deauth)
│   │   ├── vuln_engine.py        # Modular Vulnerability Scanner
│   │   ├── wps_detect.py         # 802.11 Beacon WPS Extraction
│   │   ├── gpr_engine.py         # Gaussian Process Regression (ML)
│   │   ├── netsh_wlan.py         # Windows netsh parser: cipher, auth, BSS Load
│   │   ├── net_context.py        # The one honest way to attach an IP to an AP
│   │   ├── evil_twin.py          # Rogue-AP scoring (the only source of a verdict)
│   │   ├── clients.py            # Stations seen associated with an AP
│   │   ├── ap_track.py           # Shared sighting tracker (live scan and simulator)
│   │   └── simulator.py          # The rehearsal scenario, always flagged simulated
│   ├── offensive/
│   │   ├── auto_attack.py        # Autonomous Attack Orchestrator
│   │   ├── bruteforce.py         # Network service cracking
│   │   ├── capture.py            # WPA handshake & PMKID interception
│   │   ├── decryptor.py          # Offline PCAP hash cracking
│   │   ├── dirbuster.py          # Web directory enumeration
│   │   ├── hashcat_export.py     # PMKID to .hc22000 converter
│   │   └── mitm.py               # ARP Spoofing & DNS/HTTP Interception
│   ├── gps/
│   │   └── reader.py             # NMEA GPS serial reader (HDOP)
│   ├── ipc/
│   │   └── handler.py            # IPC router + GPS pipeline + reconnect
│   ├── tests/                    # 32 files, 683 tests; no third-party packages needed
│   ├── policy.py                 # The engagement scope gate (deny by default)
│   ├── capability.py             # What this hardware can actually do
│   ├── evidence.py               # Artifact hashing and tamper detection
│   ├── cve_feed.py               # CVE snapshot: CPE-matched NVD pull, merged over the seed
│   ├── build_stamp.py            # Which build this is: git describe, build time, frozen
│   ├── logging_setup.py          # File logging; stdout stays the IPC channel
│   └── wordlists_path.py         # Wordlist resolution, refuses to be walked out of
├── src-tauri/                    # Rust / Tauri Core
│   ├── binaries/                 # Compiled Python sidecar - rebuild after engine changes
│   │   └── ewac-engine/          # One directory: the exe plus _internal/ (must stay siblings)
│   ├── src/
│   │   ├── lib.rs                # Plugins, migrations, commands
│   │   └── basemap.rs            # Byte ranges from one fixed path; no fs permission
│   ├── migrations/               # SQLite database schemas (19), pinned to LF by .gitattributes
│   └── tauri.conf.json           # Tauri config; csp (build) and devCsp (dev) are separate
├── tests/                        # 23 frontend suites (679 tests)
│   ├── entries/                  # esbuild entry points, so a module can be bundled for Node
│   ├── stubs/                    # Real SQLite and a fake sidecar, not mocks
│   └── components/               # 20 files, 153 tests: vitest + jsdom against real components
│       └── stubs/maplibre-gl.ts  # Records what the map was told; draws nothing (jsdom has no WebGL)
├── scripts/
│   ├── cdp.mjs                   # Shared CDP plumbing for both app harnesses
│   ├── csp-smoke-test.mjs        # Drives the app over CDP; fails if the policy blocked anything
│   ├── export-smoke-test.mjs     # Exports a real PDF and diffs it against the baseline
│   ├── pdfdiff.mjs               # Compares what two PDFs *say*, ignoring dates and digests
│   ├── benchmark.mjs             # Memory and CPU of the app's own process tree, by phase
│   ├── capture-previews.mjs      # The README screenshots, taken from the running app
│   ├── check-docs.mjs            # Every mechanically checkable claim in the docs
│   ├── check-ci-parity.mjs       # No source file is hidden from a fresh clone; $? survives -e
│   ├── check-wordlists.mjs       # Every shipped list is documented; a WPA list holds WPA passphrases
│   ├── check-report-margins.mjs  # Nothing in the report PDF is drawn off the page
│   ├── check-severity-classes.mjs # Every severity/signal class has a rule in the built CSS
│   ├── check-sidecar-resources.mjs # Starts the frozen engine; the bundle is what was built
│   ├── check-migration-eol.mjs   # Migrations are LF and registered; a CRLF one breaks startup
│   ├── check-risk-claims.mjs     # Only the rule set decides how bad something is
│   ├── check-map-parity.mjs      # The two maps draw the same things the same way
│   ├── check-no-glow.mjs         # No zero-offset shadows; offset ones are depth
│   ├── check-fonts.mjs           # Every declared face has a file; no font CDN anywhere
│   ├── check-fonts-runtime.mjs   # Measures, in the shipped WebView2, which family is in use
│   ├── check-cleartext-urls.mjs  # No third-party host over plain HTTP in anything exported
│   ├── check-kmz-assets.mjs      # Every icon the KML names is packed and on disk
│   ├── check-basemap-runtime.mjs # Blocks the tile hosts and reads the archive from disk
│   ├── refresh-fonts.mjs         # Re-fetches the self-hosted woff2 (needs a network)
│   ├── fetch-basemap-glyphs.mjs  # Map label glyphs; fontstacks read from the theme
│   ├── make-kml-icons.py         # Draws the two placemark pins, so none are borrowed
│   ├── migrate-legacy-db.mjs     # Carries data forward from the older schema line
│   └── sync-wordlists.mjs        # Keeps the sidecar's wordlists in step with engine/wordlists
└── public/                       # Static assets & logos
```

## GPS quality pipeline

Every stage here exists because the stage was missing once and something wrong
was drawn on the map. Nothing is stamped on an access point or added to the
track until it has passed all four.

```
  NMEA Sentence (GPGGA / GPRMC)
          │
          ▼
  ┌────────────────────────┐   GGA gps_qual == 0?
  │ Stage 0: does the      │   RMC status == 'V'?
  │ receiver stand behind  │────── YES ──▶ ❌ REJECT
  │ this? (gps/reader.py)  │              (no fix / void sentence)
  └────────┬───────────────┘
           │ NO — it is a real fix
           ▼
  ┌───────────────────┐     HDOP > 5.0?
  │ Stage 1: HDOP     │────── YES ──▶ ❌ REJECT
  │ Quality Filter    │               (poor satellite geometry)
  └────────┬──────────┘
           │ NO
           ▼
  ┌────────────────────┐    Speed > 200 km/h?
  │ Stage 2: Speed     │────── YES ──▶ ❌ REJECT
  │ Outlier (Haversine)│              (GPS jump / multipath)
  └────────┬───────────┘
           │ NO
           ▼
     ✅ VALID POSITION
     ├─▶ Stamp on AP (scan loop)
     │
     └─▶ ┌──────────────────────┐   moved < GPS_STEP_M (5 m)
         │ Stage 3: is this a   │────── YES ──▶ ⏸ NOT RECORDED
         │ step, or scatter?    │              (stationary jitter)
         │ (engineRouter.ts)    │
         └────────┬─────────────┘
                  │ NO — real travel
                  ▼
            Appended to the track
```

**Stage 0** reads the field each sentence carries about its own validity, which
nothing did until v1.0.0. A receiver with no fix still emits GGA and still fills
in a latitude — the last one it believed, or a partial solution — and a receiver
that *loses* lock keeps emitting those, overwriting the last good position every
time. That is where a parked vehicle got both a moving track and a heading.

**Stage 3** is not cosmetic, and it is the one with consequences beyond the
display. The track **is** the baseline the localizer trilaterates from, so
recording scatter as travel offers that scatter to the estimators as survey
geometry. One archived survey holds 280 fixes spanning 9.9 m.

**What happens downstream when the track is still too short.** The estimators do
not try. `estimateLocation` gates on `MIN_ALONG_TRACK_M` *before* dispatching to
any method, returns a position marked `resolved: false`, and the map groups
those into one counted marker per place the operator stood rather than stacking
them. See [§4d of the location methods encyclopedia](AP_LOCATION_METHODS.md).

## Tech stack

| Layer | Technology | Version |
|---|---|---|
| **Core** | [Tauri](https://tauri.app/) (Rust) | v2.0 |
| **Frontend** | [React](https://react.dev/) | v19.1 |
| **Build** | [Vite](https://vite.dev/) | v7.0 |
| **Styling** | [Tailwind CSS](https://tailwindcss.com/) | v4.2 |
| **State** | [Zustand](https://zustand.docs.pmnd.rs/) | v5.0 |
| **Animation** | [Framer Motion](https://motion.dev/) | v12.x |
| **Maps** | [MapLibre GL JS](https://maplibre.org/) | v5.23 |
| **Routing** | [React Router](https://reactrouter.com/) | v7.14 |
| **Engine** | [Python](https://python.org/) (PyInstaller sidecar) | 3.13 |
| **Machine Learning**| [scikit-learn](https://scikit-learn.org/) + [numpy](https://numpy.org/) + [scipy](https://scipy.org/) | `>=1.3.0` / `>=1.24.0` / `>=1.10.0` (see `engine/requirements.txt`) |
| **WiFi** | [PyWiFi](https://github.com/awkman/pywifi) | v1.1 |
| **Packets** | [Scapy](https://scapy.net/) | v2.7 |
| **GPS** | [PyNMEA2](https://github.com/Knio/pynmea2) + [PySerial](https://github.com/pyserial/pyserial) | v1.19 / v3.5 |
| **SSH** | [Paramiko](https://www.paramiko.org/) | v3.0 |
| **Database** | SQLite (via [Tauri SQL Plugin](https://v2.tauri.app/plugin/sql/)) | WAL mode |
| **TypeScript** | [TypeScript](https://www.typescriptlang.org/) | v5.8 |
