# Installing and building LOCKON EWAC

> **[← Back to the README](../README.md)** ·
> [Install](INSTALL.md) · [Architecture](ARCHITECTURE.md) · [Testing](TESTING.md) · [Troubleshooting](TROUBLESHOOTING.md) ·
> [Engineering log](ENGINEERING_LOG.md) · [Playbook](PLAYBOOK.md) · [AP location methods](AP_LOCATION_METHODS.md) · [GPS & survey](GPS_AND_SURVEY.md)

Everything needed to get from a clone to a running build, and the hardware
that decides what the tool can actually do on your machine.

<img src="../img/for-install/Installing%20and%20building%20LOCKON%20EWAC.jpg" alt="Installing and building LOCKON EWAC" width="100%">

## Installing a released build

If you just want to run it, this is the whole procedure: download
`lockon-ewac-setup.exe` from **[the Releases page](https://github.com/Meow-011/LOCKON-EWAC/releases/latest)** and
run it. Nothing else is required on the machine — no Python, no Node, no runtime,
no account.

### Check what you downloaded

The installer carries a Wi-Fi scanner, a password-recovery front end and a packet
capture path. Nobody should run one of those from a file they have not identified,
and this one is **not code-signed** (see [the note below](#known-gap-the-installer-is-not-signed)),
so a signature cannot do the identifying for you. The digest can:

```powershell
Get-FileHash .\lockon-ewac-setup.exe -Algorithm SHA256
```

| v1.0.0 | |
|---|---|
| Size | 119,685,790 bytes (114.1 MiB) |
| SHA-256 | `7527db67af61fca95726e2db8258b1de0d5177c1ae836c1963657fc4d2fc6a78` |

If it does not match, do not run it.

That digest is reproducible, which is worth stating because it is not true of every
installer: compiling `installer/lockon-ewac.iss` twice from the same application,
sidecar and wordlists produced two files with **the same SHA-256**, so the number
above identifies the inputs rather than the moment the build ran.

### Why the binary is not in the git repository

It is 114.1 MiB and GitHub refuses any single file over 100 MiB, so committing it
is not a choice that was weighed and rejected — the push is blocked outright. The
second reason outlives the first: git keeps every version of every file for ever,
and an installer that is rebuilt for each release would add its whole size to the
clone every time, permanently. A release asset is downloaded by the people who want
it and costs nothing to everybody who clones to read the source.

- **64-bit Windows 10 or 11.** The installer refuses anything older rather than
  letting you find out from a blank window: WebView2 is a hard requirement and
  nothing here is tested below Windows 10.
- **No administrator rights needed.** It installs per-user by default; elevate
  only if you want it under `%ProgramFiles%` for every account. The application
  itself needs no elevation — only two of its features do, and they say so at
  the moment you reach them rather than failing quietly.
- **SmartScreen will warn you.** The installer is not signed yet, so you will
  need **More info → Run anyway**. See [the note below](#known-gap-the-installer-is-not-signed);
  the fix is a certificate, not something an installer should talk you past.
- **Uninstalling keeps your surveys** and asks before removing them. See
  [What an uninstall keeps](#what-an-uninstall-keeps).

## What it needs from the machine

Measured, not estimated. `npm run benchmark` drives the built application through
launch, an archive list, a survey report, the tactical map and a full PDF export
while sampling every process in the app's own tree twice a second. The figures
below are the worst case it found, twice, on the largest survey available.

| | Minimum | Comfortable |
|---|---|---|
| **RAM** | 8 GB | 16 GB |
| **CPU** | any x64 dual-core | 4 cores |
| **Disk** | 500 MB, plus about 3 MB per scan session | 5 GB free |
| **Graphics** | anything WebGL-capable, including integrated | — |
| **OS** | 64-bit Windows 10 | Windows 11 |

### Where those numbers come from

Peak, during a PDF export of a 183-access-point survey: **1.63 GB working set,
1.10 GB private**. Idle with the window open: **1.0 GB working set, 0.78 GB
private**. Two runs agreed to within 0.3%.

Both figures are given because they answer different questions. Working set is
what Task Manager shows, so it is what you will see; private bytes is memory that
belongs to this application and nothing else, so it is the honest answer to "how
much RAM does this need". The gap between them is WebView2's processes sharing one
browser runtime.

Where it goes, at peak:

| Process | MB |
|---|---|
| `msedgewebview2.exe` (several, the interface) | 1,451 |
| `ewac-engine.exe` (Python, scipy + numpy + scikit-learn) | 141 |
| `lockon-ewac.exe` (the Tauri shell) | 39 |

The engine sat at exactly 141 MB in every phase of every run. It loads its
scientific stack at start-up and does not grow with the size of the survey; the
interface does.

**It is not CPU-bound.** The highest sustained figure was **1.13 cores** during
launch and **0.3–0.7 cores** during the PDF export, on a 16-core machine — so
roughly 7% of it. Idle costs 0.21 cores. The dual-core minimum is about not
contending with the export rather than about throughput; four cores is comfortable
because nothing here will use more.

**Disk.** The installation is 270 MB. The database on the machine this was
measured on is 121.6 MB after **39 scan sessions across five months** — about
3.1 MB per session — and it is dominated by 414,867 `scan_logs` rows rather than by
the surveys themselves, so it grows with how long you scan rather than with how
much you find. An offline basemap, if you install one, is separate and sized by the
extract you choose: a city is a few megabytes, a continent is gigabytes.

**Start-up** was 2.2 seconds from launching the executable to `Engine: ONLINE`,
consistently. Read that as a warm figure: the machine had WebView2 already resident
for other applications, which is the common case on Windows and not the first-boot
case.

### What these numbers do not cover

* **A live scan.** Every phase replays recorded survey data. Measuring capture
  needs radio hardware, Npcap and somewhere to drive to, so the memory and CPU
  cost of the capture path is **not** in the table above and is not claimed to be.
* **One machine, one configuration** — an Intel Core Ultra 7 255H with 16 logical
  cores, 31.5 GB of RAM, Intel Arc 140T integrated graphics, Windows 11 build
  26200. A slower disk or a machine under memory pressure will behave differently.
* **Software rendering.** The map draws through WebGL. Integrated graphics was
  enough; a machine with no GPU acceleration at all was never tested.

### A caution about reading memory figures on Windows

WebView2 is the operating system's web runtime, not this application's. Office,
Teams, Widgets and a good deal else each run their own `msedgewebview2.exe`
processes — thirty of them were already resident on the machine this was measured
on, holding **1,063 MB** between them before the benchmark started.

The first version of `scripts/benchmark.mjs` selected processes by name and
therefore added all of that to its answer, reporting 2.6 GB where the truth was
1.6 GB. It now walks `ParentProcessId` down from the executable it launched and
prints how much it excluded. If you measure this yourself in Task Manager, the
same trap is waiting: group by the LOCKON EWAC entry rather than counting every
WebView2 process on the machine.

Everything below this point is for building from source.

## Why the engine ships as a directory and not a single file

Worth knowing before the build steps, because it explains the size.

PyInstaller's `--onefile` appends a compressed archive to the executable and
unpacks the whole thing into `%TEMP%` **on every launch**. Measured on this
machine, three runs each: onefile reached its `ready` event in a median of
**20.4 s**, onedir in **2.5 s**. Those twenty seconds are exactly what an
operator sees as "Engine: OFFLINE" after opening the app, and they are paid
again every single time.

The trade is disk, and the figure had drifted: this said 162 MB expanded, which
was true when it was written. Measured again today the engine's onedir output is
**205 MB**, the whole installation is **270 MB**, and the installer that carries it
is **115 MB** — the compression the paragraph relies on is still doing its work.

Disk is not the resource you are short of while sitting in a car waiting for a
scan to start. About 27 MB of that 205 MB is not even reachable: PyInstaller's
scikit-learn hook pulls in `matplotlib` (13.9 MB) and `PIL` (12.8 MB) as optional
plotting dependencies, the spec excludes nothing, and the engine imports neither —
`import sklearn` and `import sklearn.gaussian_process` both leave them out of
`sys.modules`. They cost download and disk and never memory.

This is why `_internal\` exists beside the executable, and why the two must stay
siblings.

## Quick start

```bash
# 1. Clone the repository
git clone https://github.com/Meow-011/LOCKON-EWAC.git
cd LOCKON-EWAC

# 2. Install frontend dependencies
npm install

# 3. Set up Python engine
cd engine
python -m venv .venv
.venv\Scripts\activate         # Windows
pip install -r requirements.txt

# 4. Build the sidecar binary
.venv\Scripts\pyinstaller.exe ewac-engine-x86_64-pc-windows-msvc.spec --distpath ..\src-tauri\binaries --noconfirm

# Produces src-tauri\binaries\ewac-engine\ containing the executable and
# _internal\. Those two must stay siblings: the PyInstaller bootloader
# resolves _internal relative to the executable, and separating them fails
# with "Failed to load Python DLL".
cd ..

# 5. Launch!
npm run tauri dev
```

> **Tip:** Enable **Simulation Override** in Settings to test without GPS/WiFi hardware attached.

## Development setup

**Prerequisites:**

- Node.js v18+
- Rust & Cargo (latest stable)
- Python 3.10+ (this build: 3.13.5) — 3.10 is a hard floor, the engine uses PEP 604 unions
- (Optional) USB GPS Receiver (NMEA 0183)
- (Optional) Monitor-Mode Wi-Fi Adapter & Npcap (required for STRIKE Deauth capabilities)
- (Optional) [hashcat](https://hashcat.net/hashcat/) 6.0+ on `PATH`, or at `C:\hashcat\hashcat.exe` / `C:\Tools\hashcat\hashcat.exe` / `~\hashcat\hashcat.exe` — **required by the Decryptor**, which refuses to run without it rather than simulating a crack
  Unpack the **whole** archive to one of those locations, not just the `.exe` —
  hashcat loads its OpenCL kernels and modules from the files beside it.
  `~\hashcat\` needs no administrator rights, which makes it the
  easiest of the three. The Decryptor refuses to start when it cannot find
  hashcat and lists every path it searched; it never falls back to a simulation.

**Before you can run anything offensive:** open **Settings → Engagement Scope** and define the engagement. The engine denies every gated command until one is active. See _Engagement Scope & Audit Trail_ above.

### 1. Install Dependencies

```bash
# Frontend
npm install

# Python Engine
cd engine
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

### 2. Build the Python Sidecar

The Python engine must be compiled into a standalone `.exe` before Tauri can use it:

```bash
cd engine
.venv\Scripts\pyinstaller.exe ewac-engine-x86_64-pc-windows-msvc.spec --distpath ..\src-tauri\binaries --noconfirm

# Produces src-tauri\binaries\ewac-engine\ containing the executable and
# _internal\. Those two must stay siblings: the PyInstaller bootloader
# resolves _internal relative to the executable, and separating them fails
# with "Failed to load Python DLL".
```

> **Important:** You must rebuild the sidecar every time you modify Python code in the `engine/` directory.

The frozen sidecar reads its wordlists from `src-tauri/binaries/wordlists/`, not
from `engine/wordlists/` (see `engine/wordlists_path.py`). `npm run dev` and
`npm run build` sync that directory automatically via `npm run sync:wordlists`;
run it by hand if you add a list and want it visible without restarting either:

```bash
npm run sync:wordlists
```

The sync only copies — wordlists uploaded from the UI land in the sidecar's
directory and are never deleted.

### 3. Launch in Tactical Mode (Dev)

```bash
npm run tauri dev
```

_Note: **Simulation Override** in Settings drives a full scenario instead of the radio — 11 access points at known positions, a vehicle moving along a route with a turn in it, and RSSI from the same path-loss model the localizer inverts. It exists so a report can be rehearsed before the field: localization, rogue-AP scoring and coverage all run for real against it. Every row it produces is stamped `simulated`, and the report refuses to present it as field evidence._

### 4. Compile for Production

```bash
npm run tauri build
```

The standalone `.exe` installer can be found in `src-tauri/target/release/bundle/`.

## Recommended hardware arsenal

While LOCKON EWAC can run on any standard laptop, unlocking its full offensive potential requires specific external hardware:

### 1. The Wi-Fi Adapter (Crucial for STRIKE & WPA Capture)

To utilize **STRIKE (Deauth Jamming)**, **PMKID Capture**, or **EAPOL Handshake Interception**, your wireless adapter **MUST** support **Monitor Mode** and **Packet Injection**.
_Note: Your standard built-in laptop Wi-Fi (e.g., Intel AX200) will only work for Passive Wardriving and LAN Scanning, but cannot inject raw packets._

**Recommended Chipsets:**

- **Realtek RTL8812AU / RTL8814AU** (Excellent dual-band 2.4/5GHz performance)
- **Atheros AR9271** (Legendary 2.4GHz stability, out-of-the-box support)
- **MediaTek MT7921AU** (Modern Wi-Fi 6 / 6E support)

**Tested Tactical Adapters:**

- **Alfa AWUS036ACH** (Dual-Band 2.4/5GHz - Highly Recommended)
- **Alfa AWUS036NHA** (2.4GHz only - Bulletproof reliability)
- **Panda PAU09** (Dual-Band, compact)

### 2. Antenna Selection & Tactics

Your Wi-Fi adapter is only as good as the antenna attached to it. Choose based on your mission profile:

- **Omni-Directional (Rubber Duckies):** Best for **Wardriving** in vehicles. They capture signals in a 360-degree donut shape. Recommended: 5dBi to 9dBi gain.
- **Directional (Yagi / Panel):** Best for stationary targeting (**STRIKE, MITM**). Focuses the RF energy into a narrow beam, multiplying range significantly but requiring physical aiming at the target.

### 3. The GPS Receiver (For Wardriving)

A hardware GPS module that outputs **NMEA 0183** over a USB serial (COM) port.
There is no software fallback: an access point seen without a position is
recorded, but it cannot be placed on a map or in the report's position tables,
and nothing recovers that afterwards.

**Recommended modules:** **GlobalSat BU-353-S4** (USB puck, weatherproof,
magnetic -- built for exactly this); **u-blox NEO-6M** or **NEO-M8N** (cheap,
reliable, well supported). Baud defaults to `9600`; set it and the COM port in
Settings.

> **Which module you buy matters less than where you put its antenna and how you
> drive.** Both decide whether positions can be computed **at all**, not merely
> how precise they are --- a receiver that cannot hold HDOP under 5 records no
> coordinates rather than poor ones. See
> **[GPS and survey technique](GPS_AND_SURVEY.md)** before the first real survey.

### 4. USB Power & Virtual Machines

- **Power Draw:** Active packet injection consumes significant power. High-end adapters (like the Alfa AWUS036ACH) may require a dual-USB Y-cable or a powered USB hub to prevent brownouts and disconnects during heavy STRIKE operations.
- **VM Passthrough:** If running LOCKON inside VMware or VirtualBox, you _must_ use a USB Wi-Fi adapter. Built-in PCI-E laptop Wi-Fi cards generally cannot be passed through to guest operating systems in Monitor Mode.

### 5. RF Interference & Cable Shielding

- **The Self-Jamming Problem:** When high-power adapters (like Alfa) transmit deauth frames at 1000mW+, they generate immense electromagnetic interference. This RF noise can leak into unshielded USB cables, causing the Wi-Fi card to abruptly disconnect from Windows.
- **The Fix:** Always use high-quality **Shielded USB Cables** equipped with **Ferrite Chokes** (the plastic cylinders at the ends of the cable) to filter out high-frequency noise and maintain connection stability during STRIKE operations.

### 6. Npcap Driver (Windows Only)

If running on Windows native, you must install [Npcap](https://npcap.com/) (the successor to WinPcap). During installation, **ensure "Support raw 802.11 traffic (and monitor mode) for wireless adapters" is checked**.

## The offline basemap (optional, and worth it)

With no network the map is a flat grid: your markers and your track draw on it,
but there is no coastline, no roads and no place names to locate them against.
This is a tool that is carried into buildings and vehicles, so that is the normal
case rather than the degraded one.

The fix is a **PMTiles archive** — one file holding every tile, which the
application reads straight off the disk. There is no tile server to run and
nothing to unpack.

It is **not shipped**, because the right extract depends on where you work: the
whole planet is tens of gigabytes, and a country or a city is a few megabytes to
a few hundred. **Settings -> Offline Basemap** shows the exact path to put one at
and whether the one you put there was readable.

### Getting an archive

The planet builds and the extract tool both come from [Protomaps](https://protomaps.com/),
whose schema the bundled style matches.

```bash
# The pmtiles CLI: https://github.com/protomaps/go-pmtiles/releases
# An extract is pulled from the public planet build over range requests, so you
# download roughly the size of the area you ask for rather than the planet.

pmtiles extract https://build.protomaps.com/20260101.pmtiles bangkok.pmtiles     --bbox=100.33,13.49,100.94,13.96 --maxzoom=14
```

Then copy it to the path Settings shows, named exactly `basemap.pmtiles`, and
press **Re-check**.

### What to expect

- **Zoom.** `--maxzoom=14` is streets and building outlines, which is what a
  survey needs; 15 and 16 add detail and multiply the size.
- **Edges.** Outside the extract's bounding box the map is plain background. That
  is the edge of your data, not a failure — Settings prints the bounds the archive
  reports so you can see where they are.
- **Labels.** Latin, Latin Extended, Thai and Devanagari are carried in the
  application. A label in a script outside those — Cyrillic, Arabic, CJK — is
  dropped by MapLibre with no mark on the map. Adding a script is a line in
  `scripts/fetch-basemap-glyphs.mjs` and a re-run.
- **Nothing leaves the machine.** The style names no host: tiles come from the
  file and glyphs from the application's own bundle. `npm run test:basemap`
  fails the build if a URL ever appears in it.

## Building the installer

`npm run tauri build` already produces an MSI and an NSIS `setup.exe` under
`src-tauri/target/release/bundle/`. Both work and neither needs anything else.

`installer/lockon-ewac.iss` is an alternative built with
[Inno Setup](https://jrsoftware.org/isinfo.php) 7, for the one thing the Tauri
bundlers do not do: a page that tells the operator what this machine is missing
before they find out mid-survey.

```bash
npm run tauri build
npm run check:sidecar     # do not skip this; see below
# Inno Setup 7. A machine-wide install puts ISCC.exe under Program Files,
#   C:\Program Files\Inno Setup 7\
# and a per-user one under %LOCALAPPDATA%\Programs\.
ISCC.exe installer\lockon-ewac.iss
# -> dist-installer\lockon-ewac-setup.exe
```

### Why `check:sidecar` is in that sequence

It starts the **frozen** engine and requires its `ready` event. Nothing else in
the project does: `python engine/tests/run_all.py` imports source inside a
virtualenv, where a missing dependency is a clean `ImportError` the code handles
and a half-collected package cannot exist at all. The only symptom of a bad
freeze is an engine that refuses to start after installing, which the app
reports as "Engine: OFFLINE" without saying why.

That is not hypothetical. `tauri build` copies the sidecar into
`src-tauri/target/release/_internal` **without clearing it**, so a file from a
previous sidecar survives every later build. One rebuild left 244 orphans
behind, and one of them was fatal: `_internal\yaml\` holding a single file —
PyInstaller's optional C accelerator — and no `__init__.py`, left from before
PyYAML was removed from the virtualenv. Python reads a directory with no
`__init__.py` as a _namespace package_, so paramiko's guarded `import yaml`
succeeded and returned an empty module, its `except ImportError` never fired,
and the engine died on `AttributeError: module 'yaml' has no attribute 'error'`.
The orphan did not break something that worked — it turned an absence the code
already handled into a crash it could not.

The installer itself is now immune (it sources the engine from
`src-tauri/binaries/`, where PyInstaller writes it, and clears `{app}\_internal`
before writing), so this check is guarding the other consumer: running
`target/release/lockon-ewac.exe` directly, which is what every release-mode
harness does.

**Note that deleting the stale directory is not the fix on its own.** Tauri does
not re-copy resources when its build script is fingerprint-clean, so a plain
rebuild after deleting them leaves `target/release` with no engine at all. Copy
them back instead — `check:sidecar` prints the two commands when it fails.

It **detects and reports; it does not download or install anything**. That is a
deliberate choice, and the reasons are worth keeping:

- Npcap's free edition restricts redistribution, so bundling it is a licence
  question rather than an engineering one.
- hashcat is 379 MB, roughly three times the whole application, for a feature
  most runs never touch.
- An installer that has to reach the network to finish is one that fails in the
  field, which is where this tool is used.
- Silently installing a network driver and a password-cracking tool is precisely
  what antivirus heuristics exist to stop.
- A hardcoded download URL rots; a link on a page somebody reads does not.

The checks mirror `engine/capability.py`, deliberately — if the installer and
the engine disagreed about where to look for hashcat, the installer's verdict
would be worse than no verdict. And the engine probes again on every start, so
installing Npcap tomorrow needs no reinstall.

WebView2 is the one exception to "report, do not block": it is confirmed rather
than merely listed. Everything else on the readiness page degrades a feature,
while without WebView2 the window opens blank — no error, no explanation — which
is the hardest thing to diagnose in the field. The install still proceeds if you
say yes, because the runtime can be added afterwards without reinstalling.

### What the installer puts on disk

Beside the application, the engine, its `_internal` directory and the bundled
wordlists:

| File | Why |
|---|---|
| `LICENSE.txt` | The engine statically bundles scapy, which is GPL-2.0-only, so what the installer distributes is a combined GPLv2 work and section 1 of that licence asks for a copy to accompany every copy of the binary. It did not ship for the whole of v1.0.0's development: the file was in the repository, nothing put it in the install, and an operator handed this on a USB stick had no way to learn what their rights to it were. Renamed to `.txt` so a double-click opens it. |
| `THIRD-PARTY-NOTICES.md` | The only thing that names scapy's GPL-2.0-only, paramiko's LGPL-2.1 relinking obligation and Npcap's separate proprietary terms. An installed copy has no other source for any of it. |

The wizard does **not** gate the install on accepting the licence. Inno's
`LicenseFile=` page is accept-or-quit, and section 5 of the GPL says the opposite
--- that nothing requires you to accept it, since it governs copying and
distribution rather than use. Shipping the file is the obligation; gating on it
would misstate what the file says. `AppPublisherURL` names the repository instead,
so the Programs-and-Features entry points at the corresponding source.

### What the installer does about a running copy

`lockon-ewac.exe` is closed through Restart Manager, which asks first. The
sidecar is handled separately and forcibly: `ewac-engine.exe` is a console child
the app spawned, Restart Manager does not reliably see it, and it holds DLLs open
inside `_internal\`. A survivor makes the install fail on a locked file or defer
to a reboot.

**The window is stopped before the sidecar**, always. `src/lib/ipc.ts` keeps a
reconnect loop, so stopping the engine while the window is still open simply
makes the app start a new one and lock the files again. The uninstaller does the
same thing, for the same reason — without it, uninstalling with the app open left
the executable and most of `_internal\` behind _and reported success_.

### What an uninstall keeps

None of your data lives under the install directory, so an uninstall leaves all
of it:

| Path                                   | Contents                                                                                                      |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `%APPDATA%\com.lockon.ewac\ewac.db`    | Access points, findings, the evidence register and the credential vault — including any recovered passphrases |
| `%LOCALAPPDATA%\LOCKON-EWAC\data`      | The downloaded CVE snapshot                                                                                   |
| `%LOCALAPPDATA%\LOCKON-EWAC\logs`      | The engine log                                                                                                |
| `%LOCALAPPDATA%\LOCKON-EWAC\wordlists` | Wordlists you uploaded                                                                                        |

Keeping it is the default and the right one: this tool produces evidence, and an
uninstall is not a request to destroy a survey. The uninstaller now _says_ so and
offers to remove it, because the database holds recovered WPA passphrases and
anyone passing the machine on needs telling.

Note those paths resolve for whoever runs the uninstaller. On a per-machine
install removed by a different account, that account's data is what the prompt
would delete — which is why it asks rather than assuming.

### Known gap: the installer is not signed

Windows SmartScreen will warn "Unknown publisher" and require **More info → Run
anyway** every time. Nothing in the installer can work around this, and an
installer that told you to ignore a security warning would be teaching exactly
the wrong habit — particularly for a tool whose output is meant to be trusted as
evidence.

The only fix is a code-signing certificate. Everything else is already in place:
`signtool.exe` ships with the Windows SDK and is present at
`C:\Program Files (x86)\Windows Kits\10\bin\`, and `installer\lockon-ewac.iss`
carries the `SignTool` and `SignedUninstaller` directives commented out directly
above `[Languages]`, with the command line to configure. Once you hold a
certificate it is: define the sign tool in Inno Setup (**Tools → Configure Sign
Tools…**, name it `signtool`), uncomment those two lines, recompile.

Two things worth knowing before buying one. Use an **OV or EV** certificate from
a CA in the Windows trusted root program — a self-signed certificate changes the
warning's wording and nothing else, because no machine but the one that issued it
trusts the chain. And keep the `/tr` RFC-3161 timestamp in the command line: a
signature made without one stops validating the day the certificate expires,
including on copies that were installed years earlier.

Note that OV clears the "Unknown publisher" wording but SmartScreen reputation
still accrues per-publisher over downloads and time, so early installs may
continue to see a warning. EV establishes reputation immediately.

## Supported hardware

- **GPS Modules:** Fully compatible with **NMEA 0183** serial GPS trackers (e.g., U-blox 7/8/9 USB dongles). Configurable COM port and baud rate. Supports **GPGGA** (fix quality, satellites, HDOP, altitude) and **GPRMC** (speed, heading) sentences.
- **Wi-Fi Adapters:** Supports standard Windows native wireless cards for passive AP discovery. Monitor-mode adapters (e.g., Alfa AWUS036ACH) recommended for advanced techniques.
