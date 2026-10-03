# Third-party notices

LOCKON EWAC is distributed under **GPL-2.0-only** (see `LICENSE`). This file
records what it is built from and why that licence was chosen rather than a
permissive one.

Every version and licence below was read from the installed package metadata,
not from memory. Re-generate it after changing a dependency; a notices file that
has drifted from the lockfile is worse than none.

## Why GPL-2.0-only

The Python engine imports **scapy** in 17 places (802.11 frame handling, EAPOL
capture, passive sniffing, WPS beacon parsing) and PyInstaller bundles it into
the single `ewac-engine` executable that ships with the installer.

scapy is **`GPL-2.0-only`** — version 2, with no "or later" clause. So:

* the distributed binary is a combined work containing scapy, and recipients
  must receive GPLv2 rights to that combined work;
* **GPLv3 is not available**, because a v2-only work cannot be upgraded;
* licensing the source permissively would not change the binary's obligations,
  and would leave the project stating one thing while shipping another.

GPL-2.0-only is therefore the licence that matches what is actually being
distributed. It also happens to suit the tool: copyleft means anyone who builds
on a security auditing tool has to publish their changes, which is the right
default for software whose output people rely on as evidence.

## Known tension: `requests`

`requests` is **Apache-2.0**. The Free Software Foundation's position is that
Apache-2.0 is *incompatible* with GPLv2 — its patent-termination clause is an
additional restriction GPLv2 does not permit — although it is compatible with
GPLv3. Since scapy pins this project to v2, that tension exists in the
distributed binary.

This predates the licence decision rather than being created by it, and it is
recorded here rather than left unstated. `requests` is used in only a few
places (`engine/scanner/vuln_engine.py`, `engine/offensive/dirbuster.py`); the
clean resolution is to replace it with `urllib.request` from the standard
library, which carries the PSF licence and no patent clause.

**This is not legal advice.** If this project is going to be distributed
publicly, have the combination reviewed by someone qualified.

## Python engine dependencies

| Package | Version | Licence |
|---|---|---|
| scapy | 2.7.0 | **GPL-2.0-only** — the reason for this project's licence |
| paramiko | 5.0.0 | LGPL-2.1 |
| requests | 2.34.2 | Apache-2.0 — see the tension above |
| numpy | 2.5.3 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| scipy | 1.18.1 | BSD-3-Clause |
| scikit-learn | 1.9.1 | BSD-3-Clause |
| pyserial | 3.5 | BSD |
| IPy | 1.1 | BSD |
| pydantic | 2.13.5 | MIT |
| pywifi | 1.1.12 | MIT |
| pynmea2 | 1.19.0 | MIT |
| comtypes | 1.4.17 | MIT |

`paramiko` is LGPL-2.1. Bundling it statically (which is what PyInstaller does)
carries the LGPL's relinking obligation: recipients must be able to replace it
with their own build. Shipping the engine's source, which GPLv2 already
requires, satisfies that.

## Rust / Tauri dependencies

Declared in `src-tauri/Cargo.toml`; the full resolved tree with licences is in
`src-tauri/Cargo.lock`. The direct ones:

| Crate | Licence |
|---|---|
| tauri, tauri-plugin-{sql,shell,dialog,opener} | MIT OR Apache-2.0 |
| serde, serde_json | MIT OR Apache-2.0 |
| sysinfo | MIT |
| windows | MIT OR Apache-2.0 |

All are permissive and can be combined into a GPLv2 work.

## Frontend dependencies

Declared in `package.json`, resolved in `package-lock.json`. The notable ones:

| Package | Licence |
|---|---|
| react, react-dom | MIT |
| react-router-dom | MIT |
| @tauri-apps/api | Apache-2.0 OR MIT |
| @tauri-apps/plugin-sql | Apache-2.0 OR MIT |
| @tauri-apps/plugin-shell | Apache-2.0 OR MIT |
| @tauri-apps/plugin-dialog | Apache-2.0 OR MIT |
| @tauri-apps/plugin-opener | Apache-2.0 OR MIT |
| maplibre-gl | BSD-3-Clause |
| pmtiles | BSD-3-Clause |
| protomaps-themes-base | BSD-3-Clause |
| jspdf, jspdf-autotable | MIT |
| zustand | MIT |
| framer-motion | MIT |
| tailwindcss | MIT |
| vite, typescript, esbuild | MIT / Apache-2.0 |

The `@tauri-apps/*` packages are listed separately from the Rust crates above
even though they carry the same licence. They are a different artifact: the
crates are linked into the executable, these are JavaScript shipped inside the
bundle, and a reader checking what was distributed should not have to infer one
from the other.

**`react-router-dom` and the `@tauri-apps/*` packages were missing from this
table** until 2026-10-02, found by diffing it against `package.json` rather than
re-reading it. That is the drift this file's own header warns about, and it is
why the check below exists.

## Keeping this file honest

Re-generate after changing a dependency. The two checks that caught real drift:

```bash
# Python: every requirement appears in this file
engine/.venv/Scripts/python.exe -m pip list

# Frontend: every runtime dependency appears in this file
node -e "const p=require('./package.json'),fs=require('fs');const n=fs.readFileSync('THIRD-PARTY-NOTICES.md','utf8').toLowerCase();const m=Object.keys(p.dependencies).filter(d=>!n.includes(d.split('/').pop().toLowerCase()));console.log(m.length?m:'none missing')"
```

A version here that no longer matches the lockfile is a licence statement about
software nobody is shipping.

## Runtime tools that are *not* bundled

These are invoked if present and are never redistributed, so their licences do
not affect this project's:

* **hashcat** (MIT) — the decryptor drives it as an external process and refuses
  to run without it rather than approximating a result.
* **Npcap** — required for raw 802.11 capture. Proprietary, with its own
  redistribution terms. Installed separately by the operator.
* **Windows `netsh`, `arp`, `ping`, `tracert`** — operating-system components.

## Bundled data

`engine/wordlists/` holds eight credential, passphrase and directory lists. They
are data, not code, and they ship with the installer because the rest of this
design is built on the tool working with no network.

**They are compiled lists, not copies of any one upstream.** That was measured
rather than assumed: `common-dirs.txt` shares 333 of its 570 entries with
the SecLists file *Discovery/Web-Content/common.txt* — 58% — and the rest, including the
whole `.env.local` / `.env.prod` family, is not in that file at all. So no single
upstream licence governs any of these files, and attributing one would be claiming
a provenance they do not have.

| File | Entries | What it is |
|---|---|---|
| `cirt-default-usernames.txt` | 828 | Vendor default account names. |
| `common-dirs.txt` | 570 | Web paths for DIRBUSTER. 58% overlaps SecLists. |
| `default-passwords.txt` | 1,334 | Vendor default passwords; the brute-force default. |
| `mirai-botnet-credentials.txt` | 60 | The credential table published in the Mirai source. |
| `rockyou-wpa-optimized.txt` | 2,086 | Most-frequent passwords, filtered to the WPA length range. |
| `thai-common-passwords.txt` | 19,823 | Thai-locale passphrase candidates, all 8+ characters. |
| `thai-mobile-numbers.txt` | 33,659 | Generated by this project — see below. |
| `wpa-probable-top100k.txt` | 4,800 | Probable passphrases, all 8+ characters. |

**Three things that can be said precisely.**

* Where content overlaps **SecLists** (MIT, © 2018 Daniel Miessler), that licence
  permits redistribution provided its notice travels with it. Credit is given here
  for that reason, and the notice is reproduced in SecLists' own repository.
* `thai-mobile-numbers.txt` is **this project's own**, and it is checkable: exactly
  1,122 numbers per prefix, uniformly spaced across the whole 060–099 range, no
  duplicates. No harvested list has that shape. It contains no real subscriber's
  number other than by the coincidence of enumerating a number space.
* `rockyou-wpa-optimized.txt` is a **frequency list** — the most common passwords
  measured across the 2009 RockYou breach, headed by `password` and `12345678` —
  not a dump of individual credentials. It identifies nobody.

**What still cannot be said.** For the merged lists, no licence can be named per
entry, because the merge was not recorded when it was made. What those entries are
is factual — vendor defaults, common web paths, frequency rankings — rather than
authored expression, and they are published here for authorized testing under the
engagement gating the rest of this tool enforces. This paragraph is a record of
what is known, not a legal determination; anyone redistributing this further should
make their own.

`npm run check:wordlists` fails if a file appears in `engine/wordlists/` without a
row in the table above, so "documented per file" stays true rather than being true
on the day it was written.
