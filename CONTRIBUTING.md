# Contributing

Thanks for looking. This file is short on etiquette and long on the specific
ways this repository will catch you out, because those are the parts you cannot
guess from the code.

## The one rule everything else follows from

**This tool's output is used as evidence.** Someone reads the report and acts on
it. So the standard is not "does it work" but **"can it be defended"**:

- A number the tool prints must be one it measured. If it could not measure it,
  it says so rather than estimating quietly.
- An absence is reported as an absence, never as a zero. "No CVE found" and "the
  scan could not run" must never look the same.
- A check that cannot fail is worthless. `npm run test:pdfdiff` mutates one
  character and requires the comparator to catch it, for exactly this reason.

If a change makes the tool more confident without making it more correct, it
will be sent back.

## Setup

See [`docs/INSTALL.md`](docs/INSTALL.md). The part people miss: **the Python
engine is a compiled sidecar.** Editing `engine/*.py` changes nothing until you
rebuild it.

```bash
cd engine
.venv\Scripts\pyinstaller.exe ewac-engine-x86_64-pc-windows-msvc.spec --distpath ..\src-tauri\binaries --noconfirm
```

This has cost real debugging time: a `UnicodeDecodeError` arrived from the field
every thirty seconds, the fix was already in the source, grep found nothing to
change, and the compiled `.exe` was two days old. The engine reports a build
stamp now, and Settings shows it, because of that.

## Before you open a pull request

```bash
npx tsc --noEmit                   # must be 0
npm test                           # 23 suites
npm run test:components            # 20 files, against the real components
python engine/tests/run_all.py     # 32 files
npm run build
```

Then the static checks. There are thirteen of them and they take seconds; run
the lot rather than guessing which your change touched, because several exist
precisely because somebody guessed wrong:

```bash
npm run check:ci              # every source file reaches a fresh clone
npm run check:docs            # every mechanically checkable claim in the docs
npm run check:installer       # the .iss ships what Tauri ships, at one version
npm run check:wordlists       # every shipped list is documented
npm run check:migrations      # LF, registered, and never edited after the fact
npm run check:risk-claims     # only the rule set decides how bad something is
npm run check:map             # the live map and the report map agree
npm run check:severity-css    # every severity class has a rule in the built CSS
npm run check:icons           # every Settings card heading has an icon
npm run check:glow            # no zero-offset shadows
npm run check:fonts           # every face has a file; nothing fetches one
npm run check:cleartext       # no third party over plain HTTP
npm run check:kmz             # every KMZ icon is packed
```

CI runs all of the above. Four more are manual because they need the built
application — run them if you touched the report, the CSP, or the sidecar:

```bash
npm run test:export:release   # exports a real PDF, diffs it against the baseline
npm run check:margins         # nothing is drawn off the page, in every pinned shape
npm run test:csp:release      # the SHIPPED policy, not the dev one
npm run check:sidecar         # the bundled engine is byte-identical to the built one
```

**The component suite is not optional.** It drives the real components under
jsdom with only Tauri and MapLibre stubbed, and it is the only thing standing
between a rendering change and a surface that silently says the wrong thing — a
WEP network that was a red dot on the map and absent from the contact list got
through everything else.

## Traps, every one of which has already bitten

**`npm run check:docs` is not a formality.** It verifies every mechanically
checkable claim in the README and `docs/`: test counts, file paths, npm scripts,
cross-document links and heading anchors, and that a backticked identifier
exists in the source. It has caught four engine events that were never emitted
and nine paths written without their prefix. If you change a test count or
rename a file, this will tell you what else to update.

**Never build a Tailwind class from a variable.** Tailwind finds classes by
scanning source for complete strings, so `` `text-${level}` `` produces the right
string at run time and puts **no rule in the stylesheet**. The result is a
severity chip with no colour, which reads as a rendering glitch rather than as a
finding. `npm run check:severity-css` exists because this shipped once.

**Screen and print colours differ on purpose.** `SEVERITY_RGB` is darker than
the `--color-risk-*` variables because the same hues on white paper are thin and
several do not survive a photocopy. Keep the two tables next to each other so a
change to one prompts the question about the other.

**Never read a measurement with `Number()`.** `Number(null)` is `0` and `0` is
finite, so a NULL coordinate became a real position: the archive map drew a line
from Thailand to the Gulf of Guinea for 189 of 196 access points. Use
`finiteNumber` / `coordinatePair` from `src/lib/numbers.ts`.

**A version bump invalidates the PDF baseline.** The version is printed in the
document, so `npm run test:export:release` will report a difference. Confirm it
is only the version, then re-run with `--write-baseline`.

**Resolve wordlist paths through `wordlists_path`.** There were three ways to
guess that directory and they disagreed. There is one now; do not add a fourth.

**Do not let "sub-metre" language back into the GPR docs.** GPR is a signal
field smoother. Its peak lies on or near the driven path by construction — it
cannot place a transmitter off that path, and it was once measured at 225 m
error while reporting 69% confidence.

## Changing the localization maths

Read `tests/localization.test.mjs` first. Every estimator is measured against
simulated ground truth, and the thresholds are set from what was actually
measured, not from what felt right. If you change the maths, the numbers move
and you must say why.

Two measurements have already reversed an "obvious" improvement:

- Fitting the transmitter power *freely* is worse than assuming it with slack.
  See `docs/AP_LOCATION_METHODS.md` §4b-iii before revisiting it.
- A radius can always be made to cover by making it enormous. The unresolved
  radius is asserted from **both** sides — that it covers, and that it is not
  more than 4x the error it covers — because those pull against each other.

## Commit messages

Say what changed and **why it was wrong before**. The engineering log is written
from these, and a message that only says what changed produces a log nobody can
learn from. Prose, not bullet points; no trailing issue-number rituals.

## Scope of contributions

This is a security tool for authorised assessment. Changes that remove the
engagement-scope gate, weaken the audit trail, or make the tool quieter about
what it could not do are out of scope regardless of how they are framed. See
[`SECURITY.md`](SECURITY.md).
