"""Run every engine test in one go.

    python engine/tests/run_all.py

Each test file is also runnable on its own, and the suite is pytest-compatible
(`python -m pytest engine/tests`), but this needs no dependencies at all — which
matters because the engine's own requirements can be missing on a machine that
only wants to check the logic.

Exit code is non-zero if anything failed, so this can gate a build.

A file that ran *no* tests is a failure here, not a pass.

This used to take exit code 0 as PASS and nothing else.
`test_gps_fix_quality.py` had no `if __name__ == "__main__"` block, so running it
as a script defined seven functions, called none of them and exited 0. It was
reported as PASS for as long as it existed — locally and in CI, which runs this
file and never pytest. The seven assertions it contains hold the rule that a fix
the receiver does not stand behind is not a position: GGA quality 0 and RMC
status 'V', the defect that once gave a parked vehicle a track and a heading.

Nothing could see it. The count column in the summary was simply blank next to
that one name, and `scripts/check-docs.mjs` sums the per-file counts *written in
the docs* and checks the total appears in the docs — docs against docs, never
against what executes. The documented engine total of 488 was 481 tests and 7
that never ran.

So the contract is now explicit: every file must end its output with an
`N/M passed` line, and a file that reports zero is as loud as a file that fails.
"""
import os
import re
import subprocess
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

#: The summary line every test file in this directory ends with.
COUNT_RE = re.compile(r"^(\d+)/(\d+) passed\s*$")


def _count_of(stdout):
    """
    `(passed, total)` from a test file's last count line, or None if it has none.

    Read from the last match rather than the final line: some files print a
    per-group count as they go, and the summary is the one that comes last.
    """
    found = None
    for line in stdout.splitlines():
        m = COUNT_RE.match(line.strip())
        if m:
            found = (int(m.group(1)), int(m.group(2)))
    return found


def main() -> int:
    files = sorted(
        f for f in os.listdir(TESTS_DIR)
        if f.startswith("test_") and f.endswith(".py")
    )
    if not files:
        print("No test files found.")
        return 1

    results = []
    for name in files:
        print(f"\n=== {name} " + "=" * max(0, 60 - len(name)))
        proc = subprocess.run(
            [sys.executable, os.path.join(TESTS_DIR, name)],
            capture_output=True, text=True,
        )
        sys.stdout.write(proc.stdout)
        if proc.returncode != 0 and proc.stderr:
            sys.stderr.write(proc.stderr)

        count = _count_of(proc.stdout)
        if count is None:
            # Exited cleanly having reported nothing. Almost always a file with
            # no `__main__` block: import-only, so every assertion in it is
            # inert. Named as its own outcome because "ran nothing" and "ran and
            # passed" were indistinguishable here, and that is what hid it.
            ok, note = False, "NO TESTS RAN (no count line — missing __main__ block?)"
        elif count[1] == 0:
            ok, note = False, "NO TESTS RAN (0 collected)"
        else:
            ok = proc.returncode == 0
            note = f"{count[0]}/{count[1]} passed"
        results.append((name, ok, note, count[1] if count else 0))

    print("\n" + "=" * 70)
    failed = [n for n, ok, _, _ in results if not ok]
    for name, ok, note, _ in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:34} {note}")
    print("=" * 70)

    if failed:
        print(f"\n{len(failed)} file(s) failed: {', '.join(failed)}")
        return 1
    total = sum(n for _, _, _, n in results)
    # ASCII only. This line lands in CI logs and in terminals whose codepage is
    # not UTF-8, where an em dash arrives as a replacement character.
    print(f"\nAll {len(results)} test file(s) passed - {total} tests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
