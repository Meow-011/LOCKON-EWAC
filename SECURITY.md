# Security policy

## Reporting a vulnerability

Please report security issues **privately**, through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. That creates a private advisory visible only to the
maintainers.

> If that option is not visible, private reporting has not been enabled yet.
> A maintainer can turn it on under **Settings → Advanced Security → Private
> vulnerability reporting**. That section was called *Code security* until
> GitHub renamed it, and this file said so for long enough that the path sent a
> maintainer looking for a menu entry that no longer exists. Until then, open an issue that says only *"security
> issue, requesting a private channel"* and nothing else — do not put the
> details in a public issue.

Please do not open a public issue, a pull request, or a discussion with the
details first. This tool is used to produce reports people act on, so a flaw
that makes it misreport is as serious as one that makes it exploitable.

**What helps:** the version (Settings shows the app and engine build stamps),
what you did, what happened, and what you expected. A minimal reproduction is
worth more than a long description. If it only reproduces with particular
hardware, say which.

**What to expect:** an acknowledgement, and an honest answer about whether it is
being fixed, when, and what the workaround is in the meantime. If it is a known
limitation rather than a defect, you will be told that and pointed at where it
is already written down.

## Scope

This policy is about defects in LOCKON EWAC itself. It is **not** a channel for
vulnerabilities you discovered in a third party's network while using it —
report those to the network's owner.

Anything that causes the tool to **state something it did not measure** is in
scope and is treated as a security issue, not a cosmetic one. A position drawn
with no uncertainty, a finding that survives a failed scan, a coverage figure
that counts what was never probed — this project's output is used as evidence,
and a confident wrong answer does more damage than a crash.

## What this tool is for

LOCKON EWAC is for surveying networks **you own or have written authorisation to
assess.** That is enforced, not merely requested: the engine refuses every gated
command until an engagement scope is defined and active, and it records each
refusal in an audit trail that the report prints.

Using it against networks you have no authorisation for is likely a criminal
offence in most jurisdictions, regardless of intent.

## Known security posture

These are stated so you can judge the tool rather than discover them yourself.
None of them is secret, and all are documented in more detail in
[`docs/ENGINEERING_LOG.md`](docs/ENGINEERING_LOG.md).

| Area | Position |
|---|---|
| **Credential vault** | Secrets are encrypted at rest with AES-256-GCM, key derived from an operator passphrase via PBKDF2-SHA256 at 600,000 iterations. The key is held **in memory while the vault is unlocked**, so anything that can read this process's memory can read it. There is **no recovery** — a forgotten passphrase means the credentials are gone. |
| **Renderer privileges** | The renderer holds `sql:allow-execute` and `shell:allow-spawn`. A Content-Security-Policy is set and covers exactly the origins the app uses; `npm run test:csp:release` exercises the shipped policy over the DevTools Protocol. There is no `dangerouslySetInnerHTML`, `innerHTML`, `eval` or `new Function` anywhere in `src/`. |
| **Installer signing** | The installer is **not signed**. SmartScreen will warn "Unknown publisher". The only fix is a code-signing certificate; the directives are staged in `installer/lockon-ewac.iss` ready to enable. |
| **Attacker-controlled input** | SSIDs, hostnames and service banners are attacker-chosen strings and are rendered throughout. They are treated as data: `xmlEscape` for KML, RFC 4180 quoting plus formula-injection neutralisation for CSV. |
| **Data at rest** | Survey database and vault: `%APPDATA%\com.lockon.ewac\ewac.db`. Logs, evidence, CVE snapshot and uploaded wordlists: `%LOCALAPPDATA%\LOCKON-EWAC\`. Nothing is sent anywhere — there is no telemetry and no cloud component. **An uninstall leaves all of it**, deliberately, and says so. |

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No — upgrade |
