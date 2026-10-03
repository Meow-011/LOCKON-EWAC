; LOCKON EWAC — Inno Setup script
;
; Build with:
;     ISCC.exe installer\lockon-ewac.iss
;
; Built and verified with Inno Setup 7. The path depends on how it was
; installed -- a machine-wide install puts ISCC.exe under Program Files, a
; per-user one under %LOCALAPPDATA%\Programs\ -- so the command above names the
; executable and lets the shell or the reader find it.
;
; The number here is a record of what this file was last compiled with, not a
; preference, and it has been wrong before: it said 7 while 6 was installed, and
; nobody noticed because nobody had run it. It says 7 again now for the opposite
; reason -- 7 was installed and this script compiled under it, clean, in 97
; seconds to the same 114 MB output 6 produced. If you build with a different
; version, change this line and the two in README.md and docs/INSTALL.md;
; `npm run check:installer` will not let you change only one.
;
; What that compile does *not* cover is everything in [Code]: those procedures
; run during a real install. The eight manual steps in docs/TESTING.md were run
; against this 7-built setup on 2026-10-03 and all eight behaved as described --
; with one caveat recorded there: the silent-install guard cannot be reached on a
; machine that already has WebView2, which the test machine does.
;
; Re-run them whenever anything in [Code] changes. ISCC proves it parses.
;
; It expects `npm run tauri build` to have run first, so that
; src-tauri\target\release\ holds the app, the sidecar and its resources.
;
; ── What this installer does NOT do, deliberately ────────────────────────────
;
; It does not download or silently install Npcap or hashcat. It detects them,
; says what it found, and links to the source. That decision is worth stating
; because "install everything for the user" sounds friendlier and is worse here:
;
;   * Npcap's free edition restricts redistribution, so bundling it is a licence
;     question rather than an engineering one.
;   * hashcat is 379 MB — three times the whole application — for a feature most
;     runs never touch.
;   * An installer that must reach the network to finish is an installer that
;     fails in the field, which is where this tool is used.
;   * Silently installing a network driver and a password-cracking tool is the
;     exact behaviour antivirus heuristics exist to stop.
;   * A hardcoded download URL rots. A link on a page the user reads does not.
;
; The application probes for all of this again at runtime (`engine/capability.py`)
; and reports what is missing, so installing Npcap tomorrow needs no reinstall.

#define AppName        "LOCKON EWAC"
#define AppVersion     "1.0.0"
#define AppPublisher   "LOCKON"
#define AppExeName     "lockon-ewac.exe"
#define SrcDir         "..\src-tauri\target\release"
; The sidecar is taken from where PyInstaller writes it, NOT from the copy
; under target\release. That copy is staging for running the release binary in
; place; `tauri build` writes it without clearing it, and does not refresh it
; when its build script is fingerprint-clean -- so it can be stale, contaminated
; with orphans from an older sidecar, or simply absent. One build left a `yaml/`
; directory there holding only PyInstaller's optional C accelerator and no
; __init__.py,
; which Python reads as a namespace package: paramiko's guarded `import yaml`
; succeeded, returned an empty module, and the engine died at startup on
; `AttributeError: module 'yaml' has no attribute 'error'`.
; Sourcing the engine from its own build output makes that unrepresentable.
#define EngineDir      "..\src-tauri\binaries\ewac-engine"
#define EngineExe      "ewac-engine-x86_64-pc-windows-msvc.exe"
#define WordlistDir    "..\src-tauri\binaries\wordlists"

[Setup]
; Stable across versions: it is what Windows uses to recognise an upgrade
; rather than a second, parallel installation. Derived from the app identifier
; so it can be regenerated, never invented again.
AppId={{1CA9D4FA-B76A-51E1-BCF7-253F95B08650}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
OutputDir=..\dist-installer
; No version in the file name, by request. The version is still in the installer's
; metadata, the Programs-and-Features entry and the app itself, so an installed
; copy can always be identified — but two setup files from different versions look
; identical on disk, so keep them in separate folders if you archive them.
OutputBaseFilename=lockon-ewac-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Per-machine when elevated, per-user when not. The application itself needs no
; administrator rights; only two of its features do, and they say so at runtime.
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
; The wizard and the setup file itself carry the app's icon. Without this they
; use Inno's default, which makes the download look like somebody else's program.
SetupIconFile=..\src-tauri\icons\icon.ico
; Version metadata on setup.exe. This matters more since the version was taken
; out of the file name: the properties dialog is now the only thing on disk that
; distinguishes two setup files.
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
; Where the corresponding source is. A GPLv2 binary distribution has to be
; accompanied by the source or by an offer of it, and this is the project's own
; remote -- so the Programs-and-Features entry names it, which is the one place a
; recipient of an installed copy will think to look.
AppPublisherURL=https://github.com/Meow-011/LOCKON-EWAC
; WebView2 is a hard requirement and is an Evergreen runtime on Windows 10+.
; Older versions can technically host it, but nothing here is tested there and a
; blank window is a poor way to find that out.
MinVersion=10.0
; Let Restart Manager close the app if it is running, rather than failing on a
; locked file. `[Code]` below also deals with the sidecar, which Restart Manager
; does not reliably see — see StopEngine().
CloseApplications=yes
RestartApplications=no

; ---------------------------------------------------------------------------
; Code signing. Commented out because there is no certificate, not because it
; is optional.
;
; Unsigned, SmartScreen says "Windows protected your PC / Unknown publisher"
; and hides the Run button behind "More info". Every recipient of an evidence
; report tool is therefore trained to click past a security warning on the
; first run, which is the opposite of what this tool is for.
;
; To turn it on: define a sign tool in Inno Setup (Tools > Configure Sign
; Tools...) named `signtool` with a command line such as
;
;   "C:\Program Files (x86)\Windows Kits\10\bin\<ver>\x64\signtool.exe" sign /f "C:\path\cert.pfx" /p $p /tr http://timestamp.digicert.com /td sha256 /fd sha256 $f
;
; then uncomment the two lines below. `signtool.exe` is already present on this
; machine under "C:\Program Files (x86)\Windows Kits\10\bin\" - the certificate
; is the missing part, and it is the only missing part.
;
; /tr (RFC-3161 timestamp) is not decoration: without it every signature stops
; validating the day the certificate expires, including on copies already
; installed. Use an OV or EV certificate from a CA in the Windows trusted root
; program --- a self-signed certificate changes the warning's wording and
; nothing else, since no machine but this one would trust it.
;
;SignTool=signtool
;SignedUninstaller=yes
; ---------------------------------------------------------------------------

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
; The application and the Rust side.
Source: "{#SrcDir}\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; The Python sidecar, one directory. `_internal` must stay a sibling of the
; executable — the PyInstaller bootloader resolves it relative to the exe, and
; separating them fails at `Failed to load Python DLL`.
; Renamed on the way in: Tauri strips the target triple when it bundles, the
; app launches `ewac-engine.exe`, and StopLockon() kills that name.
Source: "{#EngineDir}\{#EngineExe}"; DestDir: "{app}"; DestName: "ewac-engine.exe"; Flags: ignoreversion
Source: "{#EngineDir}\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs
; The licence and the third-party notices.
;
; The engine statically bundles scapy, which is GPL-2.0-only, so what this
; installer distributes is a combined GPLv2 work. Section 1 of that licence asks
; that a copy of it accompany every copy of the binary, and section 3 that the
; corresponding source accompany it or be offered. `LICENSE` has been in the
; repository since the beginning and nothing ever put it into the install, so
; every installed copy was a GPLv2 distribution carrying no licence at all -- and
; an operator handed this on a USB stick had no way to learn what their rights to
; it were.
;
; THIRD-PARTY-NOTICES.md goes with it, and matters as much: it is the only thing
; that names scapy's GPL-2.0-only, paramiko's LGPL-2.1 relinking obligation and
; Npcap's separate proprietary terms. An installed copy has no other source for
; any of that.
;
; `.txt` on the way in so a double-click opens it. The notices keep their `.md`:
; they are a table and renaming them would not make Notepad render it.
;
; Deliberately NOT wired to `LicenseFile=`. Inno's licence page is an
; accept-or-quit gate, which would present the GPL as terms you must accept in
; order to *run* this -- and section 5 of the GPL says the opposite, that nothing
; requires you to accept it since it governs copying and distribution rather than
; use. Shipping the file is the obligation; gating the install on it would be a
; misstatement of what the file says.
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

; The wordlists that ship with the build. Read-only in practice: this directory
; is under %ProgramFiles% on a per-machine install, so an ordinary operator
; cannot write to it. That used to break the UI's upload button, which wrote
; here; uploads now go to %LOCALAPPDATA%\LOCKON-EWAC\wordlists and the engine
; reads both locations (`wordlists_path.wordlist_dirs()`). Replacing these on an
; upgrade is therefore safe — nothing the operator added lives here.
Source: "{#WordlistDir}\*"; DestDir: "{app}\wordlists"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Clear the engine's directory before writing the new one.
;
; Inno copies the files it carries and leaves everything else alone, so a file
; that was in a previous sidecar and is not in this one survives the upgrade.
; That is the same defect that cost this project a broken build: a leftover
; `_internal\yaml\` holding only PyInstaller's optional C accelerator, with no
; __init__.py, is read by Python as a namespace package. paramiko's guarded
; `import yaml` then succeeds and returns an empty module instead of raising
; ImportError, and the engine dies at startup on
; `AttributeError: module 'yaml' has no attribute 'error'`.
;
; An upgrade would reproduce it exactly, because the engine's dependencies
; change whenever the virtualenv does. `_internal` is PyInstaller output and
; nothing else ever writes there -- no operator data lives in it -- so deleting
; it wholesale is safe and is the only way to guarantee the installed engine is
; the engine that was built.
Type: filesandordirs; Name: "{app}\_internal"

[UninstallDelete]
; An older build wrote the downloaded CVE snapshot beside the executable before
; it moved to %LOCALAPPDATA%. Nothing creates this now, but an install upgraded
; from one of those builds still has it, and leaving a stale CVE database behind
; after an uninstall is worse than leaving nothing.
Type: filesandordirs; Name: "{app}\data"
Type: dirifempty; Name: "{app}\wordlists"
Type: dirifempty; Name: "{app}"

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; `runasoriginaluser` matters more than it looks. A per-machine install runs
; elevated, and without this the app would inherit that token - so if the
; operator elevated with a *different* administrator account, the first run
; would resolve %LOCALAPPDATA% and %APPDATA% to that admin's profile and write
; the survey database, the CVE snapshot and any uploaded wordlists there. The
; operator would then open the app normally and find it empty, with their first
; session's data sitting in someone else's profile.
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
{
  The readiness page.

  Each check mirrors what `engine/capability.py` does at runtime, and for the
  same reason: presence of a file is not the same as a working install, so where
  it is cheap the check looks at the service or runs the binary rather than at
  the filesystem alone.
}

var
  ReadyPage: TOutputMsgMemoWizardPage;

function NpcapInstalled(): Boolean;
begin
  { Two driver locations, matching capability.check_npcap(). Npcap has used both
    depending on version and on WinPcap-compatibility mode. }
  Result := FileExists(ExpandConstant('{sys}\Npcap\npcap.sys'))
         or FileExists(ExpandConstant('{sys}\drivers\npcap.sys'));
end;

{
  Registered, not running -- and the name now says which.

  `sc query npcap` exits 0 when the service *exists*, in whatever state, and this
  was called `NpcapServiceRunning`. The behaviour is right and deliberately so:
  Npcap's driver service is demand-start, so stopped is the normal resting state on
  a machine where nothing currently holds a capture handle, and reporting that as
  broken would raise an alarm on every healthy install. Testing for RUNNING here
  would be the wrong check, not a stricter one.

  What was wrong was a name asserting something the call does not establish, in
  the one file whose job is to tell an operator what is actually on their machine.
}
function NpcapServiceRegistered(): Boolean;
var
  ResultCode: Integer;
begin
  { The existence of the service is what separates a broken install from a missing
    one, which is the distinction the readiness page draws. }
  Result := Exec(ExpandConstant('{cmd}'), '/C sc query npcap > nul 2>&1', '',
                 SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function WebView2Installed(): Boolean;
var
  Version: String;
begin
  { The Evergreen runtime registers itself per-machine or per-user. Windows 11
    and current Windows 10 ship it, but a stripped or offline image may not. }
  Result :=
    RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version)
    or RegQueryStringValue(HKCU, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version);
end;

{
  Where the offline basemap lives, as one string so the probe and the message it
  prints cannot drift apart. In a function rather than a constant because an Inno
  constant written inside a brace comment would end the comment at its first
  closing brace.

  `%APPDATA%\com.lockon.ewac\basemap.pmtiles` is where `basemap.rs` looks and
  nowhere else: it joins Tauri's `app_data_dir()`, which on Windows is %APPDATA%
  plus the identifier from tauri.conf.json, with that file name.

  It did not say that until now, and the way it was wrong is worth recording. The
  separator before `basemap` was not missing or mistyped -- it was a **literal
  0x08 backspace byte**, in the string and in two comments, from a `\b` escape
  that some editing pass interpreted instead of writing. The file read correctly
  in any terminal, because the terminal performed the backspace, and what Inno
  compiled was a probe for a file whose name contains a control character. Nothing
  creates such a file, so `OfflineBasemapInstalled` could only ever return False
  and the readiness page could only ever print "No offline basemap".

  Measured on a machine that has one, rather than reasoned about: 6.6 MB at
  C:\Users\<user>\AppData\Roaming\com.lockon.ewac\basemap.pmtiles, reported absent.
  A readiness page that calls a present component missing is the same failure as a
  report claiming a clean result it never measured -- so `check:installer` now
  holds this path against basemap.rs and refuses a control byte anywhere in this
  script.
}
function BasemapPath(): String;
begin
  Result := ExpandConstant('{userappdata}') + '\com.lockon.ewac\basemap.pmtiles';
end;

function OfflineBasemapInstalled(): Boolean;
begin
  { Probed as-is, with the same caveat as the hashcat path below: a per-machine
    install runs elevated, so this resolves the elevating account's profile rather
    than the operator's, and the message says which path it examined. }
  Result := FileExists(BasemapPath());
end;

function HashcatFound(out FoundAt: String): Boolean;
var
  Candidates: array[0..2] of String;
  I: Integer;
  ResultCode: Integer;
begin
  { The same three fallback paths `_HASHCAT_LOCATIONS` lists, plus PATH. If the
    installer and the engine disagree about where to look, the installer's
    verdict is worse than no verdict.

    The third one is the hazard. On a per-machine install this wizard runs
    elevated, so the USERPROFILE this wizard expands is the *administrator's*
    profile -- while the
    app is deliberately launched with `runasoriginaluser` and the engine will
    probe the operator's `%USERPROFILE%\hashcat\`. The readiness page could
    therefore report hashcat present or absent for a profile the application
    never looks in, and the instructions below then tell the reader to install it
    under `%USERPROFILE%`.

    There is no reliable way to resolve the original user's profile from an
    elevated Inno session, so the check does not pretend to: the per-user path is
    probed as-is, and the message says which profile was examined. A wrong answer
    stated plainly is recoverable; a wrong answer presented as the operator's is
    not. }
  Candidates[0] := 'C:\hashcat\hashcat.exe';
  Candidates[1] := 'C:\Tools\hashcat\hashcat.exe';
  Candidates[2] := ExpandConstant('{%USERPROFILE}') + '\hashcat\hashcat.exe';

  for I := 0 to 2 do
  begin
    if FileExists(Candidates[I]) then
    begin
      FoundAt := Candidates[I];
      Result := True;
      Exit;
    end;
  end;

  { On PATH: ask it, rather than guessing at a directory. }
  if Exec(ExpandConstant('{cmd}'), '/C where hashcat > nul 2>&1', '',
          SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
  begin
    FoundAt := 'on PATH';
    Result := True;
    Exit;
  end;

  FoundAt := '';
  Result := False;
end;

function BuildReadinessReport(): String;
var
  S, HashcatAt: String;
begin
  S := 'What LOCKON EWAC found on this machine.' + #13#10
     + 'Nothing here blocks the installation, and nothing is downloaded for you.' + #13#10 + #13#10;

  { WebView2 — without it the window opens blank. }
  if WebView2Installed() then
    S := S + '[ OK ] WebView2 runtime' + #13#10
           + 'The interface will render.' + #13#10 + #13#10
  else
    S := S + '[ MISSING ] WebView2 runtime - REQUIRED' + #13#10
           + 'Without it the application window opens blank.' + #13#10
           + 'https://developer.microsoft.com/microsoft-edge/webview2/' + #13#10 + #13#10;

  { Npcap — everything that touches raw frames. }
  if NpcapInstalled() and NpcapServiceRegistered() then
    S := S + '[ OK ] Npcap' + #13#10
           + 'Packet capture, passive SIGINT and countermeasures are available.' + #13#10 + #13#10
  else if NpcapInstalled() then
    S := S + '[ BROKEN ] Npcap driver present, service not registered' + #13#10
           + 'Reinstall Npcap. The files being there is not the same as it working.' + #13#10
           + 'https://npcap.com' + #13#10 + #13#10
  else
    S := S + '[ MISSING ] Npcap' + #13#10
           + 'Wi-Fi scanning, GPS and reporting still work without it.' + #13#10
           + 'Handshake capture, passive SIGINT, PMKID, deauth and MITM do not.' + #13#10
           + 'Install it with "WinPcap API-compatible mode" checked.' + #13#10
           + 'https://npcap.com' + #13#10 + #13#10;

  { hashcat — the Decryptor only. }
  if HashcatFound(HashcatAt) then
    S := S + '[ OK ] hashcat (' + HashcatAt + ')' + #13#10
           + 'The Decryptor can run.' + #13#10 + #13#10
  else
    S := S + '[ OPTIONAL ] hashcat not found' + #13#10
           + 'Only the Decryptor needs it. Everything else is unaffected.' + #13#10
           + 'Unpack the whole archive - not just the .exe, it loads its' + #13#10
           + 'kernels from the files beside it - into one of:' + #13#10
           + '  %USERPROFILE%\hashcat\   (no administrator rights needed)' + #13#10
           + '  C:\hashcat\' + #13#10
           + '  C:\Tools\hashcat\' + #13#10
           + 'or put it on PATH. https://hashcat.net/hashcat/' + #13#10
           + 'This wizard checked ' + ExpandConstant('{%USERPROFILE}') + ' for the first of those,' + #13#10
           + 'which is the elevating account if you installed for all users.' + #13#10 + #13#10;

  { The offline basemap — geography when there is no network. }
  if OfflineBasemapInstalled() then
    S := S + '[ OK ] Offline basemap installed' + #13#10
           + 'With no network the map keeps its coastline, roads and place names.' + #13#10 + #13#10
  else
    S := S + '[ OPTIONAL ] No offline basemap' + #13#10
           + 'With no network the map is a flat grid: your markers and track draw' + #13#10
           + 'on it, but there is no geography to locate them against. Scanning,' + #13#10
           + 'recording and every report are unaffected.' + #13#10
           + 'It is not shipped because the right extract depends on where you' + #13#10
           + 'work - a city is a few megabytes, the planet is tens of gigabytes.' + #13#10
           + 'Settings > Offline Basemap shows the exact path and what a file' + #13#10
           + 'you put there was found to cover.' + #13#10
           + 'This wizard looked for' + #13#10
           + '  ' + BasemapPath() + #13#10
           + 'which is the elevating account if you installed for all users.' + #13#10
           + 'The application reads the operator''s.' + #13#10 + #13#10;

  { Elevation — two features, not the application. }
  if IsAdminInstallMode() then
    S := S + '[ NOTE ] Running elevated' + #13#10
           + 'Deauthentication and MITM need this. Most work does not.' + #13#10
  else
    S := S + '[ NOTE ] Not running elevated' + #13#10
           + 'Deauthentication and MITM will be unavailable until you run' + #13#10
           + 'LOCKON EWAC as administrator. Scanning and reporting do not' + #13#10
           + 'need it, and the app reports which features are unavailable.' + #13#10;

  S := S + #13#10
     + 'All of this is checked again every time the engine starts, so anything'  + #13#10
     + 'installed later is picked up without reinstalling LOCKON EWAC.';

  Result := S;
end;

{
  Stop the app and its sidecar before touching files.

  Restart Manager handles `lockon-ewac.exe` and asks the operator first, which is
  the polite path and the one that normally runs. This is the fallback for when it
  cannot - and, more importantly, the only thing that deals with the sidecar:
  `ewac-engine.exe` is a console child the app spawned, Restart Manager does not
  reliably see it, and it holds DLLs open inside `_internal\`. A survivor makes
  the install fail on a locked file or defer to a reboot, which an operator reads
  as a broken installer rather than as an app that was still running.

  **Order matters.** `src/lib/ipc.ts` keeps a reconnect loop with a retry timer,
  so killing the engine while the window is still open simply makes the app start
  a new one and re-lock the files. The window goes first, every time.

  Killing the engine is safe: it is stateless between commands, anything it has
  written is already on disk, and the app starts a fresh one when it next runs.
}
function ProcessRunning(const ExeName: String): Boolean;
var
  ResultCode: Integer;
begin
  { `tasklist /FI` exits 0 whether or not its filter matched, so the match has to
    be turned into an exit code. `find /I` does that: it exits 1 when the name is
    not in what tasklist printed, including when tasklist printed "INFO: No tasks
    are running which match the specified criteria." }
  Result := Exec(ExpandConstant('{cmd}'),
                 '/C tasklist /FI "IMAGENAME eq ' + ExeName + '" | find /I "' + ExeName + '" > nul 2>&1',
                 '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure StopLockon();
var
  ResultCode, Waited: Integer;
begin
  Exec(ExpandConstant('{cmd}'), '/C taskkill /IM lockon-ewac.exe /F > nul 2>&1', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{cmd}'), '/C taskkill /IM ewac-engine.exe /F > nul 2>&1', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);

  { `taskkill` returns once the kill has been *issued*. Process teardown, and the
    release of the handles the engine holds on the DLLs inside `_internal\`, happen
    after that -- and Inno began copying over them immediately. So the locked-file
    failure this entire procedure exists to prevent was still reachable on a fast
    machine, in a window too narrow to reproduce on demand and wide enough to hit
    an operator once.

    Bounded at two seconds, because a wait that can outlast the operator's patience
    is its own failure: if something still holds those files after that, Inno's own
    in-use handling is a better answer than a wizard that appears to have hung. }
  Waited := 0;
  while (Waited < 20) and (ProcessRunning('lockon-ewac.exe') or ProcessRunning('ewac-engine.exe')) do
  begin
    Sleep(100);
    Waited := Waited + 1;
  end;
  { Gone from the process list is not the same as its handles being closed. }
  Sleep(300);
end;

function WebView2Confirmed(): Boolean; forward;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not WebView2Confirmed() then
  begin
    Result := 'Installation cancelled: the WebView2 runtime was not found and '
      + 'you chose not to continue. Install it, then run this setup again.';
    Exit;
  end;
  StopLockon();
end;

{
  WebView2 is not optional, and the readiness page is easy to click past.

  Without it the window opens blank - no error, no explanation, just an empty
  frame - which is the hardest kind of failure for an operator to diagnose in the
  field. Everything else the readiness page lists degrades a feature; this one
  stops the application existing. So it is confirmed rather than merely reported,
  and the install still proceeds if they say yes, because the runtime can be
  installed afterwards without reinstalling this.
}
function WebView2Confirmed(): Boolean;
begin
  Result := True;
  if WebView2Installed() then
    Exit;
  { A silent install has nobody to answer, and an unattended deployment that
    hangs on a dialog nothing can click is worse than one that proceeds. It
    proceeds: WebView2 can be pushed separately, the engine probes for it on
    every start, and the application reports it at run time. Without this guard
    the MsgBox below blocks forever and its default is No, so the install would
    eventually be aborted by a prompt no operator ever saw. }
  if WizardSilent() then
    Exit;
  Result := MsgBox('The WebView2 runtime was not found on this machine.' #13#10 #13#10
    + 'LOCKON EWAC draws its entire interface in WebView2. Without it the'  #13#10
    + 'window will open blank - it will not report an error, it simply will' #13#10
    + 'not render.' #13#10 #13#10
    + 'You can install it now from:' #13#10
    + '    https://developer.microsoft.com/microsoft-edge/webview2/' #13#10
    + 'and it will be picked up without reinstalling LOCKON EWAC.' #13#10 #13#10
    + 'Continue with the installation anyway?',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;

{
  What an uninstall keeps, said out loud.

  None of this lives under the install directory, so an uninstall silently
  leaves all of it. (Note for anyone editing these comments: a brace-delimited
  Pascal comment ends at the first closing brace, so an Inno constant written
  inline here would terminate it early and the rest would be parsed as code.)

    %APPDATA%\com.lockon.ewac\ewac.db   survey data, findings, the evidence
                                        register and the credential vault
    %APPDATA%\com.lockon.ewac\basemap.pmtiles  the offline basemap, if one was
                                        installed

  Both of those paths were written here with a 0x08 byte in place of the separator
  before `basemap`, which mattered twice over. The readiness probe carrying the
  same byte could never find a basemap. And this list, read as text, put the
  basemap *beside* the identifier directory instead of inside it -- the difference
  between a file an uninstall leaves alone and one `DelTree` removes along with
  its parent. It is inside it, so Yes below deletes it, and the prompt now says so:
  a city extract is a few megabytes but a planet is tens of gigabytes, and nobody
  should discover that after agreeing to something that did not mention it.
    %LOCALAPPDATA%\LOCKON-EWAC\evidence the captured artifacts themselves
    %LOCALAPPDATA%\LOCKON-EWAC\data     the downloaded CVE snapshot
    %LOCALAPPDATA%\LOCKON-EWAC\logs     the engine log
    %LOCALAPPDATA%\LOCKON-EWAC\wordlists wordlists the operator uploaded

  The evidence directory was missing from this list and from the prompt, which
  is the one omission here that mattered: `DelTree` takes the parent, so saying
  Yes has always removed the .pcap and handshake files as well -- the artifacts
  every SHA-256 in every issued report points at -- while the prompt described
  the directory as a CVE snapshot, a log and some wordlists. An operator passing
  a machine on would reasonably have said Yes to that. `check:installer` now
  compares the prompt against the directories the engine actually writes to.

  Keeping it is the right default - this tool produces evidence, and an
  uninstall is not a request to destroy a survey. Keeping it *silently* is not:
  the database holds recovered WPA passphrases, and somebody uninstalling before
  handing the machine on needs to be told they are still there.

  Note the paths resolve for whoever runs the uninstaller. On a per-machine
  install removed by a different user, that user's data is what gets deleted, so
  this asks rather than assuming.
}
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir, AppDataDir: String;
begin
  { An uninstall hits exactly the same locked-file problem as an install, and
    nothing was stopping the app here - so uninstalling with the window open
    left the executable and most of `_internal\` behind, and the operator was
    told the removal succeeded. Same order as the install path, and for the same
    reason: the window first, or the reconnect loop starts a new engine. }
  if CurUninstallStep = usUninstall then
  begin
    StopLockon();
    Exit;
  end;

  if CurUninstallStep <> usPostUninstall then
    Exit;

  DataDir := ExpandConstant('{localappdata}\LOCKON-EWAC');
  AppDataDir := ExpandConstant('{userappdata}\com.lockon.ewac');

  if (not DirExists(DataDir)) and (not DirExists(AppDataDir)) then
    Exit;

  { Same reasoning as the install-time prompt, with the opposite default. A
    silent uninstall keeps everything: deleting a survey, its evidence register
    and a credential vault is not something to do on an unattended run that
    nobody is watching, and keeping files is the recoverable mistake. }
  if UninstallSilent() then
    Exit;

  if MsgBox('LOCKON EWAC has been removed.' #13#10 #13#10
    + 'Your survey data has been left in place:' #13#10 #13#10
    + '    ' + AppDataDir + #13#10
    + 'Access points, findings, the evidence register and the' #13#10
    + 'credential vault - including any recovered passphrases -' #13#10
    + 'and the offline basemap, if you installed one.' #13#10 #13#10
    + '    ' + DataDir + #13#10
    + '  \evidence   CAPTURED ARTIFACTS - the .pcap and handshake files' #13#10
    + '              every SHA-256 in every report you issued refers to.' #13#10
    + '  \data       the downloaded CVE snapshot' #13#10
    + '  \logs       the engine log' #13#10
    + '  \wordlists  wordlists you uploaded' #13#10 #13#10
    + 'This is kept on purpose: an uninstall is not a request to destroy a' #13#10
    + 'survey, and these files are the evidence behind any report you issued.' #13#10 #13#10
    + 'Delete all of it now?' #13#10 #13#10
    + 'Choose No to keep it. If you are passing this machine on, choose Yes -' #13#10
    + 'the vault is encrypted, but the passphrases are still on this disk.',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
  begin
    DelTree(DataDir, True, True, True);
    DelTree(AppDataDir, True, True, True);
  end;
end;

procedure InitializeWizard();
begin
  ReadyPage := CreateOutputMsgMemoPage(
    wpSelectTasks,
    'System readiness',
    'What is present, what is missing, and what each one affects',
    'LOCKON EWAC works without the optional items below. The report states which ' +
    'capabilities were unavailable, so a missing component never looks like a clean result.',
    '');
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  { Built when the page is shown rather than at startup, so the checks reflect
    anything installed while this wizard was open. }
  if (ReadyPage <> nil) and (CurPageID = ReadyPage.ID) then
    ReadyPage.RichEditViewer.Lines.Text := BuildReadinessReport();
end;
