; Inno Setup script for the Aegis Windows installer.
;
; STATUS: UNTESTED TEMPLATE. This file has never been compiled or run on a
; real Windows machine (per ADR-008, Windows artifacts don't get claimed as
; working without Windows hardware evidence). It follows standard Inno Setup
; 6 structure and is expected to need at most minor fixes, but treat the
; first compile as part of Windows validation, not a formality.
;
; Prerequisites, in order (see packaging/PACKAGING.md):
;   1. Validate Aegis from source on the Windows machine (python main.py).
;   2. Build the PyInstaller bundle:  pyinstaller packaging/aegis.spec
;      -> produces dist\Aegis\ (onedir).
;   3. Install Inno Setup 6 (https://jrsoftware.org/isinfo.php), open this
;      file in the Inno Setup Compiler, and Build. Output: an installer exe
;      in packaging\output\.
;
; KEEP IN SYNC BY HAND: MyAppVersion below duplicates core/version.py
; (__version__) because Inno Setup can't import Python. Bump both together.

#define MyAppName "Aegis"
#define MyAppVersion "2.0.4"
#define MyAppPublisher "Anubhav"
#define MyAppExeName "Aegis.exe"

[Setup]
; Never change this GUID between versions -- it's how Windows knows an
; install of a newer version should upgrade the old one, not sit beside it.
AppId={{FA646D2F-D8B9-4CAC-A947-90BB9BEA0EBD}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}
OutputDir=output
OutputBaseFilename=aegis-{#MyAppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Installer branding + the license the user must accept. LICENSE lives at the
; repo root and aegis.ico under assets/ -- both relative to this file in
; packaging/. If either path moves, Inno Setup fails loudly at compile time,
; not silently, so these are safe to assert without a Windows run.
SetupIconFile=..\assets\aegis.ico
LicenseFile=..\LICENSE
; Python 3.14 (what the bundle ships) dropped support for anything below
; Windows 8.1; the x64 build below already excludes 32-bit. 6.3 = Windows 8.1.
MinVersion=6.3
; The ETW process-monitoring backend needs elevation at RUNTIME (see
; windows/process_monitor.py); the INSTALLER only needs it to write to
; Program Files. Runtime elevation is the user's call each launch -- an
; always-elevated autostart entry would be the wrong default for an alpha.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
; Lets a /VERYSILENT install (core/updater.py's self-update path) close a
; currently-running Aegis.exe and relaunch it after -- Restart Manager
; detects the running process via its lock on Aegis.exe itself, no custom
; mutex bookkeeping needed. Without this, updating over a running install
; would just fail with a file-in-use error instead of silently succeeding.
CloseApplications=yes
RestartApplications=yes

[Files]
; Everything PyInstaller put in the onedir bundle, preserving layout.
Source: "..\dist\Aegis\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Tasks]
; Opt-in, unchecked by default: an alpha security tool silently adding
; itself to autostart is exactly the behavior Aegis exists to flag.
Name: "autostart"; Description: "Start {#MyAppName} automatically at login"; Flags: unchecked

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"""; \
    Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Per-user runtime data (events.log, aegis_events.db, .env with the API key)
; lives in {localappdata}\Aegis -- deliberately NOT deleted on uninstall:
; the event history is an audit trail, and silently destroying it on
; uninstall would be the one moment a user investigating an incident least
; wants that. Documented in PACKAGING.md instead.
Type: filesandordirs; Name: "{app}"
