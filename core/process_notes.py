"""
Plain-English notes for the OS utilities that make up most of the timeline.

WHY THIS IS NOT A SECURITY FEATURE, AND WHY THAT MATTERS FOR HOW IT'S GATED:

A name->description table is exactly the shape of the "known safe list" that
core/rule_engine.py refuses to ship, and for the same reason it would be
dangerous here: text saying "Apple's hardware registry utility" attached to a
binary called `ioreg` sitting in ~/Downloads is worse than no text at all,
because it launders a filename an attacker chose into an authoritative-sounding
claim about what the file does.

So the note is only attached when rule_engine.is_system_binary() confirms the
executable resolves inside a SIP-protected directory -- i.e. the file genuinely
IS the Apple binary of that name, enforced by the kernel. Anything else gets no
note. The severity number and the AI explanation are unaffected either way;
this only makes the timeline row readable by someone who doesn't already know
what `biomesyncd` is.

Coverage is deliberately partial. These are the handful that dominate a normal
macOS timeline -- there is no attempt at completeness, and no note is a
perfectly fine outcome.
"""

from __future__ import annotations

from core.rule_engine import is_system_binary

_NOTES = {
    # hardware / power / system inventory
    "ioreg": "read the hardware registry (connected devices, battery, displays)",
    "pmset": "checked or changed power, sleep and battery settings",
    "system_profiler": "collected a system inventory (CPU, memory, storage, network)",
    "sysctl": "read low-level kernel settings",
    "diskutil": "inspected or managed disks and volumes",
    "ifconfig": "read network interface configuration",
    "networksetup": "read or changed network settings",
    "airport": "queried Wi-Fi status",
    # Apple background daemons
    "biomesyncd": "Apple background service syncing device activity for Handoff/Continuity",
    "mdworker": "Spotlight indexing a file",
    "mdworker_shared": "Spotlight indexing a file",
    "mds": "Spotlight's indexing service",
    "mds_stores": "Spotlight writing its search index",
    "spotlightknowledged": "Spotlight's on-device knowledge index",
    "cfprefsd": "Apple's preferences service reading app settings",
    "distnoted": "Apple's system notification relay",
    "nsurlsessiond": "Apple's background download/upload service",
    "softwareupdated": "macOS checking for software updates",
    "contactsd": "Apple's Contacts service",
    "addressbookmanager": "Apple's Contacts database service",
    "addressbooksourcesync": "Apple's Contacts service syncing an account's address book",
    "com.apple.icloudhelper": "Apple's iCloud account helper",
    "remindd": "Apple's Reminders sync service",
    "trustd": "Apple's certificate-trust service, which validates TLS certificates",
    "netbiosd": "Apple's NetBIOS service, used for Windows file-sharing name lookups",
    "containermanagerd": "Apple's app-sandbox container service",
    "containermanager": "Apple's app-sandbox container service",
    "mdmclient": "macOS device-management client checking in with an MDM server",
    "managedclient": "macOS device management applying configuration profiles",
    "helpd": "Apple's Help Viewer content service",
    "extensionkitservice": "macOS host process for an app extension",
    "pluginlibraryservice": "macOS enumerating network file-system plug-ins",
    "systemsettingsagent": "the System Settings app's background helper",
    "bluetoothuiserver": "Apple's Bluetooth UI service (pairing and device prompts)",
    "axvisualsupportagent": "Apple's accessibility visual-support service",
    "parsec-fbf": "Apple's Spotlight/Siri feedback uploader",
    "oahd": "Rosetta's translation service for Intel apps on Apple silicon",
    "xprotectservice": "Apple's built-in XProtect malware scan",
    # login / authorization
    "login": "started a login session for a terminal or user",
    # p_comm truncates to 16 chars, so both spellings can arrive (see describe()).
    "authorizationhost": "macOS handling an authorization prompt (the admin password dialog)",
    "authorizationhos": "macOS handling an authorization prompt (the admin password dialog)",
    "taskgated-helper": "macOS checking a program's code signature before granting debug rights",
    # WebKit / Safari helper processes
    "com.apple.webkit.webcontent": "a Safari/WebKit tab rendering a web page",
    "com.apple.webkit.webcontent.enhancedsecurity":
        "a Safari/WebKit tab rendering a web page with enhanced security enabled",
    "com.apple.webkit.networking": "Safari/WebKit's network process, which makes the actual web requests",
    "com.apple.webkit.gpu": "Safari/WebKit's GPU process, which draws page content",
    "com.apple.safariplatformsupport.helper": "Safari's platform-support helper",
    # graphics / media XPC services
    "mtlcompilerservice": "compiled GPU shaders for an app (Metal)",
    "vtdecoderxpcservice": "decoded video for an app (VideoToolbox)",
    "vtencoderxpcservice": "encoded video for an app (VideoToolbox)",
    "com.apple.audio.sandboxhelper": "Apple's sandboxed host for an audio plug-in",
    "quicklookuiservice": "rendered a Quick Look file preview",
    "quicklookuihelper": "rendered a Quick Look file preview",
    # UI and automation surfaces
    "system events": "Apple's scripting bridge that lets AppleScript control apps and UI",
    "screencaptureui": "the macOS screenshot UI (Shift-Cmd-5 or the screenshot HUD)",
    "folderactionsdispatcher": "ran a Folder Action script attached to a watched folder",
    "com.apple.appkit.xpc.openandsavepanelservice": "showed a file Open or Save dialog",
    "system settings": "the macOS System Settings app",
    "phone": "the macOS Phone app (iPhone call relay)",
    # disk-space and diagnostics housekeeping
    "cachedeleteextension": "macOS reclaiming disk space from Safari's caches",
    "tvcacheextension": "macOS reclaiming disk space from the TV app's caches",
    "musiccacheextension": "macOS reclaiming disk space from the Music app's caches",
    "mailcachedelete": "macOS reclaiming disk space from Mail's caches",
    "assetmetricsextension": "reported asset-download metrics to Apple",
    "reportmemoryexception": "recorded an app's excessive memory use for diagnostics",
    "reportmemoryexce": "recorded an app's excessive memory use for diagnostics",
    "reportcrash": "recorded a crash report for an app that quit unexpectedly",
    "spindump": "sampled an unresponsive app to record why it hung",
    # everyday CLI tools
    "tail": "followed the end of a file, usually a log",
    "head": "read the first lines of a file",
    "tee": "wrote output to a file and passed it along",
    "sed": "edited text in a stream or file",
    "env": "ran a command with a modified environment",
    "sleep": "waited a set number of seconds, usually inside a script",
    "codesign": "inspected or applied a code signature",
    "grep": "searched text in files",
    "find": "searched the filesystem for files",
    "ps": "listed running processes",
    "top": "watched live process/CPU usage",
    "killall": "sent a signal to processes by name",
    "log": "read or streamed the unified system log",
    "defaults": "read or wrote an app preference",
    "plutil": "inspected or converted a property-list file",
    "zsh": "the default macOS shell, which runs terminal commands",
    "bash": "a shell, which runs terminal commands",
    "sh": "a shell, which runs terminal commands",
    "git": "ran a version-control operation",
    # things worth a second look even when genuine (kept in
    # severity_engine._LOLBIN_NAMES too -- these notes say what the tool is,
    # not that the use of it was fine)
    "osascript": "ran an AppleScript (Aegis uses this for its own notifications, "
                 "but it can also automate other apps)",
    "curl": "transferred data over the network",
    "wget": "downloaded a file over the network",
    "ssh": "opened a remote shell connection",
    "sudo": "ran a command as another user, usually root",
    "security": "accessed the Keychain / certificate store",
    "dscl": "read or changed user and group directory records",
    "launchctl": "loaded, started or stopped a background service",
    "screencapture": "captured the screen",
    "xattr": "read or changed extended file attributes, including quarantine flags",
    "csrutil": "checked System Integrity Protection status",
    "python": "ran a Python program",
    "python3": "ran a Python program",
    "perl": "ran a Perl program",
    "ruby": "ran a Ruby program",
}


def describe(name: str, exe_path: str) -> str | None:
    """Short human-readable note for a system utility, or None.

    None is the normal answer for anything unrecognised or anything whose path
    isn't SIP-protected -- callers must treat a missing note as "no comment",
    never as a signal in either direction.
    """
    if not name or not is_system_binary(exe_path):
        return None
    return _NOTES.get(name.lower().removesuffix(".exe"))


if __name__ == "__main__":
    import core.rule_engine as _re

    # is_system_binary() resolves _sip_ok from its own module globals, so this
    # forces the SIP branch on and the check runs identically on a SIP-disabled
    # Mac or on Linux CI (Path.resolve() doesn't require the file to exist).
    _re._sip_ok = lambda: True  # type: ignore[assignment]

    # describe() lowercases before the lookup, so a capitalised key ("System
    # Events", "MTLCompilerService") would silently never match -- the exact
    # way this table breaks when someone pastes a name straight from `ps`.
    assert all(k == k.lower() for k in _NOTES), "note keys must be lowercase"

    assert describe("ioreg", "/usr/sbin/ioreg").startswith("read the hardware registry")
    assert describe("zsh", "/bin/zsh") is not None
    # Names arrive in whatever case the collector reports them.
    assert describe("System Events", "/System/Library/CoreServices/System Events.app/"
                                     "Contents/MacOS/System Events") is not None
    assert describe("com.apple.WebKit.GPU", "/System/Library/Frameworks/WebKit.framework/x") is not None
    # p_comm truncates at 16 chars; both spellings must resolve to the same note.
    assert describe("authorizationhos", "/System/x") == describe("authorizationhost", "/System/x")
    # A payload named after a system tool must NOT inherit the friendly text.
    assert describe("ioreg", "/Users/me/Downloads/ioreg") is None
    assert describe("ioreg", "") is None
    # Unknown system binaries simply get no note.
    assert describe("some_daemon", "/usr/libexec/some_daemon") is None
    assert describe("", "/usr/sbin/ioreg") is None
    print("process_notes self-check: OK")
