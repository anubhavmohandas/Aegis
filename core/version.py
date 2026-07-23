"""
Single source of truth for the Aegis version string.

Semantic versioning with pre-release tags, tied to validation status rather
than feature completeness:

    2.0.0-alpha  -> features done; macOS validated live, Windows not yet
    2.0.0-beta   -> Windows AND macOS both validated on real hardware
    2.0.0        -> public release (packaged, installer, docs/screenshots)

NOTE: the current 2.0.x line dropped the suffix before it met that third bar
(builds are still unsigned and Windows hardware validation is still open --
see CHANGELOG.md). The suffix is deliberately NOT being added back: a version
string only ever moves forward here, because _parse_version sorts a missing
pre-release tag ABOVE any suffix, so republishing "2.0.3" as "2.0.3-alpha"
would make every installed copy treat the build it is already running as a
newer release and self-update in a loop (the v2.0.1 incident).

Bump this in exactly one place -- main.py logs it, packaging/aegis.spec
embeds it in the bundle name, and packaging/windows-installer.iss carries a
copy (Inno Setup can't import Python; keep them in sync by hand, and the
packaging docs call that out).
"""

__version__ = "2.0.4"
