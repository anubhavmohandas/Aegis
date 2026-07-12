"""
Single source of truth for the Aegis version string.

Semantic versioning with pre-release tags, tied to validation status rather
than feature completeness:

    2.0.0-alpha  -> features done; macOS validated live, Windows not yet
    2.0.0-beta   -> Windows AND macOS both validated on real hardware
    2.0.0        -> public release (packaged, installer, docs/screenshots)

Bump this in exactly one place -- main.py logs it, packaging/aegis.spec
embeds it in the bundle name, and packaging/windows-installer.iss carries a
copy (Inno Setup can't import Python; keep them in sync by hand, and the
packaging docs call that out).
"""

__version__ = "2.0.1-alpha"
