"""
Local, encrypted-at-rest storage for provider API keys (and any other small
app secret) that must survive a self-update and never be echoed back to the
dashboard in plaintext.

Previously, the dashboard wrote API keys as plaintext lines in a `.env` file
living next to the app's own code (see core/config.py's ENV_FILE_PATH). For a
packaged desktop build that path is INSIDE the app bundle core/updater.py
replaces wholesale on every self-update (`rm -rf` the old .app, copy in the
new one) -- so the key was silently deleted on every update, forcing the user
to re-enter it. This store instead lives in the same per-user data directory
as the event database (core/config.runtime_data_dir()), which self-update
never touches.

Threat model: this defends against casual disclosure of the key value --
screenshots, support bundles, backups, an accidental `git add .env`, another
local account browsing the filesystem without also lifting the sibling key
file. It is NOT an OS keychain and does not defend a fully compromised local
user account (whoever can read the data directory can, in principle, read
both files in it). Aegis has zero non-stdlib crypto dependency today, so this
uses HMAC-SHA256 as a keystream PRF (encrypt-then-MAC) rather than pulling in
`cryptography` for a handful of short strings. A hash is deliberately NOT used
here -- unlike a password, an API key must be recoverable in plaintext to
actually authenticate outbound AI calls, so this has to be reversible.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as _secrets
import stat
from pathlib import Path

_NONCE_LEN = 16
_MAC_LEN = 32


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _subkey(key: bytes, label: bytes) -> bytes:
    return hmac.new(key, label, hashlib.sha256).digest()


def _encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = _secrets.token_bytes(_NONCE_LEN)
    enc_key = _subkey(key, b"aegis-secrets-enc")
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, _keystream(enc_key, nonce, len(plaintext))))
    mac_key = _subkey(key, b"aegis-secrets-mac")
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def _decrypt(key: bytes, blob: bytes) -> bytes | None:
    if len(blob) < _NONCE_LEN + _MAC_LEN:
        return None
    nonce, rest = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    ciphertext, tag = rest[:-_MAC_LEN], rest[-_MAC_LEN:]
    mac_key = _subkey(key, b"aegis-secrets-mac")
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        return None  # tampered, corrupt, or the key file doesn't match this blob
    enc_key = _subkey(key, b"aegis-secrets-enc")
    return bytes(a ^ b for a, b in zip(ciphertext, _keystream(enc_key, nonce, len(ciphertext))))


def _chmod_user_only(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600 -- no-op-ish on Windows, real on POSIX
    except OSError:
        pass


class SecretsStore:
    """One encrypted JSON blob (name -> value) per data directory."""

    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self._key_path = data_dir / ".secrets.key"
        self._blob_path = data_dir / "secrets.enc"
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        if self._key_path.is_file():
            existing = self._key_path.read_bytes()
            if len(existing) == 32:
                return existing
        key = _secrets.token_bytes(32)
        self._key_path.write_bytes(key)
        _chmod_user_only(self._key_path)
        return key

    def _load_all(self) -> dict:
        if not self._blob_path.is_file():
            return {}
        raw = self._blob_path.read_bytes()
        if not raw:
            return {}
        plaintext = _decrypt(self._key, raw)
        if plaintext is None:
            return {}
        try:
            values = json.loads(plaintext.decode("utf-8"))
            return values if isinstance(values, dict) else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _save_all(self, values: dict) -> None:
        plaintext = json.dumps(values).encode("utf-8")
        self._blob_path.write_bytes(_encrypt(self._key, plaintext))
        _chmod_user_only(self._blob_path)

    def get(self, name: str) -> str | None:
        return self._load_all().get(name)

    def set(self, name: str, value: str) -> None:
        values = self._load_all()
        values[name] = value
        self._save_all(values)

    def delete(self, name: str) -> None:
        values = self._load_all()
        if values.pop(name, None) is not None:
            self._save_all(values)


_store: SecretsStore | None = None
_store_dir: Path | None = None


def _get_store() -> SecretsStore:
    global _store, _store_dir
    from core.config import persistent_dir  # local import: avoids a hard import cycle at module load

    data_dir = persistent_dir()
    if _store is None or _store_dir != data_dir:
        _store = SecretsStore(data_dir)
        _store_dir = data_dir
    return _store


def get_secret(name: str) -> str | None:
    return _get_store().get(name)


def set_secret(name: str, value: str) -> None:
    _get_store().set(name, value)


def delete_secret(name: str) -> None:
    _get_store().delete(name)
