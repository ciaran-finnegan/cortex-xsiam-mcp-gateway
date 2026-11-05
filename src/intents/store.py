"""Files of the intent pilot. All of them sit under ``<TENANT_PACK_DIR>/intents/``, owner-only and git-ignored."""

import json
import secrets
from pathlib import Path
from typing import Any

from usecase.learned_store import (
    LearnedStoreError,
    ensure_private_dir,
    write_private_file,
)

MAX_FILE_BYTES = 128 * 1024 * 1024
FILE_VERSION = 1
ISSUER_KEY_BYTES = 32


def intents_dir(root: Path) -> Path:
    return root / "intents"


def prepare(root: Path) -> None:
    """Create the directory and keep everything in it out of the tenant pack's own git history."""
    directory = intents_dir(root)
    ensure_private_dir(directory, root)
    ignore = directory / ".gitignore"
    if not ignore.exists() and not ignore.is_symlink():
        write_private_file(ignore, "*\n")


def check_readable(path: Path) -> bool:
    """False when the file is absent. Refuses a symbolic link or an oversized file."""
    if path.is_symlink():
        raise LearnedStoreError("Refusing to read through a symbolic link")
    if not path.exists():
        return False
    if path.stat().st_size > MAX_FILE_BYTES:
        raise LearnedStoreError("Intent pilot file exceeds the size limit")
    return True


def read_json(path: Path) -> dict[str, Any] | None:
    if not check_readable(path):
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise LearnedStoreError("Intent pilot file is unreadable") from e
    if not isinstance(value, dict) or value.get("version") != FILE_VERSION:
        raise LearnedStoreError("Intent pilot file has an unknown version")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    write_private_file(path, json.dumps({"version": FILE_VERSION, **value}, sort_keys=True, indent=1))


def issuer_key(root: Path) -> bytes:
    """The per-pack key behind the issuer hash, created on first use. It never leaves the pack."""
    path = intents_dir(root) / "issuer.key"
    if check_readable(path):
        try:
            key = bytes.fromhex(path.read_text(encoding="ascii").strip())
        except (OSError, ValueError) as e:
            raise LearnedStoreError("Issuer key is unreadable") from e
        # A damaged key would silently regroup every session under new hashes.
        if len(key) != ISSUER_KEY_BYTES:
            raise LearnedStoreError("Issuer key is unreadable")
        return key
    key = secrets.token_bytes(ISSUER_KEY_BYTES)
    write_private_file(path, key.hex())
    return key
