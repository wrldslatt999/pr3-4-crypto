"""Строгий компактний формат контейнерів із автентифікованим заголовком."""
import json
import os
import struct
import tempfile
from pathlib import Path

MAX_HEADER = 4096
MAX_INPUT = 64 * 1024 * 1024  # Обмеження цього навчального CLI, не межа AES.


class CryptoFileError(ValueError):
    """Некоректний або пошкоджений криптографічний контейнер."""


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pack_prefix(magic: bytes, header: dict) -> bytes:
    raw = canonical_json(header)
    if len(magic) != 4 or not 2 <= len(raw) <= MAX_HEADER:
        raise CryptoFileError("Invalid container header length")
    return magic + struct.pack(">H", len(raw)) + raw


def unpack(blob: bytes, magic: bytes):
    if len(blob) < 8 or blob[:4] != magic:
        raise CryptoFileError("Invalid magic/too short file")
    n = int.from_bytes(blob[4:6], "big")
    if n < 2 or n > MAX_HEADER or len(blob) < 6 + n + 1:
        raise CryptoFileError("Truncated or oversize header")
    prefix = blob[:6 + n]
    try:
        header = json.loads(prefix[6:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoFileError("Invalid header JSON") from exc
    if not isinstance(header, dict) or header.get("v") != 1:
        raise CryptoFileError("Unsupported container format")
    if pack_prefix(magic, header) != prefix:
        raise CryptoFileError("Noncanonical container header")
    return header, prefix, blob[6 + n:]


def read_input(path) -> bytes:
    f = Path(path)
    if f.stat().st_size > MAX_INPUT:
        raise CryptoFileError("File too large for educational in-memory CLI (64 MiB)")
    return f.read_bytes()


def safe_write(path, data: bytes, *, private=True, overwrite=False):
    """Атомарний запис. Наявні файли не перезаписуються без явного дозволу."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Output exists: {path}")
    fd, tmp = tempfile.mkstemp(prefix=".crypto-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600 if private else 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists() and not overwrite:
            raise FileExistsError(f"Output exists: {path}")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
