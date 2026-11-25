"""Кероване сховище AES-ключів: Scrypt + AES-GCM, ротація без втрати старих версій."""
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .formats import canonical_json, safe_write

LABEL_RE = re.compile(r"[A-Za-z0-9_-]{1,40}\Z")


def _key(password: str, salt: bytes):
    if len(password) < 12:
        raise ValueError("Passphrase must be at least 12 characters")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


class KeyStore:
    def __init__(self, root=".crypto-lab/keys"):
        self.root = Path(root)
        self.index_path = self.root / "index.json"

    def _index(self):
        if not self.index_path.exists():
            return {}
        obj = json.loads(self.index_path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("Invalid key index")
        return obj

    def new(self, label: str, bits: int, password: str, *, rotate=False):
        if not LABEL_RE.fullmatch(label):
            raise ValueError("Label must match [A-Za-z0-9_-]{1,40}")
        if bits not in (128, 192, 256):
            raise ValueError("AES bits must be 128, 192 or 256")
        index = self._index()
        if label in index and not rotate:
            raise ValueError("Label already exists; use 'sym rotate'")
        if rotate and label not in index:
            raise ValueError("Label does not exist; use 'sym new'")
        master = secrets.token_bytes(bits // 8)
        kid = secrets.token_hex(16)
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        created = datetime.now(timezone.utc).isoformat()
        public = {"v": 1, "kid": kid, "label": label, "bits": bits,
                  "created_utc": created, "kdf": "scrypt-n32768-r8-p1"}
        sealed = AESGCM(_key(password, salt)).encrypt(nonce, master, canonical_json(public))
        doc = dict(public, salt=salt.hex(), nonce=nonce.hex(), wrapped=sealed.hex())
        safe_write(self.root / (kid + ".json"), canonical_json(doc), private=True)
        versions = index.get(label, [])
        index[label] = [*versions, kid]
        safe_write(self.index_path, canonical_json(index), private=True, overwrite=True)
        return public

    def active_id(self, label):
        versions = self._index().get(label)
        if not versions:
            raise ValueError("No stored AES key for label")
        return versions[-1]

    def load(self, label: str, password: str, *, kid=None):
        versions = self._index().get(label, [])
        if not versions:
            raise ValueError("Unknown label")
        if kid is None:
            kid = versions[-1]
        if kid not in versions or not re.fullmatch(r"[0-9a-f]{32}", kid):
            raise ValueError("Key ID does not belong to this label")
        doc = json.loads((self.root / (kid + ".json")).read_text(encoding="utf-8"))
        public = {k:doc[k] for k in ("v", "kid", "label", "bits", "created_utc", "kdf")}
        if doc["kid"] != kid or doc["label"] != label:
            raise ValueError("Key metadata mismatch")
        try:
            key = AESGCM(_key(password, bytes.fromhex(doc["salt"]))).decrypt(
                bytes.fromhex(doc["nonce"]), bytes.fromhex(doc["wrapped"]), canonical_json(public)
            )
        except InvalidTag as exc:
            raise ValueError("Wrong passphrase or tampered key file") from exc
        if len(key) * 8 != doc["bits"]:
            raise ValueError("Key length mismatch")
        return key, public

    def list_metadata(self):
        index = self._index()
        return [{"label": label, "versions": len(ids), "active_kid": ids[-1]}
                for label, ids in sorted(index.items())]
