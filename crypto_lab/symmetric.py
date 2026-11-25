"""AES-GCM і AES-CBC+HMAC-SHA256 (encrypt-then-MAC)."""
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .formats import CryptoFileError, pack_prefix, unpack

MAGIC = b"CSYM"


class IntegrityError(CryptoFileError):
    """Змінені дані, неправильний ключ або невірний тег."""


def _derive(master: bytes, salt: bytes, length: int, context: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=context).derive(master)


def _validate(master: bytes):
    if len(master) not in (16, 24, 32):
        raise ValueError("AES key must contain 16, 24 or 32 bytes")


def encrypt(data: bytes, master: bytes, *, mode="gcm", key_id="benchmark") -> bytes:
    _validate(master)
    if mode not in ("gcm", "cbc"):
        raise ValueError("Mode must be gcm or cbc")
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("Input exceeds educational 64 MiB limit")
    salt = os.urandom(16)  # Унікальний salt для відділення ключа кожного файла.
    header = {"v": 1, "mode": mode, "bits": len(master) * 8,
              "kid": key_id, "salt": salt.hex()}
    if mode == "gcm":
        nonce = os.urandom(12)  # Новий 96-бітний nonce під кожен ключ файла.
        header["nonce"] = nonce.hex()
        prefix = pack_prefix(MAGIC, header)
        key = _derive(master, salt, len(master), b"lab34/AES-GCM/v1")
        return prefix + AESGCM(key).encrypt(nonce, data, prefix)
    iv = os.urandom(16)
    header["iv"] = iv.hex()
    prefix = pack_prefix(MAGIC, header)
    raw = _derive(master, salt, len(master) + 32, b"lab34/AES-CBC-HMAC/v1")
    enc_key, mac_key = raw[:len(master)], raw[len(master):]
    pad = padding.PKCS7(128).padder()
    padded = pad.update(data) + pad.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    tagger = hmac.HMAC(mac_key, hashes.SHA256())
    tagger.update(prefix + ct)  # Цілісність заголовка, IV, salt та шифротексту.
    return prefix + ct + tagger.finalize()


def decrypt(blob: bytes, master: bytes, *, expected_kid=None) -> bytes:
    _validate(master)
    header, prefix, payload = unpack(blob, MAGIC)
    if header.get("bits") != len(master) * 8:
        raise IntegrityError("AES key size mismatch")
    if expected_kid is not None and header.get("kid") != expected_kid:
        raise IntegrityError("Key identifier mismatch")
    try:
        salt = bytes.fromhex(header["salt"])
        if len(salt) != 16:
            raise ValueError("invalid salt length")
        mode = header["mode"]
        if mode == "gcm":
            nonce = bytes.fromhex(header["nonce"])
            if len(nonce) != 12 or len(payload) < 16:
                raise ValueError("invalid GCM layout")
            key = _derive(master, salt, len(master), b"lab34/AES-GCM/v1")
            return AESGCM(key).decrypt(nonce, payload, prefix)
        if mode == "cbc":
            iv = bytes.fromhex(header["iv"])
            if len(iv) != 16 or len(payload) < 48 or (len(payload) - 32) % 16:
                raise ValueError("invalid CBC layout")
            raw = _derive(master, salt, len(master) + 32, b"lab34/AES-CBC-HMAC/v1")
            enc_key, mac_key = raw[:len(master)], raw[len(master):]
            ct, tag = payload[:-32], payload[-32:]
            checker = hmac.HMAC(mac_key, hashes.SHA256())
            checker.update(prefix + ct)
            checker.verify(tag)  # До дешифрування (без padding oracle).
            decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpad = padding.PKCS7(128).unpadder()
            return unpad.update(padded) + unpad.finalize()
        raise CryptoFileError("Unsupported AES mode")
    except (KeyError, ValueError, InvalidTag, InvalidSignature) as exc:
        raise IntegrityError("Decryption/authentication failed or invalid container") from exc


def peek_key_id(blob: bytes) -> str:
    header, _, _ = unpack(blob, MAGIC)
    kid = header.get("kid")
    if not isinstance(kid, str) or len(kid) > 64:
        raise CryptoFileError("Missing/invalid key identifier")
    return kid
