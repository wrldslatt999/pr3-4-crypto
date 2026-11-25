"""AES-256-GCM для даних + RSA-OAEP-SHA256 для випадкового ключа файла."""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa

from .formats import CryptoFileError, pack_prefix, unpack
from .rsa_ops import encrypt as rsa_encrypt, decrypt as rsa_decrypt

MAGIC = b"CHYB"


def fingerprint(public) -> str:
    from cryptography.hazmat.primitives import hashes
    b = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b)
    return digest.finalize().hex()[:32]


def encrypt(data: bytes, public) -> bytes:
    if not isinstance(public, rsa.RSAPublicKey):
        raise ValueError("RSA public key required")
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    wrapped = rsa_encrypt(public, key)
    header = {"v": 1, "alg": "AES-256-GCM+RSA-OAEP-SHA256",
              "nonce": nonce.hex(), "recipient_fp": fingerprint(public),
              "wrap_bytes": len(wrapped)}
    prefix = pack_prefix(MAGIC, header)
    ct = AESGCM(key).encrypt(nonce, data, prefix + wrapped)
    return prefix + wrapped + ct


def decrypt(blob: bytes, private) -> bytes:
    header, prefix, body = unpack(blob, MAGIC)
    try:
        if header["alg"] != "AES-256-GCM+RSA-OAEP-SHA256":
            raise CryptoFileError("Unsupported hybrid algorithm")
        if header["recipient_fp"] != fingerprint(private.public_key()):
            raise CryptoFileError("Wrong recipient key")
        key_bytes = header["wrap_bytes"]
        if key_bytes != private.key_size // 8 or len(body) < key_bytes + 16:
            raise CryptoFileError("Invalid RSA-wrapped key length")
        wrapped, ct = body[:key_bytes], body[key_bytes:]
        key = rsa_decrypt(private, wrapped)
        nonce = bytes.fromhex(header["nonce"])
        if len(nonce) != 12 or len(key) != 32:
            raise CryptoFileError("Invalid AES key or nonce")
        return AESGCM(key).decrypt(nonce, ct, prefix + wrapped)
    except (KeyError, ValueError, InvalidTag) as exc:
        raise CryptoFileError("Hybrid authentication/decryption failed") from exc
