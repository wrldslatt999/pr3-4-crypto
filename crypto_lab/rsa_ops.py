"""RSA-OAEP-SHA256, RSA-PSS-SHA256, зашифрований PKCS#8 PEM."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .formats import safe_write

BITS = (2048, 3072, 4096)


def generate(bits=3072):
    if bits not in BITS:
        raise ValueError("RSA bits must be 2048, 3072 or 4096")
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private, private.public_key()


def save_keys(private, public, priv_path, pub_path, password):
    if len(password) < 12:
        raise ValueError("Private PEM password must be at least 12 characters")
    if str(priv_path) == str(pub_path):
        raise ValueError("Private and public key paths must differ")
    enc = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    pub = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    safe_write(priv_path, enc, private=True)
    safe_write(pub_path, pub, private=False)


def load_private(path, password):
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=password.encode("utf-8"))
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size not in BITS:
        raise ValueError("Only RSA 2048/3072/4096 keys are supported")
    return key


def load_public(path):
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size not in BITS:
        raise ValueError("Only RSA public keys 2048/3072/4096 are supported")
    return key


def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None,
    )


def encrypt(public, data: bytes):
    max_size = public.key_size // 8 - 2 * 32 - 2
    if len(data) > max_size:
        raise ValueError(f"RSA-OAEP only encrypts <= {max_size} bytes; use hybrid for files")
    return public.encrypt(data, _oaep())


def decrypt(private, ciphertext: bytes):
    return private.decrypt(ciphertext, _oaep())


def sign(private, data: bytes):
    return private.sign(
        data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )


def verify(public, signature: bytes, data: bytes):
    try:
        public.verify(signature, data, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
