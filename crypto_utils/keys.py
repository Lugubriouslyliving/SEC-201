"""User key pairs and password-protected private-key storage.

Each user owns TWO key pairs, one per job:

    RSA-3072  "encryption key"  - others wrap AES keys to it with RSA-OAEP,
                                  only the owner can unwrap them.
    Ed25519   "signing key"     - the owner signs outgoing messages,
                                  everyone verifies with the public half.

Using separate keys for encryption and signing is standard practice: a
weakness or misuse in one role cannot leak into the other.

Private keys never leave the client. On disk they are encrypted with
AES-256-GCM under a key derived from the user's password by scrypt, with
its own random salt (independent of the server's password salt).
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .encoding import b64d, b64e

RSA_BITS = 3072  # ~128-bit security, matches AES-128 or better
KEYFILE_N, KEYFILE_R, KEYFILE_P = 2**15, 8, 1


class KeyFileError(Exception):
    """Raised when the key file cannot be unlocked (wrong password or tampered file)."""


class UserKeys:
    """A user's two private keys (and, through them, the public keys)."""

    def __init__(self, enc_private: rsa.RSAPrivateKey, sign_private: ed25519.Ed25519PrivateKey):
        self.enc_private = enc_private
        self.sign_private = sign_private

    @classmethod
    def generate(cls) -> "UserKeys":
        # 65537 is the standard RSA public exponent.
        enc = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
        sign = ed25519.Ed25519PrivateKey.generate()
        return cls(enc, sign)

    # ---- public halves, as PEM text the server can store and share ----

    def enc_public_pem(self) -> str:
        return public_pem(self.enc_private.public_key())

    def sign_public_pem(self) -> str:
        return public_pem(self.sign_private.public_key())

    # ---- encrypted storage ----

    def to_encrypted_file(self, password: str) -> dict:
        """Return a JSON-able dict holding both private keys, encrypted.

        Steps:
          1. salt  = 16 random bytes
          2. key   = scrypt(password, salt)        -> 32 bytes (AES-256)
          3. nonce = 12 random bytes
          4. blob  = AES-GCM(key, nonce, private keys in PKCS#8 DER)
        GCM's tag means a wrong password or an edited file is *detected*,
        not silently turned into garbage keys.
        """
        plain = _join(
            self.enc_private.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
            self.sign_private.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        )
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_file_key(password, salt, KEYFILE_N, KEYFILE_R, KEYFILE_P)
        blob = AESGCM(key).encrypt(nonce, plain, b"secure-chat keyfile v1")
        return {
            "version": 1,
            "kdf": {"algorithm": "scrypt", "n": KEYFILE_N, "r": KEYFILE_R, "p": KEYFILE_P, "salt": b64e(salt)},
            "cipher": "AES-256-GCM",
            "nonce": b64e(nonce),
            "ciphertext": b64e(blob),
            # Public keys are not secret; keeping them here is convenient.
            "enc_public_pem": self.enc_public_pem(),
            "sign_public_pem": self.sign_public_pem(),
        }

    @classmethod
    def from_encrypted_file(cls, data: dict, password: str) -> "UserKeys":
        kdf = data["kdf"]
        key = _derive_file_key(password, b64d(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"])
        try:
            plain = AESGCM(key).decrypt(b64d(data["nonce"]), b64d(data["ciphertext"]), b"secure-chat keyfile v1")
        except InvalidTag:
            raise KeyFileError("Could not unlock private keys (wrong password or damaged key file).") from None
        enc_der, sign_der = _split(plain)
        enc = serialization.load_der_private_key(enc_der, password=None)
        sign = serialization.load_der_private_key(sign_der, password=None)
        return cls(enc, sign)


# ---------------------------------------------------------------- helpers


def public_pem(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def load_enc_public(pem: str) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("expected an RSA public key")
    return key


def load_sign_public(pem: str) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def fingerprint(enc_pem: str, sign_pem: str) -> str:
    """Short SHA-256 fingerprint of a user's two public keys.

    Two people can read this aloud to each other (phone, in person) to
    confirm the server handed out the right keys.
    """
    h = hashes.Hash(hashes.SHA256())
    h.update(enc_pem.encode("ascii"))
    h.update(sign_pem.encode("ascii"))
    hexed = h.finalize().hex()[:32].upper()
    return " ".join(hexed[i : i + 4] for i in range(0, len(hexed), 4))


def _derive_file_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def _join(a: bytes, b: bytes) -> bytes:
    # Length-prefix the first key so the two can be split again unambiguously.
    return len(a).to_bytes(4, "big") + a + b


def _split(data: bytes) -> tuple[bytes, bytes]:
    n = int.from_bytes(data[:4], "big")
    return data[4 : 4 + n], data[4 + n :]
