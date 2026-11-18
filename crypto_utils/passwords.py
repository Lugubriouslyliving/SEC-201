"""Salted password hashing for the server's user database.

Algorithm: scrypt (memory-hard key derivation function), via
`cryptography.hazmat.primitives.kdf.scrypt.Scrypt`.

Why scrypt and not plain SHA-256?
    A fast hash lets an attacker who steals the database try billions of
    guesses per second. scrypt is deliberately slow *and* needs a lot of
    memory per guess, which makes GPU/ASIC guessing expensive.

Why a salt?
    Each user gets 16 random bytes mixed into their hash. Two users with the
    same password get different hashes, and precomputed "rainbow tables"
    become useless because the attacker would need one table per salt.
"""

import hmac
import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .encoding import b64d, b64e

# scrypt cost parameters. n=2**15, r=8 uses ~32 MiB of memory per hash.
# They are stored with every record so they can be raised later without
# breaking existing accounts.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
HASH_BYTES = 32


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=HASH_BYTES, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def hash_password(password: str) -> dict:
    """Create a new password record: a fresh random salt plus the scrypt hash.

    The returned dict is what the server stores. It never contains the
    password itself.
    """
    salt = os.urandom(SALT_BYTES)  # unique per user, from the OS CSPRNG
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return {
        "algorithm": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": b64e(salt),
        "hash": b64e(digest),
    }


def verify_password(password: str, record: dict) -> bool:
    """Recompute the hash with the stored salt and compare in constant time.

    `hmac.compare_digest` takes the same time whether the first byte or the
    last byte differs, so an attacker cannot learn the hash byte by byte by
    timing the server's answers.
    """
    candidate = _scrypt(password, b64d(record["salt"]), record["n"], record["r"], record["p"])
    return hmac.compare_digest(candidate, b64d(record["hash"]))


# A record for a password nobody knows. When a login names a user that does
# not exist, the server still runs one scrypt computation against this dummy
# record, so "no such user" takes as long as "wrong password" and the two
# cases cannot be told apart by timing.
DUMMY_RECORD = hash_password(b64e(os.urandom(24)))
