"""Password hashing, in two layers.

    client:  login_hash = scrypt(password, salt from username)   -> sent to server
    server:  stored     = scrypt(login_hash, random salt)         -> saved in database

The client layer keeps the real password off the network and away from
the server. The server layer is the classic salted hash of whatever
credential arrives, so a stolen database is still useless for logging in.

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

from cryptography.hazmat.primitives import hashes
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


# ===================================================================
# Client side: the password never leaves the user's computer.
# ===================================================================

LOGIN_HASH_CONTEXT = b"secure-chat/login-hash/v1:"
LOGIN_HASH_BYTES = 32


def client_password_hash(username: str, password: str) -> str:
    """What the client sends to the server instead of the password.

    login_hash = scrypt(password, salt = SHA-256(context || username))

    Why the username as salt? The client must compute the same value on any
    computer, before it has talked to the server, so the salt cannot be
    random. Using the username still makes it unique per user, so one
    precomputed table cannot attack everyone at once. The context label
    keeps it unrelated to any other use of the same password.

    The result protects the real password: the server operator, the server
    log and anyone watching the network only ever see this hash. Since the
    same password also unlocks the private-key file (with a different,
    random salt), the server can never open that file either.

    Note: to the server this hash now *is* the credential. Someone who
    captures it on the network could replay it to log in (but still could
    not read any messages without the private-key file). Only an encrypted
    channel such as TLS stops that. See README, "Threat model".
    """
    h = hashes.Hash(hashes.SHA256())
    h.update(LOGIN_HASH_CONTEXT + username.encode("utf-8"))
    salt = h.finalize()
    digest = Scrypt(salt=salt, length=LOGIN_HASH_BYTES, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        password.encode("utf-8")
    )
    return b64e(digest)


def is_login_hash(value) -> bool:
    """True if `value` looks like client_password_hash() output (base64 of 32 bytes)."""
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        return len(b64d(value)) == LOGIN_HASH_BYTES
    except ValueError:
        return False


# A record for a password nobody knows. When a login names a user that does
# not exist, the server still runs one scrypt computation against this dummy
# record, so "no such user" takes as long as "wrong password" and the two
# cases cannot be told apart by timing.
DUMMY_RECORD = hash_password(b64e(os.urandom(24)))
