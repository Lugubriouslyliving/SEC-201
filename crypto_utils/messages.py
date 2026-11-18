"""The end-to-end message format.

    Sender (Bob)                                     Receiver (Alice)
    ------------                                     ----------------
    1. aes_key = 32 random bytes                     1. verify Ed25519 signature
    2. nonce   = 12 random bytes                        with Bob's public key
    3. ciphertext = AES-256-GCM(aes_key, nonce,         -> reject if invalid
                     plaintext, aad=metadata)        2. check message ID not seen
    4. wrapped_key = RSA-OAEP(Alice's public key,       -> reject replays
                              aes_key)               3. aes_key = RSA-OAEP-decrypt
    5. signature = Ed25519(Bob's private key,            (Alice's private key)
                   every field below)                4. plaintext = AES-GCM-decrypt
                                                        -> GCM tag must verify

This is "hybrid encryption": RSA is slow and can only encrypt a few hundred
bytes, AES is fast and handles any length, so RSA protects only the small
AES key and AES protects the message.

The package (all binary values base64-encoded):

    {
      "version": 1,
      "msg_id": "<random 128-bit hex>",
      "sender": "bob",
      "recipient": "alice",
      "timestamp": 1763450000,
      "nonce": "...",          # 96-bit AES-GCM nonce
      "ciphertext": "...",     # AES-GCM output (includes the 128-bit tag)
      "wrapped_key": "...",    # AES key encrypted with RSA-OAEP
      "signature": "..."       # Ed25519 over all fields above
    }
"""

import os
import time
import uuid

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encoding import b64d, b64e, canonical_json
from .keys import UserKeys, load_enc_public, load_sign_public

VERSION = 1
SIGNATURE_CONTEXT = "secure-chat/message/v1"  # domain separation label, see _signed_bytes
SIGNED_FIELDS = ("version", "msg_id", "sender", "recipient", "timestamp", "nonce", "ciphertext", "wrapped_key")
MAX_FUTURE_SKEW = 300  # seconds a timestamp may be ahead of the receiver's clock

# RSA-OAEP with SHA-256 for both the hash and the mask generation function.
OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class MessageRejected(Exception):
    """The receiver refuses a message. `reason` says why, in plain words."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _no_trace(step: str, detail: str = "") -> None:
    pass


def _signed_bytes(package: dict) -> bytes:
    """The exact bytes the signature covers.

    Every field except the signature itself is included, so changing ANY of
    them (ciphertext, nonce, wrapped key, sender, recipient, time, ID)
    breaks the signature. The context label stops a signature made for some
    other purpose from ever being accepted as a message signature.
    """
    body = {k: package[k] for k in SIGNED_FIELDS}
    body["context"] = SIGNATURE_CONTEXT
    return canonical_json(body)


def _aad(msg_id: str, sender: str, recipient: str, timestamp: int) -> bytes:
    """Associated data for AES-GCM.

    AAD is not encrypted, but GCM's tag covers it. Binding the metadata here
    means the ciphertext only decrypts in the context it was created for,
    a second line of defence behind the signature.
    """
    return canonical_json(
        {"v": VERSION, "msg_id": msg_id, "sender": sender, "recipient": recipient, "timestamp": timestamp}
    )


# ===================================================================== send


def encrypt_and_sign(
    plaintext: str,
    sender: str,
    recipient: str,
    sender_keys: UserKeys,
    recipient_enc_public_pem: str,
    trace=_no_trace,
) -> dict:
    """Build a sealed, signed package for `recipient`."""
    msg_id = uuid.uuid4().hex  # 122 random bits, unique per message
    timestamp = int(time.time())

    # --- Step 1: encrypt with a fresh AES-256 key and a fresh 96-bit nonce.
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), _aad(msg_id, sender, recipient, timestamp))
    trace(
        "ENCRYPT",
        f"AES-256-GCM with a fresh random key and nonce {nonce.hex()}\n"
        f"plaintext {len(plaintext.encode())} bytes -> ciphertext {len(ciphertext)} bytes "
        f"(last 16 bytes are the GCM tag)\n"
        f"ciphertext: {ciphertext.hex()[:64]}...",
    )

    # --- Step 2: wrap the AES key so only the recipient can recover it.
    wrapped_key = load_enc_public(recipient_enc_public_pem).encrypt(aes_key, OAEP)
    trace(
        "WRAP KEY",
        f"RSA-OAEP(SHA-256) with {recipient}'s public key: 32-byte AES key -> {len(wrapped_key)}-byte wrapped key",
    )

    package = {
        "version": VERSION,
        "msg_id": msg_id,
        "sender": sender,
        "recipient": recipient,
        "timestamp": timestamp,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "wrapped_key": b64e(wrapped_key),
    }

    # --- Step 3: sign everything with the sender's Ed25519 private key.
    signature = sender_keys.sign_private.sign(_signed_bytes(package))
    package["signature"] = b64e(signature)
    trace(
        "SIGN",
        f"Ed25519 with {sender}'s private key over version, msg_id, sender, recipient, timestamp,\n"
        f"nonce, ciphertext, wrapped_key -> 64-byte signature {signature.hex()[:32]}...",
    )
    return package


# ================================================================== receive


def verify_and_decrypt(
    package: dict,
    my_name: str,
    my_keys: UserKeys,
    sender_sign_public_pem: str,
    seen_ids: set | None = None,
    trace=_no_trace,
) -> str:
    """Check and open a package. Returns the plaintext or raises MessageRejected.

    The order matters: the signature is verified FIRST, before we spend any
    effort on (or expose any code to) data from an unauthenticated source.
    """
    try:
        _check_shape(package)
    except (KeyError, TypeError, ValueError) as exc:
        raise MessageRejected(f"malformed package ({exc})") from None

    # --- Step 1: who sent this, and is it exactly what they sent?
    try:
        signature = b64d(package["signature"])
        load_sign_public(sender_sign_public_pem).verify(signature, _signed_bytes(package))
    except (InvalidSignature, ValueError):
        trace("VERIFY", f"signature does NOT match {package['sender']}'s public key -> REJECT")
        raise MessageRejected(
            f"invalid signature: this message was not signed by '{package['sender']}' "
            "or was modified after signing"
        ) from None
    trace("VERIFY", f"Ed25519 signature is valid for {package['sender']}'s public key")

    # --- Step 2: is it really for me, and is it new?
    if package["recipient"] != my_name:
        raise MessageRejected(f"message is addressed to '{package['recipient']}', not to you")
    if package["timestamp"] > time.time() + MAX_FUTURE_SKEW:
        raise MessageRejected("timestamp is in the future")
    if seen_ids is not None:
        if package["msg_id"] in seen_ids:
            trace("REPLAY CHECK", f"message ID {package['msg_id']} was already received -> REJECT")
            raise MessageRejected(f"replay detected: message ID {package['msg_id']} was already received")
        trace("REPLAY CHECK", f"message ID {package['msg_id']} is new")

    # --- Step 3: unwrap the AES key with my RSA private key.
    try:
        aes_key = my_keys.enc_private.decrypt(b64d(package["wrapped_key"]), OAEP)
    except ValueError:
        raise MessageRejected("could not unwrap the AES key (not encrypted to your key)") from None
    trace("UNWRAP KEY", "RSA-OAEP decrypt with my private key -> 32-byte AES key")

    # --- Step 4: decrypt; GCM checks its authentication tag at the same time.
    try:
        plaintext = AESGCM(aes_key).decrypt(
            b64d(package["nonce"]),
            b64d(package["ciphertext"]),
            _aad(package["msg_id"], package["sender"], package["recipient"], package["timestamp"]),
        )
    except InvalidTag:
        trace("DECRYPT", "AES-GCM authentication tag does NOT verify -> REJECT")
        raise MessageRejected("AES-GCM authentication failed: ciphertext or metadata was modified") from None
    trace("DECRYPT", "AES-256-GCM tag verified, plaintext recovered")

    if seen_ids is not None:
        seen_ids.add(package["msg_id"])
    return plaintext.decode("utf-8")


def decrypt_without_signature_check(package: dict, my_keys: UserKeys) -> str:
    """FOR DEMONSTRATION ONLY. Skips the signature to show that AES-GCM's tag
    independently catches tampering. Never use this for real messages."""
    aes_key = my_keys.enc_private.decrypt(b64d(package["wrapped_key"]), OAEP)
    return AESGCM(aes_key).decrypt(
        b64d(package["nonce"]),
        b64d(package["ciphertext"]),
        _aad(package["msg_id"], package["sender"], package["recipient"], package["timestamp"]),
    ).decode("utf-8")


def _check_shape(package: dict) -> None:
    """Reject anything that is not a well-formed v1 package."""
    if not isinstance(package, dict):
        raise TypeError("package must be an object")
    for field in SIGNED_FIELDS + ("signature",):
        if field not in package:
            raise KeyError(field)
    if package["version"] != VERSION:
        raise ValueError("unsupported version")
    if not isinstance(package["timestamp"], int):
        raise TypeError("timestamp must be an integer")
    for field in ("msg_id", "sender", "recipient", "nonce", "ciphertext", "wrapped_key", "signature"):
        if not isinstance(package[field], str):
            raise TypeError(f"{field} must be a string")
    if len(b64d(package["nonce"])) != 12:
        raise ValueError("nonce must be 96 bits")
