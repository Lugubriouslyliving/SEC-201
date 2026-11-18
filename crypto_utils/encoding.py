"""Encoding helpers shared by client, server and crypto code.

JSON cannot carry raw bytes, so every binary value (ciphertext, nonce,
keys, signatures) travels as standard base64 text.
"""

import base64
import json


def b64e(data: bytes) -> str:
    """Bytes -> base64 text."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Base64 text -> bytes. `validate=True` rejects stray characters."""
    return base64.b64decode(text.encode("ascii"), validate=True)


def canonical_json(obj) -> bytes:
    """Serialize `obj` to one exact byte string.

    A signature is over *bytes*, so sender and receiver must turn the same
    fields into the same bytes. Sorting keys and fixing the separators makes
    the output deterministic no matter how the dict was built.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
