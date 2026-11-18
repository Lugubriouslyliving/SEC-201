"""The server's database: one JSON file, readable on purpose.

Keeping it as plain JSON makes the "server view" demo easy: open the file
and see for yourself that it holds only salted hashes, public keys and
ciphertext.

Layout:
    {
      "users": {
        "alice": {
          "password": {"algorithm": "scrypt", "n":..., "salt": "...", "hash": "..."},
          "enc_public_pem": "-----BEGIN PUBLIC KEY-----...",
          "sign_public_pem": "-----BEGIN PUBLIC KEY-----...",
          "created": 1763450000
        }
      },
      "messages": [ {"package": {...}, "received_at": ..., "delivered": false} ],
      "seen_msg_ids": ["..."]
    }
"""

import json
import os
import threading


class Storage:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()  # one client thread at a time touches the data
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        else:
            self.data = {"users": {}, "messages": [], "seen_msg_ids": []}
            self.save()
        # A set gives fast duplicate checks; the list form is what gets saved.
        self.seen = set(self.data["seen_msg_ids"])

    def save(self) -> None:
        """Write to a temp file, then rename: a crash never leaves half a file."""
        with self.lock:
            folder = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(folder, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            os.replace(tmp, self.path)
