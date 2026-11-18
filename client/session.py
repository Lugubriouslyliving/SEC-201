"""Client-side logic: keys on disk, talking to the server, sealing and opening messages.

Local files, per user, under the client's data folder (default ./client_data):

    <user>/keys.json        both private keys, encrypted with a password-derived key
    <user>/seen_ids.json    message IDs already accepted (replay detection)
    <user>/known_keys.json  public keys seen for each contact (key pinning)
"""

import json
import os

from crypto_utils.keys import KeyFileError, UserKeys, fingerprint
from crypto_utils.messages import MessageRejected, encrypt_and_sign, verify_and_decrypt

from .connection import Connection


class ClientError(Exception):
    pass


def _no_trace(step, detail=""):
    pass


class ChatClient:
    def __init__(self, host: str, port: int, data_dir: str = "client_data", trace=_no_trace):
        self.host, self.port = host, port
        self.data_dir = data_dir
        self.trace = trace
        self.conn = Connection(host, port)
        self.username: str | None = None
        self.keys: UserKeys | None = None
        self.seen_ids: set[str] = set()

    # ------------------------------------------------------------ files

    def _path(self, username: str, name: str) -> str:
        return os.path.join(self.data_dir, username, name)

    def _read_json(self, username, name, default):
        path = self._path(username, name)
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write_json(self, username, name, data):
        path = self._path(username, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # ------------------------------------------------------------ accounts

    def signup(self, username: str, password: str) -> None:
        if os.path.exists(self._path(username, "keys.json")):
            raise ClientError(f"A key file for '{username}' already exists in {self.data_dir}.")
        self.trace("KEYGEN", "generating RSA-3072 (encryption) and Ed25519 (signing) key pairs locally")
        keys = UserKeys.generate()
        resp = self.conn.request({
            "action": "signup",
            "username": username,
            "password": password,
            "enc_public_pem": keys.enc_public_pem(),
            "sign_public_pem": keys.sign_public_pem(),
        })
        if not resp["ok"]:
            raise ClientError(resp["error"])
        # Only after the server accepted the name do we write the key file.
        self._write_json(username, "keys.json", keys.to_encrypted_file(password))
        self.trace("PROTECT KEYS", f"private keys saved encrypted (scrypt + AES-256-GCM) in {self._path(username, 'keys.json')}")
        self._start_session(username, keys)

    def login(self, username: str, password: str) -> None:
        resp = self.conn.request({"action": "login", "username": username, "password": password})
        if not resp["ok"]:
            raise ClientError(resp["error"])
        keyfile = self._read_json(username, "keys.json", None)
        if keyfile is None:
            self.conn.request({"action": "logout"})
            raise ClientError(f"No key file for '{username}' in {self.data_dir}; this device cannot read their messages.")
        try:
            keys = UserKeys.from_encrypted_file(keyfile, password)
        except KeyFileError as exc:
            self.conn.request({"action": "logout"})
            raise ClientError(str(exc)) from None
        self._start_session(username, keys)

    def _start_session(self, username, keys):
        self.username, self.keys = username, keys
        self.seen_ids = set(self._read_json(username, "seen_ids.json", []))

    def logout(self) -> None:
        self.conn.request({"action": "logout"})
        self.username, self.keys, self.seen_ids = None, None, set()

    def close(self) -> None:
        self.conn.close()

    def _require_login(self):
        if self.username is None:
            raise ClientError("Please log in first.")

    # ------------------------------------------------------------ directory

    def users(self, include_self: bool = False) -> list[dict]:
        """Fetch users and public keys, pinning each user's keys the first time we see them.

        If the server later hands out DIFFERENT keys for a known user, that
        could be the server trying to impersonate them, so we refuse.
        """
        self._require_login()
        resp = self.conn.request({"action": "users", "include_self": include_self})
        if not resp["ok"]:
            raise ClientError(resp["error"])
        known = self._read_json(self.username, "known_keys.json", {})
        changed = False
        for u in resp["users"]:
            fp = fingerprint(u["enc_public_pem"], u["sign_public_pem"])
            u["fingerprint"] = fp
            pinned = known.get(u["username"])
            if pinned is None:
                known[u["username"]] = {"enc_public_pem": u["enc_public_pem"], "sign_public_pem": u["sign_public_pem"]}
                changed = True
                u["key_status"] = "new (pinned now)"
            elif pinned["enc_public_pem"] != u["enc_public_pem"] or pinned["sign_public_pem"] != u["sign_public_pem"]:
                u["key_status"] = "CHANGED - not trusted"
            else:
                u["key_status"] = "matches pinned key"
        if changed:
            self._write_json(self.username, "known_keys.json", known)
        return resp["users"]

    def _trusted_keys(self, username: str) -> dict:
        """Public keys for `username`, but only if they match the pinned copy."""
        for u in self.users(include_self=True):
            if u["username"] == username:
                if u["key_status"].startswith("CHANGED"):
                    raise ClientError(
                        f"WARNING: the server now reports different keys for '{username}'. "
                        "Refusing to use them. Verify the fingerprint with them in person."
                    )
                return u
        raise ClientError(f"Unknown user '{username}'.")

    # ------------------------------------------------------------ messages

    def build_package(self, recipient: str, text: str) -> dict:
        """Encrypt and sign, but do not send (lets demos inspect or tamper with the package)."""
        self._require_login()
        if recipient == self.username:
            raise ClientError("You cannot send a message to yourself.")
        r = self._trusted_keys(recipient)
        self.trace("READ", f"plaintext from {self.username} to {recipient}: {text!r}")
        return encrypt_and_sign(text, self.username, recipient, self.keys, r["enc_public_pem"], trace=self.trace)

    def send_package(self, package: dict) -> str:
        self._require_login()
        self.trace("TRANSMIT", f"sending package {package['msg_id']} to the server over the socket")
        resp = self.conn.request({"action": "send", "package": package})
        if not resp["ok"]:
            raise ClientError(resp["error"])
        return resp["msg_id"]

    def send(self, recipient: str, text: str) -> str:
        return self.send_package(self.build_package(recipient, text))

    def fetch_inbox(self) -> list[dict]:
        """Raw packages from the server (still encrypted)."""
        self._require_login()
        resp = self.conn.request({"action": "inbox"})
        if not resp["ok"]:
            raise ClientError(resp["error"])
        return resp["messages"]

    def open_package(self, package: dict) -> dict:
        """Verify and decrypt one package. Never raises for a bad message;
        returns {"ok": False, "reason": ...} so one bad message cannot hide the rest."""
        sender = package.get("sender", "?") if isinstance(package, dict) else "?"
        result = {"msg_id": package.get("msg_id") if isinstance(package, dict) else None,
                  "sender": sender, "timestamp": package.get("timestamp") if isinstance(package, dict) else None}
        try:
            sender_keys = self._trusted_keys(sender)
            self.trace("RECEIVE", f"package {result['msg_id']} claims to be from {sender}")
            text = verify_and_decrypt(
                package, self.username, self.keys, sender_keys["sign_public_pem"],
                seen_ids=self.seen_ids, trace=self.trace,
            )
        except (MessageRejected, ClientError) as exc:
            result.update(ok=False, reason=getattr(exc, "reason", str(exc)))
            return result
        self._write_json(self.username, "seen_ids.json", sorted(self.seen_ids))
        result.update(ok=True, text=text)
        return result

    def inbox(self) -> list[dict]:
        return [self.open_package(p) for p in self.fetch_inbox()]
