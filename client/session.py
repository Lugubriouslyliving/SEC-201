"""Client-side logic: keys on disk, talking to the server, sealing and opening messages.

Local files, per user, under the client's data folder (default ./client_data):

    <user>/keys.json        both private keys, encrypted with a password-derived key
    <user>/seen_ids.json    message IDs already accepted (replay detection)
    <user>/known_keys.json  public keys seen for each contact (key pinning)
"""

import json
import os
import re
import sys
import threading
import time
import unicodedata

from crypto_utils.keys import KeyFileError, UserKeys, fingerprint
from crypto_utils.messages import MessageRejected, encrypt_and_sign, verify_and_decrypt
from crypto_utils.passwords import client_password_hash

from .connection import DEFAULT_CA_FILE, Connection

# Same rules the server enforces; checked here first so a typo is reported
# instantly instead of after generating keys.
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 1024
# About 10 pages of text. Keeps every package far below the server's 1 MB
# request limit even for 3-byte characters (Thai, Chinese) after base64.
MAX_MESSAGE_CHARS = 20_000


class ClientError(Exception):
    pass


def _no_trace(step, detail=""):
    pass


def _stderr_notice(text):
    print(f"Notice: {text}", file=sys.stderr)


_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def safe_display(text) -> str:
    """Make received text safe to print in a terminal.

    Message text comes from other people. Printed raw, a newline would let
    a sender fake a whole extra line ("[12:00] bob: ...") and escape codes
    (ESC [ ...) could clear the screen or recolour text. So invisible control
    and formatting characters are shown as visible escapes like \\n or \\x1b.
    Ordinary text in any language, including emoji, is left alone.
    """
    out = []
    for ch in str(text):
        if ch in "‌‍":  # zero-width (non-)joiners: needed by emoji sequences and some scripts
            out.append(ch)
        elif unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs"):
            out.append(_ESCAPES.get(ch) or (f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}"))
        else:
            out.append(ch)
    return "".join(out)


class ChatClient:
    def __init__(self, host: str, port: int, data_dir: str = "client_data", trace=_no_trace, notice=_stderr_notice,
                 ca_file: str = DEFAULT_CA_FILE):
        self.host, self.port = host, port
        self.data_dir = data_dir
        self.trace = trace
        self.notice = notice
        self.conn = Connection(host, port, ca_file)
        self.username: str | None = None
        self.keys: UserKeys | None = None
        self.seen_ids: set[str] = set()
        self.file_lock = threading.Lock()  # chat mode writes files from two threads

    # ------------------------------------------------------------ files

    def _path(self, username: str, name: str) -> str:
        return os.path.join(self.data_dir, username, name)

    def _read_json(self, username, name, default, expect_type):
        """Read a local JSON file. A damaged file is moved aside (not deleted) and
        `default` is used, so one bad file cannot lock you out of chatting."""
        path = self._path(username, name)
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, expect_type):
                raise ValueError("unexpected content")
            return data
        except (OSError, ValueError) as exc:
            backup = f"{path}.damaged-{int(time.time())}"
            try:
                os.replace(path, backup)
            except OSError:
                backup = "(could not move it)"
            self.notice(f"{name} was damaged ({exc.__class__.__name__}); starting a fresh one. Old copy: {backup}")
            return default

    def _write_json(self, username, name, data):
        """Write to a temporary file, then rename over the old one, so a crash or a
        second thread never leaves a half-written file."""
        path = self._path(username, name)
        with self.file_lock:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = f"{path}.tmp-{threading.get_ident()}"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)

    def _request(self, payload: dict) -> dict:
        resp = self.conn.request(payload)
        if not resp["ok"]:
            raise ClientError(str(resp.get("error", "The server refused the request."))[:300])
        return resp

    # ------------------------------------------------------------ accounts

    def signup(self, username: str, password: str) -> None:
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            raise ClientError("Username must be 3-20 characters using only a-z, 0-9 and _ (lowercase).")
        if not MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN:
            raise ClientError(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.")
        if os.path.exists(self._path(username, "keys.json")):
            raise ClientError(f"A key file for '{username}' already exists in {self.data_dir}. Use login instead.")
        self.trace("KEYGEN", "generating RSA-3072 (encryption) and Ed25519 (signing) key pairs locally")
        keys = UserKeys.generate()
        login_hash = self._hash_password(username, password)
        self._request({
            "action": "signup",
            "username": username,
            "password_hash": login_hash,
            "enc_public_pem": keys.enc_public_pem(),
            "sign_public_pem": keys.sign_public_pem(),
        })
        # Only after the server accepted the name do we write the key file.
        self._write_json(username, "keys.json", keys.to_encrypted_file(password))
        self.trace("PROTECT KEYS", f"private keys saved encrypted (scrypt + AES-256-GCM) in {self._path(username, 'keys.json')}")
        self._start_session(username, keys)

    def _hash_password(self, username: str, password: str) -> str:
        login_hash = client_password_hash(username, password)
        self.trace("HASH PASSWORD",
                   f"scrypt(password, salt = SHA-256(username)) -> {login_hash[:16]}...\n"
                   "only this hash is sent; the password itself never leaves this computer")
        return login_hash

    def login(self, username: str, password: str) -> None:
        # A name that cannot exist is refused here, without contacting the
        # server, so text typed into the wrong box is not sent anywhere.
        if not isinstance(username, str) or not USERNAME_RE.match(username) or len(password) > MAX_PASSWORD_LEN:
            raise ClientError("Invalid username or password.")
        self._request({"action": "login", "username": username,
                       "password_hash": self._hash_password(username, password)})
        # The server said yes, so `username` is a real, validated name: safe to use in a path.
        path = self._path(username, "keys.json")
        if not os.path.exists(path):
            self.conn.request({"action": "logout"})
            raise ClientError(f"No key file for '{username}' in {self.data_dir}; this device cannot read their messages.")
        try:
            with open(path, "r", encoding="utf-8") as f:
                keys = UserKeys.from_encrypted_file(json.load(f), password)
        except KeyFileError as exc:
            self.conn.request({"action": "logout"})
            raise ClientError(str(exc)) from None
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.conn.request({"action": "logout"})
            raise ClientError(f"The key file {path} is damaged ({exc.__class__.__name__}). "
                              "Restore it from a backup; without it this account's messages cannot be read.") from None
        self._start_session(username, keys)

    def _start_session(self, username, keys):
        self.username, self.keys = username, keys
        ids = self._read_json(username, "seen_ids.json", [], list)
        self.seen_ids = {i for i in ids if isinstance(i, str)}

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
        resp = self._request({"action": "users", "include_self": include_self})
        listing = resp.get("users")
        if not isinstance(listing, list):
            raise ClientError("The server sent an invalid user list.")
        with self.file_lock:
            known = self._read_json(self.username, "known_keys.json", {}, dict)
        changed = False
        out = []
        for u in listing:
            # Ignore anything that is not a well-formed entry rather than crash on it.
            if not isinstance(u, dict) or not all(isinstance(u.get(k), str)
                                                  for k in ("username", "enc_public_pem", "sign_public_pem")):
                continue
            u = {k: u[k] for k in ("username", "enc_public_pem", "sign_public_pem")}
            u["fingerprint"] = fingerprint(u["enc_public_pem"], u["sign_public_pem"])
            pinned = known.get(u["username"])
            if not isinstance(pinned, dict):
                known[u["username"]] = {"enc_public_pem": u["enc_public_pem"], "sign_public_pem": u["sign_public_pem"]}
                changed = True
                u["key_status"] = "new (pinned now)"
            elif pinned.get("enc_public_pem") != u["enc_public_pem"] or pinned.get("sign_public_pem") != u["sign_public_pem"]:
                u["key_status"] = "CHANGED - not trusted"
            else:
                u["key_status"] = "matches pinned key"
            out.append(u)
        if changed:
            self._write_json(self.username, "known_keys.json", known)
        return out

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
        raise ClientError(f"Unknown user '{safe_display(username)[:40]}'.")

    # ------------------------------------------------------------ messages

    def build_package(self, recipient: str, text: str) -> dict:
        """Encrypt and sign, but do not send (lets demos inspect or tamper with the package)."""
        self._require_login()
        if recipient == self.username:
            raise ClientError("You cannot send a message to yourself.")
        if len(text) > MAX_MESSAGE_CHARS:
            raise ClientError(f"Message too long ({len(text)} characters; the limit is {MAX_MESSAGE_CHARS}).")
        r = self._trusted_keys(recipient)
        self.trace("READ", f"plaintext from {self.username} to {recipient}: {text!r}")
        try:
            return encrypt_and_sign(text, self.username, recipient, self.keys, r["enc_public_pem"], trace=self.trace)
        except ValueError:
            raise ClientError(f"'{recipient}' has an unusable public key; cannot encrypt to them.") from None

    def send_package(self, package: dict) -> str:
        self._require_login()
        self.trace("TRANSMIT", f"sending package {package['msg_id']} to the server over the socket")
        return self._request({"action": "send", "package": package})["msg_id"]

    def send(self, recipient: str, text: str) -> str:
        return self.send_package(self.build_package(recipient, text))

    def fetch_inbox(self) -> list:
        """Raw packages from the server (still encrypted)."""
        self._require_login()
        messages = self._request({"action": "inbox"}).get("messages")
        if not isinstance(messages, list):
            raise ClientError("The server sent an invalid inbox.")
        return messages

    def open_package(self, package) -> dict:
        """Verify and decrypt one package. Never raises for a bad message;
        returns {"ok": False, "reason": ...} so one bad message cannot hide the rest."""
        is_dict = isinstance(package, dict)
        sender = package.get("sender") if is_dict else None
        sender = sender if isinstance(sender, str) else "?"
        ts = package.get("timestamp") if is_dict else None
        result = {"msg_id": package.get("msg_id") if is_dict else None,
                  "sender": sender, "timestamp": ts if type(ts) is int and 0 < ts < 2**40 else None}
        try:
            if not is_dict:
                raise MessageRejected("malformed package (not an object)")
            sender_keys = self._trusted_keys(sender)
            self.trace("RECEIVE", f"package {result['msg_id']} claims to be from {sender}")
            text = verify_and_decrypt(
                package, self.username, self.keys, sender_keys["sign_public_pem"],
                seen_ids=self.seen_ids, trace=self.trace,
            )
        except (MessageRejected, ClientError) as exc:
            result.update(ok=False, reason=getattr(exc, "reason", str(exc)))
            return result
        except Exception as exc:  # last line of defence: never let one message crash the inbox
            result.update(ok=False, reason=f"unreadable package ({exc.__class__.__name__})")
            return result
        self._write_json(self.username, "seen_ids.json", sorted(self.seen_ids))
        result.update(ok=True, text=text)
        return result

    def inbox(self) -> list[dict]:
        return [self.open_package(p) for p in self.fetch_inbox()]
