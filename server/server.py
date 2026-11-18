"""The relay server.

What it does:
  * signup / login with salted, slow password hashes (scrypt)
  * hands out the list of users and their PUBLIC keys
  * accepts sealed message packages, stores them exactly as received,
    and delivers them when the recipient asks for their inbox

What it never does:
  * hold any private key
  * decrypt anything (it has no key that could)
  * store or log a plaintext password

Protocol: TCP, one JSON object per line (UTF-8, terminated by "\\n").
See README.md, section "Protocol".

Run:  py -m server.server --port 5050
"""

import argparse
import json
import logging
import re
import socketserver
import threading
import time

from crypto_utils.passwords import DUMMY_RECORD, hash_password, verify_password

from .storage import Storage

log = logging.getLogger("server")
log.addHandler(logging.NullHandler())  # silent unless main() configures logging

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
MIN_PASSWORD_LEN = 8
MAX_LINE = 1_000_000          # bytes; a request bigger than this is refused
MAX_CLOCK_SKEW = 300          # seconds; package timestamps must be within this of server time
GENERIC_LOGIN_ERROR = "Invalid username or password."  # same text for every login failure


class RequestHandler(socketserver.StreamRequestHandler):
    """One instance per TCP connection. A connection is one client session."""

    def setup(self):
        super().setup()
        self.user = None  # set after a successful login/signup

    def handle(self):
        peer = "%s:%s" % self.client_address
        log.info("connection from %s", peer)
        while True:
            line = self.rfile.readline(MAX_LINE + 1)
            if not line:
                break  # client closed the connection
            if len(line) > MAX_LINE:
                self._reply({"ok": False, "error": "Request too large."})
                break
            try:
                request = json.loads(line.decode("utf-8"))
                if not isinstance(request, dict):
                    raise ValueError
            except ValueError:
                self._reply({"ok": False, "error": "Request must be one JSON object per line."})
                continue
            self._reply(self.server.app.dispatch(self, request))
        log.info("connection from %s closed", peer)

    def _reply(self, obj: dict) -> None:
        self.wfile.write(json.dumps(obj).encode("utf-8") + b"\n")
        self.wfile.flush()


class ChatApp:
    """The server's logic, separate from the networking so it is easy to read and test."""

    def __init__(self, db_path: str):
        self.db = Storage(db_path)

    def dispatch(self, conn: RequestHandler, req: dict) -> dict:
        action = req.get("action")
        handlers = {
            "signup": self.signup,
            "login": self.login,
            "users": self.users,
            "send": self.send,
            "inbox": self.inbox,
            "logout": self.logout,
        }
        if action not in handlers:
            return {"ok": False, "error": f"Unknown action {action!r}."}
        if action in ("users", "send", "inbox") and conn.user is None:
            return {"ok": False, "error": "Please log in first."}
        try:
            return handlers[action](conn, req)
        except (KeyError, TypeError, ValueError) as exc:
            return {"ok": False, "error": f"Bad request ({exc.__class__.__name__})."}

    # ------------------------------------------------------------ accounts

    def signup(self, conn, req):
        username, password = req["username"], req["password"]
        enc_pem, sign_pem = req["enc_public_pem"], req["sign_public_pem"]
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            return {"ok": False, "error": "Username must be 3-20 characters: a-z, 0-9, _."}
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
            return {"ok": False, "error": f"Password must be at least {MIN_PASSWORD_LEN} characters."}
        if "BEGIN PUBLIC KEY" not in enc_pem or "BEGIN PUBLIC KEY" not in sign_pem:
            return {"ok": False, "error": "Public keys must be PEM encoded."}

        record = hash_password(password)  # slow; done outside the lock
        with self.db.lock:
            if username in self.db.data["users"]:
                return {"ok": False, "error": "That username is taken."}
            self.db.data["users"][username] = {
                "password": record,  # salt + scrypt hash only
                "enc_public_pem": enc_pem,
                "sign_public_pem": sign_pem,
                "created": int(time.time()),
            }
            self.db.save()
        conn.user = username
        log.info("signup: %s", username)  # note: never log the password
        return {"ok": True, "username": username}

    def login(self, conn, req):
        username, password = req["username"], req["password"]
        if not isinstance(username, str) or not isinstance(password, str):
            return {"ok": False, "error": GENERIC_LOGIN_ERROR}
        with self.db.lock:
            user = self.db.data["users"].get(username)
        # Always run scrypt once, even for unknown users, so the reply time
        # does not reveal whether the username exists.
        record = user["password"] if user else DUMMY_RECORD
        password_ok = verify_password(password, record)
        if user is None or not password_ok:
            log.info("login failed for %r", username)
            # One message for "no such user" and "wrong password".
            return {"ok": False, "error": GENERIC_LOGIN_ERROR}
        conn.user = username
        log.info("login: %s", username)
        return {"ok": True, "username": username}

    def logout(self, conn, req):
        conn.user = None
        return {"ok": True}

    # ------------------------------------------------------------ directory

    def users(self, conn, req):
        """Everyone except the caller, with their public keys."""
        with self.db.lock:
            listing = [
                {"username": name, "enc_public_pem": u["enc_public_pem"], "sign_public_pem": u["sign_public_pem"]}
                for name, u in sorted(self.db.data["users"].items())
            ]
        if req.get("include_self"):
            return {"ok": True, "users": listing}
        return {"ok": True, "users": [u for u in listing if u["username"] != conn.user]}

    # ------------------------------------------------------------ messages

    def send(self, conn, req):
        """Accept a sealed package. The server checks the envelope, never the contents."""
        pkg = req["package"]
        if not isinstance(pkg, dict):
            raise TypeError
        required = ("version", "msg_id", "sender", "recipient", "timestamp",
                    "nonce", "ciphertext", "wrapped_key", "signature")
        missing = [f for f in required if f not in pkg]
        if missing:
            return {"ok": False, "error": f"Package is missing fields: {', '.join(missing)}."}

        # The logged-in user may only send as themselves. (Recipients still
        # verify the signature: they must not have to trust the server.)
        if pkg["sender"] != conn.user:
            log.warning("rejected: %s tried to send as %r", conn.user, pkg["sender"])
            return {"ok": False, "error": "Sender does not match the logged-in user."}
        if not isinstance(pkg["timestamp"], int) or abs(time.time() - pkg["timestamp"]) > MAX_CLOCK_SKEW:
            return {"ok": False, "error": "Timestamp is too old or too far in the future."}

        with self.db.lock:
            if pkg["recipient"] not in self.db.data["users"]:
                return {"ok": False, "error": "Unknown recipient."}
            # Replay protection: each message ID is accepted exactly once.
            if pkg["msg_id"] in self.db.seen:
                log.warning("rejected replay of message %s", pkg["msg_id"])
                return {"ok": False, "error": f"Duplicate message ID {pkg['msg_id']}: replay rejected."}
            self.db.seen.add(pkg["msg_id"])
            self.db.data["seen_msg_ids"].append(pkg["msg_id"])
            # Stored exactly as received: still encrypted, still signed.
            self.db.data["messages"].append({"package": pkg, "received_at": int(time.time()), "delivered": False})
            self.db.save()
        log.info("stored message %s from %s to %s (%d bytes of ciphertext, base64)",
                 pkg["msg_id"], pkg["sender"], pkg["recipient"], len(pkg["ciphertext"]))
        return {"ok": True, "msg_id": pkg["msg_id"]}

    def inbox(self, conn, req):
        """Forward every undelivered package addressed to the caller."""
        with self.db.lock:
            out = []
            for entry in self.db.data["messages"]:
                if entry["package"]["recipient"] == conn.user and not entry["delivered"]:
                    out.append(entry["package"])
                    entry["delivered"] = True
            if out:
                self.db.save()
        return {"ok": True, "messages": out}


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, app: ChatApp):
        self.app = app
        super().__init__(address, RequestHandler)


def start_in_background(host: str, port: int, db_path: str) -> ThreadedServer:
    """Start a server on a background thread (used by tests and the demo). Port 0 = pick a free port."""
    srv = ThreadedServer((host, port), ChatApp(db_path))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    parser = argparse.ArgumentParser(description="Secure chat relay server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--db", default="server_data/db.json", help="path of the JSON database")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [server] %(message)s")
    with ThreadedServer((args.host, args.port), ChatApp(args.db)) as srv:
        log.info("listening on %s:%d, database %s", args.host, args.port, args.db)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log.info("shutting down")


if __name__ == "__main__":
    main()
