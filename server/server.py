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

Protocol: TLS 1.3 over TCP, one JSON object per line (UTF-8, terminated
by "\\n"). See README.md, section "Protocol". On first start the server
creates its TLS certificates in server_data/tls (see crypto_utils/tls.py);
clients need a copy of server_data/tls/ca.crt.

Robustness rule: whatever a client sends, the server answers with an error
and keeps running. One bad request never affects other users.

Run:  py -m server.server --port 5050
"""

import argparse
import json
import logging
import os
import re
import socket
import socketserver
import ssl
import sys
import threading
import time

from crypto_utils.keys import load_enc_public, load_sign_public
from crypto_utils.passwords import DUMMY_RECORD, hash_password, is_login_hash, verify_password
from crypto_utils.tls import DEFAULT_HOSTNAMES, certificate_fingerprint, ensure_server_tls, server_context

from .privacy import PRIVACY_NOTICE, PRIVACY_NOTICE_VERSION, RETENTION_DAYS, Pseudonymizer, purge_expired
from .storage import Storage

log = logging.getLogger("server")
log.addHandler(logging.NullHandler())  # silent unless main() configures logging

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
MAX_LINE = 1_000_000          # bytes; a request bigger than this is refused
MSG_ID_RE = re.compile(r"[0-9a-f]{32}")  # exactly what uuid4().hex produces; nothing else is accepted
MIN_RSA_BITS = 2048
MAX_CLOCK_SKEW = 300          # seconds; package timestamps must be within this of server time
HANDSHAKE_TIMEOUT = 15        # seconds a new connection gets to complete the TLS handshake
GENERIC_LOGIN_ERROR = "Invalid username or password."  # same text for every login failure

# scrypt needs ~32 MiB per computation. Without a limit, 1,000 simultaneous
# logins would ask for ~32 GiB. At most this many run at once; the rest wait.
SCRYPT_SLOTS = threading.BoundedSemaphore(4)

PACKAGE_STRING_FIELDS = ("msg_id", "sender", "recipient", "nonce", "ciphertext", "wrapped_key", "signature")


class RequestHandler(socketserver.StreamRequestHandler):
    """One instance per TCP connection. A connection is one client session."""

    def setup(self):
        # TLS handshake first, in this connection's own thread, with a time
        # limit, so a slow or non-TLS client cannot hold up anyone else. If it
        # fails (plain-text client, wrong protocol, someone probing the port)
        # the connection is simply dropped.
        self.request.settimeout(HANDSHAKE_TIMEOUT)
        self.request.do_handshake()
        self.request.settimeout(None)  # a logged-in user may sit idle at the prompt
        super().setup()  # (this is what sets self.connection = self.request)
        self.user = None  # set after a successful login/signup
        self.server.track(self.connection)

    def finish(self):
        self.server.untrack(self.connection)
        try:
            super().finish()
        except OSError:
            pass  # client already gone

    def handle(self):
        peer = self.server.app.pseudo.ip(self.client_address[0])  # never log the real IP address
        log.info("connection from %s", peer)
        try:
            self._serve()
        except OSError:
            pass  # the client vanished mid-request (closed window, network drop): nothing to do
        log.info("connection from %s closed", peer)

    def _serve(self):
        while True:
            line = self.rfile.readline(MAX_LINE + 1)
            if not line:
                return  # client closed the connection
            if len(line) > MAX_LINE:
                self._reply({"ok": False, "error": "Request too large."})
                return  # the rest of the oversized line is unreadable; end the session
            if not line.strip():
                self._reply({"ok": False, "error": "Empty request."})
                continue
            try:
                request = json.loads(line.decode("utf-8"))
                if not isinstance(request, dict):
                    raise ValueError
            except (ValueError, RecursionError):  # bad UTF-8, bad JSON, absurd nesting
                self._reply({"ok": False, "error": "Request must be one JSON object per line."})
                continue
            self._reply(self.server.app.dispatch(self, request))

    def _reply(self, obj: dict) -> None:
        self.wfile.write(json.dumps(obj).encode("utf-8") + b"\n")
        self.wfile.flush()


class ChatApp:
    """The server's logic, separate from the networking so it is easy to read and test."""

    def __init__(self, db_path: str):
        self.db = Storage(db_path)
        # The secret key for log pseudonyms lives next to the database, never in the log.
        self.pseudo = Pseudonymizer(os.path.join(os.path.dirname(os.path.abspath(db_path)), "privacy", "log_key"))
        with self.db.lock:  # apply the retention rule to whatever is already stored
            if purge_expired(self.db.data):
                self.db.save()

    def dispatch(self, conn: RequestHandler, req: dict) -> dict:
        action = req.get("action")
        handlers = {
            "privacy_notice": self.privacy_notice,
            "signup": self.signup,
            "login": self.login,
            "users": self.users,
            "send": self.send,
            "inbox": self.inbox,
            "mydata": self.mydata,
            "delete_account": self.delete_account,
            "logout": self.logout,
        }
        if not isinstance(action, str) or action not in handlers:
            return {"ok": False, "error": "Unknown action."}
        if action in ("users", "send", "inbox", "mydata", "delete_account") and conn.user is None:
            return {"ok": False, "error": "Please log in first."}
        try:
            return handlers[action](conn, req)
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            return {"ok": False, "error": f"Bad request ({exc.__class__.__name__})."}
        except Exception:  # a bug in the server: log it, keep running
            log.exception("unexpected error handling %r", action)
            return {"ok": False, "error": "Internal server error."}

    # ------------------------------------------------------------ accounts

    def signup(self, conn, req):
        # The client never sends the password itself, only its login hash
        # (see crypto_utils/passwords.py). Password rules such as minimum
        # length are therefore checked by the client.
        username, login_hash = req["username"], req["password_hash"]
        enc_pem, sign_pem = req["enc_public_pem"], req["sign_public_pem"]
        if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):  # fullmatch: no trailing "\n"
            return {"ok": False, "error": "Username must be 3-20 characters: a-z, 0-9, _."}
        if not is_login_hash(login_hash):
            return {"ok": False, "error": "password_hash must be the client's 32-byte login hash (base64)."}
        # Check the public keys are real keys of the right type. Otherwise a
        # user could register junk that breaks everyone who tries to message them.
        try:
            if not isinstance(enc_pem, str) or not isinstance(sign_pem, str):
                raise ValueError
            if load_enc_public(enc_pem).key_size < MIN_RSA_BITS:
                raise ValueError
            load_sign_public(sign_pem)
        except Exception:
            return {"ok": False, "error": "Public keys must be a PEM RSA key (2048+ bits) and a PEM Ed25519 key."}
        # PDPA s.19/s.23: the user must have seen and accepted the current privacy notice.
        if req.get("consent_version") != PRIVACY_NOTICE_VERSION:
            return {"ok": False, "error": "You must accept the current privacy notice to sign up."}

        with SCRYPT_SLOTS:
            record = hash_password(login_hash)  # salted again with a random salt; slow, so outside the lock
        with self.db.lock:
            if username in self.db.data["users"]:
                return {"ok": False, "error": "That username is taken."}
            self.db.data["users"][username] = {
                "password": record,  # scrypt(login hash, random salt) only
                "enc_public_pem": enc_pem,
                "sign_public_pem": sign_pem,
                "created": int(time.time()),
                "consent": {"notice_version": PRIVACY_NOTICE_VERSION, "accepted_at": int(time.time())},
            }
            self.db.save()
        conn.user = username
        log.info("signup: %s", self.pseudo.user(username))
        return {"ok": True, "username": username}

    def login(self, conn, req):
        username, login_hash = req["username"], req["password_hash"]
        if not isinstance(username, str) or not is_login_hash(login_hash):
            return {"ok": False, "error": GENERIC_LOGIN_ERROR}
        with self.db.lock:
            user = self.db.data["users"].get(username)
        # Always run scrypt once, even for unknown users, so the reply time
        # does not reveal whether the username exists.
        record = user["password"] if user else DUMMY_RECORD
        with SCRYPT_SLOTS:
            password_ok = verify_password(login_hash, record)
        if user is None or not password_ok:
            # Deliberately NOT logged: a failed login's "username" is whatever was
            # typed, and people sometimes type their password into that box.
            # One message for "no such user" and "wrong password".
            return {"ok": False, "error": GENERIC_LOGIN_ERROR}
        conn.user = username
        log.info("login: %s", self.pseudo.user(username))
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
        if req.get("include_self") is True:
            return {"ok": True, "users": listing}
        return {"ok": True, "users": [u for u in listing if u["username"] != conn.user]}

    # ------------------------------------------------------------ messages

    def send(self, conn, req):
        """Accept a sealed package. The server checks the envelope, never the contents."""
        pkg = req["package"]
        if not isinstance(pkg, dict):
            return {"ok": False, "error": "Package must be a JSON object."}
        required = ("version", "timestamp") + PACKAGE_STRING_FIELDS
        missing = [f for f in required if f not in pkg]
        if missing:
            return {"ok": False, "error": f"Package is missing fields: {', '.join(missing)}."}
        if not all(isinstance(pkg[f], str) for f in PACKAGE_STRING_FIELDS):
            return {"ok": False, "error": "Package fields have the wrong type."}
        if not MSG_ID_RE.fullmatch(pkg["msg_id"]):  # so an ID can never carry newlines or escape codes
            return {"ok": False, "error": "Invalid message ID (must be 32 lowercase hex characters)."}

        # The logged-in user may only send as themselves. (Recipients still
        # verify the signature: they must not have to trust the server.)
        if pkg["sender"] != conn.user:
            log.warning("rejected: %s tried to send as someone else", self.pseudo.user(conn.user))
            return {"ok": False, "error": "Sender does not match the logged-in user."}
        ts = pkg["timestamp"]
        # `type(...) is int` excludes True/False; the range check comes before any
        # arithmetic so an enormous number cannot cause an overflow.
        if type(ts) is not int or not 0 < ts < 2**40 or abs(time.time() - ts) > MAX_CLOCK_SKEW:
            return {"ok": False, "error": "Message timestamp is more than 5 minutes away from the server's "
                                          "time. Check that your computer's clock is correct."}

        with self.db.lock:
            if pkg["recipient"] not in self.db.data["users"]:
                return {"ok": False, "error": "Unknown recipient."}
            # Replay protection: each message ID is accepted exactly once.
            if pkg["msg_id"] in self.db.seen:
                log.warning("rejected replay of message %s", pkg["msg_id"])
                return {"ok": False, "error": f"Duplicate message ID {pkg['msg_id']}: replay rejected."}
            self.db.seen.add(pkg["msg_id"])
            self.db.data["seen_msg_ids"].append(pkg["msg_id"])
            purge_expired(self.db.data)  # retention: drop anything past its time before adding more
            # Stored exactly as received: still encrypted, still signed.
            self.db.data["messages"].append({"package": pkg, "received_at": int(time.time()), "delivered": False})
            self.db.save()
        log.info("stored message %s from %s to %s (%d bytes of ciphertext, base64)", pkg["msg_id"],
                 self.pseudo.user(pkg["sender"]), self.pseudo.user(pkg["recipient"]), len(pkg["ciphertext"]))
        return {"ok": True, "msg_id": pkg["msg_id"]}

    def inbox(self, conn, req):
        """Forward every undelivered package addressed to the caller."""
        with self.db.lock:
            out = []
            for entry in self.db.data["messages"]:
                pkg = entry.get("package") if isinstance(entry, dict) else None
                # Skip anything malformed (e.g. a hand-edited database) instead of failing the whole inbox.
                if not isinstance(pkg, dict) or pkg.get("recipient") != conn.user or entry.get("delivered"):
                    continue
                out.append(pkg)
                entry["delivered"] = True
            if out:
                purge_expired(self.db.data)  # retention: delivered packages are deleted right away
                self.db.save()
        return {"ok": True, "messages": out}

    # ------------------------------------------------------------ privacy rights (PDPA)

    def privacy_notice(self, conn, req):
        """PDPA s.23: tell people what is collected and why, before they sign up."""
        return {"ok": True, "version": PRIVACY_NOTICE_VERSION, "text": PRIVACY_NOTICE}

    def mydata(self, conn, req):
        """PDPA s.30 (access) and s.31 (portability): everything stored about the caller, as JSON."""
        with self.db.lock:
            u = self.db.data["users"][conn.user]
            waiting_for_me = sum(1 for e in self.db.data["messages"] if _party(e, "recipient") == conn.user)
            sent_waiting = sum(1 for e in self.db.data["messages"] if _party(e, "sender") == conn.user)
            record = {
                "username": conn.user,
                "created": u["created"],
                "consent": u.get("consent"),
                "enc_public_pem": u["enc_public_pem"],
                "sign_public_pem": u["sign_public_pem"],
                "password": "stored only as scrypt(login hash, random salt); not shown so a stolen session cannot take it",
                "messages_waiting_for_you": waiting_for_me,
                "messages_you_sent_still_waiting": sent_waiting,
                "retention": f"delivered messages are deleted at once; undelivered ones after {RETENTION_DAYS} days",
                "log_pseudonym": self.pseudo.user(conn.user),
            }
        return {"ok": True, "data": record}

    def delete_account(self, conn, req):
        """PDPA s.33 (erasure): remove the account and every message to or from it.
        The password is asked again, so someone at an unlocked screen cannot do it."""
        login_hash = req["password_hash"]
        with self.db.lock:
            user = self.db.data["users"].get(conn.user)
        with SCRYPT_SLOTS:
            ok = user is not None and is_login_hash(login_hash) and verify_password(login_hash, user["password"])
        if not ok:
            return {"ok": False, "error": GENERIC_LOGIN_ERROR}
        name = conn.user
        with self.db.lock:
            del self.db.data["users"][name]
            self.db.data["messages"] = [e for e in self.db.data["messages"]
                                        if name not in (_party(e, "sender"), _party(e, "recipient"))]
            self.db.save()
        conn.user = None
        log.info("account deleted: %s", self.pseudo.user(name))
        return {"ok": True}


def _party(entry, field):
    """The sender or recipient of a stored message entry, or None if the entry is malformed."""
    pkg = entry.get("package") if isinstance(entry, dict) else None
    return pkg.get(field) if isinstance(pkg, dict) else None


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, app: ChatApp, tls_context: ssl.SSLContext):
        self.app = app
        self.tls_context = tls_context
        self._connections = set()
        self._conn_lock = threading.Lock()
        super().__init__(address, RequestHandler)

    def get_request(self):
        """Every accepted connection is wrapped in TLS before anything is read from it.
        The handshake itself runs later, in the connection's thread (see RequestHandler.setup)."""
        sock, addr = self.socket.accept()
        return self.tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address):
        """A connection that fails (e.g. a failed TLS handshake) is closed quietly
        instead of printing a traceback; the server carries on."""
        exc = sys.exc_info()[1]
        peer = self.app.pseudo.ip(client_address[0])  # pseudonym, not the real IP
        if isinstance(exc, (ssl.SSLError, OSError)):
            log.info("dropped connection from %s (%s)", peer, exc.__class__.__name__)
        else:
            log.exception("error on connection from %s", peer)

    def track(self, sock):
        with self._conn_lock:
            self._connections.add(sock)

    def untrack(self, sock):
        with self._conn_lock:
            self._connections.discard(sock)

    def stop(self):
        """Stop accepting, then drop every open session (like the process exiting)."""
        self.shutdown()
        with self._conn_lock:
            for sock in list(self._connections):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.server_close()


def start_in_background(host: str, port: int, db_path: str, tls_dir: str | None = None) -> ThreadedServer:
    """Start a server on a background thread (used by tests and the demo). Port 0 = pick a free port.
    TLS certificates live in `tls_dir` (default: a "tls" folder next to the database);
    clients must trust `server.ca_file`."""
    tls_dir = tls_dir or os.path.join(os.path.dirname(os.path.abspath(db_path)), "tls")
    paths, _ = ensure_server_tls(tls_dir)
    srv = ThreadedServer((host, port), ChatApp(db_path), server_context(paths["cert"], paths["key"]))
    srv.ca_file = paths["ca"]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    parser = argparse.ArgumentParser(description="Secure chat relay server")
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (0.0.0.0 = all networks)")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--db", default="server_data/db.json", help="path of the JSON database")
    parser.add_argument("--tls-dir", default="server_data/tls", help="folder for the TLS certificates")
    parser.add_argument("--hostname", action="append", default=[],
                        help="extra name or IP clients will use to reach this server (repeatable; "
                             "only used when the certificates are first created)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [server] %(message)s")

    names = list(DEFAULT_HOSTNAMES) + args.hostname + ([args.host] if args.host not in ("0.0.0.0", "::") else [])
    paths, created = ensure_server_tls(args.tls_dir, names)
    if created:
        log.info("created TLS certificates in %s for: %s", args.tls_dir, ", ".join(dict.fromkeys(names)))
    log.info("clients must trust %s (fingerprint %s)", paths["ca"], certificate_fingerprint(paths["ca"]))
    try:
        srv = ThreadedServer((args.host, args.port), ChatApp(args.db), server_context(paths["cert"], paths["key"]))
    except ssl.SSLError as exc:
        sys.exit(f"Cannot load the TLS certificate or key in {args.tls_dir} ({exc}). "
                 "Delete that folder to create new ones.")
    except OSError as exc:
        sys.exit(f"Cannot listen on {args.host}:{args.port} ({exc}). "
                 "Is another server already running? Try --port with another number.")
    except ValueError as exc:
        sys.exit(f"Cannot read the database {args.db}: {exc}")
    with srv:
        log.info("listening on %s:%d with TLS 1.3, database %s", args.host, args.port, args.db)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log.info("shutting down")


if __name__ == "__main__":
    main()
