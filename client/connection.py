"""A tiny JSON-lines client for the relay server, over TLS 1.3."""

import json
import os
import socket
import ssl
import threading

from crypto_utils.tls import client_context

DEFAULT_CA_FILE = os.path.join("server_data", "tls", "ca.crt")


class ConnectionError_(Exception):
    """The server cannot be reached or the connection broke. The session is over."""


class Connection:
    """One TLS connection = one session with the server."""

    def __init__(self, host: str, port: int, ca_file: str = DEFAULT_CA_FILE, timeout: float = 30.0):
        if not os.path.exists(ca_file):
            raise ConnectionError_(
                f"Cannot find the server's CA certificate '{ca_file}'. Copy ca.crt from the server's "
                "server_data\\tls folder to this computer and pass it with --ca."
            )
        try:
            context = client_context(ca_file)
        except (ssl.SSLError, OSError) as exc:
            raise ConnectionError_(f"'{ca_file}' is not a valid CA certificate ({exc.__class__.__name__}).") from None
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise ConnectionError_(f"Cannot reach server at {host}:{port} ({exc}).") from None
        try:
            # The handshake checks: TLS 1.3, certificate signed by OUR CA, and
            # issued for `host`. Any failure means we are not talking to our server.
            self.sock = context.wrap_socket(raw, server_hostname=host)
        except ssl.SSLCertVerificationError as exc:
            raw.close()
            raise ConnectionError_(
                f"SECURITY WARNING: the server's certificate is not trusted ({exc.verify_message}). "
                "Someone may be impersonating the server. Not connecting."
            ) from None
        except (ssl.SSLError, OSError) as exc:
            raw.close()
            raise ConnectionError_(f"Could not set up a secure TLS connection to {host}:{port} "
                                   f"({exc.__class__.__name__}). Is this the chat server?") from None
        self.tls_version = self.sock.version()
        self.cipher = self.sock.cipher()[0]
        self.reader = self.sock.makefile("rb")
        # Chat mode checks the inbox on a background thread while the user
        # sends from the main thread; the lock keeps each request paired
        # with its own response.
        self.lock = threading.Lock()
        self.broken = False

    def request(self, payload: dict) -> dict:
        """Send one JSON object, wait for one JSON object back.

        Any network failure (server stopped, Wi-Fi dropped, timeout) or a
        reply that is not a JSON object becomes ConnectionError_, so callers
        handle one exception type instead of a dozen.
        """
        with self.lock:
            if self.broken:
                raise ConnectionError_("The connection to the server was lost. Restart the client.")
            try:
                self.sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
                line = self.reader.readline()
                if not line:
                    raise ConnectionError_("The server closed the connection.")
                reply = json.loads(line.decode("utf-8"))
                if not isinstance(reply, dict) or not isinstance(reply.get("ok"), bool):
                    raise ConnectionError_("The server sent an invalid reply.")
                return reply
            except ConnectionError_:
                self.broken = True
                raise
            except (OSError, ValueError) as exc:  # ssl.SSLError is an OSError
                self.broken = True
                raise ConnectionError_(f"Lost connection to the server ({exc.__class__.__name__}).") from None

    def close(self) -> None:
        try:
            self.reader.close()
            self.sock.close()
        except OSError:
            pass
