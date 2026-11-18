"""A tiny JSON-lines client for the relay server."""

import json
import socket
import threading


class ConnectionError_(Exception):
    pass


class Connection:
    """One TCP connection = one session with the server."""

    def __init__(self, host: str, port: int, timeout: float = 30.0):
        try:
            self.sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise ConnectionError_(f"Cannot reach server at {host}:{port} ({exc}).") from None
        self.reader = self.sock.makefile("rb")
        # Chat mode checks the inbox on a background thread while the user
        # sends from the main thread; the lock keeps each request paired
        # with its own response.
        self.lock = threading.Lock()

    def request(self, payload: dict) -> dict:
        """Send one JSON object, wait for one JSON object back."""
        with self.lock:
            self.sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            line = self.reader.readline()
        if not line:
            raise ConnectionError_("Server closed the connection.")
        return json.loads(line.decode("utf-8"))

    def close(self) -> None:
        try:
            self.reader.close()
            self.sock.close()
        except OSError:
            pass
