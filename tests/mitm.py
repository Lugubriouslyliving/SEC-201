"""A network eavesdropper for tests and the demo.

RecordingProxy sits between client and server and copies every byte in
both directions, the way someone on the same Wi-Fi, a compromised router,
or an ISP could. It cannot decrypt anything; it just records what it sees.
"""

import socket
import threading


class RecordingProxy:
    def __init__(self, target_host: str, target_port: int):
        self.target = (target_host, target_port)
        self.client_to_server = bytearray()
        self.server_to_client = bytearray()
        self._lock = threading.Lock()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._sockets = []
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return  # listener closed
            server = socket.create_connection(self.target)
            self._sockets += [client, server]
            threading.Thread(target=self._pump, args=(client, server, self.client_to_server), daemon=True).start()
            threading.Thread(target=self._pump, args=(server, client, self.server_to_client), daemon=True).start()

    def _pump(self, src, dst, record):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                with self._lock:
                    record.extend(data)
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    @property
    def everything(self) -> bytes:
        with self._lock:
            return bytes(self.client_to_server) + bytes(self.server_to_client)

    def close(self):
        self._listener.close()
        for s in self._sockets:
            try:
                s.close()
            except OSError:
                pass
