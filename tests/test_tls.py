"""TLS tests: what an attacker on the network can and cannot do.

Run:  py -m unittest tests.test_tls -v
"""

import os
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest

from client.connection import ConnectionError_
from client.session import ChatClient
from crypto_utils.passwords import client_password_hash
from crypto_utils.tls import client_context, generate_server_tls, server_context
from server.server import ChatApp, ThreadedServer, start_in_background
from tests.mitm import RecordingProxy

PW = "tls-test-password"


class TLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="secure-chat-tls-")
        cls.srv = start_in_background("127.0.0.1", 0, os.path.join(cls.workdir, "db.json"))
        cls.host, cls.port = cls.srv.server_address
        cls.ca = cls.srv.ca_file
        dave = ChatClient(cls.host, cls.port, os.path.join(cls.workdir, "dave"), ca_file=cls.ca)
        dave.signup("dave", PW)
        dave.close()

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def run_server(self, tls_dir, hostnames):
        """Start an extra server (e.g. an attacker's) with certificates from `tls_dir`."""
        paths = generate_server_tls(tls_dir, hostnames)
        srv = ThreadedServer(("127.0.0.1", 0), ChatApp(os.path.join(tls_dir, "db.json")),
                             server_context(paths["cert"], paths["key"]))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.stop)
        return srv.server_address[1]

    # ------------------------------------------------------------ eavesdropping

    def test_eavesdropper_sees_nothing_useful(self):
        """Signup, login, user list and a message, all through a proxy that records every byte."""
        proxy = RecordingProxy(self.host, self.port)
        self.addCleanup(proxy.close)
        secret_text = "the treasure is under the old mango tree"
        c = ChatClient("127.0.0.1", proxy.port, os.path.join(self.workdir, "carol"), ca_file=self.ca)
        c.signup("carol", PW)
        c.logout()
        c.login("carol", PW)
        c.users()
        c.send("dave", secret_text)
        c.close()
        time.sleep(0.2)

        seen = proxy.everything
        self.assertGreater(len(seen), 1000)  # traffic really went through the proxy
        login_hash = client_password_hash("carol", PW)
        for secret in (PW, login_hash, "password_hash", "carol", "dave", '"action"', "BEGIN PUBLIC KEY",
                       secret_text, "ciphertext", "msg_id"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret.encode(), seen)

    def test_replaying_recorded_traffic_logs_nobody_in(self):
        """The attacker replays the exact bytes of a recorded login. TLS 1.3 uses fresh
        keys for every connection, so the old bytes are meaningless to the server."""
        proxy = RecordingProxy(self.host, self.port)
        self.addCleanup(proxy.close)
        c = ChatClient("127.0.0.1", proxy.port, os.path.join(self.workdir, "dave"), ca_file=self.ca)
        c.login("dave", PW)
        c.close()
        time.sleep(0.2)
        recorded = bytes(proxy.client_to_server)

        requests_seen = []
        real_dispatch = self.srv.app.dispatch
        self.srv.app.dispatch = lambda conn, req: requests_seen.append(req) or real_dispatch(conn, req)
        try:
            with socket.create_connection((self.host, self.port), timeout=5) as s:
                try:
                    s.sendall(recorded)
                    s.recv(65536)
                except OSError:
                    pass
            time.sleep(0.3)
        finally:
            self.srv.app.dispatch = real_dispatch
        self.assertEqual(requests_seen, [], "replayed bytes must never reach the application")

    # ------------------------------------------------------------ impersonation

    def test_fake_server_with_its_own_certificate_is_refused(self):
        """An attacker runs a complete chat server with a certificate from their own CA,
        valid for 127.0.0.1. The client refuses before sending a single request."""
        fake_port = self.run_server(os.path.join(self.workdir, "attacker"), ("localhost", "127.0.0.1"))
        with self.assertRaises(ConnectionError_) as cm:
            ChatClient("127.0.0.1", fake_port, os.path.join(self.workdir, "victim"), ca_file=self.ca)
        self.assertIn("SECURITY WARNING", str(cm.exception))

    def test_certificate_for_another_host_is_refused(self):
        """A certificate for a different name must not be accepted for 127.0.0.1."""
        tls_dir = os.path.join(self.workdir, "otherhost")
        port = self.run_server(tls_dir, ("chat.example.invalid",))
        with self.assertRaises(ConnectionError_) as cm:
            ChatClient("127.0.0.1", port, os.path.join(self.workdir, "victim2"),
                       ca_file=os.path.join(tls_dir, "ca.crt"))
        self.assertIn("SECURITY WARNING", str(cm.exception))

    def test_plain_text_server_is_refused(self):
        """A server that does not speak TLS at all (e.g. the old version, or a fake)."""
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        got = []

        def fake():
            conn, _ = listener.accept()
            got.append(conn.recv(65536))
            conn.sendall(b'{"ok": true}\n')
            conn.close()
        threading.Thread(target=fake, daemon=True).start()
        with self.assertRaises(ConnectionError_):
            ChatClient("127.0.0.1", listener.getsockname()[1], os.path.join(self.workdir, "v3"), ca_file=self.ca)
        time.sleep(0.2)
        self.assertNotIn(b"password", b"".join(got))
        self.assertNotIn(b"action", b"".join(got))  # only a TLS ClientHello was sent

    def test_old_tls_versions_are_refused(self):
        ctx = client_context(self.ca)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((self.host, self.port), timeout=5) as raw:
            with self.assertRaises(ssl.SSLError):
                ctx.wrap_socket(raw, server_hostname="127.0.0.1")

    def test_connection_uses_tls13(self):
        c = ChatClient(self.host, self.port, os.path.join(self.workdir, "dave"), ca_file=self.ca)
        self.addCleanup(c.close)
        self.assertEqual(c.conn.tls_version, "TLSv1.3")

    def test_missing_or_bad_ca_file(self):
        with self.assertRaises(ConnectionError_) as cm:
            ChatClient(self.host, self.port, os.path.join(self.workdir, "x"), ca_file="no/such/ca.crt")
        self.assertIn("Cannot find", str(cm.exception))
        bad = os.path.join(self.workdir, "bad-ca.crt")
        with open(bad, "w") as f:
            f.write("not a certificate")
        with self.assertRaises(ConnectionError_):
            ChatClient(self.host, self.port, os.path.join(self.workdir, "x"), ca_file=bad)

    def test_ca_private_key_is_not_kept(self):
        files = sorted(os.listdir(os.path.dirname(self.ca)))
        self.assertEqual(files, ["ca.crt", "server.crt", "server.key"])
        with open(self.ca) as f:
            self.assertNotIn("PRIVATE KEY", f.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
