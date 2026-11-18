"""Extreme and adversarial cases.

Where test_security.py checks that the protections work, this file checks
that the application keeps working when people (or attackers) do strange
things: garbage on the socket, huge or weird messages, broken files, many
users at once, a server restart, clocks out of sync, and so on.

Run:  py -m unittest tests.test_edge_cases -v
"""

import base64
import json
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from client.connection import ConnectionError_
from client.session import MAX_MESSAGE_CHARS, ChatClient, ClientError, safe_display
from crypto_utils.encoding import b64d, b64e
from crypto_utils.keys import UserKeys
from crypto_utils.messages import MessageRejected, encrypt_and_sign, verify_and_decrypt
from crypto_utils.passwords import client_password_hash
from crypto_utils.tls import client_context
from server.server import MAX_LINE, start_in_background

PW = "edge-case-password"


class ServerFixture(unittest.TestCase):
    """Starts a fresh server per test class; helpers for clients and raw sockets."""

    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="secure-chat-edge-")
        cls.db_path = os.path.join(cls.workdir, "db.json")
        cls.srv = start_in_background("127.0.0.1", 0, cls.db_path)
        cls.host, cls.port = cls.srv.server_address
        cls.open_clients = []

    @classmethod
    def tearDownClass(cls):
        for c in cls.open_clients:
            c.close()
        cls.srv.stop()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    @classmethod
    def client(cls, device):
        c = ChatClient(cls.host, cls.port, os.path.join(cls.workdir, f"device-{device}"), ca_file=cls.srv.ca_file)
        cls.open_clients.append(c)
        return c

    @classmethod
    def user(cls, name):
        c = cls.client(name)
        c.signup(name, PW)
        return c

    def tls_socket(self, timeout=10):
        """A raw TLS connection to the server (proper handshake, then raw bytes on top)."""
        raw = socket.create_connection((self.host, self.port), timeout=timeout)
        return client_context(self.srv.ca_file).wrap_socket(raw, server_hostname=self.host)

    def raw(self, data: bytes, timeout=10):
        """Send raw bytes inside TLS, return the parsed reply (or None if the server hung up)."""
        with self.tls_socket(timeout) as s:
            s.sendall(data)
            buf = b""
            while not buf.endswith(b"\n"):
                try:
                    chunk = s.recv(65536)
                except (ConnectionResetError, ConnectionAbortedError, ssl.SSLError):
                    return None
                if not chunk:
                    return None
                buf += chunk
            return json.loads(buf)

    def assert_server_alive(self):
        reply = self.raw(b'{"action":"users"}\n')
        self.assertEqual(reply, {"ok": False, "error": "Please log in first."})


# ===================================================================== protocol


class ProtocolAbuseTests(ServerFixture):
    """Garbage on the wire must get an error reply, never crash the server."""

    def test_garbage_inputs(self):
        cases = {
            "not json": b"hello there\n",
            "invalid utf-8": b"\xff\xfe\xfa\n",
            "json array": b"[1,2,3]\n",
            "json string": b'"signup"\n',
            "null": b"null\n",
            "empty object": b"{}\n",
            "unknown action": b'{"action":"format_disk"}\n',
            "action is a list": b'{"action":["users"]}\n',
            "action is an object": b'{"action":{"a":1}}\n',
            "deep nesting": b"[" * 100_000 + b"]" * 100_000 + b"\n",
            "NaN": b'{"action":"login","username":NaN,"password_hash":NaN}\n',
            "missing fields": b'{"action":"signup"}\n',
            "wrong field types": b'{"action":"login","username":123,"password_hash":["x"]}\n',
            "plain password instead of hash": b'{"action":"login","username":"alice","password_hash":"hunter2hunter2"}\n',
        }
        for label, data in cases.items():
            with self.subTest(label):
                reply = self.raw(data)
                self.assertIsNotNone(reply, "server hung up instead of answering")
                self.assertFalse(reply["ok"])
        self.assert_server_alive()

    def test_oversized_request_is_refused(self):
        reply = self.raw(b'{"action":"users","pad":"' + b"A" * (MAX_LINE + 10) + b'"}\n')
        if reply is not None:  # the server may also just close the connection
            self.assertFalse(reply["ok"])
        self.assert_server_alive()

    def test_blank_lines_and_many_requests_on_one_connection(self):
        with self.tls_socket() as s:
            f = s.makefile("rb")
            s.sendall(b"\n" + b'{"action":"users"}\n' * 200)
            replies = [json.loads(f.readline()) for _ in range(201)]
        self.assertTrue(all(r["ok"] is False for r in replies))

    def test_abrupt_disconnects(self):
        for _ in range(25):
            s = self.tls_socket()
            s.sendall(b'{"action":"log')  # half a request, then vanish
            s.close()
        for _ in range(25):  # vanish in the middle of the TLS handshake
            s = socket.create_connection((self.host, self.port))
            s.sendall(b"\x16\x03\x01\x00")
            s.close()
        self.assert_server_alive()

    def test_plain_text_client_is_refused_and_server_survives(self):
        """Someone talks plain JSON to the TLS port: no reply in clear text, and
        the server keeps serving everyone else."""
        with socket.create_connection((self.host, self.port), timeout=10) as s:
            s.sendall(b'{"action":"users"}\n')
            try:
                data = s.recv(65536)
            except (ConnectionResetError, ConnectionAbortedError):
                data = b""
        self.assertNotIn(b'"ok"', data)  # at most a TLS alert, never a JSON answer
        self.assert_server_alive()

    def test_silent_connection_is_dropped_after_handshake_timeout(self):
        """A client that connects and says nothing cannot hold a server thread forever."""
        import server.server as srvmod
        with mock.patch.object(srvmod, "HANDSHAKE_TIMEOUT", 0.5):
            s = socket.create_connection((self.host, self.port), timeout=5)
            try:
                time.sleep(1.5)
                s.settimeout(3)
                try:
                    data = s.recv(1)  # server should have closed it
                except (ConnectionResetError, ConnectionAbortedError):
                    data = b""
                self.assertEqual(data, b"")
            finally:
                s.close()
        self.assert_server_alive()

    def test_signup_rejects_fake_public_keys(self):
        good = UserKeys.generate()
        bad_values = [
            "-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n",
            ["-----BEGIN PUBLIC KEY-----"],
            good.sign_public_pem(),  # Ed25519 key where an RSA key belongs
            12345,
        ]
        for i, bad in enumerate(bad_values):
            with self.subTest(i=i):
                req = {"action": "signup", "username": f"fakekey{i}",
                       "password_hash": client_password_hash(f"fakekey{i}", PW),
                       "enc_public_pem": bad, "sign_public_pem": good.sign_public_pem()}
                reply = self.raw(json.dumps(req).encode() + b"\n")
                self.assertFalse(reply["ok"])
        # And the swapped case for the signing key:
        req = {"action": "signup", "username": "fakekey_sign",
               "password_hash": client_password_hash("fakekey_sign", PW),
               "enc_public_pem": good.enc_public_pem(), "sign_public_pem": good.enc_public_pem()}
        self.assertFalse(self.raw(json.dumps(req).encode() + b"\n")["ok"])

    def test_send_with_absurd_field_values(self):
        bob = self.user("absurd_bob")
        self.user("absurd_alice")
        base = bob.build_package("absurd_alice", "hi")
        for label, change in {
            "timestamp 10**300": {"timestamp": 10**300},
            "timestamp negative": {"timestamp": -1},
            "timestamp bool": {"timestamp": True},
            "timestamp float": {"timestamp": time.time()},
            "msg_id list": {"msg_id": ["x"]},
            "msg_id dict": {"msg_id": {"x": 1}},
            "msg_id huge": {"msg_id": "x" * 10_000},
            "recipient list": {"recipient": ["absurd_alice"]},
            "recipient missing user": {"recipient": "nobody_at_all"},
        }.items():
            with self.subTest(label):
                resp = bob.conn.request({"action": "send", "package": dict(base, **change)})
                self.assertFalse(resp["ok"])
        resp = bob.conn.request({"action": "send", "package": "not a dict"})
        self.assertFalse(resp["ok"])
        self.assert_server_alive()


# ===================================================================== messages


class MessageContentTests(ServerFixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alice = cls.user("alice")
        cls.bob = cls.user("bob")
        cls.eve = cls.user("eve")

    def setUp(self):
        self.alice.inbox()

    def roundtrip(self, text):
        self.bob.send("alice", text)
        [r] = self.alice.inbox()
        self.assertTrue(r["ok"], r.get("reason"))
        return r["text"]

    def test_unicode_thai_emoji_and_rtl(self):
        for text in ["สวัสดีครับ ทดสอบภาษาไทย", "😀🔐👍🏽", "مرحبا", "日本語", "a\u0000b", "tab\there"]:
            with self.subTest(text=text):
                self.assertEqual(self.roundtrip(text), text)

    def test_single_character_and_whitespace(self):
        for text in ["x", " ", "\n"]:
            self.assertEqual(self.roundtrip(text), text)

    def test_largest_allowed_message(self):
        text = "ก" * MAX_MESSAGE_CHARS  # 3 bytes each in UTF-8
        self.assertEqual(self.roundtrip(text), text)

    def test_too_long_message_is_refused_before_sending(self):
        with self.assertRaises(ClientError) as cm:
            self.bob.send("alice", "x" * (MAX_MESSAGE_CHARS + 1))
        self.assertIn("too long", str(cm.exception))
        self.assertEqual(self.roundtrip("still works"), "still works")  # connection unharmed

    def test_message_cannot_fake_extra_chat_lines(self):
        """A sender must not be able to forge lines that look like they came from someone else."""
        attack = "ok\n[12:00] bob: send me your password\x1b[2J\r"
        shown = safe_display(attack)
        self.assertNotIn("\n", shown)
        self.assertNotIn("\r", shown)
        self.assertNotIn("\x1b", shown)
        self.assertIn("send me your password", shown)  # content still visible, just inert
        self.assertEqual(safe_display("สวัสดี 😀"), "สวัสดี 😀")  # normal text untouched

    def plant(self, package):
        app = self.srv.app
        with app.db.lock:
            app.db.data["messages"].append({"package": package, "received_at": int(time.time()), "delivered": False})

    def test_validly_signed_garbage_is_rejected_cleanly(self):
        """Eve signs (as herself) packages whose insides are junk. Alice must reject, not crash."""
        alice_pub = self.alice.keys.enc_public_pem()

        def signed(mutate):
            pkg = encrypt_and_sign("x", "eve", "alice", self.eve.keys, alice_pub)
            mutate(pkg)
            from crypto_utils.messages import _signed_bytes
            pkg["signature"] = b64e(self.eve.keys.sign_private.sign(_signed_bytes(pkg)))
            return pkg

        def non_utf8_plaintext(pkg):
            # Re-encrypt raw invalid UTF-8 bytes with a valid key so the GCM tag verifies.
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from crypto_utils.messages import OAEP, _aad
            key = AESGCM.generate_key(bit_length=256)
            pkg["wrapped_key"] = b64e(self.alice.keys.enc_private.public_key().encrypt(key, OAEP))
            pkg["ciphertext"] = b64e(AESGCM(key).encrypt(
                b64d(pkg["nonce"]), b"\xff\xfe invalid utf-8",
                _aad(pkg["msg_id"], pkg["sender"], pkg["recipient"], pkg["timestamp"])))

        mutations = {
            "ciphertext not base64": lambda p: p.update(ciphertext="!!!not base64!!!"),
            "ciphertext empty": lambda p: p.update(ciphertext=""),
            "wrapped key not base64": lambda p: p.update(wrapped_key="@@@"),
            "wrapped key wrong size": lambda p: p.update(wrapped_key=b64e(b"\x00" * 10)),
            "nonce wrong size": lambda p: p.update(nonce=b64e(b"\x00" * 5)),
            "plaintext not utf-8": non_utf8_plaintext,
            "msg_id empty": lambda p: p.update(msg_id=""),
        }
        for label, mutate in mutations.items():
            with self.subTest(label):
                self.plant(signed(mutate))
                results = self.alice.inbox()
                self.assertEqual(len(results), 1)
                self.assertFalse(results[0]["ok"])
        # Structurally broken packages, as a malicious server could deliver them:
        for junk in ["a string", 42, None, [], {"sender": "bob"}, {"sender": ["bob"], "msg_id": 1},
                     {"sender": "bob", "timestamp": 10**400}]:
            with self.subTest(junk=str(junk)[:30]):
                self.assertFalse(self.alice.open_package(junk)["ok"])
        # The server itself must skip junk in its database instead of failing the inbox.
        self.plant("junk entry")
        self.assertEqual(self.alice.inbox(), [])
        self.assertEqual(self.roundtrip("after the junk"), "after the junk")

    def test_message_to_yourself_is_refused(self):
        with self.assertRaises(ClientError):
            self.alice.send("alice", "me")

    def test_send_to_unknown_user(self):
        with self.assertRaises(ClientError):
            self.bob.send("ghost", "boo")


class CryptoBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a, cls.b = UserKeys.generate(), UserKeys.generate()

    def test_future_timestamp_rejected(self):
        pkg = encrypt_and_sign("x", "b", "a", self.b, self.a.enc_public_pem())
        pkg["timestamp"] += 3600
        from crypto_utils.messages import _signed_bytes
        pkg["signature"] = b64e(self.b.sign_private.sign(_signed_bytes(pkg)))
        with self.assertRaises(MessageRejected):
            verify_and_decrypt(pkg, "a", self.a, self.b.sign_public_pem())

    def test_message_for_someone_else_rejected(self):
        pkg = encrypt_and_sign("x", "b", "carol", self.b, self.a.enc_public_pem())
        with self.assertRaises(MessageRejected) as cm:
            verify_and_decrypt(pkg, "a", self.a, self.b.sign_public_pem())
        self.assertIn("addressed to", cm.exception.reason)

    def test_signature_wrong_length_or_garbage(self):
        for sig in ["", "AAAA", b64e(b"\x00" * 64), b64e(b"\x00" * 1000), "***"]:
            pkg = encrypt_and_sign("x", "b", "a", self.b, self.a.enc_public_pem())
            pkg["signature"] = sig
            with self.subTest(sig=sig[:10]), self.assertRaises(MessageRejected):
                verify_and_decrypt(pkg, "a", self.a, self.b.sign_public_pem())

    def test_empty_and_huge_passwords_for_key_file(self):
        for pw in ["", "p" * 100_000, "รหัสผ่าน🔑"]:
            with self.subTest(len=len(pw)):
                stored = self.a.to_encrypted_file(pw)
                self.assertEqual(UserKeys.from_encrypted_file(stored, pw).sign_public_pem(), self.a.sign_public_pem())


# ===================================================================== accounts & local files


class AccountAndFileTests(ServerFixture):
    def test_invalid_usernames_fail_fast_without_keygen(self):
        c = self.client("names")
        for name in ["", "ab", "Alice", "a" * 21, "../../etc", "al ice", "alice!", "ส้ม"]:
            with self.subTest(name=name):
                t0 = time.perf_counter()
                with self.assertRaises(ClientError):
                    c.signup(name, PW)
                self.assertLess(time.perf_counter() - t0, 0.2, "should fail before generating keys")

    def test_short_password_fails_fast(self):
        c = self.client("shortpw")
        t0 = time.perf_counter()
        with self.assertRaises(ClientError):
            c.signup("shortpw", "1234567")
        self.assertLess(time.perf_counter() - t0, 0.2)

    def test_duplicate_username(self):
        self.user("dupe")
        with self.assertRaises(ClientError) as cm:
            self.client("dupe-other-device").signup("dupe", "another-password")
        self.assertIn("taken", str(cm.exception))

    def test_long_and_unicode_passwords(self):
        for i, pw in enumerate(["p" * 1024, "รหัสผ่านยาวมาก🔑🔑", "  spaces  around  "]):
            name = f"pwuser{i}"
            self.client(f"{name}-a").signup(name, pw)
            self.client(f"{name}-a").login(name, pw)  # same device folder, new connection
        with self.assertRaises(ClientError):  # over the 1024-character limit
            self.client("pwuser-big").signup("pwuser_big", "p" * 1025)
        # Raw protocol: the server enforces the limit too, for login as well as signup.
        reply = self.raw(json.dumps({"action": "login", "username": "pwuser0",
                                     "password_hash": "p" * 500_000}).encode() + b"\n")
        self.assertFalse(reply["ok"])
        # A signup that sends a raw password instead of the hash is refused, so the
        # server can never end up storing a hash of a plain password.
        good = UserKeys.generate()
        reply = self.raw(json.dumps({"action": "signup", "username": "rawpw", "password_hash": "plain-password",
                                     "enc_public_pem": good.enc_public_pem(),
                                     "sign_public_pem": good.sign_public_pem()}).encode() + b"\n")
        self.assertFalse(reply["ok"])

    def test_corrupted_local_files_give_clear_errors(self):
        c = self.user("corrupt")
        keyfile = os.path.join(self.workdir, "device-corrupt", "corrupt", "keys.json")
        for content in ["{not json", "{}", '{"kdf": 5}', ""]:
            with self.subTest(content=content):
                with open(keyfile, "w", encoding="utf-8") as f:
                    f.write(content)
                with self.assertRaises(ClientError):
                    self.client("corrupt").login("corrupt", PW)
        # Pinned keys / seen IDs files broken: should not crash the client.
        c2 = self.user("corrupt2")
        folder = os.path.join(self.workdir, "device-corrupt2", "corrupt2")
        for name in ("known_keys.json", "seen_ids.json"):
            with open(os.path.join(folder, name), "w", encoding="utf-8") as f:
                f.write("[[[ broken")
        c3 = self.client("corrupt2")
        c3.login("corrupt2", PW)
        c3.users()
        c3.inbox()

    def test_login_from_a_device_without_keys(self):
        self.user("nokeys")
        with self.assertRaises(ClientError) as cm:
            self.client("nokeys-new-laptop").login("nokeys", PW)
        self.assertIn("No key file", str(cm.exception))

    def test_commands_before_login(self):
        c = self.client("anon")
        for call in (c.users, c.inbox, lambda: c.send("x", "y")):
            with self.assertRaises(ClientError):
                call()

    def test_logout_then_commands(self):
        c = self.user("loggedout")
        c.logout()
        with self.assertRaises(ClientError):
            c.inbox()
        c.login("loggedout", PW)
        c.inbox()


# ===================================================================== load & concurrency


class ConcurrencyTests(ServerFixture):
    def test_many_users_sending_at_once(self):
        """10 senders x 20 messages to one recipient, all at the same time: every
        message arrives exactly once, intact, and the database stays valid."""
        n_senders, per_sender = 10, 20
        target = self.user("target")
        senders = [self.user(f"sender{i}") for i in range(n_senders)]
        errors = []

        def blast(i, c):
            try:
                for j in range(per_sender):
                    c.send("target", f"{i}-{j}")
            except Exception as exc:  # collected and reported by the test
                errors.append(repr(exc))

        threads = [threading.Thread(target=blast, args=(i, c)) for i, c in enumerate(senders)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        results = target.inbox()
        self.assertTrue(all(r["ok"] for r in results), [r.get("reason") for r in results if not r["ok"]])
        texts = sorted(r["text"] for r in results)
        self.assertEqual(texts, sorted(f"{i}-{j}" for i in range(n_senders) for j in range(per_sender)))
        with open(self.db_path, encoding="utf-8") as f:
            json.load(f)  # still valid JSON

    def test_many_simultaneous_logins(self):
        self.user("busy")
        errors = []

        def login():
            try:
                c = ChatClient(self.host, self.port, os.path.join(self.workdir, "device-busy"), ca_file=self.srv.ca_file)
                c.login("busy", PW)
                c.close()
            except Exception as exc:
                errors.append(repr(exc))

        threads = [threading.Thread(target=login) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_inbox_poller_and_sender_share_one_connection(self):
        """Chat mode: a background thread polls while the main thread sends."""
        a, b = self.user("poll_a"), self.user("poll_b")
        stop = threading.Event()
        received, errors = [], []

        def poll():
            while not stop.is_set():
                try:
                    received.extend(r for r in a.inbox())
                except Exception as exc:
                    errors.append(repr(exc))
                time.sleep(0.01)

        t = threading.Thread(target=poll)
        t.start()
        for i in range(30):
            a.send("poll_b", f"from a {i}")  # same connection as the poller
            b.send("poll_a", f"from b {i}")
        time.sleep(0.5)
        stop.set()
        t.join()
        self.assertEqual(errors, [])
        self.assertEqual(sorted(r["text"] for r in received if r["ok"]), sorted(f"from b {i}" for i in range(30)))
        self.assertEqual(len(b.inbox()), 30)


# ===================================================================== restarts, clocks, keys


class RestartAndClockTests(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="secure-chat-restart-")
        self.ca = os.path.join(self.workdir, "tls", "ca.crt")  # created by the first start()
        self.db_path = os.path.join(self.workdir, "db.json")

    def tearDown(self):
        shutil.rmtree(self.workdir, ignore_errors=True)

    def start(self, port=0):
        srv = start_in_background("127.0.0.1", port, self.db_path)
        return srv, srv.server_address[1]

    def stop(self, srv):
        srv.stop()  # like killing the server process: open sessions are dropped too

    def test_server_restart(self):
        srv, port = self.start()
        dev = lambda n: os.path.join(self.workdir, n)
        alice = ChatClient("127.0.0.1", port, dev("a"), ca_file=self.ca)
        alice.signup("alice", PW)
        bob = ChatClient("127.0.0.1", port, dev("b"), ca_file=self.ca)
        bob.signup("bob", PW)
        pkg = bob.build_package("alice", "sent before the restart")
        bob.send_package(pkg)
        self.stop(srv)

        # The old connection is dead: the client must say so clearly, not crash.
        with self.assertRaises(ConnectionError_):
            alice.inbox()
        with self.assertRaises(ConnectionError_):
            bob.send("alice", "x")
        alice.close()
        bob.close()

        srv, port = self.start(port)
        try:
            alice = ChatClient("127.0.0.1", port, dev("a"), ca_file=self.ca)
            alice.login("alice", PW)
            [r] = alice.inbox()  # message survived the restart
            self.assertEqual(r["text"], "sent before the restart")
            bob = ChatClient("127.0.0.1", port, dev("b"), ca_file=self.ca)
            bob.login("bob", PW)
            with self.assertRaises(ClientError):  # replay list survived too
                bob.send_package(pkg)
            alice.close()
            bob.close()
        finally:
            self.stop(srv)

    def test_sender_clock_far_off(self):
        srv, port = self.start()
        try:
            a = ChatClient("127.0.0.1", port, os.path.join(self.workdir, "a"), ca_file=self.ca)
            a.signup("alice", PW)
            b = ChatClient("127.0.0.1", port, os.path.join(self.workdir, "b"), ca_file=self.ca)
            b.signup("bob", PW)
            # Bob's clock is an hour slow (only the client's view of time is changed).
            slow_clock = mock.Mock(time=lambda: time.time() - 3600)
            with mock.patch("crypto_utils.messages.time", slow_clock):
                with self.assertRaises(ClientError) as cm:
                    b.send("alice", "late")
            self.assertIn("clock", str(cm.exception).lower())
            a.close()
            b.close()
        finally:
            self.stop(srv)

    def test_database_wiped_and_name_reregistered_by_someone_else(self):
        """After a wipe, an impostor registers 'bob' with new keys. Alice's pinned key catches it."""
        srv, port = self.start()
        dev = lambda n: os.path.join(self.workdir, n)
        a = ChatClient("127.0.0.1", port, dev("a"), ca_file=self.ca)
        a.signup("alice", PW)
        b = ChatClient("127.0.0.1", port, dev("b"), ca_file=self.ca)
        b.signup("bob", PW)
        a.users()  # Alice pins Bob's real keys
        a.close()
        b.close()
        self.stop(srv)
        os.remove(self.db_path)

        srv, port = self.start(port)
        try:
            a = ChatClient("127.0.0.1", port, dev("a-new"), ca_file=self.ca)  # Alice re-registers from a fresh folder
            a.signup("alice", PW)
            shutil.copy(os.path.join(dev("a"), "alice", "known_keys.json"),
                        os.path.join(dev("a-new"), "alice", "known_keys.json"))
            impostor = ChatClient("127.0.0.1", port, dev("impostor"), ca_file=self.ca)
            impostor.signup("bob", PW)
            with self.assertRaises(ClientError) as cm:
                a.send("bob", "secret")
            self.assertIn("different keys", str(cm.exception))
            a.close()
            impostor.close()
        finally:
            self.stop(srv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
