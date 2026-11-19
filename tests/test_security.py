"""Automated security tests.

Run from the project folder:
    py -m unittest -v

Each end-to-end test talks to a real server over a real socket, started on
a free port with a temporary database.
"""

import base64
import json
import os
import shutil
import tempfile
import time
import unittest

from client.session import ChatClient, ClientError
from crypto_utils.encoding import b64d
from crypto_utils.keys import KeyFileError, UserKeys
from crypto_utils.messages import OAEP, MessageRejected, encrypt_and_sign, verify_and_decrypt
from crypto_utils.passwords import hash_password, verify_password
from server.server import GENERIC_LOGIN_ERROR, start_in_background

PW = {"alice": "alice-password-1", "bob": "bob-password-22", "eve": "eve-password-333"}


# ======================================================== crypto unit tests


class PasswordHashingTests(unittest.TestCase):
    def test_same_password_gets_different_salts_and_hashes(self):
        a, b = hash_password("hunter2hunter2"), hash_password("hunter2hunter2")
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotEqual(a["hash"], b["hash"])

    def test_verify(self):
        rec = hash_password("correct password")
        self.assertTrue(verify_password("correct password", rec))
        self.assertFalse(verify_password("wrong password", rec))

    def test_client_login_hash(self):
        from crypto_utils.passwords import client_password_hash, is_login_hash
        h = client_password_hash("alice", "same password")
        self.assertEqual(h, client_password_hash("alice", "same password"))  # same on every device
        self.assertNotEqual(h, client_password_hash("bob", "same password"))  # username acts as salt
        self.assertNotEqual(h, client_password_hash("alice", "same passwore"))
        self.assertTrue(is_login_hash(h))
        self.assertNotIn("same password", h)
        self.assertFalse(is_login_hash("same password"))

    def test_record_contains_no_plaintext(self):
        rec = hash_password("SuperSecret!")
        self.assertNotIn("SuperSecret!", json.dumps(rec))


class KeyFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = UserKeys.generate()

    def test_round_trip(self):
        stored = self.keys.to_encrypted_file("pw-for-keys")
        loaded = UserKeys.from_encrypted_file(stored, "pw-for-keys")
        self.assertEqual(loaded.sign_public_pem(), self.keys.sign_public_pem())
        self.assertEqual(loaded.enc_public_pem(), self.keys.enc_public_pem())

    def test_wrong_password_cannot_unlock(self):
        stored = self.keys.to_encrypted_file("pw-for-keys")
        with self.assertRaises(KeyFileError):
            UserKeys.from_encrypted_file(stored, "not-the-password")

    def test_file_has_no_plaintext_private_key(self):
        stored = json.dumps(self.keys.to_encrypted_file("pw-for-keys"))
        self.assertNotIn("PRIVATE KEY", stored)


class MessageCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice, cls.bob, cls.eve = UserKeys.generate(), UserKeys.generate(), UserKeys.generate()

    def seal(self, text="hello"):
        return encrypt_and_sign(text, "bob", "alice", self.bob, self.alice.enc_public_pem())

    def open(self, pkg, signer_pem=None, seen=None):
        return verify_and_decrypt(pkg, "alice", self.alice, signer_pem or self.bob.sign_public_pem(), seen_ids=seen)

    def test_round_trip(self):
        self.assertEqual(self.open(self.seal("hi there")), "hi there")

    def test_fresh_key_and_nonce_every_message(self):
        a, b = self.seal("same"), self.seal("same")
        self.assertNotEqual(a["nonce"], b["nonce"])
        self.assertNotEqual(a["wrapped_key"], b["wrapped_key"])
        self.assertNotEqual(a["ciphertext"], b["ciphertext"])
        self.assertNotEqual(a["msg_id"], b["msg_id"])
        self.assertEqual(len(b64d(a["nonce"])), 12)

    def test_every_signed_field_is_protected(self):
        for field in ("msg_id", "sender", "recipient", "timestamp", "nonce", "ciphertext", "wrapped_key"):
            pkg = self.seal()
            if field == "timestamp":
                pkg[field] -= 1
            elif field in ("nonce", "ciphertext", "wrapped_key"):
                raw = bytearray(b64d(pkg[field]))
                raw[-1] ^= 0x01
                pkg[field] = base64.b64encode(bytes(raw)).decode()
            elif field == "msg_id":  # change one hex digit, so it is still a well-formed ID
                pkg[field] = pkg[field][:-1] + ("0" if pkg[field][-1] != "0" else "1")
            else:
                pkg[field] = pkg[field] + "x"
            with self.subTest(field=field), self.assertRaises(MessageRejected) as cm:
                self.open(pkg)
            self.assertIn("signature", cm.exception.reason)

    def test_only_recipient_can_unwrap(self):
        pkg = self.seal()
        with self.assertRaises(ValueError):
            self.eve.enc_private.decrypt(b64d(pkg["wrapped_key"]), OAEP)


# ======================================================== end-to-end tests


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="secure-chat-test-")
        cls.db_path = os.path.join(cls.workdir, "db.json")
        cls.srv = start_in_background("127.0.0.1", 0, cls.db_path)
        cls.host, cls.port = cls.srv.server_address
        cls.clients = {}
        for name in ("alice", "bob", "eve"):
            c = cls.client(name)
            c.signup(name, PW[name])
            cls.clients[name] = c
        cls.alice, cls.bob, cls.eve = (cls.clients[n] for n in ("alice", "bob", "eve"))

    @classmethod
    def tearDownClass(cls):
        for c in cls.clients.values():
            c.close()
        cls.srv.stop()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    @classmethod
    def client(cls, name):
        return ChatClient(cls.host, cls.port, os.path.join(cls.workdir, f"device-{name}"), ca_file=cls.srv.ca_file)

    def setUp(self):
        self.alice.inbox()  # start each test with an empty inbox

    def plant(self, package):
        """Simulate a compromised server writing straight into the mailbox."""
        app = self.srv.app
        with app.db.lock:
            app.db.data["messages"].append({"package": package, "received_at": int(time.time()), "delivered": False})

    # ---- 1. happy path
    def test_1_bob_to_alice(self):
        self.bob.send("alice", "Hello Alice")
        results = self.alice.inbox()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["ok"], results[0].get("reason"))
        self.assertEqual(results[0]["text"], "Hello Alice")
        self.assertEqual(results[0]["sender"], "bob")

    # ---- 2. server stores ciphertext only
    def test_2_server_stores_only_ciphertext(self):
        secret = "the vault code is 4815162342"
        self.bob.send("alice", secret)
        with open(self.db_path, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn(secret, raw)
        self.assertNotIn("4815162342", raw)
        for pw in PW.values():
            self.assertNotIn(pw, raw)
        self.assertNotIn("PRIVATE KEY", raw)
        self.alice.inbox()

    # ---- 3. tampering
    def test_3_tampered_ciphertext_is_rejected(self):
        pkg = self.bob.build_package("alice", "Transfer 100")
        ct = bytearray(b64d(pkg["ciphertext"]))
        ct[0] ^= 0x01  # flip one bit of one byte
        pkg["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        self.bob.send_package(pkg)  # server cannot tell
        results = self.alice.inbox()
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["ok"])
        self.assertIn("signature", results[0]["reason"])

    # ---- 4. wrong signer
    def test_4a_server_refuses_sender_spoofing(self):
        alice_pub = next(u for u in self.eve.users() if u["username"] == "alice")["enc_public_pem"]
        forged = encrypt_and_sign("I am Bob", "bob", "alice", self.eve.keys, alice_pub)
        with self.assertRaises(ClientError):
            self.eve.send_package(forged)

    def test_4b_alice_rejects_eve_signing_as_bob(self):
        alice_pub = next(u for u in self.eve.users() if u["username"] == "alice")["enc_public_pem"]
        forged = encrypt_and_sign("I am Bob", "bob", "alice", self.eve.keys, alice_pub)
        self.plant(forged)  # even if the server is compromised...
        results = self.alice.inbox()
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["ok"])  # ...Alice still rejects it
        self.assertIn("invalid signature", results[0]["reason"])

    # ---- 5. replay
    def test_5a_server_rejects_duplicate_message_id(self):
        pkg = self.bob.build_package("alice", "once only")
        self.bob.send_package(pkg)
        with self.assertRaises(ClientError) as cm:
            self.bob.send_package(pkg)
        self.assertIn("Duplicate message ID", str(cm.exception))
        self.alice.inbox()

    def test_5b_client_rejects_redelivered_message(self):
        pkg = self.bob.build_package("alice", "once only (client check)")
        self.bob.send_package(pkg)
        first = self.alice.inbox()
        self.assertTrue(first[0]["ok"])
        self.plant(pkg)  # malicious server delivers it again
        second = self.alice.inbox()
        self.assertFalse(second[0]["ok"])
        self.assertIn("replay", second[0]["reason"])

    def test_5c_replay_detection_survives_restart_of_client(self):
        pkg = self.bob.build_package("alice", "persisted IDs")
        self.bob.send_package(pkg)
        self.assertTrue(self.alice.inbox()[0]["ok"])
        fresh_alice = self.client("alice")  # same device folder, new session
        try:
            fresh_alice.login("alice", PW["alice"])
            self.plant(pkg)
            self.assertFalse(fresh_alice.inbox()[0]["ok"])
        finally:
            fresh_alice.close()

    # ---- 6. wrong password
    def test_6_login_failures_look_identical(self):
        errors = []
        for user, pw in (("alice", "wrong-password"), ("nobody_here", "wrong-password"), ("alice", "")):
            c = self.client("guest")
            try:
                with self.assertRaises(ClientError) as cm:
                    c.login(user, pw)
                errors.append(str(cm.exception))
            finally:
                c.close()
        # Wrong password, unknown user, empty password: one identical message.
        self.assertEqual(set(errors), {GENERIC_LOGIN_ERROR})

    def test_6b_users_requires_login(self):
        c = self.client("guest")
        try:
            resp = c.conn.request({"action": "users"})
            self.assertFalse(resp["ok"])
        finally:
            c.close()

    # ---- 7. database leak
    def test_7a_stolen_hash_cannot_log_in(self):
        with open(self.db_path, encoding="utf-8") as f:
            rec = json.load(f)["users"]["alice"]["password"]
        for attempt in (rec["hash"], rec["salt"], rec["salt"] + rec["hash"], json.dumps(rec)):
            c = self.client("thief")
            try:
                with self.assertRaises(ClientError):
                    c.login("alice", attempt)
                # Skip the client and send the stolen hash straight to the server
                # as if it were the login hash. It has the right shape (32 bytes,
                # base64) but the server hashes it again, so it still fails.
                resp = c.conn.request({"action": "login", "username": "alice", "password_hash": rec["hash"]})
                self.assertFalse(resp["ok"])
            finally:
                c.close()

    # ---- password handling on the wire and in logs
    def test_8_server_never_receives_the_password(self):
        """Record every request the server gets during signup and logins: the
        real password must not appear in any of them."""
        seen = []
        real_dispatch = self.srv.app.dispatch

        def recording_dispatch(conn, req):
            seen.append(json.dumps(req))
            return real_dispatch(conn, req)

        password = "my-very-secret-pw-8"
        self.srv.app.dispatch = recording_dispatch
        try:
            c = self.client("carol")
            c.signup("carol", password)
            c.logout()
            c.login("carol", password)
            with self.assertRaises(ClientError):
                c.login("carol", password + "-typo")
            c.close()
        finally:
            self.srv.app.dispatch = real_dispatch
        traffic = "\n".join(seen)
        self.assertTrue(seen)
        self.assertNotIn(password, traffic)
        self.assertNotIn("-typo", traffic)
        self.assertIn("password_hash", traffic)

    def test_9_failed_logins_are_not_logged(self):
        """Someone types their password into the username box. The server must
        not write it to its log."""
        with self.assertLogs("server", level="INFO") as logs:
            c = self.client("alice")  # Alice's device folder, so her key file is there
            try:
                c.login("alice", PW["alice"])  # a success, so the log is not empty
                for typed_name in ("hunter2secret", "alice"):  # unknown name, then wrong password
                    with self.assertRaises(ClientError):
                        c.login(typed_name, "whatever-password")
            finally:
                c.close()
        output = "\n".join(logs.output)
        self.assertIn("login: alice", output)
        self.assertNotIn("hunter2secret", output)
        self.assertNotIn("failed", output)

    def test_7b_stolen_messages_cannot_be_read(self):
        self.bob.send("alice", "confidential")
        with open(self.db_path, encoding="utf-8") as f:
            db = json.load(f)
        pkg = db["messages"][-1]["package"]
        # No private key anywhere in the server's data:
        self.assertNotIn("PRIVATE KEY", json.dumps(db))
        # Any key other than Alice's fails to unwrap the AES key:
        for other in (self.eve.keys, self.bob.keys, UserKeys.generate()):
            with self.assertRaises(ValueError):
                other.enc_private.decrypt(b64d(pkg["wrapped_key"]), OAEP)
        # Alice's device can still read it:
        self.assertEqual(self.alice.inbox()[0]["text"], "confidential")


if __name__ == "__main__":
    unittest.main(verbosity=2)
