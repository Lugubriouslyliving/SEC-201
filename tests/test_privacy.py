"""Privacy tests: pseudonymous logs, conditional re-identification, retention,
consent, and the PDPA access and erasure rights.

Run:  py -m unittest tests.test_privacy -v
"""

import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from client.session import ChatClient, ClientError
from crypto_utils.keys import UserKeys
from crypto_utils.passwords import client_password_hash
from server.privacy import PRIVACY_NOTICE_VERSION, RETENTION_SECONDS, Pseudonymizer, purge_expired
from server.server import start_in_background

PW = "privacy-test-password"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PrivacyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="secure-chat-privacy-")
        cls.db_path = os.path.join(cls.workdir, "db.json")
        # Capture everything the server logs, as the operator would see it.
        cls.log_buffer = io.StringIO()
        cls.handler = logging.StreamHandler(cls.log_buffer)
        cls.logger = logging.getLogger("server")
        cls.old_level = cls.logger.level
        cls.logger.addHandler(cls.handler)
        cls.logger.setLevel(logging.INFO)
        cls.srv = start_in_background("127.0.0.1", 0, cls.db_path)
        cls.host, cls.port = cls.srv.server_address

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()
        cls.logger.removeHandler(cls.handler)
        cls.logger.setLevel(cls.old_level)
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def client(self, device):
        c = ChatClient(self.host, self.port, os.path.join(self.workdir, device), ca_file=self.srv.ca_file)
        self.addCleanup(c.close)
        return c

    def user(self, name):
        c = self.client(name)
        c.signup(name, PW)
        return c

    def db(self):
        with open(self.db_path, encoding="utf-8") as f:
            return json.load(f)

    # ------------------------------------------------------------ logs

    def test_server_log_has_no_usernames_or_ip_addresses(self):
        a, b = self.user("logalice"), self.user("logbob")
        b.send("logalice", "hello")
        a.inbox()
        with self.assertRaises(ClientError):
            self.client("x").login("logalice", "wrong-password-1")
        log_text = self.log_buffer.getvalue()
        self.assertIn("signup:", log_text)  # the log is still useful…
        for secret in ("logalice", "logbob", "127.0.0.1"):  # …but names and IPs never appear
            self.assertNotIn(secret, log_text)
        self.assertIn(self.srv.app.pseudo.user("logalice"), log_text)
        self.assertIn(self.srv.app.pseudo.ip("127.0.0.1"), log_text)

    def test_reidentification_needs_the_key(self):
        """Conditional privacy: the key holder can map a pseudonym back; nobody else can."""
        key_a = os.path.join(self.workdir, "keys", "a")
        key_b = os.path.join(self.workdir, "keys", "b")
        real, other = Pseudonymizer(key_a), Pseudonymizer(key_b)
        pseudonym = real.user("carol")
        self.assertEqual(real.reidentify(pseudonym, ["alice", "carol"]), ["carol"])
        self.assertEqual(other.reidentify(pseudonym, ["alice", "carol"]), [])  # wrong key: no match
        self.assertEqual(Pseudonymizer(key_a).user("carol"), pseudonym)        # stable across restarts
        self.assertNotIn("carol", pseudonym)

    def test_reidentify_command(self):
        self.user("tracked")
        pseudonym = self.srv.app.pseudo.user("tracked")
        key = os.path.join(self.workdir, "privacy", "log_key")
        out = subprocess.run([sys.executable, "-m", "server.reidentify", pseudonym, "--db", self.db_path,
                              "--key", key], capture_output=True, text=True, cwd=REPO, timeout=60)
        self.assertEqual(out.stdout.strip(), "tracked")
        out = subprocess.run([sys.executable, "-m", "server.reidentify", pseudonym, "--db", self.db_path,
                              "--key", os.path.join(self.workdir, "missing")],
                             capture_output=True, text=True, cwd=REPO, timeout=60)
        self.assertNotIn("tracked", out.stdout + out.stderr)

    # ------------------------------------------------------------ retention

    def test_delivered_messages_are_deleted_from_the_server(self):
        a, b = self.user("retalice"), self.user("retbob")
        pkg = b.build_package("retalice", "read me once")
        b.send_package(pkg)
        mine = lambda: [e for e in self.db()["messages"] if e["package"]["recipient"] == "retalice"]
        self.assertEqual(len(mine()), 1)
        self.assertEqual(a.inbox()[0]["text"], "read me once")
        self.assertEqual(mine(), [])                                   # gone from the database
        self.assertIn(pkg["msg_id"], self.db()["seen_msg_ids"])        # only the random ID is kept…
        with self.assertRaises(ClientError):                           # …so replays are still caught
            b.send_package(pkg)

    def test_undelivered_messages_expire_after_retention_period(self):
        data = {"messages": [{"package": {}, "received_at": 1_000_000, "delivered": False}]}
        self.assertEqual(purge_expired(data, now=1_000_000 + RETENTION_SECONDS - 60), 0)
        self.assertEqual(len(data["messages"]), 1)
        self.assertEqual(purge_expired(data, now=1_000_000 + RETENTION_SECONDS + 60), 1)
        self.assertEqual(data["messages"], [])

    # ------------------------------------------------------------ consent and notice

    def test_privacy_notice_is_available_before_login(self):
        notice = self.client("anon").privacy_notice()
        self.assertEqual(notice["version"], PRIVACY_NOTICE_VERSION)
        for words in ("What we collect", "Why", "How long", "Your rights", "mydata", "delete_account"):
            self.assertIn(words, notice["text"])

    def test_signup_requires_accepting_the_current_notice(self):
        keys = UserKeys.generate()
        c = self.client("noconsent")
        for version in (None, "2000-01"):
            req = {"action": "signup", "username": "noconsent", "password_hash": client_password_hash("noconsent", PW),
                   "enc_public_pem": keys.enc_public_pem(), "sign_public_pem": keys.sign_public_pem()}
            if version:
                req["consent_version"] = version
            self.assertFalse(c.conn.request(req)["ok"])
        self.assertNotIn("noconsent", self.db()["users"])
        self.user("withconsent")
        self.assertEqual(self.db()["users"]["withconsent"]["consent"]["notice_version"], PRIVACY_NOTICE_VERSION)

    # ------------------------------------------------------------ data subject rights

    def test_mydata_shows_my_data_but_not_the_password_hash(self):
        a, b = self.user("accalice"), self.user("accbob")
        b.send("accalice", "one")
        data = a.mydata()
        self.assertEqual(data["username"], "accalice")
        self.assertEqual(data["messages_waiting_for_you"], 1)
        self.assertIn("BEGIN PUBLIC KEY", data["enc_public_pem"])
        stored = self.db()["users"]["accalice"]["password"]
        self.assertNotIn(stored["hash"], json.dumps(data))
        self.assertNotIn(stored["salt"], json.dumps(data))
        self.assertNotIn("accbob", json.dumps(data))  # nothing about other people
        with self.assertRaises(ClientError):
            self.client("anon2").mydata()               # requires login

    def test_delete_account_erases_everything(self):
        a, b = self.user("delalice"), self.user("delbob")
        a.send("delbob", "from alice")
        b.send("delalice", "to alice")
        with self.assertRaises(ClientError):            # wrong password: nothing is deleted
            a.delete_account("not-the-password")
        self.assertIn("delalice", self.db()["users"])
        a.delete_account(PW)
        db = self.db()
        self.assertNotIn("delalice", db["users"])
        self.assertFalse(any("delalice" in (e["package"]["sender"], e["package"]["recipient"])
                             for e in db["messages"]))
        self.assertFalse(os.path.exists(os.path.join(self.workdir, "delalice", "delalice")))  # local keys gone
        with self.assertRaises(ClientError):
            self.client("delalice2").login("delalice", PW)
        self.assertEqual(b.inbox(), [])                 # alice's waiting message to bob was erased too


if __name__ == "__main__":
    unittest.main(verbosity=2)
