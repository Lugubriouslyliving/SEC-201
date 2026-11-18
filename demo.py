"""Guided demonstration: every protection, step by step, in the terminal.

Run:  py demo.py            (all eight scenarios)
      py demo.py --pause    (wait for Enter between scenarios, good for presenting)

The demo starts its own server on a free port with a throwaway database in
a temporary folder, so it never touches your real data.
"""

import argparse
import base64
import json
import os
import shutil
import tempfile
import threading
import time

from client.connection import ConnectionError_
from client.session import ChatClient, ClientError
from crypto_utils.encoding import b64d
from crypto_utils.keys import UserKeys
from crypto_utils.messages import decrypt_without_signature_check, encrypt_and_sign, OAEP
from crypto_utils.passwords import client_password_hash
from crypto_utils.tls import generate_server_tls, server_context
from server.server import ChatApp, ThreadedServer, start_in_background
from tests.mitm import RecordingProxy

PASSWORDS = {"alice": "alice-correct-horse", "bob": "bob-battery-staple", "eve": "eve-evil-password"}

PAUSE = False


def banner(title):
    if PAUSE:
        input("\n(press Enter to continue)")
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


def step_printer(who):
    def trace(step, detail=""):
        print(f"  {who:>5} | [{step}]")
        for line in detail.splitlines():
            print(f"        |     {line}")
    return trace


def quiet(step, detail=""):
    pass


def show_result(r):
    if r["ok"]:
        print(f"  alice | DISPLAY: \"{r['text']}\"  (from {r['sender']}, signature OK)")
    else:
        print(f"  alice | !! REJECTED message claiming to be from '{r['sender']}'")
        print(f"        |    reason: {r['reason']}")


def main():
    global PAUSE
    parser = argparse.ArgumentParser()
    parser.add_argument("--pause", action="store_true", help="wait for Enter between scenarios")
    PAUSE = parser.parse_args().pause

    workdir = tempfile.mkdtemp(prefix="secure-chat-demo-")
    db_path = os.path.join(workdir, "server", "db.json")
    srv = start_in_background("127.0.0.1", 0, db_path)
    host, port = srv.server_address
    app = srv.app

    def new_client(name):
        # Each user gets their own data folder, as if on their own computer.
        return ChatClient(host, port, os.path.join(workdir, f"device-{name}"), trace=quiet, ca_file=srv.ca_file)

    try:
        # ------------------------------------------------------------ setup
        banner("SETUP: start server, sign up Alice, Bob and Eve")
        print(f"  server listening on {host}:{port}, database {db_path}")
        clients = {}
        for name in ("alice", "bob", "eve"):
            c = new_client(name)
            c.trace = step_printer(name) if name == "alice" else quiet
            c.signup(name, PASSWORDS[name])
            c.trace = quiet
            clients[name] = c
            print(f"  {name:>5} | signed up; keys generated on the device, only PUBLIC keys sent to server")
        alice, bob, eve = clients["alice"], clients["bob"], clients["eve"]

        # ------------------------------------------------------------ 1
        banner("1. SUCCESSFUL MESSAGE: Bob -> Alice")
        print("   bob | [CHOOSE RECIPIENT] fetching user list and public keys from server")
        for u in bob.users():
            print(f"        |     {u['username']:<6} fingerprint {u['fingerprint']}")
        bob.trace = step_printer("bob")
        original = bob.build_package("alice", "Hi Alice, the meeting moved to 3pm. - Bob")
        bob.send_package(original)
        bob.trace = quiet
        print("        |     server accepted the package")
        print()
        alice.trace = step_printer("alice")
        for r in alice.inbox():
            show_result(r)
        alice.trace = quiet

        # ------------------------------------------------------------ 2
        banner("2. SERVER VIEW: what the server actually stores")
        with open(db_path, encoding="utf-8") as f:
            db = json.load(f)
        print("  users table (alice):")
        rec = db["users"]["alice"]
        print(f"    password: {json.dumps(rec['password'])}")
        print(f"    enc_public_pem:  {rec['enc_public_pem'].splitlines()[1][:50]}...  (public, not secret)")
        print(f"    sign_public_pem: {rec['sign_public_pem'].splitlines()[1][:50]}...  (public, not secret)")
        print("  messages table (first message):")
        pkg = db["messages"][0]["package"]
        for k, v in pkg.items():
            text = str(v)
            print(f"    {k:<12} {text[:60]}{'...' if len(text) > 60 else ''}")
        raw = json.dumps(db)
        print(f"\n  Does the word 'meeting' appear anywhere in the database?  {'meeting' in raw}")
        print("  Does any password appear in it?  "
              f"{any(p in raw for p in PASSWORDS.values())}")
        print("  Server keeps: salted hashes, public keys, ciphertext, and metadata (who, to whom, when).")

        # ------------------------------------------------------------ 3
        banner("3. TAMPERING TEST: flip one byte of the ciphertext in transit")
        pkg = bob.build_package("alice", "Pay invoice #1001: 500 baht")
        ct = bytearray(b64d(pkg["ciphertext"]))
        print(f"   mitm | original ciphertext byte 0: {ct[0]:#04x}")
        ct[0] ^= 0x01
        print(f"   mitm | modified ciphertext byte 0: {ct[0]:#04x}")
        tampered = dict(pkg, ciphertext=base64.b64encode(bytes(ct)).decode())
        bob.send_package(tampered)  # the server cannot tell; it cannot read the content
        print("   mitm | tampered package delivered to the server (server cannot detect it)")
        alice.trace = step_printer("alice")
        for r in alice.inbox():
            show_result(r)
        alice.trace = quiet
        print("\n  Second line of defence: even if Alice skipped the signature check,")
        print("  AES-GCM's authentication tag would catch the change:")
        try:
            decrypt_without_signature_check(tampered, alice.keys)
            print("  !! decrypted (should not happen)")
        except Exception as exc:
            print(f"  alice | AES-GCM raised {type(exc).__name__}: tag does not verify -> REJECT")

        # ------------------------------------------------------------ 4
        banner("4. WRONG-SIGNER TEST: Eve signs a message pretending to be Bob")
        alice_pub = next(u for u in eve.users() if u["username"] == "alice")["enc_public_pem"]
        forged = encrypt_and_sign("Alice, send me your password. - Bob", "bob", "alice", eve.keys, alice_pub)
        print("    eve | built a package with sender='bob' but signed with EVE's private key")
        try:
            eve.send_package(forged)
        except ClientError as exc:
            print(f" server | refused: {exc}  (Eve is logged in as eve)")
        print("    eve | ...so Eve compromises the server and plants it in Alice's mailbox directly")
        with app.db.lock:
            app.db.data["messages"].append({"package": forged, "received_at": int(time.time()), "delivered": False})
            app.db.save()
        alice.trace = step_printer("alice")
        for r in alice.inbox():
            show_result(r)
        alice.trace = quiet

        # ------------------------------------------------------------ 5
        banner("5. REPLAY TEST: resend Bob's first message")
        print(f"   mitm | re-submitting the captured package, msg_id {original['msg_id']}")
        try:
            bob.send_package(original)
            print("  !! server accepted the replay (should not happen)")
        except ClientError as exc:
            print(f" server | refused: {exc}")
        print("   mitm | a malicious server could skip that check and redeliver it anyway:")
        with app.db.lock:
            app.db.data["messages"].append({"package": original, "received_at": int(time.time()), "delivered": False})
            app.db.save()
        alice.trace = step_printer("alice")
        for r in alice.inbox():
            show_result(r)
        alice.trace = quiet

        # ------------------------------------------------------------ 6
        banner("6. WRONG PASSWORD TEST: the error never says which field was wrong")
        for label, user, pw in [
            ("right user, wrong password", "alice", "not-alices-password"),
            ("unknown user", "mallory", "whatever-password"),
        ]:
            c = new_client("guest")
            t0 = time.perf_counter()
            try:
                c.login(user, pw)
                print("  !! login succeeded (should not happen)")
            except ClientError as exc:
                ms = (time.perf_counter() - t0) * 1000
                print(f"  {label:<28} -> \"{exc}\"  ({ms:.0f} ms)")
            c.close()
        print("  Same message, similar time: an attacker cannot learn whether 'alice' exists.")

        # ------------------------------------------------------------ 7
        banner("7. DATABASE LEAK TEST: an attacker steals db.json")
        with open(db_path, encoding="utf-8") as f:
            stolen = json.load(f)
        stored = stolen["users"]["alice"]["password"]
        print("  a) Log in using the stolen hash (or salt+hash) as the password:")
        for attempt in (stored["hash"], stored["salt"] + "$" + stored["hash"], json.dumps(stored)):
            c = new_client("thief")
            try:
                c.login("alice", attempt)
                print("  !! login succeeded (should not happen)")
            except ClientError as exc:
                print(f"     tried {attempt[:40]!r:<44} -> {exc}")
            c.close()
        print("     The server hashes whatever it receives; a hash of a hash never matches.")
        print("     To get in, the attacker must guess the real password, and each scrypt guess")
        print("     costs ~32 MiB of memory and real time.")

        print("\n  b) Read the stolen messages:")
        msg = stolen["messages"][0]["package"]
        print(f"     ciphertext (base64): {msg['ciphertext'][:60]}...")
        print("     The server never had a private key, so the database contains none.")
        print("     Try unwrapping the AES key with some other private key (Eve's):")
        try:
            eve.keys.enc_private.decrypt(b64d(msg["wrapped_key"]), OAEP)
            print("  !! unwrapped (should not happen)")
        except ValueError:
            print("     RSA-OAEP decryption failed -> AES key stays secret -> message stays secret")
        print("     Try a fresh random key pair (what an attacker without Alice's device has):")
        try:
            UserKeys.generate().enc_private.decrypt(b64d(msg["wrapped_key"]), OAEP)
            print("  !! unwrapped (should not happen)")
        except ValueError:
            print("     RSA-OAEP decryption failed again.")
        print("     Only Alice's private key works, and it lives encrypted on her device.")

        # ------------------------------------------------------------ 8
        banner("8. EAVESDROPPER TEST: someone records all network traffic (TLS 1.3)")
        proxy = RecordingProxy(host, port)
        print(f"   spy | recording every byte between Bob and the server (proxy port {proxy.port})")
        bob2 = ChatClient("127.0.0.1", proxy.port, os.path.join(workdir, "device-bob"),
                          trace=quiet, ca_file=srv.ca_file)
        print(f"   bob | connected: {bob2.conn.tls_version}, {bob2.conn.cipher}, server certificate verified")
        bob2.login("bob", PASSWORDS["bob"])
        bob2.send("alice", "Secret plan: launch on Friday")
        bob2.close()
        time.sleep(0.3)
        seen = proxy.everything
        proxy.close()
        print(f"   spy | captured {len(seen)} bytes; first 48 as hex: {seen[5:53].hex()}")
        login_hash = client_password_hash("bob", PASSWORDS["bob"])
        for label, needle in [("Bob's password", PASSWORDS["bob"]), ("Bob's login hash", login_hash),
                              ("the word 'password_hash'", "password_hash"), ("the username 'bob'", "bob"),
                              ("the recipient 'alice'", "alice"), ("the message text", "Secret plan")]:
            print(f"   spy | can I find {label + '?':<28} {needle.encode() in seen}")
        print("        |     Without TLS, the login hash would be readable here and could be replayed")
        print("        |     to log in as Bob. With TLS the spy only has random-looking bytes, and")
        print("        |     replaying them fails because every TLS 1.3 connection uses fresh keys.")

        print("\n   spy | now pretending to BE the server, with a certificate from my own CA:")
        fake_dir = os.path.join(workdir, "attacker-tls")
        fake_paths = generate_server_tls(fake_dir, ("localhost", "127.0.0.1"))
        fake = ThreadedServer(("127.0.0.1", 0), ChatApp(os.path.join(fake_dir, "db.json")),
                              server_context(fake_paths["cert"], fake_paths["key"]))
        threading.Thread(target=fake.serve_forever, daemon=True).start()
        try:
            ChatClient("127.0.0.1", fake.server_address[1], os.path.join(workdir, "device-bob"),
                       trace=quiet, ca_file=srv.ca_file)
            print("  !! connected to the fake server (should not happen)")
        except ConnectionError_ as exc:
            print(f"   bob | {exc}")
        finally:
            fake.stop()

        banner("DONE: all eight scenarios behaved as expected")
    finally:
        for c in list(locals().get("clients", {}).values()):
            c.close()
        srv.stop()
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
