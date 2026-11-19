# 5. Demo and tests

[← The client](04-client.md) · [Index](README.md) · Next: [Security analysis →](06-security-analysis.md)

- [5.1 `demo.py`, line by line](#51-demopy-line-by-line): the eight-scenario presentation
- [5.2 `tests/mitm.py`, line by line](#52-testsmitmpy-line-by-line): the eavesdropping proxy
- [5.3 What each automated test proves](#53-what-each-automated-test-proves): all 70 tests

Run them with:

```powershell
py demo.py --pause
```

```powershell
py -m unittest -v
```

## 5.1 `demo.py`, line by line

The demo runs a real server and real clients in one process, on a free port, with a
temporary folder that is deleted at the end.

### Setup code

[`demo.py` lines 1–31](../demo.py#L1-L31)

```python
 1  """Guided demonstration: every protection, step by step, in the terminal.
 2  
 3  Run:  py demo.py            (all eight scenarios)
 4        py demo.py --pause    (wait for Enter between scenarios, good for presenting)
 5  
 6  The demo starts its own server on a free port with a throwaway database in
 7  a temporary folder, so it never touches your real data.
 8  """
 9  
10  import argparse
11  import base64
12  import json
13  import os
14  import shutil
15  import tempfile
16  import threading
17  import time
18  
19  from client.connection import ConnectionError_
20  from client.session import ChatClient, ClientError
21  from crypto_utils.encoding import b64d
22  from crypto_utils.keys import UserKeys
23  from crypto_utils.messages import decrypt_without_signature_check, encrypt_and_sign, OAEP
24  from crypto_utils.passwords import client_password_hash
25  from crypto_utils.tls import generate_server_tls, server_context
26  from server.server import ChatApp, ThreadedServer, start_in_background
27  from tests.mitm import RecordingProxy
28  
29  PASSWORDS = {"alice": "alice-correct-horse", "bob": "bob-battery-staple", "eve": "eve-evil-password"}
30  
31  PAUSE = False
```

- **1–8** — Module docstring: how to run it, and that it uses a throwaway folder.
- **10** — `argparse` for the `--pause` option.
- **11** — `base64` to rebuild a tampered ciphertext.
- **12** — `json` to read the server's database file.
- **13** — `os` for paths.
- **14** — `shutil` to delete the temporary folder.
- **15** — `tempfile` to create it.
- **16** — `threading` to run the fake server in scenario 8.
- **17** — `time` for timings and timestamps.
- **19** — The connection error, expected when the fake server is refused.
- **20** — The client and its error type.
- **21** — Base64 decoding.
- **22** — The key class (to make a random "attacker" key pair).
- **23** — The demo-only decrypt, the real encrypt-and-sign, and the OAEP settings.
- **24** — The login hash, to search for it in captured traffic.
- **25** — Certificate generation and server TLS settings, for the fake server.
- **26** — The server pieces.
- **27** — The recording proxy (section 5.2).
- **29** — Fixed demo passwords for the three users.
- **31** — Whether to pause between scenarios (set from the command line).

[`demo.py` lines 34–59](../demo.py#L34-L59)

```python
34  def banner(title):
35      if PAUSE:
36          input("\n(press Enter to continue)")
37      print("\n" + "=" * 78)
38      print(f"  {title}")
39      print("=" * 78)
40  
41  
42  def step_printer(who):
43      def trace(step, detail=""):
44          print(f"  {who:>5} | [{step}]")
45          for line in detail.splitlines():
46              print(f"        |     {line}")
47      return trace
48  
49  
50  def quiet(step, detail=""):
51      pass
52  
53  
54  def show_result(r):
55      if r["ok"]:
56          print(f"  alice | DISPLAY: \"{r['text']}\"  (from {r['sender']}, signature OK)")
57      else:
58          print(f"  alice | !! REJECTED message claiming to be from '{r['sender']}'")
59          print(f"        |    reason: {r['reason']}")
```

- **34** — `banner` prints a scenario title.
- **35–36** — In pause mode, wait for Enter first.
- **37–39** — A line of `=`, the title, another line.
- **42** — `step_printer(who)` returns a trace function labelled with a user's name.
- **43–46** — It prints `who | [STEP]` and then each detail line, indented.
- **47** — Return it.
- **50–51** — `quiet` prints nothing.
- **54** — `show_result` prints what Alice's client decided about one message.
- **55–56** — Accepted: the text, sender and "signature OK".
- **57–59** — Rejected: a warning and the reason.

[`demo.py` lines 62–76](../demo.py#L62-L76)

```python
62  def main():
63      global PAUSE
64      parser = argparse.ArgumentParser()
65      parser.add_argument("--pause", action="store_true", help="wait for Enter between scenarios")
66      PAUSE = parser.parse_args().pause
67  
68      workdir = tempfile.mkdtemp(prefix="secure-chat-demo-")
69      db_path = os.path.join(workdir, "server", "db.json")
70      srv = start_in_background("127.0.0.1", 0, db_path)
71      host, port = srv.server_address
72      app = srv.app
73  
74      def new_client(name):
75          # Each user gets their own data folder, as if on their own computer.
76          return ChatClient(host, port, os.path.join(workdir, f"device-{name}"), trace=quiet, ca_file=srv.ca_file)
```

- **62** — `main`.
- **63** — It will set the module-level `PAUSE`.
- **64–66** — Parse `--pause`.
- **68** — Create a temporary folder.
- **69** — The database will go in `<temp>/server/db.json`.
- **70** — Start a server on a free port (certificates are created next to the database).
- **71** — Learn the port it picked.
- **72** — Keep a handle on the server's logic, so scenarios 4 and 5 can play a compromised server.
- **74–76** — `new_client(name)` makes a client with its own device folder, trusting the server's CA.

### Setup scenario: three users sign up

[`demo.py` lines 78–90](../demo.py#L78-L90)

```python
78      try:
79          # ------------------------------------------------------------ setup
80          banner("SETUP: start server, sign up Alice, Bob and Eve")
81          print(f"  server listening on {host}:{port}, database {db_path}")
82          clients = {}
83          for name in ("alice", "bob", "eve"):
84              c = new_client(name)
85              c.trace = step_printer(name) if name == "alice" else quiet
86              c.signup(name, PASSWORDS[name])
87              c.trace = quiet
88              clients[name] = c
89              print(f"  {name:>5} | signed up; keys generated on the device, only PUBLIC keys sent to server")
90          alice, bob, eve = clients["alice"], clients["bob"], clients["eve"]
```

- **78** — Everything below is inside `try`, so the cleanup at the end always runs.
- **79–81** — Title and where the server is.
- **82** — Keep the three clients.
- **83–84** — For Alice, Bob and Eve, create a client…
- **85** — …showing the steps only for Alice, so the signup is shown once…
- **86** — …sign up (key generation, login hash, request, encrypted key file)…
- **87–88** — …switch tracing off and keep the client.
- **89** — Note that only public keys went to the server.
- **90** — Short names for the three clients.

### Scenario 1: a successful message

[`demo.py` lines 92–106](../demo.py#L92-L106)

```python
 92          # ------------------------------------------------------------ 1
 93          banner("1. SUCCESSFUL MESSAGE: Bob -> Alice")
 94          print("   bob | [CHOOSE RECIPIENT] fetching user list and public keys from server")
 95          for u in bob.users():
 96              print(f"        |     {u['username']:<6} fingerprint {u['fingerprint']}")
 97          bob.trace = step_printer("bob")
 98          original = bob.build_package("alice", "Hi Alice, the meeting moved to 3pm. - Bob")
 99          bob.send_package(original)
100          bob.trace = quiet
101          print("        |     server accepted the package")
102          print()
103          alice.trace = step_printer("alice")
104          for r in alice.inbox():
105              show_result(r)
106          alice.trace = quiet
```

- **92–93** — Title.
- **94–96** — Bob fetches the directory (which pins the keys) and prints each fingerprint.
- **97** — Show Bob's steps.
- **98** — Encrypt and sign (prints ENCRYPT, WRAP KEY, SIGN).
- **99** — Send it (prints TRANSMIT).
- **100–102** — Stop tracing Bob; note the server accepted it.
- **103** — Show Alice's steps.
- **104–105** — Alice fetches her inbox; each package is verified, replay-checked, unwrapped and decrypted, then displayed.
- **106** — Stop tracing Alice.

### Scenario 2: what the server stores

[`demo.py` lines 108–126](../demo.py#L108-L126)

```python
108          # ------------------------------------------------------------ 2
109          banner("2. SERVER VIEW: what the server actually stores")
110          with open(db_path, encoding="utf-8") as f:
111              db = json.load(f)
112          print("  users table (alice):")
113          rec = db["users"]["alice"]
114          print(f"    password: {json.dumps(rec['password'])}")
115          print(f"    enc_public_pem:  {rec['enc_public_pem'].splitlines()[1][:50]}...  (public, not secret)")
116          print(f"    sign_public_pem: {rec['sign_public_pem'].splitlines()[1][:50]}...  (public, not secret)")
117          print("  messages table (first message):")
118          pkg = db["messages"][0]["package"]
119          for k, v in pkg.items():
120              text = str(v)
121              print(f"    {k:<12} {text[:60]}{'...' if len(text) > 60 else ''}")
122          raw = json.dumps(db)
123          print(f"\n  Does the word 'meeting' appear anywhere in the database?  {'meeting' in raw}")
124          print("  Does any password appear in it?  "
125                f"{any(p in raw for p in PASSWORDS.values())}")
126          print("  Server keeps: salted hashes, public keys, ciphertext, and metadata (who, to whom, when).")
```

- **108–109** — Title.
- **110–111** — Read the server's database file directly, as the operator could.
- **112–116** — Print Alice's user record: the password record (algorithm, costs, salt, hash) and the start of each public key.
- **117–121** — Print each field of the first stored message, cut to 60 characters.
- **122** — The whole database as one string.
- **123** — Does the word "meeting" from Bob's message appear anywhere? (It doesn't.)
- **124–125** — Does any of the three passwords appear? (None does.)
- **126** — Summary of what the server does see.

### Scenario 3: tampering

[`demo.py` lines 128–148](../demo.py#L128-L148)

```python
128          # ------------------------------------------------------------ 3
129          banner("3. TAMPERING TEST: flip one byte of the ciphertext in transit")
130          pkg = bob.build_package("alice", "Pay invoice #1001: 500 baht")
131          ct = bytearray(b64d(pkg["ciphertext"]))
132          print(f"   mitm | original ciphertext byte 0: {ct[0]:#04x}")
133          ct[0] ^= 0x01
134          print(f"   mitm | modified ciphertext byte 0: {ct[0]:#04x}")
135          tampered = dict(pkg, ciphertext=base64.b64encode(bytes(ct)).decode())
136          bob.send_package(tampered)  # the server cannot tell; it cannot read the content
137          print("   mitm | tampered package delivered to the server (server cannot detect it)")
138          alice.trace = step_printer("alice")
139          for r in alice.inbox():
140              show_result(r)
141          alice.trace = quiet
142          print("\n  Second line of defence: even if Alice skipped the signature check,")
143          print("  AES-GCM's authentication tag would catch the change:")
144          try:
145              decrypt_without_signature_check(tampered, alice.keys)
146              print("  !! decrypted (should not happen)")
147          except Exception as exc:
148              print(f"  alice | AES-GCM raised {type(exc).__name__}: tag does not verify -> REJECT")
```

- **128–129** — Title.
- **130** — Bob seals a new message, but it is not sent yet.
- **131** — Decode the ciphertext into a changeable byte array.
- **132** — Show its first byte.
- **133** — Flip the lowest bit of that byte (XOR with 1): the smallest possible change.
- **134** — Show the changed byte.
- **135** — A copy of the package with the modified ciphertext. The signature is unchanged (the attacker can't re-sign without Bob's key).
- **136** — Send it. The server accepts it, because it cannot check contents.
- **137** — Say so.
- **138–141** — Alice opens her inbox with tracing on: the signature check fails and the message is rejected.
- **142–143** — Explain the second check.
- **144–146** — Try decrypting while deliberately skipping the signature…
- **147–148** — …AES-GCM raises `InvalidTag`, so the change is caught a second time.

### Scenario 4: Eve pretends to be Bob

[`demo.py` lines 150–166](../demo.py#L150-L166)

```python
150          # ------------------------------------------------------------ 4
151          banner("4. WRONG-SIGNER TEST: Eve signs a message pretending to be Bob")
152          alice_pub = next(u for u in eve.users() if u["username"] == "alice")["enc_public_pem"]
153          forged = encrypt_and_sign("Alice, send me your password. - Bob", "bob", "alice", eve.keys, alice_pub)
154          print("    eve | built a package with sender='bob' but signed with EVE's private key")
155          try:
156              eve.send_package(forged)
157          except ClientError as exc:
158              print(f" server | refused: {exc}  (Eve is logged in as eve)")
159          print("    eve | ...so Eve compromises the server and plants it in Alice's mailbox directly")
160          with app.db.lock:
161              app.db.data["messages"].append({"package": forged, "received_at": int(time.time()), "delivered": False})
162              app.db.save()
163          alice.trace = step_printer("alice")
164          for r in alice.inbox():
165              show_result(r)
166          alice.trace = quiet
```

- **150–151** — Title.
- **152** — Eve looks up Alice's RSA public key, which anyone may do.
- **153** — Eve builds a package that says `sender: "bob"` but signs it with **her own** key (she doesn't have Bob's).
- **154** — Say so.
- **155–158** — Eve tries to send it; the server refuses because Eve is logged in as `eve`, not `bob`.
- **159** — Eve "compromises the server" instead…
- **160–162** — …by writing the forged package straight into the database, as a malicious operator could.
- **163–166** — Alice checks her inbox: the signature does not match Bob's key, so it is rejected.

### Scenario 5: replay

[`demo.py` lines 168–183](../demo.py#L168-L183)

```python
168          # ------------------------------------------------------------ 5
169          banner("5. REPLAY TEST: resend Bob's first message")
170          print(f"   mitm | re-submitting the captured package, msg_id {original['msg_id']}")
171          try:
172              bob.send_package(original)
173              print("  !! server accepted the replay (should not happen)")
174          except ClientError as exc:
175              print(f" server | refused: {exc}")
176          print("   mitm | a malicious server could skip that check and redeliver it anyway:")
177          with app.db.lock:
178              app.db.data["messages"].append({"package": original, "received_at": int(time.time()), "delivered": False})
179              app.db.save()
180          alice.trace = step_printer("alice")
181          for r in alice.inbox():
182              show_result(r)
183          alice.trace = quiet
```

- **168–169** — Title.
- **170** — Pretend someone captured Bob's first package.
- **171–175** — Re-submit it: the server refuses the duplicate message ID.
- **176** — A malicious server could skip that check…
- **177–179** — …so plant the same package in Alice's mailbox again.
- **180–183** — Alice's client recognizes the ID from `seen_ids` and rejects it.

### Scenario 6: wrong password

[`demo.py` lines 185–200](../demo.py#L185-L200)

```python
185          # ------------------------------------------------------------ 6
186          banner("6. WRONG PASSWORD TEST: the error never says which field was wrong")
187          for label, user, pw in [
188              ("right user, wrong password", "alice", "not-alices-password"),
189              ("unknown user", "mallory", "whatever-password"),
190          ]:
191              c = new_client("guest")
192              t0 = time.perf_counter()
193              try:
194                  c.login(user, pw)
195                  print("  !! login succeeded (should not happen)")
196              except ClientError as exc:
197                  ms = (time.perf_counter() - t0) * 1000
198                  print(f"  {label:<28} -> \"{exc}\"  ({ms:.0f} ms)")
199              c.close()
200          print("  Same message, similar time: an attacker cannot learn whether 'alice' exists.")
```

- **185–186** — Title.
- **187–190** — Two attempts: Alice with the wrong password, and a user who doesn't exist.
- **191** — A fresh client for each attempt.
- **192** — Start a timer.
- **193–195** — Try to log in (it must fail).
- **196–198** — Print the error message and how long it took.
- **199** — Close.
- **200** — The point: same message, similar time.

### Scenario 7: the database is stolen

[`demo.py` lines 202–218](../demo.py#L202-L218)

```python
202          # ------------------------------------------------------------ 7
203          banner("7. DATABASE LEAK TEST: an attacker steals db.json")
204          with open(db_path, encoding="utf-8") as f:
205              stolen = json.load(f)
206          stored = stolen["users"]["alice"]["password"]
207          print("  a) Log in using the stolen hash (or salt+hash) as the password:")
208          for attempt in (stored["hash"], stored["salt"] + "$" + stored["hash"], json.dumps(stored)):
209              c = new_client("thief")
210              try:
211                  c.login("alice", attempt)
212                  print("  !! login succeeded (should not happen)")
213              except ClientError as exc:
214                  print(f"     tried {attempt[:40]!r:<44} -> {exc}")
215              c.close()
216          print("     The server hashes whatever it receives; a hash of a hash never matches.")
217          print("     To get in, the attacker must guess the real password, and each scrypt guess")
218          print("     costs ~32 MiB of memory and real time.")
```

- **202–203** — Title.
- **204–205** — Read the database file as a thief would.
- **206** — Alice's password record.
- **207** — Part (a).
- **208** — Try logging in with the stored hash, with salt and hash joined, and with the whole record.
- **209–215** — Each attempt goes through the normal client (which hashes it as if it were a password) and fails.
- **216–218** — Why: the server hashes whatever it receives, so a stolen hash is just another wrong password, and guessing the real password costs a full scrypt per guess.

[`demo.py` lines 220–236](../demo.py#L220-L236)

```python
220          print("\n  b) Read the stolen messages:")
221          msg = stolen["messages"][0]["package"]
222          print(f"     ciphertext (base64): {msg['ciphertext'][:60]}...")
223          print("     The server never had a private key, so the database contains none.")
224          print("     Try unwrapping the AES key with some other private key (Eve's):")
225          try:
226              eve.keys.enc_private.decrypt(b64d(msg["wrapped_key"]), OAEP)
227              print("  !! unwrapped (should not happen)")
228          except ValueError:
229              print("     RSA-OAEP decryption failed -> AES key stays secret -> message stays secret")
230          print("     Try a fresh random key pair (what an attacker without Alice's device has):")
231          try:
232              UserKeys.generate().enc_private.decrypt(b64d(msg["wrapped_key"]), OAEP)
233              print("  !! unwrapped (should not happen)")
234          except ValueError:
235              print("     RSA-OAEP decryption failed again.")
236          print("     Only Alice's private key works, and it lives encrypted on her device.")
```

- **220** — Part (b).
- **221–222** — Take the first stored message and show its ciphertext.
- **223** — Note that the database contains no private keys.
- **224–229** — Try to unwrap the AES key with Eve's private key: RSA-OAEP fails.
- **230–235** — Try again with a freshly generated key pair: fails again.
- **236** — Only Alice's key, on Alice's device, works.

### Scenario 8: eavesdropping and a fake server

[`demo.py` lines 238–259](../demo.py#L238-L259)

```python
238          # ------------------------------------------------------------ 8
239          banner("8. EAVESDROPPER TEST: someone records all network traffic (TLS 1.3)")
240          proxy = RecordingProxy(host, port)
241          print(f"   spy | recording every byte between Bob and the server (proxy port {proxy.port})")
242          bob2 = ChatClient("127.0.0.1", proxy.port, os.path.join(workdir, "device-bob"),
243                            trace=quiet, ca_file=srv.ca_file)
244          print(f"   bob | connected: {bob2.conn.tls_version}, {bob2.conn.cipher}, server certificate verified")
245          bob2.login("bob", PASSWORDS["bob"])
246          bob2.send("alice", "Secret plan: launch on Friday")
247          bob2.close()
248          time.sleep(0.3)
249          seen = proxy.everything
250          proxy.close()
251          print(f"   spy | captured {len(seen)} bytes; first 48 as hex: {seen[5:53].hex()}")
252          login_hash = client_password_hash("bob", PASSWORDS["bob"])
253          for label, needle in [("Bob's password", PASSWORDS["bob"]), ("Bob's login hash", login_hash),
254                                ("the word 'password_hash'", "password_hash"), ("the username 'bob'", "bob"),
255                                ("the recipient 'alice'", "alice"), ("the message text", "Secret plan")]:
256              print(f"   spy | can I find {label + '?':<28} {needle.encode() in seen}")
257          print("        |     Without TLS, the login hash would be readable here and could be replayed")
258          print("        |     to log in as Bob. With TLS the spy only has random-looking bytes, and")
259          print("        |     replaying them fails because every TLS 1.3 connection uses fresh keys.")
```

- **238–239** — Title.
- **240** — Start a recording proxy in front of the real server.
- **241** — Say what it does.
- **242–243** — Bob connects **through the proxy** (same device folder, so his keys are there).
- **244** — Show the TLS version and cipher, and that the certificate was verified.
- **245** — Bob logs in through the proxy.
- **246** — Bob sends a message through the proxy.
- **247** — Disconnect.
- **248** — Give the proxy a moment to finish copying.
- **249** — Everything the proxy saw, in both directions.
- **250** — Stop the proxy.
- **251** — Print how many bytes were captured and a sample in hex: unreadable.
- **252** — Compute Bob's login hash, to search for it.
- **253–256** — Search the capture for the password, the login hash, the field name, both usernames and the message text, and print the result (all `False`).
- **257–259** — Explain why this matters: without TLS the login hash could be copied and replayed.

[`demo.py` lines 261–274](../demo.py#L261-L274)

```python
261          print("\n   spy | now pretending to BE the server, with a certificate from my own CA:")
262          fake_dir = os.path.join(workdir, "attacker-tls")
263          fake_paths = generate_server_tls(fake_dir, ("localhost", "127.0.0.1"))
264          fake = ThreadedServer(("127.0.0.1", 0), ChatApp(os.path.join(fake_dir, "db.json")),
265                                server_context(fake_paths["cert"], fake_paths["key"]))
266          threading.Thread(target=fake.serve_forever, daemon=True).start()
267          try:
268              ChatClient("127.0.0.1", fake.server_address[1], os.path.join(workdir, "device-bob"),
269                         trace=quiet, ca_file=srv.ca_file)
270              print("  !! connected to the fake server (should not happen)")
271          except ConnectionError_ as exc:
272              print(f"   bob | {exc}")
273          finally:
274              fake.stop()
```

- **261** — Now the spy pretends to **be** the server.
- **262** — A folder for the attacker's certificates.
- **263** — The attacker makes their own CA and a certificate for `localhost`/`127.0.0.1`, valid as far as the attacker is concerned.
- **264–265** — A complete chat server using the attacker's certificate.
- **266** — Run it in the background.
- **267–269** — Bob tries to connect to it, trusting only the real CA.
- **270** — If that worked it would be a failure of the design (it doesn't).
- **271–272** — The client refuses with its security warning, before sending anything.
- **273–274** — Stop the fake server.

[`demo.py` lines 276–285](../demo.py#L276-L285)

```python
276          banner("DONE: all eight scenarios behaved as expected")
277      finally:
278          for c in list(locals().get("clients", {}).values()):
279              c.close()
280          srv.stop()
281          shutil.rmtree(workdir, ignore_errors=True)
282  
283  
284  if __name__ == "__main__":
285      main()
```

- **276** — Final banner.
- **277** — Cleanup, run even if a scenario failed.
- **278–279** — Close every client.
- **280** — Stop the server.
- **281** — Delete the temporary folder.
- **284–285** — Run `main()` when executed as a program.

## 5.2 `tests/mitm.py`, line by line

A small proxy that plays the network attacker in the tests and the demo.

[`tests/mitm.py` lines 1–21](../tests/mitm.py#L1-L21)

```python
 1  """A network eavesdropper for tests and the demo.
 2  
 3  RecordingProxy sits between client and server and copies every byte in
 4  both directions, the way someone on the same Wi-Fi, a compromised router,
 5  or an ISP could. It cannot decrypt anything; it just records what it sees.
 6  """
 7  
 8  import socket
 9  import threading
10  
11  
12  class RecordingProxy:
13      def __init__(self, target_host: str, target_port: int):
14          self.target = (target_host, target_port)
15          self.client_to_server = bytearray()
16          self.server_to_client = bytearray()
17          self._lock = threading.Lock()
18          self._listener = socket.create_server(("127.0.0.1", 0))
19          self.port = self._listener.getsockname()[1]
20          self._sockets = []
21          threading.Thread(target=self._accept_loop, daemon=True).start()
```

- **1–6** — Module docstring: it copies every byte both ways, like someone on the same Wi-Fi, a compromised router or an internet provider, and cannot decrypt anything.
- **8** — `socket` for listening and connecting.
- **9** — `threading` to copy both directions at once.
- **12** — The `RecordingProxy` class.
- **13** — Constructor: the real server's address.
- **14** — Remember it.
- **15** — Bytes sent from client to server are recorded here…
- **16** — …and bytes sent back here.
- **17** — A lock, since two copying threads add to the recordings.
- **18** — Listen on a free local port.
- **19** — Remember that port; clients connect to it instead of the real server.
- **20** — The sockets opened, so they can be closed later.
- **21** — Start accepting connections in the background.

[`tests/mitm.py` lines 23–32](../tests/mitm.py#L23-L32)

```python
23      def _accept_loop(self):
24          while True:
25              try:
26                  client, _ = self._listener.accept()
27              except OSError:
28                  return  # listener closed
29              server = socket.create_connection(self.target)
30              self._sockets += [client, server]
31              threading.Thread(target=self._pump, args=(client, server, self.client_to_server), daemon=True).start()
32              threading.Thread(target=self._pump, args=(server, client, self.server_to_client), daemon=True).start()
```

- **23** — `_accept_loop` handles incoming clients.
- **24** — Forever…
- **25–28** — …accept a client; when the listener is closed, stop.
- **29** — Open a matching connection to the real server.
- **30** — Remember both sockets.
- **31** — Copy client → server in one thread, recording into `client_to_server`.
- **32** — Copy server → client in another, recording into `server_to_client`.

[`tests/mitm.py` lines 34–50](../tests/mitm.py#L34-L50)

```python
34      def _pump(self, src, dst, record):
35          try:
36              while True:
37                  data = src.recv(65536)
38                  if not data:
39                      break
40                  with self._lock:
41                      record.extend(data)
42                  dst.sendall(data)
43          except OSError:
44              pass
45          finally:
46              for s in (src, dst):
47                  try:
48                      s.shutdown(socket.SHUT_RDWR)
49                  except OSError:
50                      pass
```

- **34** — `_pump` copies one direction.
- **35–37** — Read up to 64 KiB at a time.
- **38–39** — An empty read means that side closed.
- **40–41** — Record the bytes (under the lock).
- **42** — Forward them unchanged, so the connection works normally and neither side notices.
- **43–44** — Network errors end the copying.
- **45–50** — When either side stops, shut down both sockets so the other direction ends too.

[`tests/mitm.py` lines 52–63](../tests/mitm.py#L52-L63)

```python
52      @property
53      def everything(self) -> bytes:
54          with self._lock:
55              return bytes(self.client_to_server) + bytes(self.server_to_client)
56  
57      def close(self):
58          self._listener.close()
59          for s in self._sockets:
60              try:
61                  s.close()
62              except OSError:
63                  pass
```

- **52–55** — `everything` returns all captured bytes from both directions as one block.
- **57** — `close`.
- **58** — Stop accepting.
- **59–63** — Close every socket, ignoring ones already closed.

## 5.3 What each automated test proves

70 tests in three files. Each end-to-end test starts a real TLS server on a free port with
a temporary database and talks to it over real sockets.

### `tests/test_security.py` (25 tests): each protection works

| Test | What it proves |
|---|---|
| `test_same_password_gets_different_salts_and_hashes` | Equal passwords produce different stored records (unique salts) |
| `test_verify` | The right password verifies; a wrong one does not |
| `test_client_login_hash` | The login hash is the same on every device, differs per username and per password, and is never the password itself |
| `test_record_contains_no_plaintext` | A stored record contains no trace of the password |
| `KeyFileTests.test_round_trip` | Keys saved to the encrypted file come back identical |
| `test_wrong_password_cannot_unlock` | The key file refuses a wrong password |
| `test_file_has_no_plaintext_private_key` | The key file contains no readable private key |
| `MessageCryptoTests.test_round_trip` | Encrypt + sign, then verify + decrypt, gives back the text |
| `test_fresh_key_and_nonce_every_message` | Two messages with the same text differ in nonce, wrapped key, ciphertext and ID |
| `test_every_signed_field_is_protected` | Changing **any** of the 7 signed fields makes the signature check fail |
| `test_only_recipient_can_unwrap` | Another user's private key cannot unwrap the AES key |
| `test_1_bob_to_alice` | Required scenario 1: a message arrives intact, from the right sender |
| `test_2_server_stores_only_ciphertext` | Required scenario 2: the database contains no message text, no password, no private key |
| `test_3_tampered_ciphertext_is_rejected` | Required scenario 3: one flipped bit → rejected |
| `test_4a_server_refuses_sender_spoofing` | The server refuses a package whose `sender` isn't the logged-in user |
| `test_4b_alice_rejects_eve_signing_as_bob` | Required scenario 4: even planted by a compromised server, Eve's forgery is rejected |
| `test_5a_server_rejects_duplicate_message_id` | Required scenario 5: the server refuses a replayed ID |
| `test_5b_client_rejects_redelivered_message` | The client rejects a replay the server delivers anyway |
| `test_5c_replay_detection_survives_restart_of_client` | The seen-ID list is saved, so a restarted client still catches the replay |
| `test_6_login_failures_look_identical` | Required scenario 6: wrong password, unknown user and empty password give the identical message |
| `test_6b_users_requires_login` | The directory cannot be fetched without logging in |
| `test_7a_stolen_hash_cannot_log_in` | Required scenario 7a: the stolen hash or salt fails, through the client and sent raw to the server |
| `test_7b_stolen_messages_cannot_be_read` | Required scenario 7b: no private key in the database; only Alice's key can unwrap |
| `test_8_server_never_receives_the_password` | Every request the server received during signup, login and a failed login is searched: the password never appears |
| `test_9_failed_logins_are_not_logged` | A password typed as a username never reaches the server log |

### `tests/test_tls.py` (9 tests): the network attacker

| Test | What it proves |
|---|---|
| `test_eavesdropper_sees_nothing_useful` | A full signup, login, directory fetch and message, all recorded: no password, login hash, username, field name, public key or text appears in the bytes |
| `test_replaying_recorded_traffic_logs_nobody_in` | Replaying the recorded login bytes delivers **zero** requests to the application |
| `test_fake_server_with_its_own_certificate_is_refused` | A complete fake server with its own CA's certificate is refused with a security warning |
| `test_certificate_for_another_host_is_refused` | A certificate for a different host name is refused |
| `test_plain_text_server_is_refused` | A non-TLS server is refused, and it receives only a TLS greeting, never a request |
| `test_old_tls_versions_are_refused` | TLS 1.2 is refused by the server |
| `test_connection_uses_tls13` | The negotiated version is TLS 1.3 |
| `test_missing_or_bad_ca_file` | A missing or junk `ca.crt` gives a clear error |
| `test_ca_private_key_is_not_kept` | The TLS folder holds exactly `ca.crt`, `server.crt`, `server.key`, and no CA private key |

### `tests/test_edge_cases.py` (36 tests): extreme and hostile input

| Group | Tests | What they prove |
|---|---|---|
| Protocol abuse | `test_garbage_inputs`, `test_oversized_request_is_refused`, `test_blank_lines_and_many_requests_on_one_connection`, `test_abrupt_disconnects`, `test_plain_text_client_is_refused_and_server_survives`, `test_silent_connection_is_dropped_after_handshake_timeout`, `test_message_ids_must_be_hex_so_logs_cannot_be_forged`, `test_username_with_trailing_newline_is_refused`, `test_signup_rejects_fake_public_keys`, `test_send_with_absurd_field_values` | Non-JSON, bad UTF-8, deep nesting, wrong types, huge numbers, over-size requests, half-sent requests and handshakes, plain-text clients, silent clients and fake keys all get an error or are dropped, and the server keeps serving. Message IDs that aren't 32 hex characters (including the V1 attack ID with a newline and an escape code) and usernames ending in a newline are refused by both server and client, and nothing injected reaches the server log or the verbose trace |
| Message content | `test_unicode_thai_emoji_and_rtl`, `test_single_character_and_whitespace`, `test_largest_allowed_message`, `test_too_long_message_is_refused_before_sending`, `test_message_cannot_fake_extra_chat_lines`, `test_validly_signed_garbage_is_rejected_cleanly`, `test_message_to_yourself_is_refused`, `test_send_to_unknown_user` | Any language and emoji round-trip exactly; size limits hold; display injection is neutralized; junk signed by a real user is rejected without crashing |
| Crypto boundaries | `test_future_timestamp_rejected`, `test_message_for_someone_else_rejected`, `test_signature_wrong_length_or_garbage`, `test_empty_and_huge_passwords_for_key_file` | The receiver's time, recipient and signature-format checks; the key file works with any password |
| Accounts and files | `test_invalid_usernames_fail_fast_without_keygen`, `test_short_password_fails_fast`, `test_duplicate_username`, `test_long_and_unicode_passwords`, `test_corrupted_local_files_give_clear_errors`, `test_login_from_a_device_without_keys`, `test_commands_before_login`, `test_logout_then_commands` | Fast local validation, password limits, damaged files handled, keys required on the device |
| Load | `test_many_users_sending_at_once`, `test_many_simultaneous_logins`, `test_inbox_poller_and_sender_share_one_connection` | 200 simultaneous messages all arrive exactly once; 20 parallel logins; chat mode's two threads share one connection safely |
| Failures | `test_server_restart`, `test_sender_clock_far_off`, `test_database_wiped_and_name_reregistered_by_someone_else` | A killed server is reported clearly; messages and replay IDs survive restart; clock skew is explained; pinned keys catch an impostor re-registering a name |
