# 5. Demo and tests

[← The client](04-client.md) · [Index](README.md) · Next: [Security analysis →](06-security-analysis.md)

- [5.1 `demo.py`, line by line](#51-demopy-line-by-line): the nine-scenario presentation
- [5.2 `tests/mitm.py`, line by line](#52-testsmitmpy-line-by-line): the eavesdropping proxy
- [5.3 What each automated test proves](#53-what-each-automated-test-proves): all 79 tests

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
 3  Run:  py demo.py            (all nine scenarios)
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

[`demo.py` lines 108–131](../demo.py#L108-L131)

```python
108          # ------------------------------------------------------------ 2
109          banner("2. SERVER VIEW: what the server actually stores")
110          bob.send("alice", "Lunch at noon? The meeting room is booked.")  # waiting, so it is still stored
111          with open(db_path, encoding="utf-8") as f:
112              db = json.load(f)
113          print("  users table (alice):")
114          rec = db["users"]["alice"]
115          print(f"    password: {json.dumps(rec['password'])}")
116          print(f"    enc_public_pem:  {rec['enc_public_pem'].splitlines()[1][:50]}...  (public, not secret)")
117          print(f"    sign_public_pem: {rec['sign_public_pem'].splitlines()[1][:50]}...  (public, not secret)")
118          print("  messages table (first message):")
119          pkg = db["messages"][0]["package"]
120          for k, v in pkg.items():
121              text = str(v)
122              print(f"    {k:<12} {text[:60]}{'...' if len(text) > 60 else ''}")
123          raw = json.dumps(db)
124          print(f"\n  Does the word 'meeting' appear anywhere in the database?  {'meeting' in raw}")
125          print(f"  Does the word 'Lunch' appear anywhere in the database?  {'Lunch' in raw}")
126          print("  Does any password appear in it?  "
127                f"{any(p in raw for p in PASSWORDS.values())}")
128          print("  Server keeps: salted hashes, public keys, ciphertext, and metadata (who, to whom, when).")
129          alice.inbox()  # Alice reads it; the server deletes delivered messages at once (retention)
130          with open(db_path, encoding="utf-8") as f:
131              print(f"  After Alice reads it, messages stored on the server: {len(json.load(f)['messages'])}")
```

- **108–109** — Title.
- **110** — Bob sends a fresh message that Alice has not read yet. Delivered messages are deleted from the server (retention), so this one is what we can look at.
- **111–112** — Read the server's database file directly, as the operator could.
- **113–117** — Print Alice's user record: the password record (algorithm, costs, salt, hash) and the start of each public key.
- **118–122** — Print each field of the first stored message, cut to 60 characters.
- **123** — The whole database as one string.
- **124–125** — Do the words "meeting" or "Lunch" from Bob's waiting message appear anywhere? (They don't: the text is encrypted.)
- **126–127** — Does any of the three passwords appear? (None does.)
- **128** — Summary of what the server does see.
- **129** — Alice reads the message, and the server deletes it at once (retention).
- **130–131** — Count the messages left on the server: 0.

### Scenario 3: tampering

[`demo.py` lines 133–153](../demo.py#L133-L153)

```python
133          # ------------------------------------------------------------ 3
134          banner("3. TAMPERING TEST: flip one byte of the ciphertext in transit")
135          pkg = bob.build_package("alice", "Pay invoice #1001: 500 baht")
136          ct = bytearray(b64d(pkg["ciphertext"]))
137          print(f"   mitm | original ciphertext byte 0: {ct[0]:#04x}")
138          ct[0] ^= 0x01
139          print(f"   mitm | modified ciphertext byte 0: {ct[0]:#04x}")
140          tampered = dict(pkg, ciphertext=base64.b64encode(bytes(ct)).decode())
141          bob.send_package(tampered)  # the server cannot tell; it cannot read the content
142          print("   mitm | tampered package delivered to the server (server cannot detect it)")
143          alice.trace = step_printer("alice")
144          for r in alice.inbox():
145              show_result(r)
146          alice.trace = quiet
147          print("\n  Second line of defence: even if Alice skipped the signature check,")
148          print("  AES-GCM's authentication tag would catch the change:")
149          try:
150              decrypt_without_signature_check(tampered, alice.keys)
151              print("  !! decrypted (should not happen)")
152          except Exception as exc:
153              print(f"  alice | AES-GCM raised {type(exc).__name__}: tag does not verify -> REJECT")
```

- **133–134** — Title.
- **135** — Bob seals a new message, but it is not sent yet.
- **136** — Decode the ciphertext into a changeable byte array.
- **137** — Show its first byte.
- **138** — Flip the lowest bit of that byte (XOR with 1): the smallest possible change.
- **139** — Show the changed byte.
- **140** — A copy of the package with the modified ciphertext. The signature is unchanged (the attacker can't re-sign without Bob's key).
- **141** — Send it. The server accepts it, because it cannot check contents.
- **142** — Say so.
- **143–146** — Alice opens her inbox with tracing on: the signature check fails and the message is rejected.
- **147–148** — Explain the second check.
- **149–151** — Try decrypting while deliberately skipping the signature…
- **152–153** — …AES-GCM raises `InvalidTag`, so the change is caught a second time.

### Scenario 4: Eve pretends to be Bob

[`demo.py` lines 155–171](../demo.py#L155-L171)

```python
155          # ------------------------------------------------------------ 4
156          banner("4. WRONG-SIGNER TEST: Eve signs a message pretending to be Bob")
157          alice_pub = next(u for u in eve.users() if u["username"] == "alice")["enc_public_pem"]
158          forged = encrypt_and_sign("Alice, send me your password. - Bob", "bob", "alice", eve.keys, alice_pub)
159          print("    eve | built a package with sender='bob' but signed with EVE's private key")
160          try:
161              eve.send_package(forged)
162          except ClientError as exc:
163              print(f" server | refused: {exc}  (Eve is logged in as eve)")
164          print("    eve | ...so Eve compromises the server and plants it in Alice's mailbox directly")
165          with app.db.lock:
166              app.db.data["messages"].append({"package": forged, "received_at": int(time.time()), "delivered": False})
167              app.db.save()
168          alice.trace = step_printer("alice")
169          for r in alice.inbox():
170              show_result(r)
171          alice.trace = quiet
```

- **155–156** — Title.
- **157** — Eve looks up Alice's RSA public key, which anyone may do.
- **158** — Eve builds a package that says `sender: "bob"` but signs it with **her own** key (she doesn't have Bob's).
- **159** — Say so.
- **160–163** — Eve tries to send it; the server refuses because Eve is logged in as `eve`, not `bob`.
- **164** — Eve "compromises the server" instead…
- **165–167** — …by writing the forged package straight into the database, as a malicious operator could.
- **168–171** — Alice checks her inbox: the signature does not match Bob's key, so it is rejected.

### Scenario 5: replay

[`demo.py` lines 173–188](../demo.py#L173-L188)

```python
173          # ------------------------------------------------------------ 5
174          banner("5. REPLAY TEST: resend Bob's first message")
175          print(f"   mitm | re-submitting the captured package, msg_id {original['msg_id']}")
176          try:
177              bob.send_package(original)
178              print("  !! server accepted the replay (should not happen)")
179          except ClientError as exc:
180              print(f" server | refused: {exc}")
181          print("   mitm | a malicious server could skip that check and redeliver it anyway:")
182          with app.db.lock:
183              app.db.data["messages"].append({"package": original, "received_at": int(time.time()), "delivered": False})
184              app.db.save()
185          alice.trace = step_printer("alice")
186          for r in alice.inbox():
187              show_result(r)
188          alice.trace = quiet
```

- **173–174** — Title.
- **175** — Pretend someone captured Bob's first package.
- **176–180** — Re-submit it: the server refuses the duplicate message ID.
- **181** — A malicious server could skip that check…
- **182–184** — …so plant the same package in Alice's mailbox again.
- **185–188** — Alice's client recognizes the ID from `seen_ids` and rejects it.

### Scenario 6: wrong password

[`demo.py` lines 190–205](../demo.py#L190-L205)

```python
190          # ------------------------------------------------------------ 6
191          banner("6. WRONG PASSWORD TEST: the error never says which field was wrong")
192          for label, user, pw in [
193              ("right user, wrong password", "alice", "not-alices-password"),
194              ("unknown user", "mallory", "whatever-password"),
195          ]:
196              c = new_client("guest")
197              t0 = time.perf_counter()
198              try:
199                  c.login(user, pw)
200                  print("  !! login succeeded (should not happen)")
201              except ClientError as exc:
202                  ms = (time.perf_counter() - t0) * 1000
203                  print(f"  {label:<28} -> \"{exc}\"  ({ms:.0f} ms)")
204              c.close()
205          print("  Same message, similar time: an attacker cannot learn whether 'alice' exists.")
```

- **190–191** — Title.
- **192–195** — Two attempts: Alice with the wrong password, and a user who doesn't exist.
- **196** — A fresh client for each attempt.
- **197** — Start a timer.
- **198–200** — Try to log in (it must fail).
- **201–203** — Print the error message and how long it took.
- **204** — Close.
- **205** — The point: same message, similar time.

### Scenario 7: the database is stolen

[`demo.py` lines 207–224](../demo.py#L207-L224)

```python
207          # ------------------------------------------------------------ 7
208          banner("7. DATABASE LEAK TEST: an attacker steals db.json")
209          bob.send("alice", "Bank PIN reminder: do not share it")  # a message waiting on the server when it is stolen
210          with open(db_path, encoding="utf-8") as f:
211              stolen = json.load(f)
212          stored = stolen["users"]["alice"]["password"]
213          print("  a) Log in using the stolen hash (or salt+hash) as the password:")
214          for attempt in (stored["hash"], stored["salt"] + "$" + stored["hash"], json.dumps(stored)):
215              c = new_client("thief")
216              try:
217                  c.login("alice", attempt)
218                  print("  !! login succeeded (should not happen)")
219              except ClientError as exc:
220                  print(f"     tried {attempt[:40]!r:<44} -> {exc}")
221              c.close()
222          print("     The server hashes whatever it receives; a hash of a hash never matches.")
223          print("     To get in, the attacker must guess the real password, and each scrypt guess")
224          print("     costs ~32 MiB of memory and real time.")
```

- **207–208** — Title.
- **209** — Bob sends a message that is still waiting on the server when the thief copies the database.
- **210–211** — Read the database file as a thief would.
- **212** — Alice's password record.
- **213** — Part (a).
- **214** — Try logging in with the stored hash, with salt and hash joined, and with the whole record.
- **215–221** — Each attempt goes through the normal client (which hashes it as if it were a password) and fails.
- **222–224** — Why: the server hashes whatever it receives, so a stolen hash is just another wrong password, and guessing the real password costs a full scrypt per guess.

[`demo.py` lines 226–242](../demo.py#L226-L242)

```python
226          print("\n  b) Read the stolen messages:")
227          msg = stolen["messages"][0]["package"]
228          print(f"     ciphertext (base64): {msg['ciphertext'][:60]}...")
229          print("     The server never had a private key, so the database contains none.")
230          print("     Try unwrapping the AES key with some other private key (Eve's):")
231          try:
232              eve.keys.enc_private.decrypt(b64d(msg["wrapped_key"]), OAEP)
233              print("  !! unwrapped (should not happen)")
234          except ValueError:
235              print("     RSA-OAEP decryption failed -> AES key stays secret -> message stays secret")
236          print("     Try a fresh random key pair (what an attacker without Alice's device has):")
237          try:
238              UserKeys.generate().enc_private.decrypt(b64d(msg["wrapped_key"]), OAEP)
239              print("  !! unwrapped (should not happen)")
240          except ValueError:
241              print("     RSA-OAEP decryption failed again.")
242          print("     Only Alice's private key works, and it lives encrypted on her device.")
```

- **226** — Part (b).
- **227–228** — Take the first stored message and show its ciphertext.
- **229** — Note that the database contains no private keys.
- **230–235** — Try to unwrap the AES key with Eve's private key: RSA-OAEP fails.
- **236–241** — Try again with a freshly generated key pair: fails again.
- **242** — Only Alice's key, on Alice's device, works.

### Scenario 8: eavesdropping and a fake server

[`demo.py` lines 244–265](../demo.py#L244-L265)

```python
244          # ------------------------------------------------------------ 8
245          banner("8. EAVESDROPPER TEST: someone records all network traffic (TLS 1.3)")
246          proxy = RecordingProxy(host, port)
247          print(f"   spy | recording every byte between Bob and the server (proxy port {proxy.port})")
248          bob2 = ChatClient("127.0.0.1", proxy.port, os.path.join(workdir, "device-bob"),
249                            trace=quiet, ca_file=srv.ca_file)
250          print(f"   bob | connected: {bob2.conn.tls_version}, {bob2.conn.cipher}, server certificate verified")
251          bob2.login("bob", PASSWORDS["bob"])
252          bob2.send("alice", "Secret plan: launch on Friday")
253          bob2.close()
254          time.sleep(0.3)
255          seen = proxy.everything
256          proxy.close()
257          print(f"   spy | captured {len(seen)} bytes; first 48 as hex: {seen[5:53].hex()}")
258          login_hash = client_password_hash("bob", PASSWORDS["bob"])
259          for label, needle in [("Bob's password", PASSWORDS["bob"]), ("Bob's login hash", login_hash),
260                                ("the word 'password_hash'", "password_hash"), ("the username 'bob'", "bob"),
261                                ("the recipient 'alice'", "alice"), ("the message text", "Secret plan")]:
262              print(f"   spy | can I find {label + '?':<28} {needle.encode() in seen}")
263          print("        |     Without TLS, the login hash would be readable here and could be replayed")
264          print("        |     to log in as Bob. With TLS the spy only has random-looking bytes, and")
265          print("        |     replaying them fails because every TLS 1.3 connection uses fresh keys.")
```

- **244–245** — Title.
- **246** — Start a recording proxy in front of the real server.
- **247** — Say what it does.
- **248–249** — Bob connects **through the proxy** (same device folder, so his keys are there).
- **250** — Show the TLS version and cipher, and that the certificate was verified.
- **251** — Bob logs in through the proxy.
- **252** — Bob sends a message through the proxy.
- **253** — Disconnect.
- **254** — Give the proxy a moment to finish copying.
- **255** — Everything the proxy saw, in both directions.
- **256** — Stop the proxy.
- **257** — Print how many bytes were captured and a sample in hex: unreadable.
- **258** — Compute Bob's login hash, to search for it.
- **259–262** — Search the capture for the password, the login hash, the field name, both usernames and the message text, and print the result (all `False`).
- **263–265** — Explain why this matters: without TLS the login hash could be copied and replayed.

[`demo.py` lines 267–280](../demo.py#L267-L280)

```python
267          print("\n   spy | now pretending to BE the server, with a certificate from my own CA:")
268          fake_dir = os.path.join(workdir, "attacker-tls")
269          fake_paths = generate_server_tls(fake_dir, ("localhost", "127.0.0.1"))
270          fake = ThreadedServer(("127.0.0.1", 0), ChatApp(os.path.join(fake_dir, "db.json")),
271                                server_context(fake_paths["cert"], fake_paths["key"]))
272          threading.Thread(target=fake.serve_forever, daemon=True).start()
273          try:
274              ChatClient("127.0.0.1", fake.server_address[1], os.path.join(workdir, "device-bob"),
275                         trace=quiet, ca_file=srv.ca_file)
276              print("  !! connected to the fake server (should not happen)")
277          except ConnectionError_ as exc:
278              print(f"   bob | {exc}")
279          finally:
280              fake.stop()
```

- **267** — Now the spy pretends to **be** the server.
- **268** — A folder for the attacker's certificates.
- **269** — The attacker makes their own CA and a certificate for `localhost`/`127.0.0.1`, valid as far as the attacker is concerned.
- **270–271** — A complete chat server using the attacker's certificate.
- **272** — Run it in the background.
- **273–275** — Bob tries to connect to it, trusting only the real CA.
- **276** — If that worked it would be a failure of the design (it doesn't).
- **277–278** — The client refuses with its security warning, before sending anything.
- **279–280** — Stop the fake server.

### Scenario 9: privacy mechanisms

[`demo.py` lines 282–299](../demo.py#L282-L299)

```python
282          # ------------------------------------------------------------ 9
283          banner("9. PRIVACY: pseudonymous logs, access to my data, erasure")
284          pseudo = app.pseudo
285          print("   log | the server log never shows names or IP addresses, only keyed pseudonyms:")
286          for name in ("alice", "bob", "eve"):
287              print(f"        |     {name:<5} appears in the log as {pseudo.user(name)}")
288          print(f"        |     127.0.0.1 appears in the log as {pseudo.ip('127.0.0.1')}")
289          print("        |     only the holder of server_data/privacy/log_key can map them back")
290          print(f"        |     (conditional re-identification): {pseudo.user('bob')} -> "
291                f"{pseudo.reidentify(pseudo.user('bob'), ['alice', 'bob', 'eve'])}")
292          data = eve.mydata()
293          print("    eve | mydata (right of access, as JSON):")
294          for key in ("username", "consent", "messages_waiting_for_you", "retention", "log_pseudonym"):
295              print(f"        |     {key}: {data[key]}")
296          eve.delete_account(PASSWORDS["eve"])
297          print("    eve | delete_account: account, waiting messages and local keys erased")
298          with open(db_path, encoding="utf-8") as f:
299              print(f" server | is 'eve' still in the database?  {'eve' in json.load(f)['users']}")
```

- **282–283** — Title.
- **284** — The server's log pseudonymizer.
- **285** — Explain what the log shows.
- **286–287** — Show the pseudonym each user appears under in the log.
- **288** — Show the pseudonym for the IP address `127.0.0.1`.
- **289** — Only the holder of the secret log key can map pseudonyms back.
- **290–291** — Demonstrate conditional re-identification: with the key and the list of users, Bob's pseudonym maps back to `bob`.
- **292** — Eve asks for everything the server stores about her (right of access).
- **293–295** — Print the main fields: username, consent record, waiting messages, retention rule and her log pseudonym.
- **296** — Eve erases her account (right to erasure), re-confirming with her password.
- **297** — Say what was erased.
- **298–299** — Read the database again: `eve` is gone.

[`demo.py` lines 301–310](../demo.py#L301-L310)

```python
301          banner("DONE: all nine scenarios behaved as expected")
302      finally:
303          for c in list(locals().get("clients", {}).values()):
304              c.close()
305          srv.stop()
306          shutil.rmtree(workdir, ignore_errors=True)
307  
308  
309  if __name__ == "__main__":
310      main()
```

- **301** — Final banner.
- **302** — Cleanup, run even if a scenario failed.
- **303–304** — Close every client.
- **305** — Stop the server.
- **306** — Delete the temporary folder.
- **309–310** — Run `main()` when executed as a program.

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

79 tests in four files. Each end-to-end test starts a real TLS server on a free port with
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

### `tests/test_privacy.py` (9 tests): personal data handling

| Test | What it proves |
|---|---|
| `test_server_log_has_no_usernames_or_ip_addresses` | After signups, logins, a message and a failed login, the captured server log contains no username and no IP address, only their pseudonyms |
| `test_reidentification_needs_the_key` | The key holder maps a pseudonym back to the name; a different key cannot; pseudonyms stay the same after a restart |
| `test_reidentify_command` | `py -m server.reidentify` finds the user with the real key, and finds nothing without it |
| `test_delivered_messages_are_deleted_from_the_server` | A message disappears from the database once read; only its random ID remains, so a replay is still refused |
| `test_undelivered_messages_expire_after_retention_period` | A message just inside 30 days is kept; just past 30 days it is deleted |
| `test_privacy_notice_is_available_before_login` | The notice can be read without an account and covers what, why, how long and rights |
| `test_signup_requires_accepting_the_current_notice` | Signup without consent, or with an old notice version, stores nothing; a normal signup records the version |
| `test_mydata_shows_my_data_but_not_the_password_hash` | `mydata` returns the caller's own data and counts, never the stored hash or salt, nothing about other people, and needs a login |
| `test_delete_account_erases_everything` | A wrong password erases nothing; the right one removes the account, messages to and from it and the local key folder, and the account can no longer log in |

### `tests/test_edge_cases.py` (36 tests): extreme and hostile input

| Group | Tests | What they prove |
|---|---|---|
| Protocol abuse | `test_garbage_inputs`, `test_oversized_request_is_refused`, `test_blank_lines_and_many_requests_on_one_connection`, `test_abrupt_disconnects`, `test_plain_text_client_is_refused_and_server_survives`, `test_silent_connection_is_dropped_after_handshake_timeout`, `test_message_ids_must_be_hex_so_logs_cannot_be_forged`, `test_username_with_trailing_newline_is_refused`, `test_signup_rejects_fake_public_keys`, `test_send_with_absurd_field_values` | Non-JSON, bad UTF-8, deep nesting, wrong types, huge numbers, over-size requests, half-sent requests and handshakes, plain-text clients, silent clients and fake keys all get an error or are dropped, and the server keeps serving. Message IDs that aren't 32 hex characters (including the V1 attack ID with a newline and an escape code) and usernames ending in a newline are refused by both server and client, and nothing injected reaches the server log or the verbose trace |
| Message content | `test_unicode_thai_emoji_and_rtl`, `test_single_character_and_whitespace`, `test_largest_allowed_message`, `test_too_long_message_is_refused_before_sending`, `test_message_cannot_fake_extra_chat_lines`, `test_validly_signed_garbage_is_rejected_cleanly`, `test_message_to_yourself_is_refused`, `test_send_to_unknown_user` | Any language and emoji round-trip exactly; size limits hold; display injection is neutralized; junk signed by a real user is rejected without crashing |
| Crypto boundaries | `test_future_timestamp_rejected`, `test_message_for_someone_else_rejected`, `test_signature_wrong_length_or_garbage`, `test_empty_and_huge_passwords_for_key_file` | The receiver's time, recipient and signature-format checks; the key file works with any password |
| Accounts and files | `test_invalid_usernames_fail_fast_without_keygen`, `test_short_password_fails_fast`, `test_duplicate_username`, `test_long_and_unicode_passwords`, `test_corrupted_local_files_give_clear_errors`, `test_login_from_a_device_without_keys`, `test_commands_before_login`, `test_logout_then_commands` | Fast local validation, password limits, damaged files handled, keys required on the device |
| Load | `test_many_users_sending_at_once`, `test_many_simultaneous_logins`, `test_inbox_poller_and_sender_share_one_connection` | 200 simultaneous messages all arrive exactly once; 20 parallel logins; chat mode's two threads share one connection safely |
| Failures | `test_server_restart`, `test_sender_clock_far_off`, `test_database_wiped_and_name_reregistered_by_someone_else` | A killed server is reported clearly; messages and replay IDs survive restart; clock skew is explained; pinned keys catch an impostor re-registering a name |
