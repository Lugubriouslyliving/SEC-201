# 3. The server, line by line

[← crypto_utils](02-crypto-utils.md) · [Index](README.md) · Next: [The client →](04-client.md)

The server is a relay. It checks who you are, hands out public keys, and stores and
forwards sealed packages. It has no private key for any user and never decrypts a
message.

| File | Job |
|---|---|
| [`storage.py`](#31-storagepy) | The JSON database file and its lock |
| [`server.py`](#32-serverpy) | TLS connections, the request loop, the six chat actions and three privacy-rights actions |
| [`privacy.py`](#33-privacypy) | Pseudonymous logging, retention, and the privacy notice |
| [`reidentify.py`](#34-reidentifypy) | Conditional re-identification of a log pseudonym (key holder only) |

[`server/__init__.py` lines 1–1](../server/__init__.py#L1-L1)

```python
1  """Centralized relay server: authenticates users, stores public keys, stores and forwards ciphertext."""
```

- **1** — Package docstring. Its presence makes `server` a Python package, so it can be run as `py -m server.server`.

## 3.1 `storage.py`

[`server/storage.py` lines 1–20](../server/storage.py#L1-L20)

```python
 1  """The server's database: one JSON file, readable on purpose.
 2  
 3  Keeping it as plain JSON makes the "server view" demo easy: open the file
 4  and see for yourself that it holds only salted hashes, public keys and
 5  ciphertext.
 6  
 7  Layout:
 8      {
 9        "users": {
10          "alice": {
11            "password": {"algorithm": "scrypt", "n":..., "salt": "...", "hash": "..."},
12            "enc_public_pem": "-----BEGIN PUBLIC KEY-----...",
13            "sign_public_pem": "-----BEGIN PUBLIC KEY-----...",
14            "created": 1763450000
15          }
16        },
17        "messages": [ {"package": {...}, "received_at": ..., "delivered": false} ],
18        "seen_msg_ids": ["..."]
19      }
20  """
```

- **1–20** — Module docstring: the database is plain JSON on purpose, so you can open it and see it holds only salted hashes, public keys and ciphertext; it also shows the layout.

[`server/storage.py` lines 22–38](../server/storage.py#L22-L38)

```python
22  import json
23  import os
24  import threading
25  
26  
27  class Storage:
28      def __init__(self, path: str):
29          self.path = path
30          self.lock = threading.RLock()  # one client thread at a time touches the data
31          if os.path.exists(path):
32              with open(path, "r", encoding="utf-8") as f:
33                  self.data = json.load(f)
34          else:
35              self.data = {"users": {}, "messages": [], "seen_msg_ids": []}
36              self.save()
37          # A set gives fast duplicate checks; the list form is what gets saved.
38          self.seen = set(self.data["seen_msg_ids"])
```

- **22** — `json` to read and write the file.
- **23** — `os` for paths and the atomic rename.
- **24** — `threading` for the lock.
- **27** — `Storage` wraps the database.
- **28** — The constructor receives the file path.
- **29** — Remember it.
- **30** — A re-entrant lock (`RLock`). Every request runs in its own thread, so two users could change the data at the same moment; holding this lock makes each change happen one at a time. "Re-entrant" means a thread already holding it can take it again (`save` does this) without blocking itself.
- **31–33** — If the file exists, load it.
- **34–36** — Otherwise start empty (no users, no messages, no seen IDs) and write the file at once.
- **37** — Comment.
- **38** — Copy the seen message IDs into a Python `set`, which answers "seen before?" instantly however many IDs there are. The list is what gets saved; the set is for speed.

[`server/storage.py` lines 40–48](../server/storage.py#L40-L48)

```python
40      def save(self) -> None:
41          """Write to a temp file, then rename: a crash never leaves half a file."""
42          with self.lock:
43              folder = os.path.dirname(os.path.abspath(self.path))
44              os.makedirs(folder, exist_ok=True)
45              tmp = self.path + ".tmp"
46              with open(tmp, "w", encoding="utf-8") as f:
47                  json.dump(self.data, f, indent=2)
48              os.replace(tmp, self.path)
```

- **40** — `save` writes the whole database.
- **41** — Docstring.
- **42** — Take the lock so nobody changes the data while it is written.
- **43–44** — Make sure the folder exists.
- **45** — Write to a temporary file next to the real one…
- **46–47** — …as indented JSON (readable by a person).
- **48** — …then `os.replace` renames it over the real file in one step. If the server crashes mid-write, the old file is still intact, never a half-written one.

## 3.2 `server.py`

### Module header, imports and settings

[`server/server.py` lines 1–23](../server/server.py#L1-L23)

```python
 1  """The relay server.
 2  
 3  What it does:
 4    * signup / login with salted, slow password hashes (scrypt)
 5    * hands out the list of users and their PUBLIC keys
 6    * accepts sealed message packages, stores them exactly as received,
 7      and delivers them when the recipient asks for their inbox
 8  
 9  What it never does:
10    * hold any private key
11    * decrypt anything (it has no key that could)
12    * store or log a plaintext password
13  
14  Protocol: TLS 1.3 over TCP, one JSON object per line (UTF-8, terminated
15  by "\\n"). See README.md, section "Protocol". On first start the server
16  creates its TLS certificates in server_data/tls (see crypto_utils/tls.py);
17  clients need a copy of server_data/tls/ca.crt.
18  
19  Robustness rule: whatever a client sends, the server answers with an error
20  and keeps running. One bad request never affects other users.
21  
22  Run:  py -m server.server --port 5050
23  """
```

- **1–23** — Module docstring: what the server does, what it never does (hold a private key, decrypt, store or log a password), the protocol, the robustness rule, and how to run it.

[`server/server.py` lines 25–45](../server/server.py#L25-L45)

```python
25  import argparse
26  import json
27  import logging
28  import os
29  import re
30  import socket
31  import socketserver
32  import ssl
33  import sys
34  import threading
35  import time
36  
37  from crypto_utils.keys import load_enc_public, load_sign_public
38  from crypto_utils.passwords import DUMMY_RECORD, hash_password, is_login_hash, verify_password
39  from crypto_utils.tls import DEFAULT_HOSTNAMES, certificate_fingerprint, ensure_server_tls, server_context
40  
41  from .privacy import PRIVACY_NOTICE, PRIVACY_NOTICE_VERSION, RETENTION_DAYS, Pseudonymizer, purge_expired
42  from .storage import Storage
43  
44  log = logging.getLogger("server")
45  log.addHandler(logging.NullHandler())  # silent unless main() configures logging
```

- **25** — `argparse` for command-line options.
- **26** — `json` for requests and replies.
- **27** — `logging` for the operator's console messages.
- **28** — `os` for paths.
- **29** — `re` for the username pattern.
- **30** — `socket` for low-level socket shutdown.
- **31** — `socketserver` provides the TCP server and per-connection handler classes.
- **32** — `ssl` for TLS.
- **33** — `sys` for `exit` and the current exception.
- **34** — `threading` for locks and the background thread.
- **35** — `time` for timestamps.
- **37** — Public-key parsers, used to check keys at signup.
- **38** — Password functions: the dummy record, hashing, the login-hash shape check, verification.
- **39** — TLS helpers.
- **41** — The privacy pieces from section 3.3: the notice and its version, the retention period, the log pseudonymizer and the retention purge.
- **42** — The database class from section 3.1.
- **44** — A logger named `server`.
- **45** — A `NullHandler` so that, when the server is used inside tests or the demo, nothing is printed unless logging is switched on (`main()` switches it on).

[`server/server.py` lines 47–59](../server/server.py#L47-L59)

```python
47  USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
48  MAX_LINE = 1_000_000          # bytes; a request bigger than this is refused
49  MSG_ID_RE = re.compile(r"[0-9a-f]{32}")  # exactly what uuid4().hex produces; nothing else is accepted
50  MIN_RSA_BITS = 2048
51  MAX_CLOCK_SKEW = 300          # seconds; package timestamps must be within this of server time
52  HANDSHAKE_TIMEOUT = 15        # seconds a new connection gets to complete the TLS handshake
53  GENERIC_LOGIN_ERROR = "Invalid username or password."  # same text for every login failure
54  
55  # scrypt needs ~32 MiB per computation. Without a limit, 1,000 simultaneous
56  # logins would ask for ~32 GiB. At most this many run at once; the rest wait.
57  SCRYPT_SLOTS = threading.BoundedSemaphore(4)
58  
59  PACKAGE_STRING_FIELDS = ("msg_id", "sender", "recipient", "nonce", "ciphertext", "wrapped_key", "signature")
```

- **47** — Usernames: 3–20 characters, only lowercase letters, digits and `_`. `^` and `$` anchor the whole string. Keeping names this simple means they are safe in file paths and on screen.
- **48** — Requests larger than 1,000,000 bytes are refused, so nobody can make the server read unlimited data into memory.
- **49** — Message IDs must be exactly 32 lowercase hex characters (the format `uuid4().hex` produces). The pattern is used with `fullmatch`, so the whole ID must match; nothing else (no newline, no escape code) can get into the log.
- **50** — RSA public keys must be at least 2048 bits.
- **51** — Package timestamps must be within 300 s (5 minutes) of the server's clock.
- **52** — A new connection has 15 seconds to complete the TLS handshake.
- **53** — The single error text for every failed login.
- **55–56** — Comment explaining the scrypt limit.
- **57** — A semaphore with 4 slots: at most 4 scrypt computations (≈32 MiB each) run at once; others wait their turn. A burst of logins therefore cannot use up the server's memory.
- **59** — The package fields that must be strings.

### `RequestHandler`: one TLS connection

`socketserver` creates one `RequestHandler` per connection and runs `setup()`,
`handle()`, then `finish()` in that connection's own thread.

[`server/server.py` lines 62–75](../server/server.py#L62-L75)

```python
62  class RequestHandler(socketserver.StreamRequestHandler):
63      """One instance per TCP connection. A connection is one client session."""
64  
65      def setup(self):
66          # TLS handshake first, in this connection's own thread, with a time
67          # limit, so a slow or non-TLS client cannot hold up anyone else. If it
68          # fails (plain-text client, wrong protocol, someone probing the port)
69          # the connection is simply dropped.
70          self.request.settimeout(HANDSHAKE_TIMEOUT)
71          self.request.do_handshake()
72          self.request.settimeout(None)  # a logged-in user may sit idle at the prompt
73          super().setup()  # (this is what sets self.connection = self.request)
74          self.user = None  # set after a successful login/signup
75          self.server.track(self.connection)
```

- **62–63** — The class; one instance per connection, and one connection is one user session.
- **65** — `setup` runs first.
- **66–69** — Comment explaining why the handshake happens here.
- **70** — `self.request` is the TLS-wrapped socket (see `get_request`, line 292). Give it a 15-second timeout.
- **71** — Perform the TLS 1.3 handshake. If the client is not speaking TLS, is too slow, or rejects our certificate, this raises an exception, `handle_error` (line 298) logs it quietly, and the connection is dropped.
- **72** — Remove the timeout: once connected, a user may sit at the prompt as long as they like.
- **73** — The parent class's `setup` creates `self.connection`, `self.rfile` (read side) and `self.wfile` (write side).
- **74** — Not logged in yet.
- **75** — Register the connection so `stop()` can close it later.

[`server/server.py` lines 77–91](../server/server.py#L77-L91)

```python
77      def finish(self):
78          self.server.untrack(self.connection)
79          try:
80              super().finish()
81          except OSError:
82              pass  # client already gone
83  
84      def handle(self):
85          peer = self.server.app.pseudo.ip(self.client_address[0])  # never log the real IP address
86          log.info("connection from %s", peer)
87          try:
88              self._serve()
89          except OSError:
90              pass  # the client vanished mid-request (closed window, network drop): nothing to do
91          log.info("connection from %s closed", peer)
```

- **77–78** — `finish` runs last: unregister the connection.
- **79–82** — Let the parent flush and close the streams; ignore errors if the client has already gone.
- **84** — `handle` is the main body.
- **85** — The client's IP address turned into a keyed pseudonym such as `ip-eff78df829` (section 3.3). The real IP address is never written to the log.
- **86** — Log the new connection.
- **87–90** — Serve requests. An `OSError` (connection reset, closed window, network drop) just ends the session quietly.
- **91** — Log that it closed.

[`server/server.py` lines 93–111](../server/server.py#L93-L111)

```python
 93      def _serve(self):
 94          while True:
 95              line = self.rfile.readline(MAX_LINE + 1)
 96              if not line:
 97                  return  # client closed the connection
 98              if len(line) > MAX_LINE:
 99                  self._reply({"ok": False, "error": "Request too large."})
100                  return  # the rest of the oversized line is unreadable; end the session
101              if not line.strip():
102                  self._reply({"ok": False, "error": "Empty request."})
103                  continue
104              try:
105                  request = json.loads(line.decode("utf-8"))
106                  if not isinstance(request, dict):
107                      raise ValueError
108              except (ValueError, RecursionError):  # bad UTF-8, bad JSON, absurd nesting
109                  self._reply({"ok": False, "error": "Request must be one JSON object per line."})
110                  continue
111              self._reply(self.server.app.dispatch(self, request))
```

- **93–94** — `_serve`: loop over requests on this connection.
- **95** — Read one line, but at most `MAX_LINE + 1` bytes, so an endless line cannot fill memory.
- **96–97** — An empty read means the client closed the connection.
- **98–100** — If the line hit the limit, reply with an error and end the session (the rest of the oversized line can't be skipped reliably).
- **101–103** — A blank line gets an error and the loop continues.
- **104–105** — Decode UTF-8 and parse JSON.
- **106–107** — It must be a JSON object, not a list, string or number.
- **108–110** — Invalid UTF-8 or JSON (`ValueError`) and absurdly deep nesting (`RecursionError`) get an error reply; the connection stays open.
- **111** — Hand the request to the application logic and send its reply.

[`server/server.py` lines 113–115](../server/server.py#L113-L115)

```python
113      def _reply(self, obj: dict) -> None:
114          self.wfile.write(json.dumps(obj).encode("utf-8") + b"\n")
115          self.wfile.flush()
```

- **113** — `_reply` sends one JSON object.
- **114** — Serialize, encode as UTF-8, add the newline that ends the message, and write it into the TLS stream.
- **115** — Flush so it is sent now.

### `ChatApp`: the server's logic

[`server/server.py` lines 118–127](../server/server.py#L118-L127)

```python
118  class ChatApp:
119      """The server's logic, separate from the networking so it is easy to read and test."""
120  
121      def __init__(self, db_path: str):
122          self.db = Storage(db_path)
123          # The secret key for log pseudonyms lives next to the database, never in the log.
124          self.pseudo = Pseudonymizer(os.path.join(os.path.dirname(os.path.abspath(db_path)), "privacy", "log_key"))
125          with self.db.lock:  # apply the retention rule to whatever is already stored
126              if purge_expired(self.db.data):
127                  self.db.save()
```

- **118–119** — `ChatApp` holds the logic, kept separate from networking so it is easy to read and test.
- **121–122** — Open the database.
- **123–124** — Create (or load) the log pseudonymizer. Its secret key is kept in `privacy/log_key` next to the database, never in the log itself.
- **125–127** — Apply the retention rule at start-up: delete anything already delivered or older than the retention period, and save if something was removed.

[`server/server.py` lines 129–152](../server/server.py#L129-L152)

```python
129      def dispatch(self, conn: RequestHandler, req: dict) -> dict:
130          action = req.get("action")
131          handlers = {
132              "privacy_notice": self.privacy_notice,
133              "signup": self.signup,
134              "login": self.login,
135              "users": self.users,
136              "send": self.send,
137              "inbox": self.inbox,
138              "mydata": self.mydata,
139              "delete_account": self.delete_account,
140              "logout": self.logout,
141          }
142          if not isinstance(action, str) or action not in handlers:
143              return {"ok": False, "error": "Unknown action."}
144          if action in ("users", "send", "inbox", "mydata", "delete_account") and conn.user is None:
145              return {"ok": False, "error": "Please log in first."}
146          try:
147              return handlers[action](conn, req)
148          except (KeyError, TypeError, ValueError, OverflowError) as exc:
149              return {"ok": False, "error": f"Bad request ({exc.__class__.__name__})."}
150          except Exception:  # a bug in the server: log it, keep running
151              log.exception("unexpected error handling %r", action)
152              return {"ok": False, "error": "Internal server error."}
```

- **129** — `dispatch` routes one request.
- **130** — Read the `action` field (missing → `None`).
- **131–141** — The nine actions and the methods that handle them: the six chat actions plus `privacy_notice`, `mydata` and `delete_account` (section 3.2, "Privacy rights").
- **142–143** — Unknown action, or an action that isn't a string (a list or object in `action` would otherwise crash the lookup) → error.
- **144–145** — `users`, `send`, `inbox`, `mydata` and `delete_account` require this connection to be logged in. (`privacy_notice` does not: people must be able to read it before they have an account.)
- **146–147** — Call the handler.
- **148–149** — Missing fields (`KeyError`), wrong types (`TypeError`), bad values (`ValueError`) or huge numbers (`OverflowError`) become a "Bad request" reply.
- **150–152** — Anything else is a bug in the server: log the full error for the operator, give the client a generic reply, keep running.

### Signup

[`server/server.py` lines 154–178](../server/server.py#L154-L178)

```python
154      # ------------------------------------------------------------ accounts
155  
156      def signup(self, conn, req):
157          # The client never sends the password itself, only its login hash
158          # (see crypto_utils/passwords.py). Password rules such as minimum
159          # length are therefore checked by the client.
160          username, login_hash = req["username"], req["password_hash"]
161          enc_pem, sign_pem = req["enc_public_pem"], req["sign_public_pem"]
162          if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):  # fullmatch: no trailing "\n"
163              return {"ok": False, "error": "Username must be 3-20 characters: a-z, 0-9, _."}
164          if not is_login_hash(login_hash):
165              return {"ok": False, "error": "password_hash must be the client's 32-byte login hash (base64)."}
166          # Check the public keys are real keys of the right type. Otherwise a
167          # user could register junk that breaks everyone who tries to message them.
168          try:
169              if not isinstance(enc_pem, str) or not isinstance(sign_pem, str):
170                  raise ValueError
171              if load_enc_public(enc_pem).key_size < MIN_RSA_BITS:
172                  raise ValueError
173              load_sign_public(sign_pem)
174          except Exception:
175              return {"ok": False, "error": "Public keys must be a PEM RSA key (2048+ bits) and a PEM Ed25519 key."}
176          # PDPA s.19/s.23: the user must have seen and accepted the current privacy notice.
177          if req.get("consent_version") != PRIVACY_NOTICE_VERSION:
178              return {"ok": False, "error": "You must accept the current privacy notice to sign up."}
```

- **154** — Section comment.
- **156** — `signup` creates an account.
- **157–159** — Comment: the server never receives the password, only the login hash, so password rules are checked by the client.
- **160** — Read the username and login hash (a missing field raises `KeyError` → "Bad request").
- **161** — Read the two public keys.
- **162–163** — Enforce the username pattern with `fullmatch`. (With `match`, the `$` in the pattern would also accept a name ending in a newline, such as `"alice\n"`, a near-copy of `alice` that could inject lines into the log.)
- **164–165** — Refuse anything that is not exactly a 32-byte login hash. So the server can never end up storing a hash of a plain password.
- **166–167** — Comment: junk keys would break everyone who later tried to message this user.
- **168–170** — Both keys must be text.
- **171–172** — The encryption key must parse as RSA and be at least 2048 bits.
- **173** — The signing key must parse as Ed25519.
- **174–175** — Any failure → a clear error; nothing is stored.
- **176–178** — **Consent (PDPA s.19, s.23):** the request must say which privacy-notice version the person accepted, and it must be the current one. Otherwise nothing is stored. This check comes last, so the other checks above can still be tested on their own.

[`server/server.py` lines 180–195](../server/server.py#L180-L195)

```python
180          with SCRYPT_SLOTS:
181              record = hash_password(login_hash)  # salted again with a random salt; slow, so outside the lock
182          with self.db.lock:
183              if username in self.db.data["users"]:
184                  return {"ok": False, "error": "That username is taken."}
185              self.db.data["users"][username] = {
186                  "password": record,  # scrypt(login hash, random salt) only
187                  "enc_public_pem": enc_pem,
188                  "sign_public_pem": sign_pem,
189                  "created": int(time.time()),
190                  "consent": {"notice_version": PRIVACY_NOTICE_VERSION, "accepted_at": int(time.time())},
191              }
192              self.db.save()
193          conn.user = username
194          log.info("signup: %s", self.pseudo.user(username))
195          return {"ok": True, "username": username}
```

- **180–181** — Take one of the 4 scrypt slots, and hash the login hash again with a new random salt (section 2.2). This is slow (≈0.1 s), so it is done before taking the database lock, not while holding it.
- **182** — Take the database lock.
- **183–184** — If the name is taken, refuse. (This check is inside the lock, so two people cannot register the same name at the same instant.)
- **185–189** — Save the new user: the scrypt record, both public keys, and the creation time.
- **190–191** — Also record **which notice version was accepted and when**, so the operator can show consent was given (PDPA s.19 puts that burden on the operator).
- **192** — Write the file atomically.
- **193** — This connection is now logged in as the new user.
- **194** — Log the signup under the user's **pseudonym**, not the username.
- **195** — Reply with success.

### Login and logout

[`server/server.py` lines 197–219](../server/server.py#L197-L219)

```python
197      def login(self, conn, req):
198          username, login_hash = req["username"], req["password_hash"]
199          if not isinstance(username, str) or not is_login_hash(login_hash):
200              return {"ok": False, "error": GENERIC_LOGIN_ERROR}
201          with self.db.lock:
202              user = self.db.data["users"].get(username)
203          # Always run scrypt once, even for unknown users, so the reply time
204          # does not reveal whether the username exists.
205          record = user["password"] if user else DUMMY_RECORD
206          with SCRYPT_SLOTS:
207              password_ok = verify_password(login_hash, record)
208          if user is None or not password_ok:
209              # Deliberately NOT logged: a failed login's "username" is whatever was
210              # typed, and people sometimes type their password into that box.
211              # One message for "no such user" and "wrong password".
212              return {"ok": False, "error": GENERIC_LOGIN_ERROR}
213          conn.user = username
214          log.info("login: %s", self.pseudo.user(username))
215          return {"ok": True, "username": username}
216  
217      def logout(self, conn, req):
218          conn.user = None
219          return {"ok": True}
```

- **197** — `login`.
- **198** — Read the username and login hash.
- **199–200** — If either has the wrong form, return the generic error immediately. (This shortcut takes the same time for every user, so it reveals nothing about which names exist.)
- **201–202** — Look the user up under the lock.
- **203–204** — Comment.
- **205** — The real record if the user exists, otherwise the dummy record (section 2.2).
- **206–207** — Run scrypt and the constant-time comparison, in one of the 4 slots.
- **208** — Fail if the user does not exist **or** the hash does not match…
- **209–211** — Comment: failures are deliberately not logged, since people sometimes type their password into the username box.
- **212** — …with the same message in both cases.
- **213** — Success: this connection is logged in.
- **214** — Log the successful login, under the user's pseudonym.
- **215** — Reply.
- **217–219** — `logout` forgets the login for this connection.

### The user directory

[`server/server.py` lines 221–232](../server/server.py#L221-L232)

```python
221      # ------------------------------------------------------------ directory
222  
223      def users(self, conn, req):
224          """Everyone except the caller, with their public keys."""
225          with self.db.lock:
226              listing = [
227                  {"username": name, "enc_public_pem": u["enc_public_pem"], "sign_public_pem": u["sign_public_pem"]}
228                  for name, u in sorted(self.db.data["users"].items())
229              ]
230          if req.get("include_self") is True:
231              return {"ok": True, "users": listing}
232          return {"ok": True, "users": [u for u in listing if u["username"] != conn.user]}
```

- **221** — Section comment.
- **223–224** — `users` returns the directory.
- **225** — Under the lock…
- **226–229** — …build a list of every user, sorted by name, with **only** the username and the two public keys (never the password record).
- **230–231** — If the client asked for itself to be included (the client uses this to pin its own key and look up senders), return everyone. `is True` means only a real JSON `true` counts.
- **232** — Otherwise return everyone except the caller.

### Sending: checking the envelope

[`server/server.py` lines 234–248](../server/server.py#L234-L248)

```python
234      # ------------------------------------------------------------ messages
235  
236      def send(self, conn, req):
237          """Accept a sealed package. The server checks the envelope, never the contents."""
238          pkg = req["package"]
239          if not isinstance(pkg, dict):
240              return {"ok": False, "error": "Package must be a JSON object."}
241          required = ("version", "timestamp") + PACKAGE_STRING_FIELDS
242          missing = [f for f in required if f not in pkg]
243          if missing:
244              return {"ok": False, "error": f"Package is missing fields: {', '.join(missing)}."}
245          if not all(isinstance(pkg[f], str) for f in PACKAGE_STRING_FIELDS):
246              return {"ok": False, "error": "Package fields have the wrong type."}
247          if not MSG_ID_RE.fullmatch(pkg["msg_id"]):  # so an ID can never carry newlines or escape codes
248              return {"ok": False, "error": "Invalid message ID (must be 32 lowercase hex characters)."}
```

- **234** — Section comment.
- **236–237** — `send` accepts a sealed package; the docstring says the key point: the envelope is checked, never the contents.
- **238** — Read the package.
- **239–240** — It must be a JSON object.
- **241–244** — Every required field must be present; list any that are missing.
- **245–246** — All string fields must really be strings.
- **247–248** — The message ID must be exactly 32 lowercase hex characters. This is what makes it safe to print in the log lines below (the fix for finding V1).

[`server/server.py` lines 250–260](../server/server.py#L250-L260)

```python
250          # The logged-in user may only send as themselves. (Recipients still
251          # verify the signature: they must not have to trust the server.)
252          if pkg["sender"] != conn.user:
253              log.warning("rejected: %s tried to send as someone else", self.pseudo.user(conn.user))
254              return {"ok": False, "error": "Sender does not match the logged-in user."}
255          ts = pkg["timestamp"]
256          # `type(...) is int` excludes True/False; the range check comes before any
257          # arithmetic so an enormous number cannot cause an overflow.
258          if type(ts) is not int or not 0 < ts < 2**40 or abs(time.time() - ts) > MAX_CLOCK_SKEW:
259              return {"ok": False, "error": "Message timestamp is more than 5 minutes away from the server's "
260                                            "time. Check that your computer's clock is correct."}
```

- **250–251** — Comment: honest servers stop impersonation early, but recipients still verify signatures and never rely on this check.
- **252–254** — The `sender` field must equal the logged-in user. The log records only the logged-in user's pseudonym; the name they tried to use is not logged at all, so it can neither identify anyone nor inject text into the log.
- **255** — Read the timestamp.
- **256–257** — Comment.
- **258–260** — The timestamp must be a real integer (not `true`), in a sane range checked **before** any arithmetic (so `10**300` cannot cause an overflow), and within 5 minutes of the server's clock. The error tells the user to check their clock.

### Sending: replay check and storage

[`server/server.py` lines 262–277](../server/server.py#L262-L277)

```python
262          with self.db.lock:
263              if pkg["recipient"] not in self.db.data["users"]:
264                  return {"ok": False, "error": "Unknown recipient."}
265              # Replay protection: each message ID is accepted exactly once.
266              if pkg["msg_id"] in self.db.seen:
267                  log.warning("rejected replay of message %s", pkg["msg_id"])
268                  return {"ok": False, "error": f"Duplicate message ID {pkg['msg_id']}: replay rejected."}
269              self.db.seen.add(pkg["msg_id"])
270              self.db.data["seen_msg_ids"].append(pkg["msg_id"])
271              purge_expired(self.db.data)  # retention: drop anything past its time before adding more
272              # Stored exactly as received: still encrypted, still signed.
273              self.db.data["messages"].append({"package": pkg, "received_at": int(time.time()), "delivered": False})
274              self.db.save()
275          log.info("stored message %s from %s to %s (%d bytes of ciphertext, base64)", pkg["msg_id"],
276                   self.pseudo.user(pkg["sender"]), self.pseudo.user(pkg["recipient"]), len(pkg["ciphertext"]))
277          return {"ok": True, "msg_id": pkg["msg_id"]}
```

- **262** — Take the database lock for the rest.
- **263–264** — The recipient must be a registered user.
- **265** — Comment.
- **266–268** — If this message ID was accepted before, it is a replay: refuse and log it. The ID can be printed as-is because line 247 already guaranteed it is plain hex.
- **269–270** — Remember the ID: in the fast set, and in the saved list so it survives a restart. (Only this random ID is kept forever; it says nothing about who sent what.)
- **271** — **Retention:** before adding anything, delete stored messages that were delivered or are older than the retention period (section 3.3).
- **272–273** — Store the package **exactly as received**, with the time it arrived and `delivered: false`.
- **274** — Save the database.
- **275–276** — Log the ID (validated hex), the sender's and recipient's **pseudonyms**, and the ciphertext size. Nothing in this line identifies a person without the log key, and every value has been validated, so the log cannot be forged through it.
- **277** — Reply with the accepted ID.

### Forwarding: the inbox

[`server/server.py` lines 279–293](../server/server.py#L279-L293)

```python
279      def inbox(self, conn, req):
280          """Forward every undelivered package addressed to the caller."""
281          with self.db.lock:
282              out = []
283              for entry in self.db.data["messages"]:
284                  pkg = entry.get("package") if isinstance(entry, dict) else None
285                  # Skip anything malformed (e.g. a hand-edited database) instead of failing the whole inbox.
286                  if not isinstance(pkg, dict) or pkg.get("recipient") != conn.user or entry.get("delivered"):
287                      continue
288                  out.append(pkg)
289                  entry["delivered"] = True
290              if out:
291                  purge_expired(self.db.data)  # retention: delivered packages are deleted right away
292                  self.db.save()
293          return {"ok": True, "messages": out}
```

- **279–280** — `inbox` delivers waiting packages.
- **281** — Under the lock…
- **282** — …collect into a list.
- **283** — Go through every stored message.
- **284** — Take its package, or `None` if the entry is not a proper object.
- **285–287** — Skip junk entries (such as a hand-edited database), packages for other users, and packages already delivered.
- **288** — Add it to the reply.
- **289** — Mark it delivered, so it is sent only once. (It is marked before the client has confirmed it can read it; see document 6.)
- **290** — If anything was delivered…
- **291** — …**delete it from the database right away** (retention: the server keeps a package only until it reaches its recipient)…
- **292** — …and save.
- **293** — Reply with the list.

### Privacy rights (PDPA)

[`server/server.py` lines 295–299](../server/server.py#L295-L299)

```python
295      # ------------------------------------------------------------ privacy rights (PDPA)
296  
297      def privacy_notice(self, conn, req):
298          """PDPA s.23: tell people what is collected and why, before they sign up."""
299          return {"ok": True, "version": PRIVACY_NOTICE_VERSION, "text": PRIVACY_NOTICE}
```

- **295** — Section comment.
- **297–299** — `privacy_notice` returns the notice text and its version. It needs no login, because people must be able to read it **before** giving any data (PDPA s.23).

[`server/server.py` lines 301–319](../server/server.py#L301-L319)

```python
301      def mydata(self, conn, req):
302          """PDPA s.30 (access) and s.31 (portability): everything stored about the caller, as JSON."""
303          with self.db.lock:
304              u = self.db.data["users"][conn.user]
305              waiting_for_me = sum(1 for e in self.db.data["messages"] if _party(e, "recipient") == conn.user)
306              sent_waiting = sum(1 for e in self.db.data["messages"] if _party(e, "sender") == conn.user)
307              record = {
308                  "username": conn.user,
309                  "created": u["created"],
310                  "consent": u.get("consent"),
311                  "enc_public_pem": u["enc_public_pem"],
312                  "sign_public_pem": u["sign_public_pem"],
313                  "password": "stored only as scrypt(login hash, random salt); not shown so a stolen session cannot take it",
314                  "messages_waiting_for_you": waiting_for_me,
315                  "messages_you_sent_still_waiting": sent_waiting,
316                  "retention": f"delivered messages are deleted at once; undelivered ones after {RETENTION_DAYS} days",
317                  "log_pseudonym": self.pseudo.user(conn.user),
318              }
319          return {"ok": True, "data": record}
```

- **301–302** — `mydata` answers the right of access (s.30) and data portability (s.31): everything stored about the caller, as machine-readable JSON.
- **303** — Under the lock…
- **304** — …read the caller's record.
- **305** — Count messages waiting **for** the caller…
- **306** — …and messages the caller sent that are still waiting.
- **307–318** — Build the reply: name, sign-up time, consent record, both public keys, the two counts, the retention rule, and the caller's own log pseudonym (so they can see how they appear in the log). The password record is **described but not shown**: if someone hijacked a logged-in session, showing the hash would let them try to crack the password offline.
- **319** — Return it.

[`server/server.py` lines 321–339](../server/server.py#L321-L339)

```python
321      def delete_account(self, conn, req):
322          """PDPA s.33 (erasure): remove the account and every message to or from it.
323          The password is asked again, so someone at an unlocked screen cannot do it."""
324          login_hash = req["password_hash"]
325          with self.db.lock:
326              user = self.db.data["users"].get(conn.user)
327          with SCRYPT_SLOTS:
328              ok = user is not None and is_login_hash(login_hash) and verify_password(login_hash, user["password"])
329          if not ok:
330              return {"ok": False, "error": GENERIC_LOGIN_ERROR}
331          name = conn.user
332          with self.db.lock:
333              del self.db.data["users"][name]
334              self.db.data["messages"] = [e for e in self.db.data["messages"]
335                                          if name not in (_party(e, "sender"), _party(e, "recipient"))]
336              self.db.save()
337          conn.user = None
338          log.info("account deleted: %s", self.pseudo.user(name))
339          return {"ok": True}
```

- **321–323** — `delete_account` answers the right to erasure (s.33). The docstring explains why the password is asked again.
- **324** — Read the login hash the client sent.
- **325–326** — Look up the caller's record.
- **327–328** — Re-check the password in constant time, in one of the 4 scrypt slots. Being logged in is not enough: someone at an unlocked screen should not be able to erase the account.
- **329–330** — Wrong password: the generic error, and nothing is deleted.
- **331** — Remember the name.
- **332** — Under the lock…
- **333** — …delete the user record (hash, public keys, consent)…
- **334–335** — …and every stored message **to or from** that user. (Trade-off: a message they sent that is still waiting is erased too, so its recipient never gets it. We chose this because a waiting message still carries the sender's identity.)
- **336** — Save.
- **337** — Log the connection out.
- **338** — Log the deletion under the pseudonym.
- **339** — Reply with success.

[`server/server.py` lines 342–345](../server/server.py#L342-L345)

```python
342  def _party(entry, field):
343      """The sender or recipient of a stored message entry, or None if the entry is malformed."""
344      pkg = entry.get("package") if isinstance(entry, dict) else None
345      return pkg.get(field) if isinstance(pkg, dict) else None
```

- **342–343** — `_party` safely reads the sender or recipient of a stored entry.
- **344** — Take the entry's package if the entry is a proper object.
- **345** — Return the field, or `None` for a malformed entry, so a damaged database cannot crash `mydata` or `delete_account`.

### `ThreadedServer`: accepting connections

[`server/server.py` lines 348–363](../server/server.py#L348-L363)

```python
348  class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
349      allow_reuse_address = True
350      daemon_threads = True
351  
352      def __init__(self, address, app: ChatApp, tls_context: ssl.SSLContext):
353          self.app = app
354          self.tls_context = tls_context
355          self._connections = set()
356          self._conn_lock = threading.Lock()
357          super().__init__(address, RequestHandler)
358  
359      def get_request(self):
360          """Every accepted connection is wrapped in TLS before anything is read from it.
361          The handshake itself runs later, in the connection's thread (see RequestHandler.setup)."""
362          sock, addr = self.socket.accept()
363          return self.tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr
```

- **348** — `ThreadingMixIn` gives each connection its own thread; `TCPServer` listens for TCP connections.
- **349** — Allow restarting immediately on the same port, without waiting for the operating system to release it.
- **350** — Connection threads are "daemon" threads, so they don't keep the program alive after the main thread exits.
- **352** — The constructor receives the address, the logic and the TLS context.
- **353–354** — Store them.
- **355–356** — A set of open connections, and a lock protecting it.
- **357** — The parent constructor binds and listens, and remembers that `RequestHandler` handles each connection.
- **359–361** — `get_request` overrides how a connection is accepted.
- **362** — Accept the raw TCP connection.
- **363** — Wrap it in TLS as the server side, but **don't** do the handshake here (`do_handshake_on_connect=False`). This code runs in the single thread that accepts every connection, so a slow handshake here would block everyone. The handshake happens in the connection's own thread (line 71).

[`server/server.py` lines 365–373](../server/server.py#L365-L373)

```python
365      def handle_error(self, request, client_address):
366          """A connection that fails (e.g. a failed TLS handshake) is closed quietly
367          instead of printing a traceback; the server carries on."""
368          exc = sys.exc_info()[1]
369          peer = self.app.pseudo.ip(client_address[0])  # pseudonym, not the real IP
370          if isinstance(exc, (ssl.SSLError, OSError)):
371              log.info("dropped connection from %s (%s)", peer, exc.__class__.__name__)
372          else:
373              log.exception("error on connection from %s", peer)
```

- **365–367** — `handle_error` is called by `socketserver` when a connection's handler raises an exception.
- **368** — Get the exception currently being handled.
- **369** — Turn the client's IP address into its pseudonym, as everywhere else in the log.
- **370–371** — Network and TLS errors (failed handshake, client vanished) are normal: log one line.
- **372–373** — Anything else is unexpected: log the full traceback.

[`server/server.py` lines 375–392](../server/server.py#L375-L392)

```python
375      def track(self, sock):
376          with self._conn_lock:
377              self._connections.add(sock)
378  
379      def untrack(self, sock):
380          with self._conn_lock:
381              self._connections.discard(sock)
382  
383      def stop(self):
384          """Stop accepting, then drop every open session (like the process exiting)."""
385          self.shutdown()
386          with self._conn_lock:
387              for sock in list(self._connections):
388                  try:
389                      sock.shutdown(socket.SHUT_RDWR)
390                  except OSError:
391                      pass
392          self.server_close()
```

- **375–377** — `track` records an open connection.
- **379–381** — `untrack` forgets it.
- **383–384** — `stop` behaves like killing the server process: used by tests and the demo.
- **385** — Stop accepting new connections.
- **386–391** — Forcibly shut down every open session's socket; ignore errors for ones already closing.
- **392** — Close the listening socket.

### Starting the server

[`server/server.py` lines 395–404](../server/server.py#L395-L404)

```python
395  def start_in_background(host: str, port: int, db_path: str, tls_dir: str | None = None) -> ThreadedServer:
396      """Start a server on a background thread (used by tests and the demo). Port 0 = pick a free port.
397      TLS certificates live in `tls_dir` (default: a "tls" folder next to the database);
398      clients must trust `server.ca_file`."""
399      tls_dir = tls_dir or os.path.join(os.path.dirname(os.path.abspath(db_path)), "tls")
400      paths, _ = ensure_server_tls(tls_dir)
401      srv = ThreadedServer((host, port), ChatApp(db_path), server_context(paths["cert"], paths["key"]))
402      srv.ca_file = paths["ca"]
403      threading.Thread(target=srv.serve_forever, daemon=True).start()
404      return srv
```

- **395–398** — `start_in_background` is used by tests and the demo. Port 0 means "pick any free port".
- **399** — By default the certificates go in a `tls` folder next to the database.
- **400** — Create the certificates if needed.
- **401** — Build the server with a TLS 1.3 context from those files.
- **402** — Remember where `ca.crt` is, so tests can give it to clients.
- **403** — Run `serve_forever` on a daemon thread.
- **404** — Return the running server.

[`server/server.py` lines 407–416](../server/server.py#L407-L416)

```python
407  def main():
408      parser = argparse.ArgumentParser(description="Secure chat relay server")
409      parser.add_argument("--host", default="127.0.0.1", help="address to listen on (0.0.0.0 = all networks)")
410      parser.add_argument("--port", type=int, default=5050)
411      parser.add_argument("--db", default="server_data/db.json", help="path of the JSON database")
412      parser.add_argument("--tls-dir", default="server_data/tls", help="folder for the TLS certificates")
413      parser.add_argument("--hostname", action="append", default=[],
414                          help="extra name or IP clients will use to reach this server (repeatable; "
415                               "only used when the certificates are first created)")
416      args = parser.parse_args()
```

- **407** — `main` runs for `py -m server.server`.
- **408** — Create the option parser.
- **409** — `--host`: the address to listen on. The default `127.0.0.1` accepts only connections from this computer; `0.0.0.0` accepts them from the network.
- **410** — `--port`, default 5050.
- **411** — `--db`: the database file.
- **412** — `--tls-dir`: the certificate folder.
- **413–415** — `--hostname`, repeatable: extra names or IPs to put in the certificate (only used when certificates are created).
- **416** — Parse the command line.

[`server/server.py` lines 417–423](../server/server.py#L417-L423)

```python
417      logging.basicConfig(level=logging.INFO, format="%(asctime)s [server] %(message)s")
418  
419      names = list(DEFAULT_HOSTNAMES) + args.hostname + ([args.host] if args.host not in ("0.0.0.0", "::") else [])
420      paths, created = ensure_server_tls(args.tls_dir, names)
421      if created:
422          log.info("created TLS certificates in %s for: %s", args.tls_dir, ", ".join(dict.fromkeys(names)))
423      log.info("clients must trust %s (fingerprint %s)", paths["ca"], certificate_fingerprint(paths["ca"]))
```

- **417** — Switch on logging with timestamps.
- **419** — The names to put in the certificate: the defaults, any `--hostname`, and the listening address itself unless it is a wildcard.
- **420** — Load or create the certificates.
- **421–422** — If new ones were made, say so and list the names.
- **423** — Always print where `ca.crt` is and its fingerprint, so clients can check their copy.

[`server/server.py` lines 424–443](../server/server.py#L424-L443)

```python
424      try:
425          srv = ThreadedServer((args.host, args.port), ChatApp(args.db), server_context(paths["cert"], paths["key"]))
426      except ssl.SSLError as exc:
427          sys.exit(f"Cannot load the TLS certificate or key in {args.tls_dir} ({exc}). "
428                   "Delete that folder to create new ones.")
429      except OSError as exc:
430          sys.exit(f"Cannot listen on {args.host}:{args.port} ({exc}). "
431                   "Is another server already running? Try --port with another number.")
432      except ValueError as exc:
433          sys.exit(f"Cannot read the database {args.db}: {exc}")
434      with srv:
435          log.info("listening on %s:%d with TLS 1.3, database %s", args.host, args.port, args.db)
436          try:
437              srv.serve_forever()
438          except KeyboardInterrupt:
439              log.info("shutting down")
440  
441  
442  if __name__ == "__main__":
443      main()
```

- **424–425** — Create the server: open the database, build the TLS context, bind the port.
- **426–428** — An unreadable certificate or key: exit with advice to delete the folder.
- **429–431** — The port is in use or not allowed: exit with advice.
- **432–433** — A damaged database (JSON errors are `ValueError`): exit with a clear message.
- **434** — `with srv:` closes the listening socket when the block ends.
- **435** — Announce it is listening with TLS 1.3.
- **436–437** — Serve until stopped.
- **438–439** — Ctrl+C stops it with a log line instead of a traceback.
- **442–443** — Run `main()` when executed as a program (not when imported by tests).

## 3.3 `privacy.py`

The server's privacy mechanisms. Encryption keeps message contents secret, but privacy
also means collecting and keeping as little as possible about people, and telling them
what happens to their data. This module does that for the server's log and database.

[`server/privacy.py` lines 1–30](../server/privacy.py#L1-L30)

```python
 1  """Privacy mechanisms on the server: pseudonymous logs, retention and the privacy notice.
 2  
 3  Pseudonymous logging with conditional re-identification
 4      The server log must help the operator (who logged in, which message was
 5      stored, which connection failed) without turning into a list of who
 6      talks to whom. So usernames and IP addresses are never written in clear.
 7      Each one is replaced by a pseudonym:
 8  
 9          pseudonym = "u-" + HMAC-SHA256(log_key, "user:" + username)[:10 hex]
10  
11      The same user always gets the same pseudonym, so the log stays useful
12      for spotting patterns (one pseudonym failing many logins, for example).
13      Without the secret `log_key` nobody can tell who a pseudonym is.
14  
15      This is *conditional* privacy: whoever holds `log_key` (kept in
16      server_data/privacy/, not in the log) can re-identify a pseudonym with
17      `py -m server.reidentify <pseudonym>`, for example when a lawful
18      request or a security incident requires it. Everyone else, including
19      someone who only gets a copy of the log, sees pseudonyms only.
20  
21  Retention
22      Delivered messages are deleted from the database right away. Messages
23      nobody collects are deleted after RETENTION_DAYS. Only the random
24      message IDs are kept, because the replay check needs them; an ID alone
25      says nothing about who sent what.
26  
27  Privacy notice
28      The text the client shows before signup, and the version the user must
29      accept. The server stores which version was accepted and when.
30  """
```

- **1–30** — Module docstring. It explains the three mechanisms: (1) **pseudonymous logging with conditional re-identification**: usernames and IPs in the log are replaced by keyed pseudonyms that only the key holder can map back; (2) **retention**: delivered messages are deleted at once, undelivered ones after 30 days, and only the random message IDs are kept; (3) the **privacy notice** shown before signup.

[`server/privacy.py` lines 32–39](../server/privacy.py#L32-L39)

```python
32  import hashlib
33  import hmac
34  import os
35  import time
36  
37  RETENTION_DAYS = 30                 # undelivered messages are deleted after this many days
38  RETENTION_SECONDS = RETENTION_DAYS * 24 * 3600
39  PRIVACY_NOTICE_VERSION = "2026-11"  # bump when the notice text changes; users must accept the new one
```

- **32** — `hashlib` provides SHA-256 for the HMAC.
- **33** — `hmac` computes keyed hashes.
- **34** — `os` for the key file and random bytes.
- **35** — `time` for the retention check.
- **37** — Undelivered messages are deleted after 30 days. We chose 30 days so someone on a month-long break still gets their messages, without the server keeping them forever (PDPA s.37(3) asks for erasure when the retention period ends).
- **38** — The same period in seconds.
- **39** — The notice's version. When the text changes, the version changes, and the server only accepts sign-ups that agreed to the current version.

[`server/privacy.py` lines 41–52](../server/privacy.py#L41-L52)

```python
41  PRIVACY_NOTICE = f"""\
42  Privacy notice (version {PRIVACY_NOTICE_VERSION})
43    What we collect : your username, a hash of a hash of your password, your two public keys,
44                      the time you signed up, and the encrypted messages you send until they are delivered.
45    What we never get: your password, your private keys, or the text of any message.
46    Why             : only to let you log in and to deliver your messages (PDPA s.21, s.22).
47    How long        : delivered messages are deleted at once; undelivered ones after {RETENTION_DAYS} days.
48                      Your account stays until you delete it.
49    Who can see it  : only the server operator. Server logs use pseudonyms, not your name or IP address.
50    Your rights     : 'mydata' shows everything we hold about you (s.30, s.31);
51                      'delete_account' erases your account and waiting messages (s.33).
52  """
```

- **41–52** — The privacy notice text, in plain words, covering what PDPA s.23 asks a controller to tell people when collecting data: what is collected, what is never collected, the purpose, how long it is kept, who can see it, and the person's rights with the commands that exercise them. The retention period is filled in from line 37, so the notice can never disagree with the code.

[`server/privacy.py` lines 55–67](../server/privacy.py#L55-L67)

```python
55  class Pseudonymizer:
56      """Turns usernames and IP addresses into stable, keyed pseudonyms for the log."""
57  
58      def __init__(self, key_path: str):
59          self.key_path = key_path
60          if os.path.exists(key_path):
61              with open(key_path, "rb") as f:
62                  self.key = f.read()
63          else:
64              os.makedirs(os.path.dirname(os.path.abspath(key_path)), exist_ok=True)
65              self.key = os.urandom(32)            # 256-bit secret, created once per server
66              with open(key_path, "wb") as f:
67                  f.write(self.key)
```

- **55–56** — `Pseudonymizer` turns names and IP addresses into stable, keyed pseudonyms.
- **58** — The constructor receives the path of the secret key file.
- **59** — Remember it.
- **60–62** — If the key already exists, load it, so pseudonyms stay the same across restarts and the log stays consistent.
- **63–64** — Otherwise create the folder…
- **65** — …make a new 256-bit random key…
- **66–67** — …and save it. The key never appears in the log or the database.

[`server/privacy.py` lines 69–83](../server/privacy.py#L69-L83)

```python
69      def _tag(self, kind: str, value: str) -> str:
70          # HMAC, not a plain hash: without the key, nobody can test guesses such as
71          # hash("alice") to undo the pseudonym.
72          digest = hmac.new(self.key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
73          return digest[:10]
74  
75      def user(self, username) -> str:
76          return "u-" + self._tag("user", str(username))
77  
78      def ip(self, address) -> str:
79          return "ip-" + self._tag("ip", str(address))
80  
81      def reidentify(self, pseudonym: str, candidates) -> list[str]:
82          """Conditional re-identification: only possible with the key and a list of candidates."""
83          return [c for c in candidates if self.user(c) == pseudonym or self.ip(c) == pseudonym]
```

- **69** — `_tag` computes the pseudonym part.
- **70–71** — Comment: why HMAC and not a plain hash. A plain `SHA-256("alice")` could be undone by anyone who hashes a list of likely names and compares. With HMAC, they would also need the secret key.
- **72** — HMAC-SHA256 of `"user:alice"` (or `"ip:127.0.0.1"`) under the secret key. The `kind:` prefix keeps user pseudonyms and IP pseudonyms from ever colliding.
- **73** — Keep the first 10 hex characters (40 bits): short enough to read in a log, long enough that two users are very unlikely to share one in a class-sized system.
- **75–76** — A user's pseudonym, e.g. `u-e78032f543`.
- **78–79** — An IP address's pseudonym, e.g. `ip-eff78df829`.
- **81–82** — `reidentify` is the **conditional** part: given a pseudonym and a list of candidate names or IPs, return the ones that produce it. It only works with the right key.
- **83** — Compute each candidate's pseudonym and compare.

[`server/privacy.py` lines 86–100](../server/privacy.py#L86-L100)

```python
 86  def purge_expired(data: dict, now: float | None = None) -> int:
 87      """Delete delivered messages and messages older than the retention period.
 88      Returns how many were removed. The caller holds the database lock and saves."""
 89      now = time.time() if now is None else now
 90      keep = []
 91      for entry in data["messages"]:
 92          if not isinstance(entry, dict):
 93              continue                                          # junk entry: drop it
 94          too_old = now - entry.get("received_at", 0) > RETENTION_SECONDS
 95          if entry.get("delivered") or too_old:
 96              continue                                          # delivered or expired: drop it
 97          keep.append(entry)
 98      removed = len(data["messages"]) - len(keep)
 99      data["messages"] = keep
100      return removed
```

- **86–88** — `purge_expired` applies the retention rule to the database contents. The caller already holds the lock and saves afterwards.
- **89** — Use the current time unless a test passes a fixed one.
- **90** — The entries to keep.
- **91** — Look at every stored message.
- **92–93** — Drop anything that is not a proper entry (e.g. a hand-edited database).
- **94** — Is it older than the retention period? (Entries without a time count as very old.)
- **95–96** — Drop it if it was delivered or has expired.
- **97** — Otherwise keep it.
- **98** — Count how many were removed.
- **99** — Replace the list.
- **100** — Return the count, so callers know whether to save.

## 3.4 `reidentify.py`

A small command for the operator. It is the only way to turn a log pseudonym back into a
name, and it needs the secret key file, which is the "condition" in conditional privacy.

[`server/reidentify.py` lines 1–9](../server/reidentify.py#L1-L9)

```python
1  """Conditional re-identification of a pseudonym from the server log.
2  
3  Only someone who can read the server's secret log key (server_data/privacy/
4  log_key) can do this. It is meant for a lawful request or a security
5  investigation, not for everyday use.
6  
7  Run:  py -m server.reidentify u-3f9a1c0b2e
8        py -m server.reidentify ip-77b0e1d4a2 --ip 127.0.0.1 --ip 192.168.1.20
9  """
```

- **1–9** — Module docstring: who may use it, why, and two examples.

[`server/reidentify.py` lines 11–16](../server/reidentify.py#L11-L16)

```python
11  import argparse
12  import json
13  import os
14  import sys
15  
16  from .privacy import Pseudonymizer
```

- **11** — `argparse` for options.
- **12** — `json` to read the database.
- **13** — `os` to check the files exist.
- **14** — `sys` to exit with a message.
- **16** — The pseudonymizer from section 3.3.

[`server/reidentify.py` lines 19–38](../server/reidentify.py#L19-L38)

```python
19  def main():
20      parser = argparse.ArgumentParser(description="Re-identify a pseudonym from the server log")
21      parser.add_argument("pseudonym", help="e.g. u-3f9a1c0b2e or ip-77b0e1d4a2")
22      parser.add_argument("--db", default="server_data/db.json")
23      parser.add_argument("--key", default="server_data/privacy/log_key")
24      parser.add_argument("--ip", action="append", default=[], help="candidate IP addresses to test")
25      args = parser.parse_args()
26      if not os.path.exists(args.key):
27          sys.exit("No log key found. Without the key, pseudonyms cannot be re-identified (that is the point).")
28      pseudo = Pseudonymizer(args.key)
29      candidates = list(args.ip)
30      if os.path.exists(args.db):
31          with open(args.db, encoding="utf-8") as f:
32              candidates += list(json.load(f).get("users", {}))
33      matches = pseudo.reidentify(args.pseudonym, candidates)
34      print(matches[0] if matches else "No match among current users / given IPs.")
35  
36  
37  if __name__ == "__main__":
38      main()
```

- **19** — `main` runs for `py -m server.reidentify`.
- **20** — Option parser.
- **21** — The pseudonym to look up.
- **22** — The database (its usernames are the candidates).
- **23** — The secret log key.
- **24** — Optional candidate IP addresses to test (IPs are not stored anywhere, so the operator must supply them).
- **25** — Parse.
- **26–27** — Without the key, stop. This check matters: otherwise `Pseudonymizer` would create a **new** random key, which could not re-identify anything anyway.
- **28** — Load the pseudonymizer with the real key.
- **29** — Start with the given IPs…
- **30–32** — …and add every current username from the database.
- **33** — Find the candidates that produce this pseudonym.
- **34** — Print the match, or say there is none.
- **37–38** — Run `main()` when executed as a program.
