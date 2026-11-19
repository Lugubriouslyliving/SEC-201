# 3. The server, line by line

[← crypto_utils](02-crypto-utils.md) · [Index](README.md) · Next: [The client →](04-client.md)

The server is a relay. It checks who you are, hands out public keys, and stores and
forwards sealed packages. It has no private key for any user and never decrypts a
message.

| File | Job |
|---|---|
| [`storage.py`](#31-storagepy) | The JSON database file and its lock |
| [`server.py`](#32-serverpy) | TLS connections, the request loop, and the six actions |

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

[`server/server.py` lines 25–44](../server/server.py#L25-L44)

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
41  from .storage import Storage
42  
43  log = logging.getLogger("server")
44  log.addHandler(logging.NullHandler())  # silent unless main() configures logging
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
- **41** — The database class from section 3.1.
- **43** — A logger named `server`.
- **44** — A `NullHandler` so that, when the server is used inside tests or the demo, nothing is printed unless logging is switched on (`main()` switches it on).

[`server/server.py` lines 46–58](../server/server.py#L46-L58)

```python
46  USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
47  MAX_LINE = 1_000_000          # bytes; a request bigger than this is refused
48  MSG_ID_RE = re.compile(r"[0-9a-f]{32}")  # exactly what uuid4().hex produces; nothing else is accepted
49  MIN_RSA_BITS = 2048
50  MAX_CLOCK_SKEW = 300          # seconds; package timestamps must be within this of server time
51  HANDSHAKE_TIMEOUT = 15        # seconds a new connection gets to complete the TLS handshake
52  GENERIC_LOGIN_ERROR = "Invalid username or password."  # same text for every login failure
53  
54  # scrypt needs ~32 MiB per computation. Without a limit, 1,000 simultaneous
55  # logins would ask for ~32 GiB. At most this many run at once; the rest wait.
56  SCRYPT_SLOTS = threading.BoundedSemaphore(4)
57  
58  PACKAGE_STRING_FIELDS = ("msg_id", "sender", "recipient", "nonce", "ciphertext", "wrapped_key", "signature")
```

- **46** — Usernames: 3–20 characters, only lowercase letters, digits and `_`. `^` and `$` anchor the whole string. Keeping names this simple means they are safe in file paths and on screen.
- **47** — Requests larger than 1,000,000 bytes are refused, so nobody can make the server read unlimited data into memory.
- **48** — Message IDs must be exactly 32 lowercase hex characters (the format `uuid4().hex` produces). The pattern is used with `fullmatch`, so the whole ID must match; nothing else (no newline, no escape code) can get into the log.
- **49** — RSA public keys must be at least 2048 bits.
- **50** — Package timestamps must be within 300 s (5 minutes) of the server's clock.
- **51** — A new connection has 15 seconds to complete the TLS handshake.
- **52** — The single error text for every failed login.
- **54–55** — Comment explaining the scrypt limit.
- **56** — A semaphore with 4 slots: at most 4 scrypt computations (≈32 MiB each) run at once; others wait their turn. A burst of logins therefore cannot use up the server's memory.
- **58** — The package fields that must be strings.

### `RequestHandler`: one TLS connection

`socketserver` creates one `RequestHandler` per connection and runs `setup()`,
`handle()`, then `finish()` in that connection's own thread.

[`server/server.py` lines 61–74](../server/server.py#L61-L74)

```python
61  class RequestHandler(socketserver.StreamRequestHandler):
62      """One instance per TCP connection. A connection is one client session."""
63  
64      def setup(self):
65          # TLS handshake first, in this connection's own thread, with a time
66          # limit, so a slow or non-TLS client cannot hold up anyone else. If it
67          # fails (plain-text client, wrong protocol, someone probing the port)
68          # the connection is simply dropped.
69          self.request.settimeout(HANDSHAKE_TIMEOUT)
70          self.request.do_handshake()
71          self.request.settimeout(None)  # a logged-in user may sit idle at the prompt
72          super().setup()  # (this is what sets self.connection = self.request)
73          self.user = None  # set after a successful login/signup
74          self.server.track(self.connection)
```

- **61–62** — The class; one instance per connection, and one connection is one user session.
- **64** — `setup` runs first.
- **65–68** — Comment explaining why the handshake happens here.
- **69** — `self.request` is the TLS-wrapped socket (see `get_request`, line 292). Give it a 15-second timeout.
- **70** — Perform the TLS 1.3 handshake. If the client is not speaking TLS, is too slow, or rejects our certificate, this raises an exception, `handle_error` (line 298) logs it quietly, and the connection is dropped.
- **71** — Remove the timeout: once connected, a user may sit at the prompt as long as they like.
- **72** — The parent class's `setup` creates `self.connection`, `self.rfile` (read side) and `self.wfile` (write side).
- **73** — Not logged in yet.
- **74** — Register the connection so `stop()` can close it later.

[`server/server.py` lines 76–90](../server/server.py#L76-L90)

```python
76      def finish(self):
77          self.server.untrack(self.connection)
78          try:
79              super().finish()
80          except OSError:
81              pass  # client already gone
82  
83      def handle(self):
84          peer = "%s:%s" % self.client_address
85          log.info("connection from %s", peer)
86          try:
87              self._serve()
88          except OSError:
89              pass  # the client vanished mid-request (closed window, network drop): nothing to do
90          log.info("connection from %s closed", peer)
```

- **76–77** — `finish` runs last: unregister the connection.
- **78–81** — Let the parent flush and close the streams; ignore errors if the client has already gone.
- **83** — `handle` is the main body.
- **84** — The client's address as `ip:port`, for log messages.
- **85** — Log the new connection.
- **86–89** — Serve requests. An `OSError` (connection reset, closed window, network drop) just ends the session quietly.
- **90** — Log that it closed.

[`server/server.py` lines 92–110](../server/server.py#L92-L110)

```python
 92      def _serve(self):
 93          while True:
 94              line = self.rfile.readline(MAX_LINE + 1)
 95              if not line:
 96                  return  # client closed the connection
 97              if len(line) > MAX_LINE:
 98                  self._reply({"ok": False, "error": "Request too large."})
 99                  return  # the rest of the oversized line is unreadable; end the session
100              if not line.strip():
101                  self._reply({"ok": False, "error": "Empty request."})
102                  continue
103              try:
104                  request = json.loads(line.decode("utf-8"))
105                  if not isinstance(request, dict):
106                      raise ValueError
107              except (ValueError, RecursionError):  # bad UTF-8, bad JSON, absurd nesting
108                  self._reply({"ok": False, "error": "Request must be one JSON object per line."})
109                  continue
110              self._reply(self.server.app.dispatch(self, request))
```

- **92–93** — `_serve`: loop over requests on this connection.
- **94** — Read one line, but at most `MAX_LINE + 1` bytes, so an endless line cannot fill memory.
- **95–96** — An empty read means the client closed the connection.
- **97–99** — If the line hit the limit, reply with an error and end the session (the rest of the oversized line can't be skipped reliably).
- **100–102** — A blank line gets an error and the loop continues.
- **103–104** — Decode UTF-8 and parse JSON.
- **105–106** — It must be a JSON object, not a list, string or number.
- **107–109** — Invalid UTF-8 or JSON (`ValueError`) and absurdly deep nesting (`RecursionError`) get an error reply; the connection stays open.
- **110** — Hand the request to the application logic and send its reply.

[`server/server.py` lines 112–114](../server/server.py#L112-L114)

```python
112      def _reply(self, obj: dict) -> None:
113          self.wfile.write(json.dumps(obj).encode("utf-8") + b"\n")
114          self.wfile.flush()
```

- **112** — `_reply` sends one JSON object.
- **113** — Serialize, encode as UTF-8, add the newline that ends the message, and write it into the TLS stream.
- **114** — Flush so it is sent now.

### `ChatApp`: the server's logic

[`server/server.py` lines 117–121](../server/server.py#L117-L121)

```python
117  class ChatApp:
118      """The server's logic, separate from the networking so it is easy to read and test."""
119  
120      def __init__(self, db_path: str):
121          self.db = Storage(db_path)
```

- **117–118** — `ChatApp` holds the logic, kept separate from networking so it is easy to read and test.
- **120–121** — Open the database.

[`server/server.py` lines 123–143](../server/server.py#L123-L143)

```python
123      def dispatch(self, conn: RequestHandler, req: dict) -> dict:
124          action = req.get("action")
125          handlers = {
126              "signup": self.signup,
127              "login": self.login,
128              "users": self.users,
129              "send": self.send,
130              "inbox": self.inbox,
131              "logout": self.logout,
132          }
133          if not isinstance(action, str) or action not in handlers:
134              return {"ok": False, "error": "Unknown action."}
135          if action in ("users", "send", "inbox") and conn.user is None:
136              return {"ok": False, "error": "Please log in first."}
137          try:
138              return handlers[action](conn, req)
139          except (KeyError, TypeError, ValueError, OverflowError) as exc:
140              return {"ok": False, "error": f"Bad request ({exc.__class__.__name__})."}
141          except Exception:  # a bug in the server: log it, keep running
142              log.exception("unexpected error handling %r", action)
143              return {"ok": False, "error": "Internal server error."}
```

- **123** — `dispatch` routes one request.
- **124** — Read the `action` field (missing → `None`).
- **125–132** — The six actions and the methods that handle them.
- **133–134** — Unknown action, or an action that isn't a string (a list or object in `action` would otherwise crash the lookup) → error.
- **135–136** — `users`, `send` and `inbox` require this connection to be logged in.
- **137–138** — Call the handler.
- **139–140** — Missing fields (`KeyError`), wrong types (`TypeError`), bad values (`ValueError`) or huge numbers (`OverflowError`) become a "Bad request" reply.
- **141–143** — Anything else is a bug in the server: log the full error for the operator, give the client a generic reply, keep running.

### Signup

[`server/server.py` lines 145–166](../server/server.py#L145-L166)

```python
145      # ------------------------------------------------------------ accounts
146  
147      def signup(self, conn, req):
148          # The client never sends the password itself, only its login hash
149          # (see crypto_utils/passwords.py). Password rules such as minimum
150          # length are therefore checked by the client.
151          username, login_hash = req["username"], req["password_hash"]
152          enc_pem, sign_pem = req["enc_public_pem"], req["sign_public_pem"]
153          if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):  # fullmatch: no trailing "\n"
154              return {"ok": False, "error": "Username must be 3-20 characters: a-z, 0-9, _."}
155          if not is_login_hash(login_hash):
156              return {"ok": False, "error": "password_hash must be the client's 32-byte login hash (base64)."}
157          # Check the public keys are real keys of the right type. Otherwise a
158          # user could register junk that breaks everyone who tries to message them.
159          try:
160              if not isinstance(enc_pem, str) or not isinstance(sign_pem, str):
161                  raise ValueError
162              if load_enc_public(enc_pem).key_size < MIN_RSA_BITS:
163                  raise ValueError
164              load_sign_public(sign_pem)
165          except Exception:
166              return {"ok": False, "error": "Public keys must be a PEM RSA key (2048+ bits) and a PEM Ed25519 key."}
```

- **145** — Section comment.
- **147** — `signup` creates an account.
- **148–150** — Comment: the server never receives the password, only the login hash, so password rules are checked by the client.
- **151** — Read the username and login hash (a missing field raises `KeyError` → "Bad request").
- **152** — Read the two public keys.
- **153–154** — Enforce the username pattern with `fullmatch`. (With `match`, the `$` in the pattern would also accept a name ending in a newline, such as `"alice\n"`, a near-copy of `alice` that could inject lines into the log.)
- **155–156** — Refuse anything that is not exactly a 32-byte login hash. So the server can never end up storing a hash of a plain password.
- **157–158** — Comment: junk keys would break everyone who later tried to message this user.
- **159–161** — Both keys must be text.
- **162–163** — The encryption key must parse as RSA and be at least 2048 bits.
- **164** — The signing key must parse as Ed25519.
- **165–166** — Any failure → a clear error; nothing is stored.

[`server/server.py` lines 168–182](../server/server.py#L168-L182)

```python
168          with SCRYPT_SLOTS:
169              record = hash_password(login_hash)  # salted again with a random salt; slow, so outside the lock
170          with self.db.lock:
171              if username in self.db.data["users"]:
172                  return {"ok": False, "error": "That username is taken."}
173              self.db.data["users"][username] = {
174                  "password": record,  # scrypt(login hash, random salt) only
175                  "enc_public_pem": enc_pem,
176                  "sign_public_pem": sign_pem,
177                  "created": int(time.time()),
178              }
179              self.db.save()
180          conn.user = username
181          log.info("signup: %s", username)
182          return {"ok": True, "username": username}
```

- **168–169** — Take one of the 4 scrypt slots, and hash the login hash again with a new random salt (section 2.2). This is slow (≈0.1 s), so it is done before taking the database lock, not while holding it.
- **170** — Take the database lock.
- **171–172** — If the name is taken, refuse. (This check is inside the lock, so two people cannot register the same name at the same instant.)
- **173–178** — Save the new user: the scrypt record, both public keys, and the creation time.
- **179** — Write the file atomically.
- **180** — This connection is now logged in as the new user.
- **181** — Log the signup (the username only).
- **182** — Reply with success.

### Login and logout

[`server/server.py` lines 184–206](../server/server.py#L184-L206)

```python
184      def login(self, conn, req):
185          username, login_hash = req["username"], req["password_hash"]
186          if not isinstance(username, str) or not is_login_hash(login_hash):
187              return {"ok": False, "error": GENERIC_LOGIN_ERROR}
188          with self.db.lock:
189              user = self.db.data["users"].get(username)
190          # Always run scrypt once, even for unknown users, so the reply time
191          # does not reveal whether the username exists.
192          record = user["password"] if user else DUMMY_RECORD
193          with SCRYPT_SLOTS:
194              password_ok = verify_password(login_hash, record)
195          if user is None or not password_ok:
196              # Deliberately NOT logged: a failed login's "username" is whatever was
197              # typed, and people sometimes type their password into that box.
198              # One message for "no such user" and "wrong password".
199              return {"ok": False, "error": GENERIC_LOGIN_ERROR}
200          conn.user = username
201          log.info("login: %s", username)
202          return {"ok": True, "username": username}
203  
204      def logout(self, conn, req):
205          conn.user = None
206          return {"ok": True}
```

- **184** — `login`.
- **185** — Read the username and login hash.
- **186–187** — If either has the wrong form, return the generic error immediately. (This shortcut takes the same time for every user, so it reveals nothing about which names exist.)
- **188–189** — Look the user up under the lock.
- **190–191** — Comment.
- **192** — The real record if the user exists, otherwise the dummy record (section 2.2).
- **193–194** — Run scrypt and the constant-time comparison, in one of the 4 slots.
- **195** — Fail if the user does not exist **or** the hash does not match…
- **196–198** — Comment: failures are deliberately not logged, since people sometimes type their password into the username box.
- **199** — …with the same message in both cases.
- **200** — Success: this connection is logged in.
- **201** — Log the successful login.
- **202** — Reply.
- **204–206** — `logout` forgets the login for this connection.

### The user directory

[`server/server.py` lines 208–219](../server/server.py#L208-L219)

```python
208      # ------------------------------------------------------------ directory
209  
210      def users(self, conn, req):
211          """Everyone except the caller, with their public keys."""
212          with self.db.lock:
213              listing = [
214                  {"username": name, "enc_public_pem": u["enc_public_pem"], "sign_public_pem": u["sign_public_pem"]}
215                  for name, u in sorted(self.db.data["users"].items())
216              ]
217          if req.get("include_self") is True:
218              return {"ok": True, "users": listing}
219          return {"ok": True, "users": [u for u in listing if u["username"] != conn.user]}
```

- **208** — Section comment.
- **210–211** — `users` returns the directory.
- **212** — Under the lock…
- **213–216** — …build a list of every user, sorted by name, with **only** the username and the two public keys (never the password record).
- **217–218** — If the client asked for itself to be included (the client uses this to pin its own key and look up senders), return everyone. `is True` means only a real JSON `true` counts.
- **219** — Otherwise return everyone except the caller.

### Sending: checking the envelope

[`server/server.py` lines 221–235](../server/server.py#L221-L235)

```python
221      # ------------------------------------------------------------ messages
222  
223      def send(self, conn, req):
224          """Accept a sealed package. The server checks the envelope, never the contents."""
225          pkg = req["package"]
226          if not isinstance(pkg, dict):
227              return {"ok": False, "error": "Package must be a JSON object."}
228          required = ("version", "timestamp") + PACKAGE_STRING_FIELDS
229          missing = [f for f in required if f not in pkg]
230          if missing:
231              return {"ok": False, "error": f"Package is missing fields: {', '.join(missing)}."}
232          if not all(isinstance(pkg[f], str) for f in PACKAGE_STRING_FIELDS):
233              return {"ok": False, "error": "Package fields have the wrong type."}
234          if not MSG_ID_RE.fullmatch(pkg["msg_id"]):  # so an ID can never carry newlines or escape codes
235              return {"ok": False, "error": "Invalid message ID (must be 32 lowercase hex characters)."}
```

- **221** — Section comment.
- **223–224** — `send` accepts a sealed package; the docstring says the key point: the envelope is checked, never the contents.
- **225** — Read the package.
- **226–227** — It must be a JSON object.
- **228–231** — Every required field must be present; list any that are missing.
- **232–233** — All string fields must really be strings.
- **234–235** — The message ID must be exactly 32 lowercase hex characters. This is what makes it safe to print in the log lines below (the fix for finding V1).

[`server/server.py` lines 237–247](../server/server.py#L237-L247)

```python
237          # The logged-in user may only send as themselves. (Recipients still
238          # verify the signature: they must not have to trust the server.)
239          if pkg["sender"] != conn.user:
240              log.warning("rejected: %s tried to send as %r", conn.user, pkg["sender"][:40])
241              return {"ok": False, "error": "Sender does not match the logged-in user."}
242          ts = pkg["timestamp"]
243          # `type(...) is int` excludes True/False; the range check comes before any
244          # arithmetic so an enormous number cannot cause an overflow.
245          if type(ts) is not int or not 0 < ts < 2**40 or abs(time.time() - ts) > MAX_CLOCK_SKEW:
246              return {"ok": False, "error": "Message timestamp is more than 5 minutes away from the server's "
247                                            "time. Check that your computer's clock is correct."}
```

- **237–238** — Comment: honest servers stop impersonation early, but recipients still verify signatures and never rely on this check.
- **239–241** — The `sender` field must equal the logged-in user. The attempted name is logged with `%r` (Python's quoted, escaped form) and cut to 40 characters, so it cannot inject lines into the log.
- **242** — Read the timestamp.
- **243–244** — Comment.
- **245–247** — The timestamp must be a real integer (not `true`), in a sane range checked **before** any arithmetic (so `10**300` cannot cause an overflow), and within 5 minutes of the server's clock. The error tells the user to check their clock.

### Sending: replay check and storage

[`server/server.py` lines 249–263](../server/server.py#L249-L263)

```python
249          with self.db.lock:
250              if pkg["recipient"] not in self.db.data["users"]:
251                  return {"ok": False, "error": "Unknown recipient."}
252              # Replay protection: each message ID is accepted exactly once.
253              if pkg["msg_id"] in self.db.seen:
254                  log.warning("rejected replay of message %s", pkg["msg_id"])
255                  return {"ok": False, "error": f"Duplicate message ID {pkg['msg_id']}: replay rejected."}
256              self.db.seen.add(pkg["msg_id"])
257              self.db.data["seen_msg_ids"].append(pkg["msg_id"])
258              # Stored exactly as received: still encrypted, still signed.
259              self.db.data["messages"].append({"package": pkg, "received_at": int(time.time()), "delivered": False})
260              self.db.save()
261          log.info("stored message %s from %s to %s (%d bytes of ciphertext, base64)",
262                   pkg["msg_id"], pkg["sender"], pkg["recipient"], len(pkg["ciphertext"]))
263          return {"ok": True, "msg_id": pkg["msg_id"]}
```

- **249** — Take the database lock for the rest.
- **250–251** — The recipient must be a registered user.
- **252** — Comment.
- **253–255** — If this message ID was accepted before, it is a replay: refuse and log it. The ID can be printed as-is because line 234 already guaranteed it is plain hex.
- **256–257** — Remember the ID: in the fast set, and in the saved list so it survives a restart.
- **258–259** — Store the package **exactly as received**, with the time it arrived and `delivered: false`.
- **260** — Save the database.
- **261–262** — Log the ID (validated hex), sender (the logged-in user), recipient (a registered user) and ciphertext size. Every value printed here has been validated, so the log cannot be forged through it.
- **263** — Reply with the accepted ID.

### Forwarding: the inbox

[`server/server.py` lines 265–278](../server/server.py#L265-L278)

```python
265      def inbox(self, conn, req):
266          """Forward every undelivered package addressed to the caller."""
267          with self.db.lock:
268              out = []
269              for entry in self.db.data["messages"]:
270                  pkg = entry.get("package") if isinstance(entry, dict) else None
271                  # Skip anything malformed (e.g. a hand-edited database) instead of failing the whole inbox.
272                  if not isinstance(pkg, dict) or pkg.get("recipient") != conn.user or entry.get("delivered"):
273                      continue
274                  out.append(pkg)
275                  entry["delivered"] = True
276              if out:
277                  self.db.save()
278          return {"ok": True, "messages": out}
```

- **265–266** — `inbox` delivers waiting packages.
- **267** — Under the lock…
- **268** — …collect into a list.
- **269** — Go through every stored message.
- **270** — Take its package, or `None` if the entry is not a proper object.
- **271–273** — Skip junk entries (such as a hand-edited database), packages for other users, and packages already delivered.
- **274** — Add it to the reply.
- **275** — Mark it delivered, so it is sent only once. (It is marked before the client has confirmed it can read it; see document 6.)
- **276–277** — Save only if something changed.
- **278** — Reply with the list.

### `ThreadedServer`: accepting connections

[`server/server.py` lines 281–296](../server/server.py#L281-L296)

```python
281  class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
282      allow_reuse_address = True
283      daemon_threads = True
284  
285      def __init__(self, address, app: ChatApp, tls_context: ssl.SSLContext):
286          self.app = app
287          self.tls_context = tls_context
288          self._connections = set()
289          self._conn_lock = threading.Lock()
290          super().__init__(address, RequestHandler)
291  
292      def get_request(self):
293          """Every accepted connection is wrapped in TLS before anything is read from it.
294          The handshake itself runs later, in the connection's thread (see RequestHandler.setup)."""
295          sock, addr = self.socket.accept()
296          return self.tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr
```

- **281** — `ThreadingMixIn` gives each connection its own thread; `TCPServer` listens for TCP connections.
- **282** — Allow restarting immediately on the same port, without waiting for the operating system to release it.
- **283** — Connection threads are "daemon" threads, so they don't keep the program alive after the main thread exits.
- **285** — The constructor receives the address, the logic and the TLS context.
- **286–287** — Store them.
- **288–289** — A set of open connections, and a lock protecting it.
- **290** — The parent constructor binds and listens, and remembers that `RequestHandler` handles each connection.
- **292–294** — `get_request` overrides how a connection is accepted.
- **295** — Accept the raw TCP connection.
- **296** — Wrap it in TLS as the server side, but **don't** do the handshake here (`do_handshake_on_connect=False`). This code runs in the single thread that accepts every connection, so a slow handshake here would block everyone. The handshake happens in the connection's own thread (line 70).

[`server/server.py` lines 298–305](../server/server.py#L298-L305)

```python
298      def handle_error(self, request, client_address):
299          """A connection that fails (e.g. a failed TLS handshake) is closed quietly
300          instead of printing a traceback; the server carries on."""
301          exc = sys.exc_info()[1]
302          if isinstance(exc, (ssl.SSLError, OSError)):
303              log.info("dropped connection from %s:%s (%s)", *client_address, exc.__class__.__name__)
304          else:
305              log.exception("error on connection from %s:%s", *client_address)
```

- **298–300** — `handle_error` is called by `socketserver` when a connection's handler raises an exception.
- **301** — Get the exception currently being handled.
- **302–303** — Network and TLS errors (failed handshake, client vanished) are normal: log one line.
- **304–305** — Anything else is unexpected: log the full traceback.

[`server/server.py` lines 307–324](../server/server.py#L307-L324)

```python
307      def track(self, sock):
308          with self._conn_lock:
309              self._connections.add(sock)
310  
311      def untrack(self, sock):
312          with self._conn_lock:
313              self._connections.discard(sock)
314  
315      def stop(self):
316          """Stop accepting, then drop every open session (like the process exiting)."""
317          self.shutdown()
318          with self._conn_lock:
319              for sock in list(self._connections):
320                  try:
321                      sock.shutdown(socket.SHUT_RDWR)
322                  except OSError:
323                      pass
324          self.server_close()
```

- **307–309** — `track` records an open connection.
- **311–313** — `untrack` forgets it.
- **315–316** — `stop` behaves like killing the server process: used by tests and the demo.
- **317** — Stop accepting new connections.
- **318–323** — Forcibly shut down every open session's socket; ignore errors for ones already closing.
- **324** — Close the listening socket.

### Starting the server

[`server/server.py` lines 327–336](../server/server.py#L327-L336)

```python
327  def start_in_background(host: str, port: int, db_path: str, tls_dir: str | None = None) -> ThreadedServer:
328      """Start a server on a background thread (used by tests and the demo). Port 0 = pick a free port.
329      TLS certificates live in `tls_dir` (default: a "tls" folder next to the database);
330      clients must trust `server.ca_file`."""
331      tls_dir = tls_dir or os.path.join(os.path.dirname(os.path.abspath(db_path)), "tls")
332      paths, _ = ensure_server_tls(tls_dir)
333      srv = ThreadedServer((host, port), ChatApp(db_path), server_context(paths["cert"], paths["key"]))
334      srv.ca_file = paths["ca"]
335      threading.Thread(target=srv.serve_forever, daemon=True).start()
336      return srv
```

- **327–330** — `start_in_background` is used by tests and the demo. Port 0 means "pick any free port".
- **331** — By default the certificates go in a `tls` folder next to the database.
- **332** — Create the certificates if needed.
- **333** — Build the server with a TLS 1.3 context from those files.
- **334** — Remember where `ca.crt` is, so tests can give it to clients.
- **335** — Run `serve_forever` on a daemon thread.
- **336** — Return the running server.

[`server/server.py` lines 339–348](../server/server.py#L339-L348)

```python
339  def main():
340      parser = argparse.ArgumentParser(description="Secure chat relay server")
341      parser.add_argument("--host", default="127.0.0.1", help="address to listen on (0.0.0.0 = all networks)")
342      parser.add_argument("--port", type=int, default=5050)
343      parser.add_argument("--db", default="server_data/db.json", help="path of the JSON database")
344      parser.add_argument("--tls-dir", default="server_data/tls", help="folder for the TLS certificates")
345      parser.add_argument("--hostname", action="append", default=[],
346                          help="extra name or IP clients will use to reach this server (repeatable; "
347                               "only used when the certificates are first created)")
348      args = parser.parse_args()
```

- **339** — `main` runs for `py -m server.server`.
- **340** — Create the option parser.
- **341** — `--host`: the address to listen on. The default `127.0.0.1` accepts only connections from this computer; `0.0.0.0` accepts them from the network.
- **342** — `--port`, default 5050.
- **343** — `--db`: the database file.
- **344** — `--tls-dir`: the certificate folder.
- **345–347** — `--hostname`, repeatable: extra names or IPs to put in the certificate (only used when certificates are created).
- **348** — Parse the command line.

[`server/server.py` lines 349–355](../server/server.py#L349-L355)

```python
349      logging.basicConfig(level=logging.INFO, format="%(asctime)s [server] %(message)s")
350  
351      names = list(DEFAULT_HOSTNAMES) + args.hostname + ([args.host] if args.host not in ("0.0.0.0", "::") else [])
352      paths, created = ensure_server_tls(args.tls_dir, names)
353      if created:
354          log.info("created TLS certificates in %s for: %s", args.tls_dir, ", ".join(dict.fromkeys(names)))
355      log.info("clients must trust %s (fingerprint %s)", paths["ca"], certificate_fingerprint(paths["ca"]))
```

- **349** — Switch on logging with timestamps.
- **351** — The names to put in the certificate: the defaults, any `--hostname`, and the listening address itself unless it is a wildcard.
- **352** — Load or create the certificates.
- **353–354** — If new ones were made, say so and list the names.
- **355** — Always print where `ca.crt` is and its fingerprint, so clients can check their copy.

[`server/server.py` lines 356–375](../server/server.py#L356-L375)

```python
356      try:
357          srv = ThreadedServer((args.host, args.port), ChatApp(args.db), server_context(paths["cert"], paths["key"]))
358      except ssl.SSLError as exc:
359          sys.exit(f"Cannot load the TLS certificate or key in {args.tls_dir} ({exc}). "
360                   "Delete that folder to create new ones.")
361      except OSError as exc:
362          sys.exit(f"Cannot listen on {args.host}:{args.port} ({exc}). "
363                   "Is another server already running? Try --port with another number.")
364      except ValueError as exc:
365          sys.exit(f"Cannot read the database {args.db}: {exc}")
366      with srv:
367          log.info("listening on %s:%d with TLS 1.3, database %s", args.host, args.port, args.db)
368          try:
369              srv.serve_forever()
370          except KeyboardInterrupt:
371              log.info("shutting down")
372  
373  
374  if __name__ == "__main__":
375      main()
```

- **356–357** — Create the server: open the database, build the TLS context, bind the port.
- **358–360** — An unreadable certificate or key: exit with advice to delete the folder.
- **361–363** — The port is in use or not allowed: exit with advice.
- **364–365** — A damaged database (JSON errors are `ValueError`): exit with a clear message.
- **366** — `with srv:` closes the listening socket when the block ends.
- **367** — Announce it is listening with TLS 1.3.
- **368–369** — Serve until stopped.
- **370–371** — Ctrl+C stops it with a log line instead of a traceback.
- **374–375** — Run `main()` when executed as a program (not when imported by tests).
