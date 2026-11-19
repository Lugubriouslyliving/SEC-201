# 4. The client, line by line

[← The server](03-server.md) · [Index](README.md) · Next: [Demo and tests →](05-demo-and-tests.md)

All encryption, decryption, signing and verifying happens in the client. It is built in
three layers:

| File | Layer | Job |
|---|---|---|
| [`connection.py`](#41-connectionpy) | transport | One TLS 1.3 connection; send a JSON request, get a JSON reply |
| [`session.py`](#42-sessionpy) | logic | Accounts, key files, key pinning, replay list, sealing and opening messages |
| [`cli.py`](#43-clipy) | interface | The shell you type into, including live chat mode |

[`client/__init__.py` lines 1–1](../client/__init__.py#L1-L1)

```python
1  """Command-line chat client. All encryption, decryption, signing and verification happens here."""
```

- **1** — Package docstring; makes `client` a package so it can be run as `py -m client.cli`.

## 4.1 `connection.py`

[`client/connection.py` lines 1–11](../client/connection.py#L1-L11)

```python
 1  """A tiny JSON-lines client for the relay server, over TLS 1.3."""
 2  
 3  import json
 4  import os
 5  import socket
 6  import ssl
 7  import threading
 8  
 9  from crypto_utils.tls import client_context
10  
11  DEFAULT_CA_FILE = os.path.join("server_data", "tls", "ca.crt")
```

- **1** — Module docstring.
- **3** — `json` to encode requests and decode replies.
- **4** — `os` to check the CA file exists.
- **5** — `socket` for the TCP connection.
- **6** — `ssl` for TLS.
- **7** — `threading` for the request lock.
- **9** — The client TLS settings from `tls.py` (trust only our CA, TLS 1.3 only).
- **11** — Where to look for `ca.crt` by default: `server_data/tls/ca.crt` relative to the current folder, which works when client and server run from the same project folder.

[`client/connection.py` lines 14–34](../client/connection.py#L14-L34)

```python
14  class ConnectionError_(Exception):
15      """The server cannot be reached or the connection broke. The session is over."""
16  
17  
18  class Connection:
19      """One TLS connection = one session with the server."""
20  
21      def __init__(self, host: str, port: int, ca_file: str = DEFAULT_CA_FILE, timeout: float = 30.0):
22          if not os.path.exists(ca_file):
23              raise ConnectionError_(
24                  f"Cannot find the server's CA certificate '{ca_file}'. Copy ca.crt from the server's "
25                  "server_data\\tls folder to this computer and pass it with --ca."
26              )
27          try:
28              context = client_context(ca_file)
29          except (ssl.SSLError, OSError) as exc:
30              raise ConnectionError_(f"'{ca_file}' is not a valid CA certificate ({exc.__class__.__name__}).") from None
31          try:
32              raw = socket.create_connection((host, port), timeout=timeout)
33          except OSError as exc:
34              raise ConnectionError_(f"Cannot reach server at {host}:{port} ({exc}).") from None
```

- **14–15** — `ConnectionError_` (with an underscore, so it doesn't clash with Python's built-in `ConnectionError`) means "the session with the server is over".
- **18–19** — `Connection`: one TLS connection is one session.
- **21** — The constructor takes host, port, CA file, and a 30-second network timeout.
- **22–26** — If the CA file is missing, stop with instructions on where to get it.
- **27–30** — Build the TLS context; a file that is not a valid certificate gives a clear error.
- **31–32** — Open the TCP connection (30-second timeout).
- **33–34** — Server not running or unreachable → a clear error.

[`client/connection.py` lines 35–56](../client/connection.py#L35-L56)

```python
35          try:
36              # The handshake checks: TLS 1.3, certificate signed by OUR CA, and
37              # issued for `host`. Any failure means we are not talking to our server.
38              self.sock = context.wrap_socket(raw, server_hostname=host)
39          except ssl.SSLCertVerificationError as exc:
40              raw.close()
41              raise ConnectionError_(
42                  f"SECURITY WARNING: the server's certificate is not trusted ({exc.verify_message}). "
43                  "Someone may be impersonating the server. Not connecting."
44              ) from None
45          except (ssl.SSLError, OSError) as exc:
46              raw.close()
47              raise ConnectionError_(f"Could not set up a secure TLS connection to {host}:{port} "
48                                     f"({exc.__class__.__name__}). Is this the chat server?") from None
49          self.tls_version = self.sock.version()
50          self.cipher = self.sock.cipher()[0]
51          self.reader = self.sock.makefile("rb")
52          # Chat mode checks the inbox on a background thread while the user
53          # sends from the main thread; the lock keeps each request paired
54          # with its own response.
55          self.lock = threading.Lock()
56          self.broken = False
```

- **35–37** — Comment: what the handshake checks.
- **38** — `wrap_socket` performs the TLS 1.3 handshake. `server_hostname=host` makes the client check that the server's certificate was issued for exactly this name or IP, and was signed by our CA. The connection is then encrypted.
- **39–44** — If the certificate check fails (signed by another CA, wrong host name, expired), close the socket and stop with a **security warning**: someone may be impersonating the server. Nothing has been sent.
- **45–48** — Any other TLS failure (for example the server doesn't speak TLS) → a clear error.
- **49** — Remember the TLS version agreed (`TLSv1.3`), for display.
- **50** — Remember the cipher suite (e.g. `TLS_AES_256_GCM_SHA384`).
- **51** — A file-like reader on the TLS socket, so whole lines can be read.
- **52–54** — Comment: why there is a lock.
- **55** — The lock: only one request/reply exchange at a time on this connection.
- **56** — Once anything goes wrong the connection is marked broken and not reused.

[`client/connection.py` lines 58–82](../client/connection.py#L58-L82)

```python
58      def request(self, payload: dict) -> dict:
59          """Send one JSON object, wait for one JSON object back.
60  
61          Any network failure (server stopped, Wi-Fi dropped, timeout) or a
62          reply that is not a JSON object becomes ConnectionError_, so callers
63          handle one exception type instead of a dozen.
64          """
65          with self.lock:
66              if self.broken:
67                  raise ConnectionError_("The connection to the server was lost. Restart the client.")
68              try:
69                  self.sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
70                  line = self.reader.readline()
71                  if not line:
72                      raise ConnectionError_("The server closed the connection.")
73                  reply = json.loads(line.decode("utf-8"))
74                  if not isinstance(reply, dict) or not isinstance(reply.get("ok"), bool):
75                      raise ConnectionError_("The server sent an invalid reply.")
76                  return reply
77              except ConnectionError_:
78                  self.broken = True
79                  raise
80              except (OSError, ValueError) as exc:  # ssl.SSLError is an OSError
81                  self.broken = True
82                  raise ConnectionError_(f"Lost connection to the server ({exc.__class__.__name__}).") from None
```

- **58** — `request` sends one request and returns the reply.
- **59–64** — Docstring: every kind of failure becomes `ConnectionError_`.
- **65** — Take the lock, so the chat listener thread and the typing thread never interleave their requests and replies.
- **66–67** — Refuse to use a broken connection.
- **68–69** — Serialize the request to JSON, add the newline, send it all through TLS.
- **70** — Read one line, the reply.
- **71–72** — An empty read means the server closed the connection.
- **73** — Parse the reply.
- **74–75** — It must be an object with a boolean `ok`; anything else is treated as a broken server.
- **76** — Return it.
- **77–79** — Our own errors: mark broken and pass them on.
- **80–82** — Network/TLS errors (`OSError`, which includes `ssl.SSLError`) or unparseable replies (`ValueError`): mark broken and turn them into `ConnectionError_`.

[`client/connection.py` lines 84–89](../client/connection.py#L84-L89)

```python
84      def close(self) -> None:
85          try:
86              self.reader.close()
87              self.sock.close()
88          except OSError:
89              pass
```

- **84–89** — `close` closes the reader and the socket, ignoring errors if already closed.

## 4.2 `session.py`

### Header, rules and helpers

[`client/session.py` lines 1–22](../client/session.py#L1-L22)

```python
 1  """Client-side logic: keys on disk, talking to the server, sealing and opening messages.
 2  
 3  Local files, per user, under the client's data folder (default ./client_data):
 4  
 5      <user>/keys.json        both private keys, encrypted with a password-derived key
 6      <user>/seen_ids.json    message IDs already accepted (replay detection)
 7      <user>/known_keys.json  public keys seen for each contact (key pinning)
 8  """
 9  
10  import json
11  import os
12  import re
13  import sys
14  import threading
15  import time
16  import unicodedata
17  
18  from crypto_utils.keys import KeyFileError, UserKeys, fingerprint
19  from crypto_utils.messages import MessageRejected, encrypt_and_sign, verify_and_decrypt
20  from crypto_utils.passwords import client_password_hash
21  
22  from .connection import DEFAULT_CA_FILE, Connection
```

- **1–8** — Module docstring and the three local files per user.
- **10** — `json` for local files.
- **11** — `os` for paths and atomic renames.
- **12** — `re` for the username pattern.
- **13** — `sys` to print notices to the error stream.
- **14** — `threading` for the file lock and thread IDs.
- **15** — `time` to name backups of damaged files.
- **16** — `unicodedata` to classify characters in `safe_display`.
- **18** — Key-file error, the key class, and fingerprints.
- **19** — The message functions.
- **20** — The client-side login hash.
- **22** — The connection class and the default CA path.

[`client/session.py` lines 24–43](../client/session.py#L24-L43)

```python
24  # Same rules the server enforces; checked here first so a typo is reported
25  # instantly instead of after generating keys.
26  USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
27  MIN_PASSWORD_LEN = 8
28  MAX_PASSWORD_LEN = 1024
29  # About 10 pages of text. Keeps every package far below the server's 1 MB
30  # request limit even for 3-byte characters (Thai, Chinese) after base64.
31  MAX_MESSAGE_CHARS = 20_000
32  
33  
34  class ClientError(Exception):
35      pass
36  
37  
38  def _no_trace(step, detail=""):
39      pass
40  
41  
42  def _stderr_notice(text):
43      print(f"Notice: {text}", file=sys.stderr)
```

- **24–25** — Comment: these rules mirror the server's, checked locally first.
- **26** — Same username pattern as the server.
- **27** — Minimum password length 8. Only the client can enforce this, because the server never sees the password.
- **28** — Maximum 1,024 characters.
- **29–30** — Comment: why the message limit.
- **31** — At most 20,000 characters per message. Even at 3 bytes per character (Thai) plus base64 growth, that stays far below the server's 1 MB request limit.
- **34–35** — `ClientError` means "this command failed, but the session continues" (unlike `ConnectionError_`).
- **38–39** — Default "do nothing" trace printer.
- **42–43** — Default way to show notices: print to the error stream.

[`client/session.py` lines 46–66](../client/session.py#L46-L66)

```python
46  _ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
47  
48  
49  def safe_display(text) -> str:
50      """Make received text safe to print in a terminal.
51  
52      Message text comes from other people. Printed raw, a newline would let
53      a sender fake a whole extra line ("[12:00] bob: ...") and escape codes
54      (ESC [ ...) could clear the screen or recolour text. So invisible control
55      and formatting characters are shown as visible escapes like \\n or \\x1b.
56      Ordinary text in any language, including emoji, is left alone.
57      """
58      out = []
59      for ch in str(text):
60          if ch in "‌‍":  # zero-width (non-)joiners: needed by emoji sequences and some scripts
61              out.append(ch)
62          elif unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs"):
63              out.append(_ESCAPES.get(ch) or (f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}"))
64          else:
65              out.append(ch)
66      return "".join(out)
```

- **46** — How to show the three most common control characters.
- **49** — `safe_display` makes text received from other people safe to print.
- **50–57** — Docstring: a raw newline could fake a whole chat line, and escape codes (`ESC [ …`) could clear or recolour the screen.
- **58** — Build the output piece by piece.
- **59** — Look at every character.
- **60–61** — Keep the zero-width joiner and non-joiner (invisible in this source line). Emoji sequences and some writing systems need them, and they cannot move the cursor.
- **62** — Unicode categories `Cc` (control characters such as newline and ESC), `Cf` (invisible formatting, including right-to-left overrides that can reverse how text appears), `Zl`/`Zp` (line and paragraph separators) and `Cs` (broken surrogate halves)…
- **63** — …are replaced by a visible escape: `\n`, `\r`, `\t`, `\x1b`, or `\uXXXX`.
- **64–65** — Every other character (letters in any language, digits, emoji, punctuation) is kept.
- **66** — Join and return.

### `ChatClient`: setup and local files

[`client/session.py` lines 69–80](../client/session.py#L69-L80)

```python
69  class ChatClient:
70      def __init__(self, host: str, port: int, data_dir: str = "client_data", trace=_no_trace, notice=_stderr_notice,
71                   ca_file: str = DEFAULT_CA_FILE):
72          self.host, self.port = host, port
73          self.data_dir = data_dir
74          self.trace = trace
75          self.notice = notice
76          self.conn = Connection(host, port, ca_file)
77          self.username: str | None = None
78          self.keys: UserKeys | None = None
79          self.seen_ids: set[str] = set()
80          self.file_lock = threading.Lock()  # chat mode writes files from two threads
```

- **69** — `ChatClient` is everything one user's client does.
- **70–71** — The constructor: server address, data folder, trace printer, notice printer, CA file.
- **72–75** — Store the settings.
- **76** — Open the TLS connection right away (section 4.1).
- **77** — Not logged in.
- **78** — No keys loaded.
- **79** — The set of accepted message IDs.
- **80** — A lock for local files, because chat mode writes them from two threads.

[`client/session.py` lines 82–106](../client/session.py#L82-L106)

```python
 82      # ------------------------------------------------------------ files
 83  
 84      def _path(self, username: str, name: str) -> str:
 85          return os.path.join(self.data_dir, username, name)
 86  
 87      def _read_json(self, username, name, default, expect_type):
 88          """Read a local JSON file. A damaged file is moved aside (not deleted) and
 89          `default` is used, so one bad file cannot lock you out of chatting."""
 90          path = self._path(username, name)
 91          if not os.path.exists(path):
 92              return default
 93          try:
 94              with open(path, "r", encoding="utf-8") as f:
 95                  data = json.load(f)
 96              if not isinstance(data, expect_type):
 97                  raise ValueError("unexpected content")
 98              return data
 99          except (OSError, ValueError) as exc:
100              backup = f"{path}.damaged-{int(time.time())}"
101              try:
102                  os.replace(path, backup)
103              except OSError:
104                  backup = "(could not move it)"
105              self.notice(f"{name} was damaged ({exc.__class__.__name__}); starting a fresh one. Old copy: {backup}")
106              return default
```

- **82** — Section comment.
- **84–85** — `_path` builds `data_dir/<username>/<file>`.
- **87–89** — `_read_json` reads a local JSON file; a damaged one is moved aside, not deleted.
- **90** — Work out the path.
- **91–92** — No file yet → the default (empty list or dict).
- **93–95** — Open and parse.
- **96–97** — It must have the expected type (list or dict).
- **98** — Return it.
- **99** — On a read or parse error…
- **100** — …name a backup with the current time…
- **101–104** — …and rename the damaged file to it (if even that fails, say so).
- **105** — Tell the user what happened.
- **106** — Carry on with the default.

[`client/session.py` lines 108–123](../client/session.py#L108-L123)

```python
108      def _write_json(self, username, name, data):
109          """Write to a temporary file, then rename over the old one, so a crash or a
110          second thread never leaves a half-written file."""
111          path = self._path(username, name)
112          with self.file_lock:
113              os.makedirs(os.path.dirname(path), exist_ok=True)
114              tmp = f"{path}.tmp-{threading.get_ident()}"
115              with open(tmp, "w", encoding="utf-8") as f:
116                  json.dump(data, f, indent=2)
117              os.replace(tmp, path)
118  
119      def _request(self, payload: dict) -> dict:
120          resp = self.conn.request(payload)
121          if not resp["ok"]:
122              raise ClientError(str(resp.get("error", "The server refused the request."))[:300])
123          return resp
```

- **108–110** — `_write_json` writes a file safely.
- **111** — Work out the path.
- **112** — Take the file lock.
- **113** — Create the folder if needed.
- **114** — A temporary name that includes the thread ID, so two threads never share one.
- **115–116** — Write the JSON.
- **117** — Atomically rename over the real file: readers see the old version or the new one, never half of one.
- **119** — `_request` sends a request and turns an error reply into `ClientError`.
- **120** — Send through the connection.
- **121–122** — If `ok` is false, raise `ClientError` with the server's message (cut to 300 characters).
- **123** — Otherwise return the reply.

### Sign up

[`client/session.py` lines 125–147](../client/session.py#L125-L147)

```python
125      # ------------------------------------------------------------ accounts
126  
127      def signup(self, username: str, password: str) -> None:
128          if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
129              raise ClientError("Username must be 3-20 characters using only a-z, 0-9 and _ (lowercase).")
130          if not MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN:
131              raise ClientError(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.")
132          if os.path.exists(self._path(username, "keys.json")):
133              raise ClientError(f"A key file for '{username}' already exists in {self.data_dir}. Use login instead.")
134          self.trace("KEYGEN", "generating RSA-3072 (encryption) and Ed25519 (signing) key pairs locally")
135          keys = UserKeys.generate()
136          login_hash = self._hash_password(username, password)
137          self._request({
138              "action": "signup",
139              "username": username,
140              "password_hash": login_hash,
141              "enc_public_pem": keys.enc_public_pem(),
142              "sign_public_pem": keys.sign_public_pem(),
143          })
144          # Only after the server accepted the name do we write the key file.
145          self._write_json(username, "keys.json", keys.to_encrypted_file(password))
146          self.trace("PROTECT KEYS", f"private keys saved encrypted (scrypt + AES-256-GCM) in {self._path(username, 'keys.json')}")
147          self._start_session(username, keys)
```

- **125** — Section comment.
- **127** — `signup`.
- **128–129** — Check the username pattern first: instant feedback, before any slow key generation. `fullmatch` means the whole name must match, so a name with a trailing newline is refused.
- **130–131** — Check the password length (only the client can).
- **132–133** — If this folder already holds keys for this name, refuse rather than overwrite them.
- **134** — Trace.
- **135** — Generate both key pairs locally (RSA-3072 takes about half a second).
- **136** — Compute the login hash (≈0.1 s).
- **137–143** — Send the signup request: name, login hash, and the two **public** keys.
- **144** — Comment.
- **145** — Only now write `keys.json`, the private keys encrypted under `scrypt(password, new random salt)` (section 2.3). If the server had refused (name taken), no key file would be left behind.
- **146** — Trace.
- **147** — Start the session.

[`client/session.py` lines 149–154](../client/session.py#L149-L154)

```python
149      def _hash_password(self, username: str, password: str) -> str:
150          login_hash = client_password_hash(username, password)
151          self.trace("HASH PASSWORD",
152                     f"scrypt(password, salt = SHA-256(username)) -> {login_hash[:16]}...\n"
153                     "only this hash is sent; the password itself never leaves this computer")
154          return login_hash
```

- **149** — `_hash_password` wraps the login-hash function.
- **150** — Compute `scrypt(password, salt from username)`.
- **151–153** — Trace: shows only the first 16 characters of the hash.
- **154** — Return it.

### Log in

[`client/session.py` lines 156–178](../client/session.py#L156-L178)

```python
156      def login(self, username: str, password: str) -> None:
157          # A name that cannot exist is refused here, without contacting the
158          # server, so text typed into the wrong box is not sent anywhere.
159          if not isinstance(username, str) or not USERNAME_RE.fullmatch(username) or len(password) > MAX_PASSWORD_LEN:
160              raise ClientError("Invalid username or password.")
161          self._request({"action": "login", "username": username,
162                         "password_hash": self._hash_password(username, password)})
163          # The server said yes, so `username` is a real, validated name: safe to use in a path.
164          path = self._path(username, "keys.json")
165          if not os.path.exists(path):
166              self.conn.request({"action": "logout"})
167              raise ClientError(f"No key file for '{username}' in {self.data_dir}; this device cannot read their messages.")
168          try:
169              with open(path, "r", encoding="utf-8") as f:
170                  keys = UserKeys.from_encrypted_file(json.load(f), password)
171          except KeyFileError as exc:
172              self.conn.request({"action": "logout"})
173              raise ClientError(str(exc)) from None
174          except (OSError, ValueError, KeyError, TypeError) as exc:
175              self.conn.request({"action": "logout"})
176              raise ClientError(f"The key file {path} is damaged ({exc.__class__.__name__}). "
177                                "Restore it from a backup; without it this account's messages cannot be read.") from None
178          self._start_session(username, keys)
```

- **156** — `login`.
- **157–158** — Comment.
- **159–160** — A name that doesn't fully match the pattern (or an absurd password) is refused locally with the same generic message the server uses. Nothing is sent.
- **161–162** — Send the name and the login hash. A wrong password raises `ClientError` here with the server's generic message.
- **163** — Comment: the server accepted the name, so it is a valid name and safe to use in a file path.
- **164** — Path of the key file.
- **165–167** — No key file on this device: log out again and explain. (Keys exist only on the device where the account was created.)
- **168–170** — Open the file and decrypt the private keys with the password.
- **171–173** — Wrong password for the file or edited file (`KeyFileError`): log out and pass the message on.
- **174–177** — Unreadable or malformed file: log out and say which file is damaged.
- **178** — Success: start the session.

[`client/session.py` lines 180–194](../client/session.py#L180-L194)

```python
180      def _start_session(self, username, keys):
181          self.username, self.keys = username, keys
182          ids = self._read_json(username, "seen_ids.json", [], list)
183          self.seen_ids = {i for i in ids if isinstance(i, str)}
184  
185      def logout(self) -> None:
186          self.conn.request({"action": "logout"})
187          self.username, self.keys, self.seen_ids = None, None, set()
188  
189      def close(self) -> None:
190          self.conn.close()
191  
192      def _require_login(self):
193          if self.username is None:
194              raise ClientError("Please log in first.")
```

- **180–181** — `_start_session` remembers who is logged in and their keys.
- **182** — Load the accepted message IDs (empty list if none).
- **183** — Keep only string entries, as a set.
- **185–187** — `logout`: tell the server, and forget the user, keys and IDs on this side.
- **189–190** — `close` closes the connection.
- **192–194** — `_require_login` raises `ClientError` if nobody is logged in.

### The directory and key pinning

[`client/session.py` lines 196–232](../client/session.py#L196-L232)

```python
196      # ------------------------------------------------------------ directory
197  
198      def users(self, include_self: bool = False) -> list[dict]:
199          """Fetch users and public keys, pinning each user's keys the first time we see them.
200  
201          If the server later hands out DIFFERENT keys for a known user, that
202          could be the server trying to impersonate them, so we refuse.
203          """
204          self._require_login()
205          resp = self._request({"action": "users", "include_self": include_self})
206          listing = resp.get("users")
207          if not isinstance(listing, list):
208              raise ClientError("The server sent an invalid user list.")
209          with self.file_lock:
210              known = self._read_json(self.username, "known_keys.json", {}, dict)
211          changed = False
212          out = []
213          for u in listing:
214              # Ignore anything that is not a well-formed entry rather than crash on it.
215              if not isinstance(u, dict) or not all(isinstance(u.get(k), str)
216                                                    for k in ("username", "enc_public_pem", "sign_public_pem")):
217                  continue
218              u = {k: u[k] for k in ("username", "enc_public_pem", "sign_public_pem")}
219              u["fingerprint"] = fingerprint(u["enc_public_pem"], u["sign_public_pem"])
220              pinned = known.get(u["username"])
221              if not isinstance(pinned, dict):
222                  known[u["username"]] = {"enc_public_pem": u["enc_public_pem"], "sign_public_pem": u["sign_public_pem"]}
223                  changed = True
224                  u["key_status"] = "new (pinned now)"
225              elif pinned.get("enc_public_pem") != u["enc_public_pem"] or pinned.get("sign_public_pem") != u["sign_public_pem"]:
226                  u["key_status"] = "CHANGED - not trusted"
227              else:
228                  u["key_status"] = "matches pinned key"
229              out.append(u)
230          if changed:
231              self._write_json(self.username, "known_keys.json", known)
232          return out
```

- **196** — Section comment.
- **198** — `users` fetches the directory and applies pinning.
- **199–203** — Docstring.
- **204** — Must be logged in.
- **205** — Ask the server.
- **206–208** — The reply must contain a list.
- **209–210** — Load the pinned keys (under the file lock).
- **211–212** — Track whether anything new was pinned; collect results.
- **213** — For each user the server listed…
- **214–217** — …skip anything malformed instead of crashing.
- **218** — Keep only the three expected fields.
- **219** — Compute the fingerprint (section 2.3).
- **220** — Look up the pinned keys for this name.
- **221–224** — Never seen before: pin these keys now, and mark the entry "new (pinned now)".
- **225–226** — Seen before, but the keys differ: mark "CHANGED - not trusted". This is what catches a server trying to substitute keys.
- **227–228** — Same as pinned: "matches pinned key".
- **229** — Add to the results.
- **230–231** — Save the pinned keys if any were added.
- **232** — Return the list.

[`client/session.py` lines 234–244](../client/session.py#L234-L244)

```python
234      def _trusted_keys(self, username: str) -> dict:
235          """Public keys for `username`, but only if they match the pinned copy."""
236          for u in self.users(include_self=True):
237              if u["username"] == username:
238                  if u["key_status"].startswith("CHANGED"):
239                      raise ClientError(
240                          f"WARNING: the server now reports different keys for '{username}'. "
241                          "Refusing to use them. Verify the fingerprint with them in person."
242                      )
243                  return u
244          raise ClientError(f"Unknown user '{safe_display(username)[:40]}'.")
```

- **234–235** — `_trusted_keys` returns a user's keys only if they are trustworthy.
- **236** — Fetch the full directory, including ourselves.
- **237** — Find the requested user.
- **238–242** — Keys changed: refuse to use them, with a warning to compare fingerprints in person.
- **243** — Otherwise return the entry.
- **244** — No such user. The name is passed through `safe_display` and shortened, since it may come from a received package.

### Sending

[`client/session.py` lines 246–268](../client/session.py#L246-L268)

```python
246      # ------------------------------------------------------------ messages
247  
248      def build_package(self, recipient: str, text: str) -> dict:
249          """Encrypt and sign, but do not send (lets demos inspect or tamper with the package)."""
250          self._require_login()
251          if recipient == self.username:
252              raise ClientError("You cannot send a message to yourself.")
253          if len(text) > MAX_MESSAGE_CHARS:
254              raise ClientError(f"Message too long ({len(text)} characters; the limit is {MAX_MESSAGE_CHARS}).")
255          r = self._trusted_keys(recipient)
256          self.trace("READ", f"plaintext from {self.username} to {recipient}: {text!r}")
257          try:
258              return encrypt_and_sign(text, self.username, recipient, self.keys, r["enc_public_pem"], trace=self.trace)
259          except ValueError:
260              raise ClientError(f"'{recipient}' has an unusable public key; cannot encrypt to them.") from None
261  
262      def send_package(self, package: dict) -> str:
263          self._require_login()
264          self.trace("TRANSMIT", f"sending package {package['msg_id']} to the server over the socket")
265          return self._request({"action": "send", "package": package})["msg_id"]
266  
267      def send(self, recipient: str, text: str) -> str:
268          return self.send_package(self.build_package(recipient, text))
```

- **246** — Section comment.
- **248–249** — `build_package` encrypts and signs without sending (the demo uses this to tamper with a package).
- **250** — Must be logged in.
- **251–252** — No messages to yourself.
- **253–254** — Enforce the length limit before encrypting.
- **255** — Get the recipient's keys, pinned and checked.
- **256** — Trace (prints the plaintext; only in verbose mode, only on your own screen).
- **257–258** — Encrypt and sign (section 2.4) with the recipient's RSA public key.
- **259–260** — If their key cannot be used, a clear error.
- **262** — `send_package` sends a finished package.
- **263** — Must be logged in.
- **264** — Trace.
- **265** — Send it; return the message ID the server accepted.
- **267–268** — `send` builds and sends in one call.

### Receiving

[`client/session.py` lines 270–276](../client/session.py#L270-L276)

```python
270      def fetch_inbox(self) -> list:
271          """Raw packages from the server (still encrypted)."""
272          self._require_login()
273          messages = self._request({"action": "inbox"}).get("messages")
274          if not isinstance(messages, list):
275              raise ClientError("The server sent an invalid inbox.")
276          return messages
```

- **270–271** — `fetch_inbox` gets the raw, still-encrypted packages.
- **272** — Must be logged in.
- **273** — Ask the server.
- **274–275** — The reply must be a list.
- **276** — Return it.

[`client/session.py` lines 278–307](../client/session.py#L278-L307)

```python
278      def open_package(self, package) -> dict:
279          """Verify and decrypt one package. Never raises for a bad message;
280          returns {"ok": False, "reason": ...} so one bad message cannot hide the rest."""
281          is_dict = isinstance(package, dict)
282          sender = package.get("sender") if is_dict else None
283          sender = sender if isinstance(sender, str) else "?"
284          ts = package.get("timestamp") if is_dict else None
285          result = {"msg_id": package.get("msg_id") if is_dict else None,
286                    "sender": sender, "timestamp": ts if type(ts) is int and 0 < ts < 2**40 else None}
287          try:
288              if not is_dict:
289                  raise MessageRejected("malformed package (not an object)")
290              sender_keys = self._trusted_keys(sender)
291              self.trace("RECEIVE", f"package {safe_display(result['msg_id'])[:64]} claims to be from {sender}")
292              text = verify_and_decrypt(
293                  package, self.username, self.keys, sender_keys["sign_public_pem"],
294                  seen_ids=self.seen_ids, trace=self.trace,
295              )
296          except (MessageRejected, ClientError) as exc:
297              result.update(ok=False, reason=getattr(exc, "reason", str(exc)))
298              return result
299          except Exception as exc:  # last line of defence: never let one message crash the inbox
300              result.update(ok=False, reason=f"unreadable package ({exc.__class__.__name__})")
301              return result
302          self._write_json(self.username, "seen_ids.json", sorted(self.seen_ids))
303          result.update(ok=True, text=text)
304          return result
305  
306      def inbox(self) -> list[dict]:
307          return [self.open_package(p) for p in self.fetch_inbox()]
```

- **278–280** — `open_package` verifies and decrypts one package and never raises: one bad message must not hide the others.
- **281** — Is it a dict at all?
- **282–283** — The claimed sender, or `?` if missing or not text.
- **284** — The timestamp, if any.
- **285–286** — Start the result: message ID, sender, and the timestamp only if it is a sane integer (so the shell can show a time safely).
- **287** — Try the checks…
- **288–289** — Not an object: reject.
- **290** — Get the claimed sender's **pinned** keys. An unknown sender or changed key raises `ClientError`, which rejects the message.
- **291** — Trace for verbose mode. The message ID has not been validated yet at this point (that happens inside `verify_and_decrypt`), so it is passed through `safe_display` and cut to 64 characters before printing (part of the fix for finding V1).
- **292–295** — Verify the signature, then check recipient, time and replay, then unwrap, then decrypt (section 2.4), using this user's seen-ID set.
- **296–298** — Any `MessageRejected` or `ClientError`: mark the result not OK, with the reason.
- **299–301** — Any other exception (a bug or something unforeseen): also reject, never crash.
- **302** — Success: save the updated seen-ID list to disk, so a replay is caught even after restarting the client.
- **303** — Add the text to the result.
- **304** — Return it.
- **306–307** — `inbox` fetches and opens every package.

## 4.3 `cli.py`

### Header

[`client/cli.py` lines 1–25](../client/cli.py#L1-L25)

```python
 1  """Interactive command-line client.
 2  
 3  Run:  py -m client.cli --port 5050
 4  
 5  Commands:
 6      signup <username>          create an account (asks for a password)
 7      login <username>           log in (asks for a password)
 8      users                      list other users and their key fingerprints
 9      chat <username>            live conversation: type to send, replies appear as they arrive
10      send <recipient> <message> encrypt, sign and send one message
11      inbox                      fetch, verify and decrypt new messages
12      verbose on|off             print each crypto step as it happens
13      logout
14      quit
15  """
16  
17  import argparse
18  import cmd
19  import datetime
20  import getpass
21  import sys
22  import threading
23  
24  from .connection import DEFAULT_CA_FILE, ConnectionError_
25  from .session import ChatClient, ClientError, safe_display
```

- **1–15** — Module docstring: how to run it and the list of commands.
- **17** — `argparse` for options.
- **18** — `cmd` is Python's standard framework for line-based command shells: it reads a line, finds `do_<command>`, and calls it.
- **19** — `datetime` to show message times.
- **20** — `getpass` reads passwords without echoing them to the screen.
- **21** — `sys` to write directly to the terminal in chat mode.
- **22** — `threading` for the chat listener.
- **24** — The connection error and default CA path.
- **25** — The client logic and `safe_display`.

[`client/cli.py` lines 28–35](../client/cli.py#L28-L35)

```python
28  def print_step(step: str, detail: str = "") -> None:
29      print(f"  [{step}]")
30      for line in detail.splitlines():
31          print(f"      {line}")
32  
33  
34  def silent(step, detail=""):
35      pass
```

- **28–31** — `print_step` is the verbose-mode trace printer: the step name in brackets, then each detail line indented.
- **34–35** — `silent` prints nothing (verbose off).

### The shell

[`client/cli.py` lines 38–57](../client/cli.py#L38-L57)

```python
38  class ChatShell(cmd.Cmd):
39      intro = (
40          "Secure chat client.\n"
41          "  New here?  signup <your name>      Returning?  login <your name>\n"
42          "  Then:      users                   to see who you can talk to\n"
43          "             chat <their name>       to start chatting\n"
44          "Type 'help' for all commands."
45      )
46  
47      def __init__(self, client: ChatClient):
48          super().__init__()
49          self.client = client
50          self._update_prompt()
51  
52      def _update_prompt(self):
53          self.prompt = f"({self.client.username or 'not logged in'}) > "
54  
55      def postcmd(self, stop, line):
56          self._update_prompt()
57          return stop
```

- **38** — `ChatShell` builds on `cmd.Cmd`.
- **39–45** — The welcome text.
- **47–50** — Constructor: remember the client and set the prompt.
- **52–53** — The prompt shows who is logged in, e.g. `(bob) > `.
- **55–57** — After every command, refresh the prompt (login or logout may have changed it).

[`client/cli.py` lines 59–73](../client/cli.py#L59-L73)

```python
59      def onecmd(self, line):
60          # One place to turn errors into friendly messages.
61          try:
62              return super().onecmd(line)
63          except ClientError as exc:
64              print(f"Error: {exc}")
65          except ConnectionError_ as exc:
66              print(f"Connection problem: {exc}")
67              print("The client will now exit. Start the server if needed, then run the client again.")
68              return True
69          except Exception as exc:  # a bug, not the user's fault: report it and keep the shell running
70              print(f"Unexpected error ({exc.__class__.__name__}: {exc}). The command was not completed.")
71  
72      def emptyline(self):
73          pass
```

- **59** — `onecmd` runs one typed line; overriding it gives one place to handle errors.
- **60** — Comment.
- **61–62** — Run the command normally.
- **63–64** — A `ClientError` (wrong password, unknown user…) prints `Error: …` and the shell continues.
- **65–68** — A `ConnectionError_` means the session is over: explain and return `True`, which makes `cmd` exit the loop.
- **69–70** — Any other exception is a bug: report it, keep the shell running.
- **72–73** — An empty line does nothing (by default `cmd` would repeat the last command).

### Commands

[`client/cli.py` lines 75–99](../client/cli.py#L75-L99)

```python
75      # ---------------------------------------------------------- commands
76  
77      def do_signup(self, arg):
78          """signup <username>  - create an account and a new key pair on this device"""
79          username = arg.strip()
80          if not username:
81              print("Usage: signup <username>")
82              return
83          password = getpass.getpass("Choose a password (min 8 chars): ")
84          if password != getpass.getpass("Repeat password: "):
85              print("Passwords do not match.")
86              return
87          print("Generating keys (a few seconds)...")
88          self.client.signup(username, password)
89          print(f"Account created. Logged in as {username}.")
90  
91      def do_login(self, arg):
92          """login <username>  - log in and unlock your private keys"""
93          username = arg.strip()
94          if not username:
95              print("Usage: login <username>")
96              return
97          password = getpass.getpass("Password: ")
98          self.client.login(username, password)
99          print(f"Logged in as {username}.")
```

- **75** — Section comment.
- **77–78** — `signup <name>`; the docstring is what `help signup` shows.
- **79–82** — Require a name.
- **83** — Read the password without echo.
- **84–86** — Read it again; refuse if they differ.
- **87** — Warn that key generation takes a moment.
- **88** — Sign up (section 4.2).
- **89** — Confirm.
- **91–92** — `login <name>`.
- **93–96** — Require a name.
- **97** — Read the password without echo.
- **98** — Log in.
- **99** — Confirm.

[`client/cli.py` lines 101–116](../client/cli.py#L101-L116)

```python
101      def do_users(self, arg):
102          """users  - list other users with their public-key fingerprints"""
103          users = self.client.users()
104          if not users:
105              print("No other users yet.")
106          for u in users:
107              print(f"  {u['username']:<20} {u['fingerprint']}  ({u['key_status']})")
108  
109      def do_send(self, arg):
110          """send <recipient> <message>  - encrypt, sign and send a message"""
111          parts = arg.split(maxsplit=1)
112          if len(parts) != 2:
113              print("Usage: send <recipient> <message>")
114              return
115          msg_id = self.client.send(parts[0], parts[1])
116          print(f"Sent (message ID {msg_id}).")
```

- **101–102** — `users`.
- **103** — Fetch with pinning applied.
- **104–105** — Nobody else yet.
- **106–107** — Print each name, fingerprint and pin status. (Names come from the server but always match the strict username pattern.)
- **109–110** — `send <recipient> <message>`.
- **111** — Split into the recipient and the rest of the line (the message may contain spaces).
- **112–114** — Require both.
- **115** — Encrypt, sign, send.
- **116** — Show the message ID.

[`client/cli.py` lines 118–130](../client/cli.py#L118-L130)

```python
118      def do_inbox(self, arg):
119          """inbox  - fetch new messages, verify each signature, then decrypt"""
120          results = self.client.inbox()
121          if not results:
122              print("No new messages.")
123          for r in results:
124              when = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%Y-%m-%d %H:%M:%S") if r["timestamp"] else "?"
125              sender = safe_display(r["sender"])[:40]
126              if r["ok"]:
127                  print(f"  [{when}] {sender}: {safe_display(r['text'])}   (signature OK)")
128              else:
129                  print(f"  !! REJECTED message claiming to be from {sender} ({when})")
130                  print(f"     reason: {safe_display(r['reason'])}")
```

- **118–119** — `inbox`.
- **120** — Fetch and open every waiting package.
- **121–122** — Nothing new.
- **123** — For each result…
- **124** — …format its time, or `?` if none.
- **125** — Make the sender name safe and short.
- **126–127** — Accepted: print time, sender and the **safe** text.
- **128–130** — Rejected: a clear warning with the safe reason.

### Chat mode

[`client/cli.py` lines 132–149](../client/cli.py#L132-L149)

```python
132      def do_chat(self, arg):
133          """chat <username>  - live conversation; type /exit to leave"""
134          peer = arg.strip()
135          if not peer:
136              print("Usage: chat <username>   (type 'users' to see who is here)")
137              return
138          if self.client.username is None:
139              raise ClientError("Please log in first.")
140          if peer == self.client.username:
141              raise ClientError("You cannot chat with yourself.")
142          info = self.client._trusted_keys(peer)  # raises if unknown or if the key changed
143  
144          me = self.client.username
145          prompt = f"{me}> "
146          print(f"--- Chat with {peer} ---")
147          print(f"    {peer}'s key fingerprint: {info['fingerprint']}")
148          print("    Every message is encrypted for them and signed by you. Type /exit to leave.")
149          print()
```

- **132–133** — `chat <name>` starts a live conversation.
- **134** — The partner's name.
- **135–137** — Require it.
- **138–139** — Must be logged in.
- **140–141** — Not with yourself.
- **142** — Get their keys (pinned and checked); this fails cleanly if they don't exist or their key changed.
- **144** — Your name.
- **145** — The chat prompt, e.g. `bob> `.
- **146–149** — Print a header with the partner's fingerprint, for comparing in person.

[`client/cli.py` lines 151–159](../client/cli.py#L151-L159)

```python
151          print_lock = threading.Lock()
152          stop = threading.Event()
153  
154          def show(text):
155              # Print above the prompt, then redraw the prompt.
156              with print_lock:
157                  sys.stdout.write("\r" + " " * (len(prompt) + 40) + "\r")
158                  sys.stdout.write(text + "\n" + prompt)
159                  sys.stdout.flush()
```

- **151** — A lock so the two threads never print at the same moment.
- **152** — An `Event` used to tell the listener to stop.
- **154** — `show` prints an incoming line above the prompt.
- **155** — Comment.
- **156** — Hold the print lock.
- **157** — `\r` returns to the start of the line; spaces wipe the prompt; `\r` again.
- **158** — Print the message, a newline, and the prompt again.
- **159** — Flush so it appears now.

[`client/cli.py` lines 161–185](../client/cli.py#L161-L185)

```python
161          def receive_loop():
162              # Check the inbox once a second; verify and decrypt whatever arrived.
163              # Everything printed from a message goes through safe_display so a
164              # sender cannot inject fake lines or terminal escape codes.
165              while not stop.is_set():
166                  try:
167                      for r in self.client.inbox():
168                          when = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%H:%M") \
169                              if r["timestamp"] else "--:--"
170                          sender = safe_display(r["sender"])[:40]
171                          if not r["ok"]:
172                              show(f"[{when}] !! REJECTED a message claiming to be from {sender}: "
173                                   f"{safe_display(r['reason'])}")
174                          elif r["sender"] == peer:
175                              show(f"[{when}] {peer}: {safe_display(r['text'])}")
176                          else:
177                              show(f"[{when}] (from {sender}) {safe_display(r['text'])}")
178                  except ConnectionError_ as exc:
179                      show(f"!! {exc}  Type /exit.")
180                      return  # nothing more can arrive on a dead connection
181                  except ClientError as exc:
182                      show(f"!! could not check messages: {exc}")
183                  except Exception as exc:  # never let the listener die silently
184                      show(f"!! unexpected error while checking messages ({exc.__class__.__name__})")
185                  stop.wait(1.0)
```

- **161** — `receive_loop` runs in the background thread.
- **162–164** — Comment: everything from a message goes through `safe_display`.
- **165** — Until told to stop…
- **166–167** — …check the inbox (verifies and decrypts everything new).
- **168–169** — Format the time as hours:minutes.
- **170** — Make the sender name safe.
- **171–173** — Rejected: show a warning with the reason.
- **174–175** — From the partner: show `[time] name: text`.
- **176–177** — From someone else: show it labelled with their name.
- **178–180** — Connection lost: say so once and end the thread, since nothing more can arrive.
- **181–182** — Other client errors: show and keep going.
- **183–184** — Anything unexpected: show a short message; the listener never dies silently.
- **185** — Wait one second (or less if told to stop).

[`client/cli.py` lines 187–209](../client/cli.py#L187-L209)

```python
187          listener = threading.Thread(target=receive_loop, daemon=True)
188          listener.start()
189          try:
190              while True:
191                  line = input(prompt)
192                  text = line.strip()
193                  if text in ("/exit", "/quit", "/back"):
194                      break
195                  if not text:
196                      continue
197                  try:
198                      self.client.send(peer, text)
199                  except ClientError as exc:
200                      show(f"!! not sent: {exc}")
201                  except ConnectionError_ as exc:
202                      show(f"!! not sent: {exc}")
203                      break
204          except (EOFError, KeyboardInterrupt):
205              print()
206          finally:
207              stop.set()
208              listener.join(timeout=5)
209          print(f"--- Left chat with {peer} ---")
```

- **187–188** — Start the listener as a daemon thread (it won't keep the program alive).
- **189–190** — The main thread reads what you type.
- **191** — Wait for a line.
- **192** — Trim spaces.
- **193–194** — `/exit`, `/quit` or `/back` leaves the chat.
- **195–196** — Ignore empty lines.
- **197–198** — Encrypt, sign and send to the partner.
- **199–200** — A refused message (too long, key changed…): show why, keep chatting.
- **201–203** — Connection lost: show it and leave the chat.
- **204–205** — Ctrl+C or end-of-input also leaves.
- **206–208** — In every case, tell the listener to stop and wait up to 5 seconds for it.
- **209** — Confirm you have left.

[`client/cli.py` lines 211–227](../client/cli.py#L211-L227)

```python
211      def do_verbose(self, arg):
212          """verbose on|off  - show every crypto step"""
213          on = arg.strip().lower() in ("on", "1", "yes", "")
214          self.client.trace = print_step if on else silent
215          print(f"Verbose mode {'on' if on else 'off'}.")
216  
217      def do_logout(self, arg):
218          """logout"""
219          self.client.logout()
220          print("Logged out.")
221  
222      def do_quit(self, arg):
223          """quit"""
224          return True
225  
226      do_exit = do_quit
227      do_EOF = do_quit
```

- **211–212** — `verbose on|off`.
- **213** — `on`, `1`, `yes` or nothing at all means on.
- **214** — Swap in the step printer or the silent one.
- **215** — Confirm.
- **217–220** — `logout`.
- **222–224** — `quit` returns `True`, which ends the `cmd` loop.
- **226–227** — `exit` and end-of-input (Ctrl+Z on Windows) do the same as `quit`.

### Starting the client

[`client/cli.py` lines 230–261](../client/cli.py#L230-L261)

```python
230  def main():
231      parser = argparse.ArgumentParser(description="Secure chat client")
232      parser.add_argument("--host", default="127.0.0.1")
233      parser.add_argument("--port", type=int, default=5050)
234      parser.add_argument("--data", default="client_data", help="folder for this device's encrypted keys")
235      parser.add_argument("--ca", default=DEFAULT_CA_FILE,
236                          help="the server's CA certificate (copy of server_data\\tls\\ca.crt)")
237      args = parser.parse_args()
238      try:
239          client = ChatClient(args.host, args.port, args.data, trace=silent, ca_file=args.ca)
240      except ConnectionError_ as exc:
241          print(exc)
242          if "Cannot reach" in str(exc):
243              print("Start the server first:  py -m server.server")
244          return
245      shell = ChatShell(client)
246      shell.intro = (f"Connected securely ({client.conn.tls_version}, {client.conn.cipher}); "
247                     "server identity verified.\n" + shell.intro)
248      try:
249          while True:
250              try:
251                  shell.cmdloop()
252                  break
253              except KeyboardInterrupt:  # Ctrl+C at the prompt: don't crash, explain how to leave
254                  print("\n(Type 'quit' to exit.)")
255                  shell.intro = None
256      finally:
257          client.close()
258  
259  
260  if __name__ == "__main__":
261      main()
```

- **230** — `main` runs for `py -m client.cli`.
- **231** — Option parser.
- **232** — `--host`, the server address.
- **233** — `--port`.
- **234** — `--data`, this device's folder for keys and lists.
- **235–236** — `--ca`, the copy of the server's `ca.crt`.
- **237** — Parse.
- **238–239** — Create the client, which opens the TLS connection.
- **240–244** — If that fails, print why; if the server simply isn't running, say how to start it; then exit.
- **245** — Create the shell.
- **246–247** — Put the TLS version, cipher and "server identity verified" above the welcome text.
- **248–252** — Run the shell until `quit`.
- **253–255** — Ctrl+C at the prompt: don't crash; explain how to leave and keep going (without repeating the welcome text).
- **256–257** — In every case close the connection at the end.
- **260–261** — Run `main()` when executed as a program.
