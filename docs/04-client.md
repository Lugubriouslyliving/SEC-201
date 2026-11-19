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

[`client/session.py` lines 1–23](../client/session.py#L1-L23)

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
13  import shutil
14  import sys
15  import threading
16  import time
17  import unicodedata
18  
19  from crypto_utils.keys import KeyFileError, UserKeys, fingerprint
20  from crypto_utils.messages import MessageRejected, encrypt_and_sign, verify_and_decrypt
21  from crypto_utils.passwords import client_password_hash
22  
23  from .connection import DEFAULT_CA_FILE, Connection
```

- **1–8** — Module docstring and the three local files per user.
- **10** — `json` for local files.
- **11** — `os` for paths and atomic renames.
- **12** — `re` for the username pattern.
- **13** — `shutil` to delete this device's folder when the account is erased.
- **14** — `sys` to print notices to the error stream.
- **15** — `threading` for the file lock and thread IDs.
- **16** — `time` to name backups of damaged files.
- **17** — `unicodedata` to classify characters in `safe_display`.
- **19** — Key-file error, the key class, and fingerprints.
- **20** — The message functions.
- **21** — The client-side login hash.
- **23** — The connection class and the default CA path.

[`client/session.py` lines 25–44](../client/session.py#L25-L44)

```python
25  # Same rules the server enforces; checked here first so a typo is reported
26  # instantly instead of after generating keys.
27  USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
28  MIN_PASSWORD_LEN = 8
29  MAX_PASSWORD_LEN = 1024
30  # About 10 pages of text. Keeps every package far below the server's 1 MB
31  # request limit even for 3-byte characters (Thai, Chinese) after base64.
32  MAX_MESSAGE_CHARS = 20_000
33  
34  
35  class ClientError(Exception):
36      pass
37  
38  
39  def _no_trace(step, detail=""):
40      pass
41  
42  
43  def _stderr_notice(text):
44      print(f"Notice: {text}", file=sys.stderr)
```

- **25–26** — Comment: these rules mirror the server's, checked locally first.
- **27** — Same username pattern as the server.
- **28** — Minimum password length 8. Only the client can enforce this, because the server never sees the password.
- **29** — Maximum 1,024 characters.
- **30–31** — Comment: why the message limit.
- **32** — At most 20,000 characters per message. Even at 3 bytes per character (Thai) plus base64 growth, that stays far below the server's 1 MB request limit.
- **35–36** — `ClientError` means "this command failed, but the session continues" (unlike `ConnectionError_`).
- **39–40** — Default "do nothing" trace printer.
- **43–44** — Default way to show notices: print to the error stream.

[`client/session.py` lines 47–67](../client/session.py#L47-L67)

```python
47  _ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
48  
49  
50  def safe_display(text) -> str:
51      """Make received text safe to print in a terminal.
52  
53      Message text comes from other people. Printed raw, a newline would let
54      a sender fake a whole extra line ("[12:00] bob: ...") and escape codes
55      (ESC [ ...) could clear the screen or recolour text. So invisible control
56      and formatting characters are shown as visible escapes like \\n or \\x1b.
57      Ordinary text in any language, including emoji, is left alone.
58      """
59      out = []
60      for ch in str(text):
61          if ch in "‌‍":  # zero-width (non-)joiners: needed by emoji sequences and some scripts
62              out.append(ch)
63          elif unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs"):
64              out.append(_ESCAPES.get(ch) or (f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}"))
65          else:
66              out.append(ch)
67      return "".join(out)
```

- **47** — How to show the three most common control characters.
- **50** — `safe_display` makes text received from other people safe to print.
- **51–58** — Docstring: a raw newline could fake a whole chat line, and escape codes (`ESC [ …`) could clear or recolour the screen.
- **59** — Build the output piece by piece.
- **60** — Look at every character.
- **61–62** — Keep the zero-width joiner and non-joiner (invisible in this source line). Emoji sequences and some writing systems need them, and they cannot move the cursor.
- **63** — Unicode categories `Cc` (control characters such as newline and ESC), `Cf` (invisible formatting, including right-to-left overrides that can reverse how text appears), `Zl`/`Zp` (line and paragraph separators) and `Cs` (broken surrogate halves)…
- **64** — …are replaced by a visible escape: `\n`, `\r`, `\t`, `\x1b`, or `\uXXXX`.
- **65–66** — Every other character (letters in any language, digits, emoji, punctuation) is kept.
- **67** — Join and return.

### `ChatClient`: setup and local files

[`client/session.py` lines 70–81](../client/session.py#L70-L81)

```python
70  class ChatClient:
71      def __init__(self, host: str, port: int, data_dir: str = "client_data", trace=_no_trace, notice=_stderr_notice,
72                   ca_file: str = DEFAULT_CA_FILE):
73          self.host, self.port = host, port
74          self.data_dir = data_dir
75          self.trace = trace
76          self.notice = notice
77          self.conn = Connection(host, port, ca_file)
78          self.username: str | None = None
79          self.keys: UserKeys | None = None
80          self.seen_ids: set[str] = set()
81          self.file_lock = threading.Lock()  # chat mode writes files from two threads
```

- **70** — `ChatClient` is everything one user's client does.
- **71–72** — The constructor: server address, data folder, trace printer, notice printer, CA file.
- **73–76** — Store the settings.
- **77** — Open the TLS connection right away (section 4.1).
- **78** — Not logged in.
- **79** — No keys loaded.
- **80** — The set of accepted message IDs.
- **81** — A lock for local files, because chat mode writes them from two threads.

[`client/session.py` lines 83–107](../client/session.py#L83-L107)

```python
 83      # ------------------------------------------------------------ files
 84  
 85      def _path(self, username: str, name: str) -> str:
 86          return os.path.join(self.data_dir, username, name)
 87  
 88      def _read_json(self, username, name, default, expect_type):
 89          """Read a local JSON file. A damaged file is moved aside (not deleted) and
 90          `default` is used, so one bad file cannot lock you out of chatting."""
 91          path = self._path(username, name)
 92          if not os.path.exists(path):
 93              return default
 94          try:
 95              with open(path, "r", encoding="utf-8") as f:
 96                  data = json.load(f)
 97              if not isinstance(data, expect_type):
 98                  raise ValueError("unexpected content")
 99              return data
100          except (OSError, ValueError) as exc:
101              backup = f"{path}.damaged-{int(time.time())}"
102              try:
103                  os.replace(path, backup)
104              except OSError:
105                  backup = "(could not move it)"
106              self.notice(f"{name} was damaged ({exc.__class__.__name__}); starting a fresh one. Old copy: {backup}")
107              return default
```

- **83** — Section comment.
- **85–86** — `_path` builds `data_dir/<username>/<file>`.
- **88–90** — `_read_json` reads a local JSON file; a damaged one is moved aside, not deleted.
- **91** — Work out the path.
- **92–93** — No file yet → the default (empty list or dict).
- **94–96** — Open and parse.
- **97–98** — It must have the expected type (list or dict).
- **99** — Return it.
- **100** — On a read or parse error…
- **101** — …name a backup with the current time…
- **102–105** — …and rename the damaged file to it (if even that fails, say so).
- **106** — Tell the user what happened.
- **107** — Carry on with the default.

[`client/session.py` lines 109–124](../client/session.py#L109-L124)

```python
109      def _write_json(self, username, name, data):
110          """Write to a temporary file, then rename over the old one, so a crash or a
111          second thread never leaves a half-written file."""
112          path = self._path(username, name)
113          with self.file_lock:
114              os.makedirs(os.path.dirname(path), exist_ok=True)
115              tmp = f"{path}.tmp-{threading.get_ident()}"
116              with open(tmp, "w", encoding="utf-8") as f:
117                  json.dump(data, f, indent=2)
118              os.replace(tmp, path)
119  
120      def _request(self, payload: dict) -> dict:
121          resp = self.conn.request(payload)
122          if not resp["ok"]:
123              raise ClientError(str(resp.get("error", "The server refused the request."))[:300])
124          return resp
```

- **109–111** — `_write_json` writes a file safely.
- **112** — Work out the path.
- **113** — Take the file lock.
- **114** — Create the folder if needed.
- **115** — A temporary name that includes the thread ID, so two threads never share one.
- **116–117** — Write the JSON.
- **118** — Atomically rename over the real file: readers see the old version or the new one, never half of one.
- **120** — `_request` sends a request and turns an error reply into `ClientError`.
- **121** — Send through the connection.
- **122–123** — If `ok` is false, raise `ClientError` with the server's message (cut to 300 characters).
- **124** — Otherwise return the reply.

### Sign up

[`client/session.py` lines 126–151](../client/session.py#L126-L151)

```python
126      # ------------------------------------------------------------ accounts
127  
128      def signup(self, username: str, password: str, consent_version: str | None = None) -> None:
129          """`consent_version` is the privacy-notice version the person accepted. The shell
130          shows the notice and asks; tests and the demo accept it by passing nothing."""
131          if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
132              raise ClientError("Username must be 3-20 characters using only a-z, 0-9 and _ (lowercase).")
133          if not MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN:
134              raise ClientError(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.")
135          if os.path.exists(self._path(username, "keys.json")):
136              raise ClientError(f"A key file for '{username}' already exists in {self.data_dir}. Use login instead.")
137          self.trace("KEYGEN", "generating RSA-3072 (encryption) and Ed25519 (signing) key pairs locally")
138          keys = UserKeys.generate()
139          login_hash = self._hash_password(username, password)
140          self._request({
141              "action": "signup",
142              "username": username,
143              "password_hash": login_hash,
144              "enc_public_pem": keys.enc_public_pem(),
145              "sign_public_pem": keys.sign_public_pem(),
146              "consent_version": consent_version or self.privacy_notice()["version"],
147          })
148          # Only after the server accepted the name do we write the key file.
149          self._write_json(username, "keys.json", keys.to_encrypted_file(password))
150          self.trace("PROTECT KEYS", f"private keys saved encrypted (scrypt + AES-256-GCM) in {self._path(username, 'keys.json')}")
151          self._start_session(username, keys)
```

- **126** — Section comment.
- **128** — `signup`. The optional `consent_version` is the privacy-notice version the person accepted.
- **129–130** — Docstring: the shell shows the notice and asks; tests and the demo accept it by passing nothing.
- **131–132** — Check the username pattern first: instant feedback, before any slow key generation. `fullmatch` means the whole name must match, so a name with a trailing newline is refused.
- **133–134** — Check the password length (only the client can).
- **135–136** — If this folder already holds keys for this name, refuse rather than overwrite them.
- **137** — Trace.
- **138** — Generate both key pairs locally (RSA-3072 takes about half a second).
- **139** — Compute the login hash (≈0.1 s).
- **140–145** — Send the signup request: name, login hash, and the two **public** keys…
- **146–147** — …plus the accepted privacy-notice version. If none was given, the current version is fetched from the server and used (programmatic acceptance, for tests and the demo).
- **148** — Comment.
- **149** — Only now write `keys.json`, the private keys encrypted under `scrypt(password, new random salt)` (section 2.3). If the server had refused (name taken), no key file would be left behind.
- **150** — Trace.
- **151** — Start the session.

[`client/session.py` lines 153–158](../client/session.py#L153-L158)

```python
153      def _hash_password(self, username: str, password: str) -> str:
154          login_hash = client_password_hash(username, password)
155          self.trace("HASH PASSWORD",
156                     f"scrypt(password, salt = SHA-256(username)) -> {login_hash[:16]}...\n"
157                     "only this hash is sent; the password itself never leaves this computer")
158          return login_hash
```

- **153** — `_hash_password` wraps the login-hash function.
- **154** — Compute `scrypt(password, salt from username)`.
- **155–157** — Trace: shows only the first 16 characters of the hash.
- **158** — Return it.

### Log in

[`client/session.py` lines 160–182](../client/session.py#L160-L182)

```python
160      def login(self, username: str, password: str) -> None:
161          # A name that cannot exist is refused here, without contacting the
162          # server, so text typed into the wrong box is not sent anywhere.
163          if not isinstance(username, str) or not USERNAME_RE.fullmatch(username) or len(password) > MAX_PASSWORD_LEN:
164              raise ClientError("Invalid username or password.")
165          self._request({"action": "login", "username": username,
166                         "password_hash": self._hash_password(username, password)})
167          # The server said yes, so `username` is a real, validated name: safe to use in a path.
168          path = self._path(username, "keys.json")
169          if not os.path.exists(path):
170              self.conn.request({"action": "logout"})
171              raise ClientError(f"No key file for '{username}' in {self.data_dir}; this device cannot read their messages.")
172          try:
173              with open(path, "r", encoding="utf-8") as f:
174                  keys = UserKeys.from_encrypted_file(json.load(f), password)
175          except KeyFileError as exc:
176              self.conn.request({"action": "logout"})
177              raise ClientError(str(exc)) from None
178          except (OSError, ValueError, KeyError, TypeError) as exc:
179              self.conn.request({"action": "logout"})
180              raise ClientError(f"The key file {path} is damaged ({exc.__class__.__name__}). "
181                                "Restore it from a backup; without it this account's messages cannot be read.") from None
182          self._start_session(username, keys)
```

- **160** — `login`.
- **161–162** — Comment.
- **163–164** — A name that doesn't fully match the pattern (or an absurd password) is refused locally with the same generic message the server uses. Nothing is sent.
- **165–166** — Send the name and the login hash. A wrong password raises `ClientError` here with the server's generic message.
- **167** — Comment: the server accepted the name, so it is a valid name and safe to use in a file path.
- **168** — Path of the key file.
- **169–171** — No key file on this device: log out again and explain. (Keys exist only on the device where the account was created.)
- **172–174** — Open the file and decrypt the private keys with the password.
- **175–177** — Wrong password for the file or edited file (`KeyFileError`): log out and pass the message on.
- **178–181** — Unreadable or malformed file: log out and say which file is damaged.
- **182** — Success: start the session.

[`client/session.py` lines 184–198](../client/session.py#L184-L198)

```python
184      def _start_session(self, username, keys):
185          self.username, self.keys = username, keys
186          ids = self._read_json(username, "seen_ids.json", [], list)
187          self.seen_ids = {i for i in ids if isinstance(i, str)}
188  
189      def logout(self) -> None:
190          self.conn.request({"action": "logout"})
191          self.username, self.keys, self.seen_ids = None, None, set()
192  
193      def close(self) -> None:
194          self.conn.close()
195  
196      def _require_login(self):
197          if self.username is None:
198              raise ClientError("Please log in first.")
```

- **184–185** — `_start_session` remembers who is logged in and their keys.
- **186** — Load the accepted message IDs (empty list if none).
- **187** — Keep only string entries, as a set.
- **189–191** — `logout`: tell the server, and forget the user, keys and IDs on this side.
- **193–194** — `close` closes the connection.
- **196–198** — `_require_login` raises `ClientError` if nobody is logged in.

### The directory and key pinning

[`client/session.py` lines 200–236](../client/session.py#L200-L236)

```python
200      # ------------------------------------------------------------ directory
201  
202      def users(self, include_self: bool = False) -> list[dict]:
203          """Fetch users and public keys, pinning each user's keys the first time we see them.
204  
205          If the server later hands out DIFFERENT keys for a known user, that
206          could be the server trying to impersonate them, so we refuse.
207          """
208          self._require_login()
209          resp = self._request({"action": "users", "include_self": include_self})
210          listing = resp.get("users")
211          if not isinstance(listing, list):
212              raise ClientError("The server sent an invalid user list.")
213          with self.file_lock:
214              known = self._read_json(self.username, "known_keys.json", {}, dict)
215          changed = False
216          out = []
217          for u in listing:
218              # Ignore anything that is not a well-formed entry rather than crash on it.
219              if not isinstance(u, dict) or not all(isinstance(u.get(k), str)
220                                                    for k in ("username", "enc_public_pem", "sign_public_pem")):
221                  continue
222              u = {k: u[k] for k in ("username", "enc_public_pem", "sign_public_pem")}
223              u["fingerprint"] = fingerprint(u["enc_public_pem"], u["sign_public_pem"])
224              pinned = known.get(u["username"])
225              if not isinstance(pinned, dict):
226                  known[u["username"]] = {"enc_public_pem": u["enc_public_pem"], "sign_public_pem": u["sign_public_pem"]}
227                  changed = True
228                  u["key_status"] = "new (pinned now)"
229              elif pinned.get("enc_public_pem") != u["enc_public_pem"] or pinned.get("sign_public_pem") != u["sign_public_pem"]:
230                  u["key_status"] = "CHANGED - not trusted"
231              else:
232                  u["key_status"] = "matches pinned key"
233              out.append(u)
234          if changed:
235              self._write_json(self.username, "known_keys.json", known)
236          return out
```

- **200** — Section comment.
- **202** — `users` fetches the directory and applies pinning.
- **203–207** — Docstring.
- **208** — Must be logged in.
- **209** — Ask the server.
- **210–212** — The reply must contain a list.
- **213–214** — Load the pinned keys (under the file lock).
- **215–216** — Track whether anything new was pinned; collect results.
- **217** — For each user the server listed…
- **218–221** — …skip anything malformed instead of crashing.
- **222** — Keep only the three expected fields.
- **223** — Compute the fingerprint (section 2.3).
- **224** — Look up the pinned keys for this name.
- **225–228** — Never seen before: pin these keys now, and mark the entry "new (pinned now)".
- **229–230** — Seen before, but the keys differ: mark "CHANGED - not trusted". This is what catches a server trying to substitute keys.
- **231–232** — Same as pinned: "matches pinned key".
- **233** — Add to the results.
- **234–235** — Save the pinned keys if any were added.
- **236** — Return the list.

[`client/session.py` lines 238–248](../client/session.py#L238-L248)

```python
238      def _trusted_keys(self, username: str) -> dict:
239          """Public keys for `username`, but only if they match the pinned copy."""
240          for u in self.users(include_self=True):
241              if u["username"] == username:
242                  if u["key_status"].startswith("CHANGED"):
243                      raise ClientError(
244                          f"WARNING: the server now reports different keys for '{username}'. "
245                          "Refusing to use them. Verify the fingerprint with them in person."
246                      )
247                  return u
248          raise ClientError(f"Unknown user '{safe_display(username)[:40]}'.")
```

- **238–239** — `_trusted_keys` returns a user's keys only if they are trustworthy.
- **240** — Fetch the full directory, including ourselves.
- **241** — Find the requested user.
- **242–246** — Keys changed: refuse to use them, with a warning to compare fingerprints in person.
- **247** — Otherwise return the entry.
- **248** — No such user. The name is passed through `safe_display` and shortened, since it may come from a received package.

### Sending

[`client/session.py` lines 250–272](../client/session.py#L250-L272)

```python
250      # ------------------------------------------------------------ messages
251  
252      def build_package(self, recipient: str, text: str) -> dict:
253          """Encrypt and sign, but do not send (lets demos inspect or tamper with the package)."""
254          self._require_login()
255          if recipient == self.username:
256              raise ClientError("You cannot send a message to yourself.")
257          if len(text) > MAX_MESSAGE_CHARS:
258              raise ClientError(f"Message too long ({len(text)} characters; the limit is {MAX_MESSAGE_CHARS}).")
259          r = self._trusted_keys(recipient)
260          self.trace("READ", f"plaintext from {self.username} to {recipient}: {text!r}")
261          try:
262              return encrypt_and_sign(text, self.username, recipient, self.keys, r["enc_public_pem"], trace=self.trace)
263          except ValueError:
264              raise ClientError(f"'{recipient}' has an unusable public key; cannot encrypt to them.") from None
265  
266      def send_package(self, package: dict) -> str:
267          self._require_login()
268          self.trace("TRANSMIT", f"sending package {package['msg_id']} to the server over the socket")
269          return self._request({"action": "send", "package": package})["msg_id"]
270  
271      def send(self, recipient: str, text: str) -> str:
272          return self.send_package(self.build_package(recipient, text))
```

- **250** — Section comment.
- **252–253** — `build_package` encrypts and signs without sending (the demo uses this to tamper with a package).
- **254** — Must be logged in.
- **255–256** — No messages to yourself.
- **257–258** — Enforce the length limit before encrypting.
- **259** — Get the recipient's keys, pinned and checked.
- **260** — Trace (prints the plaintext; only in verbose mode, only on your own screen).
- **261–262** — Encrypt and sign (section 2.4) with the recipient's RSA public key.
- **263–264** — If their key cannot be used, a clear error.
- **266** — `send_package` sends a finished package.
- **267** — Must be logged in.
- **268** — Trace.
- **269** — Send it; return the message ID the server accepted.
- **271–272** — `send` builds and sends in one call.

### Receiving

[`client/session.py` lines 274–280](../client/session.py#L274-L280)

```python
274      def fetch_inbox(self) -> list:
275          """Raw packages from the server (still encrypted)."""
276          self._require_login()
277          messages = self._request({"action": "inbox"}).get("messages")
278          if not isinstance(messages, list):
279              raise ClientError("The server sent an invalid inbox.")
280          return messages
```

- **274–275** — `fetch_inbox` gets the raw, still-encrypted packages.
- **276** — Must be logged in.
- **277** — Ask the server.
- **278–279** — The reply must be a list.
- **280** — Return it.

[`client/session.py` lines 282–311](../client/session.py#L282-L311)

```python
282      def open_package(self, package) -> dict:
283          """Verify and decrypt one package. Never raises for a bad message;
284          returns {"ok": False, "reason": ...} so one bad message cannot hide the rest."""
285          is_dict = isinstance(package, dict)
286          sender = package.get("sender") if is_dict else None
287          sender = sender if isinstance(sender, str) else "?"
288          ts = package.get("timestamp") if is_dict else None
289          result = {"msg_id": package.get("msg_id") if is_dict else None,
290                    "sender": sender, "timestamp": ts if type(ts) is int and 0 < ts < 2**40 else None}
291          try:
292              if not is_dict:
293                  raise MessageRejected("malformed package (not an object)")
294              sender_keys = self._trusted_keys(sender)
295              self.trace("RECEIVE", f"package {safe_display(result['msg_id'])[:64]} claims to be from {sender}")
296              text = verify_and_decrypt(
297                  package, self.username, self.keys, sender_keys["sign_public_pem"],
298                  seen_ids=self.seen_ids, trace=self.trace,
299              )
300          except (MessageRejected, ClientError) as exc:
301              result.update(ok=False, reason=getattr(exc, "reason", str(exc)))
302              return result
303          except Exception as exc:  # last line of defence: never let one message crash the inbox
304              result.update(ok=False, reason=f"unreadable package ({exc.__class__.__name__})")
305              return result
306          self._write_json(self.username, "seen_ids.json", sorted(self.seen_ids))
307          result.update(ok=True, text=text)
308          return result
309  
310      def inbox(self) -> list[dict]:
311          return [self.open_package(p) for p in self.fetch_inbox()]
```

- **282–284** — `open_package` verifies and decrypts one package and never raises: one bad message must not hide the others.
- **285** — Is it a dict at all?
- **286–287** — The claimed sender, or `?` if missing or not text.
- **288** — The timestamp, if any.
- **289–290** — Start the result: message ID, sender, and the timestamp only if it is a sane integer (so the shell can show a time safely).
- **291** — Try the checks…
- **292–293** — Not an object: reject.
- **294** — Get the claimed sender's **pinned** keys. An unknown sender or changed key raises `ClientError`, which rejects the message.
- **295** — Trace for verbose mode. The message ID has not been validated yet at this point (that happens inside `verify_and_decrypt`), so it is passed through `safe_display` and cut to 64 characters before printing (part of the fix for finding V1).
- **296–299** — Verify the signature, then check recipient, time and replay, then unwrap, then decrypt (section 2.4), using this user's seen-ID set.
- **300–302** — Any `MessageRejected` or `ClientError`: mark the result not OK, with the reason.
- **303–305** — Any other exception (a bug or something unforeseen): also reject, never crash.
- **306** — Success: save the updated seen-ID list to disk, so a replay is caught even after restarting the client.
- **307** — Add the text to the result.
- **308** — Return it.
- **310–311** — `inbox` fetches and opens every package.

### Privacy rights

[`client/session.py` lines 313–331](../client/session.py#L313-L331)

```python
313      # ------------------------------------------------------------ privacy rights
314  
315      def privacy_notice(self) -> dict:
316          """The server's privacy notice: {"version": ..., "text": ...}. No login needed."""
317          return self._request({"action": "privacy_notice"})
318  
319      def mydata(self) -> dict:
320          """Everything the server stores about me (PDPA s.30 access, s.31 portability)."""
321          self._require_login()
322          return self._request({"action": "mydata"})["data"]
323  
324      def delete_account(self, password: str) -> None:
325          """Erase my account on the server and my files on this device (PDPA s.33)."""
326          self._require_login()
327          self._request({"action": "delete_account",
328                         "password_hash": self._hash_password(self.username, password)})
329          # The server has erased the account; now remove keys, pins and seen IDs here too.
330          shutil.rmtree(os.path.join(self.data_dir, self.username), ignore_errors=True)
331          self.username, self.keys, self.seen_ids = None, None, set()
```

- **313** — Section comment.
- **315–317** — `privacy_notice` asks the server for its notice text and version. No login is needed, because the notice must be shown before anything is collected.
- **319–320** — `mydata` asks for everything the server stores about me (PDPA s.30 access, s.31 portability).
- **321** — Must be logged in.
- **322** — Return the `data` part of the reply (a dict the shell prints as JSON).
- **324–325** — `delete_account` erases my account (PDPA s.33).
- **326** — Must be logged in.
- **327–328** — Send the request with my login hash, so the server can re-check the password before erasing anything. A wrong password raises `ClientError` here and nothing is deleted.
- **329** — Comment.
- **330** — The server has erased the account, so delete this device's folder too: the encrypted key file, the pinned keys and the seen-message IDs. Without this, personal data would stay on the computer after "deletion".
- **331** — Forget the user, keys and IDs in memory.

## 4.3 `cli.py`

### Header

[`client/cli.py` lines 1–28](../client/cli.py#L1-L28)

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
13      mydata                     show everything the server stores about you
14      delete_account             erase your account and data (asks to confirm)
15      logout
16      quit
17  """
18  
19  import argparse
20  import cmd
21  import datetime
22  import getpass
23  import json
24  import sys
25  import threading
26  
27  from .connection import DEFAULT_CA_FILE, ConnectionError_
28  from .session import ChatClient, ClientError, safe_display
```

- **1–17** — Module docstring: how to run it and the list of commands.
- **19** — `argparse` for options.
- **20** — `cmd` is Python's standard framework for line-based command shells: it reads a line, finds `do_<command>`, and calls it.
- **21** — `datetime` to show message times.
- **22** — `getpass` reads passwords without echoing them to the screen.
- **23** — `json` to print `mydata` in a readable, machine-readable form.
- **24** — `sys` to write directly to the terminal in chat mode.
- **25** — `threading` for the chat listener.
- **27** — The connection error and default CA path.
- **28** — The client logic and `safe_display`.

[`client/cli.py` lines 31–38](../client/cli.py#L31-L38)

```python
31  def print_step(step: str, detail: str = "") -> None:
32      print(f"  [{step}]")
33      for line in detail.splitlines():
34          print(f"      {line}")
35  
36  
37  def silent(step, detail=""):
38      pass
```

- **31–34** — `print_step` is the verbose-mode trace printer: the step name in brackets, then each detail line indented.
- **37–38** — `silent` prints nothing (verbose off).

### The shell

[`client/cli.py` lines 41–60](../client/cli.py#L41-L60)

```python
41  class ChatShell(cmd.Cmd):
42      intro = (
43          "Secure chat client.\n"
44          "  New here?  signup <your name>      Returning?  login <your name>\n"
45          "  Then:      users                   to see who you can talk to\n"
46          "             chat <their name>       to start chatting\n"
47          "Type 'help' for all commands."
48      )
49  
50      def __init__(self, client: ChatClient):
51          super().__init__()
52          self.client = client
53          self._update_prompt()
54  
55      def _update_prompt(self):
56          self.prompt = f"({self.client.username or 'not logged in'}) > "
57  
58      def postcmd(self, stop, line):
59          self._update_prompt()
60          return stop
```

- **41** — `ChatShell` builds on `cmd.Cmd`.
- **42–48** — The welcome text.
- **50–53** — Constructor: remember the client and set the prompt.
- **55–56** — The prompt shows who is logged in, e.g. `(bob) > `.
- **58–60** — After every command, refresh the prompt (login or logout may have changed it).

[`client/cli.py` lines 62–76](../client/cli.py#L62-L76)

```python
62      def onecmd(self, line):
63          # One place to turn errors into friendly messages.
64          try:
65              return super().onecmd(line)
66          except ClientError as exc:
67              print(f"Error: {exc}")
68          except ConnectionError_ as exc:
69              print(f"Connection problem: {exc}")
70              print("The client will now exit. Start the server if needed, then run the client again.")
71              return True
72          except Exception as exc:  # a bug, not the user's fault: report it and keep the shell running
73              print(f"Unexpected error ({exc.__class__.__name__}: {exc}). The command was not completed.")
74  
75      def emptyline(self):
76          pass
```

- **62** — `onecmd` runs one typed line; overriding it gives one place to handle errors.
- **63** — Comment.
- **64–65** — Run the command normally.
- **66–67** — A `ClientError` (wrong password, unknown user…) prints `Error: …` and the shell continues.
- **68–71** — A `ConnectionError_` means the session is over: explain and return `True`, which makes `cmd` exit the loop.
- **72–73** — Any other exception is a bug: report it, keep the shell running.
- **75–76** — An empty line does nothing (by default `cmd` would repeat the last command).

### Commands

[`client/cli.py` lines 78–107](../client/cli.py#L78-L107)

```python
 78      # ---------------------------------------------------------- commands
 79  
 80      def do_signup(self, arg):
 81          """signup <username>  - create an account and a new key pair on this device"""
 82          username = arg.strip()
 83          if not username:
 84              print("Usage: signup <username>")
 85              return
 86          notice = self.client.privacy_notice()  # PDPA s.23: inform before collecting anything
 87          print(notice["text"])
 88          if input("Type 'yes' to accept this notice and create your account: ").strip().lower() != "yes":
 89              print("Sign-up cancelled. Nothing was sent or stored.")
 90              return
 91          password = getpass.getpass("Choose a password (min 8 chars): ")
 92          if password != getpass.getpass("Repeat password: "):
 93              print("Passwords do not match.")
 94              return
 95          print("Generating keys (a few seconds)...")
 96          self.client.signup(username, password, consent_version=notice["version"])
 97          print(f"Account created. Logged in as {username}.")
 98  
 99      def do_login(self, arg):
100          """login <username>  - log in and unlock your private keys"""
101          username = arg.strip()
102          if not username:
103              print("Usage: login <username>")
104              return
105          password = getpass.getpass("Password: ")
106          self.client.login(username, password)
107          print(f"Logged in as {username}.")
```

- **78** — Section comment.
- **80–81** — `signup <name>`; the docstring is what `help signup` shows.
- **82–85** — Require a name.
- **86** — Fetch the privacy notice from the server (PDPA s.23: inform people **before** collecting anything).
- **87** — Show it.
- **88–90** — Continue only if the person types `yes`. Otherwise stop: no keys are made and nothing is sent or stored.
- **91** — Read the password without echo.
- **92–94** — Read it again; refuse if they differ.
- **95** — Warn that key generation takes a moment.
- **96** — Sign up (section 4.2), passing the version of the notice the person accepted, which the server records.
- **97** — Confirm.
- **99–100** — `login <name>`.
- **101–104** — Require a name.
- **105** — Read the password without echo.
- **106** — Log in.
- **107** — Confirm.

[`client/cli.py` lines 109–124](../client/cli.py#L109-L124)

```python
109      def do_users(self, arg):
110          """users  - list other users with their public-key fingerprints"""
111          users = self.client.users()
112          if not users:
113              print("No other users yet.")
114          for u in users:
115              print(f"  {u['username']:<20} {u['fingerprint']}  ({u['key_status']})")
116  
117      def do_send(self, arg):
118          """send <recipient> <message>  - encrypt, sign and send a message"""
119          parts = arg.split(maxsplit=1)
120          if len(parts) != 2:
121              print("Usage: send <recipient> <message>")
122              return
123          msg_id = self.client.send(parts[0], parts[1])
124          print(f"Sent (message ID {msg_id}).")
```

- **109–110** — `users`.
- **111** — Fetch with pinning applied.
- **112–113** — Nobody else yet.
- **114–115** — Print each name, fingerprint and pin status. (Names come from the server but always match the strict username pattern.)
- **117–118** — `send <recipient> <message>`.
- **119** — Split into the recipient and the rest of the line (the message may contain spaces).
- **120–122** — Require both.
- **123** — Encrypt, sign, send.
- **124** — Show the message ID.

[`client/cli.py` lines 126–138](../client/cli.py#L126-L138)

```python
126      def do_inbox(self, arg):
127          """inbox  - fetch new messages, verify each signature, then decrypt"""
128          results = self.client.inbox()
129          if not results:
130              print("No new messages.")
131          for r in results:
132              when = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%Y-%m-%d %H:%M:%S") if r["timestamp"] else "?"
133              sender = safe_display(r["sender"])[:40]
134              if r["ok"]:
135                  print(f"  [{when}] {sender}: {safe_display(r['text'])}   (signature OK)")
136              else:
137                  print(f"  !! REJECTED message claiming to be from {sender} ({when})")
138                  print(f"     reason: {safe_display(r['reason'])}")
```

- **126–127** — `inbox`.
- **128** — Fetch and open every waiting package.
- **129–130** — Nothing new.
- **131** — For each result…
- **132** — …format its time, or `?` if none.
- **133** — Make the sender name safe and short.
- **134–135** — Accepted: print time, sender and the **safe** text.
- **136–138** — Rejected: a clear warning with the safe reason.

### Chat mode

[`client/cli.py` lines 140–157](../client/cli.py#L140-L157)

```python
140      def do_chat(self, arg):
141          """chat <username>  - live conversation; type /exit to leave"""
142          peer = arg.strip()
143          if not peer:
144              print("Usage: chat <username>   (type 'users' to see who is here)")
145              return
146          if self.client.username is None:
147              raise ClientError("Please log in first.")
148          if peer == self.client.username:
149              raise ClientError("You cannot chat with yourself.")
150          info = self.client._trusted_keys(peer)  # raises if unknown or if the key changed
151  
152          me = self.client.username
153          prompt = f"{me}> "
154          print(f"--- Chat with {peer} ---")
155          print(f"    {peer}'s key fingerprint: {info['fingerprint']}")
156          print("    Every message is encrypted for them and signed by you. Type /exit to leave.")
157          print()
```

- **140–141** — `chat <name>` starts a live conversation.
- **142** — The partner's name.
- **143–145** — Require it.
- **146–147** — Must be logged in.
- **148–149** — Not with yourself.
- **150** — Get their keys (pinned and checked); this fails cleanly if they don't exist or their key changed.
- **152** — Your name.
- **153** — The chat prompt, e.g. `bob> `.
- **154–157** — Print a header with the partner's fingerprint, for comparing in person.

[`client/cli.py` lines 159–167](../client/cli.py#L159-L167)

```python
159          print_lock = threading.Lock()
160          stop = threading.Event()
161  
162          def show(text):
163              # Print above the prompt, then redraw the prompt.
164              with print_lock:
165                  sys.stdout.write("\r" + " " * (len(prompt) + 40) + "\r")
166                  sys.stdout.write(text + "\n" + prompt)
167                  sys.stdout.flush()
```

- **159** — A lock so the two threads never print at the same moment.
- **160** — An `Event` used to tell the listener to stop.
- **162** — `show` prints an incoming line above the prompt.
- **163** — Comment.
- **164** — Hold the print lock.
- **165** — `\r` returns to the start of the line; spaces wipe the prompt; `\r` again.
- **166** — Print the message, a newline, and the prompt again.
- **167** — Flush so it appears now.

[`client/cli.py` lines 169–193](../client/cli.py#L169-L193)

```python
169          def receive_loop():
170              # Check the inbox once a second; verify and decrypt whatever arrived.
171              # Everything printed from a message goes through safe_display so a
172              # sender cannot inject fake lines or terminal escape codes.
173              while not stop.is_set():
174                  try:
175                      for r in self.client.inbox():
176                          when = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%H:%M") \
177                              if r["timestamp"] else "--:--"
178                          sender = safe_display(r["sender"])[:40]
179                          if not r["ok"]:
180                              show(f"[{when}] !! REJECTED a message claiming to be from {sender}: "
181                                   f"{safe_display(r['reason'])}")
182                          elif r["sender"] == peer:
183                              show(f"[{when}] {peer}: {safe_display(r['text'])}")
184                          else:
185                              show(f"[{when}] (from {sender}) {safe_display(r['text'])}")
186                  except ConnectionError_ as exc:
187                      show(f"!! {exc}  Type /exit.")
188                      return  # nothing more can arrive on a dead connection
189                  except ClientError as exc:
190                      show(f"!! could not check messages: {exc}")
191                  except Exception as exc:  # never let the listener die silently
192                      show(f"!! unexpected error while checking messages ({exc.__class__.__name__})")
193                  stop.wait(1.0)
```

- **169** — `receive_loop` runs in the background thread.
- **170–172** — Comment: everything from a message goes through `safe_display`.
- **173** — Until told to stop…
- **174–175** — …check the inbox (verifies and decrypts everything new).
- **176–177** — Format the time as hours:minutes.
- **178** — Make the sender name safe.
- **179–181** — Rejected: show a warning with the reason.
- **182–183** — From the partner: show `[time] name: text`.
- **184–185** — From someone else: show it labelled with their name.
- **186–188** — Connection lost: say so once and end the thread, since nothing more can arrive.
- **189–190** — Other client errors: show and keep going.
- **191–192** — Anything unexpected: show a short message; the listener never dies silently.
- **193** — Wait one second (or less if told to stop).

[`client/cli.py` lines 195–217](../client/cli.py#L195-L217)

```python
195          listener = threading.Thread(target=receive_loop, daemon=True)
196          listener.start()
197          try:
198              while True:
199                  line = input(prompt)
200                  text = line.strip()
201                  if text in ("/exit", "/quit", "/back"):
202                      break
203                  if not text:
204                      continue
205                  try:
206                      self.client.send(peer, text)
207                  except ClientError as exc:
208                      show(f"!! not sent: {exc}")
209                  except ConnectionError_ as exc:
210                      show(f"!! not sent: {exc}")
211                      break
212          except (EOFError, KeyboardInterrupt):
213              print()
214          finally:
215              stop.set()
216              listener.join(timeout=5)
217          print(f"--- Left chat with {peer} ---")
```

- **195–196** — Start the listener as a daemon thread (it won't keep the program alive).
- **197–198** — The main thread reads what you type.
- **199** — Wait for a line.
- **200** — Trim spaces.
- **201–202** — `/exit`, `/quit` or `/back` leaves the chat.
- **203–204** — Ignore empty lines.
- **205–206** — Encrypt, sign and send to the partner.
- **207–208** — A refused message (too long, key changed…): show why, keep chatting.
- **209–211** — Connection lost: show it and leave the chat.
- **212–213** — Ctrl+C or end-of-input also leaves.
- **214–216** — In every case, tell the listener to stop and wait up to 5 seconds for it.
- **217** — Confirm you have left.

[`client/cli.py` lines 219–251](../client/cli.py#L219-L251)

```python
219      def do_verbose(self, arg):
220          """verbose on|off  - show every crypto step"""
221          on = arg.strip().lower() in ("on", "1", "yes", "")
222          self.client.trace = print_step if on else silent
223          print(f"Verbose mode {'on' if on else 'off'}.")
224  
225      def do_mydata(self, arg):
226          """mydata  - show everything the server stores about you (PDPA right of access)"""
227          print(json.dumps(self.client.mydata(), indent=2))
228  
229      def do_delete_account(self, arg):
230          """delete_account  - erase your account, your waiting messages and this device's keys"""
231          if self.client.username is None:
232              raise ClientError("Please log in first.")
233          print("This permanently deletes your account, messages waiting for you, and your keys on this device.")
234          if input(f"Type your username ({self.client.username}) to confirm: ").strip() != self.client.username:
235              print("Cancelled.")
236              return
237          password = getpass.getpass("Password: ")
238          self.client.delete_account(password)
239          print("Your account and data have been deleted.")
240  
241      def do_logout(self, arg):
242          """logout"""
243          self.client.logout()
244          print("Logged out.")
245  
246      def do_quit(self, arg):
247          """quit"""
248          return True
249  
250      do_exit = do_quit
251      do_EOF = do_quit
```

- **219–220** — `verbose on|off`.
- **221** — `on`, `1`, `yes` or nothing at all means on.
- **222** — Swap in the step printer or the silent one.
- **223** — Confirm.
- **225–226** — `mydata`: the right of access.
- **227** — Print everything the server holds about you as indented JSON, which a person can read and a program can import (portability).
- **229–230** — `delete_account`: the right to erasure.
- **231–232** — Must be logged in.
- **233** — Say plainly what will be deleted.
- **234–236** — Ask the person to type their own username to confirm; anything else cancels. This guards against deleting by accident.
- **237** — Ask for the password (without echo); the server checks it again.
- **238** — Erase on the server and on this device.
- **239** — Confirm.
- **241–244** — `logout`.
- **246–248** — `quit` returns `True`, which ends the `cmd` loop.
- **250–251** — `exit` and end-of-input (Ctrl+Z on Windows) do the same as `quit`.

### Starting the client

[`client/cli.py` lines 254–285](../client/cli.py#L254-L285)

```python
254  def main():
255      parser = argparse.ArgumentParser(description="Secure chat client")
256      parser.add_argument("--host", default="127.0.0.1")
257      parser.add_argument("--port", type=int, default=5050)
258      parser.add_argument("--data", default="client_data", help="folder for this device's encrypted keys")
259      parser.add_argument("--ca", default=DEFAULT_CA_FILE,
260                          help="the server's CA certificate (copy of server_data\\tls\\ca.crt)")
261      args = parser.parse_args()
262      try:
263          client = ChatClient(args.host, args.port, args.data, trace=silent, ca_file=args.ca)
264      except ConnectionError_ as exc:
265          print(exc)
266          if "Cannot reach" in str(exc):
267              print("Start the server first:  py -m server.server")
268          return
269      shell = ChatShell(client)
270      shell.intro = (f"Connected securely ({client.conn.tls_version}, {client.conn.cipher}); "
271                     "server identity verified.\n" + shell.intro)
272      try:
273          while True:
274              try:
275                  shell.cmdloop()
276                  break
277              except KeyboardInterrupt:  # Ctrl+C at the prompt: don't crash, explain how to leave
278                  print("\n(Type 'quit' to exit.)")
279                  shell.intro = None
280      finally:
281          client.close()
282  
283  
284  if __name__ == "__main__":
285      main()
```

- **254** — `main` runs for `py -m client.cli`.
- **255** — Option parser.
- **256** — `--host`, the server address.
- **257** — `--port`.
- **258** — `--data`, this device's folder for keys and lists.
- **259–260** — `--ca`, the copy of the server's `ca.crt`.
- **261** — Parse.
- **262–263** — Create the client, which opens the TLS connection.
- **264–268** — If that fails, print why; if the server simply isn't running, say how to start it; then exit.
- **269** — Create the shell.
- **270–271** — Put the TLS version, cipher and "server identity verified" above the welcome text.
- **272–276** — Run the shell until `quit`.
- **277–279** — Ctrl+C at the prompt: don't crash; explain how to leave and keep going (without repeating the welcome text).
- **280–281** — In every case close the connection at the end.
- **284–285** — Run `main()` when executed as a program.
