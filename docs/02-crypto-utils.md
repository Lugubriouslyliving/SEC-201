# 2. `crypto_utils`, line by line

[← How it works](01-how-it-works.md) · [Index](README.md) · Next: [The server →](03-server.md)

`crypto_utils` is the only place that touches cryptography. It never implements an
algorithm itself. It picks well-studied algorithms from the `cryptography` library and
Python's `ssl` module, chooses safe parameters, and glues them together.

| Module | Job | Used by |
|---|---|---|
| [`encoding.py`](#21-encodingpy) | base64 and canonical JSON | everything |
| [`passwords.py`](#22-passwordspy) | client login hash; server salted hash; constant-time check | client signup/login, server |
| [`keys.py`](#23-keyspy) | RSA + Ed25519 key pairs; encrypted key file; fingerprints | client |
| [`messages.py`](#24-messagespy) | encrypt + sign a message; verify + decrypt it | client |
| [`tls.py`](#25-tlspy) | private CA and server certificate; TLS 1.3 settings | server, client |

## 2.0 `__init__.py`

[`crypto_utils/__init__.py` lines 1–15](../crypto_utils/__init__.py#L1-L15)

```python
 1  """Thin, well-commented wrappers around the `cryptography` library.
 2  
 3  Nothing in this package implements a cryptographic primitive by hand.
 4  Every algorithm (scrypt, AES-GCM, RSA-OAEP, Ed25519, ECDSA certificates,
 5  TLS 1.3) comes from the `cryptography` library or Python's `ssl` module;
 6  this package only chooses parameters and glues the pieces together so the
 7  rest of the app reads clearly.
 8  
 9  Modules:
10      encoding   - base64 helpers and canonical JSON for signing
11      passwords  - client login hash + server-side salted password hashing
12      keys       - key pairs and password-protected private-key storage (client side)
13      messages   - the end-to-end message format: encrypt + sign, verify + decrypt
14      tls        - the private CA, server certificate and TLS 1.3 settings
15  """
```

- **1–15** — The package docstring. It states the rule the whole project follows (no hand-made cryptography) and lists the five modules. Python runs this file when anything imports `crypto_utils`; it contains no code, only documentation.

## 2.1 `encoding.py`

JSON can only carry text, but cryptography produces raw bytes, and a signature needs
one exact byte string. These three helpers solve both problems.

[`crypto_utils/encoding.py` lines 1–8](../crypto_utils/encoding.py#L1-L8)

```python
1  """Encoding helpers shared by client, server and crypto code.
2  
3  JSON cannot carry raw bytes, so every binary value (ciphertext, nonce,
4  keys, signatures) travels as standard base64 text.
5  """
6  
7  import base64
8  import json
```

- **1–5** — Module docstring: binary values travel as base64 text.
- **7** — `base64` is Python's standard base64 encoder/decoder.
- **8** — `json` is Python's standard JSON library.

[`crypto_utils/encoding.py` lines 11–18](../crypto_utils/encoding.py#L11-L18)

```python
11  def b64e(data: bytes) -> str:
12      """Bytes -> base64 text."""
13      return base64.b64encode(data).decode("ascii")
14  
15  
16  def b64d(text: str) -> bytes:
17      """Base64 text -> bytes. `validate=True` rejects stray characters."""
18      return base64.b64decode(text.encode("ascii"), validate=True)
```

- **11** — `b64e` ("base64 encode") takes raw bytes and returns text.
- **12** — Docstring.
- **13** — `base64.b64encode` turns bytes into base64 *bytes* (only the characters A–Z, a–z, 0–9, `+`, `/`, `=`); `.decode("ascii")` turns those into a normal `str` that JSON can hold.
- **16** — `b64d` ("base64 decode") is the reverse.
- **17** — Docstring.
- **18** — `.encode("ascii")` turns the text back into bytes. `validate=True` makes the decoder **reject** any character outside the base64 alphabet instead of silently skipping it. That matters for security: junk such as `"!!!"` raises `binascii.Error` (a kind of `ValueError`) and is rejected, rather than being quietly decoded into something unexpected.

[`crypto_utils/encoding.py` lines 21–28](../crypto_utils/encoding.py#L21-L28)

```python
21  def canonical_json(obj) -> bytes:
22      """Serialize `obj` to one exact byte string.
23  
24      A signature is over *bytes*, so sender and receiver must turn the same
25      fields into the same bytes. Sorting keys and fixing the separators makes
26      the output deterministic no matter how the dict was built.
27      """
28      return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
```

- **21** — `canonical_json` turns a Python dict into exactly one possible byte string.
- **22–27** — Docstring explaining why: a signature is over bytes, so signer and verifier must produce identical bytes from the same fields.
- **28** — `sort_keys=True` always puts keys in alphabetical order, whatever order the dict was built in. `separators=(",", ":")` removes all optional spaces. `ensure_ascii=True` writes any non-ASCII character as a `\uXXXX` escape, so there is no choice about how to encode it. `.encode("utf-8")` gives bytes. Without this, `{"a":1,"b":2}` and `{"b": 2, "a": 1}` would be the same data with different bytes, and an honest signature could fail to verify.

## 2.2 `passwords.py`

Two layers of password hashing:

```text
client:  login_hash = scrypt(password, salt = SHA-256("secure-chat/login-hash/v1:" + username))
server:  stored     = scrypt(login_hash, salt = 16 random bytes)
```

[`crypto_utils/passwords.py` lines 1–22](../crypto_utils/passwords.py#L1-L22)

```python
 1  """Password hashing, in two layers.
 2  
 3      client:  login_hash = scrypt(password, salt from username)   -> sent to server
 4      server:  stored     = scrypt(login_hash, random salt)         -> saved in database
 5  
 6  The client layer keeps the real password off the network and away from
 7  the server. The server layer is the classic salted hash of whatever
 8  credential arrives, so a stolen database is still useless for logging in.
 9  
10  Algorithm: scrypt (memory-hard key derivation function), via
11  `cryptography.hazmat.primitives.kdf.scrypt.Scrypt`.
12  
13  Why scrypt and not plain SHA-256?
14      A fast hash lets an attacker who steals the database try billions of
15      guesses per second. scrypt is deliberately slow *and* needs a lot of
16      memory per guess, which makes GPU/ASIC guessing expensive.
17  
18  Why a salt?
19      Each user gets 16 random bytes mixed into their hash. Two users with the
20      same password get different hashes, and precomputed "rainbow tables"
21      become useless because the attacker would need one table per salt.
22  """
```

- **1–22** — Module docstring: the two layers, why scrypt (slow and memory-hungry, so guessing is expensive), and why a salt (equal passwords get different hashes; precomputed tables become useless).

[`crypto_utils/passwords.py` lines 24–30](../crypto_utils/passwords.py#L24-L30)

```python
24  import hmac
25  import os
26  
27  from cryptography.hazmat.primitives import hashes
28  from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
29  
30  from .encoding import b64d, b64e
```

- **24** — `hmac` provides `compare_digest`, a comparison whose running time does not depend on where two values differ.
- **25** — `os` provides `os.urandom`, the operating system's cryptographically secure random number generator.
- **27** — `hashes` provides SHA-256, used to build the client-side salt.
- **28** — `Scrypt` is the scrypt key-derivation function from the `cryptography` library.
- **30** — The base64 helpers from section 2.1.

[`crypto_utils/passwords.py` lines 32–39](../crypto_utils/passwords.py#L32-L39)

```python
32  # scrypt cost parameters. n=2**15, r=8 uses ~32 MiB of memory per hash.
33  # They are stored with every record so they can be raised later without
34  # breaking existing accounts.
35  SCRYPT_N = 2**15
36  SCRYPT_R = 8
37  SCRYPT_P = 1
38  SALT_BYTES = 16
39  HASH_BYTES = 32
```

- **32–34** — Comment: the cost parameters are stored with every hash, so they can be raised later without breaking old accounts.
- **35** — `N = 2^15 = 32,768` is scrypt's CPU/memory cost. Memory used is about `128 × N × r` bytes = 128 × 32,768 × 8 ≈ **32 MiB per hash**. Each guess an attacker makes needs that much memory, which makes massively parallel GPU guessing expensive.
- **36** — `r = 8` is the block size (the standard value).
- **37** — `p = 1` means one computation (no parallel lanes).
- **38** — Salts are 16 random bytes (128 bits): far too many possibilities for any two users to share one, or for anyone to precompute tables.
- **39** — The output is 32 bytes (256 bits).

[`crypto_utils/passwords.py` lines 42–44](../crypto_utils/passwords.py#L42-L44)

```python
42  def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
43      kdf = Scrypt(salt=salt, length=HASH_BYTES, n=n, r=r, p=p)
44      return kdf.derive(password.encode("utf-8"))
```

- **42** — Private helper used by the server side; parameters are passed in so old records can be checked with whatever costs they were made with.
- **43** — A new `Scrypt` object is configured with the salt, output length and costs. (`Scrypt` objects are single-use, so one is made per call.)
- **44** — The password text is turned into UTF-8 bytes and run through scrypt. The result is 32 bytes.

[`crypto_utils/passwords.py` lines 47–62](../crypto_utils/passwords.py#L47-L62)

```python
47  def hash_password(password: str) -> dict:
48      """Create a new password record: a fresh random salt plus the scrypt hash.
49  
50      The returned dict is what the server stores. It never contains the
51      password itself.
52      """
53      salt = os.urandom(SALT_BYTES)  # unique per user, from the OS CSPRNG
54      digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
55      return {
56          "algorithm": "scrypt",
57          "n": SCRYPT_N,
58          "r": SCRYPT_R,
59          "p": SCRYPT_P,
60          "salt": b64e(salt),
61          "hash": b64e(digest),
62      }
```

- **47** — `hash_password` makes the record the **server** stores at signup. (On the server, the "password" passed in is the client's login hash.)
- **48–52** — Docstring.
- **53** — A fresh 16-byte salt from the OS random generator, different for every account.
- **54** — The scrypt hash itself.
- **55–62** — The record: algorithm name and costs (so it can be checked later even if defaults change), plus salt and hash as base64 text. No password or login hash is kept.

[`crypto_utils/passwords.py` lines 65–73](../crypto_utils/passwords.py#L65-L73)

```python
65  def verify_password(password: str, record: dict) -> bool:
66      """Recompute the hash with the stored salt and compare in constant time.
67  
68      `hmac.compare_digest` takes the same time whether the first byte or the
69      last byte differs, so an attacker cannot learn the hash byte by byte by
70      timing the server's answers.
71      """
72      candidate = _scrypt(password, b64d(record["salt"]), record["n"], record["r"], record["p"])
73      return hmac.compare_digest(candidate, b64d(record["hash"]))
```

- **65** — `verify_password` checks a login attempt against a stored record.
- **66–71** — Docstring explaining constant-time comparison.
- **72** — Recompute scrypt over the attempt, using the **stored** salt and the **stored** costs.
- **73** — `hmac.compare_digest` compares the two 32-byte values in constant time. A normal `==` stops at the first different byte, so it answers slightly faster for an early mismatch; an attacker timing many attempts could use that difference. `compare_digest` always takes the same time.

[`crypto_utils/passwords.py` lines 76–81](../crypto_utils/passwords.py#L76-L81)

```python
76  # ===================================================================
77  # Client side: the password never leaves the user's computer.
78  # ===================================================================
79  
80  LOGIN_HASH_CONTEXT = b"secure-chat/login-hash/v1:"
81  LOGIN_HASH_BYTES = 32
```

- **76–78** — Section comment: everything below runs on the client.
- **80** — The **context label**. Mixing this fixed text into the salt makes the login hash specific to this app and this purpose, so it is unrelated to any other hash of the same password.
- **81** — The login hash is 32 bytes.

[`crypto_utils/passwords.py` lines 84–111](../crypto_utils/passwords.py#L84-L111)

```python
 84  def client_password_hash(username: str, password: str) -> str:
 85      """What the client sends to the server instead of the password.
 86  
 87      login_hash = scrypt(password, salt = SHA-256(context || username))
 88  
 89      Why the username as salt? The client must compute the same value on any
 90      computer, before it has talked to the server, so the salt cannot be
 91      random. Using the username still makes it unique per user, so one
 92      precomputed table cannot attack everyone at once. The context label
 93      keeps it unrelated to any other use of the same password.
 94  
 95      The result protects the real password: the server operator, the server
 96      log and anyone watching the network only ever see this hash. Since the
 97      same password also unlocks the private-key file (with a different,
 98      random salt), the server can never open that file either.
 99  
100      Note: to the server this hash now *is* the credential. Someone who
101      captures it on the network could replay it to log in (but still could
102      not read any messages without the private-key file). Only an encrypted
103      channel such as TLS stops that. See README, "Threat model".
104      """
105      h = hashes.Hash(hashes.SHA256())
106      h.update(LOGIN_HASH_CONTEXT + username.encode("utf-8"))
107      salt = h.finalize()
108      digest = Scrypt(salt=salt, length=LOGIN_HASH_BYTES, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
109          password.encode("utf-8")
110      )
111      return b64e(digest)
```

- **84** — `client_password_hash` produces what the client sends instead of the password.
- **85–104** — Docstring. Key points: the username is used to build the salt because the client must get the same result on any computer before contacting the server; the hash protects the real password from the server, its logs and the network; but the hash itself becomes a password-equivalent credential for the server.
- **105** — Start a SHA-256 hash.
- **106** — Feed it the context label followed by the username's UTF-8 bytes.
- **107** — The 32-byte SHA-256 digest becomes the salt. Same username → same salt on every device; different usernames → unrelated salts.
- **108–110** — Run scrypt with that salt and the same costs as the server (≈32 MiB, about 0.1 s) over the password's UTF-8 bytes. The slowness also protects a captured login hash against fast offline guessing.
- **111** — Return the 32 bytes as base64 text (always 44 characters).

[`crypto_utils/passwords.py` lines 114–121](../crypto_utils/passwords.py#L114-L121)

```python
114  def is_login_hash(value) -> bool:
115      """True if `value` looks like client_password_hash() output (base64 of 32 bytes)."""
116      if not isinstance(value, str) or len(value) != 44:
117          return False
118      try:
119          return len(b64d(value)) == LOGIN_HASH_BYTES
120      except ValueError:
121          return False
```

- **114** — `is_login_hash` lets the server refuse anything that is not a login hash, such as a plain password sent by a broken or old client.
- **115** — Docstring.
- **116–117** — Must be a string of exactly 44 characters (the base64 length of 32 bytes).
- **118–119** — Must decode as strict base64 into exactly 32 bytes.
- **120–121** — Invalid base64 raises `ValueError`; treat it as "not a login hash".

[`crypto_utils/passwords.py` lines 124–128](../crypto_utils/passwords.py#L124-L128)

```python
124  # A record for a password nobody knows. When a login names a user that does
125  # not exist, the server still runs one scrypt computation against this dummy
126  # record, so "no such user" takes as long as "wrong password" and the two
127  # cases cannot be told apart by timing.
128  DUMMY_RECORD = hash_password(b64e(os.urandom(24)))
```

- **124–127** — Comment explaining the dummy record.
- **128** — At import time, hash a random value nobody knows. When someone logs in with a username that does not exist, the server checks against this record so it still spends one full scrypt computation. "No such user" then takes as long as "wrong password", and timing does not reveal which usernames exist.

## 2.3 `keys.py`

Each user has two key pairs. The private halves live only on the user's computer, in an
encrypted file.

[`crypto_utils/keys.py` lines 1–16](../crypto_utils/keys.py#L1-L16)

```python
 1  """User key pairs and password-protected private-key storage.
 2  
 3  Each user owns TWO key pairs, one per job:
 4  
 5      RSA-3072  "encryption key"  - others wrap AES keys to it with RSA-OAEP,
 6                                    only the owner can unwrap them.
 7      Ed25519   "signing key"     - the owner signs outgoing messages,
 8                                    everyone verifies with the public half.
 9  
10  Using separate keys for encryption and signing is standard practice: a
11  weakness or misuse in one role cannot leak into the other.
12  
13  Private keys never leave the client. On disk they are encrypted with
14  AES-256-GCM under a key derived from the user's password by scrypt, with
15  its own random salt (independent of the server's password salt).
16  """
```

- **1–16** — Module docstring: one RSA key for receiving (others encrypt to it), one Ed25519 key for signing, kept separate so a problem in one role cannot affect the other; private keys are encrypted on disk under a password-derived key.

[`crypto_utils/keys.py` lines 18–29](../crypto_utils/keys.py#L18-L29)

```python
18  import os
19  
20  from cryptography.exceptions import InvalidTag
21  from cryptography.hazmat.primitives import hashes, serialization
22  from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
23  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
24  from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
25  
26  from .encoding import b64d, b64e
27  
28  RSA_BITS = 3072  # ~128-bit security, matches AES-128 or better
29  KEYFILE_N, KEYFILE_R, KEYFILE_P = 2**15, 8, 1
```

- **18** — `os.urandom` for salts and nonces.
- **20** — `InvalidTag` is raised by AES-GCM when the tag does not match (wrong key or changed data).
- **21** — `hashes` (SHA-256 for fingerprints) and `serialization` (turning keys into bytes or PEM text and back).
- **22** — The RSA and Ed25519 implementations.
- **23** — `AESGCM`, authenticated encryption.
- **24** — `Scrypt`, for the key-file key.
- **26** — base64 helpers.
- **28** — RSA keys are 3072 bits, giving roughly 128-bit security (the level of AES-128), which is the common recommendation for keys meant to last years.
- **29** — scrypt costs for the key file (same as for passwords: ≈32 MiB per attempt).

[`crypto_utils/keys.py` lines 32–41](../crypto_utils/keys.py#L32-L41)

```python
32  class KeyFileError(Exception):
33      """Raised when the key file cannot be unlocked (wrong password or tampered file)."""
34  
35  
36  class UserKeys:
37      """A user's two private keys (and, through them, the public keys)."""
38  
39      def __init__(self, enc_private: rsa.RSAPrivateKey, sign_private: ed25519.Ed25519PrivateKey):
40          self.enc_private = enc_private
41          self.sign_private = sign_private
```

- **32–33** — `KeyFileError` is raised when the key file cannot be unlocked. One exception covers "wrong password" and "file was edited", because AES-GCM cannot tell them apart, and the user should not be told which.
- **36–37** — `UserKeys` holds one user's two private keys. The public keys can always be derived from them.
- **39** — The constructor takes an RSA private key and an Ed25519 private key.
- **40** — Stored as `enc_private` ("encryption": others encrypt to its public half).
- **41** — Stored as `sign_private`.

[`crypto_utils/keys.py` lines 43–56](../crypto_utils/keys.py#L43-L56)

```python
43      @classmethod
44      def generate(cls) -> "UserKeys":
45          # 65537 is the standard RSA public exponent.
46          enc = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
47          sign = ed25519.Ed25519PrivateKey.generate()
48          return cls(enc, sign)
49  
50      # ---- public halves, as PEM text the server can store and share ----
51  
52      def enc_public_pem(self) -> str:
53          return public_pem(self.enc_private.public_key())
54  
55      def sign_public_pem(self) -> str:
56          return public_pem(self.sign_private.public_key())
```

- **43–44** — `generate` is a class method: `UserKeys.generate()` makes a brand-new user.
- **45–46** — A new RSA key. `65537` is the standard public exponent (fast and with no known weakness); `key_size=3072`.
- **47** — A new Ed25519 key (always 256-bit; nothing to configure, which is part of why Ed25519 is hard to misuse).
- **48** — Wrap both in a `UserKeys` object.
- **50** — Section comment.
- **52–53** — The RSA public key as PEM text (`-----BEGIN PUBLIC KEY-----…`), ready to send to the server.
- **55–56** — The same for the Ed25519 public key.

[`crypto_utils/keys.py` lines 58–78](../crypto_utils/keys.py#L58-L78)

```python
58      # ---- encrypted storage ----
59  
60      def to_encrypted_file(self, password: str) -> dict:
61          """Return a JSON-able dict holding both private keys, encrypted.
62  
63          Steps:
64            1. salt  = 16 random bytes
65            2. key   = scrypt(password, salt)        -> 32 bytes (AES-256)
66            3. nonce = 12 random bytes
67            4. blob  = AES-GCM(key, nonce, private keys in PKCS#8 DER)
68          GCM's tag means a wrong password or an edited file is *detected*,
69          not silently turned into garbage keys.
70          """
71          plain = _join(
72              self.enc_private.private_bytes(
73                  serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
74              ),
75              self.sign_private.private_bytes(
76                  serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
77              ),
78          )
```

- **58** — Section comment.
- **60** — `to_encrypted_file` produces the JSON content of `keys.json`.
- **61–70** — Docstring listing the four steps.
- **71** — `_join` (line 148) packs two byte strings into one, with a length prefix so they can be split again.
- **72–74** — The RSA private key as **DER** (compact binary) in **PKCS#8** format (the standard container for private keys), *without* the library's own encryption, because the next lines encrypt it.
- **75–78** — The same for the Ed25519 private key; line 78 closes the `_join(...)` call.

[`crypto_utils/keys.py` lines 79–92](../crypto_utils/keys.py#L79-L92)

```python
79          salt = os.urandom(16)
80          nonce = os.urandom(12)
81          key = _derive_file_key(password, salt, KEYFILE_N, KEYFILE_R, KEYFILE_P)
82          blob = AESGCM(key).encrypt(nonce, plain, b"secure-chat keyfile v1")
83          return {
84              "version": 1,
85              "kdf": {"algorithm": "scrypt", "n": KEYFILE_N, "r": KEYFILE_R, "p": KEYFILE_P, "salt": b64e(salt)},
86              "cipher": "AES-256-GCM",
87              "nonce": b64e(nonce),
88              "ciphertext": b64e(blob),
89              # Public keys are not secret; keeping them here is convenient.
90              "enc_public_pem": self.enc_public_pem(),
91              "sign_public_pem": self.sign_public_pem(),
92          }
```

- **79** — A new 16-byte random salt for this key file, independent of any server salt.
- **80** — A new 12-byte (96-bit) random nonce for AES-GCM.
- **81** — Derive a 32-byte AES-256 key from the password and salt with scrypt (line 144).
- **82** — Encrypt the packed private keys with AES-256-GCM. The third argument, `b"secure-chat keyfile v1"`, is **associated data**: it is not stored in the ciphertext but is covered by the tag, so this blob cannot be passed off as some other kind of encrypted data.
- **83–92** — The file content: format version, scrypt parameters and salt (needed to re-derive the key), cipher name, nonce, ciphertext (which includes the 16-byte tag), and the two **public** keys in clear for convenience, since they are not secret.

[`crypto_utils/keys.py` lines 94–105](../crypto_utils/keys.py#L94-L105)

```python
 94      @classmethod
 95      def from_encrypted_file(cls, data: dict, password: str) -> "UserKeys":
 96          kdf = data["kdf"]
 97          key = _derive_file_key(password, b64d(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"])
 98          try:
 99              plain = AESGCM(key).decrypt(b64d(data["nonce"]), b64d(data["ciphertext"]), b"secure-chat keyfile v1")
100          except InvalidTag:
101              raise KeyFileError("Could not unlock private keys (wrong password or damaged key file).") from None
102          enc_der, sign_der = _split(plain)
103          enc = serialization.load_der_private_key(enc_der, password=None)
104          sign = serialization.load_der_private_key(sign_der, password=None)
105          return cls(enc, sign)
```

- **94–95** — `from_encrypted_file` reverses the process at login.
- **96** — Read the stored scrypt settings.
- **97** — Re-derive the AES key from the typed password and the stored salt and costs.
- **98–99** — Decrypt. AES-GCM checks the tag first: with the wrong password the key is wrong, so the tag does not match.
- **100–101** — On a tag failure, raise `KeyFileError` with a message that does not say whether the password or the file was the problem. `from None` hides the internal exception chain.
- **102** — Split the plaintext back into the two DER keys.
- **103–104** — Parse each DER blob back into a key object. `password=None` because these inner bytes are not separately encrypted.
- **105** — Return a ready-to-use `UserKeys`.

[`crypto_utils/keys.py` lines 108–128](../crypto_utils/keys.py#L108-L128)

```python
108  # ---------------------------------------------------------------- helpers
109  
110  
111  def public_pem(public_key) -> str:
112      return public_key.public_bytes(
113          serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
114      ).decode("ascii")
115  
116  
117  def load_enc_public(pem: str) -> rsa.RSAPublicKey:
118      key = serialization.load_pem_public_key(pem.encode("ascii"))
119      if not isinstance(key, rsa.RSAPublicKey):
120          raise ValueError("expected an RSA public key")
121      return key
122  
123  
124  def load_sign_public(pem: str) -> ed25519.Ed25519PublicKey:
125      key = serialization.load_pem_public_key(pem.encode("ascii"))
126      if not isinstance(key, ed25519.Ed25519PublicKey):
127          raise ValueError("expected an Ed25519 public key")
128      return key
```

- **108** — Section comment.
- **111–114** — `public_pem` turns any public key into PEM text in the standard **SubjectPublicKeyInfo** format, which records the key type, so the receiver can tell RSA from Ed25519.
- **117** — `load_enc_public` parses PEM text that is supposed to be an RSA public key.
- **118** — Parse it. Junk raises `ValueError`.
- **119–120** — If it parsed but is not RSA (for example someone put an Ed25519 key in the RSA slot), refuse. The server uses this at signup to reject fake keys.
- **121** — Return the key.
- **124–128** — The same for the Ed25519 signing key.

[`crypto_utils/keys.py` lines 131–141](../crypto_utils/keys.py#L131-L141)

```python
131  def fingerprint(enc_pem: str, sign_pem: str) -> str:
132      """Short SHA-256 fingerprint of a user's two public keys.
133  
134      Two people can read this aloud to each other (phone, in person) to
135      confirm the server handed out the right keys.
136      """
137      h = hashes.Hash(hashes.SHA256())
138      h.update(enc_pem.encode("ascii"))
139      h.update(sign_pem.encode("ascii"))
140      hexed = h.finalize().hex()[:32].upper()
141      return " ".join(hexed[i : i + 4] for i in range(0, len(hexed), 4))
```

- **131** — `fingerprint` makes a short code people can compare by voice.
- **132–136** — Docstring.
- **137** — Start SHA-256.
- **138–139** — Hash both PEM texts, so a change to either key changes the fingerprint.
- **140** — Hex-encode and keep the first 32 hex digits (128 bits), upper case. 128 bits is far too many for anyone to find two key sets with the same fingerprint.
- **141** — Insert a space every 4 digits, e.g. `E448 7A25 635F …`, to make it easier to read aloud.

[`crypto_utils/keys.py` lines 144–155](../crypto_utils/keys.py#L144-L155)

```python
144  def _derive_file_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
145      return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))
146  
147  
148  def _join(a: bytes, b: bytes) -> bytes:
149      # Length-prefix the first key so the two can be split again unambiguously.
150      return len(a).to_bytes(4, "big") + a + b
151  
152  
153  def _split(data: bytes) -> tuple[bytes, bytes]:
154      n = int.from_bytes(data[:4], "big")
155      return data[4 : 4 + n], data[4 + n :]
```

- **144–145** — `_derive_file_key`: scrypt of the password with the key file's salt and costs, giving a 32-byte AES-256 key.
- **148–150** — `_join` writes the first key's length as 4 bytes (big-endian), then the first key, then the second. Without the length, the boundary between two variable-length blobs would be ambiguous.
- **153** — `_split` reverses `_join`.
- **154** — Read the 4-byte length.
- **155** — Slice out the first key (`n` bytes after the prefix) and the second (the rest).

## 2.4 `messages.py`

The heart of end-to-end security: how one message is sealed by the sender and opened by
the recipient.

[`crypto_utils/messages.py` lines 1–32](../crypto_utils/messages.py#L1-L32)

```python
 1  """The end-to-end message format.
 2  
 3      Sender (Bob)                                     Receiver (Alice)
 4      ------------                                     ----------------
 5      1. aes_key = 32 random bytes                     1. verify Ed25519 signature
 6      2. nonce   = 12 random bytes                        with Bob's public key
 7      3. ciphertext = AES-256-GCM(aes_key, nonce,         -> reject if invalid
 8                       plaintext, aad=metadata)        2. check message ID not seen
 9      4. wrapped_key = RSA-OAEP(Alice's public key,       -> reject replays
10                                aes_key)               3. aes_key = RSA-OAEP-decrypt
11      5. signature = Ed25519(Bob's private key,            (Alice's private key)
12                     every field below)                4. plaintext = AES-GCM-decrypt
13                                                          -> GCM tag must verify
14  
15  This is "hybrid encryption": RSA is slow and can only encrypt a few hundred
16  bytes, AES is fast and handles any length, so RSA protects only the small
17  AES key and AES protects the message.
18  
19  The package (all binary values base64-encoded):
20  
21      {
22        "version": 1,
23        "msg_id": "<random 128-bit hex>",
24        "sender": "bob",
25        "recipient": "alice",
26        "timestamp": 1763450000,
27        "nonce": "...",          # 96-bit AES-GCM nonce
28        "ciphertext": "...",     # AES-GCM output (includes the 128-bit tag)
29        "wrapped_key": "...",    # AES key encrypted with RSA-OAEP
30        "signature": "..."       # Ed25519 over all fields above
31      }
32  """
```

- **1–32** — Module docstring: the five sender steps and four receiver steps side by side; why "hybrid" encryption (RSA protects only the small AES key, AES protects the message); and the package format.

[`crypto_utils/messages.py` lines 34–52](../crypto_utils/messages.py#L34-L52)

```python
34  import os
35  import time
36  import uuid
37  
38  from cryptography.exceptions import InvalidSignature, InvalidTag
39  from cryptography.hazmat.primitives import hashes
40  from cryptography.hazmat.primitives.asymmetric import padding
41  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
42  
43  from .encoding import b64d, b64e, canonical_json
44  from .keys import UserKeys, load_enc_public, load_sign_public
45  
46  VERSION = 1
47  SIGNATURE_CONTEXT = "secure-chat/message/v1"  # domain separation label, see _signed_bytes
48  SIGNED_FIELDS = ("version", "msg_id", "sender", "recipient", "timestamp", "nonce", "ciphertext", "wrapped_key")
49  MAX_FUTURE_SKEW = 300  # seconds a timestamp may be ahead of the receiver's clock
50  
51  # RSA-OAEP with SHA-256 for both the hash and the mask generation function.
52  OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
```

- **34** — `os.urandom` for the nonce.
- **35** — `time` for timestamps.
- **36** — `uuid` for random message IDs.
- **38** — `InvalidSignature` (Ed25519 verification failed) and `InvalidTag` (AES-GCM authentication failed).
- **39** — `hashes` for SHA-256 in OAEP.
- **40** — `padding` provides OAEP.
- **41** — `AESGCM`.
- **43** — Helpers from `encoding.py`.
- **44** — Key helpers from `keys.py`.
- **46** — Package format version 1. Bumping it lets a future format be told apart.
- **47** — The **signature context** (domain separation): every signature covers this label, so a signature over some other JSON can never be mistaken for a message signature.
- **48** — The fields the signature covers: everything in the package except the signature itself.
- **49** — A message may claim to be at most 5 minutes in the future (allows for clock differences).
- **51–52** — The RSA-OAEP settings: SHA-256 as the hash and inside MGF1 (the mask generation function), no label. OAEP is the modern padding for RSA encryption; the older PKCS#1 v1.5 padding has practical attacks.

[`crypto_utils/messages.py` lines 55–64](../crypto_utils/messages.py#L55-L64)

```python
55  class MessageRejected(Exception):
56      """The receiver refuses a message. `reason` says why, in plain words."""
57  
58      def __init__(self, reason: str):
59          super().__init__(reason)
60          self.reason = reason
61  
62  
63  def _no_trace(step: str, detail: str = "") -> None:
64      pass
```

- **55–56** — `MessageRejected` is how the receiver says "no". It carries a human-readable reason.
- **58–60** — Store the reason so the client can show it.
- **63–64** — `_no_trace` is the default "do nothing" for the optional step-by-step printer used by verbose mode and the demo.

[`crypto_utils/messages.py` lines 67–77](../crypto_utils/messages.py#L67-L77)

```python
67  def _signed_bytes(package: dict) -> bytes:
68      """The exact bytes the signature covers.
69  
70      Every field except the signature itself is included, so changing ANY of
71      them (ciphertext, nonce, wrapped key, sender, recipient, time, ID)
72      breaks the signature. The context label stops a signature made for some
73      other purpose from ever being accepted as a message signature.
74      """
75      body = {k: package[k] for k in SIGNED_FIELDS}
76      body["context"] = SIGNATURE_CONTEXT
77      return canonical_json(body)
```

- **67** — `_signed_bytes` builds the exact bytes the signature covers.
- **68–74** — Docstring: changing any field breaks the signature; the context label prevents cross-purpose signatures.
- **75** — Copy only the signed fields (so an extra field an attacker adds cannot change what is checked).
- **76** — Add the context label.
- **77** — Canonical JSON (section 2.1): one exact byte string for both signer and verifier.

[`crypto_utils/messages.py` lines 80–89](../crypto_utils/messages.py#L80-L89)

```python
80  def _aad(msg_id: str, sender: str, recipient: str, timestamp: int) -> bytes:
81      """Associated data for AES-GCM.
82  
83      AAD is not encrypted, but GCM's tag covers it. Binding the metadata here
84      means the ciphertext only decrypts in the context it was created for,
85      a second line of defence behind the signature.
86      """
87      return canonical_json(
88          {"v": VERSION, "msg_id": msg_id, "sender": sender, "recipient": recipient, "timestamp": timestamp}
89      )
```

- **80** — `_aad` builds the **associated data** for AES-GCM.
- **81–86** — Docstring: AAD is authenticated but not encrypted; binding the metadata means the ciphertext only decrypts in its original context, a second line of defence behind the signature.
- **87–89** — Canonical JSON of version, message ID, sender, recipient and timestamp.

[`crypto_utils/messages.py` lines 92–105](../crypto_utils/messages.py#L92-L105)

```python
 92  # ===================================================================== send
 93  
 94  
 95  def encrypt_and_sign(
 96      plaintext: str,
 97      sender: str,
 98      recipient: str,
 99      sender_keys: UserKeys,
100      recipient_enc_public_pem: str,
101      trace=_no_trace,
102  ) -> dict:
103      """Build a sealed, signed package for `recipient`."""
104      msg_id = uuid.uuid4().hex  # 122 random bits, unique per message
105      timestamp = int(time.time())
```

- **92** — Section comment: sending.
- **95–102** — `encrypt_and_sign` takes the text, both names, the sender's keys, the recipient's RSA public key as PEM, and the optional trace printer.
- **103** — Docstring.
- **104** — `uuid4` gives 122 random bits as 32 hex characters. The chance of two messages ever sharing an ID is negligible, and IDs cannot be predicted.
- **105** — The current time in whole seconds since 1970 (Unix time).

[`crypto_utils/messages.py` lines 107–117](../crypto_utils/messages.py#L107-L117)

```python
107      # --- Step 1: encrypt with a fresh AES-256 key and a fresh 96-bit nonce.
108      aes_key = AESGCM.generate_key(bit_length=256)
109      nonce = os.urandom(12)
110      ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), _aad(msg_id, sender, recipient, timestamp))
111      trace(
112          "ENCRYPT",
113          f"AES-256-GCM with a fresh random key and nonce {nonce.hex()}\n"
114          f"plaintext {len(plaintext.encode())} bytes -> ciphertext {len(ciphertext)} bytes "
115          f"(last 16 bytes are the GCM tag)\n"
116          f"ciphertext: {ciphertext.hex()[:64]}...",
117      )
```

- **107** — Step 1 comment.
- **108** — A brand-new random 256-bit AES key, used for this one message only.
- **109** — A brand-new random 96-bit nonce. With a fresh key every time, nonce reuse (the one thing that badly breaks GCM) cannot happen.
- **110** — Encrypt the UTF-8 bytes of the text with AES-256-GCM, with the metadata as associated data. The output is the ciphertext followed by a 16-byte tag.
- **111–117** — Optional trace for verbose mode: nonce, sizes, and the start of the ciphertext. It never prints the AES key.

[`crypto_utils/messages.py` lines 119–124](../crypto_utils/messages.py#L119-L124)

```python
119      # --- Step 2: wrap the AES key so only the recipient can recover it.
120      wrapped_key = load_enc_public(recipient_enc_public_pem).encrypt(aes_key, OAEP)
121      trace(
122          "WRAP KEY",
123          f"RSA-OAEP(SHA-256) with {recipient}'s public key: 32-byte AES key -> {len(wrapped_key)}-byte wrapped key",
124      )
```

- **119** — Step 2 comment.
- **120** — Parse the recipient's RSA public key (rejecting anything that isn't RSA) and encrypt the 32-byte AES key with RSA-OAEP. For a 3072-bit key the result is 384 bytes. Only the holder of the recipient's private key can undo this.
- **121–124** — Trace.

[`crypto_utils/messages.py` lines 126–135](../crypto_utils/messages.py#L126-L135)

```python
126      package = {
127          "version": VERSION,
128          "msg_id": msg_id,
129          "sender": sender,
130          "recipient": recipient,
131          "timestamp": timestamp,
132          "nonce": b64e(nonce),
133          "ciphertext": b64e(ciphertext),
134          "wrapped_key": b64e(wrapped_key),
135      }
```

- **126–135** — Assemble the package. Text fields stay text; the three binary fields become base64. The signature is not there yet.

[`crypto_utils/messages.py` lines 137–145](../crypto_utils/messages.py#L137-L145)

```python
137      # --- Step 3: sign everything with the sender's Ed25519 private key.
138      signature = sender_keys.sign_private.sign(_signed_bytes(package))
139      package["signature"] = b64e(signature)
140      trace(
141          "SIGN",
142          f"Ed25519 with {sender}'s private key over version, msg_id, sender, recipient, timestamp,\n"
143          f"nonce, ciphertext, wrapped_key -> 64-byte signature {signature.hex()[:32]}...",
144      )
145      return package
```

- **137** — Step 3 comment.
- **138** — Sign the canonical bytes of all fields with the sender's Ed25519 private key. Ed25519 signatures are always 64 bytes and deterministic, with no random number to get wrong.
- **139** — Add the signature (base64).
- **140–144** — Trace.
- **145** — Return the finished package, ready to send.

[`crypto_utils/messages.py` lines 148–167](../crypto_utils/messages.py#L148-L167)

```python
148  # ================================================================== receive
149  
150  
151  def verify_and_decrypt(
152      package: dict,
153      my_name: str,
154      my_keys: UserKeys,
155      sender_sign_public_pem: str,
156      seen_ids: set | None = None,
157      trace=_no_trace,
158  ) -> str:
159      """Check and open a package. Returns the plaintext or raises MessageRejected.
160  
161      The order matters: the signature is verified FIRST, before we spend any
162      effort on (or expose any code to) data from an unauthenticated source.
163      """
164      try:
165          _check_shape(package)
166      except (KeyError, TypeError, ValueError) as exc:
167          raise MessageRejected(f"malformed package ({str(exc)[:80]})") from None
```

- **148** — Section comment: receiving.
- **151–158** — `verify_and_decrypt` takes the package, the receiver's own name and keys, the claimed sender's signing public key, the set of already-seen message IDs, and the trace printer. It returns the text or raises `MessageRejected`.
- **159–163** — Docstring: the signature is checked first.
- **164–165** — Run the shape checks (lines 233–261).
- **166–167** — Any shape problem becomes a rejection, with the reason cut to 80 characters so a hostile package cannot flood the screen.

[`crypto_utils/messages.py` lines 169–179](../crypto_utils/messages.py#L169-L179)

```python
169      # --- Step 1: who sent this, and is it exactly what they sent?
170      try:
171          signature = b64d(package["signature"])
172          load_sign_public(sender_sign_public_pem).verify(signature, _signed_bytes(package))
173      except (InvalidSignature, ValueError):
174          trace("VERIFY", f"signature does NOT match {package['sender']}'s public key -> REJECT")
175          raise MessageRejected(
176              f"invalid signature: this message was not signed by '{package['sender']}' "
177              "or was modified after signing"
178          ) from None
179      trace("VERIFY", f"Ed25519 signature is valid for {package['sender']}'s public key")
```

- **169** — Step 1 comment: authenticity and integrity.
- **170–171** — Decode the signature.
- **172** — Verify it with the sender's public key over the canonical bytes of every signed field. Ed25519's `verify` raises `InvalidSignature` if even one bit of any field differs, or if a different key made the signature.
- **173–178** — On failure: trace it and reject with a clear warning. Nothing has been decrypted.
- **179** — Trace success.

[`crypto_utils/messages.py` lines 181–190](../crypto_utils/messages.py#L181-L190)

```python
181      # --- Step 2: is it really for me, and is it new?
182      if package["recipient"] != my_name:
183          raise MessageRejected(f"message is addressed to '{package['recipient']}', not to you")
184      if package["timestamp"] > time.time() + MAX_FUTURE_SKEW:
185          raise MessageRejected("timestamp is in the future")
186      if seen_ids is not None:
187          if package["msg_id"] in seen_ids:
188              trace("REPLAY CHECK", f"message ID {package['msg_id']} was already received -> REJECT")
189              raise MessageRejected(f"replay detected: message ID {package['msg_id']} was already received")
190          trace("REPLAY CHECK", f"message ID {package['msg_id']} is new")
```

- **181** — Step 2 comment.
- **182–183** — The signed `recipient` must be me. This stops a valid message to Carol from being shown to Alice as if it were for her.
- **184–185** — Reject timestamps more than 5 minutes in the future. (A past timestamp is allowed: messages may wait on the server while you are offline.)
- **186** — Replay checking is optional so the function can also be used without state (the demo uses this).
- **187–189** — If this message ID was already accepted, it is a replay: reject.
- **190** — Trace.

[`crypto_utils/messages.py` lines 192–197](../crypto_utils/messages.py#L192-L197)

```python
192      # --- Step 3: unwrap the AES key with my RSA private key.
193      try:
194          aes_key = my_keys.enc_private.decrypt(b64d(package["wrapped_key"]), OAEP)
195      except ValueError:
196          raise MessageRejected("could not unwrap the AES key (not encrypted to your key)") from None
197      trace("UNWRAP KEY", "RSA-OAEP decrypt with my private key -> 32-byte AES key")
```

- **192** — Step 3 comment.
- **193–194** — Decrypt the wrapped key with the receiver's RSA private key and OAEP.
- **195–196** — OAEP decryption raises `ValueError` if the key was not encrypted to this key pair or was altered.
- **197** — Trace.

[`crypto_utils/messages.py` lines 199–219](../crypto_utils/messages.py#L199-L219)

```python
199      # --- Step 4: decrypt; GCM checks its authentication tag at the same time.
200      try:
201          plaintext = AESGCM(aes_key).decrypt(
202              b64d(package["nonce"]),
203              b64d(package["ciphertext"]),
204              _aad(package["msg_id"], package["sender"], package["recipient"], package["timestamp"]),
205          )
206      except InvalidTag:
207          trace("DECRYPT", "AES-GCM authentication tag does NOT verify -> REJECT")
208          raise MessageRejected("AES-GCM authentication failed: ciphertext or metadata was modified") from None
209      except ValueError:  # e.g. an AES key of the wrong length, wrapped by a hostile sender
210          raise MessageRejected("could not decrypt: the sender's package is malformed") from None
211      try:
212          text = plaintext.decode("utf-8")
213      except UnicodeDecodeError:
214          raise MessageRejected("decrypted content is not valid text") from None
215      trace("DECRYPT", "AES-256-GCM tag verified, plaintext recovered")
216  
217      if seen_ids is not None:
218          seen_ids.add(package["msg_id"])
219      return text
```

- **199** — Step 4 comment.
- **200–205** — AES-GCM decryption with the recovered key and nonce, rebuilding the same associated data from the package fields. GCM checks the tag before returning anything.
- **206–208** — Tag mismatch → the ciphertext, nonce or metadata changed → reject.
- **209–210** — A hostile but validly-signed sender could wrap a key of the wrong length; `AESGCM` then raises `ValueError`. Reject cleanly instead of crashing.
- **211–214** — The decrypted bytes must be valid UTF-8; otherwise reject (another hostile-sender case).
- **215** — Trace.
- **217–218** — Only now, after every check passed, record the ID as seen.
- **219** — Return the text.

[`crypto_utils/messages.py` lines 222–230](../crypto_utils/messages.py#L222-L230)

```python
222  def decrypt_without_signature_check(package: dict, my_keys: UserKeys) -> str:
223      """FOR DEMONSTRATION ONLY. Skips the signature to show that AES-GCM's tag
224      independently catches tampering. Never use this for real messages."""
225      aes_key = my_keys.enc_private.decrypt(b64d(package["wrapped_key"]), OAEP)
226      return AESGCM(aes_key).decrypt(
227          b64d(package["nonce"]),
228          b64d(package["ciphertext"]),
229          _aad(package["msg_id"], package["sender"], package["recipient"], package["timestamp"]),
230      ).decode("utf-8")
```

- **222** — `decrypt_without_signature_check` exists only for the demo.
- **223–224** — Docstring warning.
- **225** — Unwrap the AES key, skipping the signature.
- **226–230** — Decrypt with AES-GCM. The demo uses this to show that even without the signature, GCM's tag alone catches a modified ciphertext.

[`crypto_utils/messages.py` lines 233–261](../crypto_utils/messages.py#L233-L261)

```python
233  def _check_shape(package: dict) -> None:
234      """Reject anything that is not a well-formed v1 package.
235  
236      This only parses; it trusts nothing. Every binary field must be valid
237      base64 of a sensible size, so nothing later can trip over junk, even
238      junk that its sender signed with a perfectly valid key.
239      """
240      if not isinstance(package, dict):
241          raise TypeError("package must be an object")
242      for field in SIGNED_FIELDS + ("signature",):
243          if field not in package:
244              raise KeyError(field)
245      if package["version"] != VERSION:
246          raise ValueError("unsupported version")
247      if type(package["timestamp"]) is not int or not 0 < package["timestamp"] < 2**40:
248          raise TypeError("timestamp must be a reasonable integer")
249      for field in ("msg_id", "sender", "recipient", "nonce", "ciphertext", "wrapped_key", "signature"):
250          if not isinstance(package[field], str):
251              raise TypeError(f"{field} must be a string")
252      if len(package["msg_id"]) != 32 or any(c not in "0123456789abcdef" for c in package["msg_id"]):
253          raise ValueError("message ID must be 32 lowercase hex characters")
254      if len(b64d(package["nonce"])) != 12:
255          raise ValueError("nonce must be 96 bits")
256      if len(b64d(package["ciphertext"])) < 16:
257          raise ValueError("ciphertext shorter than a GCM tag")
258      if not b64d(package["wrapped_key"]):
259          raise ValueError("empty wrapped key")
260      if len(b64d(package["signature"])) != 64:
261          raise ValueError("Ed25519 signatures are 64 bytes")
```

- **233** — `_check_shape` validates structure before anything else touches the package.
- **234–239** — Docstring: it only parses and trusts nothing.
- **240–241** — Must be a JSON object (dict).
- **242–244** — Every signed field and the signature must exist.
- **245–246** — Version must be 1.
- **247–248** — The timestamp must be a real integer (`type(...) is int` excludes `True`/`False`, which Python otherwise treats as 1 and 0) within a sane range (below 2^40, about the year 36,812), so later arithmetic cannot overflow.
- **249–251** — All other fields must be strings.
- **252–253** — The message ID must be exactly 32 lowercase hex characters, which is what `uuid4().hex` (line 104) produces. Allowing any text here would let a hostile sender put newlines or terminal escape codes into the ID, which is later printed (finding V1, now fixed; see document 6).
- **254–255** — The nonce must decode to exactly 12 bytes (96 bits).
- **256–257** — The ciphertext must be at least 16 bytes, the size of the GCM tag alone.
- **258–259** — The wrapped key must not be empty.
- **260–261** — The signature must be exactly 64 bytes (Ed25519's size).

## 2.5 `tls.py`

Creates the server's certificates on first start and defines the TLS settings for both
sides.

[`crypto_utils/tls.py` lines 1–25](../crypto_utils/tls.py#L1-L25)

```python
 1  """TLS certificates and settings for the client-server connection.
 2  
 3  Why TLS on top of the end-to-end encryption?
 4      End-to-end encryption already protects message *contents*. TLS protects
 5      everything else on the wire: the login hash (which would otherwise be
 6      replayable), usernames, the user list, who sends to whom, and the
 7      message envelopes. It also proves to the client that it is talking to
 8      the real server and not an impostor in the middle.
 9  
10  How trust works here (a private certificate authority):
11  
12      ca.crt       "Secure Chat local CA": the ONLY certificate clients trust.
13                   Copy this file to every client computer.
14      server.crt   the server's certificate, signed by the CA, valid for the
15                   server's host names / IP addresses.
16      server.key   the server's private key. Never leaves the server.
17  
18  The CA's own private key is used once, to sign server.crt, and then thrown
19  away, so nobody (including a thief of the server folder) can mint another
20  certificate that clients would trust. To change host names, delete the tls
21  folder; a new CA is made and ca.crt must be copied to clients again.
22  
23  TLS itself is Python's standard `ssl` module (OpenSSL). Certificates are
24  built with `cryptography`. Nothing here is hand-made cryptography.
25  """
```

- **1–25** — Module docstring: why TLS on top of end-to-end encryption, what the three files are, and why the CA's private key is discarded.

[`crypto_utils/tls.py` lines 27–38](../crypto_utils/tls.py#L27-L38)

```python
27  import datetime
28  import ipaddress
29  import os
30  import ssl
31  
32  from cryptography import x509
33  from cryptography.hazmat.primitives import hashes, serialization
34  from cryptography.hazmat.primitives.asymmetric import ec
35  from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
36  
37  CA_FILE, CERT_FILE, KEY_FILE = "ca.crt", "server.crt", "server.key"
38  DEFAULT_HOSTNAMES = ("localhost", "127.0.0.1", "::1")
```

- **27** — `datetime` for certificate validity dates.
- **28** — `ipaddress` to tell IP addresses from host names.
- **29** — `os` for folders and paths.
- **30** — `ssl` is Python's TLS implementation (OpenSSL underneath).
- **32** — `x509` builds and reads certificates.
- **33** — `hashes` (SHA-256 for signatures and fingerprints) and `serialization` (writing PEM files).
- **34** — `ec` is elliptic-curve cryptography, used for the CA and server keys.
- **35** — Standard identifiers for "TLS server" usage and for the common-name field.
- **37** — The three file names.
- **38** — Names the server certificate is always valid for: `localhost`, IPv4 loopback and IPv6 loopback.

[`crypto_utils/tls.py` lines 41–52](../crypto_utils/tls.py#L41-L52)

```python
41  def _name(common_name: str) -> x509.Name:
42      return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
43  
44  
45  def _san_entries(hostnames):
46      entries = []
47      for h in dict.fromkeys(hostnames):  # de-duplicate, keep order
48          try:
49              entries.append(x509.IPAddress(ipaddress.ip_address(h)))
50          except ValueError:
51              entries.append(x509.DNSName(h))
52      return entries
```

- **41–42** — `_name` builds a certificate name containing just a common name (CN).
- **45** — `_san_entries` builds the Subject Alternative Name list, which is what TLS clients actually check the host name against.
- **46** — Start an empty list.
- **47** — `dict.fromkeys` removes duplicates while keeping the order.
- **48–49** — If the value parses as an IP address, add it as an IP entry.
- **50–51** — Otherwise add it as a DNS name.
- **52** — Return the list.

[`crypto_utils/tls.py` lines 55–59](../crypto_utils/tls.py#L55-L59)

```python
55  def generate_server_tls(folder: str, hostnames=DEFAULT_HOSTNAMES) -> dict:
56      """Create ca.crt, server.crt and server.key in `folder`. Returns their paths."""
57      os.makedirs(folder, exist_ok=True)
58      now = datetime.datetime.now(datetime.timezone.utc)
59      start = now - datetime.timedelta(minutes=5)  # tolerate small clock differences
```

- **55** — `generate_server_tls` makes all three files.
- **56** — Docstring.
- **57** — Create the folder if needed.
- **58** — Current time in UTC (certificates use UTC).
- **59** — Validity starts 5 minutes ago, so a client whose clock is slightly behind still accepts it.

[`crypto_utils/tls.py` lines 61–78](../crypto_utils/tls.py#L61-L78)

```python
61      # 1. The certificate authority (P-256 elliptic-curve key: fast and strong).
62      ca_key = ec.generate_private_key(ec.SECP256R1())
63      ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
64      ca_cert = (
65          x509.CertificateBuilder()
66          .subject_name(_name("Secure Chat local CA"))
67          .issuer_name(_name("Secure Chat local CA"))
68          .public_key(ca_key.public_key())
69          .serial_number(x509.random_serial_number())
70          .not_valid_before(start)
71          .not_valid_after(now + datetime.timedelta(days=3650))
72          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
73          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
74                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
75                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
76          .add_extension(ca_ski, critical=False)
77          .sign(ca_key, hashes.SHA256())
78      )
```

- **61** — Comment: the CA uses a P-256 elliptic-curve key, which is fast and roughly as strong as RSA-3072.
- **62** — Generate the CA's private key.
- **63** — The Subject Key Identifier, a hash of the CA public key that later links the server certificate back to this CA.
- **64–65** — Start building the CA certificate.
- **66–67** — Subject and issuer are the same name: the CA vouches for itself (self-signed root).
- **68** — The CA's public key goes in the certificate.
- **69** — A random serial number, as the standard requires.
- **70–71** — Valid from 5 minutes ago for 10 years.
- **72** — **Basic Constraints: CA = true, path length 0**, marked critical. It may sign certificates, but only end certificates, never another CA.
- **73–75** — **Key Usage** (critical): only `key_cert_sign` and `crl_sign`. The CA key may sign certificates and nothing else.
- **76** — Include the Subject Key Identifier.
- **77–78** — Sign the certificate with the CA's own key using ECDSA with SHA-256; line 78 closes the builder expression.

[`crypto_utils/tls.py` lines 80–100](../crypto_utils/tls.py#L80-L100)

```python
 80      # 2. The server's own key and certificate, signed by the CA.
 81      server_key = ec.generate_private_key(ec.SECP256R1())
 82      server_cert = (
 83          x509.CertificateBuilder()
 84          .subject_name(_name("Secure Chat server"))
 85          .issuer_name(ca_cert.subject)
 86          .public_key(server_key.public_key())
 87          .serial_number(x509.random_serial_number())
 88          .not_valid_before(start)
 89          .not_valid_after(now + datetime.timedelta(days=825))
 90          .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
 91          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
 92                                       data_encipherment=False, key_agreement=False, key_cert_sign=False,
 93                                       crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
 94          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
 95          .add_extension(x509.SubjectAlternativeName(_san_entries(hostnames)), critical=False)
 96          .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
 97          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
 98          .sign(ca_key, hashes.SHA256())
 99      )
100      del ca_key  # never saved: no one can issue more trusted certificates
```

- **80** — Comment.
- **81** — Generate the server's own P-256 private key.
- **82–83** — Start building the server certificate.
- **84** — Subject name "Secure Chat server" (informational; host names are checked through SAN).
- **85** — Issuer is the CA.
- **86** — The server's public key.
- **87** — Random serial.
- **88–89** — Valid from 5 minutes ago for 825 days (a common maximum lifetime for server certificates).
- **90** — Basic Constraints: **not** a CA, so this certificate cannot be used to sign others.
- **91–93** — Key Usage: `digital_signature` only. In TLS 1.3 the server proves it holds the key by signing the handshake.
- **94** — Extended Key Usage: **TLS server authentication** only.
- **95** — The SAN list: the host names and IPs clients will connect to.
- **96** — This certificate's own key identifier.
- **97** — The Authority Key Identifier: points at the CA's key identifier, linking the chain.
- **98–99** — Signed by the **CA's** private key; line 99 closes the builder expression.
- **100** — `del ca_key` drops the only reference to the CA private key. It was never written to disk, so after this function returns nobody can issue another certificate clients would trust.

[`crypto_utils/tls.py` lines 102–108](../crypto_utils/tls.py#L102-L108)

```python
102      paths = tls_paths(folder)
103      _write(paths["ca"], ca_cert.public_bytes(serialization.Encoding.PEM))
104      _write(paths["cert"], server_cert.public_bytes(serialization.Encoding.PEM))
105      _write(paths["key"], server_key.private_bytes(serialization.Encoding.PEM,
106                                                    serialization.PrivateFormat.PKCS8,
107                                                    serialization.NoEncryption()))
108      return paths
```

- **102** — Work out the three file paths.
- **103** — Write the CA certificate (public) as PEM.
- **104** — Write the server certificate (public) as PEM.
- **105–107** — Write the server's private key as unencrypted PKCS#8 PEM, so the server can start without someone typing a passphrase. Its only protection is file permissions (see document 6).
- **108** — Return the paths.

[`crypto_utils/tls.py` lines 111–121](../crypto_utils/tls.py#L111-L121)

```python
111  def tls_paths(folder: str) -> dict:
112      return {"ca": os.path.join(folder, CA_FILE), "cert": os.path.join(folder, CERT_FILE),
113              "key": os.path.join(folder, KEY_FILE)}
114  
115  
116  def ensure_server_tls(folder: str, hostnames=DEFAULT_HOSTNAMES) -> tuple[dict, bool]:
117      """Use the existing certificates in `folder`, or create them. Returns (paths, created)."""
118      paths = tls_paths(folder)
119      if all(os.path.exists(p) for p in paths.values()):
120          return paths, False
121      return generate_server_tls(folder, hostnames), True
```

- **111–113** — `tls_paths` maps a folder to the three file paths.
- **116** — `ensure_server_tls` is called at every server start.
- **117** — Docstring.
- **118** — Work out the paths.
- **119–120** — If all three files exist, reuse them (clients keep trusting the same CA).
- **121** — Otherwise generate new ones and report that they were created.

[`crypto_utils/tls.py` lines 124–129](../crypto_utils/tls.py#L124-L129)

```python
124  def certificate_fingerprint(pem_path: str) -> str:
125      """SHA-256 fingerprint of a certificate, for checking ca.crt was copied correctly."""
126      with open(pem_path, "rb") as f:
127          cert = x509.load_pem_x509_certificate(f.read())
128      hexed = cert.fingerprint(hashes.SHA256()).hex().upper()
129      return ":".join(hexed[i:i + 2] for i in range(0, 24, 2)) + ":..."
```

- **124** — `certificate_fingerprint` gives a short identifier for `ca.crt`.
- **125** — Docstring.
- **126–127** — Read and parse the certificate.
- **128** — SHA-256 over the certificate's DER bytes, in upper-case hex.
- **129** — The first 12 bytes as `AA:BB:…`, followed by `...` to show it is shortened. Enough to compare by eye that a copied `ca.crt` is the right one.

[`crypto_utils/tls.py` lines 132–146](../crypto_utils/tls.py#L132-L146)

```python
132  def server_context(cert_path: str, key_path: str) -> ssl.SSLContext:
133      """TLS 1.3 only. TLS 1.3 always uses forward-secret key exchange and
134      authenticated encryption (AES-GCM or ChaCha20-Poly1305)."""
135      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
136      ctx.minimum_version = ssl.TLSVersion.TLSv1_3
137      ctx.load_cert_chain(cert_path, key_path)
138      return ctx
139  
140  
141  def client_context(ca_path: str) -> ssl.SSLContext:
142      """Trust ONLY our CA (not the computer's usual list of public CAs),
143      require TLS 1.3, and check the certificate matches the host name."""
144      ctx = ssl.create_default_context(cafile=ca_path)  # verify_mode=CERT_REQUIRED, check_hostname=True
145      ctx.minimum_version = ssl.TLSVersion.TLSv1_3
146      return ctx
```

- **132** — `server_context` builds the server's TLS settings.
- **133–134** — Docstring: TLS 1.3 always uses forward-secret key exchange and authenticated encryption.
- **135** — A server-side TLS context.
- **136** — Refuse anything older than TLS 1.3.
- **137** — Load the certificate and its private key.
- **138** — Return it.
- **141** — `client_context` builds the client's TLS settings.
- **142–143** — Docstring.
- **144** — `create_default_context(cafile=…)` turns on certificate verification (`CERT_REQUIRED`) and host-name checking, and, because a `cafile` is given, trusts **only** that file instead of the computer's usual list of public certificate authorities.
- **145** — Refuse anything older than TLS 1.3.
- **146** — Return it.

[`crypto_utils/tls.py` lines 149–151](../crypto_utils/tls.py#L149-L151)

```python
149  def _write(path: str, data: bytes) -> None:
150      with open(path, "wb") as f:
151          f.write(data)
```

- **149–151** — `_write` writes bytes to a file, closing it afterwards.
