# Secure Chat: full technical documentation

This folder explains the whole system: how it works step by step, what every line of
code does, and how well it protects **security**, **integrity** and **privacy**,
including where it can still be attacked.

The project's main [README](../README.md) is the user guide (setup, commands,
protocol summary). These documents go much deeper.

## Reading order

| # | Document | What it covers |
|---|---|---|
| 1 | [How the system works, step by step](01-how-it-works.md) | The parts, where data lives, and every step from starting the server to reading a message, with links to the exact lines |
| 2 | [crypto_utils, line by line](02-crypto-utils.md) | Base64 and canonical JSON, password hashing, key pairs and the key file, the message format, TLS certificates |
| 3 | [The server, line by line](03-server.md) | The JSON database and the TLS relay server |
| 4 | [The client, line by line](04-client.md) | The TLS connection, the client logic (keys, pinning, replay list), the interactive shell and chat mode |
| 5 | [Demo and tests](05-demo-and-tests.md) | `demo.py` and the eavesdropping proxy line by line, plus what each of the 79 automated tests proves |
| 6 | [Security, integrity and privacy analysis](06-security-analysis.md) | Does the system provide them, how, against whom, and every known way it can be attacked or fail |

If you only have ten minutes, read document 1 and then document 6.

## How to read the line-by-line documents

Each piece of code is shown exactly as it appears in the source, with its real line
numbers, followed by an explanation keyed to those numbers:

```python
11  def b64e(data: bytes) -> str:
12      """Bytes -> base64 text."""
13      return base64.b64encode(data).decode("ascii")
```

- **11** — what line 11 does
- **12–13** — what lines 12 to 13 do together

Every non-blank line of the application (`crypto_utils/`, `server/`, `client/`,
`demo.py` and `tests/mitm.py`) is explained. Docstrings and comments are explained
as one range, since they describe themselves. The heading above each code block links
to those lines on GitHub.

The code shown matches the commit this documentation was added in. If the code
changes later, line numbers in these documents may drift.

## Words used throughout

| Term | Meaning here |
|---|---|
| **Plaintext** | The readable message, such as `"Hi Alice"` |
| **Ciphertext** | The scrambled bytes after encryption |
| **Key pair** | A private key (kept secret on your computer) and its public key (shared with everyone) |
| **Package** | One encrypted, signed message as it travels: ciphertext, nonce, wrapped key, metadata, signature |
| **Wrapped key** | The one-time AES key, encrypted with the recipient's RSA public key |
| **Login hash** | `scrypt(password)` computed on the client; sent instead of the password |
| **Nonce** | "Number used once": random bytes that make every encryption different |
| **Salt** | Random bytes mixed into a password hash so equal passwords hash differently |
| **Tag** | The 16-byte check value AES-GCM attaches; it fails if anything was changed |
| **Pinning** | Remembering a contact's public keys the first time, and refusing if they later change |
| **CA** | Certificate authority: the key that vouches for the server's TLS certificate |
| **Eve / Mallory** | Names for attackers: Eve is another user, Mallory is anyone on the network |
