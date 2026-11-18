# Secure Chat: a teaching demo of security, privacy and integrity

A command-line chat where messages go from sender to receiver through a central
server, and the server can never read them. Each message is:

- **encrypted** with AES-256-GCM, so only the recipient can read it,
- **signed** with Ed25519, so the recipient knows who sent it and that nobody changed it,
- **unique**, with a random message ID, so an old message cannot be replayed.

Passwords never leave the user's computer: the client sends a scrypt hash, and the
server stores that only after salting and hashing it again. Private keys never leave
the user's computer and are encrypted on disk with a key derived from the password.
The whole client-server connection runs over TLS 1.3, and the client accepts only
the server's own certificate.

Every algorithm comes from the Python [`cryptography`](https://cryptography.io)
library. Nothing cryptographic is written by hand.

---

## Contents

1. [Setup (Windows PowerShell)](#1-setup-windows-powershell)
2. [Using the chat](#2-using-the-chat)
3. [Running the demo and tests](#3-running-the-demo-and-tests)
4. [How a message travels: Bob sends to Alice](#4-how-a-message-travels-bob-sends-to-alice)
5. [Mapping to security goals](#5-mapping-to-security-goals)
6. [Protocol](#6-protocol)
7. [Threat model](#7-threat-model)
8. [Design decisions in plain language](#8-design-decisions-in-plain-language)
9. [Project layout](#9-project-layout)

---

## 1. Setup (Windows PowerShell)

You need Python 3.10 or newer. Open PowerShell in this folder.

```powershell
py -m venv .venv
```

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell refuses to run the activate script, allow local scripts for your user once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

```powershell
pip install -r requirements.txt
```

All commands below are run from this folder (the one holding `README.md`).

## 2. Using the chat

**Window 1, start the server:**

```powershell
py -m server.server --port 5050
```

The server writes its database to `server_data\db.json`. On its first start it also
creates its TLS certificates in `server_data\tls\` and prints the fingerprint of
`ca.crt`. Clients started from this same folder find `ca.crt` automatically.

**Window 2, Alice's client.** Each user gets their own `--data` folder, standing in
for their own computer:

```powershell
py -m client.cli --port 5050 --data client_data\alice
```

**Window 3, Bob's client:**

```powershell
py -m client.cli --port 5050 --data client_data\bob
```

Each client starts with `Connected securely (TLSv1.3, …); server identity verified.`

**Chatting between two computers.** On the server computer, listen on the network
and put the name or IP address clients will use into the certificate. Do this on the
first start, or delete `server_data\tls` first so new certificates are made:

```powershell
py -m server.server --host 0.0.0.0 --hostname 192.168.1.20
```

Copy `server_data\tls\ca.crt` (only that file, never `server.key`) to the other
computer, for example on a USB stick, and point the client at it:

```powershell
py -m client.cli --host 192.168.1.20 --ca C:\path\to\ca.crt --data client_data\bob
```

The client refuses to connect if the server's certificate was not issued by that CA
for that address, so nobody on the network can pose as the server.

Then sign up in each window and start chatting:

```text
(not logged in) > signup alice          # in Alice's window; asks for a password twice
(not logged in) > signup bob            # in Bob's window
(bob) > users                           # list users and their key fingerprints
(bob) > chat alice                      # in Bob's window
(alice) > chat bob                      # in Alice's window
```

Inside `chat`, just type and press Enter. The other person's messages appear by
themselves as they arrive (the client checks for new messages every second, and
verifies and decrypts each one before showing it):

```text
--- Chat with alice ---
    alice's key fingerprint: E448 7A25 635F B825 D308 5F2D 9020 ACE3
    Every message is encrypted for them and signed by you. Type /exit to leave.

bob> hi alice, meeting moved to 3pm
[15:02] alice: ok, see you then
bob> /exit
--- Left chat with alice ---
```

Next time, use `login alice` instead of `signup`. Messages sent while you were away
show up when you open the chat (or with `inbox`).

| Command | What it does |
|---|---|
| `signup <username>` | Makes two key pairs on this computer, sends only the public keys and a hash of the password to the server, saves the private keys encrypted. |
| `login <username>` | Sends a hash of the password for the server to check; the client unlocks the private keys with the password locally. |
| `users` | Lists other users with a fingerprint of their public keys. |
| `chat <username>` | Live conversation. Type to send; incoming messages appear as they arrive. `/exit` leaves. |
| `send <recipient> <message>` | Encrypts, signs, and sends a single message. |
| `inbox` | Fetches new messages; verifies each signature, then decrypts. |
| `verbose on` / `verbose off` | Show or hide each crypto step. |
| `logout`, `quit` | |

Passwords are typed with `getpass`, so they are not shown on screen.

## 3. Running the demo and tests

**Guided demo**, eight scenarios with each step printed (the seven required ones
plus a network eavesdropper):

```powershell
py demo.py
```

For presenting, pause between scenarios:

```powershell
py demo.py --pause
```

The demo starts its own server on a free port with a temporary database and deletes
it at the end, so it does not touch `server_data` or `client_data`.

**Automated tests** (68 tests, about 70 seconds):

```powershell
py -m unittest -v
```

The tests are in three files:

- `tests/test_security.py` (25 tests) checks that each protection works: the seven
  scenarios below, unit tests of the crypto code, and two password checks: every
  request the server receives during signup and login is recorded and searched for
  the real password (never found), and failed logins leave nothing in the server log.
- `tests/test_tls.py` (9 tests) plays a network attacker:

| Attack | Result |
|---|---|
| Record every byte of signup, login, user list and a message through a proxy (`tests/mitm.py`) | None of the password, login hash, usernames, field names, public keys or message text appear in the recording |
| Replay the recorded login bytes to the server | Not a single request reaches the application |
| Run a complete fake chat server with a certificate from the attacker's own CA | Client refuses with a security warning before sending anything |
| Certificate issued for a different host name | Refused |
| A server that does not speak TLS | Refused; only a TLS greeting was sent |
| Connect with TLS 1.2 | Refused; TLS 1.3 only |
| Missing or junk `ca.crt` | Clear error |
| The CA's private key | Not stored anywhere |

- `tests/test_edge_cases.py` (34 tests) checks that the app keeps working under
  extreme or hostile conditions:

| Area | What is thrown at it |
|---|---|
| Protocol abuse | Non-JSON, invalid UTF-8, arrays, `null`, 100,000-level nesting, `NaN`, unknown/list/object actions, missing or wrong-typed fields, requests over 1 MB, 200 requests on one connection, half-sent requests and half-finished TLS handshakes then disconnects, plain-text JSON sent to the TLS port, a client that connects and says nothing (dropped after the handshake timeout). The server answers or drops each one and keeps serving. |
| Fake keys | Signing up with junk "PEM" text, a list, a number, or the wrong key type in each slot. Refused. |
| Absurd packages | Timestamps of 10³⁰⁰, −1, `true`, a float; 10,000-character message IDs; list recipients. Refused. |
| Hostile senders | A real user signs packages with junk inside (invalid base64, wrong sizes, ciphertext that decrypts to invalid UTF-8). The recipient rejects each one cleanly and keeps chatting. |
| Display injection | A message containing a newline plus a fake `[12:00] bob:` line and terminal escape codes. Shown as visible `\n` / `\x1b`, so it cannot fake a line or clear the screen. |
| Message content | Thai, emoji, Arabic, Japanese, NUL bytes, tabs, a single space; the maximum size (20,000 Thai characters); one character over the limit (refused before sending). |
| Accounts | Invalid usernames and short passwords (refused instantly, before key generation), duplicates, 1,024-character and Thai/emoji passwords, a 500,000-character password over the raw protocol. |
| Local files | Damaged or empty key file (clear error), damaged pinned-keys and seen-IDs files (moved aside, chat continues), logging in from a device without keys. |
| Load | 10 users each sending 20 messages at the same moment (all 200 arrive exactly once, database stays valid); 20 simultaneous logins; chat-mode polling and sending on one connection. |
| Failures | Server killed mid-session (client says so clearly, no crash); restart (messages and replay list survive); sender's clock an hour off (clear "check your clock" error); database wiped and an impostor registers the same name (pinned keys refuse the impostor). |

What each required scenario looks like, and where it is tested:

| # | Scenario | What happens | Demo section | Tests |
|---|---|---|---|---|
| 1 | Bob → Alice succeeds | Each step printed: encrypt, wrap key, sign, transmit, verify, replay check, unwrap, decrypt | 1 | `test_1_bob_to_alice` |
| 2 | Server view | Prints the stored user record and message. The plaintext and passwords appear nowhere in the database | 2 | `test_2_server_stores_only_ciphertext` |
| 3 | Tampering | One byte of ciphertext flipped after signing. Server cannot notice; Alice rejects: invalid signature. Demo also shows AES-GCM's tag catches it on its own | 3 | `test_3_…`, `test_every_signed_field_is_protected` |
| 4 | Wrong signer | Eve signs a message with `sender: "bob"`. The server refuses it (Eve is logged in as eve). Then Eve plants it directly in the database, as a compromised server could; Alice still rejects it | 4 | `test_4a_…`, `test_4b_…` |
| 5 | Replay | Resending a captured message: the server rejects the duplicate ID. If a malicious server redelivers it anyway, Alice's client rejects it too, even after a restart | 5 | `test_5a_…`, `test_5b_…`, `test_5c_…` |
| 6 | Wrong password | Wrong password and unknown username give the identical message `Invalid username or password.` and take about the same time | 6 | `test_6_login_failures_look_identical` |
| 7 | Database leak | Logging in with the stolen hash/salt fails. The stolen messages cannot be opened with any key but Alice's, and the database has no private keys | 7 | `test_7a_…`, `test_7b_…` |
| 8 | Eavesdropper (extra) | A spy records Bob's login and message: no password, login hash, name or text in the bytes. Then the spy poses as the server with its own certificate: Bob's client refuses | 8 | `tests/test_tls.py` |

## 4. How a message travels: Bob sends to Alice

```text
 BOB'S COMPUTER                     SERVER                         ALICE'S COMPUTER
 ──────────────                     ──────                         ────────────────
 h = scrypt(password,
      salt from username)
 login  ───── username + h ───────▶ scrypt(h, random salt)
   (password never sent)            == stored hash? (constant time)
 users  ◀──── alice's public keys ── (public keys only)

 1 aes_key = 32 random bytes
   nonce   = 12 random bytes
   ct = AES-256-GCM(aes_key, nonce,
        plaintext, aad = metadata)
 2 wrapped = RSA-OAEP(alice_pub,
                      aes_key)
 3 sig = Ed25519(bob_priv,
        version, msg_id, sender,
        recipient, timestamp,
        nonce, ct, wrapped)
 4 send ───────── package ────────▶ checks: logged-in user == sender,
                                    msg_id never seen, timestamp fresh
                                    stores package AS IS
                                    (cannot decrypt: no private keys)
                                                       inbox ◀──── login + inbox
                                    ──────── package ─────────────▶
                                                                    5 verify sig with bob_pub
                                                                      FIRST. Bad → reject.
                                                                    6 msg_id seen before?
                                                                      → reject (replay)
                                                                    7 aes_key = RSA-OAEP-
                                                                      decrypt(alice_priv)
                                                                    8 plaintext = AES-GCM-
                                                                      decrypt; tag must verify
                                                                    9 display
```

The code for steps 1-3 is `encrypt_and_sign` and for steps 5-8 is
`verify_and_decrypt`, both in [crypto_utils/messages.py](crypto_utils/messages.py).

## 5. Mapping to security goals

### Security (access control and secrets at rest)

- **The password never leaves your computer.** The client sends a *login hash*
  instead: `h = scrypt(password, salt = SHA-256("secure-chat/login-hash/v1:" + username))`.
  The server, its log and anyone watching the network never see the password itself.
- **Passwords are hashed and salted (again) on the server.** The server stores
  `scrypt(h, salt)` with a fresh 16-byte random salt per user. Login recomputes it and
  compares with `hmac.compare_digest`, which takes the same time wherever the bytes
  differ. The server refuses anything that is not a proper 32-byte login hash, so it
  can never end up storing a plain password.
- **Nothing about failed logins is logged.** A failed login's "username" is whatever
  was typed, and people sometimes type their password into that box. The server log
  records only successful logins and signups.
- **Private keys are protected at rest.** Each client stores its private keys
  encrypted with AES-256-GCM under a key derived from the password by scrypt with its
  own salt. A stolen laptop gives the thief an encrypted file, not keys.
- **Access requires login.** `users`, `send` and `inbox` are refused until the
  connection has logged in, and a user can only send as themselves.
- **Login failures reveal nothing.** Wrong password and unknown user get the same
  message, and the server runs scrypt once even for unknown users so timing matches.

### Privacy (only the recipient can read)

- Each message is encrypted with a new random AES-256 key, and that key is encrypted
  ("wrapped") with the recipient's RSA public key. Only the recipient's private key
  unwraps it.
- The server stores and forwards ciphertext only. It holds no private key, so it
  could not decrypt even if it wanted to.

### Integrity (nothing changed, right sender, not a repeat)

- **Digital signatures prove who sent a message.** The sender signs every field of
  the package with their Ed25519 private key. Change any byte, or sign with the wrong
  key, and verification fails.
- **AES-GCM detects modification** independently: its 128-bit tag covers the
  ciphertext and the metadata (passed as associated data).
- **Message IDs and timestamps stop replays.** Each message has a random 128-bit ID.
  The server accepts an ID once, and the recipient's client remembers every ID it has
  accepted (saved to disk), so a replay is caught even if the server is malicious. The
  server also refuses packages whose timestamp is more than 5 minutes off.

## 6. Protocol

**Transport:** TLS 1.3 over TCP (older TLS versions are refused). The client trusts
only the server's private CA (`server_data\tls\ca.crt`), not the computer's usual
list of public CAs, and checks the certificate matches the host name it connected
to. Inside TLS, each request and each response is one JSON object on one line,
UTF-8, ending in `\n`. The client sends a request and waits for exactly one response.
One TLS connection is one session: after `login` succeeds, that connection is
"logged in" until `logout` or disconnect. Requests over 1 MB are refused, and a new
connection has 15 seconds to finish the TLS handshake.

The certificate files, made by `crypto_utils/tls.py` on the server's first start:

| File | What it is | Where it goes |
|---|---|---|
| `ca.crt` | The private certificate authority (ECDSA P-256), valid 10 years | Copied to every client |
| `server.crt` | The server's certificate, signed by the CA, for `localhost`, `127.0.0.1`, `::1` plus any `--hostname` | Stays on the server |
| `server.key` | The server's TLS private key | Stays on the server, never copied |

The CA's private key signs `server.crt` once and is then discarded, never written
to disk.

All binary values (keys, nonces, ciphertext, signatures) are base64. Public keys are
PEM text.

Every response has `"ok": true` or `"ok": false, "error": "<message>"`.

| Request | Needs login | Success response |
|---|---|---|
| `{"action":"signup","username":"alice","password_hash":"…","enc_public_pem":"…","sign_public_pem":"…"}` | no | `{"ok":true,"username":"alice"}` (also logs in) |
| `{"action":"login","username":"alice","password_hash":"…"}` | no | `{"ok":true,"username":"alice"}` |
| `{"action":"users"}` (optional `"include_self":true`) | yes | `{"ok":true,"users":[{"username":"bob","enc_public_pem":"…","sign_public_pem":"…"}]}` |
| `{"action":"send","package":{…}}` | yes | `{"ok":true,"msg_id":"…"}` |
| `{"action":"inbox"}` | yes | `{"ok":true,"messages":[{…package…}]}` (undelivered ones, then marked delivered) |
| `{"action":"logout"}` | no | `{"ok":true}` |

`password_hash` is the client's login hash: base64 of the 32-byte
`scrypt(password, salt = SHA-256("secure-chat/login-hash/v1:" + username))`, with
n=2^15, r=8, p=1. The server refuses anything else.

Rules: usernames are 3-20 characters of `a-z 0-9 _`; passwords 8-1,024 characters
(checked by the client, since the server never sees the password);
public keys must parse as an RSA key of at least 2048 bits and an Ed25519 key;
messages up to 20,000 characters (checked by the client). Any malformed request gets
an `"ok": false` reply; the server never crashes or drops other users because of one.

**The message package:**

```json
{
  "version": 1,
  "msg_id": "275e54a6120841e8a05b542925641cc5",
  "sender": "bob",
  "recipient": "alice",
  "timestamp": 1795014802,
  "nonce": "waLqXJhlowvxagAI",
  "ciphertext": "yAb7I2pSl9DfuBLkaVBbEbeqgUh7nxP5…",
  "wrapped_key": "bofIyFMcD5C2CJXRYELx0LqUyDmNQY9a…",
  "signature": "2pQ3OxA95ZfsvxGo5cG+Q8NzGdwq7Pww…"
}
```

- `ciphertext` = AES-256-GCM output, with the 16-byte tag at the end. Associated data:
  canonical JSON of `{v, msg_id, sender, recipient, timestamp}`.
- `wrapped_key` = RSA-OAEP (SHA-256, MGF1-SHA-256) encryption of the 32-byte AES key.
- `signature` = Ed25519 over the canonical JSON of every other field plus
  `"context": "secure-chat/message/v1"`. Canonical JSON means keys sorted, no spaces,
  ASCII only, so both sides produce the same bytes.

**Server checks on `send`:** all fields present; `sender` equals the logged-in user;
recipient exists; `msg_id` never seen; `timestamp` within 5 minutes of server time.
The server does **not** check the signature or decrypt anything; that is the
recipient's job, because the recipient should not have to trust the server.

## 7. Threat model

**Who we defend against**

| Attacker | What they can do | What protects you |
|---|---|---|
| Someone on the network | Read, record, change or replay traffic; pose as the server | TLS 1.3: they see only encrypted bytes (no password, login hash, names or envelopes) and cannot replay them. A fake server is refused because its certificate is not from our CA. Message contents are additionally end-to-end encrypted and signed |
| The server operator, or someone who hacked the server | Read the whole database, change it, add or redeliver messages | Cannot read messages (no private keys). Cannot forge or change them (signatures). Replays caught by the client's message ID list |
| Someone who steals the database | Has hashes, salts, public keys, ciphertext | Hashes cannot be used to log in; guessing passwords is slow (scrypt). Messages unreadable |
| Another user (Eve) | Sign up, send messages, pretend to be someone else | Server refuses `sender` ≠ logged-in user; even if bypassed, the signature check fails |
| Someone who steals a laptop's key file | Has the encrypted `keys.json` | Must guess the password; each guess costs a scrypt computation |

**What is NOT protected (honest limits)**

- **Metadata is visible to the server:** who talks to whom, when, how often, and
  roughly how long each message is (AES-GCM does not hide length). Hiding this needs
  much heavier designs (mixnets, padding, onion routing).
- **TLS is only as good as how `ca.crt` reaches the client.** If an attacker can swap
  the `ca.crt` file you copy to a client, they can pose as the server. Copy it over a
  channel you trust (USB stick, in person) and compare the fingerprint the server
  prints at start-up.
- **`server.key` is stored unencrypted** so the server can start without someone
  typing a passphrase. Anyone who can read the server's folder can impersonate the
  server on the network. (They still cannot read messages: those need the users'
  private keys.) Protect the server computer, and delete `server_data\tls` to make
  new certificates if it may have been copied.
- **The login hash is a password-equivalent for the server.** TLS keeps it off the
  network, but if malware on your computer or a malicious server operator captured it,
  they could log in as you. They still could not read or sign your messages.
- **Network observers still see traffic shape:** that your computer talks to the
  server, when, and roughly how much. TLS hides content, not timing and volume.
- **Trusting public keys.** The client gets public keys from the server. A malicious
  server could hand out its own key the *first* time you look someone up. The client
  pins each key the first time it sees it ("trust on first use") and refuses if the
  server later changes it, and `users` shows a fingerprint that two people can compare
  in person. Without that comparison, the very first lookup is trusted blindly.
- **No forward secrecy for stored messages.** TLS 1.3 gives the *connection* forward
  secrecy, so recorded network traffic stays unreadable even if a key leaks later.
  But the server keeps the end-to-end encrypted packages, and if Alice's private key
  and password are stolen later, those stored copies can be decrypted. Protocols like
  Signal fix this with short-lived keys (the Double Ratchet); that is beyond this demo.
- **Compromised endpoint.** Malware on Alice's or Bob's computer sees plaintext. No
  encryption helps there.
- **No login rate limiting or account lockout**, and no "forgot password": losing the
  password means losing the private keys and the ability to read messages.
- **Denial of service:** the server can delete or withhold messages. Signatures prove
  what *arrived* is genuine; they cannot prove something *didn't* arrive. The server
  also has no limit on the number of open connections or on idle time after login, so
  a flood of connections could exhaust it. (It does limit request size to 1 MB,
  passwords to 1,024 characters and the TLS handshake to 15 seconds, and runs at most
  4 scrypt computations at once so a burst of logins cannot exhaust memory.)
- **Scale:** the server rewrites its whole JSON database on every message. That is
  fine for a classroom (thousands of messages) but not for real traffic, which would
  need a proper database.
- **Same account in two windows at once:** each new message is delivered to whichever
  session checks first, so the other window does not see it. Use one window per user.
- **No reconnect:** if the server restarts, clients say the connection was lost and
  must be started again.
- **Replay window on the client:** seen IDs are kept per device folder. A fresh device
  for the same user has no history (and also no keys, since keys live on the original
  device).

## 8. Design decisions in plain language

**Why hybrid encryption (AES + RSA) instead of only RSA?**
RSA can only encrypt something smaller than its key (about 300 bytes here) and is
slow. AES is fast and works on any length. So AES encrypts the message, and RSA only
encrypts the 32-byte AES key. Every serious system (TLS, PGP, Signal) works this way.

**Why AES-256-GCM?**
GCM is "authenticated encryption": it encrypts *and* produces a tag that detects any
change. Older modes (like CBC) only encrypt; changing the ciphertext silently changes
the plaintext. 256-bit keys are the strongest standard size.

**Why a fresh key and a fresh random 96-bit nonce per message?**
GCM breaks badly if the same key and nonce are ever used twice. A new random key per
message makes that impossible in practice. 96 bits is the nonce size GCM is designed
for.

**Why put the metadata in GCM's "associated data"?**
Associated data is not encrypted but *is* covered by the tag. So a ciphertext only
decrypts under its own sender, recipient, ID and time. It is a second lock behind the
signature.

**Why RSA-OAEP with SHA-256, 3072-bit keys?**
OAEP is the safe padding for RSA encryption; the older "PKCS#1 v1.5" padding has
known attacks. 3072 bits gives about 128-bit security, matching current guidance.

**Why Ed25519 for signatures, and separate keys for signing and encrypting?**
Ed25519 is fast, has small keys and signatures (64 bytes), and has no tricky
parameters to get wrong. Using one key pair per job means a problem in one use cannot
spill into the other.

**Why sign *everything*, and verify *first*?**
If the signature covered only the ciphertext, an attacker could swap the wrapped key,
change the recipient, or change the time. Signing every field binds them together.
Verifying before anything else means unauthenticated data never reaches the
decryption code, and the user gets one clear answer: "not from Bob, rejected".

**Why a "context" label inside the signed data?**
It makes the signature mean "this is a secure-chat v1 message". A signature made for
any other purpose can never be passed off as a message signature.

**Why canonical JSON?**
A signature is over exact bytes. JSON allows the same data in many byte forms (key
order, spaces). Sorting keys and fixing separators gives one form both sides agree on.

**Why scrypt for passwords, instead of SHA-256?**
SHA-256 is designed to be fast, so an attacker with a stolen database can try billions
of guesses per second. scrypt is designed to be slow *and* memory-hungry (about 32 MiB
per guess here), which makes mass guessing on GPUs expensive. Its parameters are
saved with each hash so they can be raised later.

**Why a random salt per user?**
Without salts, everyone with password `123456` has the same hash: crack one, crack
all, and precomputed tables work. A unique salt makes each hash a separate problem.

**Why constant-time comparison?**
A normal `==` stops at the first different byte, so it answers slightly faster the
earlier the mismatch is. An attacker measuring response times could use that.
`hmac.compare_digest` always takes the same time.

**Why the same error for "wrong password" and "no such user"?**
Different errors let an attacker find out which usernames exist, then focus on them.
One generic error, plus running scrypt even for unknown users, removes that clue.

**Why TLS, when messages are already end-to-end encrypted?**
The two layers protect different things. End-to-end encryption protects message
*contents* from everyone, including the server. TLS protects the *connection*: the
login hash (which an eavesdropper could otherwise replay to log in as you), usernames,
the user list, and who sends to whom. TLS also proves to the client it reached the
real server, which the end-to-end layer cannot do. Real messengers use both.

**Why TLS 1.3 only?**
TLS 1.3 removed the old, weak options: every connection uses a fresh key exchange
(forward secrecy, which is also why replaying recorded bytes fails) and authenticated
encryption. Allowing older versions would let an attacker try to push the connection
down to them.

**Why our own small certificate authority instead of a public one?**
A public CA (like the ones websites use) needs a domain name and an internet-facing
server; a classroom chat on `localhost` or a home network has neither. A private CA
lets the server make its certificate on first start. The client trusts *only* this CA,
not the hundreds of public CAs a computer normally trusts, so no outside certificate,
however genuine, is accepted for this server.

**Why throw away the CA's private key?**
Whoever holds it can issue certificates that every client accepts. After it signs the
server's certificate once, nothing needs it, so it is never saved. A thief who copies
the server's folder therefore cannot mint new trusted certificates (though they can
use `server.key` itself; see the threat model).

**Why check the host name in the certificate?**
Otherwise any certificate from our CA would do for any address. Checking the name
means the certificate only works for the server it was made for.

**Why hash the password on the client before sending it?**
So the password itself never travels and the server never knows it. That matters for
three reasons: people reuse passwords on other sites; the same password unlocks your
private-key file, so a server that knew it could open that file if it ever got a copy;
and a log line or a debugging print on the server cannot leak what it never received.

**Why use the username as the client-side salt?**
The client must produce the same hash on any computer, before talking to the server,
so it cannot use a random salt it would have to look up. The username is unique per
user, so it still stops one precomputed table from attacking everyone. The fixed
"secure-chat/login-hash/v1" label keeps the hash unrelated to any other use of the
password. The real random salt is added by the server's second scrypt.

**Why hash again on the server?**
If the server stored the login hash directly, a stolen database would contain exactly
what you need to log in. Hashing it again with a random salt means the database holds
`scrypt(h)`, which is useless for logging in.

**Why a separate salt for the key file?**
The login hash and the client's key-file key are both derived from the same password.
Different salts (one from the username, one random and stored in the key file) make
them unrelated, so the login hash says nothing about the key that protects your
private keys.

**Why check replays in two places?**
The server rejecting duplicate IDs stops most replays early. But the server is not
trusted, so the client also remembers every ID it accepted. The client check is the
one that actually guarantees it.

**Why does the server check the sender, if signatures already prove it?**
Defence in depth: honest servers should stop obvious impersonation early. But the
client never relies on it.

**Why key pinning and fingerprints?**
Encryption is only as good as the public key you encrypt to. Pinning stops the server
from silently swapping keys after the first contact; fingerprints let users close the
gap for the first contact too.

**Why a plain JSON file for the server's database?**
So that you can open it and see for yourself what the server knows. A real system
would use a proper database.

## 9. Project layout

```text
secure-chat/
├── client/
│   ├── cli.py          interactive shell (signup, login, users, chat, send, inbox, logout)
│   ├── session.py      key files, key pinning, replay list, send/receive logic
│   └── connection.py   JSON-over-TLS connection, server certificate check
├── server/
│   ├── server.py       threaded TLS server, accounts, store-and-forward
│   └── storage.py      JSON database with atomic writes
├── crypto_utils/
│   ├── passwords.py    client login hash + server scrypt hashing + constant-time verify
│   ├── keys.py         RSA/Ed25519 key pairs, encrypted key file, fingerprints
│   ├── messages.py     encrypt_and_sign / verify_and_decrypt
│   ├── tls.py          private CA + server certificate, TLS 1.3 settings
│   └── encoding.py     base64 and canonical JSON
├── tests/
│   ├── test_security.py    25 tests: each protection (unit + end-to-end over real sockets)
│   ├── test_edge_cases.py  34 tests: hostile input, extreme values, load, crashes, restarts
│   ├── test_tls.py         9 tests: eavesdropping, replay, fake servers, TLS versions
│   └── mitm.py             recording proxy used as the "eavesdropper"
├── demo.py             guided demonstration of all eight scenarios
├── requirements.txt
└── README.md
```
