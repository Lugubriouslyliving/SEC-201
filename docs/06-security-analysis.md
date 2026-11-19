# 6. Security, integrity and privacy analysis

[← Demo and tests](05-demo-and-tests.md) · [Index](README.md)

This document answers two questions honestly:

1. **Does the system provide security, integrity and privacy?** (Sections 6.1–6.5)
2. **How can it still be attacked or fail?** (Sections 6.6–6.8)

Claims marked **[tested]** are checked by the automated tests (document 5). Claims marked
**[verified]** were reproduced by hand during this review. Everything else follows from
reading the code, with line references.

## 6.1 Short answer

| Goal | Provided? | Main mechanisms | Main limits |
|---|---|---|---|
| **Security** (only the right people get in; secrets stay secret) | **Yes, for credentials and keys** | Client-side and server-side scrypt; constant-time comparison; generic login errors; encrypted key file; TLS 1.3 with a private CA | No rate limiting (V5); signup reveals which names exist (V4); the login hash is a password-equivalent for the server (V7) |
| **Integrity** (nothing changed; right sender; not a repeat) | **Yes, for every message that arrives** | Ed25519 signature over every field, verified first; AES-GCM tag over ciphertext and metadata; message IDs checked by server and client; TLS 1.3 | Cannot detect messages that are **withheld, deleted or delayed** (V3); first-contact key substitution (V2) |
| **Privacy** (only the recipient reads) | **Yes, for message contents. No, for metadata** | AES-256-GCM per message; AES key wrapped with the recipient's RSA-OAEP key; the server holds no private key; TLS hides everything from the network | The server sees who talks to whom, when and how much (V3, V14); messages are signed, so the sender cannot deny them (V13) |

**Overall:** message contents are well protected against the network, other users, a
curious or compromised server, and anyone who steals the server's database. The system is
**not** production-ready: the weak points are trust in public keys at first contact,
everything a malicious server can do with metadata and availability, and the lack of
rate limits.

## 6.2 Assets and attackers

**Assets**, from most to least sensitive:

1. Message plaintext
2. Users' private keys (RSA and Ed25519)
3. Passwords (often reused on other sites)
4. The ability to log in as someone
5. Metadata: who talks to whom, when, how often, how much
6. Availability: messages arriving at all

**Attackers considered:**

| Name | Who | Capabilities |
|---|---|---|
| **A1 Network attacker** (Mallory) | Same Wi-Fi, a compromised router, an internet provider | Read, record, change, drop, replay and inject network traffic; run a fake server |
| **A2 Malicious user** (Eve) | Has a normal account | Send any well-formed request, sign anything with her own key, read the user directory |
| **A3 Malicious or compromised server** | The operator, or whoever broke into the server | Read and change `db.json` and the code; log every request; deliver, drop or fake messages; hand out any public key |
| **A4 Database thief** | Got a copy of `db.json` only | Offline analysis of everything in it |
| **A5 Device thief** | Got a client's `client_data` folder | Offline analysis of `keys.json`, `known_keys.json`, `seen_ids.json` |
| **A6 Endpoint malware** | Runs code on a user's computer | Everything the user can do |

A6 defeats any messaging system (it can read the screen and the keyboard). It is listed
for completeness and not considered further.

## 6.3 Security: how it is achieved

| Protection | How | Against | Evidence |
|---|---|---|---|
| Password never leaves the client | Client sends `scrypt(password, salt = SHA-256(context ‖ username))` instead ([passwords.py:84–111](../crypto_utils/passwords.py#L84-L111)) | A1, A3, server logs | **[tested]** `test_8_server_never_receives_the_password` |
| Stored credentials useless if stolen | Server stores `scrypt(login hash, 16-byte random salt)` ([passwords.py:47–62](../crypto_utils/passwords.py#L47-L62)); sending the stored hash is just another wrong guess | A4 | **[tested]** `test_7a_stolen_hash_cannot_log_in` |
| Slow guessing | scrypt N=2^15, r=8: ≈32 MiB and ≈0.1 s per guess | A4, A5 | Parameters in [passwords.py:35–39](../crypto_utils/passwords.py#L35-L39) |
| No timing leak in comparison | `hmac.compare_digest` ([passwords.py:73](../crypto_utils/passwords.py#L73)) | A1, A2 | Code |
| Login doesn't reveal whether a user exists | Same message; dummy scrypt for unknown users ([server.py:192–199](../server/server.py#L192-L199)) | A2 | **[tested]** `test_6_login_failures_look_identical`; demo scenario 6 (113 ms vs 116 ms). *But see V4: signup does reveal it.* |
| Passwords typed in the wrong box aren't logged | Failed logins are not logged; impossible names never leave the client ([server.py:195–199](../server/server.py#L195-L199), [session.py:159–160](../client/session.py#L159-L160)) | A3 (logs) | **[tested]** `test_9_failed_logins_are_not_logged` |
| Private keys protected at rest | AES-256-GCM under `scrypt(password, random salt)` ([keys.py:60–92](../crypto_utils/keys.py#L60-L92)) | A5 | **[tested]** `test_wrong_password_cannot_unlock`, `test_file_has_no_plaintext_private_key` |
| Private keys never on the server | Generated and stored only on the client | A3, A4 | **[tested]** `test_2_…`, `test_7b_…` |
| Real server, encrypted channel | TLS 1.3 only; client trusts only the private CA and checks the host name ([tls.py:132–146](../crypto_utils/tls.py#L132-L146), [connection.py:35–48](../client/connection.py#L35-L48)) | A1 | **[tested]** all of `test_tls.py` |
| Nobody can mint new trusted certificates | CA private key discarded after one use ([tls.py:100](../crypto_utils/tls.py#L100)) | A3, A4 | **[tested]** `test_ca_private_key_is_not_kept` |
| Access control | `users`/`send`/`inbox` need a logged-in connection; `send` only as yourself ([server.py:135–136](../server/server.py#L135-L136), [server.py:239–241](../server/server.py#L239-L241)) | A2 | **[tested]** `test_6b_…`, `test_4a_…` |
| Robust input handling | Strict parsing and size limits on both sides; one bad request never affects others | A2, A1 | **[tested]** 36 tests in `test_edge_cases.py` |

## 6.4 Integrity: how it is achieved

| Property | How | Evidence |
|---|---|---|
| **The message was not changed** | Ed25519 signature over the canonical JSON of all 8 fields; any change fails ([messages.py:67–77](../crypto_utils/messages.py#L67-L77), [messages.py:170–178](../crypto_utils/messages.py#L170-L178)) | **[tested]** `test_every_signed_field_is_protected`, `test_3_…` |
| **…checked twice** | AES-GCM's 128-bit tag also covers the ciphertext and the metadata (as associated data) ([messages.py:80–89](../crypto_utils/messages.py#L80-L89)) | Demo scenario 3 (`InvalidTag`) |
| **It came from the claimed sender** | Signature checked with the sender's **pinned** key, before decrypting ([session.py:290](../client/session.py#L290)) | **[tested]** `test_4b_…` |
| **It was meant for me** | The signed `recipient` must be me ([messages.py:182–183](../crypto_utils/messages.py#L182-L183)). Alice cannot pass Bob's message on to Carol as if Bob had sent it to Carol | **[tested]** `test_message_for_someone_else_rejected` |
| **It is not a repeat** | The server accepts each message ID once; the client remembers accepted IDs on disk ([server.py:253–257](../server/server.py#L253-L257), [messages.py:186–190](../crypto_utils/messages.py#L186-L190)) | **[tested]** `test_5a_…`, `test_5b_…`, `test_5c_…` |
| **Signatures can't be reused for something else** | Context label `secure-chat/message/v1` inside every signature | Code |
| **Junk signed by a real user can't break the client** | Strict shape checks; every failure is a clean rejection ([messages.py:233–261](../crypto_utils/messages.py#L233-L261), [session.py:296–301](../client/session.py#L296-L301)) | **[tested]** `test_validly_signed_garbage_is_rejected_cleanly` |
| **Text can't fake chat lines** | `safe_display` escapes control and formatting characters ([session.py:49–66](../client/session.py#L49-L66)) | **[tested]** `test_message_cannot_fake_extra_chat_lines`; message IDs and usernames are restricted so they can't carry control characters either: `test_message_ids_must_be_hex_so_logs_cannot_be_forged`, `test_username_with_trailing_newline_is_refused` |
| **Network traffic is not changed** | TLS 1.3 authenticated encryption | **[tested]** `test_tls.py` |

**What integrity does *not* cover:** whether you received *every* message, in the right
order, on time. A signature proves what arrived is genuine; it cannot prove that something
else was not dropped (see V3).

## 6.5 Privacy: what is and is not hidden

| Data | Network attacker (A1) | Server (A3) | Database thief (A4) |
|---|---|---|---|
| Message text | hidden (TLS + E2E) | **hidden** (E2E) | hidden (E2E) |
| Password | hidden | **hidden** | hidden |
| Login hash | hidden (TLS) | **visible** (it checks it) | not stored (only `scrypt` of it) |
| Usernames, directory, public keys | hidden (TLS) | visible | visible |
| Who sent what to whom, and when | hidden (TLS) | **visible** | visible (messages are never deleted) |
| Message length | approximately (traffic volume) | visible (to the byte, +16) | visible |
| That you use the service, when and how much | **visible** (IP addresses, timing, volume) | visible (IP addresses in the log) | not stored |

Why the server cannot read messages, in one sentence: each message's AES key exists only
inside `wrapped_key`, which only the recipient's RSA private key can open, and that key was
generated on the recipient's computer and never sent anywhere.

## 6.6 Known vulnerabilities and weaknesses

| ID | Weakness | Severity | Who can exploit it | Status |
|---|---|---|---|---|
| **V1** | Message ID (and a username ending in a newline) printed unescaped in the server log and in client verbose mode | Low–Medium | A2 (any user) | **Fixed** (was **[verified]**); regression tests added |
| **V2** | Public keys are trusted on first use (TOFU) | **Medium–High** | A3, or A1 with `server.key` | Design limit; fingerprints mitigate |
| **V3** | The server sees all metadata and controls delivery | **Medium** | A3 | Design limit |
| **V4** | Signup and the directory reveal which usernames exist | Medium | A2, anyone who can sign up | **[verified]**, not fixed |
| **V5** | No rate limiting on login or signup | Medium | A1/A2 (anyone who can connect) | Not fixed |
| **V6** | Resource exhaustion (connections, storage, database growth) | Medium | A2 | Partly mitigated |
| **V7** | The login hash is a password-equivalent for the server | Medium | A3 | Design limit |
| **V8** | Offline guessing of weak passwords | Medium | A4 (if V7), A5 | Mitigated by scrypt only |
| **V9** | `server.key` stored unencrypted | Medium | Whoever reads the server's disk | Accepted risk |
| **V10** | No forward secrecy for stored messages; messages are never deleted | Low–Medium | A3/A4 plus a later key theft | Design limit |
| **V11** | Messages are marked delivered before the client confirms | Low | Accident, or A1 cutting the connection | Not fixed |
| **V12** | Local `seen_ids.json` and `known_keys.json` are not protected | Low | A5/A6 | Accepted risk |
| **V13** | No deniability: signatures prove authorship to anyone | Low (privacy) | The recipient | Design choice |
| **V14** | Message length and traffic timing leak | Low | A1, A3 | Design limit |
| **V15** | Plaintext and keys linger in memory and the terminal | Low | A6, anyone at the screen | Accepted risk |
| **V16** | No key rotation, revocation, password change or account deletion | Low | — | Missing feature |
| **V17** | Look-alike usernames (`a1ice` vs `alice`) | Low | A2 | Fingerprints mitigate |
| **V18** | `ca.crt` must reach clients safely | Low | A1 during the copy | Fingerprint mitigates |

### V1. Message ID and username injection into logs and verbose output (fixed)

**What it was:** The sender chooses `msg_id`. The server and the client only checked
that it was a string of 1–64 characters. The server then printed it as-is in its log
([server.py:254](../server/server.py#L254), [server.py:261–262](../server/server.py#L261-L262)),
and the client printed it raw in verbose traces
([session.py:291](../client/session.py#L291)).

**Attack (reproduced during this review, before the fix):** Eve sent a package whose ID
was `"x\n2026-01-01 [server] login: admin\x1b[31m"` (41 characters). The server accepted
it, and its log then contained a forged line `… [server] login: admin` and a raw
terminal escape code. Alice's verbose trace printed the same text.

**A second path of the same kind:** The username check used `re.match` with a pattern
ending in `$`. In Python's regular expressions, `$` also matches just before a final
newline, so `"alice\n"` passed and could be registered as a near-copy of `alice`,
carrying a newline into the `signup:` log line.

**Impact:** Fake log entries can mislead the operator or hide activity, and escape codes
can garble the operator's terminal. Message contents and keys were never affected, and
normal (non-verbose) chat output was already safe through `safe_display`.

**Fix (now in the code):**
- The server accepts only IDs of exactly 32 lowercase hex characters, the format
  `uuid4().hex` produces ([server.py:48](../server/server.py#L48),
  [server.py:234–235](../server/server.py#L234-L235)).
- The client applies the same rule when opening a package
  ([messages.py:252–253](../crypto_utils/messages.py#L252-L253)), so it also holds against
  a malicious server.
- The client's verbose trace passes the not-yet-validated ID through `safe_display`
  ([session.py:291](../client/session.py#L291)).
- Usernames are checked with `fullmatch` on both sides
  ([server.py:153](../server/server.py#L153), [session.py:128](../client/session.py#L128),
  [session.py:159](../client/session.py#L159)).

**Evidence:** **[tested]** `test_message_ids_must_be_hex_so_logs_cannot_be_forged` replays
the exact attack ID (and five other malformed IDs) and checks the server refuses it,
the client rejects it, and neither the server log nor the verbose trace contains a raw
newline or escape code. `test_username_with_trailing_newline_is_refused` covers the
username path. Re-running the original attack script against the fixed code: the server
refused the package, and the log stayed clean.

### V2. Trust on first use of public keys

**What:** When Bob first looks up Alice, he must trust whatever public keys the server
returns; the client pins them from then on
([session.py:220–228](../client/session.py#L220-L228)).

**Attack:** A malicious server (A3), or someone holding `server.key` (see V9), gives Bob
**its own** keys labelled "alice" the first time, and does the same to Alice for "bob".
It can then decrypt each message, read it, re-encrypt it to the real recipient and
re-sign it with its own key. Both clients accept everything, because the substituted keys
are the pinned ones. This is a full man-in-the-middle of the end-to-end layer.

**What stops it:** Only comparing fingerprints out of band. `users` and `chat` show them
([cli.py:106–107](../client/cli.py#L106-L107), [cli.py:147](../client/cli.py#L147)).
If Bob and Alice compare and they match, no substitution happened. Once pinned, a later
swap **is** detected: **[tested]**
`test_database_wiped_and_name_reregistered_by_someone_else`.

**Real-world fix:** Signal's "safety numbers", or key transparency logs, which make
substitution detectable or publicly auditable.

### V3. The server sees metadata and controls delivery

**What:** The server must know sender and recipient to route messages, and stores
packages forever ([server.py:259](../server/server.py#L259); nothing ever deletes them).

**Attacks:** A malicious server can:
- build a complete social graph: who talks to whom, when, how often, how much;
- **drop** any message, and the recipient can never know it existed;
- **delay** messages (the original timestamp is shown, but nothing warns about a delay);
- **reorder** messages (no sequence numbers);
- leave users out of the directory.

It **cannot** read, change or forge messages, or replay them to a client that has already
seen them.

**Fixes (heavy):** sealed-sender designs hide the sender from the server; padding and
cover traffic hide sizes and timing; per-conversation sequence numbers or hash chains let
clients detect gaps.

### V4. Username enumeration **[verified]**

**What:** Login carefully gives one message for "no such user" and "wrong password". But
signup answers `That username is taken.` ([server.py:171–172](../server/server.py#L171-L172)),
and any logged-in user can list every username ([server.py:210–219](../server/server.py#L210-L219)).

**Attack:** Anyone can sign up once and call `users`, or try signing up as `alice` and
read the reply. During this review, trying to sign up as an existing name returned
`That username is taken.`.

**Impact:** Attackers learn valid targets for password guessing (V5). In a directory-based
chat, listing users is a feature, so the login-error protection mainly shows good practice.

**Fix:** Invite-only signup, a directory limited to contacts, or rate limits (V5) so that
knowing a name isn't enough.

### V5. No rate limiting

**What:** Nothing limits how many logins or signups one client may attempt.

**Attack:** Online password guessing. Each server-side check costs about 0.1 s in one of
4 scrypt slots ([server.py:56](../server/server.py#L56)), so the server checks roughly
**40 guesses per second**, about 3.5 million per day, against a known username (V4). The
minimum password length is 8 with no strength check
([session.py:27](../client/session.py#L27)), so weak passwords such as `password1`
would fall quickly. Signup can also be scripted to create unlimited accounts.

**Fix:** Per-account and per-IP limits with growing delays, account lockout with alerts,
and a password strength check (for example zxcvbn) at signup.

### V6. Resource exhaustion (denial of service)

**What is already protected:** request size (1 MB), handshake time (15 s), concurrent
scrypt (4 at once), and strict parsing.

**What is not:**
- **Unlimited connections:** each one gets a thread, and after login there is no idle
  timeout ([server.py:71](../server/server.py#L71)). Thousands of open connections exhaust
  threads or memory.
- **Unlimited storage:** any user can send up to ~1 MB packages without limit, and
  delivered messages are never deleted, so the disk fills up.
- **Database rewrite:** every `send` rewrites the whole `db.json`
  ([storage.py:40–48](../server/storage.py#L40-L48)) under one lock. Cost grows with the
  database size, so a large database slows everyone down.
- **Unbounded replies:** `inbox` returns all waiting messages in one reply, and
  `seen_msg_ids` grows forever.
- **Login queue:** if many scrypt checks queue up behind the 4 slots, a client waiting more
  than 30 s gives up ([connection.py:21](../client/connection.py#L21)).

**Fix:** Connection and idle limits, per-user quotas, deleting delivered messages, a real
database (such as SQLite), and paginated inboxes.

### V7. The login hash is a password-equivalent for the server

**What:** The server receives `h = scrypt(password, salt from username)` on every login
and compares it ([server.py:185–194](../server/server.py#L185-L194)).

**Attack:** A malicious operator can log `h` and later replay it to log in as you. That
gives them your inbox (and lets them mark your messages delivered so you never see them),
but not message contents or the ability to sign as you. Because the salt is derived from
the username, they can also run an offline dictionary attack on `h` (V8), and they can
prepare guesses for a chosen username before ever seeing its hash.

**Why it is acceptable here:** A server operator can already deny service and see
metadata (V3). Hashing on the client still protects what matters most: the real password
(reused elsewhere, and the key to `keys.json`).

**Real-world fix:** A PAKE such as OPAQUE, where the server never sees anything that lets
it log in as you or test password guesses offline without its own secret.

### V8. Offline guessing of weak passwords

**What:** The same password protects the login and `keys.json`. scrypt makes each guess
cost ≈32 MiB and ≈0.1 s on a normal CPU, which slows guessing but cannot save a weak
password.

**Attack:** A device thief (A5) with `keys.json` can try passwords offline, with no rate
limit and as many machines as they like. The AES-GCM tag tells them when a guess is right.
A server operator with a logged login hash (V7) can do the same against `h`.

**Fix:** Stronger scrypt (or Argon2id) settings for the key file, a password strength
check, and optionally keeping keys in the operating system's key store.

### V9. `server.key` is stored unencrypted

**What:** [tls.py:105–107](../crypto_utils/tls.py#L105-L107) writes the TLS private key
without encryption, so the server can start unattended.

**Attack:** Whoever reads `server_data/tls/server.key` can impersonate the server to
clients. They then see login hashes (V7) and metadata, and can attempt V2 against contacts
the victims have not pinned yet. They still cannot read messages between users who
already pinned each other's real keys.

**Fix:** Restrictive file permissions, a passphrase or hardware key store, and
re-creating `server_data/tls` (and redistributing `ca.crt`) if it may have been copied.

### V10. No forward secrecy for stored messages; nothing is deleted

**What:** TLS 1.3 gives the *connection* forward secrecy, but each message's AES key is
wrapped with a long-term RSA key. The server keeps every package forever.

**Attack:** Someone who copies the database today and steals Alice's `keys.json` **and**
password next year can decrypt every message ever sent to her.

**Fix:** Delete messages after delivery, and use ephemeral key agreement per message or
session (X25519, the Double Ratchet) so old keys are destroyed.

### V11. Delivery before confirmation

**What:** `inbox` marks messages delivered as soon as it sends them
([server.py:275](../server/server.py#L275)), before the client has verified or saved them.

**Attack or accident:** If the connection drops or the client crashes right after the
server replies, those messages are never shown and never re-sent. An attacker who can cut
connections at the right moment can make messages vanish.

**Fix:** The client acknowledges message IDs after processing; the server marks them
delivered only then.

### V12. Local state is not protected

**What:** `seen_ids.json` and `known_keys.json` are plain JSON.

**Attack:** Anyone who can write to the client's folder (A5, A6) can delete a pin (so a
substituted key is accepted again, as in V2) or remove IDs (so a replay would be
accepted). Replay protection is also per device folder: a second folder for the same
user starts with no history (though it also has no keys).

**Fix:** Authenticate these files with a key derived from the password, as `keys.json`
already is.

### V13. No deniability

**What:** Every message carries Bob's Ed25519 signature over its content.

**Privacy impact:** Alice (or anyone she gives the package and Bob's public key to) can
prove to a third party that Bob wrote it. Private conversations in protocols such as
Signal deliberately avoid this by authenticating with shared keys instead of signatures.

### V14. Length and traffic analysis

**What:** AES-GCM ciphertext is exactly the plaintext's UTF-8 length plus 16 bytes. Chat
mode polls once a second.

**Attack:** The server knows exact message sizes. A network observer sees TLS record
sizes and timing, enough to tell when someone is actively chatting and roughly how long
the messages are.

**Fix:** Pad messages to fixed size buckets; add cover traffic.

### V15. Secrets in memory and on screen

**What:** Python cannot reliably wipe strings or keys from memory. Decrypted text stays in
the terminal's scrollback, and `verbose on` prints plaintext.

**Attack:** Malware, a memory dump, the operating system's swap file, or someone looking
at an unlocked screen.

**Fix:** Mostly outside the app's control. Clear the terminal (`cls`), lock the screen,
and leave verbose mode off on shared computers.

### V16. No key rotation, revocation, password change or account deletion

If a private key or password is compromised, there is no way to replace the keys under the
same name, warn contacts, change the password, or delete the account. The name stays bound
to the old keys forever.

### V17. Look-alike usernames

Eve can register `a1ice` or `alice_` and hope Bob picks the wrong name. Usernames are
restricted to `a-z 0-9 _`, which removes Unicode look-alikes, but simple substitutions
remain. Comparing fingerprints catches this too.

### V18. Distributing `ca.crt`

The whole TLS trust rests on the client having the genuine `ca.crt`. If an attacker swaps
it while it is being copied, they can impersonate the server (as in V9). Compare the
fingerprint the server prints at start-up with the file you copied.

## 6.7 Attacks that do not work

Equally important to know what the design stops:

| Attack | Why it fails | Evidence |
|---|---|---|
| Read messages by sniffing the network | TLS 1.3, and end-to-end encryption inside it | **[tested]** `test_eavesdropper_sees_nothing_useful` |
| Replay recorded network traffic | TLS 1.3 uses fresh keys for every connection | **[tested]** `test_replaying_recorded_traffic_logs_nobody_in` |
| Pose as the server with any other certificate | Client trusts only the private CA and checks the host name | **[tested]** `test_fake_server_…`, `test_certificate_for_another_host_…` |
| Force an older TLS version | TLS 1.3 minimum on both sides | **[tested]** `test_old_tls_versions_are_refused` |
| Change one bit of a message | Signature fails; GCM tag fails too | **[tested]** `test_3_…`, `test_every_signed_field_is_protected` |
| Eve signs as Bob | Signature checked with Bob's pinned key | **[tested]** `test_4b_…` |
| Resend an old message | Server and client both track IDs | **[tested]** `test_5a_…`, `test_5b_…`, `test_5c_…` |
| Log in with a stolen database hash | The server hashes it again; it never matches | **[tested]** `test_7a_…` |
| Read stolen stored messages | No private key exists on the server | **[tested]** `test_7b_…` |
| Learn the password from the server or its log | Only the login hash is sent; failed logins aren't logged | **[tested]** `test_8_…`, `test_9_…` |
| Tell existing users apart by login timing | Dummy scrypt for unknown users; constant-time comparison | Demo scenario 6 (but see V4) |
| Crash a client with signed junk | Strict parsing; every failure is a clean rejection | **[tested]** `test_validly_signed_garbage_is_rejected_cleanly` |
| Fake chat lines with newlines or escape codes | `safe_display` | **[tested]** `test_message_cannot_fake_extra_chat_lines` |
| Crash the server with malformed input | Every request is parsed defensively; errors are per-request | **[tested]** `test_garbage_inputs` and 7 more |
| Forge server log lines through a message ID or username | IDs must be 32 hex characters; usernames must fully match `[a-z0-9_]{3,20}` | **[tested]** `test_message_ids_must_be_hex_so_logs_cannot_be_forged`, `test_username_with_trailing_newline_is_refused` |
| AES-GCM nonce reuse | A fresh random key for every message, so key + nonce never repeat | [messages.py:108–109](../crypto_utils/messages.py#L108-L109) |
| Padding-oracle attacks on RSA | OAEP padding; and the recipient's accept/reject decision is never sent back to anyone, so there is no oracle to query | [messages.py:52](../crypto_utils/messages.py#L52) |
| Pass Bob's message to Carol as if it were for her | `recipient` is signed and checked | **[tested]** `test_message_for_someone_else_rejected` |

## 6.8 Recommended fixes, in priority order

| Priority | Fix | Addresses | Effort |
|---|---|---|---|
| ✓ | ~~Accept only 32-hex-character message IDs; `fullmatch` for usernames~~ **Done** | V1 | Small |
| 2 | Rate-limit login and signup per IP and per account; add a password strength check | V5, V8 | Small–medium |
| 3 | Make fingerprint checking part of the flow (e.g. a `verify <name>` command that marks a contact as verified) | V2 | Small |
| 4 | Client acknowledgements; delete delivered messages | V11, V10, V6 | Medium |
| 5 | Connection, idle-time and storage quotas; move to SQLite | V6 | Medium |
| 6 | Authenticate `seen_ids.json` and `known_keys.json` with a password-derived key | V12 | Small |
| 7 | Restrict `server.key` permissions; document key rotation | V9, V16 | Small |
| 8 | Message padding | V14 | Small |
| 9 | Forward-secret messaging (X25519 + ratchet) | V10, V13 | Large |
| 10 | Password-authenticated key exchange (OPAQUE) | V7 | Large |
