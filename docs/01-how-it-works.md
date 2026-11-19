# 1. How the system works, step by step

[← Index](README.md) · Next: [crypto_utils, line by line →](02-crypto-utils.md)

This document follows a message from the moment the server starts until Alice reads
what Bob wrote. Every step links to the exact lines that do it, and documents 2–4
explain those lines one by one.

## 1.1 The parts

```text
 ┌──────────────── Bob's computer ────────────────┐                 ┌──────────────── Alice's computer ──────────────┐
 │ client/cli.py      the shell Bob types into    │                 │ client/cli.py                                  │
 │ client/session.py  keys, pinning, send/receive │                 │ client/session.py                              │
 │ crypto_utils/      AES-GCM, RSA-OAEP, Ed25519, │                 │ crypto_utils/                                  │
 │                    scrypt                      │                 │                                                │
 │ client/connection.py  TLS 1.3 socket           │                 │ client/connection.py                           │
 │ client_data/bob/   keys.json (encrypted),      │                 │ client_data/alice/  keys.json, seen_ids.json,  │
 │                    seen_ids.json,              │                 │                     known_keys.json            │
 │                    known_keys.json             │                 │                                                │
 └───────────────────────┬────────────────────────┘                 └────────────────────────┬───────────────────────┘
                         │ TLS 1.3                                                           │ TLS 1.3
                         │ (JSON lines inside)                                               │
                         ▼                                                                   ▼
                 ┌────────────────────────── The server ───────────────────────────────────────┐
                 │ server/server.py   accepts TLS connections, checks logins, relays packages  │
                 │ server/storage.py  server_data/db.json: users (hash + public keys),         │
                 │                    messages (encrypted packages), seen message IDs          │
                 │ server_data/tls/   ca.crt (given to clients), server.crt, server.key        │
                 └─────────────────────────────────────────────────────────────────────────────┘
```

**Two layers of protection, on purpose:**

1. **TLS 1.3** protects each *connection* between a client and the server: nobody on
   the network can read or change what passes, and the client knows it reached the
   real server.
2. **End-to-end encryption and signatures** protect each *message* from Bob all the way
   to Alice, including from the server itself. The server holds no private key and
   could not read a message even if it wanted to.

TLS ends at the server. The end-to-end layer goes through the server untouched.

## 1.2 Who knows what

| Information | Bob's client | Network (Mallory) | Server | Alice's client |
|---|---|---|---|---|
| Bob's password | yes (typed) | no | **no** | no |
| Bob's login hash | yes | no (inside TLS) | yes (it checks it) | no |
| Bob's private keys | yes (encrypted on disk) | no | **no** | no |
| Bob's public keys | yes | no (inside TLS) | yes | yes |
| Message text | yes | no | **no** | yes |
| Who sends to whom, when, size | yes | that Bob and Alice each talk to the server, when and how much | **yes** | yes |

The bold "no"s are the point of the design. The "yes" for the server in the last row
is its biggest limit (see [document 6](06-security-analysis.md)).

## 1.3 Where data is stored

| File | Machine | Contents | Protected by |
|---|---|---|---|
| `server_data/db.json` | server | usernames; `scrypt(login hash, random salt)`; public keys; sign-up time and accepted notice version; packages **until delivered** (at most 30 days); every message ID ever accepted | contents are hashes, public data and end-to-end ciphertext |
| `server_data/privacy/log_key` | server | the secret key that turns names and IPs into log pseudonyms | **file permissions only** |
| `server_data/tls/ca.crt` | server, copied to clients | the certificate of the private CA | public by design |
| `server_data/tls/server.crt` | server | the server's TLS certificate | public by design |
| `server_data/tls/server.key` | server | the server's TLS private key | **file permissions only** |
| `client_data/<user>/keys.json` | client | RSA and Ed25519 private keys | AES-256-GCM under `scrypt(password, random salt)` |
| `client_data/<user>/seen_ids.json` | client | IDs of messages already accepted | file permissions only |
| `client_data/<user>/known_keys.json` | client | pinned public keys of contacts | file permissions only |

Messages themselves are never saved on a client. They exist in plaintext only in
memory and on screen.

---

## Step 0. The server starts

Command: `py -m server.server`

1. Command-line options are read: address, port, database path, TLS folder, extra host
   names. ([server.py:407–416](../server/server.py#L407-L416))
2. Logging is switched on so the operator sees activity.
   ([server.py:417](../server/server.py#L417))
3. **TLS certificates.** If `server_data/tls/` is missing any of its three files, a new
   private CA is created and used once to sign a server certificate. The CA's private
   key is then discarded. ([server.py:419–423](../server/server.py#L419-L423),
   [tls.py:55–108](../crypto_utils/tls.py#L55-L108))
4. The server prints the CA fingerprint so clients can check their copy of `ca.crt`.
   ([server.py:423](../server/server.py#L423))
5. The database is loaded (or created empty), and a TLS 1.3-only context is built from
   the certificate and key. ([server.py:425](../server/server.py#L425),
   [storage.py:28–38](../server/storage.py#L28-L38),
   [tls.py:132–138](../crypto_utils/tls.py#L132-L138))
6. The server listens forever. Each new connection gets its own thread.
   ([server.py:434–439](../server/server.py#L434-L439))

## Step 1. A client starts and opens a TLS connection

Command: `py -m client.cli --data client_data\bob`

1. Options are read, including where `ca.crt` is.
   ([cli.py:254–261](../client/cli.py#L254-L261))
2. `ChatClient` creates a `Connection` ([session.py:71–81](../client/session.py#L71-L81)),
   which:
   - checks `ca.crt` exists and builds a TLS context that trusts **only** that CA and
     only TLS 1.3 ([connection.py:22–30](../client/connection.py#L22-L30),
     [tls.py:141–146](../crypto_utils/tls.py#L141-L146));
   - opens a TCP connection ([connection.py:31–34](../client/connection.py#L31-L34));
   - performs the TLS handshake and checks the server's certificate was signed by our
     CA for this host name. Any failure stops here with a security warning
     ([connection.py:35–48](../client/connection.py#L35-L48)).
3. On the server side, the accepted socket is wrapped in TLS
   ([server.py:359–363](../server/server.py#L359-L363)) and the handshake runs in the
   connection's own thread with a 15-second limit
   ([server.py:65–75](../server/server.py#L65-L75)).
4. The shell prints which TLS version and cipher were agreed, then the welcome text.
   ([cli.py:269–271](../client/cli.py#L269-L271))

From now on, every request is one JSON object on one line inside the TLS tunnel, and
every reply is one JSON object back ([connection.py:58–82](../client/connection.py#L58-L82),
[server.py:93–115](../server/server.py#L93-L115)).

## Step 2. Sign up

Bob types `signup bob`.

| # | Where | What happens |
|---|---|---|
| 1 | [cli.py:86–90](../client/cli.py#L86-L90), [server.py:297–299](../server/server.py#L297-L299) | The shell fetches the server's **privacy notice** (what is collected, why, for how long, and your rights) and continues only if Bob types `yes` |
| 1b | [cli.py:91–94](../client/cli.py#L91-L94) | The shell asks for the password twice with `getpass` (not shown on screen) and checks both match |
| 2 | [session.py:131–136](../client/session.py#L131-L136) | The client checks the username format and password length **before** doing anything slow, and refuses if this folder already has a key file for that name |
| 3 | [session.py:138](../client/session.py#L138), [keys.py:43–48](../crypto_utils/keys.py#L43-L48) | Two key pairs are generated **on Bob's computer**: RSA-3072 (for others to encrypt to Bob) and Ed25519 (for Bob to sign with) |
| 4 | [session.py:139](../client/session.py#L139), [passwords.py:84–111](../crypto_utils/passwords.py#L84-L111) | The **login hash** is computed: `scrypt(password, salt = SHA-256("secure-chat/login-hash/v1:" + "bob"))`. The password itself is never sent |
| 5 | [session.py:140–147](../client/session.py#L140-L147) | Request sent: `{"action":"signup","username":"bob","password_hash":…,"enc_public_pem":…,"sign_public_pem":…,"consent_version":"2026-11"}` |
| 6 | [server.py:129–152](../server/server.py#L129-L152) | The server's dispatcher picks the `signup` handler |
| 7 | [server.py:160–178](../server/server.py#L160-L178) | The server checks the username format, that `password_hash` really is a 32-byte login hash, that both public keys are real keys of the right type, and that the current privacy notice was accepted |
| 8 | [server.py:180–181](../server/server.py#L180-L181), [passwords.py:47–62](../crypto_utils/passwords.py#L47-L62) | The server hashes the login hash **again** with scrypt and a fresh 16-byte random salt |
| 9 | [server.py:182–192](../server/server.py#L182-L192) | Under the database lock: refuse if the name is taken; otherwise save the record, including the accepted notice version and time, and write `db.json` atomically |
| 10 | [server.py:193–195](../server/server.py#L193-L195) | This connection is now logged in as `bob`; the log records `signup: u-…` (a pseudonym, not the name) |
| 11 | [session.py:149](../client/session.py#L149), [keys.py:60–92](../crypto_utils/keys.py#L60-L92) | Only after the server said yes, the client saves both private keys to `keys.json`, encrypted with AES-256-GCM under `scrypt(password, new random salt)` |
| 12 | [session.py:151](../client/session.py#L151), [session.py:184–187](../client/session.py#L184-L187) | The client remembers it is logged in and loads its list of already-seen message IDs |

## Step 3. Log in (next time)

Bob types `login bob`.

| # | Where | What happens |
|---|---|---|
| 1 | [cli.py:99–107](../client/cli.py#L99-L107) | Password read with `getpass` |
| 2 | [session.py:163–164](../client/session.py#L163-L164) | A name that cannot exist is refused locally, so text typed in the wrong box is never sent |
| 3 | [session.py:165–166](../client/session.py#L165-L166) | Login hash computed and sent: `{"action":"login","username":"bob","password_hash":…}` |
| 4 | [server.py:198–202](../server/server.py#L198-L202) | Server checks the hash's shape and looks up the user |
| 5 | [server.py:205–207](../server/server.py#L205-L207), [passwords.py:65–73](../crypto_utils/passwords.py#L65-L73) | scrypt runs **even if the user doesn't exist** (against a dummy record) and the result is compared in constant time |
| 6 | [server.py:208–212](../server/server.py#L208-L212) | Wrong password and unknown user get the **same** reply, `Invalid username or password.`, and nothing is logged |
| 7 | [session.py:168–181](../client/session.py#L168-L181), [keys.py:94–105](../crypto_utils/keys.py#L94-L105) | On success the client opens `keys.json` with the password. A wrong password or edited file makes AES-GCM's tag fail, and the client logs out again |

## Step 4. Choose a recipient

Bob types `users`, or `chat alice` / `send alice …`, which do the same lookup.

1. The client asks for the user list. The server answers with every username and its
   two public keys, never anything secret.
   ([session.py:208–212](../client/session.py#L208-L212),
   [server.py:223–232](../server/server.py#L223-L232))
2. For each user the client computes a short **fingerprint** of the two public keys.
   ([session.py:223](../client/session.py#L223), [keys.py:131–141](../crypto_utils/keys.py#L131-L141))
3. **Pinning:** the first time Bob sees Alice, her keys are saved in `known_keys.json`.
   If the server ever returns different keys for Alice, the client marks them
   `CHANGED - not trusted` and refuses to use them.
   ([session.py:213–236](../client/session.py#L213-L236),
   [session.py:238–248](../client/session.py#L238-L248))
4. Bob and Alice can read their fingerprints to each other (phone, in person) to make
   sure the very first lookup was honest too.

## Step 5. Bob encrypts and signs

Bob types `send alice Hi Alice` (or a line inside `chat alice`).

| # | Where | What happens |
|---|---|---|
| 1 | [session.py:254–259](../client/session.py#L254-L259) | Checks: logged in, not to self, at most 20,000 characters; Alice's **pinned** public keys are fetched |
| 2 | [messages.py:104–105](../crypto_utils/messages.py#L104-L105) | A random message ID (`uuid4`) and the current time are chosen |
| 3 | [messages.py:108–109](../crypto_utils/messages.py#L108-L109) | A fresh random **256-bit AES key** and a fresh random **96-bit nonce** are generated, used for this message only |
| 4 | [messages.py:110](../crypto_utils/messages.py#L110), [messages.py:80–89](../crypto_utils/messages.py#L80-L89) | The text is encrypted with **AES-256-GCM**. The metadata (version, ID, sender, recipient, time) is bound in as *associated data*, so it is covered by GCM's tag without being encrypted |
| 5 | [messages.py:120](../crypto_utils/messages.py#L120) | The AES key is **wrapped** with Alice's RSA-3072 public key using **RSA-OAEP (SHA-256)**, so only Alice's private key can recover it |
| 6 | [messages.py:126–135](../crypto_utils/messages.py#L126-L135) | The package is assembled; binary values become base64 text |
| 7 | [messages.py:138–139](../crypto_utils/messages.py#L138-L139), [messages.py:67–77](../crypto_utils/messages.py#L67-L77) | Bob's **Ed25519** private key signs the canonical JSON of *every* field plus the label `secure-chat/message/v1`. The 64-byte signature is added |
| 8 | [session.py:266–269](../client/session.py#L266-L269) | `{"action":"send","package":{…}}` is sent through TLS |

What the package looks like (from a real run; long values shortened):

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

## Step 6. The server checks the envelope and stores the package

| # | Where | What happens |
|---|---|---|
| 1 | [server.py:144–145](../server/server.py#L144-L145) | `send` is refused unless this connection is logged in |
| 2 | [server.py:238–248](../server/server.py#L238-L248) | All fields present, the right types, and a message ID of exactly 32 lowercase hex characters |
| 3 | [server.py:252–254](../server/server.py#L252-L254) | `sender` must equal the logged-in user: Bob cannot send as Alice through this server |
| 4 | [server.py:255–260](../server/server.py#L255-L260) | The timestamp must be within 5 minutes of the server's clock |
| 5 | [server.py:262–264](../server/server.py#L262-L264) | The recipient must exist |
| 6 | [server.py:265–270](../server/server.py#L265-L270) | **Replay check:** a message ID is accepted once, ever |
| 7 | [server.py:271–274](../server/server.py#L271-L274) | Expired packages are purged, then this package is stored **exactly as received** (still encrypted, still signed) with `delivered: false` |

The server never checks the signature and never decrypts: it has no key that could,
and the recipient must not have to trust it anyway.

## Step 7. Alice receives, verifies, then decrypts

Alice types `inbox`, or the chat-mode listener asks once a second.

| # | Where | What happens |
|---|---|---|
| 1 | [server.py:279–293](../server/server.py#L279-L293) | The server returns every undelivered package addressed to Alice and **deletes them from its database** (only the random message IDs stay, for replay checks) |
| 2 | [session.py:274–280](../client/session.py#L274-L280) | The client checks the reply really is a list |
| 3 | [session.py:285–294](../client/session.py#L285-L294) | For each package: read the claimed sender safely, then fetch that sender's **pinned** signing key (unknown sender or changed key → reject) |
| 4 | [messages.py:164–167](../crypto_utils/messages.py#L164-L167), [messages.py:233–261](../crypto_utils/messages.py#L233-L261) | **Shape check:** every field present, right type, valid base64 of a sensible size |
| 5 | [messages.py:170–179](../crypto_utils/messages.py#L170-L179) | **Signature check first.** The Ed25519 signature must verify over all fields with Bob's public key. If not: reject with a clear warning, decrypt nothing |
| 6 | [messages.py:182–183](../crypto_utils/messages.py#L182-L183) | The package must be addressed to Alice |
| 7 | [messages.py:184–185](../crypto_utils/messages.py#L184-L185) | The timestamp must not be more than 5 minutes in the future |
| 8 | [messages.py:186–190](../crypto_utils/messages.py#L186-L190) | **Replay check:** the message ID must not be in Alice's `seen_ids` |
| 9 | [messages.py:193–197](../crypto_utils/messages.py#L193-L197) | **Unwrap:** Alice's RSA private key decrypts the AES key (RSA-OAEP) |
| 10 | [messages.py:200–210](../crypto_utils/messages.py#L200-L210) | **Decrypt:** AES-256-GCM decrypts and checks its tag over the ciphertext *and* the metadata. Any change → reject |
| 11 | [messages.py:211–214](../crypto_utils/messages.py#L211-L214) | The result must be valid UTF-8 text |
| 12 | [messages.py:217–219](../crypto_utils/messages.py#L217-L219), [session.py:306](../client/session.py#L306) | The ID is added to `seen_ids`, which is saved to disk |
| 13 | [cli.py:126–138](../client/cli.py#L126-L138) | The text is displayed through `safe_display`, which turns newlines and terminal escape codes into visible `\n`, `\x1b`, so a message cannot fake extra chat lines |

Any failure produces `{"ok": false, "reason": …}` for that one message; the rest of the
inbox is still shown ([session.py:300–305](../client/session.py#L300-L305)).

## Step 8. Chat mode

`chat alice` combines steps 4–7 into a live conversation
([cli.py:140–217](../client/cli.py#L140-L217)):

- **Main thread:** reads what you type; each line goes through step 5; `/exit` leaves.
- **Listener thread:** every second runs step 7 and prints new messages above your
  prompt.
- Both threads share one TLS connection. A lock in `Connection.request` makes sure each
  request is paired with its own reply ([connection.py:65](../client/connection.py#L65)).
- If the connection dies, the listener stops and says so once
  ([cli.py:186–188](../client/cli.py#L186-L188)).

## Step 9. Log out and quit

- `logout` tells the server to forget this connection's login and clears the keys from
  the client object ([session.py:189–191](../client/session.py#L189-L191),
  [server.py:217–219](../server/server.py#L217-L219)).
- `quit` ends the shell; the connection is closed
  ([cli.py:246–251](../client/cli.py#L246-L251), [cli.py:280–281](../client/cli.py#L280-L281)).

## Step 10. Privacy rights: see my data, delete my account

| Command | Where | What happens |
|---|---|---|
| `mydata` | [cli.py:225–227](../client/cli.py#L225-L227), [server.py:301–319](../server/server.py#L301-L319) | The server returns everything it stores about you as JSON: name, sign-up time, accepted notice version, public keys, how many messages are waiting, the retention rule and your log pseudonym. The password record is described but not shown |
| `delete_account` | [cli.py:229–239](../client/cli.py#L229-L239), [session.py:324–331](../client/session.py#L324-L331), [server.py:321–339](../server/server.py#L321-L339) | After you type your username and password again, the server erases your account and every message to or from you, and the client deletes your key file, pins and seen IDs from this device |

Behind the scenes, two more privacy mechanisms run all the time
([privacy.py](../server/privacy.py)):

- **Retention:** packages are deleted as soon as they are delivered, and after 30 days if
  nobody collects them.
- **Pseudonymous logs:** the server log shows `u-e78032f543` instead of `alice` and
  `ip-eff78df829` instead of `127.0.0.1`. Only someone with the secret key in
  `server_data/privacy/log_key` can map them back, using `py -m server.reidentify`.

## The whole journey on one page

```text
 BOB'S CLIENT                              SERVER                               ALICE'S CLIENT
 ════════════                              ══════                               ══════════════
 TLS 1.3 handshake ──────────────────────▶ certificate from private CA
 (checks cert: our CA? our host?)          (server.key never leaves)

 h = scrypt(pw, salt=SHA256(ctx||"bob"))
 login {bob, h} ───────────────────────▶   scrypt(h, stored salt) == stored?
                                           (dummy scrypt if no such user;
                                            same error either way)
 users ◀──────────────────────────────── public keys only
 pin alice's keys, show fingerprint

 aes_key, nonce = random
 ct  = AES-256-GCM(aes_key, nonce, text, aad=metadata)
 wk  = RSA-OAEP(alice_pub, aes_key)
 sig = Ed25519(bob_priv, all fields + context)
 send {package} ───────────────────────▶   logged in as sender? fresh time?
                                           new msg_id? recipient exists?
                                           store package unchanged
                                                                    ◀──────── TLS 1.3 + login + inbox
                                           package (marked delivered) ───────▶
                                                                               pinned bob key?
                                                                               shape OK?
                                                                               1. verify sig ── fail → REJECT
                                                                               2. for me? not future?
                                                                               3. msg_id unseen? ── no → REJECT
                                                                               4. aes_key = RSA-OAEP-dec(alice_priv)
                                                                               5. text = AES-GCM-dec ── tag bad → REJECT
                                                                               6. remember msg_id
                                                                               7. print safely
```
