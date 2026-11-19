"""Privacy mechanisms on the server: pseudonymous logs, retention and the privacy notice.

Pseudonymous logging with conditional re-identification
    The server log must help the operator (who logged in, which message was
    stored, which connection failed) without turning into a list of who
    talks to whom. So usernames and IP addresses are never written in clear.
    Each one is replaced by a pseudonym:

        pseudonym = "u-" + HMAC-SHA256(log_key, "user:" + username)[:10 hex]

    The same user always gets the same pseudonym, so the log stays useful
    for spotting patterns (one pseudonym failing many logins, for example).
    Without the secret `log_key` nobody can tell who a pseudonym is.

    This is *conditional* privacy: whoever holds `log_key` (kept in
    server_data/privacy/, not in the log) can re-identify a pseudonym with
    `py -m server.reidentify <pseudonym>`, for example when a lawful
    request or a security incident requires it. Everyone else, including
    someone who only gets a copy of the log, sees pseudonyms only.

Retention
    Delivered messages are deleted from the database right away. Messages
    nobody collects are deleted after RETENTION_DAYS. Only the random
    message IDs are kept, because the replay check needs them; an ID alone
    says nothing about who sent what.

Privacy notice
    The text the client shows before signup, and the version the user must
    accept. The server stores which version was accepted and when.
"""

import hashlib
import hmac
import os
import time

RETENTION_DAYS = 30                 # undelivered messages are deleted after this many days
RETENTION_SECONDS = RETENTION_DAYS * 24 * 3600
PRIVACY_NOTICE_VERSION = "2026-11"  # bump when the notice text changes; users must accept the new one

PRIVACY_NOTICE = f"""\
Privacy notice (version {PRIVACY_NOTICE_VERSION})
  What we collect : your username, a hash of a hash of your password, your two public keys,
                    the time you signed up, and the encrypted messages you send until they are delivered.
  What we never get: your password, your private keys, or the text of any message.
  Why             : only to let you log in and to deliver your messages (PDPA s.21, s.22).
  How long        : delivered messages are deleted at once; undelivered ones after {RETENTION_DAYS} days.
                    Your account stays until you delete it.
  Who can see it  : only the server operator. Server logs use pseudonyms, not your name or IP address.
  Your rights     : 'mydata' shows everything we hold about you (s.30, s.31);
                    'delete_account' erases your account and waiting messages (s.33).
"""


class Pseudonymizer:
    """Turns usernames and IP addresses into stable, keyed pseudonyms for the log."""

    def __init__(self, key_path: str):
        self.key_path = key_path
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self.key = f.read()
        else:
            os.makedirs(os.path.dirname(os.path.abspath(key_path)), exist_ok=True)
            self.key = os.urandom(32)            # 256-bit secret, created once per server
            with open(key_path, "wb") as f:
                f.write(self.key)

    def _tag(self, kind: str, value: str) -> str:
        # HMAC, not a plain hash: without the key, nobody can test guesses such as
        # hash("alice") to undo the pseudonym.
        digest = hmac.new(self.key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
        return digest[:10]

    def user(self, username) -> str:
        return "u-" + self._tag("user", str(username))

    def ip(self, address) -> str:
        return "ip-" + self._tag("ip", str(address))

    def reidentify(self, pseudonym: str, candidates) -> list[str]:
        """Conditional re-identification: only possible with the key and a list of candidates."""
        return [c for c in candidates if self.user(c) == pseudonym or self.ip(c) == pseudonym]


def purge_expired(data: dict, now: float | None = None) -> int:
    """Delete delivered messages and messages older than the retention period.
    Returns how many were removed. The caller holds the database lock and saves."""
    now = time.time() if now is None else now
    keep = []
    for entry in data["messages"]:
        if not isinstance(entry, dict):
            continue                                          # junk entry: drop it
        too_old = now - entry.get("received_at", 0) > RETENTION_SECONDS
        if entry.get("delivered") or too_old:
            continue                                          # delivered or expired: drop it
        keep.append(entry)
    removed = len(data["messages"]) - len(keep)
    data["messages"] = keep
    return removed
