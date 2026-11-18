"""Interactive command-line client.

Run:  py -m client.cli --port 5050

Commands:
    signup <username>          create an account (asks for a password)
    login <username>           log in (asks for a password)
    users                      list other users and their key fingerprints
    send <recipient> <message> encrypt, sign and send
    inbox                      fetch, verify and decrypt new messages
    verbose on|off             print each crypto step as it happens
    logout
    quit
"""

import argparse
import cmd
import datetime
import getpass

from .connection import ConnectionError_
from .session import ChatClient, ClientError


def print_step(step: str, detail: str = "") -> None:
    print(f"  [{step}]")
    for line in detail.splitlines():
        print(f"      {line}")


def silent(step, detail=""):
    pass


class ChatShell(cmd.Cmd):
    intro = "Secure chat client. Type 'help' for commands."

    def __init__(self, client: ChatClient):
        super().__init__()
        self.client = client
        self._update_prompt()

    def _update_prompt(self):
        self.prompt = f"({self.client.username or 'not logged in'}) > "

    def postcmd(self, stop, line):
        self._update_prompt()
        return stop

    def onecmd(self, line):
        # One place to turn errors into friendly messages.
        try:
            return super().onecmd(line)
        except ClientError as exc:
            print(f"Error: {exc}")
        except ConnectionError_ as exc:
            print(f"Connection problem: {exc}")
            return True

    def emptyline(self):
        pass

    # ---------------------------------------------------------- commands

    def do_signup(self, arg):
        """signup <username>  - create an account and a new key pair on this device"""
        username = arg.strip()
        if not username:
            print("Usage: signup <username>")
            return
        password = getpass.getpass("Choose a password (min 8 chars): ")
        if password != getpass.getpass("Repeat password: "):
            print("Passwords do not match.")
            return
        print("Generating keys (a few seconds)...")
        self.client.signup(username, password)
        print(f"Account created. Logged in as {username}.")

    def do_login(self, arg):
        """login <username>  - log in and unlock your private keys"""
        username = arg.strip()
        if not username:
            print("Usage: login <username>")
            return
        password = getpass.getpass("Password: ")
        self.client.login(username, password)
        print(f"Logged in as {username}.")

    def do_users(self, arg):
        """users  - list other users with their public-key fingerprints"""
        users = self.client.users()
        if not users:
            print("No other users yet.")
        for u in users:
            print(f"  {u['username']:<20} {u['fingerprint']}  ({u['key_status']})")

    def do_send(self, arg):
        """send <recipient> <message>  - encrypt, sign and send a message"""
        parts = arg.split(maxsplit=1)
        if len(parts) != 2:
            print("Usage: send <recipient> <message>")
            return
        msg_id = self.client.send(parts[0], parts[1])
        print(f"Sent (message ID {msg_id}).")

    def do_inbox(self, arg):
        """inbox  - fetch new messages, verify each signature, then decrypt"""
        results = self.client.inbox()
        if not results:
            print("No new messages.")
        for r in results:
            when = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%Y-%m-%d %H:%M:%S") if isinstance(r["timestamp"], int) else "?"
            if r["ok"]:
                print(f"  [{when}] {r['sender']}: {r['text']}   (signature OK)")
            else:
                print(f"  !! REJECTED message claiming to be from {r['sender']} ({when})")
                print(f"     reason: {r['reason']}")

    def do_verbose(self, arg):
        """verbose on|off  - show every crypto step"""
        on = arg.strip().lower() in ("on", "1", "yes", "")
        self.client.trace = print_step if on else silent
        print(f"Verbose mode {'on' if on else 'off'}.")

    def do_logout(self, arg):
        """logout"""
        self.client.logout()
        print("Logged out.")

    def do_quit(self, arg):
        """quit"""
        return True

    do_exit = do_quit
    do_EOF = do_quit


def main():
    parser = argparse.ArgumentParser(description="Secure chat client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--data", default="client_data", help="folder for this device's encrypted keys")
    args = parser.parse_args()
    try:
        client = ChatClient(args.host, args.port, args.data, trace=silent)
    except ConnectionError_ as exc:
        print(exc)
        print("Start the server first:  py -m server.server")
        return
    try:
        ChatShell(client).cmdloop()
    finally:
        client.close()


if __name__ == "__main__":
    main()
