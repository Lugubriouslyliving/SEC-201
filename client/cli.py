"""Interactive command-line client.

Run:  py -m client.cli --port 5050

Commands:
    signup <username>          create an account (asks for a password)
    login <username>           log in (asks for a password)
    users                      list other users and their key fingerprints
    chat <username>            live conversation: type to send, replies appear as they arrive
    send <recipient> <message> encrypt, sign and send one message
    inbox                      fetch, verify and decrypt new messages
    verbose on|off             print each crypto step as it happens
    logout
    quit
"""

import argparse
import cmd
import datetime
import getpass
import sys
import threading

from .connection import ConnectionError_
from .session import ChatClient, ClientError


def print_step(step: str, detail: str = "") -> None:
    print(f"  [{step}]")
    for line in detail.splitlines():
        print(f"      {line}")


def silent(step, detail=""):
    pass


class ChatShell(cmd.Cmd):
    intro = (
        "Secure chat client.\n"
        "  New here?  signup <your name>      Returning?  login <your name>\n"
        "  Then:      users                   to see who you can talk to\n"
        "             chat <their name>       to start chatting\n"
        "Type 'help' for all commands."
    )

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

    def do_chat(self, arg):
        """chat <username>  - live conversation; type /exit to leave"""
        peer = arg.strip()
        if not peer:
            print("Usage: chat <username>   (type 'users' to see who is here)")
            return
        if self.client.username is None:
            raise ClientError("Please log in first.")
        if peer == self.client.username:
            raise ClientError("You cannot chat with yourself.")
        info = self.client._trusted_keys(peer)  # raises if unknown or if the key changed

        me = self.client.username
        prompt = f"{me}> "
        print(f"--- Chat with {peer} ---")
        print(f"    {peer}'s key fingerprint: {info['fingerprint']}")
        print("    Every message is encrypted for them and signed by you. Type /exit to leave.")
        print()

        print_lock = threading.Lock()
        stop = threading.Event()

        def show(text):
            # Print above the prompt, then redraw the prompt.
            with print_lock:
                sys.stdout.write("\r" + " " * (len(prompt) + 40) + "\r")
                sys.stdout.write(text + "\n" + prompt)
                sys.stdout.flush()

        def receive_loop():
            # Check the inbox once a second; verify and decrypt whatever arrived.
            while not stop.is_set():
                try:
                    for r in self.client.inbox():
                        when = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%H:%M") \
                            if isinstance(r["timestamp"], int) else "--:--"
                        if not r["ok"]:
                            show(f"[{when}] !! REJECTED a message claiming to be from {r['sender']}: {r['reason']}")
                        elif r["sender"] == peer:
                            show(f"[{when}] {peer}: {r['text']}")
                        else:
                            show(f"[{when}] (from {r['sender']}) {r['text']}")
                except (ClientError, ConnectionError_) as exc:
                    show(f"!! could not check messages: {exc}")
                stop.wait(1.0)

        listener = threading.Thread(target=receive_loop, daemon=True)
        listener.start()
        try:
            while True:
                line = input(prompt)
                text = line.strip()
                if text in ("/exit", "/quit", "/back"):
                    break
                if not text:
                    continue
                try:
                    self.client.send(peer, text)
                except ClientError as exc:
                    show(f"!! not sent: {exc}")
        except (EOFError, KeyboardInterrupt):
            print()
        finally:
            stop.set()
            listener.join(timeout=5)
        print(f"--- Left chat with {peer} ---")

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
