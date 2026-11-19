"""Conditional re-identification of a pseudonym from the server log.

Only someone who can read the server's secret log key (server_data/privacy/
log_key) can do this. It is meant for a lawful request or a security
investigation, not for everyday use.

Run:  py -m server.reidentify u-3f9a1c0b2e
      py -m server.reidentify ip-77b0e1d4a2 --ip 127.0.0.1 --ip 192.168.1.20
"""

import argparse
import json
import os
import sys

from .privacy import Pseudonymizer


def main():
    parser = argparse.ArgumentParser(description="Re-identify a pseudonym from the server log")
    parser.add_argument("pseudonym", help="e.g. u-3f9a1c0b2e or ip-77b0e1d4a2")
    parser.add_argument("--db", default="server_data/db.json")
    parser.add_argument("--key", default="server_data/privacy/log_key")
    parser.add_argument("--ip", action="append", default=[], help="candidate IP addresses to test")
    args = parser.parse_args()
    if not os.path.exists(args.key):
        sys.exit("No log key found. Without the key, pseudonyms cannot be re-identified (that is the point).")
    pseudo = Pseudonymizer(args.key)
    candidates = list(args.ip)
    if os.path.exists(args.db):
        with open(args.db, encoding="utf-8") as f:
            candidates += list(json.load(f).get("users", {}))
    matches = pseudo.reidentify(args.pseudonym, candidates)
    print(matches[0] if matches else "No match among current users / given IPs.")


if __name__ == "__main__":
    main()
