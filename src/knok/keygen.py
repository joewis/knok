"""CLI: create an agent keypair and print its public half.

Usage: python -m knok.keygen --name carl --hub bridge.example [--dir ~/.config/knok]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .identity import IdentityError, generate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="knok.keygen")
    parser.add_argument("--name", required=True)
    parser.add_argument("--hub", required=True)
    parser.add_argument("--dir", default=os.environ.get("KNOK_KEY_DIR", "~/.config/knok"))
    args = parser.parse_args(argv)

    directory = Path(args.dir).expanduser()
    try:
        identity = generate(args.name, args.hub)
        path = identity.save(directory / f"{args.name}.key")
    except IdentityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"agent_id: {identity.agent_id}")
    print(f"fingerprint: {identity.fingerprint}")
    print(f"public_key: {identity.public_b64()}")
    print(f"private_key: {path} (mode 0600)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
