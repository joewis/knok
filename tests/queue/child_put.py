"""Child process for the kill/restart tests.

Opens a queue, puts (and optionally gets) an envelope, then dies with
``os._exit(1)`` — no close, no ack, no graceful shutdown. If the parent can
still read the message afterwards, the fsync-before-ack promise holds; a
test that only reopens the file proves nothing about fsync.

Usage: child_put.py <db-path> <envelope-json-path> <mode> <now-iso> <owner-id>
  mode "put":     put the envelope, then die.
  mode "put_get": put the envelope, get it (one delivery attempt), then die.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from knok.queue import Queue  # noqa: E402

db_path, envelope_path, mode, now_iso, owner = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
envelope = json.loads(Path(envelope_path).read_text())
now = datetime.fromisoformat(now_iso)
queue = Queue(db_path, owner)
queue.put(envelope, now)
if mode == "put_get":
    queue.get(now)
elif mode != "put":
    raise SystemExit(f"unknown mode {mode!r}")
sys.stdout.flush()
os._exit(1)
