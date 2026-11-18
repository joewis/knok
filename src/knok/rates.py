"""Fixed-bucket counters for the limits in SPEC §9.

Contract: ``count`` never writes; ``hit`` writes once. Callers check every window they care about
first and only then record a hit, so a message refused by one window does not consume budget in
another.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path


def _bucket(moment: datetime, span: timedelta) -> str:
    if span == timedelta(hours=1):
        return moment.strftime("%Y-%m-%dT%H")
    return moment.strftime("%Y-%m-%d")


class Rates:
    """Counters for §9's limits. Windows are fixed buckets, not sliding ones: a fixed bucket can
    admit up to twice the limit across a boundary, which is the cheap side of that error for a
    throttle whose job is to make a spray expensive rather than impossible."""

    def __init__(self, path: str | Path):
        # Same pattern as Queue: the transport serves on its own thread, so
        # the connection must be usable from it, guarded by one lock.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS rates (scope TEXT NOT NULL, key TEXT NOT NULL,"
            " bucket TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (scope, key, bucket))"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Rates":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def count(self, scope: str, key: str, moment: datetime, span: timedelta = timedelta(hours=1)) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT count FROM rates WHERE scope = ? AND key = ? AND bucket = ?",
                (scope, key, _bucket(moment, span)),
            ).fetchone()
            return row[0] if row else 0

    def hit(self, scope: str, key: str, moment: datetime, span: timedelta = timedelta(hours=1)) -> int:
        with self._lock:
            self._conn.execute(
                "INSERT INTO rates (scope, key, bucket, count) VALUES (?, ?, ?, 1)"
                " ON CONFLICT(scope, key, bucket) DO UPDATE SET count = count + 1",
                (scope, key, _bucket(moment, span)),
            )
            self._conn.commit()
            return self.count(scope, key, moment, span)
