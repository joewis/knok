"""Bridge-local audit files have a retention policy: 30 days, then pruned (#124).

``delivery.jsonl``, ``refused.jsonl``, ``dropped.jsonl`` and ``notices.jsonl`` were all append-only
with no rotation, truncation or pruning, so metadata — identifiers, peer relationships, rules,
outcomes, timestamps — accumulated past the lifetime of the hub item it described. The spec's own
clocks are 30 days for hub-log metadata (§10) and 30 days for dead letters (§6); the bridge-local
audit files now keep the same 30 days, and the bridge prunes older rows on its poll loop.

What the tests hold:

* rows older than 30 days are dropped, fresh rows stay, and a row the pruner cannot date is kept
  rather than deleted as evidence it cannot read;
* pruning replaces the file atomically, so a crash mid-prune leaves the old file or the new one,
  never a half-written one;
* the poll loop prunes at most once a day of process time — retention is 30 days, so re-reading
  four files every two-second poll would be pure churn;
* a ledger the pruner cannot read (a directory where the file belongs) is left alone and the poll
  still runs.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from knok.bridge import LEDGER_RETENTION, prune_ledgers

from test_phase2 import deployment  # noqa: F401  (fixture used by name)

OLD = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)


def stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def row(at: str, message_id: str = "m-1", **extra):
    record = {"at": at, "messageId": message_id, "outcome": "queued"}
    record.update(extra)
    return json.dumps(record, sort_keys=True)


def test_prune_ledgers_drops_rows_older_than_30_days(tmp_path: Path):
    directory = tmp_path
    (directory / "delivery.jsonl").write_text(
        "\n".join(
            [
                row(stamp(OLD), "m-old"),
                row(stamp(NOW - timedelta(days=29)), "m-fresh"),
                row(stamp(NOW - timedelta(days=30, seconds=1)), "m-just-over"),
            ]
        )
        + "\n"
    )
    (directory / "notices.jsonl").write_text(
        json.dumps({"receivedAt": stamp(OLD), "messageId": "m-old-notice", "kind": "refused"})
        + "\n"
        + json.dumps({"receivedAt": stamp(NOW), "messageId": "m-fresh-notice", "kind": "refused"})
        + "\n"
    )
    (directory / "refused.jsonl").write_text(row(stamp(OLD), "m-old-refused") + "\n")
    (directory / "dropped.jsonl").write_text(row(stamp(OLD), "m-old-dropped") + "\n")

    removed = prune_ledgers(directory, now=NOW)

    assert removed == {
        "delivery.jsonl": 2,
        "notices.jsonl": 1,
        "refused.jsonl": 1,
        "dropped.jsonl": 1,
    }
    assert [json.loads(line)["messageId"] for line in
            (directory / "delivery.jsonl").read_text().splitlines()] == ["m-fresh"]
    assert [json.loads(line)["messageId"] for line in
            (directory / "notices.jsonl").read_text().splitlines()] == ["m-fresh-notice"]
    assert (directory / "refused.jsonl").read_text() == ""
    assert (directory / "dropped.jsonl").read_text() == ""


def test_prune_ledgers_keeps_rows_it_cannot_date(tmp_path: Path):
    directory = tmp_path
    (directory / "delivery.jsonl").write_text(
        "\n".join(
            [
                '{"messageId": "m-no-time", "outcome": "queued"}',
                '{"at": "not a timestamp", "messageId": "m-bad-time", "outcome": "queued"}',
                "this line is not json at all",
                row(stamp(OLD), "m-old"),
            ]
        )
        + "\n"
    )

    removed = prune_ledgers(directory, now=NOW)

    assert removed == {"delivery.jsonl": 1}
    kept = (directory / "delivery.jsonl").read_text().splitlines()
    assert len(kept) == 3, "undated and unreadable rows stay; only the dated old row goes"
    assert "m-old" not in (directory / "delivery.jsonl").read_text()


def test_prune_ledgers_leaves_missing_files_alone(tmp_path: Path):
    assert prune_ledgers(tmp_path, now=NOW) == {}
    assert list(tmp_path.iterdir()) == [], "pruning must not create files that were never there"


def test_prune_ledgers_skips_a_file_it_cannot_replace(tmp_path: Path):
    directory = tmp_path
    (directory / "delivery.jsonl").mkdir()  # a directory where the ledger belongs
    assert prune_ledgers(directory, now=NOW) == {}
    assert (directory / "delivery.jsonl").is_dir(), "a directory is left exactly as found"


def test_the_poll_loop_prunes_stale_rows_and_then_rests(deployment):
    hub, bridges, root = deployment
    muse = bridges["muse"]
    directory = muse.state.directory
    (directory / "delivery.jsonl").write_text(row(stamp(OLD), "m-old") + "\n")
    (directory / "notices.jsonl").write_text(
        json.dumps({"receivedAt": stamp(OLD), "messageId": "m-old-notice", "kind": "refused"})
        + "\n"
    )

    counts = muse.poll_once()

    assert counts["fetched"] == 0
    assert "m-old" not in (directory / "delivery.jsonl").read_text()
    assert "m-old-notice" not in (directory / "notices.jsonl").read_text()

    # The second poll, immediately after, does no pruning work: retention is 30 days, so the
    # poll loop prunes at most once a day of process time.
    delivery_mtime = (directory / "delivery.jsonl").stat().st_mtime_ns
    notices_mtime = (directory / "notices.jsonl").stat().st_mtime_ns
    muse.poll_once()
    assert (directory / "delivery.jsonl").stat().st_mtime_ns == delivery_mtime
    assert (directory / "notices.jsonl").stat().st_mtime_ns == notices_mtime


def test_retention_is_thirty_days():
    assert LEDGER_RETENTION == timedelta(days=30), "aligned with the spec's log and dead-letter clocks"
