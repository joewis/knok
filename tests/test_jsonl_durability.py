"""JSONL durability: a failed notice write is not acked (#112), and a torn trailing line
never corrupts the file (#114).

#112: ``_handle_frame`` discarded ``_record_notice``'s Boolean and returned the frame's id
as ackable, so a hub-signed ``expired``/``dead`` frame could be acknowledged — and deleted by
the hub — while the recipient's local notice was never recorded. The drain path and the
refusal-notice path already gate on the write; the hub-frame path must do the same.

#114: every JSONL append is ``write`` + ``flush`` + ``fsync``, which makes a *completed*
append durable before the ack, but a crash during the append can leave a partial final line.
Nothing truncated or validated it on restart, so the next append glued its record onto the
fragment and the file carried a permanently malformed line. The repair is conservative: only
the final line can be torn — every line before it was complete when a later line was written
after it — so a bridge drops a trailing line that is not a complete, valid JSON line, before
it appends again and on startup.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from knok.envelope import sign
from knok.hubclient import HubClient

from test_delivery_ledger import deposit, rows  # noqa: F401  (fixtures and helpers by name)
from test_phase2 import deployment, iso, now  # noqa: F401  (fixture used by name)


def jsonl_lines(path: Path) -> list[dict]:
    """Every record in a JSONL file, parsed. Raises on a malformed line — that is the point."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def deposit_already_expired(sender, recipient_id: str, *, context: str, message_id: str):
    """Deposit an envelope whose TTL already ran out.

    The hub accepts it (202) and queues a hub-signed ``expired`` frame in the *sender's*
    mailbox — the same frame a sweep produces. ``sign`` is asked about the envelope as of a
    moment inside its lifetime, because signing an already-dead envelope is rightly refused;
    the hub verifies as of ``sentAt`` and applies its own expiry decision.
    """
    moment = now()
    unsigned = {
        "envelopeVersion": 1,
        "seq": 0,
        "message": {
            "kind": "message",
            "messageId": message_id,
            "contextId": context,
            "role": "agent",
            "parts": [{"kind": "text", "text": "too late"}],
        },
        "from": sender.identity.agent_id,
        "to": [recipient_id],
        "sentAt": iso(moment - timedelta(hours=2)),
        "expiresAt": iso(moment - timedelta(hours=1)),
        "turn": {"expectsReply": False, "closesThread": False},
    }
    envelope = sign(unsigned, sender.identity, now=moment - timedelta(hours=2))
    client = HubClient(sender.state.hub_url, sender.identity)
    return client.deposit(envelope), envelope


def test_a_failed_notice_write_leaves_the_expired_frame_at_the_hub(deployment):
    """#112: the frame is acked only once its notice is on disk.

    The expired frame is the only evidence the message died — the body is already gone — so
    acknowledging it while ``notices.jsonl`` cannot be written lets the hub delete the only
    copy and the owner never learns the message expired.
    """
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    deposit_already_expired(carl, muse.identity.agent_id, context="c-gone", message_id="m-gone")
    assert len(carl.client.fetch()["messages"]) == 1, "the hub owes carl one expired frame"

    path: Path = carl.state.directory / "notices.jsonl"
    path.mkdir()  # a directory where the notices file belongs: every append raises OSError

    counts = carl.poll_once()

    assert counts["notices"] == 0 and counts["unhandled"] == 1
    assert len(carl.client.fetch()["messages"]) == 1, "no ack without a notice: the hub keeps it"

    path.rmdir()
    counts = carl.poll_once()

    assert counts["notices"] == 1
    assert carl.client.fetch()["messages"] == [], "recorded, so the frame may be acknowledged"
    notices = jsonl_lines(carl.state.directory / "notices.jsonl")
    assert len(notices) == 1 and notices[0]["kind"] == "expired"
    assert notices[0]["messageId"] == "m-gone"


def test_a_torn_delivery_ledger_tail_is_truncated_before_the_next_append(deployment):
    """#114: a crash mid-append loses at most the record being written, never the file."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    path: Path = muse.state.directory / "delivery.jsonl"
    # A fragment from a write that never completed: no terminating newline, not valid JSON.
    path.write_text('{"at": "2026-11-21T00:00:00Z", "messageId": "m-torn", "outc', encoding="utf-8")

    deposit(carl, muse.identity.agent_id, "after the crash", context="c-1", message_id="m-after")
    counts = muse.poll_once()

    assert counts["queued"] == 1
    ledger = jsonl_lines(path)
    assert [row["messageId"] for row in ledger] == ["m-after"], "the fragment is gone, the row clean"
    assert ledger[0]["outcome"] == "queued"


def test_a_torn_inbox_tail_is_truncated_before_the_next_delivery(deployment):
    """#114: the inbox heals the same way — the queue replays the message, the file stays clean."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    deposit(carl, muse.identity.agent_id, "held for delivery", context="c-2", message_id="m-held")
    assert muse.poll_once()["queued"] == 1
    path: Path = muse.state.directory / "inbox.jsonl"
    path.write_text('{"envelopeVersion": 1, "message": {"messageId": "m-tor', encoding="utf-8")

    assert muse.drain() == 1

    inbox = jsonl_lines(path)
    assert len(inbox) == 1, "the fragment is gone and the message is the only record"
    assert inbox[0]["message"]["messageId"] == "m-held"


def test_a_torn_notices_tail_is_truncated_before_the_next_notice(deployment):
    """#114: the same repair on ``notices.jsonl``, reached through a hub-signed frame."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    path: Path = carl.state.directory / "notices.jsonl"
    path.write_text('{"kind": "expired", "messageId": "m-tor', encoding="utf-8")

    deposit_already_expired(carl, muse.identity.agent_id, context="c-3", message_id="m-late")
    counts = carl.poll_once()

    assert counts["notices"] == 1
    notices = jsonl_lines(path)
    assert len(notices) == 1 and notices[0]["messageId"] == "m-late"


def test_an_already_glued_final_line_is_dropped_not_kept(deployment):
    """#114: a crash before this repair existed can leave a fused line *with* a newline.

    Two records glued into one newline-terminated line are unrecoverable as written — neither
    record survives on its own — so the repair drops the fused line and keeps every complete
    line before it. The next append then starts clean.
    """
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    path: Path = muse.state.directory / "delivery.jsonl"
    path.write_text(
        '{"at": "2026-11-21T00:00:00Z", "messageId": "m-keep", "outcome": "queued"}\n'
        '{"messageId": "m-glued"}{"at": "2026-11-21T00:00:01Z", "messageId": "m-lost"}\n',
        encoding="utf-8",
    )

    deposit(carl, muse.identity.agent_id, "after the glue", context="c-4", message_id="m-clean")
    assert muse.poll_once()["queued"] == 1

    ledger = jsonl_lines(path)
    assert [row["messageId"] for row in ledger] == ["m-keep", "m-clean"]
