"""Selection order for the knok-inbox hook.

The bug these pin: the hook picked the *newest* three unread and reversed them, so a
backlog larger than MAX_MESSAGES starved the oldest mail — the mail most likely to be
waiting on an answer — and delivered later messages first.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "knok_inbox", Path(__file__).resolve().parents[1] / "__init__.py"
)
hook = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hook)


def _write_inbox(path: Path, ids: list[str]) -> None:
    lines = []
    for n, message_id in enumerate(ids):
        lines.append(
            json.dumps(
                {
                    "from": "muse@knok.local",
                    "sentAt": f"2026-11-21T12:{n:02d}:00Z",
                    "message": {
                        "messageId": message_id,
                        "contextId": f"c-{message_id}",
                        "parts": [{"text": f"body of {message_id}"}],
                    },
                }
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture()
def mailbox(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox.jsonl"
    state = tmp_path / "seen.json"
    monkeypatch.setattr(hook, "INBOX", inbox)
    monkeypatch.setattr(hook, "STATE", state)
    return inbox, state


def test_the_oldest_unread_are_delivered_first(mailbox):
    inbox, _ = mailbox
    _write_inbox(inbox, ["m-1", "m-2", "m-3", "m-4"])

    context = hook._handle("hello", "telegram")

    assert context is not None
    # m-4 is newer but must wait; m-1 was waiting first.
    assert "body of m-1" in context
    assert "body of m-2" in context
    assert "body of m-3" in context
    assert "body of m-4" not in context
    assert context.index("body of m-1") < context.index("body of m-3")


def test_the_remaining_mail_arrives_on_the_next_turn_and_nothing_repeats(mailbox):
    inbox, state = mailbox
    _write_inbox(inbox, ["m-1", "m-2", "m-3", "m-4"])

    hook._handle("first", "telegram")
    second = hook._handle("second", "telegram")

    assert second is not None
    assert "body of m-4" in second
    for already_seen in ("body of m-1", "body of m-2", "body of m-3"):
        assert already_seen not in second

    assert hook._handle("third", "telegram") is None
    assert len(json.loads(state.read_text())["seen"]) == 4


def test_a_non_interactive_turn_does_not_consume_mail(mailbox):
    inbox, state = mailbox
    _write_inbox(inbox, ["m-1"])

    assert hook._handle("cron", "cron") is None
    assert not state.exists()

    assert hook._handle("hello", "telegram") is not None
