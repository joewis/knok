"""The seen set is a claim about delivery, so it is only written once delivery is visible.

The bug these pin: ids entered the seen set when the block was *built*, before Hermes merged it
into the turn's message. A turn that died after the hook and before the model call marked that
mail as delivered forever — the agent never saw it and nothing said so.
"""

from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "knok_inbox", Path(__file__).resolve().parents[1] / "__init__.py"
)
hook = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hook)


def _write_inbox(path: Path, ids: list[str]) -> None:
    lines = [
        json.dumps(
            {
                "from": "muse@knok.local",
                "sentAt": f"2026-11-22T06:{n:02d}:00Z",
                "message": {
                    "messageId": message_id,
                    "contextId": f"c-{message_id}",
                    "parts": [{"text": f"body of {message_id}"}],
                },
            }
        )
        for n, message_id in enumerate(ids)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture()
def mailbox(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox.jsonl"
    state = tmp_path / "seen.json"
    monkeypatch.setattr(hook, "INBOX", inbox)
    monkeypatch.setattr(hook, "STATE", state)
    return inbox, state


def _state(path: Path) -> dict:
    return json.loads(path.read_text())


def test_an_injection_is_pending_until_the_conversation_shows_it(mailbox):
    inbox, state = mailbox
    _write_inbox(inbox, ["m-1"])

    assert hook._handle("hi", "telegram", history=[]) is not None

    written = _state(state)
    assert written["seen"] == [], "built is not delivered"
    assert written["pending"]["ids"] == ["m-1"]


def test_it_is_confirmed_once_its_block_is_in_the_history(mailbox):
    inbox, state = mailbox
    _write_inbox(inbox, ["m-1", "m-2"])

    first = hook._handle("hi", "telegram", history=[])
    assert first is not None

    # The next turn carries the previous one, block and all.
    history = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": first + "\nplease answer it"},
    ]
    second = hook._handle("next", "telegram", history=history)

    assert _state(state)["seen"] == ["m-1", "m-2"]
    assert second is None, "nothing left unread"


def test_an_unconfirmed_injection_is_offered_again(mailbox):
    """The turn did not happen: the mail must not be marked delivered."""
    inbox, state = mailbox
    _write_inbox(inbox, ["m-1"])

    first = hook._handle("hi", "telegram", history=[])
    assert first is not None

    # A turn arrives whose history does NOT contain the block — the previous turn died.
    again = hook._handle("next", "telegram", history=[{"role": "user", "content": "next"}])

    assert again is not None and "body of m-1" in again
    assert _state(state)["seen"] == []
    assert _state(state)["pending"]["ids"] == ["m-1"]


def test_an_injection_the_history_cannot_confirm_expires(mailbox, monkeypatch):
    """Compaction can eat the block; after the TTL, believing it beats offering it forever."""
    inbox, state = mailbox
    _write_inbox(inbox, ["m-1"])

    assert hook._handle("hi", "telegram", history=[]) is not None
    written = _state(state)
    written["pending"]["at"] = time.time() - hook.PENDING_TTL_SECONDS - 1
    state.write_text(json.dumps(written), encoding="utf-8")

    assert hook._handle("next", "telegram", history=[{"role": "user", "content": "next"}]) is None
    assert _state(state)["seen"] == ["m-1"], "believed rather than offered forever"


def test_the_turn_that_carried_the_mail_confirms_it(mailbox):
    """`post_llm_call` is the delivery evidence: the block rode that turn's user message.

    It has to be this hook, not the next turn's history — injected context is merged into the
    request and never persisted, so the conversation cannot show it afterwards.
    """
    inbox, state = mailbox
    _write_inbox(inbox, ["m-1"])

    assert hook._handle("hi", "telegram", history=[], session_id="s-1") is not None
    assert _state(state)["seen"] == []

    hook.post_llm_call(session_id="s-1", platform="telegram")

    assert _state(state)["seen"] == ["m-1"]
    assert _state(state)["pending"] is None


def test_another_sessions_turn_cannot_confirm_it(mailbox):
    inbox, state = mailbox
    _write_inbox(inbox, ["m-1"])

    assert hook._handle("hi", "telegram", history=[], session_id="s-1") is not None
    hook.post_llm_call(session_id="s-other", platform="telegram")

    assert _state(state)["seen"] == [], "a cron turn must not mark a chat's mail delivered"
    assert _state(state)["pending"]["ids"] == ["m-1"]
