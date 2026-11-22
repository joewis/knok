"""The wake rules: one turn per burst, never for mail the injector already has, never a record
for a turn the host did not open.

These pin the behaviour that made mail invisible before the plugin existed: nothing started a
turn when a message arrived, so mail waited for Jörg's next message (measured 36-73 minutes).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_spec = importlib.util.spec_from_file_location(
    "knok_wake", Path(__file__).resolve().parents[1] / "__init__.py"
)
wake = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wake)


def _row(message_id: str, text: str = "hello") -> dict:
    return {
        "from": "muse@knok.local",
        "message": {
            "messageId": message_id,
            "contextId": "c-1",
            "parts": [{"kind": "text", "text": text}],
        },
    }


def _write(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class Host:
    """Stands in for PluginContext: records what the plugin asked it to open."""

    def __init__(self, accept: bool = True) -> None:
        self.accept = accept
        self.calls: list[tuple[str, dict]] = []

    def inject_message(self, content: str, origin: dict) -> bool:
        self.calls.append((content, dict(origin)))
        return self.accept


@pytest.fixture()
def paths(tmp_path, monkeypatch):
    inbox = tmp_path / "inbox.jsonl"
    seen = tmp_path / "seen.json"
    state = tmp_path / "wake.json"
    monkeypatch.setattr(wake, "INBOX", inbox)
    monkeypatch.setattr(wake, "SEEN_STATE", seen)
    monkeypatch.setattr(wake, "STATE", state)
    return inbox, seen, state


def test_a_burst_is_one_wake_after_it_settles(paths):
    inbox, seen, _state = paths
    now = time.time()
    _write(inbox, [_row("m-1"), _row("m-2"), _row("m-3")])
    seen.write_text(json.dumps({"seen": []}), encoding="utf-8")
    host = Host()

    # Still arriving: the quiet window has not passed.
    assert wake.tick(host, now=now) == 0
    assert host.calls == []

    # Settled: one turn for all three, not three turns.
    assert wake.tick(host, now=now + wake.QUIET_SECONDS + 1) == 3
    assert len(host.calls) == 1
    assert "m-1, m-2, m-3" in host.calls[0][0]


def test_mail_the_injector_already_showed_is_not_a_wake(paths):
    inbox, seen, _state = paths
    now = time.time()
    _write(inbox, [_row("m-1"), _row("m-2")])
    seen.write_text(json.dumps({"seen": ["m-1", "m-2"]}), encoding="utf-8")
    host = Host()

    assert wake.tick(host, now=now + wake.QUIET_SECONDS + 1) == 0
    assert host.calls == []


def test_no_second_wake_inside_the_gap(paths):
    inbox, seen, _state = paths
    now = time.time()
    _write(inbox, [_row("m-1")])
    seen.write_text(json.dumps({"seen": []}), encoding="utf-8")
    host = Host()

    assert wake.tick(host, now=now + wake.QUIET_SECONDS + 1) == 1
    # A new message arrives a moment later: same turn, not another one.
    _write(inbox, [_row("m-1"), _row("m-2")])
    assert wake.tick(host, now=now + wake.QUIET_SECONDS + 5) == 0
    assert len(host.calls) == 1


def test_a_refused_wake_is_not_remembered(paths):
    """No record for a turn the host did not open — the next pass must try again."""
    inbox, seen, state = paths
    now = time.time()
    _write(inbox, [_row("m-1")])
    seen.write_text(json.dumps({"seen": []}), encoding="utf-8")

    assert wake.tick(Host(accept=False), now=now + wake.QUIET_SECONDS + 1) == 0
    assert not state.exists(), "a refusal wrote no state"

    assert wake.tick(Host(accept=True), now=now + wake.QUIET_SECONDS + 2) == 1


def test_unread_mail_is_retried_once_a_wake_goes_stale(paths):
    inbox, seen, _state = paths
    now = time.time()
    _write(inbox, [_row("m-1")])
    seen.write_text(json.dumps({"seen": []}), encoding="utf-8")
    host = Host()

    assert wake.tick(host, now=now + wake.QUIET_SECONDS + 1) == 1
    later = now + wake.QUIET_SECONDS + wake.RETRY_AFTER_SECONDS + wake.MIN_GAP_SECONDS + 2
    assert wake.tick(host, now=later) == 1, "still unread and the wake went stale: try again"
    assert len(host.calls) == 2


def test_the_wake_names_the_session_it_belongs_to(paths, monkeypatch):
    monkeypatch.setattr(wake, "ORIGIN", {"platform": "telegram", "chat_id": "12345"})
    inbox, seen, _state = paths
    now = time.time()
    _write(inbox, [_row("m-1")])
    seen.write_text(json.dumps({"seen": []}), encoding="utf-8")
    host = Host()

    wake.tick(host, now=now + wake.QUIET_SECONDS + 1)
    content, origin = host.calls[0]
    assert origin == {"platform": "telegram", "chat_id": "12345"}, "the configured chat, not a guess"
    assert "knok-inbox" in content, "the turn is told where the mail comes from"


def test_mail_in_flight_is_not_woken_again(paths):
    """Pending means "a turn already carries this": waking again duplicates the turn.

    Observed: the same message started three turns ten minutes apart while it waited for the
    injector to confirm it, because the wake only knew about `seen`.
    """
    inbox, seen, _state = paths
    now = time.time()
    _write(inbox, [_row("m-1")])
    seen.write_text(json.dumps({"seen": [], "pending": {"ids": ["m-1"], "at": now}}),
                    encoding="utf-8")
    host = Host()

    assert wake.tick(host, now=now + wake.QUIET_SECONDS + 1) == 0
    assert host.calls == []
