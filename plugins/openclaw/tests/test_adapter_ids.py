"""The reply id has to be a function of the message, not a fresh uuid.

Two failures meet here. Passing ``--reply-to`` fails the send outright: the CLI dropped the flag in
#37 because the field it emitted is not A2A and the validator rejects it, so an adapter carrying it
works only against an older deployed copy and dies on a fresh clone. And letting ``knok send`` mint
a random ``messageId`` makes the retry path duplicate: a crash between the hub accepting the reply
and the staged file being moved re-sends under a new id, and the peer reads the answer twice. A
derived id makes that second deposit the same message, which the queue dedupes.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ADAPTER = Path(__file__).resolve().parents[1] / "knok_adapter.py"


@pytest.fixture()
def adapter(tmp_path, monkeypatch):
    monkeypatch.setenv("KNOK_ADAPTER_AGENT", "tester@knok.local")
    monkeypatch.setenv("KNOK_ADAPTER_OPENCLAW_AGENT", "tester")
    monkeypatch.setenv("KNOK_ADAPTER_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("KNOK_ADAPTER_INBOX", str(tmp_path / "inbox.jsonl"))
    spec = importlib.util.spec_from_file_location("knok_adapter_under_test", ADAPTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reply_id_is_derived_from_the_message(adapter):
    assert adapter.reply_id_for("m-abc123") == "r-abc123"
    assert adapter.reply_id_for("m-abc123") == adapter.reply_id_for("m-abc123"), "a retry must reuse it"
    assert adapter.reply_id_for("m-abc123") != adapter.reply_id_for("m-abc124")
    assert adapter.reply_id_for("odd-id") == "r-odd-id", "an id without the m- prefix still works"


def test_the_send_carries_the_derived_id_and_no_reply_to(adapter, monkeypatch):
    seen: dict[str, list[str]] = {}

    class Result:
        returncode = 0
        stdout = json.dumps({"accepted": True, "messageId": "r-abc123"})
        stderr = ""

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return Result()

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    adapter.send_reply("muse@knok.local", "c-1", "hello", "r-abc123")

    cmd = seen["cmd"]
    assert cmd[cmd.index("--message-id") + 1] == "r-abc123"
    assert "--reply-to" not in cmd, "the CLI dropped it in #37; passing it fails the send outright"
