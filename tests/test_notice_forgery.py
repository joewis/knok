"""Peer-controlled notice fields must not forge terminal or log lines (#123).

A pinned peer can send a signed envelope carrying ``metadata["knok.notice"]``. The handler used to
check only that ``messageId`` was a string, and copied ``contextId`` and ``rule`` without any
check; the values were then interpolated into a terminal line (``knok notices``) and into bridge
log lines with plain ``%s``. A newline in a peer-supplied field made one notice print as several
lines, including text resembling a second event. The JSONL file itself was never at risk — the
encoder escapes newlines — so the fix is at the two human-facing boundaries:

* the notice boundary validates each field: a string, printable, and bounded; anything else is a
  malformed notice — acked, not recorded, like the existing malformed path;
* every log line and terminal row that interpolates a peer value escapes control characters first,
  so even a value that arrives through another path stays on one line.
"""

from __future__ import annotations

import logging

from knok.bridge import NOTICE_KEY, safe_log_text
from knok.cli import _notice_line

from test_phase2 import deployment, send  # noqa: F401  (fixture used by name)
from test_refusal_notice import apply_policy, notices_of, policy_path, rewrite


def notice_item(sender_id, message_id, notice):
    """A signed-looking notice envelope, the way one arrives from a pinned peer."""
    return {
        "from": sender_id,
        "message": {
            "kind": "message",
            "messageId": message_id,
            "contextId": "c-notice",
            "role": "agent",
            "parts": [{"kind": "text", "text": "refused"}],
            "metadata": {NOTICE_KEY: notice},
        },
    }


def test_a_notice_with_a_newline_in_its_message_id_is_ignored(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    item = notice_item(
        muse.identity.agent_id,
        "r-newline",
        {"kind": "refused", "messageId": "m-x\nFORGED: muse refused m-y", "rule": "policy"},
    )
    outcome, message_id = carl._handle_refusal_notice(
        item, muse.identity.agent_id, item["message"]["metadata"][NOTICE_KEY]
    )
    assert (outcome, message_id) == ("refused", "r-newline"), "acked, not re-offered forever"
    assert notices_of(root, "carl") == [], "a forged id must not reach notices.jsonl"


def test_a_notice_with_control_characters_in_context_or_rule_is_ignored(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    for bad in (
        {"kind": "refused", "messageId": "m-x", "contextId": "c-1\nsecond line", "rule": "policy"},
        {"kind": "refused", "messageId": "m-x", "contextId": "c-1", "rule": "limits\tescaped"},
        {"kind": "refused", "messageId": "m-x", "contextId": "c-1", "rule": "policy\x07bell"},
    ):
        item = notice_item(muse.identity.agent_id, "r-control", bad)
        outcome, _ = carl._handle_refusal_notice(
            item, muse.identity.agent_id, item["message"]["metadata"][NOTICE_KEY]
        )
        assert outcome == "refused"
    assert notices_of(root, "carl") == []


def test_an_overlong_notice_field_is_ignored(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    item = notice_item(
        muse.identity.agent_id,
        "r-long",
        {"kind": "refused", "messageId": "m-" + "x" * 300, "rule": "policy"},
    )
    outcome, _ = carl._handle_refusal_notice(
        item, muse.identity.agent_id, item["message"]["metadata"][NOTICE_KEY]
    )
    assert outcome == "refused"
    assert notices_of(root, "carl") == []


def test_a_plain_valid_notice_is_still_recorded(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    item = notice_item(
        muse.identity.agent_id,
        "r-ok",
        {"kind": "refused", "messageId": "m-ok", "contextId": "c-ok", "rule": "policy"},
    )
    outcome, message_id = carl._handle_refusal_notice(
        item, muse.identity.agent_id, item["message"]["metadata"][NOTICE_KEY]
    )
    assert (outcome, message_id) == ("notices", "r-ok")
    assert [notice["messageId"] for notice in notices_of(root, "carl")] == ["m-ok"]


def test_safe_log_text_keeps_one_line():
    assert safe_log_text("m-x\nFORGED: second event") == "m-x\\u000aFORGED: second event"
    assert safe_log_text("a\tb\x07c") == "a\\u0009b\\u0007c"
    assert safe_log_text("plain id") == "plain id"
    assert safe_log_text(None) == "-"
    assert safe_log_text("x" * 300) == "x" * 256 + "…"
    assert "\n" not in safe_log_text("line1\nline2")


def test_a_notice_line_never_spans_lines():
    line = _notice_line(
        {
            "kind": "refused",
            "from": "muse@bridge.example",
            "receivedAt": "2026-11-21T00:00:00Z",
            "messageId": "m-x\nFORGED: carl refused m-y (policy)",
            "contextId": "c-1\nsecond line",
            "rule": "policy\ninjected",
        }
    )
    assert "\n" not in line, "one notice is one terminal line, whatever the peer sent"
    assert "FORGED" in line, "the value is still visible, escaped rather than dropped"
    assert "\\u000a" in line


def test_a_gate_refusal_log_line_escapes_the_peer_message_id(deployment, caplog):
    """The same class of issue in the bridge's own logs: a messageId with a newline."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    rewrite(root, "muse", block=[], allow=[])
    apply_policy(muse, policy_path(root, "muse"))
    send(carl, muse.identity.agent_id, "refuse me", message_id="m-evil\nFORGED gate refused m-other")

    with caplog.at_level(logging.INFO, logger="knok.bridge"):
        assert muse.poll_once()["refused"] == 1

    refused = [record for record in caplog.records if "gate refused" in record.getMessage()]
    assert refused, "the refusal must be logged"
    assert "\n" not in refused[0].getMessage(), "the log line must stay one line"
    assert "m-evil\\u000aFORGED" in refused[0].getMessage()
