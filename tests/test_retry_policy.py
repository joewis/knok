"""The adapter's retry policy: which failures are worth repeating, and when (#48).

The wire half (#56) replays a stored envelope verbatim and the read half (#64) reports which
messages died, but neither says *when* a retry is the right move. This is that policy: a rate
limit is transient, so a replay after the window clears should succeed; a policy refusal, a
thread refusal, a malformed message, an expiry and a dead letter will not change by waiting, so
repeating them is noise. The policy reads the notice, the stored attempt and the retry ledger,
and says retry, waiting or terminal — never a fresh contextId, never beyond the budget.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from knok.bridge import NOTICES
from knok.cli import SENT_LEDGER, main
from knok.retry import (
    BACKOFF_LIMITS,
    BACKOFF_UNREACHABLE,
    MAX_RETRIES,
    RETRY_LEDGER,
    Decision,
    decide_notice,
    decide_send,
    due,
    read_notices,
    read_retries,
    record_retry,
    retry_count,
    terminal_decided,
)

from test_phase2 import DOMAIN, deployment
from test_notices_cli import record as record_notice

#: The unit tests decide against this fixed clock, so the table is exact. The CLI tests below
#: use the real clock instead: ``knok retry`` reads ``datetime.now``, and a fixed stamp would
#: drift from due to waiting depending on when the suite runs.
NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def envelope(message_id: str, **overrides) -> dict:
    """A stored attempt: the envelope ``send`` recorded, with a 72h TTL like the default."""
    record = {
        "recordedAt": _iso(NOW - timedelta(hours=1)),
        "envelope": {
            "from": f"carl@{DOMAIN}",
            "message": {
                "messageId": message_id,
                "contextId": "c-1",
                "kind": "message",
                "from": f"carl@{DOMAIN}",
                "to": f"muse@{DOMAIN}",
                "created": _iso(NOW - timedelta(hours=1)),
                "body": {"text": "hello"},
            },
            "sentAt": _iso(NOW - timedelta(hours=1)),
            "expiresAt": _iso(NOW + timedelta(hours=71)),
            "signature": "a-signature",
        },
    }
    record.update(overrides)
    return record


def notice(message_id: str, kind: str = "refused", **overrides) -> dict:
    record = {
        "kind": kind,
        "from": f"muse@{DOMAIN}",
        "receivedAt": _iso(NOW - timedelta(hours=2)),
        "messageId": message_id,
        "contextId": "c-1",
        "rule": "limits",
    }
    record.update(overrides)
    return record


def live_envelope(message_id: str, **overrides) -> dict:
    """An attempt stamped against the real clock, for the CLI tests."""
    record = envelope(message_id)
    record["recordedAt"] = _iso(_now() - timedelta(hours=1))
    record["envelope"]["message"]["created"] = _iso(_now() - timedelta(hours=1))
    record["envelope"]["sentAt"] = _iso(_now() - timedelta(hours=1))
    record["envelope"]["expiresAt"] = _iso(_now() + timedelta(hours=71))
    record.update(overrides)
    return record


def live_notice(message_id: str, kind: str = "refused", received_hours_ago: float = 2, **overrides) -> dict:
    """A notice stamped against the real clock, for the CLI tests."""
    record = notice(message_id, kind=kind)
    record["receivedAt"] = _iso(_now() - timedelta(hours=received_hours_ago))
    record.update(overrides)
    return record


#: The decision table, one row per notice kind/rule: the verdict the policy must give, and the
#: attempt number the next retry would be. A row here is a promise the adapter keeps.
TABLE = [
    # kind, rule, action, attempt
    ("refused", "limits", "retry", 1),
    ("refused", "policy", "terminal", 0),
    ("refused", "thread", "terminal", 0),
    ("refused", "malformed", "terminal", 0),
    ("refused", "blocked", "terminal", 0),
    ("refused", None, "terminal", 0),
    ("refused", "unknown-rule", "terminal", 0),
    ("expired", None, "terminal", 0),
    ("dead", None, "terminal", 0),
    ("late", None, "terminal", 0),
    ("gap", None, "terminal", 0),
]


@pytest.mark.parametrize("kind,rule,action,attempt", TABLE)
def test_the_decision_table(kind, rule, action, attempt):
    decision = decide_notice(notice("m-50", kind=kind, rule=rule), envelope("m-50")["envelope"], [], NOW)
    assert decision.action == action, f"{kind}/{rule} must be {action}"
    assert decision.attempt == attempt
    assert decision.reason, "a decision without a reason is not auditable"


def test_a_rate_limit_retry_waits_for_the_window_to_clear():
    # The notice carries only the rule, not which window fired, so the first retry waits an hour
    # (the hourly window) and the second a day (the daily window).
    first = decide_notice(notice("m-50"), envelope("m-50")["envelope"], [], NOW)
    assert first.action == "retry"
    assert first.not_before == NOW - timedelta(hours=2) + BACKOFF_LIMITS[0]
    assert due(first, NOW), "the notice is two hours old; the first retry is due"

    retries = [{"messageId": "m-50", "decision": "retry", "attempt": 1}]
    second = decide_notice(notice("m-50"), envelope("m-50")["envelope"], retries, NOW)
    assert second.action == "retry"
    assert second.attempt == 2
    assert second.not_before == NOW - timedelta(hours=2) + BACKOFF_LIMITS[1]
    assert not due(second, NOW), "the second retry is due a day after the notice, not yet"


def test_a_retry_is_terminal_once_the_budget_is_spent():
    retries = [
        {"messageId": "m-50", "decision": "retry", "attempt": 1},
        {"messageId": "m-50", "decision": "retry", "attempt": 2},
    ]
    assert retry_count(retries, "m-50") == MAX_RETRIES
    decision = decide_notice(notice("m-50"), envelope("m-50")["envelope"], retries, NOW)
    assert decision.action == "terminal"
    assert "budget" in decision.reason


def test_a_retry_is_terminal_when_the_envelope_expires_first():
    # The notice is fresh, so the first retry is due an hour after it — but the envelope
    # expires in thirty minutes, before the retry is due. Repeating it buys nothing.
    attempt = envelope("m-50")
    attempt["envelope"]["expiresAt"] = _iso(NOW + timedelta(minutes=30))
    fresh = notice("m-50", receivedAt=_iso(NOW))
    decision = decide_notice(fresh, attempt["envelope"], [], NOW)
    assert decision.action == "terminal"
    assert "expir" in decision.reason


def test_no_stored_attempt_means_no_retry():
    decision = decide_notice(notice("m-50"), None, [], NOW)
    assert decision.action == "terminal"
    assert "no stored attempt" in decision.reason


def test_a_notice_with_no_message_id_is_not_a_retry():
    record = notice("m-50")
    del record["messageId"]
    decision = decide_notice(record, envelope("m-50")["envelope"], [], NOW)
    assert decision.action == "terminal"


def test_a_gap_has_no_message_id_and_is_not_a_send_retry():
    record = {
        "kind": "gap",
        "from": f"muse@{DOMAIN}",
        "to": f"carl@{DOMAIN}",
        "contextId": "c-5",
        "missing": [3, 4, 5],
        "releasedAt": _iso(NOW),
    }
    decision = decide_notice(record, envelope("m-50")["envelope"], [], NOW)
    assert decision.action == "terminal"
    assert "RESEND" in decision.reason


#: The send-time half: what a failed deposit means for the retry.
SEND_TABLE = [
    # exit code, action, attempt, backoff
    (3, "retry", 1, BACKOFF_UNREACHABLE[0]),
    (2, "terminal", 0, None),
    (0, "terminal", 0, None),
    (4, "terminal", 0, None),
]


@pytest.mark.parametrize("status,action,attempt,backoff", SEND_TABLE)
def test_decide_send(status, action, attempt, backoff):
    # The attempt was sent just now, so the backoff is dated from now.
    record = envelope("m-50")
    record["envelope"]["sentAt"] = _iso(NOW)
    decision = decide_send(status, record["envelope"], [], NOW)
    assert decision.action == action
    assert decision.attempt == attempt
    if backoff is None:
        assert decision.not_before is None
    else:
        assert decision.not_before == NOW + backoff


def test_an_unreachable_send_backs_off_like_the_poison_ladder():
    record = envelope("m-50")
    record["envelope"]["sentAt"] = _iso(NOW)
    first = decide_send(3, record["envelope"], [], NOW)
    assert first.not_before == NOW + BACKOFF_UNREACHABLE[0]
    retries = [{"messageId": "m-50", "decision": "retry", "attempt": 1}]
    second = decide_send(3, record["envelope"], retries, NOW)
    assert second.attempt == 2
    assert second.not_before == NOW + BACKOFF_UNREACHABLE[1]
    assert due(second, NOW + BACKOFF_UNREACHABLE[1])


def test_due_needs_a_time_and_that_time_to_have_passed():
    assert due(Decision(action="retry", reason="x", not_before=None, attempt=1), NOW), (
        "no not_before means due now"
    )
    assert not due(
        Decision(action="retry", reason="x", not_before=NOW + timedelta(hours=1), attempt=1), NOW
    )
    assert due(
        Decision(action="retry", reason="x", not_before=NOW, attempt=1), NOW
    ), "the exact due instant is due, not after it"


def test_the_ledger_counts_retries_and_records_a_terminal(tmp_path):
    directory = tmp_path / "agent"
    directory.mkdir()
    assert read_retries(directory) == []
    assert retry_count([], "m-50") == 0
    assert not terminal_decided([], "m-50")

    record = {
        "messageId": "m-50",
        "contextId": "c-1",
        "kind": "refused",
        "rule": "limits",
        "attempt": 1,
        "at": _iso(NOW),
        "decision": "retry",
        "reason": "a rate limit is transient",
    }
    assert record_retry(directory, record) is True
    assert retry_count(read_retries(directory), "m-50") == 1

    terminal = {**record, "attempt": 0, "decision": "terminal", "reason": "the budget is spent"}
    assert record_retry(directory, terminal) is True
    assert terminal_decided(read_retries(directory), "m-50")
    assert len(read_retries(directory)) == 2


def test_a_torn_retry_line_does_not_hide_the_rest(tmp_path):
    directory = tmp_path / "agent"
    directory.mkdir()
    record_retry(directory, {"messageId": "m-50", "decision": "retry", "attempt": 1})
    with open(directory / RETRY_LEDGER, "a", encoding="utf-8") as handle:
        handle.write('{"messageId": "m-5\n')  # crash mid-append
    record_retry(directory, {"messageId": "m-51", "decision": "retry", "attempt": 1})
    records = read_retries(directory)
    assert [record["messageId"] for record in records] == ["m-50", "m-51"]


@pytest.fixture
def state(monkeypatch, tmp_path):
    """A bare agent state dir, with a notice and a stored attempt the policy can decide on."""
    directory = tmp_path / "agent"
    directory.mkdir()
    monkeypatch.setenv("KNOK_STATE", str(directory))
    return directory


def write_attempt(directory: Path, record: dict) -> None:
    with open(directory / SENT_LEDGER, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def test_dry_run_reports_without_recording(state, capsys):
    record_notice(state, live_notice("m-50"))
    write_attempt(state, live_envelope("m-50"))
    assert main(["retry", "--dry-run"]) == 0
    line = capsys.readouterr().out.strip()
    assert "would retry m-50 (attempt 1)" in line
    assert not (state / RETRY_LEDGER).exists(), "a dry run records nothing"


def test_a_scan_that_cannot_retry_still_records_its_terminal_decisions(state, capsys):
    """Two phases: deciding needs no hub, so a missing identity must not lose the terminal
    decisions. The due retry is reported as not performed, and the scan exits 1."""
    record_notice(state, live_notice("m-50", rule="policy"))
    record_notice(state, live_notice("m-51", rule="limits"))
    write_attempt(state, live_envelope("m-50"))
    write_attempt(state, live_envelope("m-51"))
    assert main(["retry"]) == 1
    out, err = capsys.readouterr()
    assert "terminal m-50" in out
    assert "would retry m-51 (attempt 1)" in out
    assert "cannot retry" in err
    records = read_retries(state)
    assert len(records) == 1, "only the terminal decision is recorded; the retry never ran"
    assert records[0]["messageId"] == "m-50"
    assert records[0]["decision"] == "terminal"


def test_a_terminal_decision_is_recorded_and_not_redecided(state, capsys):
    record_notice(state, live_notice("m-50", rule="policy"))
    write_attempt(state, live_envelope("m-50"))
    assert main(["retry"]) == 0
    assert "terminal m-50" in capsys.readouterr().out
    records = read_retries(state)
    assert len(records) == 1
    assert records[0]["decision"] == "terminal"
    assert records[0]["rule"] == "policy"

    # The second scan reports the same decision but records nothing new.
    assert main(["retry"]) == 0
    assert "terminal m-50" in capsys.readouterr().out
    assert len(read_retries(state)) == 1


def test_a_waiting_retry_is_reported_and_not_recorded(state, capsys):
    # The notice is ten minutes old: the first retry is due an hour after it, not yet.
    record_notice(state, live_notice("m-50", received_hours_ago=1 / 6))
    write_attempt(state, live_envelope("m-50"))
    assert main(["retry", "--dry-run"]) == 0
    assert "waiting m-50" in capsys.readouterr().out
    assert not (state / RETRY_LEDGER).exists()


def test_message_id_with_no_notice_is_not_an_error(state, capsys):
    assert main(["retry", "--message-id", "m-never-sent"]) == 0
    assert "no delivery notice for m-never-sent" in capsys.readouterr().err


def test_json_is_one_object_per_message_decided(state, capsys):
    record_notice(state, live_notice("m-50", rule="policy"))
    record_notice(state, live_notice("m-51", kind="expired", rule=None))
    write_attempt(state, live_envelope("m-50"))
    write_attempt(state, live_envelope("m-51"))
    assert main(["retry", "--json"]) == 0
    outcomes = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(outcomes) == 2
    assert [outcome["messageId"] for outcome in outcomes] == ["m-50", "m-51"]
    assert all(outcome["decision"] == "terminal" for outcome in outcomes)
    assert outcomes[0]["rule"] == "policy"
    assert outcomes[1]["kind"] == "expired"


def test_scan_takes_the_latest_notice_per_message(state, capsys):
    # Two notices for one message: the policy decides on the latest, not the first.
    record_notice(state, live_notice("m-50", rule="limits"))
    record_notice(state, live_notice("m-50", rule="policy", received_hours_ago=0))
    write_attempt(state, live_envelope("m-50"))
    assert main(["retry", "--json"]) == 0
    outcomes = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(outcomes) == 1
    assert outcomes[0]["rule"] == "policy"
    assert outcomes[0]["decision"] == "terminal"


@pytest.fixture
def carl_env(monkeypatch, deployment):
    """The real CLI as carl, against the real hub and bridges."""
    hub, bridges, root = deployment
    monkeypatch.setenv("KNOK_AGENT", f"carl@{DOMAIN}")
    monkeypatch.setenv("KNOK_STATE", str(root / "agents" / "carl"))
    monkeypatch.setenv("KNOK_REGISTRY", str(root / "registry"))
    monkeypatch.setenv("KNOK_HUB_URL", hub.url)
    return hub, bridges, root


def test_a_rate_limit_refusal_is_retried_when_the_window_clears(carl_env, capsys):
    """End to end: a refused/limits notice, a due retry, one replayed envelope, one thread.

    The first attempt is deposited and acked away (it never reached the peer, the state #48
    describes); the bridge records the rate-limit refusal; ``knok retry`` replays the stored
    envelope verbatim, and the peer receives the message in the thread the first attempt opened.
    """
    hub, bridges, root = carl_env
    muse = bridges["muse"]

    assert main(["send", "--to", f"muse@{DOMAIN}", "--text", "did you get this?"]) == 0
    first = json.loads(capsys.readouterr().out)

    # The first attempt never reached her: something between deposit and delivery ate it.
    muse.client.ack([first["messageId"]])

    # The bridge records the refusal, two hours ago — past the first hour's backoff, so the
    # retry is due now.
    state = root / "agents" / "carl"
    record_notice(
        state,
        {
            "kind": "refused",
            "from": f"muse@{DOMAIN}",
            "receivedAt": _iso(_now() - timedelta(hours=2)),
            "messageId": first["messageId"],
            "contextId": first["contextId"],
            "rule": "limits",
        },
    )

    assert main(["retry"]) == 0
    line = capsys.readouterr().out.strip()
    assert f"retried {first['messageId']} (attempt 1): accepted" in line

    records = read_retries(state)
    assert len(records) == 1
    assert records[0]["decision"] == "retry"
    assert records[0]["attempt"] == 1
    assert records[0]["rule"] == "limits"

    assert muse.poll_once()["queued"] == 1
    delivered = muse.queue.get()
    assert delivered["message"]["messageId"] == first["messageId"]
    assert delivered["message"]["contextId"] == first["contextId"]

    attempts = [json.loads(line) for line in (state / SENT_LEDGER).read_text().splitlines()]
    assert len(attempts) == 1, "a retry is not a new attempt; it must not grow the ledger"
