"""`knok notices`: the sender reads the failures the bridge already recorded (#48).

`knok send` exits 0 once the hub has the envelope, and what happens after that — a gate refusal, an
expiry, a dead letter — is written to the sender's own ``notices.jsonl`` by its bridge. Until now
nothing read that file: the signal existed on disk and reached no caller. This command is the
sender's read half; the end-to-end test shows the loop closing into ``send --retry-of``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from knok.bridge import NOTICES
from knok.cli import main

from test_phase2 import DOMAIN, deployment
from test_refusal_notice import apply_policy, policy_path, rewrite


@pytest.fixture
def state(monkeypatch, tmp_path):
    """A bare agent state dir: these tests write the notices themselves."""
    directory = tmp_path / "agent"
    directory.mkdir()
    monkeypatch.setenv("KNOK_STATE", str(directory))
    return directory


def record(directory: Path, notice: dict) -> None:
    with open(directory / NOTICES, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(notice, sort_keys=True) + "\n")


def refusal(message_id: str, **overrides) -> dict:
    notice = {
        "kind": "refused",
        "from": f"muse@{DOMAIN}",
        "receivedAt": "2026-11-19T20:00:00Z",
        "messageId": message_id,
        "contextId": "c-1",
        "rule": "policy",
    }
    notice.update(overrides)
    return notice


def test_no_notices_yet_is_reported_as_such(state, capsys):
    assert main(["notices"]) == 0
    out, err = capsys.readouterr()
    assert out == ""
    assert "no delivery notices" in err


def test_an_empty_file_is_not_a_failure(state, capsys):
    (state / NOTICES).write_text("")
    assert main(["notices"]) == 0
    assert "no delivery notices" in capsys.readouterr().err


def test_a_refusal_is_readable_by_a_human(state, capsys):
    record(state, refusal("m-50"))
    assert main(["notices"]) == 0
    line = capsys.readouterr().out.strip()
    for expected in ("2026-11-19T20:00:00Z", f"muse@{DOMAIN}", "m-50", "[c-1]", "refused (policy)"):
        assert expected in line


def test_json_is_the_record_the_bridge_wrote(state, capsys):
    record(state, refusal("m-50"))
    assert main(["notices", "--json"]) == 0
    printed = capsys.readouterr().out.splitlines()
    assert len(printed) == 1
    assert json.loads(printed[0]) == refusal("m-50")


def test_an_expired_frame_has_no_rule_and_still_prints(state, capsys):
    # The hub's own frame is a failure too, and it uses the hub's field names — no `rule`, no
    # `receivedAt`. A reader that assumed the refusal shape would print `?` for half the line.
    record(
        state,
        {
            "kind": "expired",
            "from": f"muse@{DOMAIN}",
            "messageId": "m-51",
            "contextId": "c-2",
            "expiredAt": "2026-11-19T21:00:00Z",
        },
    )
    assert main(["notices"]) == 0
    line = capsys.readouterr().out.strip()
    assert "2026-11-19T21:00:00Z" in line
    assert "m-51" in line
    assert "expired" in line
    assert "(" not in line


def test_kind_selects_one_sort_of_failure(state, capsys):
    record(state, refusal("m-50"))
    record(
        state,
        {"kind": "expired", "from": f"muse@{DOMAIN}", "messageId": "m-51", "contextId": "c-2"},
    )
    assert main(["notices", "--kind", "expired", "--json"]) == 0
    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [notice["messageId"] for notice in printed] == ["m-51"]

    assert main(["notices", "--kind", "dead"]) == 0
    assert "no dead notices" in capsys.readouterr().err


def test_limit_keeps_the_newest(state, capsys):
    for index in range(3):
        record(state, refusal(f"m-{index}"))
    assert main(["notices", "--limit", "2", "--json"]) == 0
    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [notice["messageId"] for notice in printed] == ["m-1", "m-2"]


def test_a_nonpositive_limit_is_a_usage_error(state, capsys):
    # ``selected[-limit:]`` with limit 0 is ``selected[0:]`` — everything — and a negative limit
    # silently drops notices from the front. Both are usage errors, not ways to ask for notices.
    for index in range(3):
        record(state, refusal(f"m-{index}"))
    for bad in ("0", "-1"):
        assert main(["notices", "--limit", bad, "--json"]) == 2
        out, err = capsys.readouterr()
        assert out == ""
        assert f"--limit must be at least 1, got {bad}" in err


def test_a_torn_line_does_not_hide_the_rest(state, capsys):
    record(state, refusal("m-50"))
    with open(state / NOTICES, "a", encoding="utf-8") as handle:
        handle.write('{"kind": "refused", "messageId": "m-5\n')  # crash mid-append
    record(state, refusal("m-52"))
    assert main(["notices", "--json"]) == 0
    out, err = capsys.readouterr()
    assert [json.loads(line)["messageId"] for line in out.splitlines()] == ["m-50", "m-52"]
    assert "1 unreadable line" in err


@pytest.fixture
def carl_env(monkeypatch, deployment):
    """The real CLI as carl, against the real hub and bridges."""
    hub, bridges, root = deployment
    monkeypatch.setenv("KNOK_AGENT", f"carl@{DOMAIN}")
    monkeypatch.setenv("KNOK_STATE", str(root / "agents" / "carl"))
    monkeypatch.setenv("KNOK_REGISTRY", str(root / "registry"))
    monkeypatch.setenv("KNOK_HUB_URL", hub.url)
    return hub, bridges, root


def test_the_notice_names_the_id_a_retry_takes(carl_env, capsys):
    """The whole loop: refused, read, retried — one message, one thread.

    This is the defect #48 describes in one test: the refusal is no longer silent, and the id it
    reports is exactly the argument ``--retry-of`` needs, so the retry continues the thread the
    first attempt opened instead of starting a second one.
    """
    hub, bridges, root = carl_env
    carl, muse = bridges["carl"], bridges["muse"]

    rewrite(root, "muse", allow=[], block=[])
    apply_policy(muse, policy_path(root, "muse"))

    assert main(["send", "--to", muse.identity.agent_id, "--text", "did you get this?"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert muse.poll_once()["refused"] == 1

    # carl's bridge is handed the peer's notice and writes it; the command reads that, not a copy.
    assert carl.poll_once()["notices"] == 1
    assert main(["notices", "--json"]) == 0
    notices = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [notice["messageId"] for notice in notices] == [first["messageId"]]
    assert notices[0]["contextId"] == first["contextId"]
    assert notices[0]["rule"] == "policy"
    assert notices[0]["from"] == muse.identity.agent_id

    rewrite(root, "muse", allow=[carl.identity.agent_id])
    apply_policy(muse, policy_path(root, "muse"))
    assert main(["send", "--retry-of", notices[0]["messageId"]]) == 0
    retried = json.loads(capsys.readouterr().out)
    assert retried["contextId"] == first["contextId"], "a retry keeps the thread it repeats"

    assert muse.poll_once()["queued"] == 1
    delivered = muse.queue.get()
    assert delivered["message"]["messageId"] == first["messageId"]
    assert delivered["message"]["contextId"] == first["contextId"]
