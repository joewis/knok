"""A retry repeats the attempt, in the thread it started (#48, send/thread half).

Kiko's first-contact test produced the defect: the reply was dropped, the retry after the fix
minted a new ``contextId``, and the conversation restarted instead of continuing. The end-to-end
test below walks exactly that path with the real ``knok send`` against a real hub, and asserts on
the context the *recipient* ends up holding.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from knok.cli import SENT_LEDGER, main
from knok.gate import Gate
from knok.hubclient import HubError
from knok.policy import load as load_policy

from test_phase2 import DOMAIN, deployment


@pytest.fixture
def carl_env(monkeypatch, deployment):
    """Run the real CLI as carl: state dir, registry, agent id and hub url from the environment."""
    hub, bridges, root = deployment
    monkeypatch.setenv("KNOK_AGENT", f"carl@{DOMAIN}")
    monkeypatch.setenv("KNOK_STATE", str(root / "agents" / "carl"))
    monkeypatch.setenv("KNOK_REGISTRY", str(root / "registry"))
    monkeypatch.setenv("KNOK_HUB_URL", hub.url)
    return hub, bridges, root


def ledger(root: Path) -> list[dict]:
    path = root / "agents" / "carl" / SENT_LEDGER
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_send_records_the_attempt_in_the_ledger(carl_env, capsys):
    hub, bridges, root = carl_env
    assert main(["send", "--to", f"muse@{DOMAIN}", "--text", "hello"]) == 0
    printed = json.loads(capsys.readouterr().out)
    entries = ledger(root)
    assert len(entries) == 1
    envelope = entries[0]["envelope"]
    assert envelope["message"]["messageId"] == printed["messageId"]
    assert envelope["message"]["contextId"] == printed["contextId"]
    assert envelope["signature"], "what is stored must be what was signed, not a rebuild of it"


def test_a_retry_reuses_the_thread_it_repeats(carl_env, capsys):
    hub, bridges, root = carl_env
    muse = bridges["muse"]

    assert main(["send", "--to", f"muse@{DOMAIN}", "--text", "did you get this?"]) == 0
    first = json.loads(capsys.readouterr().out)

    # The first attempt never reached her: something between deposit and delivery ate it.
    muse.client.ack([first["messageId"]])

    assert main(["send", "--retry-of", first["messageId"]]) == 0
    retried = json.loads(capsys.readouterr().out)
    assert retried["retried"] is True
    assert retried["contextId"] == first["contextId"], "a retry must not start a new thread"
    assert retried["messageId"] != first["messageId"], (
        "a retry mints a new messageId; the old one is in seen and would be dropped"
    )
    assert retried["retryOf"] == first["messageId"]

    assert muse.poll_once()["queued"] == 1
    delivered = muse.queue.get()
    assert delivered["message"]["contextId"] == first["contextId"]
    assert delivered["message"]["messageId"] == retried["messageId"]
    assert delivered["message"]["metadata"]["retryOf"] == first["messageId"]
    assert delivered["seq"] == ledger(root)[0]["envelope"]["seq"], (
        "the original seq was never consumed, so the retry reuses it; seq+1 would open "
        "an unfillable gap"
    )
    assert len(ledger(root)) == 2, (
        "a retry is a new attempt in the same thread; it grows the ledger by one"
    )


def test_a_retry_of_an_unknown_message_is_refused(carl_env, capsys):
    hub, bridges, root = carl_env
    assert main(["send", "--retry-of", "m-never-sent"]) == 4
    assert "no attempt m-never-sent" in capsys.readouterr().err
    assert ledger(root) == []


def test_send_still_needs_a_recipient_and_a_body(carl_env):
    with pytest.raises(SystemExit) as excinfo:
        main(["send", "--text", "to whom?"])
    assert "needs --to and --text" in str(excinfo.value)


def test_a_failed_deposit_is_still_retryable(carl_env, capsys, monkeypatch):
    """The attempt that never reached the hub is the one a caller most needs to retry."""
    hub, bridges, root = carl_env
    import knok.cli

    real_client = knok.cli.HubClient

    class Unreachable:
        def __init__(self, *args, **kwargs):
            pass

        def deposit(self, envelope):
            raise HubError("connection refused")

    monkeypatch.setattr("knok.cli.HubClient", Unreachable)
    assert main(["send", "--to", f"muse@{DOMAIN}", "--text", "did this leave?"]) == 3
    recorded = ledger(root)
    assert len(recorded) == 1, "a failed deposit must still be on record"
    message_id = recorded[0]["envelope"]["message"]["messageId"]

    # The hub is reachable again: the retry lands a new envelope in the same thread.
    # The failed send printed its own object first (the messageId the caller needs to retry
    # it), so the retry's object is the last line.
    monkeypatch.setattr("knok.cli.HubClient", real_client)
    assert main(["send", "--retry-of", message_id]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    retried = json.loads(lines[-1])
    assert retried["contextId"] == recorded[0]["envelope"]["message"]["contextId"]
    assert retried["messageId"] != message_id, "a retry mints a new messageId"
    assert retried["retryOf"] == message_id


def test_the_end_to_end_incident_one_thread_not_two(carl_env, capsys):
    """Kiko's repro: a dropped message, a retry, and the peer must see one conversation."""
    hub, bridges, root = carl_env
    muse = bridges["muse"]

    # The peer's policy does not admit carl yet — the state Kiko's reply died in (#48).
    path = root / "agents" / "muse" / "policy.json"
    document = json.loads(path.read_text())
    document["allow"] = []
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    policy = load_policy(path)
    muse.policy = policy
    muse.gate = Gate(policy, muse.contacts, muse.threads, muse.rates)

    assert main(["send", "--to", f"muse@{DOMAIN}", "--text", "first contact"]) == 0
    first = json.loads(capsys.readouterr().out)
    refused = muse.poll_once()
    assert refused["refused"] == 1, "the message died at the gate, as it did in the incident"

    # The operator fixes the policy, and the sender retries the attempt that was refused.
    document["allow"] = [f"carl@{DOMAIN}"]
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    policy = load_policy(path)
    muse.policy = policy
    muse.gate = Gate(policy, muse.contacts, muse.threads, muse.rates)

    assert main(["send", "--retry-of", first["messageId"]]) == 0
    retried = json.loads(capsys.readouterr().out)
    assert retried["contextId"] == first["contextId"]
    assert retried["messageId"] != first["messageId"], "a retry mints a new messageId"
    assert retried["retryOf"] == first["messageId"]

    assert muse.poll_once()["queued"] == 1
    delivered = muse.queue.get()
    assert delivered["message"]["contextId"] == first["contextId"]
    assert delivered["message"]["messageId"] == retried["messageId"]
    assert delivered["message"]["metadata"]["retryOf"] == first["messageId"]
    assert muse.poll_once()["queued"] == 0, "one message, one delivery: the retry is a new envelope"
    assert muse.queue.get() is None, "one conversation, not two"
    assert len(ledger(root)) == 2, "the retry is a new attempt in the same thread"

    # The behaviour this replaces, pinned: a fresh `send` mints a new context, which is exactly how
    # the incident split the conversation in two.
    assert main(["send", "--to", f"muse@{DOMAIN}", "--text", "retry the naive way"]) == 0
    naive = json.loads(capsys.readouterr().out)
    assert naive["contextId"] != first["contextId"]
