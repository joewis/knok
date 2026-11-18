import json

import pytest

from knok.policy import PolicyError, load, parse

BASE = {
    "agent_id": "carl@bridge.example",
    "contact_policy": "request",
    "allow": ["muse@bridge.example"],
    "block": [],
    "limits": {"contact_requests_per_day": 20, "messages_per_hour": 100},
}


def test_parses_a_valid_policy():
    policy = parse(BASE)
    assert policy.agent_id == "carl@bridge.example"
    assert policy.may_send("muse@bridge.example")
    assert not policy.may_send("mallory@bridge.example")


def test_unknown_key_is_fatal():
    with pytest.raises(PolicyError, match="unknown policy keys"):
        parse({**BASE, "rate_limits": {}})


def test_unknown_limit_is_fatal():
    with pytest.raises(PolicyError, match="unknown limit"):
        parse({**BASE, "limits": {"messages_per_day": 1}})


def test_open_contact_policy_is_refused():
    with pytest.raises(PolicyError, match="contact_policy"):
        parse({**BASE, "contact_policy": "open"})


def test_invalid_agent_id_is_fatal():
    with pytest.raises(PolicyError):
        parse({**BASE, "agent_id": "carl@host@nope"})


def test_block_overrides_allow():
    policy = parse({**BASE, "block": ["muse@bridge.example"]})
    assert not policy.may_send("muse@bridge.example")


def test_missing_file_reports_clearly(tmp_path):
    with pytest.raises(PolicyError, match="cannot read policy"):
        load(tmp_path / "nope.json")


def test_invalid_json_reports_clearly(tmp_path):
    path = tmp_path / "p.json"
    path.write_text("{not json")
    with pytest.raises(PolicyError, match="not valid JSON"):
        load(path)
