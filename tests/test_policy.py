import pytest

from knok.policy import PolicyError, load, parse

BASE = {
    "agent_id": "carl@bridge.example",
    "contact_policy": "closed",
    "allow": ["muse@bridge.example"],
    "block": [],
    "limits": {"messages_per_hour": 100, "per_sender_per_hour": 20},
}


def test_parses_a_valid_policy():
    policy = parse(BASE)
    assert policy.agent_id == "carl@bridge.example"
    assert "muse@bridge.example" in policy.allow
    assert policy.direct_delivery is False


def test_unknown_key_is_fatal():
    with pytest.raises(PolicyError, match="unknown policy keys"):
        parse({**BASE, "rate_limits": {}})


def test_unknown_limit_is_fatal():
    with pytest.raises(PolicyError, match="unknown limit"):
        parse({**BASE, "limits": {"messages_per_minute": 1}})


def test_probation_key_is_rejected():
    # #119: the policy file carried a `probation` flag no gate decision ever read, so an
    # operator could set it and believe probation limits were enforced when nothing was.
    # §9 puts the probation flag in the Agent Card's `bridge` extension, not in the policy
    # file, so the parser rejects it like any other unknown key.
    with pytest.raises(PolicyError, match="unknown policy keys"):
        parse({**BASE, "probation": True})


def test_direct_delivery_requires_a_non_public_deployment():
    # §9: there is no open mode on a public hub.
    with pytest.raises(PolicyError, match="not allowed on a public deployment"):
        parse({**BASE, "contact_policy": "direct"})
    policy = parse({**BASE, "contact_policy": "direct", "deployment": "private"})
    assert policy.direct_delivery is True


def test_unknown_contact_policy_is_fatal():
    with pytest.raises(PolicyError, match="contact_policy"):
        parse({**BASE, "contact_policy": "open"})


def test_invalid_agent_id_is_fatal():
    with pytest.raises(PolicyError):
        parse({**BASE, "agent_id": "carl@host@nope"})


def test_block_overrides_allow():
    policy = parse({**BASE, "block": ["muse@bridge.example"]})
    assert "muse@bridge.example" in policy.allow  # the allow entry stays; decide() checks block first
    assert "muse@bridge.example" in policy.block


def test_missing_file_reports_clearly(tmp_path):
    with pytest.raises(PolicyError, match="cannot read policy"):
        load(tmp_path / "nope.json")


def test_invalid_json_reports_clearly(tmp_path):
    path = tmp_path / "p.json"
    path.write_text("{not json")
    with pytest.raises(PolicyError, match="not valid JSON"):
        load(path)
