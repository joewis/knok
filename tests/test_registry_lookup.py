"""A sender learns a newly registered agent's card from the hub (#57).

The local registry is a snapshot from ``registry.tgz``. When a new agent joins after the tarball was
issued, the CLI refused to send at all — "not in the registry; refusing to send into the void" —
even though the hub, which is the namespace authority (§4), held the card. Re-issuing the tarball by
hand was the only workaround, which is a deployment ritual standing in for a protocol answer.

The lookup is authenticated and its answer is still checked: a card the hub sends has to verify on
its own and has to name the id that was asked for.
"""

from __future__ import annotations

import http.client
import json
import shutil
import urllib.parse

import pytest

from knok.bridge import load_cards
from knok.cli import main
from knok.hubclient import HubClient
from knok.identity import b64url_decode
from knok.provision import load_key

from test_phase2 import DOMAIN, deployment  # noqa: F401  (fixture reused by import)

NEWCOMER = f"bobby@{DOMAIN}"


@pytest.fixture
def stale_registry(tmp_path, deployment):
    """A sender whose registry predates the newcomer, plus the env the CLI reads.

    The card is on the hub and in the deployment's registry; only *carl's copy* is the stale one,
    which is exactly the state an agent is in when the tarball was issued before the new agent
    joined.
    """
    hub, bridges, root = deployment
    stale = tmp_path / "stale-registry"
    stale.mkdir()
    for path in sorted((root / "registry").glob("*.json")):
        if path.stem != NEWCOMER:
            shutil.copy(path, stale / path.name)
    assert NEWCOMER not in load_cards(stale)

    carl = f"carl@{DOMAIN}"
    return {
        "hub": hub,
        "root": root,
        "carl": carl,
        "stale": stale,
        "env": {
            "KNOK_AGENT": carl,
            "KNOK_STATE": str(root / "agents" / "carl"),
            "KNOK_HUB_URL": hub.url,
            "KNOK_REGISTRY": str(stale),
        },
    }


def use_env(monkeypatch, env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def test_send_learns_a_card_the_local_registry_never_had(stale_registry, monkeypatch, capsys):
    """The whole bug: the send used to die before a deposit existed."""
    situation = stale_registry
    use_env(monkeypatch, situation["env"])

    assert main(["send", "--to", NEWCOMER, "--text", "hello, you are new"]) == 0

    printed = capsys.readouterr()
    assert NEWCOMER in printed.err, "the CLI must say where the card came from"
    assert "learned its card from the hub" in printed.err
    deposited = json.loads(printed.out)
    assert deposited["messageId"]

    # The message is at the hub, addressed to the newcomer, from the stale-registry sender.
    bobby = load_key(NEWCOMER, situation["root"] / "agents" / "bobby" / "identity.key")
    page = HubClient(situation["hub"].url, bobby).fetch()
    assert len(page["messages"]) == 1
    assert page["messages"][0]["message"]["parts"][0]["text"] == "hello, you are new"
    assert page["messages"][0]["from"] == situation["carl"]


def test_an_id_the_hub_does_not_know_is_still_refused(stale_registry, monkeypatch):
    """The refusal has to survive for ids nobody has registered — that is the whole point of it."""
    use_env(monkeypatch, stale_registry["env"])

    with pytest.raises(SystemExit) as refused:
        main(["send", "--to", f"nobody@{DOMAIN}", "--text", "into the void"])

    assert "not registered with the hub" in str(refused.value), (
        "the refusal must name the hub, not the local snapshot — the local copy is the stale one"
    )


def test_a_card_for_the_wrong_agent_is_refused(stale_registry, monkeypatch):
    """A hub answer that names somebody else is a bug or an attack; neither is a reason to send."""
    situation = stale_registry
    use_env(monkeypatch, situation["env"])
    muse_document = json.loads((situation["stale"] / f"muse@{DOMAIN}.json").read_text())

    monkeypatch.setattr(
        "knok.cli.HubClient",
        lambda url, identity: type("C", (), {"card": lambda self, agent_id: muse_document})(),
    )

    with pytest.raises(SystemExit) as refused:
        main(["send", "--to", NEWCOMER, "--text", "hello"])

    assert "cannot be trusted" in str(refused.value)
    assert f"muse@{DOMAIN}" in str(refused.value), (
        "the refusal must name the id the card actually carries"
    )


def test_a_card_that_does_not_verify_is_refused(stale_registry, monkeypatch):
    """The document carries its own proof; a mangled signature must not become a pinned key."""
    situation = stale_registry
    use_env(monkeypatch, situation["env"])

    document = json.loads((situation["stale"] / f"muse@{DOMAIN}.json").read_text())
    document["signature"] = "A" + document["signature"][1:]
    # The precondition is about *this* document, not about ``card_body``: the payload still decodes
    # and still carries a public key, so a refusal here is a statement about the signature. Written
    # this way on purpose — it holds whether or not #59 is fixed, so this suite cannot be broken by
    # an unrelated PR landing, and #59's own test pins ``card_body``'s half.
    body = json.loads(b64url_decode(document["payload"]))
    assert body["bridge"]["publicKey"], "the payload must still decode: this is a bad signature"

    monkeypatch.setattr(
        "knok.cli.HubClient",
        lambda url, identity: type("C", (), {"card": lambda self, agent_id: document})(),
    )

    with pytest.raises(SystemExit) as refused:
        main(["send", "--to", NEWCOMER, "--text", "hello"])

    assert "cannot be trusted" in str(refused.value)
    assert "signature" in str(refused.value)


def test_the_lookup_requires_authentication(stale_registry):
    """Not an open directory: an unsigned GET is the same refusal as any other unauthenticated call."""
    hub = stale_registry["hub"]
    parsed = urllib.parse.urlparse(hub.url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        connection.request("GET", "/v1/registry/" + urllib.parse.quote(NEWCOMER, safe=""))
        response = connection.getresponse()
        assert response.status == 403
        assert NEWCOMER.encode() not in response.read(), (
            "the refusal must not confirm or deny the id to an unauthenticated caller"
        )
    finally:
        connection.close()


def test_a_card_is_served_to_a_registered_agent(stale_registry):
    """The positive control for the endpoint, at the client level."""
    situation = stale_registry
    carl = load_key(situation["carl"], situation["root"] / "agents" / "carl" / "identity.key")
    document = HubClient(situation["hub"].url, carl).card(NEWCOMER)

    assert document is not None
    body = json.loads(b64url_decode(document["payload"]))
    assert f"{body['name']}@{body['bridge']['hub']}" == NEWCOMER
    bobby = load_key(NEWCOMER, situation["root"] / "agents" / "bobby" / "identity.key")
    assert body["bridge"]["publicKey"] == bobby.public_b64(), (
        "the served card must be the one the hub pinned, not a re-issue"
    )


def test_an_unregistered_id_returns_none_rather_than_an_exception(stale_registry):
    """``None`` is the one honest reason to refuse, so the client has to report it as data."""
    situation = stale_registry
    carl = load_key(situation["carl"], situation["root"] / "agents" / "carl" / "identity.key")
    assert HubClient(situation["hub"].url, carl).card(f"nobody@{DOMAIN}") is None
