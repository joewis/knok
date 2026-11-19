"""A running bridge adopts a card added, changed or removed on disk (#54).

The policy reload (#52) made the *gate* follow the file. This is the trust anchor behind it: a peer
provisioned after the bridge started has no pinned card, so its signature cannot be verified, the
envelope is left at the hub, and after the bounded attempt counter it is dropped — the #48 silent-drop
class one layer down.

The clock is the assertion, never a restart. The bridge is built once, before the card exists, and
every test drives it through ``poll_once`` afterwards. Nothing here constructs a second ``Bridge``
or restarts a hub.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from knok.bridge import Bridge, BridgeState, load_cards
from knok.envelope import sign
from knok.hub import Hub
from knok.hubclient import HubClient
from knok.identity import b64url_decode, fingerprint, public_key_from_b64
from knok.provision import load_key, provision

from test_phase2 import DOMAIN, iso, now

#: Everyone provisioned before any bridge starts. The allow-lists are written for all three, so a
#: refusal in these tests can only be the registry — the policy half is #53's business.
NAMES = ["carl", "muse", "bobby"]
LATE = "bobby"
OBSERVER = "muse"


@pytest.fixture
def late_registry(tmp_path: Path):
    """A deployment in which ``bobby`` joins after the bridges are already running.

    ``provision`` writes the card for everyone, so the fixture then *removes* bobby's card file
    before building any bridge: at construction time the directory genuinely does not have him, and
    the hub's snapshot still does. Re-writing the file is therefore the only thing that changes —
    exactly the case #54 describes.
    """
    provision(tmp_path, hub_domain=DOMAIN, agents=NAMES)
    cards_dir = tmp_path / "registry"

    late_card = cards_dir / f"{LATE}@{DOMAIN}.json"
    late_text = late_card.read_text()
    late_card.unlink()

    raw_cards = {p.stem: json.loads(p.read_text()) for p in cards_dir.glob("*.json")}
    registry = {
        fingerprint(public_key_from_b64(json.loads(b64url_decode(document["payload"]))["bridge"]["publicKey"])): json.loads(
            b64url_decode(document["payload"])
        )["bridge"]["publicKey"]
        for document in raw_cards.values()
    }
    # The hub knows bobby even though no peer's registry does: that is the premise of the bug.
    hub_registry = dict(registry)
    bobby_identity = load_key(f"{LATE}@{DOMAIN}", tmp_path / "agents" / LATE / "identity.key")
    hub_registry[fingerprint(bobby_identity.public_key)] = json.loads(
        b64url_decode(json.loads(late_text)["payload"])
    )["bridge"]["publicKey"]

    hub = Hub(
        path=tmp_path / "hub" / "hub.db",
        identity=load_key(f"postmaster@{DOMAIN}", tmp_path / "hub" / "identity.key"),
        cards={**raw_cards, f"{LATE}@{DOMAIN}": json.loads(late_text)},
        registry=hub_registry,
        port=0,
        sweep_interval=3600,
    ).start()

    bridges = {}
    for name in NAMES:
        if name == LATE:
            continue
        state = BridgeState(
            agent_id=f"{name}@{DOMAIN}",
            directory=tmp_path / "agents" / name,
            hub_url=hub.url,
            registry=load_cards(cards_dir),
            registry_dir=cards_dir,
        )
        assert f"{LATE}@{DOMAIN}" not in state.registry, "the fixture must start before bobby exists"
        bridges[name] = Bridge(state, poll_seconds=0.01)

    yield hub, bridges, tmp_path, cards_dir, late_text, bobby_identity
    for bridge in bridges.values():
        bridge.close()
    hub.stop()


def deposit_from(identity, hub, *, to: str, text: str, message_id: str, context: str = "c-late"):
    """Sign and deposit one message the way an agent's CLI does."""
    moment = now()
    unsigned = {
        "envelopeVersion": 1,
        "seq": 0,
        "message": {
            "kind": "message",
            "messageId": message_id,
            "contextId": context,
            "role": "agent",
            "parts": [{"kind": "text", "text": text}],
        },
        "from": identity.agent_id,
        "to": [to],
        "sentAt": iso(moment - timedelta(seconds=1)),
        "expiresAt": iso(moment + timedelta(hours=72)),
        "turn": {"expectsReply": False, "closesThread": False},
    }
    return HubClient(hub.url, identity).deposit(sign(unsigned, identity))


def test_a_card_added_mid_run_admits_the_peer(late_registry):
    """The whole bug: the hub knows bobby, the bridge does not, and nobody restarts anything."""
    hub, bridges, root, cards_dir, late_text, bobby = late_registry
    muse = bridges[OBSERVER]

    # Before the card exists the envelope cannot be verified, so it must be left at the hub —
    # the correct behaviour today, and the reason the bug is silent rather than wrong.
    deposit_from(bobby, hub, to=muse.identity.agent_id, text="hello, I am new", message_id="m-late")
    first = muse.poll_once()
    assert first["unhandled"] == 1, "an unverifiable sender must not be queued"
    assert first["queued"] == 0
    assert muse.queue.get() is None
    assert muse.client.fetch()["messages"], "the message is still at the hub, not dropped"

    # The operator provisions him: one file appears in the registry directory.
    (cards_dir / f"{bobby.agent_id}.json").write_text(late_text)

    second = muse.poll_once()
    assert second["queued"] == 1, "a peer pinned mid-run must be admitted without a restart"
    delivered = muse.queue.get()
    assert delivered["message"]["messageId"] == "m-late"
    assert delivered["message"]["contextId"] == "c-late"
    assert muse.client.fetch()["messages"] == [], "delivered once, then acked"


def test_a_card_removed_mid_run_stops_being_trusted(late_registry):
    """Revocation of a *key*, not a peer: deleting the card must stop verification, not wait for a restart."""
    hub, bridges, root, cards_dir, late_text, bobby = late_registry
    muse = bridges[OBSERVER]
    (cards_dir / f"{bobby.agent_id}.json").write_text(late_text)
    assert muse.poll_once()["fetched"] == 0
    assert bobby.agent_id in muse.state.registry

    (cards_dir / f"{bobby.agent_id}.json").unlink()
    deposit_from(bobby, hub, to=muse.identity.agent_id, text="still here?", message_id="m-revoked")
    counts = muse.poll_once()
    assert counts["queued"] == 0, "a deleted card must not verify a signature any more"
    assert counts["unhandled"] == 1
    assert muse.queue.get() is None, "the application must never see it"
    assert bobby.agent_id not in muse.state.registry


def test_a_corrupt_card_narrows_the_registry_instead_of_emptying_it(late_registry):
    """A bad edit is a statement about one card; the rest keep working."""
    hub, bridges, root, cards_dir, late_text, bobby = late_registry
    muse = bridges[OBSERVER]
    victim = f"carl@{DOMAIN}"
    assert victim in muse.state.registry, "the fixture must start trusting carl"
    others = set(muse.state.registry) - {victim}
    assert others

    # Carl's file is present but truncated: `load_cards` drops it, everything else still verifies.
    (cards_dir / f"{victim}.json").write_text('{"payload": "not-a-jws"')

    assert muse.reload_registry_if_changed() is True
    assert victim not in muse.state.registry, "a card that no longer verifies must stop being trusted"
    assert set(muse.state.registry) == others, "one broken card must not cost the others"


def test_an_empty_registry_directory_is_refused(late_registry):
    """Half-rewritten provisioning must not empty the trust anchor and silently drop everyone."""
    hub, bridges, root, cards_dir, late_text, bobby = late_registry
    muse = bridges[OBSERVER]
    before = dict(muse.state.registry)

    # A provisioning step that deletes and re-unpacks the directory leaves it momentarily empty.
    for path in sorted(cards_dir.glob("*.json")):
        path.rename(cards_dir.parent / (path.name + ".staged"))
    assert list(cards_dir.glob("*.json")) == []

    assert muse.reload_registry_if_changed() is False, "an empty directory is not 'trust nobody'"
    assert muse.state.registry == before, "the registry in force must be kept"

    # And the bridge still works: the peers it knew are still verifiable.
    deposit_from(bobby, hub, to=muse.identity.agent_id, text="unaffected", message_id="m-still")
    assert muse.poll_once()["unhandled"] == 1


def test_losing_this_agents_own_card_is_refused(late_registry):
    """A bridge whose own card vanished is misconfigured, not decommissioned by the peer list."""
    hub, bridges, root, cards_dir, late_text, bobby = late_registry
    muse = bridges[OBSERVER]
    before = dict(muse.state.registry)

    (cards_dir / f"{muse.identity.agent_id}.json").unlink()

    assert muse.reload_registry_if_changed() is False
    assert muse.state.registry == before


def test_an_unchanged_directory_is_not_reloaded(late_registry):
    """The check is a stat, and a rebuild on every poll would be a tax with no answer."""
    hub, bridges, root, cards_dir, late_text, bobby = late_registry
    muse = bridges[OBSERVER]
    (cards_dir / f"{bobby.agent_id}.json").write_text(late_text)
    assert muse.reload_registry_if_changed() is True

    same_object = muse.state.registry
    assert muse.reload_registry_if_changed() is False
    assert muse.state.registry is same_object, "an unchanged directory must not rebuild the dict"


def test_a_state_without_a_registry_directory_never_reloads(late_registry):
    """An embedded bridge built from an in-memory registry has nothing to re-read, and says so by not trying."""
    hub, bridges, root, cards_dir, late_text, bobby = late_registry
    muse = bridges[OBSERVER]
    muse.state.registry_dir = None

    assert muse._registry_dir_stamp() is None
    assert muse.reload_registry_if_changed() is False
    assert bobby.agent_id not in muse.state.registry
