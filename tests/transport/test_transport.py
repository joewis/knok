"""Slice 4 — direct transport (SPEC §6, §9; issue #21).

Every test runs a real HTTP round trip: a server thread on loopback and a
real ``http.client`` caller. The refusal test compares the exact status and
body across refusal kinds, because §9's indistinguishability is a byte-level
claim, not a vibe.
"""

from __future__ import annotations

import http.client
import json
import sys
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import helpers  # noqa: E402
from helpers import build_envelope, close_pair, make_pair, new_message_id  # noqa: E402
from knok.queue import Queue  # noqa: E402
from knok.transport import (  # noqa: E402
    MAX_ENVELOPE_BYTES,
    REFUSAL_BODY,
    REFUSAL_STATUS,
    TransportRefused,
    post_envelope,
    verify_ack,
)


def _get(url, path):
    parsed = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def test_round_trip_real_http(pair):
    envelope = build_envelope(pair.carl_id, pair.muse_id.agent_id)
    ack = pair.carl.bridge.send(pair.muse.url, envelope)
    assert ack["kind"] == "ack"
    assert ack["messageId"] == envelope["message"]["messageId"]
    assert ack["seq"] == 0
    assert ack["contextId"] == "c-1"
    assert ack["from"] == pair.muse_id.agent_id
    assert verify_ack(ack, pair.muse_id.public_key) is True
    assert pair.muse.queue.depth() == 1

    delivered = pair.muse.queue.get()
    assert delivered["message"]["messageId"] == envelope["message"]["messageId"]
    assert delivered["message"]["parts"][0]["text"] == "Can you review §4?"
    assert pair.muse.queue.ack(delivered["message"]["messageId"]) is True
    assert pair.muse.queue.depth() == 0


def test_health_is_liveness_only(pair):
    """§10/issue #25: an unauthenticated GET must not name the agent or its mail."""
    status, body = _get(pair.muse.url, "/v1/health")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}
    pair.carl.bridge.send(
        pair.muse.url, build_envelope(pair.carl_id, pair.muse_id.agent_id)
    )
    _, body = _get(pair.muse.url, "/v1/health")
    assert json.loads(body) == {"status": "ok"}, "queue depth must not leak either"


def test_over_cap_refused_and_not_queued(pair):
    envelope = build_envelope(pair.carl_id, pair.muse_id.agent_id)
    envelope["message"]["parts"][0]["text"] = "x" * (MAX_ENVELOPE_BYTES + 1)
    raw = json.dumps(envelope).encode()
    assert len(raw) > MAX_ENVELOPE_BYTES
    status, body = post_envelope(pair.muse.url, raw)
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
    assert pair.muse.queue.depth() == 0


def test_duplicate_message_id_delivered_once(pair):
    envelope = build_envelope(pair.carl_id, pair.muse_id.agent_id)
    first = pair.carl.bridge.send(pair.muse.url, envelope)
    second = pair.carl.bridge.send(pair.muse.url, envelope)
    # At-least-once: the retransmission is acked, not refused — but stored once.
    assert first["messageId"] == second["messageId"] == envelope["message"]["messageId"]
    assert pair.muse.queue.depth() == 1
    assert pair.muse.queue.get()["message"]["messageId"] == envelope["message"]["messageId"]
    assert pair.muse.queue.get() is None


def test_ack_implies_durable(pair, tmp_path):
    envelope = build_envelope(pair.carl_id, pair.muse_id.agent_id)
    pair.carl.bridge.send(pair.muse.url, envelope)
    # The ack is already in hand. Reopen the queue on the same path: the
    # message must still be there, i.e. put() fsynced before the ack went out.
    pair.muse.bridge.stop()
    pair.muse.queue.close()
    reopened = Queue(tmp_path / "muse" / "queue.db", pair.muse_id.agent_id)
    try:
        delivered = reopened.get()
        assert delivered["message"]["messageId"] == envelope["message"]["messageId"]
    finally:
        reopened.close()


def test_refusal_is_indistinguishable(pair):
    muse_url = pair.muse.url
    cases = {}

    # Bad signature: signed, then the body tampered with.
    bad_sig = build_envelope(pair.carl_id, pair.muse_id.agent_id)
    bad_sig["message"]["parts"][0]["text"] = "forged"
    cases["bad signature"] = json.dumps(bad_sig).encode()

    # Stranger: mallory is registered (her card verifies) but has no contact.
    cases["stranger"] = json.dumps(
        build_envelope(pair.mallory_id, pair.muse_id.agent_id, context_id="c-9")
    ).encode()

    # Malformed: not JSON at all.
    cases["malformed"] = b"{not json"

    # Over-cap: garbage past the 64 KiB cap.
    cases["over-cap"] = b"x" * (MAX_ENVELOPE_BYTES + 1)

    # Sealed (form 2): no ``message`` in clear, so neither gate nor queue can
    # work on it — and the signature cannot cover a message that is not there.
    cases["sealed"] = json.dumps({
        "envelopeVersion": 1,
        "seq": 0,
        "messageId": new_message_id(),
        "sealed": {"hpke": {"enc": "AA==", "ciphertext": "AA=="},
                   "recipientKeyId": "SHA256:AAAA"},
        "from": pair.carl_id.agent_id,
        "to": [pair.muse_id.agent_id],
        "sentAt": helpers.SENT_AT,
        "expiresAt": helpers.EXPIRES_AT,
        "turn": {"expectsReply": False, "closesThread": False},
        "signature": "ed25519:AA==",
    }).encode()

    # Wrong recipient: validly signed by carl, but addressed to carl, not muse.
    cases["wrong recipient"] = json.dumps(
        build_envelope(pair.carl_id, pair.carl_id.agent_id)
    ).encode()

    observed = {name: post_envelope(muse_url, raw) for name, raw in cases.items()}
    for name, (status, body) in observed.items():
        assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY), name
    assert len({(s, b) for s, b in observed.values()}) == 1
    assert pair.muse.queue.depth() == 0


def test_deliver_raising_is_refused(pair, monkeypatch):
    # §9: deliver() is written not to raise, but if it ever does — a card
    # whose ``bridge`` object is the wrong shape, a sqlite error under load —
    # the response must still be the shared refusal, not a 500 and not a
    # dropped connection.
    def _boom(envelope):
        raise RuntimeError("sqlite under load")

    monkeypatch.setattr(pair.muse.bridge, "deliver", _boom)
    envelope = build_envelope(pair.carl_id, pair.muse_id.agent_id)
    status, body = post_envelope(pair.muse.url, json.dumps(envelope).encode())
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
    assert pair.muse.queue.depth() == 0


def test_unknown_sender_refused_with_the_shared_string(pair, tmp_path):
    # A second muse bridge holding only carl's card: mallory is unregistered
    # here, so her envelope is refused before any signature work on her key.
    lonely = make_pair(tmp_path / "lonely", muse_cards_for={pair.carl_id.agent_id})
    try:
        envelope = build_envelope(
            pair.mallory_id, pair.muse_id.agent_id, context_id="c-9"
        )
        with pytest.raises(TransportRefused) as exc:
            lonely.mallory.bridge.send(lonely.muse.url, envelope)
        assert (exc.value.status, exc.value.body) == (REFUSAL_STATUS, REFUSAL_BODY)
    finally:
        close_pair(lonely)


def test_tampered_ack_does_not_verify(pair):
    envelope = build_envelope(pair.carl_id, pair.muse_id.agent_id)
    ack = pair.carl.bridge.send(pair.muse.url, envelope)
    assert verify_ack(ack, pair.muse_id.public_key) is True
    tampered = dict(ack, messageId="m-forged")
    assert verify_ack(tampered, pair.muse_id.public_key) is False
    wrong_key = dict(ack)
    assert verify_ack(wrong_key, pair.carl_id.public_key) is False


def test_a_message_is_verified_against_the_key_at_its_own_sent_time(pair):
    """#23: a key revoked this morning still validates a message signed yesterday."""
    from datetime import datetime, timezone

    from knok.registry import KeyRecord, Registry

    carl = pair.carl_id
    revoked_at = datetime(2026, 11, 18, 6, 0, tzinfo=timezone.utc)
    pair.muse.bridge.registry = Registry([
        KeyRecord(
            agent_id=carl.agent_id,
            key_type="ed25519",
            public_key=carl.public_b64(),
            fingerprint=carl.fingerprint,
            not_before=datetime(2026, 11, 1, tzinfo=timezone.utc),
            not_after=datetime(2026, 12, 1, tzinfo=timezone.utc),
            revoked_at=revoked_at,
        )
    ])

    # Signed before the revocation: accepted, even though it arrives after it.
    signed_earlier = build_envelope(
        carl, pair.muse_id.agent_id, context_id="c-before",
        sent_at="2026-11-18T05:00:00Z", expires_at="2026-11-21T05:00:00Z",
    )
    assert pair.muse.bridge.deliver(signed_earlier) is not None

    # Signed after the revocation: refused, with the same refusal as everything else.
    signed_later = build_envelope(
        carl, pair.muse_id.agent_id, context_id="c-after",
        sent_at="2026-11-18T07:00:00Z", expires_at="2026-11-21T05:00:00Z",
    )
    assert pair.muse.bridge.deliver(signed_later) is None


def test_an_unknown_sender_costs_the_same_crypto_as_a_known_one(pair, monkeypatch):
    """§9/issue #24: the wall clock must not answer "does this name exist?"."""
    import knok.agentcard as agentcard_module
    import knok.envelope as envelope_module
    import knok.transport as transport_module

    calls: list[str] = []

    def counted(module, name):
        real = getattr(module, name)

        def wrapper(*args, **kwargs):
            calls.append(module.__name__)
            return real(*args, **kwargs)

        monkeypatch.setattr(module, name, wrapper)

    # Every module that can perform a signature check on this path, so the count is
    # of real Ed25519 operations and not of one namespace's share of them.
    counted(agentcard_module, "verify_signature")
    counted(envelope_module, "verify_signature")
    counted(transport_module, "verify_signature")

    known = build_envelope(pair.carl_id, pair.muse_id.agent_id)
    assert pair.muse.bridge.deliver(known) is not None
    known_calls = len(calls)

    calls.clear()
    stranger = build_envelope(pair.carl_id, pair.muse_id.agent_id)
    stranger["from"] = "stranger@bridge.example"
    assert pair.muse.bridge.deliver(stranger) is None  # same refusal as any other
    stranger_calls = len(calls)

    assert known_calls == stranger_calls, (
        f"known sender did {known_calls} signature checks, unknown did {stranger_calls}"
    )
