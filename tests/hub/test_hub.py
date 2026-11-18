"""Slice 5 — the hub (docs/HUB.md v0.2).

Every test runs a real HTTP round trip: a server thread on loopback and a real
``http.client`` caller. Refusals compare the exact status and body, because
§9's indistinguishability is a byte-level claim, not a vibe — and the 429 is
the one deliberate exception to it.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hub_helpers as helpers  # noqa: E402
from hub_helpers import (  # noqa: E402
    ack_as,
    build_envelope,
    close_hub,
    deposit,
    fetch_as,
    health_as,
    iso,
    make_hub,
    new_message_id,
    now_dt,
    presence_as,
    raw_request,
    signed_headers,
    verify_frame,
)
from knok.envelope import sign  # noqa: E402
from knok.hub import Hub  # noqa: E402
from knok.identity import generate  # noqa: E402
from knok.transport import MAX_ENVELOPE_BYTES, REFUSAL_BODY, REFUSAL_STATUS  # noqa: E402

#: The shared refusal as parsed JSON — deposit() parses response bodies.
REFUSAL_JSON = json.loads(REFUSAL_BODY)


@pytest.fixture
def ns(tmp_path):
    ns = make_hub(tmp_path)
    yield ns
    close_hub(ns)


def test_deposit_fetch_ack_round_trip(ns):
    envelope = build_envelope(ns.carl_id, ns.muse_id.agent_id)
    status, body, _ = deposit(ns.url, envelope)
    assert status == 202
    assert body == {"accepted": True, "messageId": envelope["message"]["messageId"]}

    status, page = fetch_as(ns.url, ns.muse_id)
    assert status == 200
    assert page["next"] is None
    assert [m["message"]["messageId"] for m in page["messages"]] == [
        envelope["message"]["messageId"]
    ]

    status, result = ack_as(ns.url, ns.muse_id, [envelope["message"]["messageId"]])
    assert (status, result) == (200, {"acked": 1})

    status, page = fetch_as(ns.url, ns.muse_id)
    assert page == {"messages": [], "next": None}


def test_deposit_refusals_share_one_403(ns):
    message_id = new_message_id()

    # Tampered after signing: the signature no longer verifies.
    tampered = build_envelope(ns.carl_id, ns.muse_id.agent_id, message_id=message_id)
    tampered["message"]["parts"][0]["text"] = "forged"
    # Unknown sender: nobody holds a card for this name.
    stranger = generate("stranger", "hub.local")
    stranger_env = build_envelope(stranger, ns.muse_id.agent_id)
    # Unknown recipient.
    unknown_rcpt = build_envelope(ns.carl_id, "nobody@hub.local")
    # Fan-out: more than one recipient.
    fanout = build_envelope(ns.carl_id, ns.muse_id.agent_id, message_id=new_message_id())
    fanout["to"] = [ns.muse_id.agent_id, ns.carl_id.agent_id]
    fanout = sign(
        {k: v for k, v in fanout.items() if k != "signature"}, ns.carl_id
    )
    # Over the 64 KiB per-message cap.
    big = build_envelope(ns.carl_id, ns.muse_id.agent_id, message_id=new_message_id())
    big["message"]["parts"][0]["text"] = "x" * (MAX_ENVELOPE_BYTES + 1)

    for envelope in (tampered, stranger_env, unknown_rcpt, fanout, big):
        status, body, _ = deposit(ns.url, envelope)
        assert (status, body) == (REFUSAL_STATUS, REFUSAL_JSON)

    # Nothing refused above was stored.
    status, page = fetch_as(ns.url, ns.muse_id)
    assert page == {"messages": [], "next": None}


def test_hub_itself_cannot_deposit(ns):
    # The hub is not an agent: even a perfectly signed envelope from its own
    # id is refused, so a stolen hub key buys no mailbox. envelope.sign
    # refuses the reserved name "hub", so the envelope is hand-signed here —
    # exactly what an attacker with the hub key would do.
    from knok.canonical import canonical_bytes

    base = build_envelope(ns.carl_id, ns.muse_id.agent_id)
    unsigned = {k: v for k, v in base.items() if k != "signature"}
    unsigned["from"] = ns.hub_identity.agent_id
    envelope = dict(unsigned)
    envelope["signature"] = ns.hub_identity.sign(canonical_bytes(unsigned))
    status, body, _ = deposit(ns.url, envelope)
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_JSON)


def test_duplicate_deposit_stored_once(ns):
    envelope = build_envelope(ns.carl_id, ns.muse_id.agent_id)
    for _ in range(2):
        status, body, _ = deposit(ns.url, envelope)
        assert status == 202
        assert body == {"accepted": True, "messageId": envelope["message"]["messageId"]}
    status, page = fetch_as(ns.url, ns.muse_id)
    assert len(page["messages"]) == 1

    # Same messageId, different body, same sender: a permanent refusal.
    other = build_envelope(
        ns.carl_id, ns.muse_id.agent_id,
        message_id=envelope["message"]["messageId"], text="a different body",
    )
    status, body, _ = deposit(ns.url, other)
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_JSON)


def test_signed_request_auth_per_endpoint(ns):
    # Missing headers, bad signature, unknown agent, header/signer mismatch,
    # and a target rewritten after signing — all the same 403, on every
    # signed endpoint.
    targets = [
        ("GET", "/v1/mail"),
        ("POST", "/v1/mail/ack"),
        ("GET", "/v1/presence/" + ns.carl_id.agent_id),
        ("GET", "/v1/health"),
    ]
    for method, target in targets:
        # No headers at all.
        status, body, _ = raw_request(ns.url, method, target)
        assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
        # Signed by a stranger, who holds no card here: unknown agent.
        stranger = generate("stranger", "hub.local")
        signed = signed_headers(stranger, method, target)
        body_bytes = b'{"messageIds": []}' if method == "POST" else None
        status, body, _ = raw_request(ns.url, method, target, signed, body_bytes)
        assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
        # Header names muse, signature is carl's: the rebuilt document
        # differs from the signed one, so verification fails.
        signed = signed_headers(ns.carl_id, method, target)
        signed["X-Knok-Agent"] = ns.muse_id.agent_id
        status, body, _ = raw_request(ns.url, method, target, signed, body_bytes)
        assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)

    # A target rewritten after signing: limit raised by a middlebox.
    signed = signed_headers(ns.muse_id, "GET", "/v1/mail?limit=50")
    status, body, _ = raw_request(ns.url, "GET", "/v1/mail?limit=5", signed)
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)


def test_replay_refused(ns):
    target = "/v1/mail"
    signed = signed_headers(ns.muse_id, "GET", target)
    status, _, _ = raw_request(ns.url, "GET", target, signed)
    assert status == 200
    # The identical request again: same (agent, nonce) — a replay.
    status, body, _ = raw_request(ns.url, "GET", target, signed)
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)


def test_skew_refused(ns):
    # Ten minutes out, either direction: refused, signed or not.
    for delta in (timedelta(minutes=10), timedelta(minutes=-10)):
        signed = signed_headers(
            ns.muse_id, "GET", "/v1/mail", at=iso(now_dt() + delta)
        )
        status, body, _ = raw_request(ns.url, "GET", "/v1/mail", signed)
        assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
    # Four minutes out is inside the 5-minute bound: accepted.
    signed = signed_headers(
        ns.muse_id, "GET", "/v1/mail", at=iso(now_dt() - timedelta(minutes=4))
    )
    status, _, _ = raw_request(ns.url, "GET", "/v1/mail", signed)
    assert status == 200


def test_ack_scoping(ns):
    envelope = build_envelope(ns.carl_id, ns.muse_id.agent_id)
    deposit(ns.url, envelope)
    message_id = envelope["message"]["messageId"]

    # Carl cannot delete muse's mail: foreign ids are ignored, not refused.
    status, result = ack_as(ns.url, ns.carl_id, [message_id])
    assert (status, result) == (200, {"acked": 0})
    status, page = fetch_as(ns.url, ns.muse_id)
    assert len(page["messages"]) == 1

    # The owner acks once, then again: idempotent, second call returns 0.
    status, result = ack_as(ns.url, ns.muse_id, [message_id])
    assert (status, result) == (200, {"acked": 1})
    status, result = ack_as(ns.url, ns.muse_id, [message_id])
    assert (status, result) == (200, {"acked": 0})
    # Acking an id that was never there is also 0, not an error.
    status, result = ack_as(ns.url, ns.muse_id, ["m-nope"])
    assert (status, result) == (200, {"acked": 0})


def test_cursor_paging(ns):
    ids = []
    for seq in range(5):
        envelope = build_envelope(ns.carl_id, ns.muse_id.agent_id, seq=seq)
        deposit(ns.url, envelope)
        ids.append(envelope["message"]["messageId"])

    seen, cursor = [], None
    for _ in range(3):
        status, page = fetch_as(ns.url, ns.muse_id, limit=2, cursor=cursor)
        assert status == 200
        seen.extend(m["message"]["messageId"] for m in page["messages"])
        cursor = page["next"]
        if cursor is None:
            break
    assert seen == ids  # FIFO by arrival, nothing skipped, nothing repeated
    assert cursor is None  # last page ends the walk


def test_over_capacity_429(tmp_path):
    ns = make_hub(tmp_path, max_messages=3)
    try:
        first = None
        for seq in range(3):
            envelope = build_envelope(ns.carl_id, ns.muse_id.agent_id, seq=seq)
            if first is None:
                first = envelope
            status, _, _ = deposit(ns.url, envelope)
            assert status == 202
        status, body, headers = deposit(
            ns.url, build_envelope(ns.carl_id, ns.muse_id.agent_id, seq=3)
        )
        assert status == 429
        assert body["error"] == "over-capacity"
        assert body["retryAfterSeconds"] == 60
        assert headers.get("Retry-After") == "60"
        # A duplicate at cap is still a duplicate, not an over-capacity: it
        # stores nothing, so the cap is not what refuses it.
        status, _, _ = deposit(ns.url, first)
        assert status == 202
    finally:
        close_hub(ns)


def test_expiry_sweeper_signed_frame(tmp_path):
    ns = make_hub(tmp_path, sweep_interval=0.2)
    try:
        moment = now_dt()
        envelope = build_envelope(
            ns.carl_id, ns.muse_id.agent_id,
            sent_at=iso(moment - timedelta(seconds=10)),
            expires_at=iso(moment + timedelta(seconds=2)),
        )
        status, _, _ = deposit(ns.url, envelope)
        assert status == 202
        time.sleep(3.5)  # past expiry, past several sweep ticks
        # The recipient never sees the dead envelope...
        status, page = fetch_as(ns.url, ns.muse_id)
        assert page == {"messages": [], "next": None}
        # ...and the sender gets a frame signed by the hub, not by anyone else.
        status, page = fetch_as(ns.url, ns.carl_id)
        assert status == 200
        assert len(page["messages"]) == 1
        frame = page["messages"][0]
        assert frame["kind"] == "expired"
        assert frame["messageId"] == envelope["message"]["messageId"]
        assert frame["from"] == ns.hub_identity.agent_id
        assert frame["to"] == [ns.carl_id.agent_id]
        assert verify_frame(frame, ns.hub_identity.public_key) is True
        # A frame forged by any agent does not verify as a hub frame.
        forged = dict(frame, signature=ns.carl_id.sign(b"forged"))
        assert verify_frame(forged, ns.hub_identity.public_key) is False
        # The frame acks like mail, by its messageId.
        status, result = ack_as(ns.url, ns.carl_id, [frame["messageId"]])
        assert (status, result) == (200, {"acked": 1})
    finally:
        close_hub(ns)


def test_fetch_skips_expired_before_sweep(ns):
    # Sweep interval is 60 s here, so nothing sweeps during this test.
    moment = now_dt()
    envelope = build_envelope(
        ns.carl_id, ns.muse_id.agent_id,
        sent_at=iso(moment - timedelta(seconds=10)),
        expires_at=iso(moment + timedelta(seconds=1)),
    )
    deposit(ns.url, envelope)
    time.sleep(1.5)
    status, page = fetch_as(ns.url, ns.muse_id)
    assert page == {"messages": [], "next": None}  # skipped, not handed over
    status, page = fetch_as(ns.url, ns.carl_id)
    assert page == {"messages": [], "next": None}  # no frame yet: no sweep yet
    assert ns.hub.sweep() == 1
    status, page = fetch_as(ns.url, ns.carl_id)
    assert len(page["messages"]) == 1
    assert page["messages"][0]["kind"] == "expired"


def test_already_expired_deposit_accepted_and_framed(ns):
    moment = now_dt()
    envelope = build_envelope(
        ns.carl_id, ns.muse_id.agent_id,
        sent_at=iso(moment - timedelta(seconds=120)),
        expires_at=iso(moment - timedelta(seconds=60)),
        sign_now=moment - timedelta(seconds=120),
    )
    # Accepted, not refused: the sender's 202 must not be a lie.
    status, body, _ = deposit(ns.url, envelope)
    assert status == 202
    assert body == {"accepted": True, "messageId": envelope["message"]["messageId"]}
    status, page = fetch_as(ns.url, ns.muse_id)
    assert page == {"messages": [], "next": None}
    status, page = fetch_as(ns.url, ns.carl_id)
    assert len(page["messages"]) == 1
    assert page["messages"][0]["kind"] == "expired"
    assert verify_frame(page["messages"][0], ns.hub_identity.public_key) is True


def test_restart_preserves_mail_and_nonces(tmp_path):
    ns = make_hub(tmp_path)
    envelope = build_envelope(ns.carl_id, ns.muse_id.agent_id)
    deposit(ns.url, envelope)
    target = "/v1/mail"
    signed = signed_headers(ns.muse_id, "GET", target)
    status, page, _ = raw_request(ns.url, "GET", target, signed)
    assert status == 200
    assert len(json.loads(page)["messages"]) == 1

    close_hub(ns)
    restarted = make_hub(
        tmp_path, identities=(ns.carl_id, ns.muse_id, ns.mallory_id)
    )  # same store path, same agents, new process state
    try:
        # The pre-restart nonce is still known: replay is refused.
        status, body, _ = raw_request(restarted.url, "GET", target, signed)
        assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
        # And the mail survived the restart.
        status, page = fetch_as(restarted.url, restarted.muse_id)
        assert status == 200
        assert [m["message"]["messageId"] for m in page["messages"]] == [
            envelope["message"]["messageId"]
        ]
    finally:
        close_hub(restarted)


def test_presence(ns):
    # Nobody has been heard from yet (muse's own requests note muse, not carl).
    status, body = presence_as(ns.url, ns.muse_id, ns.carl_id.agent_id)
    assert (status, body) == (200, {"online": False, "lastSeen": None})
    # An unknown agent answers the same way: presence is not an oracle.
    status, body = presence_as(ns.url, ns.muse_id, "nobody@hub.local")
    assert (status, body) == (200, {"online": False, "lastSeen": None})
    # Unauthenticated presence is the shared refusal.
    status, body, _ = raw_request(
        ns.url, "GET", f"/v1/presence/{ns.carl_id.agent_id}"
    )
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
    # Carl deposits, which authenticates him: now he is online.
    deposit(ns.url, build_envelope(ns.carl_id, ns.muse_id.agent_id))
    status, body = presence_as(ns.url, ns.muse_id, ns.carl_id.agent_id)
    assert status == 200
    assert body["online"] is True
    assert isinstance(body["lastSeen"], str) and body["lastSeen"].endswith("Z")


def test_health_own_mailbox_only(ns):
    deposit(ns.url, build_envelope(ns.carl_id, ns.muse_id.agent_id))
    status, body = health_as(ns.url, ns.muse_id)
    assert (status, body) == (200, {"status": "ok", "queued": 1, "droppedFrames": 0})
    # Carl's box is empty even though his mail is sitting in muse's box.
    status, body = health_as(ns.url, ns.carl_id)
    assert (status, body) == (200, {"status": "ok", "queued": 0, "droppedFrames": 0})
    # No agent id, no global depth: health must not leak another box (#25).
    assert "agent_id" not in json.dumps(body)
    # Unauthenticated health is the shared refusal.
    status, body, _ = raw_request(ns.url, "GET", "/v1/health")
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)


def test_dropped_frame_counted_and_reported(tmp_path):
    ns = make_hub(tmp_path, max_messages=3)
    try:
        # Fill carl's box to the cap.
        for seq in range(3):
            deposit(ns.url, build_envelope(ns.muse_id, ns.carl_id.agent_id, seq=seq))
        # Carl sends an already-expired envelope to muse: the frame for carl
        # cannot be queued, so it is counted, not lost silently.
        moment = now_dt()
        envelope = build_envelope(
            ns.carl_id, ns.muse_id.agent_id,
            sent_at=iso(moment - timedelta(seconds=120)),
            expires_at=iso(moment - timedelta(seconds=60)),
            sign_now=moment - timedelta(seconds=120),
        )
        status, _, _ = deposit(ns.url, envelope)
        assert status == 202
        status, body = health_as(ns.url, ns.carl_id)
        assert body == {"status": "ok", "queued": 3, "droppedFrames": 1}
    finally:
        close_hub(ns)


def test_unknown_path_is_shared_403(ns):
    signed = signed_headers(ns.muse_id, "GET", "/v1/nope")
    status, body, _ = raw_request(ns.url, "GET", "/v1/nope", signed)
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
    signed = signed_headers(ns.muse_id, "POST", "/v1/nope", b"{}")
    status, body, _ = raw_request(ns.url, "POST", "/v1/nope", signed, b"{}")
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
