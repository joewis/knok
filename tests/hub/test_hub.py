"""Slice 5 — the hub (docs/HUB.md v0.2).

Every test runs a real HTTP round trip: a server thread on loopback and a real
``http.client`` caller. Refusals compare the exact status and body, because
§9's indistinguishability is a byte-level claim, not a vibe — and the 429 is
the one deliberate exception to it.
"""

from __future__ import annotations

import json
import socket
import sys
import time
import urllib.parse
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


def _raw_http(url: str, head: bytes, body: bytes = b"") -> str:
    """Send a request exactly as written — http.client normalises headers, so it
    cannot express the duplicates and malformed lines these tests are about."""
    parsed = urllib.parse.urlparse(url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.sendall(head + b"\r\n" + body)
        return sock.recv(4096).decode("latin-1")


def test_the_handler_ceiling_refuses_before_the_thread_exists(ns, monkeypatch):
    """#126 review: the cap must be exercised by real sockets, not by patching the
    limit — hold every handler open with a half-sent request, then knock."""
    import knok.hub as hub_module

    monkeypatch.setattr(hub_module._Handler, "timeout", 10)
    parsed = urllib.parse.urlparse(ns.url)
    held = []
    try:
        for _ in range(hub_module.MAX_CONCURRENT_REQUESTS):
            sock = socket.create_connection((parsed.hostname, parsed.port), timeout=5)
            # No blank line: the handler blocks reading headers, holding its slot.
            sock.sendall(b"GET /v1/health HTTP/1.1\r\nHost: hub\r\n")
            held.append(sock)
        time.sleep(0.5)  # let the accept loop hand every socket to a handler

        extra = socket.create_connection((parsed.hostname, parsed.port), timeout=5)
        try:
            extra.settimeout(3)
            assert b"429" in extra.recv(256)
        finally:
            extra.close()
    finally:
        for sock in held:
            sock.close()


def test_an_idle_handler_is_closed_by_the_hub(ns, monkeypatch):
    """#126: a client that connects and says nothing must not hold a thread."""
    import knok.hub as hub_module

    # The timeout has to be configured, not inherited: on main _Handler carries
    # no timeout of its own, and the base class default only applies because
    # StreamRequestHandler reads the attribute at accept time.
    assert hub_module._Handler.timeout == hub_module.REQUEST_TIMEOUT_SECONDS
    monkeypatch.setattr(hub_module._Handler, "timeout", 1)
    parsed = urllib.parse.urlparse(ns.url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.settimeout(5)
        assert sock.recv(64) == b""  # closed by the handler's own timeout
def test_a_duplicated_authentication_header_is_refused(ns):
    """#102: .get() returns the first value, so a second X-Knok-Agent is
    invisible to everything downstream. Ambiguity is refused, not resolved."""
    signed = signed_headers(ns.carl_id, "GET", "/v1/mail")
    head = (
        b"GET /v1/mail HTTP/1.1\r\nHost: hub\r\nConnection: close\r\n"
        + b"".join(f"{k}: {v}\r\n".encode() for k, v in signed.items())
        + f"X-Knok-Agent: {ns.muse_id.agent_id}\r\n".encode()
    )
    assert " 403" in _raw_http(ns.url, head)


def test_a_duplicated_content_length_is_refused(ns):
    """#104: two lengths let sender and hub disagree about where the body ends.

    The request is correctly signed, so a refusal can only come from the
    framing check — without it the hub reads the first length and accepts.
    """
    envelope = build_envelope(ns.carl_id, ns.muse_id.agent_id)
    body = json.dumps(envelope).encode()
    signed = signed_headers(ns.carl_id, "POST", "/v1/mail", body)
    head = (
        b"POST /v1/mail HTTP/1.1\r\nHost: hub\r\nConnection: close\r\n"
        b"Content-Type: application/json\r\n"
        + b"".join(f"{k}: {v}\r\n".encode() for k, v in signed.items())
        + f"Content-Length: {len(body)}\r\nContent-Length: {len(body)}\r\n".encode()
    )
    assert " 403" in _raw_http(ns.url, head, body)


def test_a_transfer_encoding_body_is_refused(ns):
    """#104: the handler reads Content-Length only, so a chunked body would be
    parsed as whatever followed the headers."""
    envelope = build_envelope(ns.carl_id, ns.muse_id.agent_id)
    body = json.dumps(envelope).encode()
    signed = signed_headers(ns.carl_id, "POST", "/v1/mail", body)
    head = (
        b"POST /v1/mail HTTP/1.1\r\nHost: hub\r\nConnection: close\r\n"
        b"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
        + b"".join(f"{k}: {v}\r\n".encode() for k, v in signed.items())
        + f"Content-Length: {len(body)}\r\n".encode()
    )
    assert " 403" in _raw_http(ns.url, head, body)


def test_the_request_floor_is_per_agent(ns):
    """#128 review: a global floor lets one agent's fast clock — legal inside the
    skew window — raise the floor for everyone, so a later hub-clock correction
    refuses senders who did nothing wrong."""
    at0 = now_dt()
    assert ns.hub._request_time_is_current(ns.carl_id.agent_id, at0 + timedelta(seconds=700))
    # carl's floor is now seven hundred seconds ahead; muse has never been seen.
    assert ns.hub._request_time_is_current(ns.muse_id.agent_id, at0) is True


def test_a_backward_clock_step_cannot_revive_a_pruned_nonce(ns):
    """#100: the skew check compares against the hub's clock, so stepping the hub
    back widens what counts as fresh and an already-pruned nonce returns."""
    at0 = now_dt()
    headers = signed_headers(ns.carl_id, "GET", "/v1/mail", at=iso(at0))
    assert ns.hub.authenticate(
        method="GET", target="/v1/mail", headers=headers, body=b"", now=at0
    ) == ns.carl_id.agent_id

    # Seven hundred seconds later the first nonce is outside the window and gone.
    at1 = at0 + timedelta(seconds=700)
    later = signed_headers(ns.carl_id, "GET", "/v1/mail", at=iso(at1))
    assert ns.hub.authenticate(
        method="GET", target="/v1/mail", headers=later, body=b"", now=at1
    ) == ns.carl_id.agent_id

    # Clock rolled back to four minutes after the first request: within skew, and
    # the nonce is no longer in the table. The high-water floor refuses it.
    rolled_back = at0 + timedelta(seconds=240)
    assert ns.hub.authenticate(
        method="GET", target="/v1/mail", headers=headers, body=b"", now=rolled_back
    ) is None


def test_an_agent_nonce_table_has_a_ceiling(ns, monkeypatch):
    """#101: the window bounds nonces in time, not in number."""
    import knok.hub as hub_module

    monkeypatch.setattr(hub_module, "MAX_NONCES_PER_AGENT", 3)
    moment = now_dt()
    assert all(ns.hub._claim_nonce(ns.carl_id.agent_id, f"n-{i}", moment) for i in range(5))

    held = [row[0] for row in ns.hub._conn.execute(
        "SELECT nonce FROM nonces WHERE agent = ? ORDER BY seen_at", (ns.carl_id.agent_id,)
    ).fetchall()]
    assert len(held) == 3
    assert "n-0" not in held and "n-4" in held  # oldest evicted, newest kept


def test_a_slow_client_is_disconnected(ns, monkeypatch):
    """#103: a handler with no socket timeout lets one client hold a thread for
    as long as it likes by never finishing its request."""
    import knok.hub as hub_module

    monkeypatch.setattr(hub_module._Handler, "timeout", 0.2)
    parsed = urllib.parse.urlparse(ns.url)
    with socket.create_connection((parsed.hostname, parsed.port), timeout=5) as sock:
        sock.sendall(b"GET /v1/mail HTTP/1.1\r\nHost: hub\r\n")
        sock.settimeout(3)
        assert sock.recv(1024) == b""  # the hub closed the connection


def test_an_ack_with_too_many_ids_is_refused(ns):
    """#105: one ack must not be a request to run an unbounded DELETE loop."""
    ids = [f"m-{i}" for i in range(101)]
    status, body = ack_as(ns.url, ns.muse_id, ids)
    assert status == 403
    assert body == REFUSAL_JSON


def test_an_unimplemented_method_answers_the_shared_refusal(ns):
    """#106: the inherited 501 (with an HTML body) classified the request."""
    response = _raw_http(ns.url, b"PUT /v1/mail HTTP/1.1\r\nHost: hub\r\nConnection: close\r\n")
    assert " 403" in response


def test_a_malformed_request_line_answers_the_shared_refusal(ns):
    response = _raw_http(ns.url, b"NOT-HTTP\r\n\r\n")
    assert " 403" in response


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


def test_an_acked_envelope_cannot_be_deposited_again(ns):
    """#99: ack deletes the mail row, so without a tombstone a replay of the same
    still-valid envelope is stored again and handed over a second time."""
    envelope = build_envelope(ns.carl_id, ns.muse_id.agent_id)
    status, body, _ = deposit(ns.url, envelope)
    assert status == 202 and body["accepted"] is True

    assert ack_as(ns.url, ns.muse_id, [envelope["message"]["messageId"]])[0] == 200

    # A duplicate answers 202 as well — deliberately, so a replay learns nothing
    # from the shape of the reply. The evidence is the effect: nothing is stored,
    # so the recipient is not handed the message a second time.
    status, body, _ = deposit(ns.url, envelope)
    assert status == 202 and body["messageId"] == envelope["message"]["messageId"]
    assert fetch_as(ns.url, ns.muse_id)[1]["messages"] == []


def test_an_acked_id_reused_for_a_different_body_is_refused(ns):
    """#99: the tombstone carries the hash, so reusing the id for a different
    body is still a refusal rather than a silent replacement."""
    first = build_envelope(ns.carl_id, ns.muse_id.agent_id, text="the original")
    assert deposit(ns.url, first)[0] == 202
    assert ack_as(ns.url, ns.muse_id, [first["message"]["messageId"]])[0] == 200

    second = build_envelope(
        ns.carl_id, ns.muse_id.agent_id,
        message_id=first["message"]["messageId"], text="something else",
    )
    status, body, _ = deposit(ns.url, second)
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_JSON)


def test_a_retry_with_a_new_id_is_accepted_after_the_ack(ns):
    """#99 must not break retry: SPEC §8 mints a new messageId carrying retryOf,
    which is a different id and therefore a different message."""
    first = build_envelope(ns.carl_id, ns.muse_id.agent_id)
    assert deposit(ns.url, first)[0] == 202
    assert ack_as(ns.url, ns.muse_id, [first["message"]["messageId"]])[0] == 200

    retry = build_envelope(ns.carl_id, ns.muse_id.agent_id, text="did you get this?")
    retry["message"]["metadata"] = {"retryOf": first["message"]["messageId"]}
    retry = sign(retry, ns.carl_id)
    assert deposit(ns.url, retry)[0] == 202
    assert [m["message"]["messageId"] for m in fetch_as(ns.url, ns.muse_id)[1]["messages"]] == [
        retry["message"]["messageId"]
    ]


def test_unknown_path_is_shared_403(ns):
    signed = signed_headers(ns.muse_id, "GET", "/v1/nope")
    status, body, _ = raw_request(ns.url, "GET", "/v1/nope", signed)
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)
    signed = signed_headers(ns.muse_id, "POST", "/v1/nope", b"{}")
    status, body, _ = raw_request(ns.url, "POST", "/v1/nope", signed, b"{}")
    assert (status, body) == (REFUSAL_STATUS, REFUSAL_BODY)


def test_a_message_signed_before_a_revocation_is_still_accepted(ns):
    """#23 at the hub: the deposit asks the sender's key what it meant at `sentAt`.

    The card is verified as of the message's instant, not as of the deposit. A key revoked half an
    hour ago signed a message an hour ago; refusing it here would make the hub disagree with every
    bridge that verified the same message at the same instant.
    """
    from datetime import timedelta

    from knok.registry import KeyRecord, Registry

    from hub_helpers import iso, now_dt

    moment = now_dt()
    carl = ns.carl_id

    def record(identity, revoked_at=None):
        return KeyRecord(
            agent_id=identity.agent_id,
            key_type="ed25519",
            public_key=identity.public_b64(),
            fingerprint=identity.fingerprint,
            not_before=moment - timedelta(days=1),
            not_after=moment + timedelta(days=1),
            revoked_at=revoked_at,
        )

    # Every registered agent needs a record: the recipient's card is checked too.
    ns.hub.registry = Registry([
        record(carl, revoked_at=moment - timedelta(minutes=30)),
        record(ns.muse_id),
        record(ns.mallory_id),
    ])

    before = build_envelope(carl, ns.muse_id.agent_id, context_id="c-before",
                            sent_at=iso(moment - timedelta(hours=1)))
    status, _body, _ = deposit(ns.url, before)
    assert status == 202

    after = build_envelope(carl, ns.muse_id.agent_id, context_id="c-after",
                           sent_at=iso(moment - timedelta(minutes=10)))
    status, body, _ = deposit(ns.url, after)
    assert status == 403
    assert body == REFUSAL_JSON
