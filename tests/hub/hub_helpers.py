"""Shared scaffolding for the hub tests: a hub plus three registered agents.

Every test runs real HTTP against a loopback hub — no mocks of the wire — and
signs its requests the way a bridge would, so a refusal can be observed
rather than asserted.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from knok.canonical import canonical_bytes
from knok.envelope import sign
from knok.hub import Hub, verify_frame
from knok.identity import Identity, generate
from knok.transport import REFUSAL_BODY, REFUSAL_STATUS, make_agent_card, registry_for

HUB_DOMAIN = "hub.local"


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Relative to the wall clock: literal dates turn the suite red on a calendar day
# rather than on a code change.
SENT_AT = iso(now_dt() - timedelta(hours=1))
EXPIRES_AT = iso(now_dt() + timedelta(hours=23))


def new_message_id() -> str:
    return "m-" + secrets.token_hex(16)  # 128 bits from a CSPRNG (§6)


def build_envelope(sender, recipient_id, *, seq=0, message_id=None,
                   context_id="c-1", text="Can you review §4?",
                   sent_at=None, expires_at=None, sign_now=None):
    moment = now_dt()
    unsigned = {
        "envelopeVersion": 1,
        "seq": seq,
        "message": {
            "kind": "message",
            "messageId": message_id or new_message_id(),
            "contextId": context_id,
            "role": "agent",
            "parts": [{"kind": "text", "text": text}],
        },
        "from": sender.agent_id,
        "to": [recipient_id],
        "sentAt": sent_at or iso(moment - timedelta(minutes=1)),
        "expiresAt": expires_at or iso(moment + timedelta(hours=72)),
        "turn": {"expectsReply": True, "closesThread": False},
    }
    return sign(unsigned, sender, now=sign_now)


def make_hub(tmp_path, *, sweep_interval=60, max_messages=None, max_bytes=None,
             identities=None):
    """A hub with carl, muse and mallory registered; mallory is a stranger.

    Pass ``identities`` (a ``(carl, muse, mallory)`` triple) to restart a hub
    on the same store with the same agents — a restart must not re-key them.
    """
    if identities is None:
        identities = tuple(generate(name, HUB_DOMAIN) for name in ("carl", "muse", "mallory"))
    carl, muse, mallory = identities
    hub_identity = Identity("hub@hub.local", Ed25519PrivateKey.generate())
    identities = [carl, muse, mallory]
    cards = {
        ident.agent_id: make_agent_card(ident, HUB_DOMAIN, f"http://127.0.0.1/{ident.agent_id}")
        for ident in identities
    }
    registry = registry_for(*identities, hub_identity)
    kwargs = {"sweep_interval": sweep_interval}
    if max_messages is not None:
        kwargs["max_messages"] = max_messages
    if max_bytes is not None:
        kwargs["max_bytes"] = max_bytes
    hub = Hub(
        path=tmp_path / "hub.db", identity=hub_identity,
        cards=cards, registry=registry, **kwargs,
    ).start()
    return SimpleNamespace(
        hub=hub, url=hub.url, hub_identity=hub_identity,
        carl_id=carl, muse_id=muse, mallory_id=mallory,
        cards=cards, registry=registry,
    )


def close_hub(ns):
    ns.hub.stop()


def signed_headers(identity, method, target, body=b"", *, nonce=None, at=None):
    """The HUB.md request document, signed: what a bridge sends on fetch/ack."""
    nonce = nonce or secrets.token_hex(16)
    at = at or iso(now_dt())
    document = {
        "agent": identity.agent_id,
        "nonce": nonce,
        "at": at,
        "method": method,
        "target": target,
        "bodySha256": hashlib.sha256(body).hexdigest(),
    }
    signature = identity.sign(canonical_bytes(document))
    return {
        "X-Knok-Agent": identity.agent_id,
        "X-Knok-Nonce": nonce,
        "X-Knok-At": at,
        "X-Knok-Signature": signature,
    }


def raw_request(url, method, target, headers=None, body=None):
    parsed = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        conn.request(method, target, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        conn.close()


def deposit(url, envelope):
    raw = envelope if isinstance(envelope, bytes) else json.dumps(envelope).encode()
    status, body, headers = raw_request(
        url, "POST", "/v1/mail", {"Content-Type": "application/json"}, raw
    )
    try:
        parsed = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        parsed = body
    return status, parsed, headers


def fetch_as(url, identity, *, limit=None, cursor=None, headers=None):
    query = []
    if cursor is not None:
        query.append(f"cursor={cursor}")
    if limit is not None:
        query.append(f"limit={limit}")
    target = "/v1/mail" + ("?" + "&".join(query) if query else "")
    signed = headers if headers is not None else signed_headers(identity, "GET", target)
    status, body, _ = raw_request(url, "GET", target, signed)
    return status, json.loads(body) if body else None


def ack_as(url, identity, message_ids, *, headers=None, undelivered=None):
    payload: dict[str, object] = {"messageIds": list(message_ids)}
    if undelivered:
        payload["undelivered"] = list(undelivered)
    body = json.dumps(payload).encode()
    signed = headers if headers is not None else signed_headers(
        identity, "POST", "/v1/mail/ack", body
    )
    status, raw, _ = raw_request(
        url, "POST", "/v1/mail/ack",
        {**signed, "Content-Type": "application/json"}, body,
    )
    return status, json.loads(raw) if raw else None


def presence_as(url, identity, target_id):
    target = f"/v1/presence/{target_id}"
    signed = signed_headers(identity, "GET", target)
    status, body, _ = raw_request(url, "GET", target, signed)
    return status, json.loads(body) if body else None


def health_as(url, identity):
    signed = signed_headers(identity, "GET", "/v1/health")
    status, body, _ = raw_request(url, "GET", "/v1/health", signed)
    return status, json.loads(body) if body else None


__all__ = [
    "HUB_DOMAIN",
    "ack_as",
    "build_envelope",
    "close_hub",
    "deposit",
    "fetch_as",
    "health_as",
    "iso",
    "make_hub",
    "new_message_id",
    "now_dt",
    "presence_as",
    "raw_request",
    "signed_headers",
    "verify_frame",
]
