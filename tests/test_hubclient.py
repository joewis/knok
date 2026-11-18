"""Tests for the hub client half of the contract (docs/HUB.md v0.2)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from knok.canonical import canonical_bytes
from knok.hubclient import (
    HubClient,
    HubError,
    HubRefused,
    _sorted_target,
    request_document,
    signed_headers,
)
from knok.identity import generate, verify_signature

IDENTITY = generate("carl", "hub.local")


def test_target_includes_the_query_in_sorted_order():
    assert _sorted_target("/v1/mail", {"limit": 50, "cursor": "b"}) == "/v1/mail?cursor=b&limit=50"
    assert _sorted_target("/v1/mail", {"limit": 50, "cursor": None}) == "/v1/mail?limit=50"
    assert _sorted_target("/v1/health", None) == "/v1/health"


def test_document_covers_method_target_and_body():
    doc = request_document(IDENTITY, "POST", "/v1/mail/ack", b'{"messageIds": []}')
    assert doc["agent"] == "carl@hub.local"
    assert doc["method"] == "POST"
    assert doc["target"] == "/v1/mail/ack"
    assert len(doc["bodySha256"]) == 64
    assert doc["at"].endswith("Z")


def test_headers_carry_a_signature_that_verifies():
    body = b'{"messageIds": ["m-1"]}'
    headers = signed_headers(IDENTITY, "POST", "/v1/mail/ack", body)
    doc = {
        "agent": headers["X-Knok-Agent"],
        "nonce": headers["X-Knok-Nonce"],
        "at": headers["X-Knok-At"],
        "method": "POST",
        "target": "/v1/mail/ack",
        "bodySha256": __import__("hashlib").sha256(body).hexdigest(),
    }
    assert verify_signature(IDENTITY.public_key, canonical_bytes(doc),
                            "ed25519:" + headers["X-Knok-Signature"])


def test_a_changed_target_breaks_the_signature():
    headers = signed_headers(IDENTITY, "GET", "/v1/mail?limit=50")
    doc = {
        "agent": headers["X-Knok-Agent"],
        "nonce": headers["X-Knok-Nonce"],
        "at": headers["X-Knok-At"],
        "method": "GET",
        "target": "/v1/mail?limit=500",  # a middlebox raising the limit
        "bodySha256": __import__("hashlib").sha256(b"").hexdigest(),
    }
    assert not verify_signature(IDENTITY.public_key, canonical_bytes(doc),
                               "ed25519:" + headers["X-Knok-Signature"])


def test_nonces_are_unique_per_request():
    seen = {signed_headers(IDENTITY, "GET", "/v1/health")["X-Knok-Nonce"] for _ in range(50)}
    assert len(seen) == 50


class _Recorder(BaseHTTPRequestHandler):
    requests: list = []

    def log_message(self, *args, **kwargs):  # keep pytest output clean
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        _Recorder.requests.append(
            {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body}
        )
        if "full" in self.path:
            status = 429
        elif "denied" in self.path:
            status = 403
        else:
            status = 200
        payload = b'{"ok": true}' if status == 200 else b'{"error": "refused: delivery not permitted"}'
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle


@pytest.fixture
def hub_url():
    _Recorder.requests = []
    server = HTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_fetch_signs_the_parameters_it_sends(hub_url):
    client = HubClient(hub_url, IDENTITY)
    client.fetch(limit=7, cursor="abc")
    sent = _Recorder.requests[-1]
    assert sent["path"] == "/v1/mail?cursor=abc&limit=7"
    assert sent["headers"]["X-Knok-Agent"] == "carl@hub.local"
    assert sent["headers"]["X-Knok-Signature"]


def test_deposit_sends_the_envelope_as_its_own_credential(hub_url):
    client = HubClient(hub_url, IDENTITY)
    envelope = {"envelopeVersion": 1, "from": "carl@hub.local", "signature": "ed25519:x"}
    client.deposit(envelope)
    sent = _Recorder.requests[-1]
    assert sent["method"] == "POST"
    assert "X-Knok-Signature" not in sent["headers"]
    assert json.loads(sent["body"])["from"] == "carl@hub.local"


def test_over_capacity_is_retryable_and_a_permanent_refusal_is_not(hub_url):
    client = HubClient(hub_url, IDENTITY)
    with pytest.raises(HubRefused) as full:
        client._signed_json("GET", "/v1/mail/full")
    assert full.value.status == 429
    assert full.value.retryable is True

    with pytest.raises(HubRefused) as denied:
        client._signed_json("GET", "/v1/mail/denied")
    assert denied.value.status == 403
    assert denied.value.retryable is False
