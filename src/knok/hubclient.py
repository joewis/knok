"""Client half of the hub contract (`docs/HUB.md` v0.2).

Contract: every request is authenticated by the caller's own key. Deposit carries a signed envelope;
fetch and ack sign a request document over the **exact request-target, query included**, with `at`
inside the hub's five-minute skew window and a nonce the hub accepts once. Nothing here holds a
secret other than the agent's key, and nothing here decides policy — the gate does that on arrival.

Refusals raise :class:`HubRefused` carrying the status, because the caller needs to tell a retryable
answer (429, mailbox full) from a permanent one (403, bad signature or unknown agent).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from .canonical import canonical_bytes
from .identity import Identity, b64url

SKEW_SECONDS = 300


class HubError(RuntimeError):
    """The hub could not be reached, or answered something unparsable."""


class HubRefused(HubError):
    """The hub refused the request. ``status`` distinguishes 429 (retry) from 403 (permanent)."""

    def __init__(self, status: int, body: bytes):
        super().__init__(f"hub refused: {status} {body[:200]!r}")
        self.status = status
        self.body = body

    @property
    def retryable(self) -> bool:
        return self.status == 429


def _sorted_target(path: str, params: dict[str, Any] | None) -> str:
    """The exact request-target: path plus a query string with sorted keys.

    Sorting is what makes the signed bytes independent of the caller's dict order while still
    covering every parameter, so a middlebox cannot raise `limit` or move the `cursor`.
    """
    if not params:
        return path
    pairs = sorted((k, str(v)) for k, v in params.items() if v is not None)
    return path + "?" + urllib.parse.urlencode(pairs)


def request_document(
    identity: Identity,
    method: str,
    target: str,
    body: bytes = b"",
    now: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    moment = now or datetime.now(timezone.utc)
    return {
        "agent": identity.agent_id,
        "nonce": nonce or b64url(os.urandom(16)),
        "at": moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": method,
        "target": target,
        "bodySha256": hashlib.sha256(body).hexdigest(),
    }


def signed_headers(
    identity: Identity,
    method: str,
    target: str,
    body: bytes = b"",
    now: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Headers carrying a signed request document (base64url Ed25519 over its JCS bytes)."""
    document = request_document(identity, method, target, body, now, nonce)
    signature = identity.sign(canonical_bytes(document))
    return {
        "X-Knok-Agent": document["agent"],
        "X-Knok-Nonce": document["nonce"],
        "X-Knok-At": document["at"],
        "X-Knok-Signature": signature.split(":", 1)[1],
    }


class HubClient:
    """A thin HTTP client for one agent's mailbox."""

    def __init__(self, base_url: str, identity: Identity, timeout: float = 10.0):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise HubError(f"not a hub url: {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self._host = parsed.hostname
        self._port = parsed.port
        self._https = parsed.scheme == "https"
        self.identity = identity
        self.timeout = timeout

    # -- plumbing ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: bytes | None = None,
        signed: bool = True,
    ) -> tuple[int, bytes]:
        target = _sorted_target(path, params)
        payload = body or b""
        headers = {"Content-Type": "application/json"}
        if signed:
            headers.update(signed_headers(self.identity, method, target, payload))
        klass = http.client.HTTPSConnection if self._https else http.client.HTTPConnection
        conn = klass(self._host, self._port, timeout=self.timeout)
        try:
            conn.request(method, target, body=payload if body is not None else None, headers=headers)
            response = conn.getresponse()
            return response.status, response.read()
        except OSError as exc:
            raise HubError(f"cannot reach hub at {self.base_url}: {exc}") from exc
        finally:
            conn.close()

    def _signed_json(self, method: str, path: str, params=None, body: Any = None) -> Any:
        payload = json.dumps(body, sort_keys=True).encode("utf-8") if body is not None else b""
        status, raw = self._request(method, path, params, payload if body is not None else None)
        if status >= 400:
            raise HubRefused(status, raw)
        try:
            return json.loads(raw) if raw else None
        except ValueError as exc:
            raise HubError(f"hub returned unparsable json: {raw[:200]!r}") from exc

    # -- endpoints --------------------------------------------------------

    def deposit(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Deposit one signed envelope. The envelope is the credential; no extra signature."""
        payload = json.dumps(envelope, sort_keys=True).encode("utf-8")
        # The body is its own proof, so the request document is not signed here: adding a second
        # signature over the same body would authenticate nothing new and double the work per message.
        status, raw = self._request("POST", "/v1/mail", None, payload, signed=False)
        if status >= 400:
            raise HubRefused(status, raw)
        return json.loads(raw)

    def fetch(self, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        return self._signed_json("GET", "/v1/mail", {"limit": limit, "cursor": cursor})

    def ack(self, message_ids: list[str]) -> dict[str, Any]:
        return self._signed_json("POST", "/v1/mail/ack", None, {"messageIds": message_ids})

    def presence(self, agent_id: str) -> dict[str, Any]:
        return self._signed_json("GET", "/v1/presence/" + urllib.parse.quote(agent_id, safe=""))

    def health(self) -> dict[str, Any]:
        status, raw = self._request("GET", "/v1/health")
        if status >= 400:
            raise HubRefused(status, raw)
        return json.loads(raw)
