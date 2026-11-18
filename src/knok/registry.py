"""Key records and the registry that holds them (decision 0002, issues #15 and #23).

The registry answers a question about a key **at a time**, because that is the question verification
actually asks. A dict can only answer "is this key in the set", which cannot express a key that was
revoked this morning — and a message signed yesterday must still verify while one signed this
afternoon must not.

A record is a log entry, never edited in place: revocation and rotation add facts (`revoked_at`,
`superseded_by`) rather than replacing the key. Nothing here deletes a record; retention is the
hub's decision.

The legacy dict remains supported by :func:`knok.agentcard.verify_card` and
:meth:`Registry.from_dict` means what a dict always meant: every key valid forever.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .identity import b64url, fingerprint, public_key_from_b64

__all__ = ["KeyRecord", "Registry", "KEY_TYPES", "VALID", "UNKNOWN", "fingerprint_of_raw",
           "fingerprint_matches", "fingerprint_of_b64"]

#: `ed25519` signs; `x25519` seals (§4/§6 form 2).
KEY_TYPES = ("ed25519", "x25519")

VALID = "valid"
UNKNOWN = "unknown"


def fingerprint_of_b64(public_key_b64: str) -> str:
    """Fingerprint an Ed25519 key carried as base64, the form the registry stores."""
    return fingerprint(public_key_from_b64(public_key_b64))


def fingerprint_of_raw(public_key: bytes) -> str:
    """``SHA256:<base64url>`` over a raw public key, for key types with no DER encoding.

    Ed25519 fingerprints hash the DER SubjectPublicKeyInfo (:func:`knok.identity.fingerprint`);
    X25519 keys are carried raw in the card, so their fingerprint hashes those 32 bytes. Both are
    named by the same scheme, and neither is used to verify anything — the fingerprint identifies a
    record, the record carries the key.
    """
    return "SHA256:" + b64url(hashlib.sha256(public_key).digest())


def _key_bytes(public_key: str) -> bytes:
    """Decode a stored public key, tolerating an ``x25519:`` prefix and missing padding."""
    text = public_key.split(":", 1)[1] if public_key.startswith("x25519:") else public_key
    text = text.strip()
    text += "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text.encode("ascii"))


def fingerprint_matches(record: "KeyRecord") -> bool:
    """Whether the record's fingerprint really is the fingerprint of its key.

    A record that files a key under someone else's id is worse than no record: it makes the id the
    answer to "who is this" while the bytes belong to somebody else.
    """
    try:
        if record.key_type == "ed25519":
            return fingerprint_of_b64(record.public_key) == record.fingerprint
        return fingerprint_of_raw(_key_bytes(record.public_key)) == record.fingerprint
    except Exception:
        return False


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class KeyRecord:
    """One key, one validity window, and whatever has since happened to it."""

    agent_id: str
    key_type: str
    public_key: str
    fingerprint: str
    not_before: datetime
    not_after: datetime
    revoked_at: datetime | None = None
    superseded_by: str | None = None
    superseded_at: datetime | None = None
    reason: str = ""
    extra: Mapping[str, Any] = field(default_factory=dict)

    def status(self, at: datetime) -> str:
        """What this key means at ``at``.

        ``not-yet-valid`` and ``expired`` bound the window; ``revoked`` and ``superseded`` are
        terminal facts that take effect from their own timestamps. A record with no bounds (the
        legacy dict form) is valid at every instant.
        """
        if at < self.not_before:
            return "not-yet-valid"
        if self.revoked_at is not None and at >= self.revoked_at:
            return "revoked"
        if self.superseded_at is not None and at >= self.superseded_at:
            return "superseded"
        if at >= self.not_after:
            return "expired"
        return VALID

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "agentId": self.agent_id,
            "keyType": self.key_type,
            "publicKey": self.public_key,
            "fingerprint": self.fingerprint,
            "notBefore": _iso(self.not_before),
            "notAfter": _iso(self.not_after),
        }
        if self.revoked_at is not None:
            body["revokedAt"] = _iso(self.revoked_at)
        if self.superseded_by is not None:
            body["supersededBy"] = self.superseded_by
        if self.superseded_at is not None:
            body["supersededAt"] = _iso(self.superseded_at)
        if self.reason:
            body["reason"] = self.reason
        return body

    @classmethod
    def from_dict(cls, body: Mapping[str, Any]) -> "KeyRecord":
        """Parse one record. Raises ``ValueError`` on anything that cannot be a record."""
        if not isinstance(body, Mapping):
            raise ValueError("key record must be an object")
        agent_id = body.get("agentId")
        key_type = body.get("keyType")
        public_key = body.get("publicKey")
        fingerprint_value = body.get("fingerprint")
        if not isinstance(agent_id, str) or not agent_id:
            raise ValueError("key record needs an agentId")
        if key_type not in KEY_TYPES:
            raise ValueError(f"key record keyType must be one of {', '.join(KEY_TYPES)}")
        if not isinstance(public_key, str) or not public_key:
            raise ValueError("key record needs a publicKey")
        if not isinstance(fingerprint_value, str) or not fingerprint_value:
            raise ValueError("key record needs a fingerprint")
        not_before = _parse(body.get("notBefore"))
        not_after = _parse(body.get("notAfter"))
        if not_before is None or not_after is None:
            raise ValueError("key record needs ISO-8601 notBefore and notAfter")
        if not_after <= not_before:
            raise ValueError("key record notAfter must be after notBefore")

        def optional(name: str) -> datetime | None:
            if body.get(name) is None:
                return None
            parsed = _parse(body.get(name))
            if parsed is None:
                raise ValueError(f"key record {name} must be ISO-8601")
            return parsed

        superseded_by = body.get("supersededBy")
        reason = body.get("reason")
        if isinstance(superseded_by, str) and body.get("supersededAt") is None:
            # "Replaced by X" without a time cannot be applied: the record would either never
            # report supersession or report it from its own start, both of which are wrong.
            raise ValueError("key record with supersededBy must also carry supersededAt")

        return cls(
            agent_id=agent_id,
            key_type=key_type,
            public_key=public_key,
            fingerprint=fingerprint_value,
            not_before=not_before,
            not_after=not_after,
            revoked_at=optional("revokedAt"),
            superseded_by=superseded_by if isinstance(superseded_by, str) else None,
            superseded_at=optional("supersededAt"),
            reason=reason if isinstance(reason, str) else "",
        )


class Registry:
    """A set of key records, asked about by fingerprint and instant."""

    def __init__(self, records: Iterable[KeyRecord] = ()):
        self._by_fingerprint: dict[str, KeyRecord] = {}
        for record in records:
            self.add(record)

    def add(self, record: KeyRecord) -> None:
        if not fingerprint_matches(record):
            raise ValueError(
                f"key record fingerprint {record.fingerprint} does not match its public key"
            )
        existing = self._by_fingerprint.get(record.fingerprint)
        if existing is not None and existing != record:
            # A record is a log entry: a second distinct record for one fingerprint is a mistake
            # or an attack, and silently keeping either one hides it.
            raise ValueError(f"a different record already exists for {record.fingerprint}")
        self._by_fingerprint[record.fingerprint] = record

    def get(self, fingerprint: str) -> KeyRecord | None:
        return self._by_fingerprint.get(fingerprint)

    def public_key(self, fingerprint: str) -> str | None:
        record = self._by_fingerprint.get(fingerprint)
        return record.public_key if record else None

    def status(self, fingerprint: str, at: datetime | None = None) -> str:
        record = self._by_fingerprint.get(fingerprint)
        if record is None:
            return UNKNOWN
        return record.status(at or datetime.now(timezone.utc))

    def for_agent(self, agent_id: str, key_type: str | None = None) -> list[KeyRecord]:
        return [
            record for record in self._by_fingerprint.values()
            if record.agent_id == agent_id and (key_type is None or record.key_type == key_type)
        ]

    @classmethod
    def from_dict(cls, mapping: Mapping[str, str]) -> "Registry":
        """A legacy ``{fingerprint: public_key}`` dict, as records with no bounds.

        This means **valid forever** — no revocation, no expiry, no supersession. It exists so the
        existing tests and the private-hub deployment keep working while the record form lands; it is
        not a statement that a key can never be withdrawn.
        """
        registry = cls()
        for fingerprint_value, public_key in mapping.items():
            registry.add(KeyRecord(
                agent_id="",
                key_type="ed25519",
                public_key=public_key,
                fingerprint=fingerprint_value,
                not_before=datetime.min.replace(tzinfo=timezone.utc),
                not_after=datetime.max.replace(tzinfo=timezone.utc),
            ))
        return registry

    def __len__(self) -> int:
        return len(self._by_fingerprint)
