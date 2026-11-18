"""Agent identities: an Ed25519 keypair behind a ``name@hub-domain`` id.

Contract: an id is only meaningful together with the key it was registered under; nothing
here decides whether a peer is *trusted*, it only proves that a message was signed by the
private half of a given public key (SPEC §4).
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
RESERVED = {"admin", "root", "system", "hub", "bridge"}


class IdentityError(ValueError):
    """Raised when an agent id or key material is not valid."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def validate_name(name: str) -> None:
    if not NAME_RE.match(name):
        raise IdentityError(f"invalid agent name {name!r}: lowercase [a-z0-9][a-z0-9._-]{{0,31}}")
    if name in RESERVED:
        raise IdentityError(f"reserved agent name {name!r}")


def validate_agent_id(agent_id: str) -> None:
    if agent_id.count("@") != 1:
        raise IdentityError(f"invalid agent id {agent_id!r}: expected name@hub-domain")
    name, hub = agent_id.split("@")
    validate_name(name)
    if not hub or " " in hub or "/" in hub:
        raise IdentityError(f"invalid hub domain in {agent_id!r}")


def fingerprint(public_key: Ed25519PublicKey) -> str:
    """SHA-256 over the DER SubjectPublicKeyInfo, as ``SHA256:<base64url>``."""
    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return "SHA256:" + b64url(hashlib.sha256(der).digest())


@dataclass(frozen=True)
class Identity:
    agent_id: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)

    def sign(self, payload: bytes) -> str:
        return "ed25519:" + b64url(self.private_key.sign(payload))

    def public_b64(self) -> str:
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def save(self, path: str | Path) -> Path:
        """Write the private key as PEM with mode 0600, refusing to overwrite."""
        target = Path(path)
        if target.exists():
            raise IdentityError(f"refusing to overwrite existing key {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        pem = self.private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
        return target


def generate(name: str, hub: str) -> Identity:
    validate_name(name)
    if not hub:
        raise IdentityError("hub domain is required")
    return Identity(f"{name}@{hub}", Ed25519PrivateKey.generate())


def load(agent_id: str, path: str | Path) -> Identity:
    """Load a PKCS8 PEM private key. The caller vouches for the agent id."""
    validate_agent_id(agent_id)
    key = load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityError(f"{path} does not contain an Ed25519 private key")
    return Identity(agent_id, key)


def public_key_from_b64(text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(text))


def verify_signature(public_key: Ed25519PublicKey, payload: bytes, signature: str) -> bool:
    """True when ``signature`` is a valid ``ed25519:<b64url>`` over ``payload``."""
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        return False
    try:
        raw = b64url_decode(signature[len("ed25519:"):])
    except Exception:
        return False
    try:
        public_key.verify(raw, payload)
    except (InvalidSignature, ValueError):
        return False
    return True
