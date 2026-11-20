"""HPKE base mode, single shot, for the one suite SPEC §6 names.

RFC 9180, mode 0 (base), DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 — the
ciphersuite §6 fixes. Only what the envelope needs is here: one message per context, no PSK, no
sender authentication (the envelope's Ed25519 signature is that, and it is verified before this
runs), and no exporter. A second AEAD would be a compatibility matrix nobody asked for.

**Interop is the contract, not our convenience.** Both directions are checked against the RFC's own
test vectors in ``tests/test_sealed_envelope.py`` (appendix A.2): the key schedule must reproduce
``key``/``base_nonce`` from A.2.1, decrypting the RFC's ciphertext must yield its plaintext, and
sealing with the RFC's ephemeral key must reproduce its ciphertext byte for byte. A hand-rolled
HPKE that only round-trips against itself proves nothing — it would agree with any mistake made
twice.

Errors are one exception type. The caller decides what a failure *means* (a refusal, an unhandled
item), and the envelope layer turns it into a reason string rather than letting a hostile ciphertext
escape as a crash.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

#: Identifiers from RFC 9180 §7.1/§7.2/§7.3.
KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0003

Nsecret = 32  # DHKEM(X25519, HKDF-SHA256) shared secret
NH = 32       # HKDF-SHA256 output size
NK = 32       # ChaCha20Poly1305 key size
NN = 12       # ChaCha20Poly1305 nonce size
NENC = 32     # X25519 public key size

VERSION_LABEL = b"HPKE-v1"
SUITE_ID = b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big")
KEM_SUITE_ID = b"KEM" + KEM_ID.to_bytes(2, "big")


class HpkeError(Exception):
    """A sealed body could not be opened. One type, so a caller cannot tell a wrong key from a
    corrupt body by its class — both are refusals, and the distinction is not the receiver's to
    advertise."""


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 §2.2), spelled out because ``cryptography``'s ``HKDF.derive`` runs
    extract *and* expand — using it here would hash the PRK a second time."""
    return hmac.new(salt or b"\x00" * NH, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 §2.3)."""
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _labeled_extract(salt: bytes, suite_id: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, VERSION_LABEL + suite_id + label + ikm)


def _labeled_expand(prk: bytes, suite_id: bytes, label: bytes, info: bytes, length: int) -> bytes:
    # RFC 9180 §4: the length goes in front, not behind — ``I2OSP(L, 2) || "HPKE-v1" || suite_id
    # || label || info``. Putting it last is the mistake that agrees with itself and no one else.
    labeled_info = _i2osp(length, 2) + VERSION_LABEL + suite_id + label + info
    return _expand(prk, labeled_info, length)


def _kem_shared_secret(dh: bytes, kem_context: bytes) -> bytes:
    """DHKEM's ExtractAndExpand (RFC 9180 §4.1)."""
    eae_prk = _labeled_extract(b"", KEM_SUITE_ID, b"eae_prk", dh)
    return _labeled_expand(eae_prk, KEM_SUITE_ID, b"shared_secret", kem_context, Nsecret)


def key_schedule(shared_secret: bytes, info: bytes = b"") -> tuple[bytes, bytes]:
    """Base-mode key schedule (RFC 9180 §5.1) for one message: ``(key, base_nonce)``.

    Single shot means sequence number 0, so the AEAD nonce *is* ``base_nonce`` and there is no
    per-message counter to keep in step on either side.
    """
    psk_id_hash = _labeled_extract(b"", SUITE_ID, b"psk_id_hash", b"")
    info_hash = _labeled_extract(b"", SUITE_ID, b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash  # mode 0
    secret = _labeled_extract(shared_secret, SUITE_ID, b"secret", b"")
    key = _labeled_expand(secret, SUITE_ID, b"key", context, NK)
    base_nonce = _labeled_expand(secret, SUITE_ID, b"base_nonce", context, NN)
    return key, base_nonce


def seal(recipient_public: bytes, plaintext: bytes, *, aad: bytes = b"", info: bytes = b"",
         encap_private: bytes | None = None) -> tuple[bytes, bytes]:
    """Seal ``plaintext`` to a recipient's raw X25519 key. Returns ``(enc, ciphertext)``.

    ``encap_private`` exists so a test can pin the ephemeral key and compare against a published
    vector; production callers never pass it. The ephemeral key must be fresh per message — reusing
    one leaks that two sealed bodies share a key schedule, which is the whole difference between
    this and a shared static key.
    """
    if len(recipient_public) != NENC:
        raise HpkeError("recipient key is not a 32-byte X25519 public key")
    try:
        peer = X25519PublicKey.from_public_bytes(recipient_public)
    except ValueError as exc:
        raise HpkeError("recipient key is not an X25519 public key") from exc
    eph = X25519PrivateKey.from_private_bytes(encap_private) if encap_private else X25519PrivateKey.generate()
    enc = eph.public_key().public_bytes_raw()
    try:
        dh = eph.exchange(peer)
    except ValueError as exc:  # low-order point: the shared secret is all zeroes
        raise HpkeError("recipient key yields no shared secret") from exc
    key, nonce = key_schedule(_kem_shared_secret(dh, enc + recipient_public), info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def open_sealed(recipient_private: bytes, enc: bytes, ciphertext: bytes, *, aad: bytes = b"",
                info: bytes = b"") -> bytes:
    """Open a single-shot sealed body. Raises :class:`HpkeError` for anything that is not a valid
    ciphertext under this key — a wrong key, a corrupted body, a truncated ``enc``."""
    if len(recipient_private) != NENC:
        raise HpkeError("recipient private key is not 32 bytes")
    if len(enc) != NENC:
        raise HpkeError("enc is not a 32-byte X25519 public key")
    try:
        private = X25519PrivateKey.from_private_bytes(recipient_private)
        peer = X25519PublicKey.from_public_bytes(enc)
        dh = private.exchange(peer)
    except ValueError as exc:
        raise HpkeError("enc is not usable as an X25519 public key") from exc
    recipient_public = private.public_key().public_bytes_raw()
    key, nonce = key_schedule(_kem_shared_secret(dh, enc + recipient_public), info)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise HpkeError("sealed body does not authenticate under this key") from exc
