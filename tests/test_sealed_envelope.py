"""HPKE and the sealed envelope: the crypto is checked against the RFC, not against itself.

Two layers, held separately:

* ``knok.hpke`` must match RFC 9180 appendix A.2 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
  ChaCha20Poly1305 — the suite SPEC §6 names) in both directions. A round trip through our own
  code proves only self-consistency, which any mistake in the key schedule also has.
* ``envelope.seal`` / ``envelope.unseal`` must turn a form 1 envelope into a form 2 one and back
  with the clear header, the signature and the ``messageId`` cross-check intact, and must refuse —
  never raise — a body that was tampered with, sealed for someone else, or names a different id
  inside than outside.

Where the bridge calls ``unseal`` is decision 0003 and the next slice; this one lands the primitive
and the envelope contract it is called through.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from knok import hpke
from knok.envelope import form_of, seal, sign, unseal, validate, verify_envelope
from knok.identity import generate
from knok.registry import fingerprint_of_raw

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# --- RFC 9180 A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base mode ---

RFC_INFO = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
RFC_SK_R = bytes.fromhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
RFC_PK_R = bytes.fromhex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
RFC_SK_E = bytes.fromhex("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600")
RFC_ENC = bytes.fromhex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
RFC_SHARED_SECRET = bytes.fromhex("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7")
RFC_KEY = bytes.fromhex("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91")
RFC_BASE_NONCE = bytes.fromhex("5c4d98150661b848853b547f")
RFC_PT = b"Beauty is truth, truth beauty"
RFC_CT = bytes.fromhex(
    "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db"
    "21993c62ce81883d2dd1b51a28"
)


def test_the_key_schedule_reproduces_the_rfc_vector():
    """Encap is where a hand-rolled HPKE goes wrong: one misordered label prefix and every
    ciphertext is wrong in a way that only a foreign implementation can see."""
    ephemeral = X25519PrivateKey.from_private_bytes(RFC_SK_E)
    dh = ephemeral.exchange(hpke.X25519PublicKey.from_public_bytes(RFC_PK_R))
    shared_secret = hpke._kem_shared_secret(dh, RFC_ENC + RFC_PK_R)
    assert ephemeral.public_key().public_bytes_raw() == RFC_ENC

    assert shared_secret == RFC_SHARED_SECRET
    key, base_nonce = hpke.key_schedule(shared_secret, RFC_INFO)
    assert key == RFC_KEY
    assert base_nonce == RFC_BASE_NONCE


def test_opening_the_rfc_ciphertext_yields_its_plaintext():
    assert hpke.open_sealed(RFC_SK_R, RFC_ENC, RFC_CT, aad=b"Count-0", info=RFC_INFO) == RFC_PT


def test_sealing_with_the_rfc_ephemeral_key_reproduces_its_ciphertext():
    enc, ciphertext = hpke.seal(RFC_PK_R, RFC_PT, aad=b"Count-0", info=RFC_INFO,
                                encap_private=RFC_SK_E)
    assert enc == RFC_ENC
    assert ciphertext == RFC_CT


def test_a_changed_ciphertext_byte_does_not_open():
    tampered = bytearray(RFC_CT)
    tampered[-1] ^= 0x01
    with pytest.raises(hpke.HpkeError):
        hpke.open_sealed(RFC_SK_R, RFC_ENC, bytes(tampered), aad=b"Count-0", info=RFC_INFO)


def test_the_wrong_key_is_the_same_refusal_as_a_changed_byte():
    other = X25519PrivateKey.generate().private_bytes_raw()
    with pytest.raises(hpke.HpkeError):
        hpke.open_sealed(other, RFC_ENC, RFC_CT, aad=b"Count-0", info=RFC_INFO)


# --- the envelope layer -------------------------------------------------------------


@pytest.fixture
def recipient():
    private = X25519PrivateKey.generate()
    raw_private = private.private_bytes_raw()
    raw_public = private.public_key().public_bytes_raw()
    return raw_private, raw_public, fingerprint_of_raw(raw_public)


@pytest.fixture
def plain_envelope():
    """A form 1 envelope whose clock is the test's, not the calendar's: a fixture dated with
    hard-coded times stops testing sealing the day it expires."""
    moment = datetime.now(timezone.utc)
    carl, muse = generate("carl", "bridge.example"), generate("muse", "bridge.example")
    envelope = {
        "envelopeVersion": 1,
        "seq": 3,
        "message": {
            "kind": "message",
            "messageId": "m-sealed-1",
            "contextId": "c-secret-thread",
            "role": "agent",
            "parts": [{"kind": "text", "text": "the key is in the blue drawer"}],
        },
        "from": carl.agent_id,
        "to": [muse.agent_id],
        "sentAt": (moment - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (moment + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "turn": {"expectsReply": True, "closesThread": False},
    }
    return sign(envelope, carl), carl


def test_seal_and_unseal_return_the_message_and_hide_the_context(plain_envelope, recipient):
    envelope, carl = plain_envelope
    raw_private, raw_public, key_id = recipient

    sealed = seal(envelope, carl, raw_public, key_id)

    assert form_of(sealed) == "sealed" and validate(sealed) is None
    assert sealed["messageId"] == "m-sealed-1"
    assert "message" not in sealed and "c-secret-thread" not in str(sealed)
    blob = base64.b64decode(sealed["sealed"]["hpke"]["ciphertext"])
    assert b"blue drawer" not in blob, "the body must not be readable in the envelope"
    ok, reason = verify_envelope(sealed, carl.public_key)
    assert ok, reason

    opened, reason = unseal(sealed, raw_private, key_id=key_id)
    assert reason == ""
    assert opened is not None
    assert opened["message"] == envelope["message"]
    assert validate(opened) is None and form_of(opened) == "plain"
    # The signature is the sealed envelope's, and it is kept as evidence rather than re-made: the
    # recipient does not sign the sender's message.
    assert opened["signature"] == sealed["signature"]


def test_a_receiver_with_the_wrong_key_refuses_rather_than_raises(plain_envelope, recipient):
    envelope, carl = plain_envelope
    _, raw_public, key_id = recipient
    sealed = seal(envelope, carl, raw_public, key_id)

    other_private = X25519PrivateKey.generate().private_bytes_raw()
    opened, reason = unseal(sealed, other_private, key_id=key_id)

    assert opened is None
    assert "authenticate" in reason


def test_a_body_sealed_for_another_key_id_is_named_as_such(plain_envelope, recipient):
    envelope, carl = plain_envelope
    raw_private, raw_public, key_id = recipient
    sealed = seal(envelope, carl, raw_public, key_id)

    opened, reason = unseal(sealed, raw_private, key_id="SHA256:someone-else")

    assert opened is None and "different recipient key" in reason


def test_a_tampered_ciphertext_is_a_refusal_not_an_exception(plain_envelope, recipient):
    envelope, carl = plain_envelope
    raw_private, raw_public, key_id = recipient
    sealed = seal(envelope, carl, raw_public, key_id)

    blob = bytearray(base64.b64decode(sealed["sealed"]["hpke"]["ciphertext"]))
    blob[0] ^= 0xFF
    sealed["sealed"]["hpke"]["ciphertext"] = base64.b64encode(bytes(blob)).decode()

    opened, reason = unseal(sealed, raw_private, key_id=key_id)

    assert opened is None and reason


def test_a_body_naming_a_different_id_is_malformed(plain_envelope, recipient):
    """The clear ``messageId`` is what the hub routed on and what ``seen`` holds; a body that
    disagrees is a protocol error, not an instruction to prefer the inner id."""
    envelope, carl = plain_envelope
    raw_private, raw_public, key_id = recipient
    inner = dict(envelope["message"], messageId="m-other")
    swapped = dict(envelope, message=inner)
    sealed = seal(swapped, carl, raw_public, key_id)
    sealed["messageId"] = "m-sealed-1"  # the hub's id; the body still says m-other
    sealed = sign({k: v for k, v in sealed.items() if k != "signature"}, carl)

    opened, reason = unseal(sealed, raw_private, key_id=key_id)

    assert opened is None and "messageId does not match" in reason


@pytest.mark.parametrize("field, value, expected", [
    ("enc", "not base64!!", "not base64"),
    ("ciphertext", "AAAA", "too short"),
    ("enc", "AAECAwQFBgc=", "32-byte key"),
])
def test_malformed_sealed_fields_are_refusals(plain_envelope, recipient, field, value, expected):
    envelope, carl = plain_envelope
    raw_private, raw_public, key_id = recipient
    sealed = seal(envelope, carl, raw_public, key_id)
    sealed["sealed"]["hpke"][field] = value
    sealed = sign({k: v for k, v in sealed.items() if k != "signature"}, carl)

    opened, reason = unseal(sealed, raw_private, key_id=key_id)

    assert opened is None and expected in reason


def test_unsealing_something_that_is_not_sealed_says_so(plain_envelope, recipient):
    envelope, _ = plain_envelope
    raw_private, _, key_id = recipient

    opened, reason = unseal(envelope, raw_private, key_id=key_id)

    assert opened is None and reason == "envelope is not sealed"


def test_sealing_an_already_sealed_envelope_is_refused(plain_envelope, recipient):
    envelope, carl = plain_envelope
    _, raw_public, key_id = recipient
    sealed = seal(envelope, carl, raw_public, key_id)

    with pytest.raises(ValueError, match="already sealed"):
        seal(sealed, carl, raw_public, key_id)


# --- SPEC §6 pins the sealed bytes (issue #83) ------------------------------------------
# Fixed vector: the sealed bytes for one message under fixed keys. The plaintext is the A2A
# Message JCS-encoded and HPKE aad/info are empty, so these bytes are the wire format — any
# change to the plaintext, the canonicalisation, the key schedule or the aad/info breaks this
# test on purpose. The keys are SHA-256 of fixed labels, recorded here so the vector is
# reproducible from the file alone.

VECTOR_RECIPIENT_PRIVATE = bytes.fromhex(
    "cc321355d1639ff05db17e4482540d93c784312dd526ade7185947296725f8cc")
VECTOR_RECIPIENT_PUBLIC = bytes.fromhex(
    "8ab511ae3443a130ea99527702dbc0fe345cdf6fa142c5951c245841bcf57814")
VECTOR_EPHEMERAL_PRIVATE = bytes.fromhex(
    "3f2ab8bdac9c83ffad31283a910cab59a32e9c845515ecf6d2dbc2c3e1967107")
VECTOR_ENC = "ZoP+fCmgLrtGt8vokdbvWVl14+QHAuSke2e/Ke/vMj4="
VECTOR_CIPHERTEXT = (
    "VwUDJmdYZfvnwTpw5HYxtuK6HPM3lZ09Qx4rPDAKsf1haeTy3f2UZPLm5meykYg8IjTBJwuWRCIrOS2Efy0VzjnN59SJn76ZMQka/"
    "u7tS49M3XsAWZRPLweDLMFzOh2rANcqY7/QTY3ueEYbHiYi+5GHAZfB2uJOSB3kYUer7eoUcgP3F2QJXR2Phdx9GBvdkvLws+"
    "qXUiq7aCJ74jVkhq+JuLfg3Tz7lg==")


def test_the_pinned_aad_and_info_are_named_constants():
    """The pin is a wire format, not an accident of defaults: the empty aad/info are named."""
    assert hpke.SEALED_AAD == b""
    assert hpke.SEALED_INFO == b""


def test_sealing_with_a_nonempty_aad_or_info_is_refused(plain_envelope, recipient):
    """SPEC §6 pins aad and info empty, and the envelope layer enforces it — a caller that asks
    for anything else gets a refusal, not a non-conformant sealed envelope."""
    envelope, carl = plain_envelope
    raw_private, raw_public, key_id = recipient

    with pytest.raises(ValueError, match="aad and info empty"):
        seal(envelope, carl, raw_public, key_id, aad=b"Count-0")
    with pytest.raises(ValueError, match="aad and info empty"):
        seal(envelope, carl, raw_public, key_id, info=b"Count-0")

    sealed = seal(envelope, carl, raw_public, key_id)
    opened, reason = unseal(sealed, raw_private, key_id=key_id, aad=b"Count-0")
    assert opened is None and "aad and info empty" in reason
    opened, reason = unseal(sealed, raw_private, key_id=key_id, info=b"Count-0")
    assert opened is None and "aad and info empty" in reason


def test_the_sealed_bytes_are_fixed_by_spec_section_6(plain_envelope):
    """The wire format, pinned: same message, same keys, same bytes. A future change to the
    plaintext, the canonicalisation, the key schedule or the aad/info must break this test."""
    envelope, carl = plain_envelope

    sealed = seal(envelope, carl, VECTOR_RECIPIENT_PUBLIC, "test-key-id",
                  encap_private=VECTOR_EPHEMERAL_PRIVATE)
    assert sealed["sealed"]["hpke"]["enc"] == VECTOR_ENC
    assert sealed["sealed"]["hpke"]["ciphertext"] == VECTOR_CIPHERTEXT

    opened, reason = unseal(sealed, VECTOR_RECIPIENT_PRIVATE, key_id="test-key-id")
    assert reason == "" and opened is not None
    assert opened["message"] == envelope["message"]
