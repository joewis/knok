# Review 05 — Sealed messages and HPKE

## Mode

Knok implements RFC 9180 HPKE **base mode (mode 0)** using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, one message per context. Base mode provides recipient confidentiality and ciphertext integrity, but it does not authenticate the sender. That is supplied by the separate Ed25519 envelope signature, which the receiving caller is required to verify before calling `unseal` (the ordering is explicit in `envelope.py` and decision 0003).

This is the right HPKE mode for “anyone may send to this agent; only the holder of the recipient private key may read”, provided the Ed25519 verification step is mandatory and precedes decryption. HPKE itself does not establish who sent the ciphertext.

## Binding table

| Value | What it is bound to | What changes if altered |
|---|---|---|
| HPKE `info` | Empty byte string by default. It is included in the HPKE key schedule; it is not currently derived from any envelope field. | A sender/receiver disagreement derives a different key and authentication fails. |
| HPKE `aad` | Empty byte string by default. It is authenticated by ChaCha20-Poly1305 but is not currently derived from any envelope field. | A sender/receiver disagreement causes AEAD authentication failure. |
| KEM context | `enc || recipient_public_key` in `_kem_shared_secret`. | Changing the encapsulated key or recipient public key changes the shared secret and derived key; the ciphertext will not open under the original recipient key. |
| Recipient key ID | Clear `sealed.recipientKeyId`, covered by the envelope signature. `unseal` compares it with the caller's `key_id` when supplied. | An unsigned edit breaks the envelope signature. A correctly signed but mismatched ID is refused before decryption. The ID is not itself an HPKE input. |
| `messageId` | Clear form-2 header, covered by the Ed25519 signature; copied from the inner Message and compared after decryption. | An unsigned edit breaks signature verification. If a valid sender signs a different clear ID around the old ciphertext, unseal refuses the inner/outer ID mismatch. It is not in AAD or info. |
| `contextId` | Inside the JCS-encoded A2A Message, hence inside the ciphertext and protected by AEAD. | Altering it requires producing a new valid ciphertext. It is not visible to the hub or separately represented in AAD/info. |
| Form and envelope version | The form is determined by the exclusive presence of `message` or `sealed`; `envelopeVersion` and all other envelope fields are covered by the Ed25519 signature. | Replacing form 2 with form 1, or changing the version, without a new valid sender signature is detected. HPKE does not independently bind these fields. |

The signature is the actual binding between the clear envelope header and the sealed body in this implementation. Empty AAD is therefore not an unauthenticated-header vulnerability when the caller obeys the verify-before-unseal contract. It is nevertheless a wire-format choice that must be specified before independent implementations interoperate.

## Findings

**No security findings in the scoped implementation under the repository's stated deployment model.** The following checks passed by inspection:

- `src/knok/hpke.py:103-126`: production default generates a fresh X25519 ephemeral private key for each `seal` call. The DH shared secret is used to derive one key and one base nonce for that single ciphertext; there is no exporter or persistent HPKE context.
- `src/knok/hpke.py:88-101`: the key schedule is explicitly mode 0 and sequence number zero. There is no multi-message nonce counter because each call is a single-shot context.
- `src/knok/envelope.py:246-285`: sealing JCS-encodes the complete A2A Message, including `contextId`, copies its `messageId` into the clear header, removes the old signature, and signs the new form-2 envelope. The signature covers both the ciphertext and clear header.
- `src/knok/envelope.py:288-347`: unsealing checks the optional recipient key ID, strictly base64-decodes the fields, opens the ciphertext, parses UTF-8 JSON, checks the inner/outer message ID, and validates the reconstructed form-1 envelope. It returns a refusal tuple rather than propagating ordinary hostile-ciphertext failures.
- `src/knok/hpke.py:128-151`: wrong-key, changed-AAD and changed-ciphertext AEAD failures converge on `HpkeError("sealed body does not authenticate under this key")`. The receiver cannot distinguish those cases from that exception. Earlier structural failures (bad base64, wrong lengths, unusable encapsulated point, or mismatched key ID) do have distinct local reason strings.
- `src/knok/envelope.py:288-347`: plaintext exists in process memory as the decoded `plaintext` bytes and parsed `message`, then is returned in the reconstructed envelope. These scoped functions do not write it to a queue, inbox, ledger, notice or log.

### Deliberate boundary / not a finding

- `encap_private` at `hpke.py:103-118` permits a caller to pin the ephemeral private key, explicitly for published-vector tests. Reusing that override for multiple messages to the same recipient with the same `info` would reuse the HPKE key and nonce, which is unsafe for ChaCha20-Poly1305. The production default is fresh generation, and the parameter is documented as test-only; no production call site is part of this brief. I have not promoted misuse of that documented test hook into a current defect. Keep it out of production call paths.
- `envelope.seal` receives the recipient's raw X25519 public key and key-ID string as separate caller arguments. It does not fetch or verify an Agent Card, or prove that the supplied ID fingerprints the supplied public key. The receiving side can compare the ID with its expected ID, and HPKE authentication proves possession of the corresponding private key. Card authenticity, key-record status and revocation are responsibilities of the caller/registry layer, outside this brief; no claim is made here that those checks are already wired into a live sealed-message path.
- Base mode intentionally has no sender authentication. Calling `unseal` without first verifying the sealed envelope would discard the system's sender-authentication guarantee. The function documents that precondition; decision 0003 places it after card and envelope verification.
- The opened envelope retains the signature over the *sealed* representation. It is evidence of the received sealed envelope, not a signature over the reconstructed form-1 object. Re-verifying the returned form-1 object is expected to fail; this is documented, not a defect.

## RFC vectors and test status

The brief names `tests/conformance/test_slice0.py` for the RFC vectors, but the RFC 9180 A.2.1 vectors actually live in `tests/test_sealed_envelope.py:33-70`. The conformance file is the A2A loopback harness and contains no HPKE vectors.

The A.2.1 tests cover:
1. the encapsulated public key, DHKEM shared secret, key and base nonce against the published values;
2. opening the published ciphertext to recover the published plaintext; and
3. sealing with the published ephemeral private key to reproduce the ciphertext byte-for-byte.

That is meaningful evidence for the implemented DHKEM/key schedule and the RFC's single-shot AEAD operation. It does **not** prove the envelope's chosen `aad`/`info` policy, fresh-ephemeral behaviour across multiple production messages, or multi-message context handling. The envelope tests separately cover round-trip, wrong recipient key, wrong key ID, tampering, malformed enc/ciphertext, and inner/outer message-ID mismatch.

I inspected the GitHub Actions run for commit `10134bb254a24674b8bf1406d5a02e8bea95d606` (run #152). The full suite completed with **375 passed and 36 failed**. None of the failures listed by pytest were in `tests/test_sealed_envelope.py`; the listed failures were dominated by fixtures rejected as `envelope has expired`. Thus the sealed-envelope/RFC tests passed in that run, but the repository-wide CI was red. This is not a clean full-suite pass.

## Open protocol gap — issue #83

This is explicitly **not filed as a defect**: issue [#83](https://github.com/joewis/knok/issues/83) is open and correctly identifies that SPEC §6 has not yet normatively fixed the plaintext encoding and HPKE `aad`/`info` values. The implementation currently seals `canonical_bytes(message)` and defaults both HPKE inputs to empty bytes. The issue says this must be written into §6 before the hub accepts form 2. Until then, this is a deliberate pre-interoperability gap, not a safe invitation for another implementation to choose its own values.

## Decryption boundary and refusal behaviour

Decision 0003 says the receiving bridge will verify the sender's card and signature, unseal before the gate, and hand plaintext form 1 to the queue. It also says the queue stores plaintext and the dead-letter record must retain the originally received ciphertext separately. The scoped code implements the primitive and envelope transformation only; it does not establish that the bridge → gate → queue integration is live. Accordingly, this review cannot claim where plaintext is persisted in the running system, whether an undecryptable message is retried or dead-lettered, or whether the sender receives a refusal. Decision 0003's intended behaviour is refusal followed by retry at the hub until TTL, but that is a design statement, not verified runtime behaviour in this scope.

The hub currently refuses form 2 at deposit, as decision 0003 records. Therefore there is no live end-to-end sealed-message path to downgrade or exploit at this point. At the envelope level, changing a signed form-2 envelope into form 1 is detected by signature verification; only the sender can create a valid plaintext form-1 envelope. Enforcement of a recipient's `sealedRequired` policy is outside these files and must be checked at the deposit/bridge policy boundary before sealed mail is enabled.

## Scope and method

Reviewed only the files named by brief 05, plus the specified decision 0003, SPEC §6 and issue #83 for context. No source code was changed. RFC tests were assessed from their test definitions and the repository's GitHub Actions run; I did not execute pytest locally.