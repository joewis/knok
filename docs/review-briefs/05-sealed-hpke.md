# Review brief 5 — Sealed messages and HPKE

You are reviewing the sealed-message path: the HPKE implementation, what it binds, and what the
receiving side does with a body it cannot open. Report findings, not a summary.

## Scope — read only these

- `src/knok/hpke.py` — `key_schedule`, `seal`, `open_sealed`, `_kem_shared_secret`
- `src/knok/envelope.py` — `seal` / `unseal` and the form-2 envelope shape
- `tests/conformance/test_slice0.py` — the RFC 9180 A.2 vectors
- `tests/test_sealed_envelope.py`

## Context

- `docs/decisions/0003-sealed-decryption-boundary.md` — where decryption happens, and why
- `docs/SPEC.md` §6 (forms)
- Issue **#83** — what bytes are sealed and what `aad` / `info` are; still open

## Deliberately outside this brief

Transport and request authentication (brief 1). Key storage (brief 4). This brief assumes the keys
exist and are correct and asks what the sealed path does with them.

## Questions

1. **Mode.** Which HPKE mode is implemented — base, psk, auth, auth-psk? Is that the right mode for
   "anyone may send to this agent, only the holder may read"? What does base mode leave
   unauthenticated, and where else does the system supply that assurance?
2. **Vectors.** Run the RFC 9180 A.2 vectors in both directions. If they pass, say precisely what
   that proves (key schedule, ciphertext reproducibility) and what it does not (nonce reuse under
   this code's own framing, `aad`/`info` correctness, multi-message behaviour).
3. **Binding.** What exactly are `info` and `aad`, and what are they bound to — recipient, sender,
   `messageId`, `contextId`, form, version? Attempt to move a ciphertext: another recipient, another
   `messageId`, another context, another form. Which of those still open, and what does that allow?
4. **Freshness.** Is a fresh ephemeral key generated per message? Is the KEM shared secret used once?
   Is any value reused across messages or across recipients — salt, context, export secret?
5. **Recipient key.** Where does the recipient's public key come from at seal time, and what happens
   if it is stale, revoked, or belongs to another agent? Is the encryption key the same as the
   identity key, and does the sender verify the card before using it?
6. **Failure.** On a wrong key, wrong `aad`, truncated ciphertext, or tampered bytes: refusal or
   exception? Does the failure reveal which of those it was, and to whom?
7. **Plaintext lifetime.** Once opened, where does the plaintext exist — memory, the queue, the inbox
   file, the delivery ledger, a notice, a log, a traceback? Which of those is a change from the
   plaintext path, and which contradict 0003's boundary?
8. **Refusal to decrypt.** What happens to a sealed message the receiver cannot open — dropped,
   retried, dead-lettered, held, or does it block the queue? Is the sender told anything?
9. **Downgrade.** Can a sender make a sealed message arrive as plaintext, or vice versa, without the
   receiver noticing? What does the form field contribute to the signature and to policy?

## Report

Begin with the mode and its limits in three sentences. Then an `aad`/`info` binding table (value →
what it is bound to → what breaks if changed). Then findings as `F1`, `F2`, … with `file:line` and
the failing input. Anything that is #83's open question is a gap to name, not a defect to file.
