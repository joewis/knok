# Review brief 4 — Cryptographic key handling

You are reviewing the lifecycle of every private and public key in the system: where it is made, how
it is stored, what it can do, what happens when it is rotated, and what an attacker gets if they take
it. Report findings, not a summary.

## Scope — read only these

- `src/knok/identity.py` — sign/verify, key loading and saving
- `src/knok/keygen.py` — key creation
- `src/knok/agentcard.py` — the card that publishes a public key
- `src/knok/contacts.py` — key records, `request`, `approve`, `deny`, `revoke`, `decision`
- `src/knok/hub.py` — `_card_public_key`
- `src/knok/cli.py` — the key and approval commands
- `tests/test_identity.py`, `tests/test_card_body.py`, `tests/test_card_expiry.py`,
  `tests/test_pinned_identity.py`

## Context

- `docs/decisions/0002-registry-and-key-records.md`
- `docs/SPEC.md` §5 (identity) and §9 (approval)
- Issue **#90** — what a revoked key can still do, and the decision pending on it

## Deliberately outside this brief

HPKE's own scheme (brief 5). Here you check how the sealing key is stored and used, not whether the
KEM is right.

## Questions

1. **Generation.** Where does key material come from — which RNG call, seeded how? Is any key
   derived from a passphrase, an environment variable, an agent id, a hostname, or a clock?
2. **Storage.** For every artefact holding private material: file mode, ownership, directory mode,
   atomicity of the write, and what exists on disk if the write is interrupted. Is a key ever
   written to a temp file, a backup, or a world-readable location?
3. **Exposure.** Can private material reach a log line, an exception message, a notice, a
   serialised envelope, `argv`, or an environment dump? Search every `format`, `%`, `f"` and `repr`
   that touches an identity object.
4. **Separation.** Are Ed25519 (signing) and X25519 (sealing) distinct keys? If one key serves both,
   state the cost precisely. Is a card's signing key the same as its encryption key, and does the
   registry verify them the same way?
5. **Rotation.** Walk the full path: a peer rotates, publishes a new card, the registry records it.
   What does the registry keep per name — one record or a history? What can the old key still do:
   sign, receive, decrypt, authenticate a request, accept an approval? Which of those is intended?
6. **Trust binding.** When a card is trusted, what is bound to what: name, fingerprint, key bytes,
   validity window, hub? Can a card be moved to another name, another hub, or another agent's file
   without detection? What is the "pinned" rule and where is it enforced?
7. **Approval.** What exactly does the owner see on screen, and what is recorded? Can a decision be
   recorded against a key the owner did not see? Read §9's answer and check the code matches it —
   `approve` refuses a mismatch while `deny` records it, and the two columns are equal by
   construction on one path.
8. **Lifetime in memory.** Is key material copied into long-lived objects, cached without bound,
   held by a connection, or left in a traceback?
9. **Failure.** What happens when a key file is missing, truncated, has the wrong mode, or belongs to
   another identity? Refusal or traceback? Does the message leak the path or the key?

## Report

Begin with a lifecycle table: generate → store → publish → use → rotate → revoke → destroy, one row
per step, with the file and line where each happens. Then findings on the rows: `F1`, `F2`, … with
`file:line`, the failing input or sequence, the consequence, and whether the design intended it.
Anything that is #90's open decision should be named as such, not re-reported as a new defect.
