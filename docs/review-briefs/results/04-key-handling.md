# Review 04 — Cryptographic key handling

## Lifecycle

| Stage | Implementation | Assessment |
|---|---|---|
| Generate signing key | `identity.py::generate` calls `Ed25519PrivateKey.generate()`; the cryptography backend supplies the key-generation randomness. Agent name and hub are used only as identity labels, not as key derivation input. | Good: no passphrase, hostname, environment variable, clock, or agent-id derivation. |
| Store signing key | `Identity.save()` serialises unencrypted PKCS#8 PEM and creates the destination with `O_CREAT | O_EXCL`, mode `0600`. | File mode is set correctly on creation; see F1 for load-time enforcement. Write is direct to the final path, not temp-file + rename, and is not fsynced. |
| Load signing key | `identity.py::load` reads PEM, requires Ed25519, and compares its derived fingerprint with the expected registry fingerprint. CLI loads `KNOK_STATE/identity.key` against the local card's public key. | Strong identity-to-key binding; no permission/owner check. |
| Publish signing key | `agentcard.py::sign_card` requires the card's `bridge.publicKey` to match the signing identity and signs the canonical card using EdDSA. The JWS `kid` is the key fingerprint. | Card body, name, and public key are cryptographically bound. |
| Verify/use signing key | Envelope and card signatures are checked against the public key selected from the pinned card/registry. Hub verification uses `Hub._card_public_key`; the local bridge checks its pinned card before accepting messages. | Correct signature-key binding for the supported card/dict trust model. |
| Rotate | There is no dedicated rotate command. `keygen` writes `<name>.key` and refuses overwrite. A new card/key can be installed manually. `Registry` and `KeyRecord` model historical key records, but the hub constructor still copies a plain dict. | Historical rotation is not operational at the hub yet; see “Known implementation boundary” below. |
| Revoke | `Contacts.revoke()` revokes a contact relationship, not a cryptographic key. `KeyRecord.status()` models cryptographic revocation, but the hub's current dict registry has no revocation timestamps. | Do not confuse contact revocation with key revocation. |
| Destroy | No key-destruction or secure-erasure command exists. Removing/replacing a private-key file is an operator action. | Filesystem deletion is not guaranteed secure erasure on SSDs, copy-on-write filesystems, snapshots, or backups. |

## Findings

### F1 — Private-key loading accepts files with unsafe permissions

**Severity: Medium in a multi-user/shared-host deployment; Low on a single-user host with correctly managed state directories**  
**Location:** `src/knok/identity.py:94-111`; caller: `src/knok/cli.py:67-75`.

`Identity.save()` creates a new key file with mode `0600`, but `Identity.load()` simply reads the path and parses the PEM. It does not inspect the file's mode, owner, or whether the path is a symlink. Consequently, a key copied from a backup, manually installed, restored with incorrect permissions, or made permissive later is silently accepted.

Example: change `identity.key` to mode `0644`. Knok continues to load and use the key even though every local user can read it. The mode set by `save()` protects the initial write; it does not protect the actual runtime trust boundary after the file is changed or provisioned by another mechanism.

The spec says the private key is held in a file with mode `0600`, owned by the agent's user (§3). Enforce that invariant when loading, or make the policy explicit if non-POSIX platforms are supported. At minimum, reject group/world-readable files on POSIX and report a clear error. Consider checking ownership as well where the process has a meaningful per-agent UID. A symlink policy should be deliberate rather than accidental.

### F2 — Key-file creation is not crash-atomic or durable

**Severity: Low (availability / provisioning reliability, not key disclosure)**  
**Location:** `src/knok/identity.py:94-103`.

The key is written directly to its final path after an exclusive create. If the process or machine stops during `handle.write(pem)`, a truncated file remains at the final name. The next key-generation attempt refuses to overwrite it, while `load()` fails to parse it. Recovery requires an operator to identify and remove the incomplete file before generating or restoring the key.

The use of `O_EXCL` correctly prevents overwriting an existing key and avoids a simple check-then-create race. The weakness is only interruption handling: there is no temporary file, atomic rename, flush/fsync, or directory fsync. Write to a same-directory temporary file with restrictive permissions, fsync it, atomically install it without replacing an existing destination, then fsync the directory. If this is intentionally a minimal provisioning utility, document that a failed generation may leave a partial file and provide a safe recovery instruction.

## Approval and trust binding

The contact approval implementation is materially stronger than a name-only approval:

- `Contacts.pending()` returns the peer, request text, presentation time, and fingerprint that arrived with the request. The request record is local; the peer sees `requested`, not the internal `held` state.
- `approve()` requires the fingerprint supplied by the caller to equal the fingerprint stored with the presented request. A mismatch is refused. The decision row records both presented and decided fingerprints; on the approval path they are equal by construction.
- `deny()` deliberately records a mismatch instead of refusing it. Refusing a rotated key is safe, and the audit should preserve which key was presented and which key was on screen when the owner denied it.
- Decisions are append-only. A later presentation/decision supersedes the earlier row instead of silently rewriting its history.
- `accept()` separately requires an approved decision. A contact request cannot become accepted merely because a caller invokes `accept()`.

This matches SPEC §9 and the decision described in the code. The owner-facing presentation itself cannot be verified in this review: the inspected CLI exposes send/recv/inbox/notices/retry commands, but no contact-approval UI or command. The Contacts API supplies the data needed for a prompt; it does not prove what a separate caller actually displayed.

One audit caveat: `decided_by` is supplied by the caller to `approve()` and `deny()`; Contacts does not authenticate it against the operating-system user or another identity provider. The stored actor is therefore an assertion made by the caller, not independently verified attribution. That is acceptable if only a trusted owner-controlled process can call this local API. It is not a reliable multi-user audit identity without an authenticated caller boundary.

## Key separation and exposure

- Ed25519 is used for signing. X25519 is a distinct key type used by the HPKE implementation; no Ed25519 private key is reused as an X25519 key.
- `hpke.py` generates an ephemeral X25519 key for each seal operation and accepts the recipient's raw X25519 private bytes as an argument when opening. The reviewed scope contains no persistent X25519 private-key generation/storage path. The bridge's sealed-envelope receive path is not yet live, so there is no evidence here of an integrated recipient-key vault. The key-management implications of the HPKE flow belong in Review 05.
- The signing private key is serialised unencrypted as PKCS#8 PEM. Its protection is the OS file permission and host/user boundary, not encryption at rest. A copied key file or host-level compromise gives the attacker the ability to sign as that agent.
- The reviewed code prints the private-key file path, public key and fingerprint during key generation, not private-key bytes. Identity error messages can disclose a path and public fingerprint, but no private material. No private key is included in an envelope or Agent Card.
- Python objects retain the private-key object in process memory for as long as the `Identity` object is reachable. There is no explicit zeroisation; this is normal for this Python/cryptography design and should not be represented as secure memory erasure.

## Known implementation boundary — rotation and revocation

This is a documented incomplete phase, not a new finding.

`registry.py` has a useful `KeyRecord` model: it checks that a fingerprint matches the public key and can report `valid`, `not-yet-valid`, `expired`, `revoked`, or `superseded` for a given instant. `verify_card()` can consult a `Registry` object.

The live hub path does not currently use that model. `Hub.__init__` accepts a `dict[str, str]` and copies it with `dict(registry)`; `Hub._card_public_key()` then passes that plain dictionary to `verify_card()`. The dictionary form means every included key is valid forever. There is no per-agent key history at the hub, no key-revocation command, and no registry publication/fetch path. Removing a key from the dictionary withdraws it immediately but also loses historical verification; leaving it in means it remains valid indefinitely.

Decision 0002 and SPEC §4 explicitly say signed registry records and publication are not implemented yet. The sender-asserted `sentAt` limitation is also already recorded in issue #90 and SPEC §4; it should not be counted again as a newly discovered key-handling defect.

## Failure behaviour and test coverage

- Missing key file: `Path.read_bytes()` raises `FileNotFoundError`; malformed/truncated PEM raises the cryptography loader's exception. These are not converted to a stable `IdentityError` by `load()`. In the CLI path, that can surface as a traceback rather than a concise provisioning error.
- Wrong key type: explicitly refused with `IdentityError`.
- Wrong identity/key pairing: refused by fingerprint comparison before the key is returned.
- Existing destination: `save()` refuses overwrite.
- Invalid/tampered card: card verification fails closed; a bad file is dropped from `load_cards()` rather than stopping the entire directory load.
- Card identity binding: the signed `name@hub` is checked; a card cannot be moved to another filename to grant its key authority over that filename's identity.
- Card expiry: `validUntil` is checked on use by the bridge; an unreadable stated expiry is refused.
- Approval mismatch: approval refuses a key that differs from the fingerprint presented; denial records the mismatch.

The specified tests were reviewed statically, not run. Existing tests cover key generation uniqueness, key-file mode on initial save, overwrite refusal, save/load round-trip, fingerprint mismatch, card signature and identity binding, card expiry, and approval/denial fingerprint history. They do not cover permissive key-file loading, wrong file ownership, interrupted key writes, or the hub's inability to consume the record-based registry.
