# Review briefs

One review is not a review of a system; it is a review of whatever the reviewer happened to read.
These briefs cut the repository into areas small enough to hold in one pass, and give each pass the
questions it exists to answer.

Give a reviewer one brief and the files it names — not the repository. A reviewer handed the whole
tree will summarise it, and a summary is not evidence.

| # | Brief | Answers |
|---|---|---|
| 1 | [Authentication and request replay](01-authentication-and-replay.md) | Who is this request from, and can it be used twice? |
| 2 | [The hub's HTTP implementation](02-hub-http.md) | What does the server accept, and what bounds it? |
| 3 | [Envelope and canonicalisation](03-envelope-and-canonicalisation.md) | What does a signature actually cover? |
| 4 | [Cryptographic key handling](04-key-handling.md) | Where do keys live, and what can an old one still do? |
| 5 | [Sealed messages and HPKE](05-sealed-hpke.md) | What is bound to a ciphertext, and where does plaintext go? |
| 6 | [Delivery, queue and durability](06-delivery-durability.md) | What survives a crash, and what is duplicated? |
| 7 | [Retry policy and CLI](07-retry-and-cli.md) | Is a retry the same message, and does the exit code lie? |
| 8 | [Contact gate and abuse](08-gate-and-abuse.md) | What can a peer make the system do, and learn? |
| 9 | [Logging and notices](09-logging-and-notices.md) | What is written down, and who can read it? |

## Ground rules — paste these with every brief

- The spec is a claim, the code is an implementation, and they can disagree. A disagreement is a
  finding; say which of the two you believe and why.
- A behaviour you dislike is not a defect. Name the input, the outcome, and why it matters. If it is
  deliberate and documented — in the decision records, or `docs/HUB.md`'s known-risks list — say you
  are restating a documented risk rather than discovering one.
- Severity is consequence × reachability on the deployment `README.md` describes, not on a
  hypothetical public hub. State which deployment you assume.
- Do not propose a fix before you have stated the failure. A fix without a failing input is a guess.

## Using a model reviewer

- **One brief per run.** Attach the files in its *Scope* section and nothing else. This is also what
  keeps a small-context model from choking.
- **Ask for the table first.** Each brief names a table (endpoints, bounds, crash points, outcomes).
  A reviewer that cannot fill the table has not read the code.
- **Demand `file:line` and the failing input.** Reject prose findings; ask it to redo the finding with
  a line number or drop it.
- **Say what is already decided.** Briefs 1, 4 and 5 name the deliberate designs and the open issues.
  Without that, a reviewer re-reports them as defects — which is exactly what the first attempt did.
- **Two passes per area if the reviewer is weak.** Pass one: read and fill the table. Pass two: attack
  the table. A single pass over nine files produces a plausible summary; two produce findings.

## What is out of bounds for every brief

Nothing in this repository is deployed publicly. The threat model in `docs/SPEC.md` §11 applies: the
hub is untrusted for confidentiality, trusted for availability; the bridge holds keys; peers are
authenticated but not trusted. A finding that assumes a hostile hub operator, a hostile kernel, or a
compromised host is out of scope — say so and stop.

## How the citations were counted

Counts taken 2026-11-21. Every `path:line` and `path:line-line` reference in
`results/0*.md` was matched with this expression, one match per citation:

```python
R = re.compile(r"`((?:src|tests|docs)/[^`\s:()]+):(\d+)(?:-(\d+))?`")
```

That is: a single inline-code span whose whole body is a path under `src/`, `tests/` or `docs/`, a
colon, a line number, and an optional `-end` with a plain hyphen. The span must close immediately
after the number or range — prose inside the backticks disqualifies the span.

| File | Citations |
|---|---|
| 01 authentication and replay | 89 |
| 02 hub HTTP | 172 |
| 03 envelope and canonicalisation | 95 |
| 04 key handling | 83 |
| 05 sealed HPKE | 103 |
| 06 delivery durability | 199 |
| 07 retry and CLI | 128 |
| 08 gate and abuse | 240 |
| 09 logging and notices | 280 |
| **Total** | **1,389** |

Two counts, and why they agree. The broad count above is 1,389. The narrow count — the same spans,
kept only if they resolve inside the pinned commit — is also 1,389, because every one of them
resolves. A number smaller than 1,389 is not a stricter count; it is an undercount.

What neither count includes: 14 spans list several ranges in one span, or use an en dash instead of
a hyphen (`` `src/knok/queue.py:508-531, 532-572, 600-610, 704-747` ``,
`` `src/knok/bridge.py:831–849` ``). They carry 26 ranges between them, so counting every individual
range rather than every span gives 1,415. The 1,389 figure counts spans, not ranges.

Resolution. For each of the 1,389 citations, `git show 828c9791:<path>` succeeds and the range
satisfies `1 <= start <= end <= <line count of that file at that commit>`. All 1,389 pass. Review 01
pins itself to `393197d4` rather than `828c9791`; its 89 citations resolve at both.

The pin is not current main, and these reviews do not describe current main. `828c9791` is nine
commits behind `origin/main` as of 2026-11-21 — `ac34d0d`, `6270b5a`, `f202db8` and six others landed
after it — and 12 of the 47 cited files have changed since. The line numbers are true of the pinned
tree only. To check a citation against today's `main`, resolve it at `828c9791` first: a line that
has moved is drift, not a bad citation.
