# Working on this

Two authors: **Carl** (`carl@elitedesk`, Hermes agent with this checkout) and **Muse** (`muse@muse-vm`,
the agent on the Muse VM). Both have write access to this repository, and neither pushes to `main`.

## The loop

1. **Issue first.** Whoever spots work opens an issue and labels it `spec`, `code` or `question`.
   One decision per issue, so the history stays readable.
2. **Branch.** Work happens on `carl/<topic>` or `muse/<topic>`, branched from `main` and kept short —
   a branch that lives longer than a few days is a branch that will conflict.
3. **Pull request.** The PR description says what changed and **why**, and for a spec change names
   the section. "Looks good" is not a review; "§6 is wrong because ack is a transport operation and
   the text treats it as a message" is.
4. **Review by the other author.** Carl reviews Muse's PRs, Muse reviews Carl's. The author of a PR
   never merges it. Review happens in the PR, not over the bridge — the diff is the argument.
5. **Merge.** Squash to one commit per decision, then delete the branch.

## If Muse's access is revoked

The fallback is the original shape and still works: Muse answers over the bridge with patch-shaped
text — section heading, replacement text, one line of reasoning — and Carl applies it as a commit
with `Co-authored-by: Muse <muse@muse-vm>`. Nothing else about the workflow changes.

## Credentials

Muse authenticates with a **deploy key scoped to this repository**, write access, no account-wide
permissions, revocable from one settings page. A personal access token is not used: a PAT carries
scopes beyond this repo and expires on a calendar nobody is watching.

- The private half lives on the Muse VM, mode 0600, owned by the user that runs the agent.
- Commits are attributed with `git config user.name "Muse"` and
  `git config user.email "muse@muse-vm"`; GitHub shows them as unattributed, so a deploy-key commit
  carries `Co-authored-by: Muse <muse@muse-vm>` when the work is substantial enough to matter.
- A deploy key that leaks is deleted in one place and grants nothing outside this repo. Rotate it
  the same day the VM is rebuilt.

## Rules

- **Never push to `main`.** The rule is enforced by the two authors, not by GitHub: branch
  protection is not available on a private repository on a free account (it arrives when the repo
  goes public, which is where this is headed). Until then the protection is a habit, so the habit has
  to be explicit — check `git branch --show-current` before a push, and never `git push` from a
  detached state.
- **One decision per commit.** A commit that changes topology *and* the envelope is two commits.
- **The spec is the artifact.** Code follows the spec; when code proves the spec wrong, the spec
  changes in the same PR.
- **No secret ever enters the repo.** Keys, tokens, hostnames that resolve to private addresses, and
  personal data live in the deployment, not here. A secret that reaches a commit is rotated, not
  deleted — the history keeps it.
- **Every open question gets an answer before the phase that depends on it starts.** §12 lists them;
  they are not decorations.
- **Reviews are adversarial on purpose.** The useful reply is "this is wrong because…".

## Commit style

`<area>: <what changed and why>`, one line, imperative, no full stop.

```
spec: §7 routing — public hub is the same binary with a registry, not a fork
code: envelope — sign the canonical bytes, not the JSON string
fix: queue — fsync before ack, or the durability promise is a lie
```

## Conflict resolution

Muse rebases onto `main`; only the branch owner force-pushes their own branch, and only after a
review comment says why. If a branch conflicts with `main` and the fix is not obvious, the PR is
closed and the decision is re-opened as an issue — a three-way merge of two agents' edits to the
same paragraph is how a spec acquires sentences nobody wrote.
