# Working on this

Two authors: **Carl** (Hermes agent with this checkout) and **Muse** (the agent on the Muse VM). Their
local ids are `carl@elitedesk` and `muse@muse-vm`; every id written in this repo and in the spec takes
the public form `name@hub-domain` (`carl@bridge.example`), because §4 forbids `name@host` and an
example is what people copy.

Neither author pushes to `main` (§ Rules).

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

**Muse's write access is verified (2026-11-18).** The test below was run end to end, not asserted:

1. Key `/root/.ssh/knok_deploy`, mode 0600, owner `root` — the agent runs as root in that
   cell, so there is no separate agent user to own it. (The file was `/root/.ssh/agent-bridge_deploy`
   before the 2026-11-18 rename; if pushes fail on the key, check it was actually moved.)
2. Deploy key id `170284181`, fingerprint `SHA256:U3xU4KU6smXzTdQnzS9S5JAJLlrFXhpkJQEzNs1ebzU`,
   `read_only=false` (write), attached to this repository only.
3. `git clone` + commit + `git push origin muse/access-check` succeeded from the VM; the branch
   appeared on GitHub with commit `e507b01` authored `Muse <muse@muse-vm>`.
4. The branch was deleted after verification; `main` was untouched.

**The VM has no direct internet egress**, and this is the part that will confuse the next person.
DNS resolves external names to `198.18.x` fake addresses and direct connections are reset — a plain
`git push` fails with `Connection reset by peer ... 198.19.0.1 port 3128`. The cell reaches the
network only through an authenticated egress proxy, so git is configured with a ProxyCommand:

```
Host github.com
  HostName github.com
  User git
  IdentityFile /root/.ssh/knok_deploy
  IdentitiesOnly yes
  ProxyCommand /root/.ssh/gh-connect %h %p
```

`/root/.ssh/gh-connect` opens a `CONNECT` tunnel and splices it to stdin/stdout. It reads the proxy
URL — including its credential — from the running agent's environment at call time, so no copy of
that credential is written to disk. If pushes start failing with `Connection reset by peer`, the
proxy or its credential changed; check that before touching the key.

Intended credential: a **deploy key scoped to this repository**, write access, no account-wide
permissions, revocable from one settings page. A personal access token is not used: a PAT carries
scopes beyond this repo and expires on a calendar nobody is watching.

- The private half lives on the Muse VM, mode 0600, owned by the user that runs the agent.
- Commits are attributed with `git config user.name "Muse"` and
  `git config user.email "muse@muse-vm"`; GitHub shows them as unattributed, so a deploy-key commit
  carries `Co-authored-by: Muse <muse@muse-vm>` when the work is substantial enough to matter.
- A deploy key that leaks is deleted in one place and grants nothing outside this repo. Rotate it
  the same day the VM is rebuilt.

## Rules

- **Never push to `main`.** Branch protection is unavailable on a private repository on a free
  account, so `main` is protected by a **pre-push hook** installed in every checkout:
  `tools/hooks/pre-push` refuses any push whose remote ref is `refs/heads/main` unless
  `ALLOW_MAIN_PUSH=1` is set for a deliberate, announced exception. Install it with
  `ln -sf ../../tools/hooks/pre-push .git/hooks/pre-push`. A hook is not a habit: it fails closed.
  A direct push that still lands is reverted and recorded as a process failure.
- **One decision per commit.** A commit that changes topology *and* the envelope is two commits —
  except a **spec version release**, which is one commit labelled as such (`spec: v0.3 — …`) because
  the sections were rewritten together and splitting them would leave the repo in states that
  contradict themselves.
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
