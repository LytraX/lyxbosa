# Working on LyxBoSa

Conventions every agent and human on this repository follows. `CLAUDE.md` imports this file.

## Never push customer data. Check, don't assume.

**This repository is public.** It is built from real incident data, and the working tree
holds material that must never leave the machine: `trail-data/`, `corpus/local/`,
`corpus/blobs/`, `corpus/shards/`, and the pseudonym maps under
`trail-data/incoming/*/private/`. All of it is gitignored. Gitignored is not a guarantee —
it is a default that a single `git add -f`, a new directory, or a name written into a source
comment gets around.

**Before you push, or before you suggest a push, run:**

```
python3 corpus/pre-push-check.py
```

It exits non-zero and prints `REFUSE TO PUSH` if any tracked file, **any commit message
about to be pushed**, or the published index carries a customer identifier. Takes about 3
seconds over ~160 files. If it refuses, fix the finding — do not push and do not reason your
way past it.

**A commit message counts, and it is the harder half.** The first version of this script
checked only files, reported SAFE TO PUSH, and a message naming three accounts was already on
the remote — in the paragraph explaining the lesson about not naming them. A message is as
permanent as a blob and worse to remove: once a pull request references the commit, its
`refs/pull/*` ref is server-side, cannot be pushed to or deleted, and only deleting the
repository clears it. So **run the check before opening a PR, not after** — that ordering is
the whole reason to use a PR here rather than pushing to `master` directly.

Prove it still works when you change it:

```
python3 corpus/pre-push-check.py --inject
```

### Why this file exists

On 2026-09-05 a scan report naming four customer sites next to malware findings was found in
this repository's public history. It had been committed by accident 69 commits earlier and
`.gitignore` already declared it; nobody noticed because nothing ever looked.

Rewriting history did not fix it. GitHub kept serving the old objects by SHA, and those SHAs
were published on the repository's own pull-request pages — `refs/pull/*` is server-side and
cannot be pushed to or deleted. Anonymous, unauthenticated requests still returned the file
after the rewrite and the force-push. **The repository had to be deleted and recreated.**
Seven pull requests and the CI history went with it.

Three minutes of checking would have prevented all of it.

## A check that has never been observed to fail is not yet a check

Five checks written during that incident passed while being blind:

- a regex matching `/home/` that could not see `/home2/`, where the largest account lived
- a per-ref sweep that could not see a stale worktree pinning the entire old history
- a two-file question asked about one of the two files
- four substring sweeps that reported thousands of coincidences and no real hits
- a status check that read a 404 response body as success, and reported all ten objects
  present when every one was already gone — exactly inverted

What caught each one was a **positive control**: asserting that the check can also say the
other thing. Every checker in `corpus/` has an `--inject` mode for this reason. When you add
a check, add its control in the same commit, and run it before you trust a green result.

## `grep` here cannot see the files that matter

`grep` is a shell function wrapping a tool that respects `.gitignore`. Every gitignored tree
is invisible to it — including the **237 Python files under `trail-data/`**, which is where
the passes that wrote most of this index actually live: the sensitivity tagger, the second
decoder, and the writers of every field `field-provenance.py` reports as an orphan.

So a sweep that concludes *nothing reads this field* or *no tool writes this string* is
**unproven** when it was run through the wrapper. Use `command grep` (or `find`) for any
question about what exists on this machine, and say which you used when you report the
answer.

This was found the hard way: a reader sweep over the whole tree returned nothing, and the
writer it was looking for was sitting in a directory the sweep never opened. Both counts
differ — 5 hits against 8 — on a question as ordinary as which files define a function.

## Describe collisions; do not quote them

When documenting a false positive, name the identifier by shape — "a six-letter label matched
inside a stock class name" — never by spelling it out. Writing a client name into a comment
puts it in git exactly as surely as an unmasked data row does.

This happened five times in one day, including in a commit titled "scrub three client names",
in a masking tool's own explanation of prefix-collapsing, and in the docstring of the very
script written to catch it. That last one was refused by the script itself. It is a
remarkably easy mistake to make; assume you will make it, and let the tool tell you.

## Before you report a round green

Three commands, all three, every time. Two of them were already habit; the third is here
because a round was reported green while it was failing.

```
python3 corpus/shard-gate.py corpus/index.jsonl              # published half
python3 corpus/shard-gate.py corpus/local/index-local.jsonl  # local half
python3 corpus/make-summary.py --check                       # the summary vs the index
```

`make-summary.py --check` is the authority on whether `index-summary.json` still describes
the index, and the summary is the denominator every suite run quotes. A round that moves
rows and does not regenerate it leaves a published file asserting counts that no longer
exist — and the gate runs cannot see that, because they read the index and not the summary.
Regenerate it in the commit where the counts settle, and say in that commit that `--check`
was failing until you did.

## Measurement conventions

- **Every count difference carries an attributed cause.** A number that changed is not a
  result until it says why. See `docs/tasks/CORPUS_PLAN.md` §8.
- **State the power of a sampling check**, not just its outcome. Eight files out of 191,141
  detect a 1%-of-files discrepancy 7.7% of the time; reporting "verified" from that is
  reporting nothing. §11.
- **A denominator enumerated by the same process that produced the numerator bounds the
  result, not reality.** Eleven instances are recorded in §11. Assume a twelfth exists in
  whatever you measure next — and note that a *tool* can carry the property as readily as a
  measurement: four of the eleven are the orphan census bounding its own answer, in four
  different ways, each one found only after the previous repair was called done.
- **Never report a detection figure taken across a changing binary or a changing index.**
  `corpus/verify.py` reads `$LYXBOSA_BIN`, defaulting to `build-release/lyxbosa`; point it at
  your own build rather than rebuilding the one another session is measuring with.

## Index writes

Every write to either half of the corpus index goes through `corpus/indexio.py`:
`write_jsonl_atomic` for the write, `index_lock` held across the **whole** read-modify-write,
and re-read inside the lock immediately before writing. Never `open(path, "w")` on an index —
that truncates 62 MB before the first row lands, and a stale full-file rewrite drops another
writer's rows with every gate still passing.

## Branches

Every branch starts from `master`. Never branch off another feature branch: if the next task
needs the current one's work, push it, merge it, then branch from the updated `master`.
Chained branches leave ancestry nobody can follow, and a prompt that depends on unmerged work
is chaining one level up.
