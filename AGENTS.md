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

It exits non-zero and prints `REFUSE TO PUSH` if any tracked file or the published index
carries a customer identifier. Takes about 3 seconds over ~160 files. If it refuses, fix the
finding — do not push and do not reason your way past it.

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

## Describe collisions; do not quote them

When documenting a false positive, name the identifier by shape — "a six-letter label matched
inside a stock class name" — never by spelling it out. Writing a client name into a comment
puts it in git exactly as surely as an unmasked data row does.

This happened five times in one day, including in a commit titled "scrub three client names",
in a masking tool's own explanation of prefix-collapsing, and in the docstring of the very
script written to catch it. That last one was refused by the script itself. It is a
remarkably easy mistake to make; assume you will make it, and let the tool tell you.

## Measurement conventions

- **Every count difference carries an attributed cause.** A number that changed is not a
  result until it says why. See `docs/tasks/CORPUS_PLAN.md` §8.
- **State the power of a sampling check**, not just its outcome. Eight files out of 191,141
  detect a 1%-of-files discrepancy 7.7% of the time; reporting "verified" from that is
  reporting nothing. §11.
- **A denominator enumerated by the same process that produced the numerator bounds the
  result, not reality.** Five instances are recorded in §11. Assume a sixth exists in
  whatever you measure next.
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
