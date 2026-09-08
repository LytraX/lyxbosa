# Working on LyxBoSa

Conventions every agent and human on this repository follows. `CLAUDE.md` imports this file.

## Never push customer data. Check, don't assume.

**This repository is public.** It is built from real incident data, and the working tree
holds material that must never leave the machine: `trail-data/`, `corpus/local/`,
`corpus/blobs/`, `corpus/shards/`, and the pseudonym maps under
`trail-data/incoming/*/private/`. All of it is gitignored. Gitignored is not a guarantee —
it is a default that a single `git add -f`, a new directory, or a name written into a source
comment gets around.

**Gate the push on it. Not before it — on it:**

```
python3 corpus/pre-push-check.py && git push origin <branch>
```

The `&&` is the instruction. Running the check and then pushing on the next line is not the
same thing, and the difference has already been paid for: on 2026-09-07 the check printed
`REFUSE TO PUSH` and the push went out anyway, because the two were separate statements. The
finding that time was a stale figure rather than an identifier, and no pull request had been
opened yet, so deleting the remote branch was enough — a leak would not have been recoverable
that way, because `refs/pull/*` is server-side and the whole reason this file exists.

It exits non-zero and prints `REFUSE TO PUSH` if any tracked file, **any commit message
about to be pushed**, or the published index carries a customer identifier — and now also if
a shipped figure disagrees with the index summary, for the reason its docstring gives under
*why a figure check belongs in a leak gate*. It takes a few seconds over every tracked file.
If it refuses, fix the finding — do not push and do not reason your way past it.

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

## Uncommitted work in the tree is the only copy of it

An agent finishes a round by reporting and handing over a working tree: *nothing committed,
nothing pushed*. That tree is the sole copy. `git checkout -- <file>`, `git reset --hard` and a
mishandled `git stash` destroy it with no way back — it was never staged, so it is not in the
object database and `git fsck` will not find it.

This has cost real work. Reverting one file to undo an experiment of one's own also discarded
that round's changes to the same file — a generator repair and fifteen control cases — which
had to be written a second time. **Commit or stash before experimenting in a tree somebody else
filled**, and revert your own hunks rather than the file.

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

Four commands, all four, every time. Two of them were already habit; the third is here
because a round was reported green while it was failing, and the fourth because a published
`README.md` spent several rounds asserting a detection rate less than half the real one.

```
python3 corpus/shard-gate.py corpus/index.jsonl              # published half
python3 corpus/shard-gate.py corpus/local/index-local.jsonl  # local half
python3 corpus/make-summary.py --check                       # the summary vs the index
python3 corpus/doc-figures.py --check                        # the documents vs the summary
```

They are a chain, and each link is only worth running because the next one exists:

```
index.jsonl + local/index-local.jsonl  --(make-summary.py --check)-->  index-summary.json
index-summary.json                     --(doc-figures.py --check)  -->  README.md, SOURCES.md
```

`make-summary.py --check` is the authority on whether `index-summary.json` still describes
the index, and the summary is the denominator every suite run quotes. A round that moves
rows and does not regenerate it leaves a published file asserting counts that no longer
exist — and the gate runs cannot see that, because they read the index and not the summary.
Regenerate it in the commit where the counts settle, and say in that commit that `--check`
was failing until you did.

`doc-figures.py --check` is the same argument one level out. `make-summary.py --check` can
pass while `README.md` — the first thing a stranger reads — quotes figures from three rounds
ago, because nothing compared them. It reads **only** the summary and never the index, so
that a document cannot agree with the index while disagreeing with the denominator: two
denominators nobody compares is the defect, not the fix. **Never hand-correct a figure inside
a generated region.** Hand-correction is how every one of these went stale; edit the tool, run
it, and leave the prose around the markers alone — it survives regeneration by design.

## Measurement conventions

- **Every count difference carries an attributed cause.** A number that changed is not a
  result until it says why. See `docs/tasks/CORPUS_PLAN.md` §8.
- **State the power of a sampling check**, not just its outcome. Eight files out of 191,141
  detect a 1%-of-files discrepancy 7.7% of the time; reporting "verified" from that is
  reporting nothing. §11.
- **A denominator enumerated by the same process that produced the numerator bounds the
  result, not reality.** Thirteen instances are recorded in §11. Assume a fourteenth exists in
  whatever you measure next — and note that a *tool* can carry the property as readily as a
  measurement: four of the thirteen are the orphan census bounding its own answer, in four
  different ways, each one found only after the previous repair was called done. The
  thirteenth is the one to read first if you are about to label anything: a family definition
  can be **clean** — byte-defined, marker-verified, refusing anything the rule-set determines —
  while the **pool it was drawn from** is detection-conditioned. Membership and sampling frame
  are two failures, the second is invisible in the assigning code, and the repair is to measure
  the frame at write time and record it on the row.
- **Never report a detection figure taken across a changing binary or a changing index.**
  `corpus/verify.py` reads `$LYXBOSA_BIN`, defaulting to `build-release/lyxbosa`. Build in
  `build/` and point it there — see *Build directories* below for why that is not a free choice.

## Build directories: there are two, and you do not add a third

`build/` is the debug build. `build-release/` is the release build. `build-static/` exists to
test static linking. **You do not add a fourth.**

When you need a binary to measure with, build in `build/` and run
`LYXBOSA_BIN=build/lyxbosa python3 corpus/verify.py`. Do not rebuild `build-release/` — another
session measures with it, and a detection figure taken across a changing binary is not a
figure. The measurement convention above says "your own build" and it means `build/`.

**A third directory was created once and it was the wrong repair.** `verify.py` had
`build-release/lyxbosa` hardcoded, so a round that needed its own binary made `build-rules/`
to avoid disturbing it. The workaround was at the wrong layer: the defect was a hardcoded path
in the tool, the fix was `$LYXBOSA_BIN`, and the directory was deleted. If two builds are not
enough for what you are doing, the thing to change is the tool that cannot be pointed at a
binary — not the number of directories.

This is not a new rule. `docs/RELEASING.md` already defines exactly two CMake presets —
`debug` to `build/` and `release` to `build-release/` — and says to release the binary you are
about to tag from `build-release/`. It simply was not written where an agent reads its
conventions.

Two reasons it is not merely tidiness. `.vscode/settings.json` points
`C_Cpp.default.compileCommands` at `build/compile_commands.json` and deliberately does **not**
exclude `build/` from cpptools, because the generated headers live there; a third directory is
outside that configuration and gets indexed by nothing or by everything.

And `.gitignore` names build directories **individually**, not as a `build-*` pattern —
measured: a new `build-scratch-probe/` shows up as `??` in `git status`. So a *fresh* name is
visible, but **every name already on the list is invisible forever**, which is why a leftover
survives there rather than being noticed. `/build-rules/` sat ignored after the directory was
deleted, alongside `/build-release-portable/` which never existed here; both entries are now
removed, so recreating either would show up.

What remains listed is what is used: `/build/`, `/build-release/`, `/build-static/` and
`/build-win-release*/`. Note that only the first two appear in `RELEASING.md`'s preset table —
`build-static/` is for testing static linking and `build-win-release*` for Windows packaging, so
neither is reachable by `cmake --preset`, and neither is a precedent for adding your own.

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
