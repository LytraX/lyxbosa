#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Refuse to push customer data. Run this before every push, and read AGENTS.md for why.

On 2026-09-05 a scan report that named four customer sites next to malware findings was
found in this repository's public history. It had been committed by accident 69 commits
earlier, `.gitignore` already declared it, and nobody noticed because nothing ever looked.
Rewriting history did not fix it - GitHub kept serving the old objects by SHA, and those
SHAs were published on the repository's own pull-request pages. The repository had to be
deleted and recreated to remove them.

That is the cost this file exists to avoid. It is cheap: a few seconds over ~150 files.

WHAT IT CHECKS, and why each one is here rather than assumed:

  tracked files   Every file `git ls-files` reports, against both pseudonym maps. This is
                  the check that was missing. The index halves had verifiers; the tracked
                  files - source, docs, committed JSON - had none, and a scan report is a
                  tracked file.
  commit messages Every message about to be pushed. A message is as permanent as a blob and
                  harder to remove: once a commit is referenced by a pull request, its
                  `refs/pull/*` ref is server-side and cannot be pushed to or deleted. The
                  first version of this script omitted this check, said SAFE TO PUSH, and a
                  commit message naming three accounts had already reached the remote - in
                  the paragraph explaining the very lesson about not naming them.
  published index Delegated to verify-infected-mask.py, which owns that question.
  gate invariants Delegated to shard-gate.py: no `origin` on a published row, every
                  /home<digits>/<x>/ pseudonymous.
  index summary   Delegated to make-summary.py --check: the denominator on disk must agree
                  with the index it claims to summarise. AGENTS.md has required that run
                  since the round it was written for, annotated with the note that it exists
                  because a round was reported green while it was failing - and a round was
                  then reported green while it was failing again. A written rule that has
                  been missed twice does not want stronger wording, it wants a gate, so the
                  rule is now enforced by the same script that enforces the other three.
                  A stale summary is not a leak; it is a false denominator, and every
                  measurement in a round report is quoted against it.
  doc figures     Delegated to doc-figures.py --check: the generated regions in README.md
                  and SOURCES.md must agree with that denominator. See below for why this
                  one belongs in a leak gate and the derived database does not.

WHY A FIGURE CHECK BELONGS IN A LEAK GATE, WHEN THE DERIVED DATABASE DELIBERATELY DOES NOT:

The test is not "is it a leak". It is "does pushing make it public, under this project's
name, in a form a stranger will act on". Push is the irreversible step this file guards, and
what makes it irreversible is publication, not secrecy.

  corpus/local/index.db is gitignored, derived and never pushed. A stale one cannot reach
  anybody, so a `--check` for it here would gate an event that cannot happen; it is guarded
  instead by `derived_db.open_ro()` refusing to open a stale file, which is a guarantee at
  the moment of use rather than at the moment of push. Adding it here would have diluted
  this file with a question that push does not ask.

  README.md ships. It is the first thing a stranger reads, it is quoted in the release
  notes, and it carried a detection figure of 22.2% against a real 53.6% - published, under
  this project's name, in a repository whose every other document is obsessive about
  denominators. An outside reviewer found it before anybody here did. That is not a leak and
  it is not a secret; it is a false public claim, which is the other thing a push makes
  permanent, and it is exactly the shape the make-summary delegation above was added for.

So the rule this file follows: a check earns a place here when the thing it defends becomes
public on push and wrong is worse than absent. `index-summary.json` and the generated regions
both qualify. The database does not, and saying so is what keeps the list from growing into
"every check we have", which is how a gate stops being read.

WHAT IT DOES NOT DO: it does not sweep for substrings. Four such sweeps were written during
that incident and all four manufactured hits. A two-letter account name matched 52,103 rows
through `wp-content`. A six-letter label matched a plugin framework's own `global-*` files.
Another six-letter label matched inside a stock Magento class name - including in the
sentence describing that very collision. A five-letter label matched animate, animation and
animating. Every one reported a leak where none existed, and a check whose output is
coincidences is a check nobody finishes. So the leak predicate is imported from
verify-infected-mask.py rather than rewritten here: containment for names long enough to be
nothing else, whole alphabetic runs for short ones.

The labels above are described by length rather than spelled out, and that is not fussiness.
The first version of this docstring named two of them as examples, and this script refused
its own push over it - a leak written into the tool built to catch leaks, which is the fifth
time that shape occurred during the incident. Describe collisions; do not quote them.

--inject is not optional decoration. Five checks written during that incident passed while
being blind: a /home/-only regex that could not see /home2/, a per-ref sweep that could not
see a stale worktree, a two-file question asked about one file, and a status check that read
a 404 body as success and reported every object present when all ten were gone. What caught
each of them was a positive control. A check that has never been observed to fail is not yet
a check.
"""
import json, os, subprocess, sys, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "vim_", os.path.join(HERE, "verify-infected-mask.py"))
_vim = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vim)

ROOT = os.path.dirname(HERE)
MAPS = [os.path.join(ROOT, "trail-data/incoming/2026-09-03/private/account-mapping.json"),
        os.path.join(ROOT, "trail-data/incoming/2026-09-03/private/infected-tree-mapping.json")]

# A stock Magento class name that two pre-existing source files carry. It contains a client
# label by coincidence and reveals nothing. Listed by the string that collides rather than by
# the label, so this file names no customer.
KNOWN_BENIGN_SEGMENTS = {"upgradeconsumersecret"}


def messages_to_push(base="master"):
    """(sha, message) for every commit on HEAD that `base` does not have.

    Range rather than all history: rewriting a pushed message costs a force-push, and
    rewriting one inside a pull-request ref costs the repository. What matters is what is
    about to leave the machine.
    """
    head = subprocess.run(["git", "-C", ROOT, "rev-parse", "--abbrev-ref", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    if head == base:
        base = "origin/%s" % base
    out = subprocess.run(["git", "-C", ROOT, "log", "--format=%H%x00%B%x01",
                          "%s..HEAD" % base], capture_output=True, text=True).stdout
    recs = []
    for rec in out.split("\x01"):
        if "\x00" in rec:
            sha, msg = rec.split("\x00", 1)
            recs.append((sha.strip(), msg))
    return recs


def sweep_messages(recs, ids, keep):
    hits = []
    for sha, msg in recs:
        for seg in set(_vim.segments_of(msg)):
            low = seg.lower()
            if low in keep or any(b in low for b in KNOWN_BENIGN_SEGMENTS):
                continue
            for ident in ids:
                at = low.find(ident)
                if at >= 0 and _vim._is_a_leak(low, ident, at):
                    hits.append((sha[:12], seg[:50]))
                    break
            else:
                continue
            break
    return hits


def tracked_files():
    out = subprocess.run(["git", "-C", ROOT, "ls-files"],
                         capture_output=True, text=True).stdout
    return [f for f in out.split("\n") if f]


def sweep(paths, ids, keep):
    hits = []
    for rel in paths:
        p = os.path.join(ROOT, rel)
        try:
            text = open(p, encoding="utf-8", errors="replace").read()
        except (OSError, IsADirectoryError):
            continue
        for seg in set(_vim.segments_of(text)):
            low = seg.lower()
            # Containment, not equality: a segment carries whatever punctuation is not a
            # separator, so the Magento class name arrives as `UpgradeConsumerSecret and
            # **`UpgradeConsumerSecret from markdown. An equality test missed both.
            if low in keep or any(b in low for b in KNOWN_BENIGN_SEGMENTS):
                continue
            for ident in ids:
                at = low.find(ident)
                if at >= 0 and _vim._is_a_leak(low, ident, at):
                    hits.append((rel, seg[:60]))
                    break
            else:
                continue
            break
    return hits


def run_map(map_path, paths, quiet=False):
    m = _vim.load_map(map_path) if hasattr(_vim, "load_map") else json.load(open(map_path))
    ids = _vim.identifiers(m)
    keep = _vim.keep_tokens(m)
    hits = sweep(paths, ids, keep)
    if not quiet:
        print("  %-26s %4d identifiers, %3d tracked files -> %s"
              % (os.path.basename(map_path), len(ids), len(paths),
                 "PASS" if not hits else "%d FILE(S) LEAKING" % len(hits)))
        for rel, seg in hits[:10]:
            print("      %-46s  segment: %s" % (rel[:46], seg))
    return hits


def summary_check(corpus_dir):
    """(ok, output) from `make-summary.py --check` run against `corpus_dir`.

    Parameterised on the directory rather than hardwired to `HERE` so `inject()` can point
    it at a tree holding a deliberately stale summary. A delegation that is only ever run
    against the real, currently-passing file is a delegation nobody has seen say no - which
    is the same blindness as a check with no positive control, one level out.

    `make-summary.py` locates everything it reads from its own `__file__`, and `abspath`
    does not resolve symlinks, so a directory of symlinks to the real index halves is enough
    to run the real script over a substituted summary.
    """
    r = subprocess.run([sys.executable, os.path.join(corpus_dir, "make-summary.py"),
                        "--check"], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout or "") + (r.stderr or "")


def docfigures_check(root):
    """(ok, output) from `doc-figures.py --check` run against `root`.

    Parameterised on the repository root for the same reason `summary_check` is
    parameterised on the corpus directory: a delegation only ever run against the real,
    currently-passing tree is a delegation nobody has seen say no.

    `doc-figures.py` takes its root from its own `__file__` and `abspath` does not resolve
    symlinks, so a temp tree holding a symlink to the tool and copies of the documents is
    enough to run the real script over substituted files.
    """
    r = subprocess.run([sys.executable, os.path.join(root, "corpus", "doc-figures.py"),
                        "--check"], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout or "") + (r.stderr or "")


def inject_docfigures():
    """Both directions, over a temp tree. Nothing in the repository is written.

    The stale case perturbs the SUMMARY rather than the document, because that is the real
    sequence: a round moves rows, `make-summary.py` regenerates, and the documents quoting it
    are left behind. The control asserts the refusal names the figure, not just the file.
    """
    import shutil, tempfile
    spec = importlib.util.spec_from_file_location(
        "df_", os.path.join(HERE, "doc-figures.py"))
    df = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(df)

    ok_all = True
    tmp = tempfile.mkdtemp(prefix="pre-push-docfigures-")
    try:
        os.makedirs(os.path.join(tmp, "corpus"))
        os.symlink(os.path.join(HERE, "doc-figures.py"),
                   os.path.join(tmp, "corpus", "doc-figures.py"))
        for rel, _name, _r in df.REGIONS:
            dst = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.exists(dst):
                shutil.copy2(os.path.join(ROOT, rel), dst)
        sp = os.path.join(tmp, "corpus", "index-summary.json")
        shutil.copy2(os.path.join(HERE, "index-summary.json"), sp)

        fresh_ok, _out = docfigures_check(tmp)
        if fresh_ok:
            print("  documents that agree with the summary         accepted")
        else:
            print("  FAIL: agreeing documents were refused"); ok_all = False

        cur = json.load(open(sp))
        cur["malicious_detected"] = cur["malicious_detected"] + 1
        json.dump(cur, open(sp, "w"), indent=1, sort_keys=True)
        stale_ok, out = docfigures_check(tmp)
        if stale_ok:
            print("  FAIL: a stale README was accepted"); ok_all = False
        else:
            print("  a README stale by one detection sample        refused")
            if "detection_pct" not in out and "detection_ratio" not in out:
                print("  FAIL: the refusal did not name the figure that drifted")
                ok_all = False
            if "README.md" not in out:
                print("  FAIL: the refusal did not name the file")
                ok_all = False

        # A region that is simply gone must fail, not pass quietly over a document nothing
        # is defending any more. This is the merge failure mode.
        shutil.copy2(os.path.join(HERE, "index-summary.json"), sp)
        rel, name, _r = df.REGIONS[0]
        p = os.path.join(tmp, rel)
        import re as _re
        whole = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(
            _re.sub(df._BEGIN_RE % _re.escape(name), "",
                    _re.sub(df._END_RE % _re.escape(name), "", whole)))
        gone_ok, out = docfigures_check(tmp)
        if gone_ok:
            print("  FAIL: a document with no generated region was accepted"); ok_all = False
        else:
            print("  a document whose generated region is gone     refused")
    finally:
        import shutil as _sh
        _sh.rmtree(tmp, ignore_errors=True)
    return 0 if ok_all else 1


def _summary_sandbox(tmp):
    """A corpus directory of symlinks with its own copy of index-summary.json.

    The summary is a COPY because it is the file under test; everything else is a symlink
    because it is 62 MB and is not.
    """
    import shutil
    for n in ("make-summary.py", "clearance.py", "index.jsonl"):
        os.symlink(os.path.join(HERE, n), os.path.join(tmp, n))
    if os.path.isdir(os.path.join(HERE, "local")):
        os.symlink(os.path.join(HERE, "local"), os.path.join(tmp, "local"))
    shutil.copy2(os.path.join(HERE, "index-summary.json"),
                 os.path.join(tmp, "index-summary.json"))
    return tmp


def inject_summary():
    """Both directions. A delegation that always refuses and one that never fires look
    identical from a green run, so neither is assumed.

    Nothing in the repository is written: the stale summary is a copy inside a temp tree.
    """
    import tempfile
    ok_all = True
    tmp = tempfile.mkdtemp(prefix="pre-push-summary-")
    try:
        _summary_sandbox(tmp)
        fresh_ok, _out = summary_check(tmp)
        if fresh_ok:
            print("  a summary that agrees with the index           accepted")
        else:
            print("  FAIL: a fresh summary was refused"); ok_all = False

        # Perturb one integer. Not a malformed file - that would prove only that a broken
        # JSON is caught. A summary that is valid, plausible and wrong by one is the actual
        # failure mode: a count that moved and a denominator that did not.
        sp = os.path.join(tmp, "index-summary.json")
        cur = json.load(open(sp))
        field = next((k for k, v in sorted(cur.items()) if isinstance(v, int)), None)
        if field is None:
            print("  FAIL: no integer field to perturb"); return 1
        cur[field] = cur[field] + 1
        json.dump(cur, open(sp, "w"), indent=1, sort_keys=True)
        stale_ok, out = summary_check(tmp)
        if stale_ok:
            print("  FAIL: a stale summary was accepted"); ok_all = False
        else:
            print("  a summary stale by one in %-20s refused" % field)
            if field not in out:
                print("  FAIL: the refusal did not name the field that drifted")
                ok_all = False
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return 0 if ok_all else 1


def inject(paths):
    """Prove the sweep can fail. Writes nothing: a synthetic path list is enough."""
    m = json.load(open(MAPS[0]))
    ids = _vim.identifiers(m)
    keep = _vim.keep_tokens(m)
    long_ident = next((i for i in sorted(ids, key=len, reverse=True) if len(i) >= 6), None)
    if not long_ident:
        print("  cannot self-test: no identifier long enough in the map")
        return 1
    tmp = os.path.join(ROOT, ".pre-push-check-selftest.tmp")
    ok = True
    try:
        open(tmp, "w").write("path: /home/%s/public_html/x.php\n" % long_ident)
        if not sweep([os.path.relpath(tmp, ROOT)], ids, keep):
            print("  FAIL: planted identifier was not caught"); ok = False
        else:
            print("  planted identifier in a tracked-file body      caught")
        open(tmp, "w").write("this is about animation and wp-content and a manual\n")
        if sweep([os.path.relpath(tmp, ROOT)], ids, keep):
            print("  FAIL: ordinary English was reported"); ok = False
        else:
            print("  ordinary English (animation, wp-content)       silent")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print("  the sweep can fail, and does not fire on English" if ok else "  SELF-TEST FAILED")
    print()
    print("=== the make-summary delegation, in both directions ===")
    if inject_summary():
        ok = False
    print()
    print("=== the doc-figures delegation, in both directions ===")
    if inject_docfigures():
        ok = False
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inject", action="store_true",
                    help="prove the check can fail, then exit")
    a = ap.parse_args()
    if a.inject:
        return inject(tracked_files())

    paths = tracked_files()
    print("=== tracked files, against every pseudonym map ===")
    bad = 0
    for mp in MAPS:
        if not os.path.exists(mp):
            print("  %-26s MAP ABSENT - cannot certify" % os.path.basename(mp)); bad += 1
            continue
        bad += len(run_map(mp, paths))

    print()
    print("=== commit messages about to be pushed ===")
    recs = messages_to_push()
    if not recs:
        print("  nothing ahead of master")
    for mp in MAPS:
        if not os.path.exists(mp): continue
        m = json.load(open(mp))
        hits = sweep_messages(recs, _vim.identifiers(m), _vim.keep_tokens(m))
        print("  %-26s %d commit(s) -> %s"
              % (os.path.basename(mp), len(recs),
                 "PASS" if not hits else "%d MESSAGE(S) LEAKING" % len(hits)))
        for sha, seg in hits[:10]:
            print("      %s  segment: %s" % (sha, seg))
        bad += len(hits)

    print()
    print("=== published index, delegated to the tools that own the question ===")
    idx = os.path.join(HERE, "index.jsonl")
    for mp in MAPS:
        if not os.path.exists(mp): continue
        r = subprocess.run([sys.executable, os.path.join(HERE, "verify-infected-mask.py"),
                            idx, "--map", mp], capture_output=True, text=True)
        print("  verify-infected-mask x %-26s %s"
              % (os.path.basename(mp), "PASS" if r.returncode == 0 else "FAIL"))
        bad += (r.returncode != 0)
    r = subprocess.run([sys.executable, os.path.join(HERE, "shard-gate.py"), idx],
                       capture_output=True, text=True)
    print("  shard-gate on the published half              %s"
          % ("PASS" if r.returncode == 0 else "FAIL"))
    bad += (r.returncode != 0)
    ok, out = summary_check(HERE)
    print("  make-summary --check on the denominator      %s" % ("PASS" if ok else "FAIL"))
    if not ok:
        for line in out.strip().split("\n")[:8]:
            print("      %s" % line)
    bad += (not ok)
    ok, out = docfigures_check(ROOT)
    print("  doc-figures --check on the shipped figures   %s" % ("PASS" if ok else "FAIL"))
    if not ok:
        for line in out.strip().split("\n")[:8]:
            print("      %s" % line)
    bad += (not ok)

    print()
    if bad:
        print("REFUSE TO PUSH: %d problem(s). Do not push until every line reads PASS." % bad)
    else:
        print("SAFE TO PUSH: no customer identifier in any tracked file or the published\n"
              "              index, and every shipped figure agrees with the index summary.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
