#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run every control suite in `corpus/` and say which ones fail.

  corpus/control-suites.py            run them all, report, exit non-zero if any is not ok
  corpus/control-suites.py --list     what would be run, and how, without running it
  corpus/control-suites.py --inject   controls on this runner, both directions

WHY THIS EXISTS
---------------
`AGENTS.md` says a check that has never been observed to fail is not yet a check, and every
tool here carries a `--inject` for that reason. Nothing ran them. Measured 2026-09-08:

  * `doc-figures.py --inject` had been failing 4 of 56 since round 18, because four cases
    hardcoded a family rate they read from the live summary and the summary moved. The
    document was right, the rule was right and `--check` passed throughout.
  * `field-provenance.py --inject` had been failing 1 of 57 since round 14, because its claim
    that `account_hash` has no real write position was false - a module-level fixture helper
    in `derive-index-db.py` had one.
  * three more could not be invoked AT ALL without arguments nobody was passing:
    `shard-gate.py`, `mask-samples.py` and `verify-infected-mask.py`. All three pass once
    given them. They were not failing; they were not running, which is worse, because a
    failing suite at least has an exit code somebody could have looked at.
  * `review-app.py --inject` refuses on a stale derived database and never reaches its cases.

Six of forty, and the two that were genuinely red went six and two rounds unseen. Not one of
these is a hard problem to find - the whole difficulty was that nobody was looking, and
"remember to run the suites" is the instruction that had already failed.

WHY ONE COMMAND AND NOT FIVE MORE LINES IN AGENTS.md
-----------------------------------------------------
The pre-report list is four commands because four is a list somebody runs. The obvious repair
- add `doc-figures.py --inject` and `field-provenance.py --inject` to it - fixes the two
suites that happened to break this month and leaves the other thirty-eight exactly as unwatched
as they were, so the next instance of this round is already scheduled. A list of twenty is a
list that gets skipped and then quoted as green, which is the failure it was meant to prevent
wearing a bigger hat.

So: one line on the list, and the coverage stops depending on anybody's memory. The whole run
takes 27 seconds warm, measured over four runs, of which 7.8 is `classify-known-miss.py` and
5.6 is `field-provenance.py`. The first run after a reboot is 46 seconds, and the difference is
page cache over the 62 MB published index rather than anything either tool does - quoted both
ways because a single cold measurement reported as the cost is the figure somebody budgets
against.

DISCOVERED, NOT LISTED
----------------------
The suites are found by parsing every `corpus/*.py` and asking whether it names `--inject` or
`--selftest` as a string constant. A hardcoded list would be the same memory dependency one
level up: a tool that grows a control suite would be watched only if somebody remembered to
add it here, which is precisely the thing that did not happen.

Discovery has its own failure mode and it is the dangerous direction: a discovery that finds
nothing reports zero failures, and zero failures reads as green. That is the same shape as the
status check in AGENTS.md that read a 404 body as success and reported ten objects present when
every one was gone. So `--inject` asserts the discovery against an independent enumeration and
asserts it is not empty, and a run that finds fewer than `FLOOR` suites refuses rather than
reporting green.

THREE WAYS TO BE NOT-OK, AND THEY ARE DIFFERENT PROBLEMS
---------------------------------------------------------
  FAILED         the suite ran and reported failing cases. Read its output; a control is
                 telling you something.
  CANNOT INVOKE  argparse refused: the suite needs arguments this runner does not know. This
                 is worse than FAILED - the suite has never run at all - and the repair is a
                 row in `INVOCATION`, not a fix to the tool.
  CRASHED        an unhandled exception before the cases. Usually a precondition: a stale
                 derived database, a missing map.

All three exit non-zero. None of them is a skip: a suite this runner cannot deal with is
reported loudly, because a quiet skip is how a control suite fails for six rounds.
"""
import argparse, ast, os, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SELF = os.path.basename(__file__)

# The flags a control suite is invoked by, in preference order.
FLAGS = ("--inject", "--selftest")

# Suites that need arguments before they will run, and what to pass. DECLARED, because there
# is no way to derive it: `--stage` is a directory, `rows` is a jsonl path, `shard-gate` takes
# the index it is gating. Three rows, and every one of them was a suite that had never run.
#
# `{tmpdir}` is a scratch directory this runner creates and removes; `{index}` is the published
# index half. A suite whose declared invocation stops working shows up as CANNOT INVOKE, which
# is the loud direction - it cannot silently start being skipped again.
INVOCATION = {
    # `--inject` synthesises its own vocabulary and says so, so it needs no stock tree; only
    # the staging directory is still required, and that was enough to keep it from ever running.
    "mask-samples.py": ["--stage", "{tmpdir}/mask-stage"],
    # The positional is required by argparse and unread under --inject, which tests the map
    # sweep rather than any rows.
    "verify-infected-mask.py": ["{tmpdir}/no-rows.jsonl"],
    # usage: shard-gate.py --inject <index.jsonl>
    "shard-gate.py": ["{index}"],
}

# A run that discovers fewer suites than this refuses instead of reporting green. Not a count
# of what exists - that would have to be updated every time a tool is added, and would go
# stale into a second false denominator - but a floor far enough below it that only a broken
# discovery trips it. 40 exist today.
FLOOR = 25

TIMEOUT = 900


def suite_flag(path):
    """The flag `path` runs its control suite under, or None if it has none.

    Parsed rather than grepped: a text search cannot tell `"--inject"` in an
    `add_argument` call from `--inject` written inside a docstring explaining somebody
    else's tool, and this file's own module docstring names four of them.
    """
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, ValueError):                                # pragma: no cover
        return None
    named = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and node.value in FLAGS:
            named.add(node.value)
    # A string constant inside a docstring is an Expr statement whose value is the string, and
    # a docstring naming another tool's flag is not a control suite of one's own.
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            d = ast.get_docstring(node, clean=False)
            if d:
                docstrings.update(f for f in FLAGS if f in d)
    real = named - (docstrings - _non_docstring_flags(tree))
    for f in FLAGS:
        if f in real:
            return f
    return None


def _non_docstring_flags(tree):
    """The flags this module names OUTSIDE any docstring - the ones it really dispatches on."""
    doc_nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                doc_nodes.add(id(body[0].value))
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and node.value in FLAGS and id(node) not in doc_nodes:
            out.add(node.value)
    return out


def discover(root=HERE, skip=(SELF,)):
    """[(filename, flag)] for every control suite in `root`, sorted."""
    out = []
    for fn in sorted(os.listdir(root)):
        if not fn.endswith(".py") or fn in skip:
            continue
        flag = suite_flag(os.path.join(root, fn))
        if flag:
            out.append((fn, flag))
    return out


def argv_for(fn, flag, tmpdir, index):
    extra = [a.format(tmpdir=tmpdir, index=index) for a in INVOCATION.get(fn, ())]
    return [flag] + extra


def classify(rc, out):
    """'ok' | 'FAILED' | 'CANNOT INVOKE' | 'CRASHED' | 'TIMEOUT'.

    A non-zero exit is never read as anything but not-ok. The categories only say WHICH kind
    of not-ok, and they are decided from evidence the suite itself printed rather than from a
    guess: argparse writes `usage:` and exits 2, an unhandled exception writes a traceback.
    """
    if rc == 0:
        return "ok"
    if rc == 2 or "usage:" in out[:400]:
        return "CANNOT INVOKE"
    if "Traceback (most recent call last)" in out:
        return "CRASHED"
    return "FAILED"


def run_one(root, fn, flag, tmpdir, index, timeout=TIMEOUT):
    argv = [sys.executable, os.path.join(root, fn)] + argv_for(fn, flag, tmpdir, index)
    t0 = time.time()
    try:
        r = subprocess.run(argv, capture_output=True, text=True, cwd=ROOT, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", time.time() - t0, "no output within %ds" % timeout
    out = (r.stdout or "") + (r.stderr or "")
    return classify(r.returncode, out), time.time() - t0, out


def tail(out, n=6):
    lines = [l for l in out.rstrip("\n").split("\n") if l.strip()]
    return lines[-n:]


def run(root=HERE, out=sys.stdout, timeout=TIMEOUT):
    suites = discover(root)
    print("=== control suites in %s ===" % os.path.relpath(root, ROOT), file=out)
    if len(suites) < FLOOR:
        # The inverted-status failure, refused rather than reported. Zero suites found means
        # zero failures, and zero failures reads as green to every reader and every script.
        print("  DISCOVERY FOUND %d SUITES, FLOOR IS %d - refusing to report a result.\n"
              "  A discovery that finds nothing reports everything green; that is the shape\n"
              "  of the status check AGENTS.md records reading a 404 as success."
              % (len(suites), FLOOR), file=out)
        return 1

    tmpdir = tempfile.mkdtemp(prefix="control-suites-")
    os.makedirs(os.path.join(tmpdir, "mask-stage"), exist_ok=True)
    open(os.path.join(tmpdir, "no-rows.jsonl"), "w").close()
    index = os.path.join(HERE, "index.jsonl")
    bad, total = [], 0.0
    try:
        for fn, flag in suites:
            state, dt, output = run_one(root, fn, flag, tmpdir, index, timeout)
            total += dt
            print("  %-28s %-10s %6.1fs  %s"
                  % (fn, flag, dt, "ok" if state == "ok" else state), file=out)
            if state != "ok":
                bad.append((fn, state))
                for line in tail(output):
                    print("      %s" % line[:110], file=out)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(file=out)
    print("suites: %d · ok: %d · not ok: %d · %.1fs"
          % (len(suites), len(suites) - len(bad), len(bad), total), file=out)
    for fn, state in bad:
        print("  %-14s %s" % (state, fn), file=out)
    if bad:
        print("\n  FAILED        the suite ran and its cases disagree. Read its output.\n"
              "  CANNOT INVOKE the suite needs arguments: add a row to INVOCATION in\n"
              "                corpus/control-suites.py. It has never run.\n"
              "  CRASHED       it raised before reaching its cases - usually a precondition,\n"
              "                such as a derived database that needs rebuilding.", file=out)
    return 1 if bad else 0


# --------------------------------------------------------------------------- controls

def inject():
    """Both directions, over planted tools in a temp directory.

    The load-bearing cases are the two that say this runner cannot report green by accident:
    a suite that exits non-zero must be counted, and a discovery that finds nothing must
    refuse rather than report zero failures.
    """
    import io, shutil
    fails, cases = [], []

    def case(label, ok):
        cases.append(label)
        print("  %-62s %s" % (label, "ok" if ok else "WRONG"))
        if not ok:
            fails.append(label)

    tmp = tempfile.mkdtemp(prefix="control-suites-inject-")
    try:
        def plant(name, body):
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write(body)

        plant("passing.py", "import sys\n"
                            "if '--inject' in sys.argv:\n"
                            "    print('  a case  ok')\n"
                            "    sys.exit(0)\n")
        plant("failing.py", "import sys\n"
                            "if '--inject' in sys.argv:\n"
                            "    print('  a case  WRONG')\n"
                            "    print('cases: 1 * passed: 0 * failed: 1')\n"
                            "    sys.exit(1)\n")
        plant("needsargs.py", "import argparse, sys\n"
                              "ap = argparse.ArgumentParser()\n"
                              "ap.add_argument('rows')\n"
                              "ap.add_argument('--inject', action='store_true')\n"
                              "ap.parse_args()\n")
        plant("crashing.py", "import sys\n"
                             "if '--inject' in sys.argv:\n"
                             "    raise RuntimeError('a precondition is not met')\n")
        plant("nosuite.py", "def f():\n    return 1\n")
        plant("mentions.py", '"""A docstring that says --inject about somebody else\'s tool."""\n'
                             "def f():\n    return 2\n")
        plant("selftester.py", "import sys\n"
                               "if '--selftest' in sys.argv:\n"
                               "    sys.exit(0)\n")

        found = dict(discover(tmp, skip=()))
        print("=== discovery ===")
        case("a tool with --inject is discovered", found.get("passing.py") == "--inject")
        case("a tool with --selftest is discovered",
             found.get("selftester.py") == "--selftest")
        case("a tool with no control suite is not", "nosuite.py" not in found)
        # A docstring naming another tool's flag is not a control suite. This file's own
        # docstring names four, and a substring sweep would have enrolled it.
        case("a docstring mentioning --inject is not a suite", "mentions.py" not in found)

        print()
        print("=== a non-zero exit is never read as success ===")
        # The inverted-status failure, which AGENTS.md records as a status check reading a 404
        # body as success and reporting ten objects present when every one was gone.
        buf = io.StringIO()
        rc = run(tmp, out=buf, timeout=60)
        text = buf.getvalue()
        case("a discovery below the floor refuses", rc != 0)
        case("  ...and says so rather than reporting zero failures",
             "DISCOVERY FOUND" in text and "refusing" in text)

        # Now with the floor lowered, so the run itself can be asserted.
        global FLOOR
        keep, FLOOR = FLOOR, 1
        try:
            buf = io.StringIO()
            rc = run(tmp, out=buf, timeout=60)
            text = buf.getvalue()
        finally:
            FLOOR = keep
        case("a run holding a failing suite exits non-zero", rc != 0)
        case("  ...and names the passing one as ok",
             any(l.startswith("  passing.py") and l.rstrip().endswith("ok")
                 for l in text.split("\n")))
        # Read out of the SUMMARY block rather than matched as a formatted substring: an
        # assertion keyed to column padding breaks when a label changes width and says nothing
        # about whether the verdict was right.
        summary = dict(reversed(l.strip().rsplit(None, 1)) for l in text.split("\n")
                       if l.startswith("  ") and l.strip().endswith(".py")
                       and l.strip().split()[0] in ("FAILED", "CANNOT", "CRASHED", "TIMEOUT"))
        case("  ...and the failing one as FAILED", summary.get("failing.py") == "FAILED")
        case("  ...and quotes its output, so the reader is not sent hunting",
             "cases: 1 * passed: 0 * failed: 1" in text)
        # The category this round exists for: a suite that never ran is not a suite that
        # passed, and it must not read like one.
        case("  ...a suite that cannot be invoked is CANNOT INVOKE",
             summary.get("needsargs.py") == "CANNOT INVOKE")
        case("  ...and one that raises before its cases is CRASHED",
             summary.get("crashing.py") == "CRASHED")
        case("  ...and none of the three is silently skipped",
             text.count("not ok: 3") == 1 and len(summary) == 3)

        print()
        print("=== and on the real directory ===")
        real = discover(HERE)
        case("every corpus tool with a control suite is discovered", len(real) >= FLOOR)
        # Against an INDEPENDENT enumeration, because a discovery agreeing with itself proves
        # nothing: §11 is about a denominator produced by the process that produced the
        # numerator, and a runner is as capable of carrying that as a measurement is.
        #
        # The independent one is a substring sweep, and it disagrees - it reports two files
        # more. Both are prose: `credential_disposition.py` names another tool's flag in a
        # COMMENT, which is not an AST node at all, and `derived_db.py` has `--inject` inside
        # a longer sentence in a help string, which is not the flag. That is the direction the
        # disagreement has to run. A sweep finding MORE than the parser is the parser being
        # precise; a sweep finding a suite the parser missed would be a suite going unwatched,
        # so the two halves are asserted separately rather than as one equality.
        by_text = set()
        for fn in sorted(os.listdir(HERE)):
            if fn.endswith(".py") and fn != SELF:
                if any(f in open(os.path.join(HERE, fn), encoding="utf-8").read()
                       for f in FLAGS):
                    by_text.add(fn)
        names = {fn for fn, _f in real}
        case("  ...and the parser invents no suite a text sweep cannot see",
             names <= by_text)
        case("  ...and misses none: every extra the sweep reports is prose",
             all(not _non_docstring_flags(
                     ast.parse(open(os.path.join(HERE, fn), encoding="utf-8").read()))
                 for fn in sorted(by_text - names)))
        # Every declared invocation still names a tool that is here and still needs it.
        case("every INVOCATION row names a discovered suite",
             set(INVOCATION) <= {fn for fn, _f in real})
        case("  ...and each of them really does refuse to run bare",
             all(classify(*_bare(fn)) == "CANNOT INVOKE" for fn in sorted(INVOCATION)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(cases), len(cases) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


def _bare(fn):
    """(rc, output) from running `fn`'s suite with no arguments - the state it was found in."""
    flag = suite_flag(os.path.join(HERE, fn))
    r = subprocess.run([sys.executable, os.path.join(HERE, fn), flag],
                       capture_output=True, text=True, cwd=ROOT, timeout=TIMEOUT)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--list", action="store_true",
                    help="what would be run, and how, without running it")
    ap.add_argument("--inject", action="store_true",
                    help="controls on this runner, both directions")
    ap.add_argument("--timeout", type=int, default=TIMEOUT)
    a = ap.parse_args()
    if a.list and a.inject:
        sys.exit("--list and --inject are different questions; pass one")
    if a.inject:
        return inject()
    if a.list:
        for fn, flag in discover():
            extra = " ".join(INVOCATION.get(fn, ()))
            print("  %-28s %s %s" % (fn, flag, extra))
        return 0
    return run(timeout=a.timeout)


if __name__ == "__main__":
    sys.exit(main())
