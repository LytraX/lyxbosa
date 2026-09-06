#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Which edits move a provenance digest, asserted rather than asserted-in-a-comment.

WHY THIS IS A SEPARATE FILE
---------------------------
`verify-content-mask.py` says, of the note it moved out to `fp-note.txt`:

    "Editing `fp-note.txt` now moves nothing, and `--assert-note-is-not-behaviour` is the
     control that says so."

That flag does not exist. It is named in a comment in the file it would guard, and nothing
in the tree implements it - a control claimed and never written, which AGENTS.md's rule is
specifically about. The property it claims is TRUE, measured here; what was missing is the
thing that could say so, and a true property with no check is one edit away from being a
false property with no check.

It cannot be added where it was promised. `verify-content-mask.py` is one of the six modules
in `gate_provenance.TOOLS`, so adding an argparse branch to it changes its AST and moves the
`tools` digest - putting all 142 stamped rows into re-measurement to install a check that
asserts prose edits do not do exactly that. The comment that names the flag is invisible to
the AST, so repointing it costs nothing; the implementation has to live somewhere the digest
does not read. That is here.

This file is therefore deliberately NOT in `TOOLS`: it decides no gate verdict, and a control
that moved the digest every time it gained a case would be a control nobody kept.

WHAT IT ASSERTS, AND WHY EACH HALF IS NEEDED
--------------------------------------------
A digest check has two ways to be useless and both have to be excluded:

  * it never moves     - then it cannot report a behaviour change, which is its whole job;
  * it always moves    - then every prose edit re-measures the index and it gets turned off.

So every case here comes in a pair: an edit that must NOT move it, and an edit that must.
The second half is the positive control. Each case edits a real file in the working tree,
recomputes, and restores the original bytes in a `finally` - the digest is taken from the
code that would actually run, so there is no way to ask this question without touching the
files, and no acceptable way to leave them touched.
"""
import importlib.util, os, shutil, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gate_provenance                                                   # noqa: E402

NOTE = os.path.join(HERE, "fp-note.txt")
FINDING_NOTE = os.path.join(HERE, "finding-note.txt")
GATE = os.path.join(HERE, "verify-content-mask.py")
SENSITIVITY = os.path.join(HERE, "sensitivity.py")


def _tools_digest():
    """Uncached: the cache is keyed by root and would return the pre-edit answer."""
    gate_provenance._DIGEST_CACHE.clear()
    return gate_provenance.tools_digest()


def _sensitivity_digest():
    spec = importlib.util.spec_from_file_location("sensitivity_probe", SENSITIVITY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.digest()


def _with_edit(path, replace, digest_fn):
    """`digest_fn()` with one substitution applied to `path`, original bytes restored."""
    with open(path, encoding="utf-8") as fh:
        original = fh.read()
    old, new = replace
    if old not in original:
        raise RuntimeError("%s does not contain the text this case edits: %r"
                           % (os.path.basename(path), old[:60]))
    backup = tempfile.mkstemp(prefix="digest-controls.", suffix=".bak")[1]
    shutil.copyfile(path, backup)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(original.replace(old, new, 1))
        return digest_fn()
    finally:
        shutil.copyfile(backup, path)
        os.unlink(backup)
        with open(path, encoding="utf-8") as fh:
            if fh.read() != original:                                # pragma: no cover
                raise RuntimeError("FAILED TO RESTORE %s - fix this by hand before "
                                   "committing anything" % path)


CASES = [
    # (label, path, (old, new), which digest, must it move?)
    ("prose in fp-note.txt", NOTE,
     ("a hit is not by itself a leak", "A HIT IS NOT BY ITSELF A LEAK"),
     "tools", False),
    ("a comment in a TOOLS module", GATE,
     ("# The gates.", "# The gates, and a word added to prove a comment is not behaviour."),
     "tools", False),
    ("a docstring in a TOOLS module", GATE,
     ('"""(ok, result) for one sample\'s bytes.',
      '"""(ok, result) for one sample\'s bytes. Reworded to prove prose is not behaviour.'),
     "tools", False),
    ("editing the sensitivity tagger", SENSITIVITY,
     ("TAGS = frozenset(", "TAGS = frozenset(  "),
     "tools", False),
    ("a NEW RULE in the sensitivity tagger", SENSITIVITY,
     ('(rb"eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.", "jwt"),',
      '(rb"eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.", "jwt"),\n'
      '    (rb"PROBE_ONLY_NEVER_COMMITTED", "probe"),'),
     "tools", False),
    # ... and the same edit MUST move the tagger's own digest, or the tagger has provenance
    # in name only.
    ("a NEW RULE in the sensitivity tagger", SENSITIVITY,
     ('(rb"eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.", "jwt"),',
      '(rb"eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.", "jwt"),\n'
      '    (rb"PROBE_ONLY_NEVER_COMMITTED", "probe"),'),
     "sensitivity", True),
    # THE IDENTIFIER NOTE, WHICH IS THE ONE THIS FILE WAS WRITTEN ABOUT.
    #
    # It was a string literal inside the gate for two rounds while its second clause was
    # known to be wrong, because correcting it cost a re-measurement of every stamped row.
    # It is in `finding-note.txt` now, and the whole point of the move is this line.
    ("prose in finding-note.txt", FINDING_NOTE,
     ("identifier names deliberately not recorded here",
      "IDENTIFIER NAMES DELIBERATELY NOT RECORDED HERE"),
     "tools", False),
    # THE OTHER NOTE, AND THE PAIR IS STILL THE POINT - WITH THE ANSWER REVERSED.
    #
    # `secret_literals.note` used to be a literal in this TOOLS module, and this case used
    # to assert that it MOVED the digest. That was not a preference: 124 rows recorded
    # twelve `secret_literals` keys and 8 recorded thirteen, the extra being that note, and
    # `gate_evidence.compare_gate` compares the keys the ROW holds - so if the text moved,
    # the 8 would read `evidence-moved` and the 124 `agrees` for one measurement. Being
    # pinned inside the AST was the only thing keeping that fork from going live quietly.
    #
    # The key is gone rather than relocated, and the prose is a docstring. That closes the
    # fork instead of guarding it: no writer records the key, the 8 rows reconcile to twelve
    # through `remeasure-gates.recorded_form`, and there is no second schema left. So the
    # assertion flips - editing that paragraph must NOT move the digest - and the case stays
    # here, under its old subject, because a control that quietly disappears when its answer
    # changes is how a repository forgets what it decided.
    ("the secret note, now a docstring", GATE,
     ("Counts and shapes only. A credential-shaped literal remaining after ",
      "Counts and shapes only - a credential-shaped literal remaining after "),
     "tools", False),
    # ... and the loader IS behaviour, which is the half that must still move. Without this
    # every case above passes against a gate that attaches no note at all.
    ("which note the gate attaches", GATE,
     ('res["plaintext_finding"]["note"] = finding_notes.IDENTIFIER_NOTE',
      'res["plaintext_finding"]["note"] = finding_notes.FP_NOTE'),
     "tools", True),
    ("a constant in a TOOLS module", GATE,
     ("MIN_CARRY = 8", "MIN_CARRY = 9"), "tools", True),
    ("a regex literal in a TOOLS module", GATE,
     ('("bcrypt", re.compile(rb"\\$2[aby]\\$\\d\\d\\$[./A-Za-z0-9]{53}"))',
      '("bcrypt", re.compile(rb"\\$2[aby]\\$\\d\\d\\$[./A-Za-z0-9]{52}"))'),
     "tools", True),
]


def inject():
    failures = []
    base_tools = _tools_digest()
    base_sens = _sensitivity_digest()
    print("baseline tools digest       : %s" % base_tools)
    print("baseline sensitivity digest : %s" % base_sens)
    print()
    print("%-42s %-12s %-9s %s" % ("edit", "digest", "moved?", "verdict"))
    print("-" * 82)
    for label, path, replace, which, must_move in CASES:
        fn = _tools_digest if which == "tools" else _sensitivity_digest
        base = base_tools if which == "tools" else base_sens
        got = _with_edit(path, replace, fn)
        moved = got != base
        ok = moved == must_move
        print("%-42s %-12s %-9s %s"
              % ("%s [%s]" % (label, which), got, "yes" if moved else "no",
                 "ok" if ok else ("WRONG: expected it to %smove"
                                  % ("" if must_move else "not "))))
        if not ok:
            failures.append("%s [%s]" % (label, which))

    # The control on the controls: every file is byte-identical to what it was.
    after_tools, after_sens = _tools_digest(), _sensitivity_digest()
    print()
    print("%-42s %-12s %s" % ("working tree restored (tools)", after_tools,
                              "ok" if after_tools == base_tools else "NOT RESTORED"))
    print("%-42s %-12s %s" % ("working tree restored (sensitivity)", after_sens,
                              "ok" if after_sens == base_sens else "NOT RESTORED"))
    if after_tools != base_tools or after_sens != base_sens:
        failures.append("a case did not restore the file it edited")

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(CASES), len(CASES) - len(failures), len(failures)))
    for f in failures:
        print("FAIL:", f)
    return 1 if failures else 0


if __name__ == "__main__":
    if "--inject" in sys.argv or "--assert-note-is-not-behaviour" in sys.argv:
        sys.exit(inject())
    sys.exit("usage: digest-controls.py --inject\n"
             "       (--assert-note-is-not-behaviour is accepted as the name "
             "verify-content-mask.py's comment gives this control)")
