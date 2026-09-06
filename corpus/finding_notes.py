#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The prose a gate finding carries, kept where an AST digest cannot see it.

WHY THIS FILE EXISTS
--------------------
`gate_provenance.tools_digest` is taken over the syntax trees of six modules, and a string
literal is part of a syntax tree. So a sentence written into `verify-content-mask.py` and
attached to a finding could not be corrected: fixing four characters of prose moved the
digest, and every stamped row read `stale` until it was re-measured against bytes that, for
most rows, are not on this machine. `FP_NOTE` hit that first and was moved out to
`fp-note.txt`. The identifier note hit it next, and its second clause was known to be wrong
for two rounds while the price of the edit was a re-measurement of the whole index.

That is the wrong shape for a repair. A note is what a reader is told; it decides nothing.
The AST holds the FILENAME and the loader - which are behaviour, and which move the digest
exactly as they should - and the prose is data beside them.

WHY THE FIXTURES READ IT FROM HERE TOO
--------------------------------------
Five modules build a finding-shaped dict in their own controls and each hard-coded the note
by hand. Measured before this file existed: all five carried `identifier names deliberately
not recorded here` and the generator wrote `... here; they are the thing being masked`, so
every one of the five had been asserting, for as long as they had existed, text that the
generator has never produced. Nothing could see it, because each fixture agreed with itself.

That is the failure AGENTS.md is about - a control that passes while being wrong - so the
fixtures now take the note from this module, and `--inject` checks the tie in the direction
that can fail: it reads the five modules' own syntax trees and reports any finding-shaped
dict that has gone back to a hard-coded note.

WHAT IS *NOT* HERE, AND WHY THAT IS NOT AN OVERSIGHT
-----------------------------------------------------
`secret_gate`'s note is not relocated to a file; it is deleted, and its content is in that
function's docstring. It was recorded on nobody: `mask-samples.py` writes a named twelve
fields and `remeasure-gates.recorded_form` narrows to the same twelve, so the key survived
only on 8 rows written by an earlier build. Relocating it would have kept a caption alive in
a return value nothing stores; removing it lets those 8 rows reconcile to twelve keys
through the machinery that already exists for that, and closes the 12-versus-13 key fork
that `gate_evidence` could only call harmless while the text was pinned inside the AST.
"""
import ast, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))

# The prose files. The names are behaviour and live in the AST; the contents are not.
IDENTIFIER_NOTE_PATH = os.path.join(HERE, "finding-note.txt")
FP_NOTE_PATH = os.path.join(HERE, "fp-note.txt")

# The modules that build a finding-shaped fixture, and must not hard-code the note again.
FIXTURES = ("clearance.py", "gate_evidence.py", "lift-adjudication.py",
            "remeasure-gates.py", "shard-gate.py")

# The key a finding carries the note under, and the one `_profile` carries the rate under.
NOTE_KEY = "note"
FP_KEY = "false_positive_note"


def load(path):
    """The file's text as one line, or a hard failure.

    Whitespace is collapsed so that re-wrapping a paragraph cannot change the stored string:
    the note is recorded onto index rows and compared field by field by
    `gate_evidence.compare_gate`, so a reflowed file would otherwise read as a measurement
    that moved.

    An empty or missing file raises rather than yielding "". A finding that cites a
    qualifier it cannot state is a finding with the qualifier silently removed, and
    `clearance.finding_digest` covers this string - so a silent empty would move every
    digest and un-anchor every clearance keyed to one.
    """
    with open(path, encoding="utf-8") as fh:
        text = " ".join(fh.read().split())
    if not text:
        raise RuntimeError("%s is empty; a finding must not carry a note it cannot state"
                           % path)
    return text


IDENTIFIER_NOTE = load(IDENTIFIER_NOTE_PATH)
FP_NOTE = load(FP_NOTE_PATH)


# ---------------------------------------------------------------------------------------
# The tie between the generator and the fixtures, checked in the direction that can fail.
# ---------------------------------------------------------------------------------------
# The vocabulary `shard-gate.FINDING_SHAPE` uses for its types. A dict whose every string
# value is one of these is describing a finding, not being one.
TYPE_TAGS = frozenset(("str", "int", "ints", "strs"))


def is_shape_table(node):
    """True for a dict that maps finding keys to TYPE names rather than to values."""
    strings = [v.value for v in node.values
               if isinstance(v, ast.Constant) and isinstance(v.value, str)]
    return bool(strings) and all(v in TYPE_TAGS for v in strings)


def hardcoded_notes(names=FIXTURES, root=HERE):
    """[(module, lineno, text)] for every finding-shaped dict holding a LITERAL note.

    Read from each module's syntax tree rather than by text search, because the question is
    whether a dict displayed in the source carries a constant under `note` - and a text
    search cannot tell a dict key from the same word in a docstring, which is where several
    of these modules discuss the note at length.

    A dict is finding-shaped when it carries `note` alongside at least one key `_profile`
    emits. That guard matters: `masking.note` is a different field on the row itself, and a
    sweep that flagged every `"note":` in the tree would report those and be turned off.

    One dict passes that guard and is not a fixture: `shard-gate.FINDING_SHAPE`, which maps
    every key a finding may carry to the TYPE it must have, so its `note` is the four
    characters `str`. It is excluded by what it is rather than by name - a dict whose every
    string value is a type tag is a shape table and not a finding - so a shape table that
    ever gained real prose would be reported rather than skipped, and the exclusion cannot
    quietly widen to cover a fixture. `--inject` asserts both halves of that.
    """
    shape = {"distinct_identifiers", "occurrences", "identifier_lengths", "positions",
             "segment_lengths", "kinds", "methods", FP_KEY}
    out = []
    for name in names:
        path = os.path.join(root, name)
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            keys = {k.value for k in node.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            if NOTE_KEY not in keys or not (keys & shape):
                continue
            if is_shape_table(node):
                continue
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and k.value == NOTE_KEY
                        and isinstance(v, ast.Constant) and isinstance(v.value, str)):
                    out.append((name, v.lineno, v.value))
    return out


def inject(root=HERE):
    """Both directions: the note is not behaviour, and the fixtures cannot drift from it."""
    import shutil, tempfile
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-64s %-20s %s" % (label, str(got)[:20],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    print("=== the generator emits exactly this text, and nothing restates it ===")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "vcm_notes", os.path.join(root, "verify-content-mask.py"))
    VCM = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(VCM)
    # A finding built by the real generator, from a planted hit, rather than a hand-made
    # dict. A fixture compared against a fixture is the defect this file was written for.
    ids, keep = {"acct01"}, set()
    planted = "$p = '/home/acct01/public_html/index.php';"
    _ok, res = VCM.gate(planted.encode(), ids, keep)
    finding = res.get("plaintext_finding") or {}
    case("the gate emitted a plaintext finding at all", bool(finding), True)
    case("its note is the one in finding-note.txt",
         finding.get(NOTE_KEY) == IDENTIFIER_NOTE, True)
    case("its false-positive note is the one in fp-note.txt",
         finding.get(FP_KEY) == FP_NOTE, True)
    # The positive half. Without it the two cases above pass against any pair of equal
    # strings, including two empties.
    case("and the comparison can say no", finding.get(NOTE_KEY) == IDENTIFIER_NOTE + "!",
         False)
    case("the secret gate carries no note to record",
         NOTE_KEY in VCM.secret_gate(b"<?php echo 1;", b"<?php echo 1;")[1], False)

    print()
    print("=== no fixture hard-codes the note ===")
    live = hardcoded_notes(root=root)
    case("finding-shaped dicts holding a literal note", [(n, t[:20]) for n, _l, t in live],
         [])

    print()
    print("=== the shape table is excluded for what it is, not by name ===")
    shape_tbl = ast.parse('X = {"note": "str", "occurrences": "int", "kinds": {"acct"}}')
    real_note = ast.parse('X = {"note": "some real prose", "occurrences": "int"}')
    case("a dict of type tags is a shape table",
         is_shape_table(next(n for n in ast.walk(shape_tbl) if isinstance(n, ast.Dict))),
         True)
    case("the same table carrying real prose is not",
         is_shape_table(next(n for n in ast.walk(real_note) if isinstance(n, ast.Dict))),
         False)

    print()
    print("=== and the sweep can find one, or it is asserting nothing ===")
    tmp = tempfile.mkdtemp(prefix="finding-notes-inject.")
    try:
        for n in FIXTURES:
            shutil.copy2(os.path.join(root, n), os.path.join(tmp, n))
        p = os.path.join(tmp, "clearance.py")
        src = open(p, encoding="utf-8").read()
        marker = '"segment_lengths": [25],'
        if marker not in src:                                         # pragma: no cover
            raise AssertionError("control fixture is stale: clearance.py no longer builds "
                                 "a finding with %r" % marker)
        open(p, "w", encoding="utf-8").write(
            src.replace(marker, marker + '\n            "note": "a planted hard-coded note",',
                        1))
        planted_hits = hardcoded_notes(root=tmp)
        case("a note written back into a fixture is reported",
             [(n, t) for n, _l, t in planted_hits], [("clearance.py",
                                                      "a planted hard-coded note")])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("=== a missing or empty note file is a hard failure, not an empty string ===")
    tmp2 = tempfile.mkdtemp(prefix="finding-notes-empty.")
    try:
        empty = os.path.join(tmp2, "empty.txt")
        open(empty, "w").close()
        try:
            load(empty)
            got = "returned"
        except RuntimeError:
            got = "refused"
        case("an empty note file", got, "refused")
        try:
            load(os.path.join(tmp2, "does-not-exist.txt"))
            got = "returned"
        except OSError:
            got = "refused"
        case("a missing note file", got, "refused")
        # The negative half: a file with prose in it must still load.
        ok = os.path.join(tmp2, "ok.txt")
        open(ok, "w", encoding="utf-8").write("  some\n  prose  \n")
        case("a file with prose in it loads, whitespace collapsed", load(ok), "some prose")
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    if "--inject" in sys.argv:
        sys.exit(inject())
    if "--show" in sys.argv:
        print("identifier note : %s" % IDENTIFIER_NOTE)
        print()
        print("false-positive  : %s" % FP_NOTE)
        sys.exit(0)
    sys.exit("usage: finding_notes.py --inject | --show")
