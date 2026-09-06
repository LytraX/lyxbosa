#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""What produced a stored gate verdict, so the gate can ask whether it still would.

THE PROBLEM THIS EXISTS FOR
---------------------------
`shard-gate.py` reads `masking.plaintext_gate == "PASS"` and treats it as a pass. It has no
way to ask *when* that was measured or *by what*, so a verdict recorded by a version of the
gate that has since got stricter reads exactly like one measured a minute ago. That is not a
hypothetical: re-gating by hand found 5 of 95 local rows whose recorded `PASS` the current
gate rejects, and 1 of 8 rows in the published half of the index. In every case the sample
had not changed - the predicate had. Nothing in the index moved, and nothing could have.

`measured_with` already existed and does not answer this. It records the scanner binary,
which is the right provenance for `detection_survived` and says nothing at all about the
masker or the identifier gate. Provenance for the wrong question reads as provenance.

WHAT IS STAMPED, AND WHY THAT AND NOT A COMMIT
----------------------------------------------
The question a stamp has to answer is "would these tools, as they stand now, return the same
verdict". A git commit cannot answer it: every record this round had to repair was written by
an *uncommitted* working tree, and a commit id would have been either absent or - worse -
the id of the last commit, which is a confident wrong answer. The tools also live in five
files that change for reasons that do not affect a verdict at all; this repository edits
docstrings constantly, and a stamp that moved on every prose edit would put the whole index
into re-measurement every round and would be turned off within two.

So the stamp is an **AST digest**: each source file is parsed, its docstrings are removed,
and `ast.dump` renders the remaining tree without line numbers or column offsets. Comments
and formatting are absent from an AST by construction, so reindenting a function or rewriting
its docstring does not move the digest. Renaming a local, changing a regex literal, adding a
branch or reordering two rules all do. That is the boundary the question needs.

Two digests, because they answer to different owners and only one of them can be checked by a
stranger:

  * `tools` - the five tracked modules that decide which bytes may change and what counts as
    a leak. Tracked, so anyone who clones this repository can recompute it.
  * `map`   - the identifier list, the keep list and the tier table, which are equally part
    of the gate's behaviour: adding a name or narrowing a tier changes verdicts without
    touching a line of code. The maps are out of repo, so this half is checkable only on a
    machine that has them, and `verify()` says so rather than passing quietly.

WHAT IT WOULD AND WOULD NOT HAVE CAUGHT
---------------------------------------
Would have caught, last round: the slot-rule delimiter change (a regex literal in
`content_mask.py`), the tier demotion and its rollback (both move the `map` digest), and
every uncommitted intermediate state of `mask-samples.py` whose records are still in the
index - because the digest is taken from the code that actually ran, not from what was
committed.

Would NOT have caught: a behaviour change with no source change on either side. A different
Python version whose `re` module resolves an overlapping alternation differently, a locale
that changes `str.isalpha()` for a non-ASCII byte, or a scanner rebuild - that last one is
what `measured_with` is for, and it is kept for exactly that reason rather than folded in
here. Nor does it catch a change in `shard-gate.py` itself: the stamp is about the verdicts
stored on a row, and the rule that reads them is not one of them.
"""
import ast, hashlib, json, os, sys, datetime

HERE = os.path.dirname(os.path.abspath(__file__))

# The five modules whose logic decides a stored gate verdict. `shard-gate.py` is deliberately
# absent - it consumes these verdicts and does not produce them - and so is `indexio.py`,
# which moves bytes and decides nothing.
TOOLS = ("incident_mask.py",        # tier rules and span selection, inherited by the rest
         "content_mask.py",         # the byte masker
         "verify-content-mask.py",  # the gate: plaintext, encoded layers, secrets
         "verify-infected-mask.py", # the leak predicate the gate delegates to
         "mask-samples.py",         # the driver that decides what is recorded at all
         "gate_provenance.py")      # this file: the digest algorithm is part of the claim


def _strip_docstrings(tree):
    """Docstrings are prose and must not move the digest. Everything else must."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
            continue
        body = getattr(node, "body", None)
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            node.body = body[1:] or [ast.Pass()]
    return tree


def module_digest(path):
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    tree = _strip_docstrings(ast.parse(src))
    # include_attributes=False drops lineno/col_offset, so reformatting is invisible.
    return hashlib.sha256(ast.dump(tree).encode("utf-8")).hexdigest()


_DIGEST_CACHE = {}


def tools_digest(root=HERE, tools=TOOLS):
    """Cached per root: `shard-gate.py` asks this once per row over 92,800 rows, and
    re-parsing six files each time turns a three-second gate into a four-minute one."""
    key = (root, tools)
    if key in _DIGEST_CACHE:
        return _DIGEST_CACHE[key]
    h = hashlib.sha256()
    for name in sorted(tools):
        h.update(name.encode("utf-8"))
        h.update(module_digest(os.path.join(root, name)).encode("utf-8"))
    _DIGEST_CACHE[key] = h.hexdigest()[:12]
    return _DIGEST_CACHE[key]


_MAP_CACHE = {}


def map_digest(map_paths):
    """The behavioural surface of the maps: who is masked, what is kept, how widely.

    Hashes rather than records. A digest of customer identifiers reveals none of them, which
    is what lets this field live in a tracked index at all.
    """
    sys.path.insert(0, HERE)
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "vim_prov", os.path.join(HERE, "verify-infected-mask.py"))
    vim = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vim)

    key = tuple(sorted(map_paths))
    if key in _MAP_CACHE:
        return _MAP_CACHE[key]
    h = hashlib.sha256()
    for p in sorted(map_paths):
        if not os.path.exists(p):
            _MAP_CACHE[key] = None
            return None
        with open(p, encoding="utf-8") as fh:
            m = json.load(fh)
        h.update(os.path.basename(p).encode("utf-8"))
        for name in sorted(vim.identifiers(m)):
            h.update(("id:" + name.lower()).encode("utf-8"))
        for k in sorted(vim.keep_tokens(m)):
            h.update(("keep:" + k.lower()).encode("utf-8"))
        for k, v in sorted((m.get("mask_tier") or {}).items()):
            h.update(("tier:%s=%s" % (k.lower(), v)).encode("utf-8"))
    _MAP_CACHE[key] = h.hexdigest()[:12]
    return _MAP_CACHE[key]


def stamp(map_paths, root=HERE):
    """What a measuring tool writes onto the row."""
    return {"tools": tools_digest(root),
            "map": map_digest(map_paths),
            "at": datetime.datetime.now().replace(microsecond=0).isoformat()}


# ---------------------------------------------------------------------------------------
# The comparison. Three outcomes and never two, because "cannot tell" must not read as
# "fine" - that is the whole defect this file is about, one level up.
# ---------------------------------------------------------------------------------------
def verify(stored, map_paths=(), root=HERE):
    """(state, detail). state is 'ok', 'absent' or 'stale'.

    The `tools` half is always required: those five files are tracked, so a stranger who
    clones this repository can recompute the digest and check every row in the published
    half. The `map` half is checked only where the maps exist. On a machine without them the
    result says `map not checked` rather than passing quietly - §7.2's map-free invariants
    are a floor under what a stranger can verify, never a licence to report a partial check
    as a whole one.
    """
    if not isinstance(stored, dict) or not stored.get("tools"):
        return "absent", "no gate provenance recorded"
    want_tools = tools_digest(root)
    if stored["tools"] != want_tools:
        return "stale", ("measured by tools %s; these are %s"
                         % (stored["tools"], want_tools))
    want_map = map_digest(map_paths) if map_paths else None
    if want_map is None:
        return "ok", "tools match; map not checked (maps not present)"
    if stored.get("map") != want_map:
        return "stale", ("measured against map %s; this is %s"
                         % (stored.get("map"), want_map))
    return "ok", "tools and map both match"


# ---------------------------------------------------------------------------------------
# Controls.
# ---------------------------------------------------------------------------------------
def inject():
    """Prove the digest moves for a logic change and holds for a prose one.

    The negative half is as load-bearing as the positive: a digest that changed on every
    edit would be correct on the failure it was written for and useless within a round,
    because every row would read stale every time and re-measurement would stop meaning
    anything. So `a docstring rewrite` and `a comment added` must NOT move it.
    """
    import tempfile, shutil
    fails = []

    def case(label, mutate, want_move):
        tmp = tempfile.mkdtemp(prefix="gate-prov-inject.")
        try:
            for n in TOOLS:
                shutil.copy2(os.path.join(HERE, n), os.path.join(tmp, n))
            # Not a TOOLS file, and that is the point: it is the prose the findings cite,
            # and it has to be present in the fixture for the case that rewrites it.
            for prose in ("fp-note.txt", "finding-note.txt"):
                shutil.copy2(os.path.join(HERE, prose), os.path.join(tmp, prose))
            # `verify-content-mask.py` imports it, so the fixture root has to hold it or the
            # digest cannot be taken over that root at all.
            shutil.copy2(os.path.join(HERE, "finding_notes.py"),
                         os.path.join(tmp, "finding_notes.py"))
            # The cache is keyed by root, and this fixture mutates a root in place, so it
            # has to be cleared between the two reads. Without this every positive case
            # reports "held" and the suite passes while measuring nothing - which is what
            # it did the first time the cache was added.
            _DIGEST_CACHE.clear()
            before = tools_digest(tmp)
            mutate(tmp)
            _DIGEST_CACHE.clear()
            after = tools_digest(tmp)
            moved = before != after
            ok = moved == want_move
            print("  %-56s %-9s %s" % (label, "moved" if moved else "held",
                                       "ok" if ok else "WRONG"))
            if not ok:
                fails.append(label)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def edit(tmp, name, old, new, count=1):
        p = os.path.join(tmp, name)
        s = open(p, encoding="utf-8").read()
        if old not in s:
            raise AssertionError("control fixture is stale: %r not in %s" % (old[:40], name))
        open(p, "w", encoding="utf-8").write(s.replace(old, new, count))

    print("=== a change that alters a verdict must MOVE the digest ===")

    # The exact change that turned two recorded passes into failures. The slot rule's
    # trailing guard went from a positive list of delimiters to the negative form; this
    # reverses it, which is what last round's records were measured under.
    # DOCROOT_SLOT's trailing guard. It ended with a positive list of the delimiters
    # expected to follow, which missed a path terminated by a tag open; the negative form
    # replaced it. Reversing it here reproduces the state last round's records were
    # measured under, which is the change no field in the index could see.
    case("a slot rule's delimiter guard goes back to a positive list",
         lambda t: edit(t, "content_mask.py",
                        r'(?![A-Za-z0-9-])")',
                        r'(?=[/\"\'<\\s])")'), True)

    case("the leak predicate's length threshold moves",
         lambda t: edit(t, "verify-infected-mask.py",
                        "LONG_ENOUGH_TO_BE_ONLY_A_NAME = 6",
                        "LONG_ENOUGH_TO_BE_ONLY_A_NAME = 5"), True)
    case("a tier test is reordered",
         lambda t: edit(t, "incident_mask.py",
                        'if low in vocab or len(low) < 3:',
                        'if len(low) < 3 or low in vocab:'), True)
    case("a branch is added to the driver",
         lambda t: edit(t, "mask-samples.py", "    survived = rules_after == rules_before",
                        "    survived = rules_after == rules_before\n"
                        "    if not survived:\n        pass"), True)
    case("a gate result key is renamed",
         lambda t: edit(t, "verify-content-mask.py",
                        '"secret_gate": "FAIL" if (carried or increased)',
                        '"secret_gate_v2": "FAIL" if (carried or increased)'), True)

    print()
    print("=== a change that cannot alter a verdict must NOT move it ===")
    case("a module docstring is rewritten",
         lambda t: edit(t, "content_mask.py", '"""', '"""REWRITTEN FOR THE CONTROL. '), False)
    case("a comment is added",
         lambda t: edit(t, "incident_mask.py", "import ", "# an added comment\nimport "), False)

    def reindent(tmp):
        p = os.path.join(tmp, "verify-infected-mask.py")
        s = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(s.replace("\n\n\n", "\n\n\n\n"))
    case("blank lines are added throughout", reindent, False)

    # The findings' false-positive note. It was a module-level string literal in
    # `verify-content-mask.py`, so every word of it sat inside the AST this digest is taken
    # over: a four-character prose repair moved `tools` and put all 139 stamped rows into
    # re-measurement, which is why a figure known to be wrong stayed wrong for a round. It
    # now lives in `fp-note.txt`.
    #
    # THREE assertions, because the obvious one passes on a module that ignores the file
    # entirely - including the module this replaced. Rewriting the note must not move the
    # digest; the loader must actually follow the file; and the prose must be absent from
    # the AST. The second and third are what make the first mean anything.
    def prose_edit(tmp):
        with open(os.path.join(tmp, "fp-note.txt"), "w", encoding="utf-8") as fh:
            fh.write("REWRITTEN FOR THE CONTROL: 0 false positives over 0 files.\n")
    case("the findings' false-positive note is rewritten", prose_edit, False)

    import importlib.util as _il
    _sp = _il.spec_from_file_location("vcm_prov",
                                      os.path.join(HERE, "verify-content-mask.py"))
    _vcm = _il.module_from_spec(_sp)
    _sp.loader.exec_module(_vcm)
    _tmp = tempfile.mkdtemp(prefix="fp-note-control.")
    try:
        alt = os.path.join(_tmp, "fp-note.txt")
        with open(alt, "w", encoding="utf-8") as fh:
            fh.write("a wholly different note\n")
        # getattr rather than an attribute access: run against a tree where the note is
        # still a literal there is no loader, and a control that raises there reports
        # nothing at all. It has to be able to SAY the other thing.
        _fn = getattr(_vcm, "finding_notes", None)
        loader = getattr(_fn, "load", None)
        follows = bool(loader) and (loader(alt) == "a wholly different note"
                                    and _vcm.FP_NOTE != "a wholly different note")
    finally:
        shutil.rmtree(_tmp, ignore_errors=True)
    print("  %-56s %-9s %s" % ("the note is read from that file, not from this one",
                               "follows" if follows else "IGNORED",
                               "ok" if follows else "WRONG"))
    if not follows:
        fails.append("the note is not actually loaded from fp-note.txt")

    _src = ast.dump(_strip_docstrings(ast.parse(
        open(os.path.join(HERE, "verify-content-mask.py"), encoding="utf-8").read())))
    _leaked = [w for w in ("false positives across", "Re-run with --stock-fp",
                           "identifiers of 6+ characters") if w in _src]
    print("  %-56s %-9s %s" % ("the note's prose is absent from the digest's input",
                               "absent" if not _leaked else "PRESENT",
                               "ok" if not _leaked else "WRONG"))
    if _leaked:
        fails.append("the note's prose is still inside the AST the digest reads")

    # The identifier note went the same way and for the same reason, so the same three
    # questions are asked of it. Its prose was wrong in its second clause for two rounds
    # because correcting it cost a re-measurement of every stamped row.
    _ident = [w for w in ("deliberately not recorded here", "the thing being masked",
                          "is an adjudication") if w in _src]
    print("  %-56s %-9s %s" % ("the identifier note's prose is absent too",
                               "absent" if not _ident else "PRESENT",
                               "ok" if not _ident else "WRONG"))
    if _ident:
        fails.append("the identifier note's prose is still inside the AST")

    # And the negative half: the LOADER is behaviour and must move the digest. Without this
    # the cases above are satisfied by deleting the note altogether. The loader is now a
    # reference to the module that holds the prose, so the edit is which note is loaded -
    # the same question the filename used to ask, one indirection along.
    case("which note the gate loads changes",
         lambda t: edit(t, "verify-content-mask.py",
                        "FP_NOTE = finding_notes.FP_NOTE",
                        "FP_NOTE = finding_notes.IDENTIFIER_NOTE"),
         True)

    print()
    print("=== verify() must separate 'absent' from 'stale' from 'ok' ===")
    now = tools_digest()
    for label, stored, want in (
            ("no provenance at all", None, "absent"),
            ("an empty dict", {}, "absent"),
            ("a stamp with no tools digest", {"map": "abc", "at": "x"}, "absent"),
            ("a stamp from superseded tools", {"tools": "0" * 12, "map": None}, "stale"),
            ("a stamp from the current tools", {"tools": now, "map": None}, "ok")):
        got, _ = verify(stored)
        ok = got == want
        print("  %-56s %-9s %s" % (label, got, "ok" if ok else "WRONG (wanted %s)" % want))
        if not ok:
            fails.append(label)

    # And the map half, which is the one a stranger cannot check.
    import incident_mask
    maps = [incident_mask.MAP_PATH]
    have = all(os.path.exists(p) for p in maps)
    if have:
        real = map_digest(maps)
        got, detail = verify({"tools": now, "map": real}, maps)
        ok = got == "ok" and "map" in detail
        print("  %-56s %-9s %s" % ("a stamp matching the live map", got,
                                   "ok" if ok else "WRONG"))
        if not ok:
            fails.append("live map stamp")
        got, _ = verify({"tools": now, "map": "0" * 12}, maps)
        ok = got == "stale"
        print("  %-56s %-9s %s" % ("a stamp from a superseded map", got,
                                   "ok" if ok else "WRONG"))
        if not ok:
            fails.append("superseded map stamp")
        got, detail = verify({"tools": now, "map": "0" * 12}, ["/nonexistent/map.json"])
        ok = got == "ok" and "not checked" in detail
        print("  %-56s %-9s %s" % ("maps absent: says so rather than passing quietly", got,
                                   "ok" if ok else "WRONG"))
        if not ok:
            fails.append("absent-map reporting")
    else:
        print("  maps not present; the map half of the control did not run")

    n = 20 if have else 17
    print()
    print("cases: %d · passed: %d · failed: %d" % (n, n - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


USAGE = ("usage: gate_provenance.py --show [--map <path> ...]\n"
         "       gate_provenance.py --inject")

if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--inject" in argv:
        sys.exit(inject())
    if "--show" in argv:
        sys.path.insert(0, HERE)
        import incident_mask
        maps = []
        while "--map" in argv:
            i = argv.index("--map")
            maps.append(argv[i + 1])
            del argv[i:i + 2]
        maps = maps or [incident_mask.MAP_PATH]
        print("tools digest : %s" % tools_digest())
        for n in sorted(TOOLS):
            print("    %-26s %s" % (n, module_digest(os.path.join(HERE, n))[:12]))
        print("map digest   : %s  (over %s)"
              % (map_digest(maps), ", ".join(os.path.basename(p) for p in maps)))
        sys.exit(0)
    sys.exit(USAGE)
