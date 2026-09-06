#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Which fields in the index no tracked tool writes - the census, not the individual cases.

THE PATTERN, WHICH IS NOW THE FINDING
--------------------------------------
Three fields have been found one at a time, a round apart each, by somebody noticing:

  * `masking.not_applicable_reason` - 29 rows. `mask-samples.py` READS it and never writes
    it, so the driver honours a claim it cannot produce. Author: an uncommitted state of
    that same file, never saved anywhere.
  * `sensitivity` - every mechanically-derived tag in both halves. Author: an untracked file
    under `trail-data`, reproduced into `corpus/sensitivity.py` once somebody looked.
  * `deobfuscation.decoded_form_tags` and its siblings - author: a SECOND untracked decoder,
    in a method vocabulary that does not map onto the tracked one.

Each was found by reading, and reading found them in the order they happened to come up. The
question "how many more are there" has never been asked of the whole index, and it is a
mechanical question: enumerate the fields the rows actually carry, and ask which of them any
tracked module in `corpus/` can be shown to write.

WHAT `WRITES` MEANS HERE, AND WHY THE APPROXIMATION POINTS THE WAY IT DOES
---------------------------------------------------------------------------
A string search cannot tell a writer from a reader, and that distinction is the whole
subject: `mask-samples.py` contains the literal `not_applicable_reason`, so any grep-based
census would have reported that field covered and the defect would still be open. So the
sources are parsed, and a field counts as WRITTEN only where its name appears in a position
that produces a value:

    r["k"] = v        {"k": v}        d.setdefault("k", v)        d.pop("k")

and counts as READ where it appears only in `d.get("k")`, `"k" in d`, or a Load subscript.

The approximation is one-sided and the direction matters. A name in a write position might
still belong to some other dictionary, so `written` is an OVER-count; therefore `orphan` -
present on rows, absent from every tracked module - is an UNDER-count. **Every field this
reports is really unaccounted for, and there may be more that it does not report.** That is
the safe direction for a census whose purpose is to find things nobody has looked at, and it
is stated rather than left to be inferred.

TWO DENOMINATORS, BOTH BOUNDED BY THE PROCESS THAT PRODUCED THEM (§11)
-----------------------------------------------------------------------
  * the fields are enumerated FROM THE ROWS. A field that every row has since lost is
    invisible here, and `masking.encoded_layer_gate_uncapped` - 3 rows when `stamp-legacy.py`
    was written, 0 now - is a worked example: it was an orphan and this census could not see
    it today. So the count is of fields CURRENTLY CARRIED, never of fields ever written.
  * the modules are enumerated from `corpus/*.py`. A field written by a tracked tool that
    has since been deleted reads as an orphan, which is the correct answer for a reader but
    is not the same claim as "nothing ever wrote it".

    corpus/field-provenance.py
    corpus/field-provenance.py --json
    corpus/field-provenance.py --inject
"""
import argparse, ast, collections, json, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# Fields whose author is known not to be in this repository, with what is known about it.
# A row here is a decision that has been taken, not a suppression: the census still counts
# them, and printing them beside the answer is what stops a known orphan from being
# rediscovered every round as though it were new.
KNOWN = {
    "not_applicable_reason": ("an uncommitted state of mask-samples.py, never saved; "
                              "corpus/mark-not-maskable.py now writes it"),
    "decoded_form_tags": ("trail-data/incoming/2026-09-03/deobfuscate.py, untracked; "
                          "reproduced as corpus/deobfuscate.py"),
    "encoded_form_tags": ("the same untracked decoder as decoded_form_tags"),
    "hidden_by_encoding": ("the same untracked decoder as decoded_form_tags"),
    "evidence_decoded": ("the same untracked decoder as decoded_form_tags"),
    "evidence_encoded": ("the same untracked decoder as decoded_form_tags"),
    "sensitivity": ("trail-data/incoming/2026-09-03/sensitivity.py, untracked; reproduced "
                    "as corpus/sensitivity.py"),
    "placements": ("trail-data/incoming/2026-09-04/merge-context.py, untracked; it is not "
                   "dead - 15,674 PUBLISHED rows carry it - and it now has a tracked reader "
                   "in shard-gate.placementViolations, which asserts sum(placements) == "
                   "count (or the older copies_on_disk)"),
    "copies_on_disk": ("the older name for `count` on two published rows; read by the same "
                       "shard-gate invariant as `placements`"),
    # --- triaged 2026-09-07 (cl). Searched with `command grep` over the 276 python files
    # under corpus/, trail-data/, docs/ and tests/ found by `find`, because the shell's
    # `grep` respects .gitignore and cannot see trail-data at all - which is where every
    # untracked writer named below actually lives.
    "campaign_marker": ("written by trail-data/incoming/2026-09-03/derived/promote-sc.py "
                        "and promote-round.py, untracked. Read by make-shard-manifest.py, "
                        "which lists it in INDEX_OWNED so every manifest overwrites it from "
                        "the row. The census used to call it an orphan because "
                        "`key_positions` finds subscripts and `.get()` calls and this is a "
                        "bare string in a table iterated later; `named_field_tables` reads "
                        "that table out of the module's AST, so the resolution is derived "
                        "and not asserted here"),
    "attacker_written": ("written by trail-data/incoming/2026-09-03/round8/apply.py and "
                         "plan.py and derived/promote-round.py, all untracked. No reader "
                         "anywhere; orphan confirmed, writer named"),
    "basis": ("`review.basis`, `sensitivity_evidence.derived.basis` and "
              "`sensitivity_evidence.secret.basis` share this leaf. Written by "
              "trail-data/incoming/2026-09-03/round8/plan.py, untracked. No tracked module "
              "reads or writes the KEY - two mention the string and neither is a reader: "
              "tag-sensitivity.py carries `human_basis`, a different field, and uses the "
              "English word in a message; make-summary.py has the placeholder "
              "`<no basis recorded>` for a missing `reason`. So all three are orphans, and "
              "the shared leaf cannot be hiding a reader either way - sharing only ever "
              "ADDS matches, see `leaf_collisions`. The first sweep here searched for the "
              "quoted string and found neither module, which would have been the right "
              "answer for the wrong reason"),
    "prior_corpus": ("no writer and no reader on this machine. The only mentions are two "
                     "DOCSTRINGS - incident_mask.py and verify-infected-mask.py - citing "
                     "`prior_corpus.family` as a past failure, and that field does not "
                     "exist in either half today. Carried in by an import that predates "
                     "every tool here"),
    "fp_fixture": ("orphan confirmed, and the near-miss is named so the next sweep does not "
                   "resolve it by accident: corpus/verify.py holds `fp_fixtures` (PLURAL) "
                   "ten times, which is that tool's own result key and not this row field"),
    "observed_by": ("orphan confirmed, with the same trap: corpus/verify.py writes "
                    "`observed_by_rerun`, a different key of its own, and a substring sweep "
                    "for `observed_by` hits it"),
    "carrier_format": ("no mention in any of the 276 python files, nor in docs/ or tests/. "
                       "Orphan with no writer identifiable on this machine"),
    "local_only_history": ("as carrier_format: no mention anywhere on this machine"),
    "polymorphic_sibling_note": ("as carrier_format: no mention anywhere on this machine"),
    "expect_provenance": ("no writer or reader; the single mention is "
                          "docs/results/corpus-round-14-2026-09-06.md, a round report, "
                          "which is not a reader"),
}

# Fields REMOVED from the index, so the next census cannot rediscover them as new and so a
# reader can tell "deleted on purpose" from "never existed". A removal is a decision with an
# author, and `corpus/drop-field.py` is the only thing that should make one.
REMOVED = {
    "origin.incident": ("removed 2026-09-06 (cl) from 47,133 local rows, 0 published. One "
                        "distinct value across every row that carried it: the 8-character "
                        "constant `INCIDENT`, a string literal hardcoded in "
                        "trail-data/incoming/2026-09-04/merge-context.py, untracked. Zero "
                        "entropy, no data path to it, so it was never a customer identifier "
                        "by construction; no reader anywhere in 272 python files; and "
                        "perfectly redundant with the origin key-shape it co-occurred with "
                        "(`account_hash` present iff `incident` was). git cannot name the "
                        "commit: the local half is gitignored and the writer is untracked. "
                        "The writer still emits it, so a future merge pass will put it "
                        "back - that is a property of an untracked writer, not of this "
                        "removal."),
}


# Fields that MOVED. A move is a removal at one name and an appearance at another, and
# neither half is visible to a census enumerated from the rows: the old name simply stops
# existing and the new one reads as though it had always been there. Recorded for the same
# reason `REMOVED` is - so the next reader can tell "renamed on purpose" from "new" - and
# separately from `REMOVED`, because the data is still in the index and calling that a
# removal would be false.
MOVED = {
    "masking.encoded_layer_finding.{classification,decision,resolution,value,why_it_matters}":
        ("-> masking.human_adjudication.* on 2026-09-06 (cl), 2 published rows, with "
         "`about` added to name the gate. The block was a human adjudication occupying the "
         "key `clearance.evidence_for` returns for `encoded_layer_gate`, so the finding "
         "digest for that gate was being computed over prose and an address: rewording the "
         "argument moved it. Measured before the move rather than argued: run against both "
         "maps over the exact fixture bytes the shard ships, the current tools return PASS "
         "for both rows and emit no `encoded_layer_finding` at all, so the block was never "
         "a gate finding. Both rows read `evidence-moved` to `gate_evidence.compare_gate` "
         "before the move and `agrees` after, which is what had made them unrepairable by "
         "`verify-and-stamp.py` and `remeasure-gates.py` alike. Digest moved 663ee3e0cf71 "
         "-> ebddfbf1d6ed on both; no clearance was keyed to either, checked over every "
         "clearance object on this machine; `publishable` stayed true with zero blockers. "
         "The new leaf is `human_adjudication` and not `adjudication` because `classify` "
         "matches on the leaf, and a reader of `adjudication` would silently reclassify "
         "`sensitivity_review.adjudication` - 68 rows, a real orphan - as read-only."),
}


# A control suite is not a writer. Every tool in this tree carries one, and a control
# fixture is a dict literal - `{"decision": …, "resolution": …}` - which `key_positions`
# reads as a write position exactly like a real one. Nothing that runs against the index
# passes through these functions.
#
# THIS IS THE SAME DEFECT THIS FILE ALREADY DOCUMENTS ABOUT ITSELF, IN A SECOND PLACE.
# `KNOWN` and `REMOVED` are dict literals keyed by field name, so the census was the sole
# claimed writer of six real index fields until it stopped parsing itself. Control fixtures
# are the same shape one level along, and the count is not small: measured over both halves,
# NINE fields carried by rows have no write position anywhere in `corpus/` outside a control
# suite - including `account_hash` on 67,985 rows and `origin.account_hash` on 47,133, whose
# only mention in this repository is a fixture in `regen-tiers.py --inject`. Every one of
# them was being reported as covered.
CONTROL_SUITES = ("inject", "_selftest")


def _control_nodes(tree):
    """Every node inside a control-suite function, by identity."""
    inside = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in CONTROL_SUITES:
            for c in ast.walk(n):
                inside.add(id(c))
    return inside


def key_positions(path):
    """({written}, {read}) - the string constants this module writes and reads as keys.

    A module-level `NAME = "literal"` is resolved, because the tools here write through
    exactly that idiom - `RECORD_KEY = "sensitivity_adopted"`, then `after[RECORD_KEY] = …`.
    Without it `adopt-decoded-tags.py` and `tag-sensitivity.py` both report their own record
    field as an orphan, which is a false finding in the direction that wastes a round.

    Write positions inside `inject()` and `_selftest()` do NOT count - see `CONTROL_SUITES`.
    Read positions still do: a control that reads a field is a tracked reader of it in the
    only sense this census measures, and the asymmetry is deliberate, because `written` is
    the state that hides a field from the report.
    """
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    written, read = set(), set()
    control = _control_nodes(tree)

    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            consts[node.targets[0].id] = node.value.value

    def const(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return consts.get(node.id)
        return None

    def write(s, node):
        if s and id(node) not in control:
            written.add(s)

    for node in ast.walk(tree):
        # r["k"] = v  /  del r["k"]
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.Delete)):
            targets = node.targets if hasattr(node, "targets") else [node.target]
            for t in targets:
                if isinstance(t, ast.Subscript):
                    write(const(t.slice), node)
        # {"k": v}
        elif isinstance(node, ast.Dict):
            for k in node.keys:
                write(const(k), node)
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else None
            if name in ("setdefault", "pop") and node.args:
                write(const(node.args[0]), node)
            elif name == "get" and node.args:
                s = const(node.args[0])
                if s:
                    read.add(s)
            elif name == "dict":
                for kw in node.keywords:
                    if kw.arg:
                        write(kw.arg, node)
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            s = const(node.slice)
            if s:
                read.add(s)
        elif isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(op, ast.In):
                    s = const(node.left)
                    if s:
                        read.add(s)
    return written, read


# This file writes no index row. It is a census, and its own bookkeeping tables - `KNOWN`,
# `REMOVED` - are dict literals whose KEYS are field names, which `key_positions` reads as
# write positions like any other. So the census counted itself as the writer of every field
# it had recorded as an orphan, and `main()` does not print fields in the `written` state:
# `evidence_decoded`, `evidence_encoded` and `hidden_by_encoding` were classified as covered
# and never printed, by the note saying nobody covers them. Excluding this file is not a
# special case, it is the truth about it - and it is asserted in `inject()` rather than left
# to a comment.
SELF = os.path.basename(__file__)


# How many modules were actually parsed. It used to be reported as
# `len({m for v in writes.values() for m in v})` - the number of modules with at least one
# WRITE position, printed under the label "tracked modules parsed". The two were the same
# number by accident and stopped being it the moment control fixtures stopped counting as
# writes: three modules whose only key literals are in their control suite dropped out, and
# the line read "30 parsed" over a directory of 34. A count is not a count of what its label
# says until something makes it so.
PARSED = []


# Module-level ALL-CAPS tuples/lists/sets of plain strings that ARE a list of index field
# names, named here rather than guessed at. `key_positions` finds subscripts and `.get()`
# calls; a bare string in a table that is iterated later is neither, and this repository
# writes that idiom constantly.
#
# Why a NAMED list and not "every uppercase tuple of strings": most such tables are not
# field names at all - shape vocabularies, gate verdict values, regex labels - and crediting
# their contents as reads would inflate `read-only` exactly the way `written` is already
# inflated. §11 is about a denominator enumerated by the process that produced it; widening
# this to a pattern would be a twelfth instance rather than a repair.
FIELD_NAME_TABLES = {
    "make-shard-manifest.py": ("INDEX_OWNED",),
}


def named_field_tables(path, names):
    """{constant: [field names]} read from `path`'s AST, or {} where the shape is gone.

    Parsed rather than imported (importing runs a tool) and rather than grepped (a text
    search cannot tell one tuple from another) - the same tie `gate_evidence` makes for
    `mask-samples.py`'s key tuple. A constant that is no longer a flat tuple of strings is
    ABSENT from the result rather than empty, so `--inject` can tell "the shape moved" from
    "the table is empty" instead of reporting agreement either way.
    """
    out = {}
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if not (isinstance(t, ast.Name) and t.id in names):
                continue
            v = node.value
            if not isinstance(v, (ast.Tuple, ast.List, ast.Set)):
                continue
            vals = [e.value for e in v.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if len(vals) == len(v.elts) and vals:
                out[t.id] = vals
    return out


def scan_modules(root=HERE):
    """(writes, reads) over every tracked python module in `corpus/`, except this one."""
    writes, reads = collections.defaultdict(set), collections.defaultdict(set)
    del PARSED[:]
    for fn in sorted(os.listdir(root)):
        if not fn.endswith(".py") or fn == SELF:
            continue
        try:
            w, r = key_positions(os.path.join(root, fn))
        except SyntaxError:                                          # pragma: no cover
            continue
        PARSED.append(fn)
        for k in w:
            writes[k].add(fn)
        for k in r:
            reads[k].add(fn)
        # A field this module carries by naming it in a declared table is READ by it, not
        # written: the table says the value comes from the row.
        for _const, fields in named_field_tables(os.path.join(root, fn),
                                                 FIELD_NAME_TABLES.get(fn, ())).items():
            for k in fields:
                reads[k].add(fn)
    return writes, reads


def field_census(paths, max_depth=2, map_threshold=None):
    """({dotted field: row count}, {value-keyed parents}) over the index halves.

    A dict whose KEYS are data rather than schema - `masking.not_masked`, `placements` -
    would otherwise contribute one "field" per distinct value and drown the census in things
    no module could ever be expected to name. So such a parent is reported as a value-keyed
    map, its own name is still censused, and its children are not.

    THE TEST USED TO BE "MORE THAN EIGHT CHILDREN", AND IT WAS WRONG BOTH WAYS
    --------------------------------------------------------------------------
    The previous docstring named the risk exactly - "a schema block with nine keys would be
    misread as a map" - and then that is what happened, to nine blocks at once. Measured
    over both halves, the count test classified ten parents as value-keyed. **One of them
    was.** The other nine were schema blocks whose children were therefore never censused
    at all, and they include `masking` (26 children), which holds every gate verdict, every
    finding, `provenance` and `secret_literals` - the block a human clearance is keyed to.
    An orphan field anywhere under it was invisible to the tool whose entire job is to find
    orphan fields. It also ran the other way: three value KEYS under
    `sensitivity_review.adjudication` were counted as fields and reported as orphans,
    because that parent had only four children and stayed under the threshold.

    The test is now what actually distinguishes the two: **schema keys are written by a
    programmer and are identifiers; value keys are data labels and are not.** Over both
    halves exactly four parents have any non-identifier child, and all four are real
    value-keyed maps - `placements` (10 of 11), `masking.encoded_regions` (3 of 3),
    `masking.not_masked` (2 of 2), `sensitivity_review.adjudication` (3 of 4). Every other
    parent in the corpus has children that are identifiers without exception. So the rule is
    a majority of non-identifier children, it needs no size threshold, and `map_threshold`
    is accepted and ignored so an old caller does not silently get a different census.
    """
    counts = collections.Counter()
    children = collections.defaultdict(set)
    rows = []
    for p in paths:
        if not os.path.exists(p):
            continue
        for line in open(p, encoding="utf-8"):
            if line.strip():
                rows.append(json.loads(line))
    # pass one: who is a map
    for row in rows:
        stack = [("", row, 0)]
        while stack:
            prefix, obj, depth = stack.pop()
            if not isinstance(obj, dict) or depth > max_depth:
                continue
            for k, v in obj.items():
                name = "%s.%s" % (prefix, k) if prefix else k
                if prefix:
                    children[prefix].add(k)
                if isinstance(v, dict) and depth < max_depth:
                    stack.append((name, v, depth + 1))
    maps = {p_ for p_, kids in children.items()
            if kids and sum(1 for k in kids if not k.isidentifier()) * 2 > len(kids)}
    # pass two: count, not descending into a value-keyed map
    for row in rows:
        stack = [("", row, 0)]
        while stack:
            prefix, obj, depth = stack.pop()
            if not isinstance(obj, dict) or depth > max_depth:
                continue
            for k, v in obj.items():
                name = "%s.%s" % (prefix, k) if prefix else k
                counts[name] += 1
                if isinstance(v, dict) and depth < max_depth and name not in maps:
                    stack.append((name, v, depth + 1))
    return counts, maps


def leaf_collisions(counts):
    """(shared_leaves, fields_on_a_shared_leaf) - the size of the bound `classify` carries.

    THE THIRD WAY THIS CENSUS IS BOUNDED BY ITS OWN PROCESS, AND IT WAS NEVER SIZED
    -------------------------------------------------------------------------------
    `classify` matches a field by its LEAF name. `masking.secret_literals.note` and
    `ioc.note` are one question to it, and so are `origin.path` and
    `masking.measured_with.path`. So "read by shard-gate.py" does not mean this field has a
    reader - it means some tracked module mentions this STRING somewhere.

    The docstring states `written` is an over-count because a name in a write position might
    belong to another dictionary. That is this property, stated for the shallowest case and
    never sized. Measured over both halves: **37 leaf names are shared by more than one
    dotted field, 118 of 316 fields sit on one, and 113 of the 262 non-orphan
    classifications - 43% - rest on a leaf they share with at least one other field.** The
    worst is `note`, one leaf across thirteen fields.

    It bit this round in the other direction and was caught by measuring rather than by
    luck: the adjudication lifted out of `encoded_layer_finding` was going to be called
    `masking.adjudication`, and a reader of `adjudication` would have reclassified
    `sensitivity_review.adjudication` - 68 rows, a real orphan - as read-only. It is called
    `masking.human_adjudication` for that reason and no other.

    Not repaired here. Matching on the dotted path instead is not a one-line change: the
    tools genuinely index by leaf (`m["provenance"]`, `f.get("payload_size")`), so a path
    match would report almost everything as an orphan and the census would be useless in the
    other direction. What is owed is the number, printed every run, so that a round claiming
    N orphans resolved says how many of them could be somebody else's reader.
    """
    leaves = collections.defaultdict(list)
    for field in counts:
        leaves[field.rsplit(".", 1)[-1]].append(field)
    shared = {k: v for k, v in leaves.items() if len(v) > 1}
    return shared, sum(len(v) for v in shared.values())


def classify(counts, writes, reads, shared=None):
    """[(field, rows, state, detail)] - state is 'written', 'read-only' or 'ORPHAN'.

    THE SHARED LEAF IS MARKED ON THE VERDICT, NOT ONLY IN A FOOTNOTE
    ------------------------------------------------------------------
    43% of non-orphan classifications rest on a leaf shared with another field, and that
    figure used to appear once in the header - so a reader looking at any single `written`
    row could not tell whether it was one of the 43%. It is now on the row.

    **The bound is one-directional, and saying so is the point.** Matching by leaf can only
    ADD matches: a module that names `basis` might mean any of the three fields on that
    leaf. So

      * a `written` or `read-only` verdict on a shared leaf is WEAKER than the same verdict
        on its own leaf - the module may be naming a different field entirely;
      * an `ORPHAN` verdict is UNAFFECTED by sharing. A leaf no module names at all is named
        for none of the fields on it, however many there are, so sharing cannot manufacture
        a false orphan.

    That asymmetry is why the marker is only printed where it can change the reading, and
    why the triage in `KNOWN` can confirm an orphan on a shared leaf at full confidence
    while a non-orphan on one is explicitly flagged as resting on less.
    """
    shared = shared if shared is not None else leaf_collisions(counts)[0]
    out = []
    for field, n in counts.most_common():
        leaf = field.rsplit(".", 1)[-1]
        if writes.get(leaf):
            state, detail = "written", ", ".join(sorted(writes[leaf])[:3])
        elif reads.get(leaf):
            state, detail = "read-only", "read by %s" % ", ".join(sorted(reads[leaf])[:3])
        else:
            state, detail = "ORPHAN", "no tracked module in corpus/ mentions it"
        others = [f for f in shared.get(leaf, ()) if f != field]
        if others and state != "ORPHAN":
            detail += ("  [leaf `%s` is shared with %s: this verdict may be about %s]"
                       % (leaf, ", ".join(sorted(others)[:3]),
                          "one of them" if len(others) > 1 else "that field"))
        if leaf in KNOWN:
            detail += "  [known: %s]" % KNOWN[leaf]
        out.append((field, n, state, detail))
    return out


def report_removed():
    for title, table in (("fields REMOVED from the index, not merely absent", REMOVED),
                         ("fields that MOVED, so neither name is new", MOVED)):
        if not table:
            continue
        print()
        print("=== %s ===" % title)
        for f, why in sorted(table.items()):
            print("  %s" % f)
            for line in _wrap(why, 88):
                print("      %s" % line)


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line); line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", action="append", default=[])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    paths = a.index or [os.path.join(HERE, "index.jsonl"),
                        os.path.join(HERE, "local", "index-local.jsonl")]
    writes, reads = scan_modules()
    counts, maps = field_census(paths)
    rows = classify(counts, writes, reads)
    tally = collections.Counter(s for _f, _n, s, _d in rows)

    if a.json:
        print(json.dumps({"fields": [{"field": f, "rows": n, "state": s, "detail": d}
                                     for f, n, s, d in rows],
                          "tally": dict(tally)}, indent=1))
        return 0

    print("index halves read      : %s" % ", ".join(os.path.basename(p) for p in paths))
    print("tracked modules parsed : %d   (of which any field name appears in: %d)"
          % (len(PARSED), len({m for v in writes.values() for m in v}
                              | {m for v in reads.values() for m in v})))
    print("fields carried by rows : %d   (value-keyed maps not descended: %d)"
          % (len(rows), len(maps)))
    print("  written by a tracked module : %d" % tally["written"])
    print("  only READ by tracked modules: %d" % tally["read-only"])
    print("  mentioned nowhere (ORPHAN)  : %d" % tally["ORPHAN"])
    shared, on_shared = leaf_collisions(counts)
    inherited = sum(1 for f, _n, s, _d in rows
                    if s != "ORPHAN" and len(shared.get(f.rsplit(".", 1)[-1], ())) > 1)
    not_orphan = tally["written"] + tally["read-only"]
    print("  classified on a leaf shared with another field: %d of %d (%.0f%%)"
          % (inherited, not_orphan, 100.0 * inherited / max(not_orphan, 1)))
    print()
    print("`written` is an over-count and `ORPHAN` is therefore an under-count: every field")
    print("below is really unaccounted for, and there may be more this cannot see. The field")
    print("list is enumerated FROM THE ROWS, so a field every row has lost is invisible.")
    print()
    print("And a field is matched by its LEAF name, so %d leaves are shared by more than one"
          % len(shared))
    print("field (%d fields sit on one; the worst is `%s`, across %d). A `read by` on any of"
          % (on_shared, max(shared, key=lambda k: len(shared[k])) if shared else "-",
             max((len(v) for v in shared.values()), default=0)))
    print("those means a module mentions the STRING, not necessarily this field. §11's")
    print("eleventh instance; the line above is the size of it.")
    print()
    for f, n, s, d in rows:
        if s == "written":
            continue
        print("  %-11s %-42s %7d rows   %s" % (s, f, n, d))
    report_removed()
    return 0


def inject():
    """Positive control: each of the three states, and the read/write distinction itself.

    The load-bearing case is the last one. A grep-based census reports a field covered
    because some module contains its name, which is exactly how `not_applicable_reason`
    stayed open while `mask-samples.py` mentioned it on line 393 - so a control that only
    proved `written` and `ORPHAN` would pass on the tool this replaces.
    """
    import shutil, tempfile
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-64s %-22s %s" % (label, str(got)[:22],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    tmp = tempfile.mkdtemp(prefix="field-prov-inject.")
    try:
        with open(os.path.join(tmp, "writer.py"), "w", encoding="utf-8") as fh:
            fh.write("def f(r, d):\n"
                     "    r['written_by_subscript'] = 1\n"
                     "    d.setdefault('written_by_setdefault', 2)\n"
                     "    r.pop('written_by_pop', None)\n"
                     "    return {'written_in_a_dict_literal': 3}\n")
        with open(os.path.join(tmp, "viaconst.py"), "w", encoding="utf-8") as fh:
            fh.write("KEY = 'written_through_a_constant'\n"
                     "def h(r):\n"
                     "    r[KEY] = 1\n")
        with open(os.path.join(tmp, "reader.py"), "w", encoding="utf-8") as fh:
            fh.write("def g(r):\n"
                     "    if r.get('read_by_get'):\n"
                     "        return r['read_by_subscript']\n"
                     "    return 'read_by_in' in r\n")
        w, r = scan_modules(tmp)

        print("=== a write position must be seen as a write ===")
        for k in ("written_by_subscript", "written_by_setdefault", "written_by_pop",
                  "written_in_a_dict_literal"):
            case(k, sorted(w.get(k, ())), ["writer.py"])
        # The idiom every record-writing tool here uses. Without this the tools report
        # their own fields as orphans.
        case("written_through_a_constant",
             sorted(w.get("written_through_a_constant", ())), ["viaconst.py"])

        print()
        print("=== a read position must NOT be ===")
        for k in ("read_by_get", "read_by_subscript", "read_by_in"):
            case("%s is not counted as written" % k, sorted(w.get(k, ())), [])
            case("%s is counted as read" % k, sorted(r.get(k, ())), ["reader.py"])

        print()
        print("=== and the three states must each be reachable ===")
        idx = os.path.join(tmp, "probe.jsonl")
        with open(idx, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"written_by_subscript": 1, "read_by_get": 2,
                                 "nothing_mentions_this": 3,
                                 "masking": {"read_by_subscript": 4}}) + "\n")
        counts, _maps = field_census([idx])
        got = {f: s for f, _n, s, _d in classify(counts, w, r)}
        case("a field a module writes", got.get("written_by_subscript"), "written")
        case("a field a module only reads", got.get("read_by_get"), "read-only")
        case("a field nothing mentions", got.get("nothing_mentions_this"), "ORPHAN")
        case("a nested field is reached by its leaf name",
             got.get("masking.read_by_subscript"), "read-only")

        print()
        print("=== a value-keyed map must not become one field per value ===")
        # The map fixture carries DATA LABELS, the way every real one in this corpus does
        # ("live webroot: other", "hex-digest:not-a-tagged-secret"). It used to carry
        # `value_0 … value_11`, which are identifiers, and so modelled a map that does not
        # exist here while missing the property that separates the two.
        idx2 = os.path.join(tmp, "maps.jsonl")
        with open(idx2, "w", encoding="utf-8") as fh:
            for i in range(12):
                fh.write(json.dumps({"counter": {"a label: with punctuation %d" % i: 1},
                                     "schema": {"a": 1, "b": 2}}) + "\n")
        c2, maps = field_census([idx2])
        case("the map itself is censused", "counter" in c2, True)
        case("its value keys are not", [f for f in c2 if f.startswith("counter.")], [])
        case("and it is reported as a map", sorted(maps), ["counter"])
        case("a small schema block is still descended into",
             sorted(f for f in c2 if f.startswith("schema.")), ["schema.a", "schema.b"])

        # The direction that was broken: a schema block with MORE children than the old
        # count threshold. Nine such blocks were classified as maps and never descended
        # into, `masking` among them.
        idx3 = os.path.join(tmp, "wide-schema.jsonl")
        wide = {"masking": {"k%02d" % i: 1 for i in range(26)}}
        with open(idx3, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(wide) + "\n")
        c3, maps3 = field_census([idx3])
        case("a 26-key block of identifiers is NOT a map", sorted(maps3), [])
        case("  and every one of its children is censused",
             len([f for f in c3 if f.startswith("masking.")]), 26)

        # And a small map must still be caught, which the count threshold could not do:
        # three value keys under a four-child parent were reported as orphan FIELDS.
        idx4 = os.path.join(tmp, "small-map.jsonl")
        with open(idx4, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"adjudication": {"pii dropped": 1, "identity->c2": 2,
                                                  "identity dropped": 1, "note": "x"}}) + "\n")
        c4, maps4 = field_census([idx4])
        case("a four-child parent of data labels is still a map", sorted(maps4),
             ["adjudication"])
        case("  so its value keys are not censused as fields",
             [f for f in c4 if f.startswith("adjudication.")], [])

        print()
        print("=== a control fixture is not a writer, and a control READER still is ===")
        # The same defect as the KNOWN/REMOVED tables below, one module along: every tool
        # here carries an `inject()` and a control fixture is a dict literal. Measured over
        # both halves, NINE fields carried by rows had no write position anywhere outside a
        # control suite - `account_hash` on 67,985 rows and `origin.account_hash` on 47,133
        # among them - and all nine were being reported as covered.
        #
        # Both directions. Without the negative half the rule could simply be "ignore these
        # functions entirely", which would throw away real read coverage: eight of those
        # nine turned out to have a genuine tracked READER, and only `deobfuscation.status`
        # (645 rows) was a true orphan the census had been hiding.
        with open(os.path.join(tmp, "controlled.py"), "w", encoding="utf-8") as fh:
            fh.write("def build(r):\n"
                     "    r['written_for_real'] = 1\n"
                     "def inject():\n"
                     "    row = {'written_only_in_a_fixture': 1}\n"
                     "    return row.get('read_only_in_a_fixture')\n"
                     "def _selftest():\n"
                     "    return {'written_only_in_a_selftest': 2}\n")
        wc, rc = scan_modules(tmp)
        case("a field written in build() is written",
             sorted(wc.get("written_for_real", ())), ["controlled.py"])
        case("a field written only inside inject() is NOT",
             wc.get("written_only_in_a_fixture"), None)
        case("nor one written only inside _selftest()",
             wc.get("written_only_in_a_selftest"), None)
        case("but a field READ inside a control is still read",
             sorted(rc.get("read_only_in_a_fixture", ())), ["controlled.py"])
        # And on the real tree, which is where the nine were found.
        rw0, _rr0 = scan_modules(HERE)
        case("account_hash has no real write position in corpus/",
             rw0.get("account_hash"), None)
        case("deobfuscation.status's leaf has none either",
             rw0.get("status"), None)

        print()
        print("=== the case this tool exists for: the real not_applicable_reason ===")
        rw, rr = scan_modules(HERE)
        case("mask-samples.py mentions it", "mask-samples.py" in rr.get(
            "not_applicable_reason", set()) | rw.get("not_applicable_reason", set()), True)
        case("and a grep would therefore have called it covered",
             bool(rr.get("not_applicable_reason")), True)

        print()
        print("=== the census must not count its own bookkeeping tables as writers ===")
        # KNOWN and REMOVED are dict literals keyed by field name. Before this was fixed,
        # three fields KNOWN recorded as orphans - evidence_decoded, evidence_encoded,
        # hidden_by_encoding - were classified `written` by this file and then not printed,
        # because main() prints only the states that are not `written`. The note saying
        # nobody writes them was what stopped them being reported.
        case("this file is not among the modules scanned",
             SELF in {m for v in rw.values() for m in v} |
                     {m for v in rr.values() for m in v}, False)
        for f in ("evidence_decoded", "evidence_encoded", "hidden_by_encoding"):
            case("  %s has no writer once KNOWN is excluded" % f, rw.get(f), None)
        case("a field KNOWN records is still classified ORPHAN, with its note",
             [st for fld, _n, st, _d in classify(collections.Counter(
                 {"hidden_by_encoding": 1}), rw, rr) if fld == "hidden_by_encoding"],
             ["ORPHAN"])
        case("  and the note is still attached",
             "known:" in classify(collections.Counter({"hidden_by_encoding": 1}),
                                  rw, rr)[0][3], True)
        # The other direction: excluding this file must not hide a REAL writer.
        case("a field a real module writes is still written",
             classify(collections.Counter({"sensitivity": 1}), rw, rr)[0][2], "written")

        print()
        print("=== a field is matched by its LEAF, and the size of that is now printed ===")
        # §11's eleventh. Both directions: a sizing that reported every field as colliding
        # and one that reported none would look identical from a green run.
        toy = collections.Counter({"a.note": 1, "b.note": 1, "c.unique": 1})
        sh, on = leaf_collisions(toy)
        case("two fields sharing a leaf are counted as sharing it", sorted(sh), ["note"])

        print()
        print("=== a field named in a declared table is read, and the tie is to the AST ===")
        _msm = os.path.join(HERE, "make-shard-manifest.py")
        _tables = named_field_tables(_msm, FIELD_NAME_TABLES["make-shard-manifest.py"])
        case("INDEX_OWNED was found in make-shard-manifest.py's AST",
             "INDEX_OWNED" in _tables, True)
        case("and campaign_marker is in it",
             "campaign_marker" in _tables.get("INDEX_OWNED", []), True)
        case("so it classifies as read, not orphan",
             classify(collections.Counter({"campaign_marker": 1}), *scan_modules())[0][2],
             "read-only")
        # The extractor must report ABSENCE rather than an empty list, or the tie above
        # passes by being blind the day the constant is renamed or reshaped.
        _fd, _tmp = tempfile.mkstemp(suffix=".py")
        with os.fdopen(_fd, "w") as fh:
            fh.write("INDEX_OWNED = tuple(x for x in ())\n")
        case("a constant that is no longer a flat tuple is absent, not empty",
             named_field_tables(_tmp, ("INDEX_OWNED",)), {})
        with open(_tmp, "w") as fh:
            fh.write('OTHER = ("a", "b")\n')
        case("and a table this does not ask for is not read",
             named_field_tables(_tmp, ("INDEX_OWNED",)), {})
        with open(_tmp, "w") as fh:
            fh.write('INDEX_OWNED = ("a", "b")\n')
        case("a real one is read", named_field_tables(_tmp, ("INDEX_OWNED",)),
             {"INDEX_OWNED": ["a", "b"]})
        os.unlink(_tmp)

    # THE MARKER, IN BOTH DIRECTIONS AND IN BOTH STATES.
        #
        # It has to appear where the verdict could be about another field, and it has to STAY
        # AWAY from an orphan, where sharing changes nothing - a marker on every row would say
        # no more than the footnote it replaced.
        _counts = collections.Counter({"a.note": 3, "b.note": 2, "c.own": 1, "d.note": 1})
        _shared = leaf_collisions(_counts)[0]
        _rows = {f: d for f, _n, _s, d in
                 classify(_counts, {"note": {"m.py"}}, {}, shared=_shared)}
        case("a written verdict on a shared leaf says so",
             "leaf `note` is shared with" in _rows["a.note"], True)
        case("and names the other fields it might be about",
             "b.note" in _rows["a.note"] and "d.note" in _rows["a.note"], True)
        _own = {f: d for f, _n, _s, d in
                classify(_counts, {"own": {"m.py"}}, {}, shared=_shared)}
        case("a written verdict on its OWN leaf does not", "is shared with" in _own["c.own"],
             False)
        _orph = {f: (s, d) for f, _n, s, d in classify(_counts, {}, {}, shared=_shared)}
        case("an orphan on a shared leaf is still an orphan", _orph["a.note"][0], "ORPHAN")
        case("and carries no sharing caveat, because sharing cannot make a false orphan",
             "is shared with" in _orph["a.note"][1], False)
        case("and both are counted, not one", on, 2)
        case("a leaf nothing else uses is not counted",
             "unique" in sh, False)
        case("a census with no collisions at all reports none",
             leaf_collisions(collections.Counter({"x.a": 1, "y.b": 1})), ({}, 0))
        # The live sizing, and the specific thing it guarded this round: the lifted
        # adjudication is `human_adjudication` because a reader of `adjudication` would have
        # claimed `sensitivity_review.adjudication`, which is a real orphan on 68 rows.
        live, _m = field_census(
            [os.path.join(HERE, "index.jsonl"),
             os.path.join(HERE, "local", "index-local.jsonl")])
        lsh, lon = leaf_collisions(live)
        print("  leaves shared by more than one field : %d  (%d fields sit on one)"
              % (len(lsh), lon))
        case("the leaf chosen this round is carried by exactly one field",
             sorted(f for f in live if f.rsplit(".", 1)[-1] == "human_adjudication"),
             ["masking.human_adjudication"])
        # The name NOT chosen. `adjudication` is carried today by one field, a real orphan;
        # a second field with that leaf makes it shared, and a reader of either would then
        # cover both. This is the case measured before the name was picked.
        would = collections.Counter(live)
        would["masking.adjudication"] = 2
        case("the name NOT chosen would have shared a leaf with a real orphan",
             sorted(leaf_collisions(would)[0].get("adjudication", ())),
             ["masking.adjudication", "sensitivity_review.adjudication"])
        case("and `sensitivity_review.adjudication` is still an orphan today",
             [st for fld, _n, st, _d in classify(collections.Counter(
                 {"sensitivity_review.adjudication": 68}), rw, rr)], ["ORPHAN"])
        # Every field this round moved out of ORPHAN must be on a leaf of its own, or the
        # resolution is somebody else's reader being counted as this field's.
        resolved = ("fixture_sha256", "fixture_size", "payload_sha256", "payload_size",
                    "ioc", "c2_fallback_ip", "campaign_hosts",
                    "classification", "value", "why_it_matters")
        case("every orphan resolved this round sits on a leaf of its own",
             sorted(k for k in resolved if k in lsh), [])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
