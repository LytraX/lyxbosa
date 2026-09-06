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
import argparse, ast, collections, json, os, sys

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


def key_positions(path):
    """({written}, {read}) - the string constants this module writes and reads as keys.

    A module-level `NAME = "literal"` is resolved, because the tools here write through
    exactly that idiom - `RECORD_KEY = "sensitivity_adopted"`, then `after[RECORD_KEY] = …`.
    Without it `adopt-decoded-tags.py` and `tag-sensitivity.py` both report their own record
    field as an orphan, which is a false finding in the direction that wastes a round.
    """
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    written, read = set(), set()

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

    for node in ast.walk(tree):
        # r["k"] = v  /  del r["k"]
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.Delete)):
            targets = node.targets if hasattr(node, "targets") else [node.target]
            for t in targets:
                if isinstance(t, ast.Subscript):
                    k = const(t.slice)
                    if k:
                        written.add(k)
        # {"k": v}
        elif isinstance(node, ast.Dict):
            for k in node.keys:
                s = const(k)
                if s:
                    written.add(s)
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else None
            if name in ("setdefault", "pop") and node.args:
                s = const(node.args[0])
                if s:
                    written.add(s)
            elif name == "get" and node.args:
                s = const(node.args[0])
                if s:
                    read.add(s)
            elif name == "dict":
                for kw in node.keywords:
                    if kw.arg:
                        written.add(kw.arg)
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


def scan_modules(root=HERE):
    """(writes, reads) over every tracked python module in `corpus/`, except this one."""
    writes, reads = collections.defaultdict(set), collections.defaultdict(set)
    for fn in sorted(os.listdir(root)):
        if not fn.endswith(".py") or fn == SELF:
            continue
        try:
            w, r = key_positions(os.path.join(root, fn))
        except SyntaxError:                                          # pragma: no cover
            continue
        for k in w:
            writes[k].add(fn)
        for k in r:
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


def classify(counts, writes, reads):
    """[(field, rows, state, detail)] - state is 'written', 'read-only' or 'ORPHAN'."""
    out = []
    for field, n in counts.most_common():
        leaf = field.rsplit(".", 1)[-1]
        if writes.get(leaf):
            state, detail = "written", ", ".join(sorted(writes[leaf])[:3])
        elif reads.get(leaf):
            state, detail = "read-only", "read by %s" % ", ".join(sorted(reads[leaf])[:3])
        else:
            state, detail = "ORPHAN", "no tracked module in corpus/ mentions it"
        if leaf in KNOWN:
            detail += "  [known: %s]" % KNOWN[leaf]
        out.append((field, n, state, detail))
    return out


def report_removed():
    if not REMOVED:
        return
    print()
    print("=== fields REMOVED from the index, not merely absent ===")
    for f, why in sorted(REMOVED.items()):
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
    print("tracked modules parsed : %d" % len({m for v in writes.values() for m in v}))
    print("fields carried by rows : %d   (value-keyed maps not descended: %d)"
          % (len(rows), len(maps)))
    print("  written by a tracked module : %d" % tally["written"])
    print("  only READ by tracked modules: %d" % tally["read-only"])
    print("  mentioned nowhere (ORPHAN)  : %d" % tally["ORPHAN"])
    print()
    print("`written` is an over-count and `ORPHAN` is therefore an under-count: every field")
    print("below is really unaccounted for, and there may be more this cannot see. The field")
    print("list is enumerated FROM THE ROWS, so a field every row has lost is invisible.")
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
