#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Remove a dead field from an index half, and refuse to do it blind.

WHY A TOOL AND NOT A ONE-LINER
-------------------------------
Removing a field from 47,133 rows is three lines of Python, and that is exactly the problem.
Every orphan field this corpus has found was written by a script somebody ran once and never
committed: `not_applicable_reason` by an uncommitted state of `mask-samples.py`, `sensitivity`
by an untracked file under `trail-data`, the decoded-form tags by a second untracked decoder,
`origin.incident` and `placements` by an untracked merge pass. A round that removes an orphan
with an untracked one-liner has done the same thing again in the other direction, and the
next census cannot tell that the field was deleted on purpose from the fact that it was never
there. So the deletion is a tracked act with an author, a recorded reason, and a control.

WHAT IT REFUSES
---------------
  * a field any tracked module in `corpus/` writes or reads. `field-provenance.py` already
    owns the question of who touches a field; asking it here rather than restating the
    answer means the guard cannot drift from the census that justified the removal.
  * `publishable`, and anything under `masking`. The first is computed by `shard-gate.py`
    alone (4.4); the second is the record a clearance is keyed to, and dropping a key out
    of it would silently invalidate a human decision.
  * a run that would change the row count, or any field other than the one named. Both are
    asserted after the edit and before the write rather than trusted.
  * `--apply` without an author, and a field that is not on a single row - the second
    because a no-op deletion reported as a success is how a typo becomes "done".

WHAT IT WRITES
--------------
Only the removal. It does NOT record a tombstone on the rows: a per-row note that a field
used to exist is the same volume of dead weight the removal is clearing. The record of the
deletion belongs in corpus/CHANGELOG.md and in `field-provenance.KNOWN`, where a reader looks.

    corpus/drop-field.py --index corpus/local/index-local.jsonl --field origin.incident
    corpus/drop-field.py --index ... --field origin.incident --by cl --apply
    corpus/drop-field.py --inject
"""
import argparse, copy, importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy   # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "field_provenance_drop", os.path.join(HERE, "field-provenance.py"))
FP = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(FP)

# Never removable, whatever the census says. `masking` because a clearance is keyed to the
# finding recorded inside it; `publishable` and its blockers because shard-gate computes
# them and this tool must never be the thing that moved one.
PROTECTED = ("publishable", "publish_blocker", "publish_blockers", "sha256", "masking")


def resolve(row, dotted):
    """(parent dict, leaf) for a dotted path, or (None, leaf) where the path is not there."""
    parts = dotted.split(".")
    obj = row
    for p in parts[:-1]:
        if not isinstance(obj, dict) or p not in obj:
            return None, parts[-1]
        obj = obj[p]
    return (obj if isinstance(obj, dict) else None), parts[-1]


def carrying(rows, dotted):
    n = 0
    for r in rows:
        parent, leaf = resolve(r, dotted)
        if parent is not None and leaf in parent:
            n += 1
    return n


def guard(dotted):
    """None, or why this field must not be dropped."""
    parts = dotted.split(".")
    if parts[0] in PROTECTED or dotted in PROTECTED:
        return "%s is protected: it is computed or it is what a clearance is keyed to" % parts[0]
    writes, reads = FP.scan_modules()
    leaf = parts[-1]
    if writes.get(leaf):
        return ("a tracked module writes %r (%s); a field with a writer is not dead"
                % (leaf, ", ".join(sorted(writes[leaf])[:3])))
    if reads.get(leaf):
        return ("a tracked module reads %r (%s); removing it would break that reader"
                % (leaf, ", ".join(sorted(reads[leaf])[:3])))
    return None


def drop(rows, dotted):
    """(new_rows, removed) - `rows` is not mutated."""
    out, removed = [], 0
    for r in rows:
        parent, leaf = resolve(r, dotted)
        if parent is None or leaf not in parent:
            out.append(r)
            continue
        r2 = copy.deepcopy(r)
        p2, _l = resolve(r2, dotted)
        del p2[leaf]
        out.append(r2)
        removed += 1
    return out, removed


def assert_scoped(before, after, dotted):
    """None, or what changed that should not have.

    Compared by serialising each row with the named field stripped from BOTH sides: if
    anything else moved, the two strings differ. Cheaper to read than a recursive diff and
    it cannot miss a nested change the way a key-by-key top-level comparison can.
    """
    if len(before) != len(after):
        return "row count moved %d -> %d" % (len(before), len(after))
    for b, a in zip(before, after):
        if b.get("sha256") != a.get("sha256"):
            return "row order moved at %s" % (b.get("sha256", "?")[:12])
        bs, _n = drop([b], dotted)
        as_, _n = drop([a], dotted)
        if json.dumps(bs[0], sort_keys=True) != json.dumps(as_[0], sort_keys=True):
            return "%s changed something other than %s" % (b["sha256"][:12], dotted)
        pa, leaf = resolve(a, dotted)
        if pa is not None and leaf in pa:
            return "%s still carries %s" % (a["sha256"][:12], dotted)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", action="append", default=[])
    ap.add_argument("--field", help="dotted path, e.g. origin.incident")
    ap.add_argument("--by", help="who is removing it")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    if not a.field:
        return ap.error("--field is required unless --inject")
    indexes = a.index or [os.path.join(HERE, "index.jsonl"),
                          os.path.join(HERE, "local", "index-local.jsonl")]

    why = guard(a.field)
    if why:
        print("REFUSED: %s" % why)
        return 1

    total = 0
    for idx in indexes:
        if not os.path.exists(idx):
            continue
        rows = read_jsonl(idx)
        n = carrying(rows, a.field)
        total += n
        print("%-44s %6d of %6d row(s) carry %s"
              % (os.path.basename(idx), n, len(rows), a.field))
    if not total:
        print("REFUSED: no row carries %r; a deletion that removes nothing must not "
              "report success" % a.field)
        return 1
    if not a.apply:
        print()
        print("dry run: nothing written. Re-run with --by <who> --apply.")
        return 0
    if not a.by:
        return ap.error("--by is required to write")

    for idx in indexes:
        if not os.path.exists(idx):
            continue
        with index_lock(idx):
            rows = read_jsonl(idx)                    # re-read INSIDE the lock
            after, removed = drop(rows, a.field)
            if not removed:
                print("%s: nothing to remove on re-read" % os.path.basename(idx))
                continue
            bad = assert_scoped(rows, after, a.field)
            if bad:
                sys.exit("refusing to write %s: %s" % (idx, bad))
            write_jsonl_atomic(idx, after)
            print("%-44s removed from %d row(s)" % (os.path.basename(idx), removed))
    print()
    print("removed by %s. Record it in corpus/CHANGELOG.md and field-provenance.KNOWN, which is"
          % a.by)
    print("where the next census looks. Then re-run corpus/make-summary.py.")
    return 0


# ---------------------------------------------------------------------------------------
# Controls. The refusals are the point of the tool, so they are what is asserted.
# ---------------------------------------------------------------------------------------

def inject():
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-64s %-24s %s" % (label, str(got)[:24],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    # The fixture field is deliberately NOT a name any real row uses. The first draft of
    # this control used `origin.incident` - the field it was written to remove - and
    # `field-provenance` promptly reported that field as WRITTEN, by this file, because a
    # dict-literal key in a test fixture is a write position like any other. The control
    # poisoned the census its own guard consults. That is the module-side §11 bound in the
    # field-provenance docstring arriving in practice within one round of being written
    # down, and the fix is that a fixture must never spell a field the corpus really has.
    GHOST = "ghost_field_no_row_carries"
    rows = [{"sha256": "a" * 64, "origin": {GHOST: "X", "path": "/p", "mode": "0o444"},
             "publishable": False, "count": 2},
            {"sha256": "b" * 64, "origin": {"path": "/q"}, "publishable": True, "count": 1},
            {"sha256": "c" * 64, "publishable": True}]

    print("=== it must REFUSE these ===")
    case("a field shard-gate computes", guard("publishable") is not None, True)
    case("anything under masking, which a clearance is keyed to",
         guard("masking.secret_gate") is not None, True)
    case("a field a tracked module writes", guard("sensitivity") is not None, True)
    case("a field a tracked module only reads", guard("fixture") is not None, True)

    print("=== it must ALLOW a genuine orphan ===")
    case("a dotted field no tracked module mentions", guard("origin." + GHOST), None)

    print("=== the removal itself ===")
    after, removed = drop(rows, "origin." + GHOST)
    case("removed from exactly the rows that carried it", removed, 1)
    case("  and the row that lacked it is untouched",
         after[1]["origin"], {"path": "/q"})
    case("  and a row with no origin at all is untouched", "origin" in after[2], False)
    case("  and the parent dict survives with its other keys",
         sorted(after[0]["origin"]), ["mode", "path"])
    case("  and the input rows were not mutated", GHOST in rows[0]["origin"], True)
    case("  and nothing else moved", assert_scoped(rows, after, "origin." + GHOST), None)
    case("row count is unchanged", len(after), len(rows))
    case("publishable was not touched",
         [r.get("publishable") for r in after], [False, True, True])

    print("=== the scope assertion must be able to say no ===")
    tampered = copy.deepcopy(after)
    tampered[0]["publishable"] = True
    case("a publishable flipped alongside the removal is caught",
         assert_scoped(rows, tampered, "origin." + GHOST) is not None, True)
    left = copy.deepcopy(rows)
    case("a removal that did not happen is caught",
         assert_scoped(rows, left, "origin." + GHOST) is not None, True)
    short = copy.deepcopy(after)[:-1]
    case("a row that vanished is caught",
         assert_scoped(rows, short, "origin." + GHOST) is not None, True)
    reordered = [after[1], after[0], after[2]]
    case("a row order that moved is caught",
         assert_scoped(rows, reordered, "origin." + GHOST) is not None, True)

    print("=== counting ===")
    case("carrying() counts only rows that really have it",
         carrying(rows, "origin." + GHOST), 1)
    case("  and is zero for a field nobody has",
         carrying(rows, "origin.nonesuch"), 0)

    print()
    print("%d control(s) run, %d failed" % (len(ran), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LockBusy as exc:
        sys.exit(str(exc))
