#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Move a human adjudication out of the gate-evidence key it is squatting in.

WHAT IS WRONG, MEASURED RATHER THAN DESCRIBED
----------------------------------------------
Two published rows - `9437f7423b83` and `9bbe4a34dc6b`, the polyglot siblings of §5.4 -
record this under `masking.encoded_layer_finding`:

    classification / decision / resolution / value / why_it_matters

Not one of those is a key the encoded-layer gate produces. `verify-content-mask._profile`
emits counts, lengths, positions and segment sizes; the gate writes a finding only where it
FAILS, and both rows record `encoded_layer_gate: PASS`. Run today against both maps - 288
identifiers, 64 keep tokens - over the exact fixture bytes the shard ships, both gates pass
and the tools emit **no `encoded_layer_finding` at all**. So the block is not a stale
finding, a superseded schema or a partial record. It is a human adjudication wearing the
name of a gate's evidence.

THAT NAME IS LOAD-BEARING, WHICH IS WHY THIS IS A REPAIR AND NOT A TIDY-UP
---------------------------------------------------------------------------
`clearance.finding_digest` is taken over `clearance.evidence_for`, and
`encoded_layer_finding` is exactly what that returns for `encoded_layer_gate`. So on these
two rows the digest for the encoded-layer gate is computed **over prose and an address**:
rewording the argument moves the digest, and a clearance keyed to it would go inert for a
reason having nothing to do with the gate. Nothing keys to it today - checked, not assumed:
every clearance object on this machine is enumerated in the report - but "nothing has
happened yet" is not a property, it is a delay.

The second consequence is already live. `gate_evidence.compare_gate` compares the recorded
evidence against what the tools produce now, and the tools produce none, so both rows read
`evidence-moved` today - which means `verify-and-stamp.py` will not re-stamp them and
`remeasure-gates.py` refuses them outright under its human-decision rule. Both rows are
unrepairable by either tool while the block sits there. After the move both read `agrees`.

WHAT THIS MAY MOVE, AND WHAT IT REFUSES
----------------------------------------
An allow-list, not a heuristic. The block moved must carry `decision` and nothing outside
`{classification, decision, resolution, value, why_it_matters}`. A single profile key -
`occurrences`, `identifier_lengths`, `false_positive_note` - and it is refused whole,
because a block that is part finding and part judgement is a different defect with a
different repair, and moving it would delete real gate evidence.

Refused as well:

  * a gate the row does not record, or records as anything other than a pass. A FAIL's
    finding IS evidence; only a passing gate can legitimately record none.
  * a row already carrying `masking.human_adjudication`. Two adjudications in one slot is a
    merge, and a merge is a human's to write.
  * a `decision` with no `resolution`. `shard-gate`'s question five blocks that row, and
    moving it would move the blocker to a new key rather than answering it.

WHY `human_adjudication` AND NOT `adjudication`
------------------------------------------------
`field-provenance.classify` matches a field by its LEAF name, so a tracked reader of
`adjudication` would silently reclassify `sensitivity_review.adjudication` - 68 rows, a
value-keyed map, a genuine orphan - as read-only. Resolving one orphan by accidentally
claiming another is the census defect this repository has already recorded twice. No row
carries the leaf `human_adjudication`.

ONE KEY IS ADDED, AND IT IS NOT PART OF THE MOVE
-------------------------------------------------
`about`, naming the gate the adjudication was about. The old key said that structurally - an
adjudication under `encoded_layer_finding` is about the encoded layer - and a pure move
would throw it away. It is recorded rather than inferred, and `shard-gate.adjudication
Violations` asserts it names a gate the row actually records.

    corpus/lift-adjudication.py --index corpus/index.jsonl --by cl
    corpus/lift-adjudication.py --index corpus/index.jsonl --by cl --apply
    corpus/lift-adjudication.py --inject
"""
import argparse, copy, datetime, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy    # noqa: E402
import clearance                                                            # noqa: E402
import finding_notes                                                        # noqa: E402

# Where the adjudication lands.
TARGET = "human_adjudication"

# The gate name the block is recorded against, added on the move.
ABOUT = "about"

# The complete shape of an adjudication. Nothing outside this may be moved: every other key
# under a finding name belongs to the gate, and this tool must never be able to delete one.
ADJUDICATION_KEYS = frozenset({"classification", "decision", "resolution", "value",
                               "why_it_matters"})

# The key that makes a block a human's rather than a gate's, and the one that says the human
# finished. Same two names `shard-gate` keys its question-five invariant to, restated here
# rather than imported because that module executes an index gate on import.
DECISION = "decision"
RESOLUTION = "resolution"

# Every place a finding is recorded, from the module a clearance is keyed through, so this
# tool and the digest cannot disagree about which keys are gate evidence.
FINDING_KEYS = {k: g for g, keys in clearance.EVIDENCE_KEYS.items() for k in keys}


def _blocks(masking):
    """[(gate, key, container, block)] for every finding key holding a human decision.

    `masking` itself and `masking.gate_categories`, which is the second place this index
    records a finding - the same two places `shard-gate._decision_blocks` looks, and for
    the same reason.
    """
    out = []
    for container, prefix in ((masking, ""), (masking.get("gate_categories"),
                                              "gate_categories.")):
        if not isinstance(container, dict):
            continue
        for key, block in sorted(container.items()):
            if isinstance(block, dict) and DECISION in block and key in FINDING_KEYS:
                out.append((FINDING_KEYS[key], prefix + key, container, block))
    return out


def plan(row):
    """[(gate, from_key, refusal_or_None)] - what this row offers and what would be done.

    A refusal is per block, never per row: a row can hold one movable adjudication and one
    that is refused, and reporting "row refused" would hide which.
    """
    m = row.get("masking") or {}
    out = []
    for gate, key, _container, block in _blocks(m):
        out.append((gate, key, _refuse(row, m, gate, block)))
    return out


def _refuse(row, masking, gate, block):
    extra = sorted(set(block) - ADJUDICATION_KEYS)
    if extra:
        return ("carries %s, which is not adjudication shape. A block that is part gate "
                "finding and part human judgement is a different defect, and moving it "
                "whole would delete evidence." % "/".join(extra))
    if not block.get(RESOLUTION):
        return ("records a %r with no %r. shard-gate blocks that row; moving it would move "
                "the blocker to a new key rather than answer it." % (DECISION, RESOLUTION))
    if gate not in masking:
        return "the row records no %s result, so there is no gate for it to be about" % gate
    verdict = masking.get(gate)
    passed = verdict == "PASS" or (isinstance(verdict, dict)
                                   and verdict.get("result") == "PASS")
    if not passed:
        return ("%s records %r, not a pass. A finding under a non-passing gate is gate "
                "evidence and is not this tool's to move." % (gate, verdict))
    if TARGET in masking:
        return ("the row already carries masking.%s; merging two adjudications is a "
                "human's to write" % TARGET)
    return None


def apply_to(row):
    """(after, moves, refusals). `after` is a new row; the input is never mutated."""
    after = copy.deepcopy(row)
    m = after.get("masking") or {}
    moves, refusals = [], []
    for gate, key, container, block in _blocks(m):
        why = _refuse(after, m, gate, block)
        if why:
            refusals.append((key, why))
            continue
        container.pop(key.rsplit(".", 1)[-1])
        m[TARGET] = dict(block, **{ABOUT: gate})
        moves.append((gate, key))
    return after, moves, refusals


def assert_moved(before, after, moves):
    """None, or what changed that should not have.

    Additive except for the key vacated, and the vacated key is named rather than inferred:
    a check that allowed "some key under masking disappeared" would pass a tool that removed
    the wrong one.
    """
    if not moves:
        return "nothing was moved, so nothing may have changed" if before != after else None
    b, a = copy.deepcopy(before), copy.deepcopy(after)
    bm, am = b.get("masking") or {}, a.get("masking") or {}
    vacated = {k.rsplit(".", 1)[-1] for _g, k in moves}
    for k in vacated:
        for container in (bm, bm.get("gate_categories") or {}):
            container.pop(k, None)
        for container in (am, am.get("gate_categories") or {}):
            container.pop(k, None)
    if am.pop(TARGET, None) is None:
        return "masking.%s was not written" % TARGET
    if bm != am:
        moved_keys = sorted({k for k in set(bm) | set(am) if bm.get(k) != am.get(k)})
        return "masking.%s changed outside the move" % "/".join(moved_keys)
    b.pop("masking", None)
    a.pop("masking", None)
    if b != a:
        return "changed %s outside masking" % "/".join(
            sorted({k for k in set(b) | set(a) if b.get(k) != a.get(k)}))
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=os.path.join(HERE, "index.jsonl"))
    ap.add_argument("--by", help="who is moving it")
    ap.add_argument("--apply", action="store_true", help="write it; default is a dry run")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    if not a.by or not a.by.strip():
        return ap.error("--by is required: moving a human's record has an owner")

    rows = read_jsonl(a.index)
    print("index                   : %s" % a.index)
    print("rows                    : %d" % len(rows))
    todo, refused = [], []
    for r in rows:
        for gate, key, why in plan(r):
            (refused if why else todo).append((r["sha256"], gate, key, why))
    print("adjudications in a finding key : %d" % (len(todo) + len(refused)))
    for sha, gate, key, _why in todo:
        row = next(x for x in rows if x["sha256"] == sha)
        m = row["masking"]
        print("  MOVE   %s  masking.%s -> masking.%s   (about %s)"
              % (sha[:12], key, TARGET, gate))
        print("         finding digest for %s: %s -> %s"
              % (gate, clearance.finding_digest(m, gate),
                 clearance.finding_digest(apply_to(row)[0]["masking"], gate)))
    for sha, _gate, key, why in refused:
        print("  REFUSE %s  masking.%s: %s" % (sha[:12], key, why))
    if not todo:
        print()
        print("nothing to move.")
        return 1 if refused else 0
    if not a.apply:
        print()
        print("dry run: nothing written. Re-run with --apply.")
        print("`publishable` is NOT written here - run shard-gate.py --fix afterwards,")
        print("which is the only thing allowed to compute it.")
        return 0

    with index_lock(a.index):
        # Re-read inside the lock: a digest computed against a stale copy would describe a
        # movement that is not the one being written.
        rows = read_jsonl(a.index)
        n = 0
        for i, r in enumerate(rows):
            after, moves, _ref = apply_to(r)
            if not moves:
                continue
            bad = assert_moved(r, after, moves)
            if bad:
                sys.exit("refusing to write %s: %s" % (r["sha256"][:12], bad))
            rows[i] = after
            n += 1
        write_jsonl_atomic(a.index, rows)
    print()
    print("written: %d row(s) at %s by %s"
          % (n, datetime.datetime.now().replace(microsecond=0).isoformat(), a.by.strip()))
    print("record the move in field-provenance.MOVED, and run")
    print("  corpus/shard-gate.py --fix %s" % os.path.relpath(a.index, os.getcwd()))
    return 0


# ---------------------------------------------------------------------------------------
# Controls. Both directions for every rule: a mover that refuses everything and one that
# moves everything look identical from a green run over a two-row population.
# ---------------------------------------------------------------------------------------

def inject():
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-64s %-10s %s" % (label, str(got)[:10],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    ADJ = {"classification": "ambiguous between c2 and identity",
           "decision": "held for human confirmation; not published until resolved",
           "resolution": {"resolution": "attacker-owned; kept as an IOC",
                          "method": "resolved from the local collection"},
           "value": "an address inside an encoded layer",
           "why_it_matters": "masking cannot reach inside an encoded layer"}
    # A real gate finding, in the shape `verify-content-mask._profile` emits.
    FIND = {"distinct_identifiers": 1, "occurrences": 1, "identifier_lengths": [6],
            "positions": ["begins"], "segment_lengths": [25],
            "note": finding_notes.IDENTIFIER_NOTE}

    def row(masking=None, **kw):
        m = {"applied": True, "plaintext_gate": "PASS", "encoded_layer_gate": "PASS",
             "detection_survived": True,
             "provenance": {"tools": "a" * 12, "map": "b" * 12, "at": "2026-09-06T00:00:00"}}
        m.update(masking or {})
        r = {"sha256": "0" * 64, "verdict": "malicious", "sensitivity": ["c2"], "masking": m}
        r.update(kw)
        return r

    print("=== it must MOVE this, and only this ===")
    r = row({"encoded_layer_finding": dict(ADJ)})
    after, moves, refusals = apply_to(r)
    case("an adjudication under a passing gate's finding key", [g for g, _k in moves],
         ["encoded_layer_gate"])
    case("the finding key is vacated",
         "encoded_layer_finding" in after["masking"], False)
    case("the adjudication lands under masking.%s" % TARGET,
         sorted(after["masking"].get(TARGET, {})), sorted(set(ADJ) | {ABOUT}))
    case("and it records the gate it was about",
         after["masking"][TARGET][ABOUT], "encoded_layer_gate")
    case("nothing else on the row moves", assert_moved(r, after, moves) or "clean", "clean")
    case("the input row is not mutated", "encoded_layer_finding" in r["masking"], True)
    # The property the move exists for, asserted rather than described.
    case("the encoded-layer finding digest MOVES",
         clearance.finding_digest(r["masking"], "encoded_layer_gate")
         != clearance.finding_digest(after["masking"], "encoded_layer_gate"), True)
    case("and no OTHER gate's digest moves",
         all(clearance.finding_digest(r["masking"], g)
             == clearance.finding_digest(after["masking"], g)
             for g in ("plaintext_gate", "detection_survived")), True)
    case("the vacated key leaves the gate reading as its own evidence-free self",
         clearance.evidence_for(after["masking"], "encoded_layer_gate"), {})
    # The second place a finding is recorded.
    r2 = row({"gate_categories": {"encoded_layer_finding": dict(ADJ)}})
    a2, m2, _ = apply_to(r2)
    case("an adjudication recorded under gate_categories", [k for _g, k in m2],
         ["gate_categories.encoded_layer_finding"])
    case("and gate_categories is left without it",
         "encoded_layer_finding" in a2["masking"]["gate_categories"], False)

    print()
    print("=== and it must REFUSE these ===")

    def refusal(label, masking, want=True):
        rr = row(masking)
        _a, mv, rf = apply_to(rr)
        case(label, "refused" if (rf and not mv) else "moved",
             "refused" if want else "moved")

    refusal("one real profile key mixed into the block",
            {"encoded_layer_finding": dict(ADJ, occurrences=3)})
    refusal("the whole real finding, decision bolted on",
            {"encoded_layer_finding": dict(FIND, decision="held")})
    refusal("a decision with no resolution",
            {"encoded_layer_finding": {k: v for k, v in ADJ.items() if k != "resolution"}})
    refusal("a resolution recorded as empty",
            {"encoded_layer_finding": dict(ADJ, resolution={})})
    refusal("the gate records FAIL, so the finding is evidence",
            {"encoded_layer_gate": "FAIL", "encoded_layer_finding": dict(ADJ)})
    refusal("the gate records a dict-form FAIL",
            {"encoded_layer_gate": {"result": "FAIL"}, "encoded_layer_finding": dict(ADJ)})
    refusal("the row already carries an adjudication",
            {"encoded_layer_finding": dict(ADJ), TARGET: dict(ADJ)})
    # The negative half of the "FAIL is refused" pair: a dict-form PASS is still a pass.
    refusal("a dict-form PASS is a pass and is moved",
            {"encoded_layer_gate": {"result": "PASS"}, "encoded_layer_finding": dict(ADJ)},
            want=False)

    print()
    print("=== and it must not SEE these at all ===")
    for label, masking in (("an ordinary gate finding with no decision",
                            {"encoded_layer_gate": "FAIL",
                             "encoded_layer_finding": dict(FIND)}),
                           ("a decision in a block that is not a finding key",
                            {"legacy": dict(ADJ)}),
                           ("a row with no masking block at all", None)):
        rr = row(masking) if masking is not None else {"sha256": "0" * 64}
        case(label, plan(rr), [])

    print()
    print("=== the additive assertion must catch a tool that did more ===")
    r = row({"encoded_layer_finding": dict(ADJ)})
    good, moves, _ = apply_to(r)
    for label, mutate in (
            ("a gate verdict rewritten alongside",
             lambda x: x["masking"].__setitem__("encoded_layer_gate", "FAIL")),
            ("publishable written",
             lambda x: x.__setitem__("publishable", True)),
            ("a second masking key removed",
             lambda x: x["masking"].pop("plaintext_gate")),
            ("the adjudication not written at all",
             lambda x: x["masking"].pop(TARGET))):
        bad = copy.deepcopy(good)
        mutate(bad)
        case(label, "caught" if assert_moved(r, bad, moves) else "MISSED", "caught")
    case("and the clean move is not caught",
         assert_moved(r, good, moves) or "clean", "clean")

    print()
    print("=== the finding-key table is clearance's, not a second copy ===")
    case("every key it will move is one a clearance keys through",
         sorted(FINDING_KEYS) ,
         sorted({k for keys in clearance.EVIDENCE_KEYS.values() for k in keys}))
    case("and the target is not itself a finding key", TARGET in FINDING_KEYS, False)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LockBusy as exc:
        sys.exit(str(exc))
