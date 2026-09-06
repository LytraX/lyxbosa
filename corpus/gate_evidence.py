#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compare a recorded gate finding with the one the current tools produce - the whole finding.

WHAT WAS WRONG
--------------
A provenance stamp asserts that *these tools produced these verdicts*. Both tools that write
one compared the verdict by CLASS and nothing else: `verify-and-stamp.reverify` through
`shard-gate.gate_result`, and `remeasure-gates.moved` through the same call. Neither looked
at the evidence recorded underneath the verdict.

So a payload can go stale beneath a stamp that appears to certify it, and the two tools then
disagree in a way that leaves the row unrepairable by either:

  * `verify-and-stamp.py` stamps where the verdicts agree. `FAIL` did not become `PASS`, so
    it stamped, and the stamp now says the current tools produced a payload they do not.
  * `remeasure-gates.py` refuses where no verdict moved - "rewriting the record here would
    move a measurement that did not change" - so it will not write the fresh payload either.
    It was right about the verdict and wrong about the row.

This is worse than the two blind spots closed before it, and in a specific way rather than a
rhetorical one. Those blocked rows: a row with no usable provenance raises a blocker and
stops. This one *authorises*. The evidence is what a human reads when they judge a finding,
and `clearance.finding_digest` is taken over exactly that evidence, so a payload that moves
under a current stamp silently un-anchors a human decision instead of blocking a row.

There is a second route to the same place, and it was opened deliberately last round.
`FP_NOTE` was moved out of `verify-content-mask.py` into `corpus/fp-note.txt` so that
correcting a false-positive figure would stop invalidating 140 stamps. That was right, and it
means the note is now outside the AST the tools digest reads: the note can be rewritten with
`provenance.tools` unmoved, while `false_positive_note` inside every stored finding - and
every clearance digest keyed to it - moves. Only a comparison of the evidence can see that.

WHY A SEPARATE MODULE, AND WHY IT IS NOT IN `gate_provenance.TOOLS`
-------------------------------------------------------------------
Separate, because the defect was two tools disagreeing about what they compare. A shared
definition is the repair; two more copies of a widened comparison would be the same defect
with more code.

Out of `TOOLS`, on the same ground `shard-gate.py` is out: `TOOLS` is the modules whose logic
DECIDES a stored gate verdict, and this one decides none - it compares two records of one.
Including it would invalidate all 142 stamps on every edit to a comparator, which is a price
this repository has now paid twice and measured once.

WHAT IS COMPARED, AND THE RULE THAT WAS MEASURED RATHER THAN ASSUMED
--------------------------------------------------------------------
The evidence is read through `clearance.evidence_for`, not through a second lookup table.
That is the load-bearing choice in this file: a stamp has to certify *exactly* what a
clearance keys to, and two independent notions of "the evidence for this gate" would drift
apart silently. `same_finding()` asserts the tie directly, and `--inject` asserts it in both
directions.

**Only the keys the row records are compared.** The alternative - requiring the recorded
block to carry every key the current tools emit - was measured over the 132 masked rows whose
bytes are hash-verified on this machine:

  * 126 rows record 12 `secret_literals` keys and 6 record 13. The 12 are `mask-samples.py`'s
    named subset; the 13 are everything `secret_gate` returns bar the verdict, which is what
    `remeasure-gates.py` writes. The one key that differs is `note`, a constant string of
    prose. Under the strict rule 126 of 132 rows - 95% of the masked population - would read
    as drift for a prose key neither tool disagrees about.

That is the flood shape this corpus keeps refusing, so the armed rule is the recorded keys.
Keys the current tools produce and the row does not are reported as `unrecorded_fields` and
are not a difference: an incomplete record is a different defect from a wrong one, with a
different repair, and §8 counts causes rather than symptoms. The opposite direction IS a
difference - a key the row records that the tools no longer produce reads as absent and
fails, which is what stops a field being deleted out of a comparison.

WHAT IT DOES NOT ANSWER
-----------------------
Whether the bytes are the ones the row stands behind. `restage-masked.py` answers that by
hash and refuses where it cannot; a comparison run over the wrong bytes is worse than none,
because it looks like one. And it says nothing about `detection_survived`, whose evidence is
`rules_before`/`rules_after` and whose provenance is `measured_with`: no module in `TOOLS`
produces it and no stamp here claims it.
"""
import json

import clearance

__all__ = ["STAMPED_GATES", "evidence_for", "compare_gate", "compare", "same_finding"]

# The gates a provenance stamp claims: every one produced by a module inside
# `gate_provenance.TOOLS`. `detection_survived` is clearable and is deliberately absent -
# see the closing paragraph above.
STAMPED_GATES = ("plaintext_gate", "encoded_layer_gate", "secret_gate")

# One definition of "the evidence for this gate", borrowed from the module a clearance is
# keyed through rather than restated. The import is the assertion; `same_finding` is the
# check that the assertion is worth anything.
evidence_for = clearance.evidence_for


def _class(gate_result, value):
    """The verdict as its CLASS, through the tree's single parser for a gate value.

    Six local rows store the encoded verdict as `{"result": "FAIL", ...}`, and a byte
    comparison would report a movement on every one of them.
    """
    return gate_result(value)[0]


def compare_gate(masking, gate, today_verdict, today_evidence, gate_result):
    """(state, detail) for ONE gate. Four states, never two.

      'not-recorded'   - the row records no verdict for this gate, so it owes nothing
      'agrees'         - same verdict class, and every recorded evidence field matches
      'verdict-moved'  - the class moved
      'evidence-moved' - the class held and a recorded evidence field did not

    `verdict-moved` and `evidence-moved` are separate because the causes are separate and
    §8 counts causes: a verdict moves when the predicate's answer changes, and evidence
    moves when its profile does with the answer unchanged. A caller that only needs "may I
    stamp this" can treat both as no, and the report still says which happened.
    """
    if gate not in (masking or {}):
        return "not-recorded", {}
    was, now = _class(gate_result, masking.get(gate)), _class(gate_result, today_verdict)
    detail = {"verdict": {"recorded": was, "today": now}}
    key = (clearance.EVIDENCE_KEYS.get(gate) or (None,))[0]
    recorded = evidence_for(masking, gate).get(key)
    fields, unrecorded = {}, []
    if isinstance(recorded, dict):
        now_ev = today_evidence if isinstance(today_evidence, dict) else {}
        for k in sorted(recorded):
            if recorded[k] != now_ev.get(k):
                fields[k] = {"recorded": recorded[k], "today": now_ev.get(k)}
        unrecorded = sorted(set(now_ev) - set(recorded))
    elif recorded is not None:
        # A finding recorded as something other than an object. Compared whole rather than
        # per field, because there are no fields to walk.
        if recorded != today_evidence:
            fields["<the finding itself>"] = {"recorded": recorded, "today": today_evidence}
    if unrecorded:
        detail["unrecorded_fields"] = unrecorded
    if fields:
        detail["evidence"] = fields
    if was != now:
        return "verdict-moved", detail
    if fields:
        return "evidence-moved", detail
    return "agrees", detail


def compare(masking, today, gate_result, gates=STAMPED_GATES):
    """(state, per_gate) over every stamped gate the row records.

    `today` is {gate: (verdict, evidence_or_None)} for the gates the caller could measure.
    A gate the caller did not measure must simply be absent from `today`; this function
    never treats a missing measurement as agreement - it reports `cannot-check` for that
    gate and the overall state is `cannot-check`, because "could not tell" reading as
    "fine" is the defect the whole provenance mechanism exists for, one level up.
    """
    per, worst = {}, "agrees"
    order = {"agrees": 0, "cannot-check": 1, "evidence-moved": 2, "verdict-moved": 2}
    for g in gates:
        if g not in (masking or {}):
            continue
        if g not in today:
            per[g] = ("cannot-check", {})
        else:
            verdict, ev = today[g]
            per[g] = compare_gate(masking, g, verdict, ev, gate_result)
        if order[per[g][0]] > order[worst]:
            worst = per[g][0]
    return worst, per


def same_finding(masking, gate, today_verdict, today_evidence, gate_result):
    """Would a clearance keyed to this finding still be keyed to it after the repair?

    This is the property the comparison exists to protect, asserted rather than described.
    A clearance is keyed to `clearance.finding_digest` over the gate, its recorded verdict
    and its evidence; if `compare_gate` said `agrees` while that digest moved, a stamp would
    be certifying a finding no clearance can still reach - the same defect facing the other
    way.

    So `fresh` is built as the repair would leave the row, not as the raw measurement:

      * the recorded verdict is KEPT where its class holds, because normalising a dict-form
        `{"result": "FAIL"}` into the string `"FAIL"` moves the digest for a verdict nobody
        re-decided. `remeasure-gates.build()` writes only what moved for this reason;
      * evidence is compared over the keys the row records, mirroring `compare_gate`;
      * a row that records no evidence block gets none written, so the absence is stable.

    The consequence of the schema rule is stated rather than hidden: a re-measurement that
    widens a recorded block DOES move the digest, and would take a clearance with it. It can
    only happen on a row whose evidence moved - which moves the digest anyway - because
    nothing is written where nothing moved.
    """
    key = (clearance.EVIDENCE_KEYS.get(gate) or (None,))[0]
    recorded = evidence_for(masking, gate).get(key)
    fresh = dict(masking or {})
    fresh.pop("gate_categories", None)
    if _class(gate_result, (masking or {}).get(gate)) != _class(gate_result, today_verdict):
        fresh[gate] = today_verdict
    if recorded is None:
        fresh.pop(key, None)
    elif isinstance(recorded, dict) and isinstance(today_evidence, dict):
        fresh[key] = {k: today_evidence.get(k) for k in recorded}
    elif today_evidence is None:
        fresh.pop(key, None)
    else:
        fresh[key] = today_evidence
    return (clearance.finding_digest(masking or {}, gate)
            == clearance.finding_digest(fresh, gate))


# ---------------------------------------------------------------------------------------
# Controls.
#
# In both directions throughout, and not as a formality: a comparison that always refuses
# and one that never fires look identical from a green run. That shape has now come up
# three times in this repository - the additive assertion that could see an overwrite and
# not an addition, the delegation that had to be shown to accept a fresh summary as well as
# refuse a stale one, and this - so it is the default expectation rather than a special
# case, and every positive case below is paired with the negative that would pass without
# it.
# ---------------------------------------------------------------------------------------
def _selftest():
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-66s %-16s %s" % (label, str(got)[:16],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    # The tree's own parser, imported the way the callers import it, so this suite cannot
    # pass against a stub that the real callers would not use.
    import importlib.util, os
    here = os.path.dirname(os.path.abspath(__file__))
    _sp = importlib.util.spec_from_file_location("sg_ev", os.path.join(here, "shard-gate.py"))
    SG = importlib.util.module_from_spec(_sp)
    _sp.loader.exec_module(SG)
    gr = SG.gate_result

    find = {"distinct_identifiers": 1, "occurrences": 1, "identifier_lengths": [6],
            "positions": ["begins"], "segment_lengths": [25],
            "false_positive_note": "127 false positives across 104 of 8,000 stock files",
            "note": "identifier names deliberately not recorded here"}
    secret = {"secret_literals_before": 1, "secret_literals_after": 1,
              "secret_literals_carried_over": 1, "shapes_carried_over": ["quoted-credential"],
              "literal_population_comparable": False}
    m = {"applied": True,
         "plaintext_gate": "PASS",
         "encoded_layer_gate": "FAIL", "encoded_layer_finding": dict(find),
         "secret_gate": "FAIL", "secret_literals": dict(secret),
         "provenance": {"tools": "a" * 12, "map": "b" * 12, "at": "2026-09-06T14:00:00"}}

    print("=== the same measurement, twice: nothing may move ===")
    case("identical verdict and identical evidence",
         compare_gate(m, "encoded_layer_gate", "FAIL", dict(find), gr)[0], "agrees")
    case("a gate the row does not record owes nothing",
         compare_gate({"applied": True}, "secret_gate", "PASS", {}, gr)[0], "not-recorded")
    # The dict-form schema, which six local rows carry. A byte comparison of the verdict
    # would rewrite every one of them and report a movement that did not happen.
    dictm = dict(m, encoded_layer_gate={"result": "FAIL", "occurrences": 1})
    case("a dict-form FAIL against a live FAIL is not a movement",
         compare_gate(dictm, "encoded_layer_gate", "FAIL", dict(find), gr)[0], "agrees")

    print()
    print("=== the case this file exists for: the verdict holds and the evidence moves ===")
    st, d = compare_gate(m, "secret_gate", "FAIL",
                         dict(secret, secret_literals_before=2, secret_literals_after=2,
                              secret_literals_carried_over=2), gr)
    case("1/1/1 recorded, 2/2/2 measured, both FAIL", st, "evidence-moved")
    case("and the verdict is reported as unmoved",
         d["verdict"]["recorded"] == d["verdict"]["today"] == "fail", True)
    # `.get`, not `[...]`: run against a comparator that cannot see evidence at all this
    # case must REPORT, not raise. A suite that dies on the first blind case cannot say how
    # blind the thing is, and the whole point of running it against the superseded
    # comparison is the count it produces.
    case("and every field that moved is named",
         sorted(d.get("evidence") or {}), ["secret_literals_after", "secret_literals_before",
                                           "secret_literals_carried_over"])
    # Prose counts. `clearance.finding_digest` covers `false_positive_note` on purpose - "a
    # false-positive rate the human weighed is part of what they weighed" - and the note now
    # lives OUTSIDE the tools digest, so this is the one drift a current stamp cannot see.
    case("a false-positive figure the human weighed is re-measured",
         compare_gate(m, "encoded_layer_gate", "FAIL",
                      dict(find, false_positive_note="131 across 108"), gr)[0],
         "evidence-moved")
    case("the finding's own prose changes",
         compare_gate(m, "encoded_layer_gate", "FAIL", dict(find, note="reworded"), gr)[0],
         "evidence-moved")

    print()
    print("=== and the other direction, which a comparison that always refuses would fail ===")
    case("a verdict that moved is called a verdict movement, not an evidence one",
         compare_gate(m, "encoded_layer_gate", "PASS", None, gr)[0], "verdict-moved")
    case("a row recording a verdict and NO evidence block still agrees",
         compare_gate({"secret_gate": "PASS"}, "secret_gate", "PASS", None, gr)[0], "agrees")
    case("evidence recorded only under gate_categories reads identically",
         compare_gate({"encoded_layer_gate": "FAIL",
                       "gate_categories": {"encoded_layer_finding": dict(find)}},
                      "encoded_layer_gate", "FAIL", dict(find), gr)[0], "agrees")

    print()
    print("=== the schema rule, in both directions and measured before it was armed ===")
    # 126 of the 132 masked rows record 12 `secret_literals` keys where the current gate
    # emits 13; the odd one is `note`, written by `remeasure-gates.py` and not by
    # `mask-samples.py`. Refusing on that would put 95% of the population into
    # re-measurement for a constant string.
    st, d = compare_gate(m, "secret_gate", "FAIL", dict(secret, note="counts and shapes"), gr)
    case("a key the tools emit and the row does not record is not a difference", st, "agrees")
    case("and it is reported rather than dropped", d.get("unrecorded_fields"), ["note"])
    thin = {k: v for k, v in secret.items() if k != "secret_literals_carried_over"}
    case("a key the row records and the tools no longer emit IS a difference",
         compare_gate(m, "secret_gate", "FAIL", thin, gr)[0], "evidence-moved")

    print()
    print("=== compare() must not read an unmeasured gate as an agreeing one ===")
    st, per = compare(m, {"encoded_layer_gate": ("FAIL", dict(find)),
                          "plaintext_gate": ("PASS", None)}, gr)
    case("a recorded gate absent from the measurement", per["secret_gate"][0], "cannot-check")
    case("and the whole row reads cannot-check", st, "cannot-check")
    st, _p = compare(m, {"encoded_layer_gate": ("FAIL", dict(find)),
                         "plaintext_gate": ("PASS", None),
                         "secret_gate": ("FAIL", dict(secret))}, gr)
    case("every gate measured and agreeing", st, "agrees")
    st, _p = compare(m, {"encoded_layer_gate": ("FAIL", dict(find)),
                         "plaintext_gate": ("PASS", None),
                         "secret_gate": ("FAIL", dict(secret, secret_literals_after=2))}, gr)
    case("one gate's evidence moved", st, "evidence-moved")

    print()
    print("=== the tie to the thing this protects: clearance.finding_digest ===")
    # Without these two the comparison could agree about a payload no clearance can still be
    # keyed to, which is the same defect facing the other way.
    case("agreement implies the finding digest is unmoved",
         same_finding(m, "secret_gate", "FAIL", dict(secret), gr), True)
    case("a moved evidence field implies the digest moved",
         same_finding(m, "secret_gate", "FAIL", dict(secret, secret_literals_after=2), gr),
         False)
    case("a moved false-positive figure implies the digest moved",
         same_finding(m, "encoded_layer_gate", "FAIL",
                      dict(find, false_positive_note="131 across 108"), gr), False)
    # And the negative half of the tie: everything `compare_gate` calls agreement must leave
    # the digest where it is, or the schema rule above would be quietly incompatible with
    # clearances. Three ways it says agreement, three assertions.
    case("a key the row does not record does not move the digest",
         same_finding(m, "secret_gate", "FAIL", dict(secret, note="counts and shapes"), gr),
         True)
    case("a verdict that changes SHAPE but not class does not move the digest",
         same_finding(dictm, "encoded_layer_gate", "FAIL", dict(find), gr), True)
    case("a row recording no evidence block keeps its digest",
         same_finding({"secret_gate": "FAIL"}, "secret_gate", "FAIL", dict(secret), gr),
         True)

    print()
    print("=== the evidence lookup is clearance's, not a second copy ===")
    case("evidence_for is clearance.evidence_for",
         evidence_for is clearance.evidence_for, True)
    case("every stamped gate has an evidence key in clearance's table",
         all(g in clearance.EVIDENCE_KEYS for g in STAMPED_GATES), True)
    case("and every stamped gate is clearable",
         all(g in clearance.CLEARABLE_GATES for g in STAMPED_GATES), True)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    import sys
    if "--inject" in sys.argv or "--selftest" in sys.argv:
        sys.exit(_selftest())
    sys.exit("usage: gate_evidence.py --inject   (this module is a library; see the docstring)")
