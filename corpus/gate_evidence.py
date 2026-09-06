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

  * **124 rows record 12 `secret_literals` keys and 8 record 13**, re-derived today over both
    halves. The figure recorded when this rule was armed was 126 and 6, and the difference
    has a cause rather than an error: the two rows `remeasure-gates.py` rewrote at the end of
    that round - `34bba99dae63`, whose payload went 1/1/1 to 2/2/2, and `b827cdd9d417`, whose
    went 22/23/22 to 27/25/23 - moved from twelve keys to thirteen as a side effect of being
    rewritten. Arming the rule created two more instances of the case it was measured against.
    The 12 are `mask-samples.py`'s named subset; the 13 are everything `secret_gate` returns
    bar the verdict, which is what `remeasure-gates.py` wrote. The one key that differs is
    `note`, a constant string of prose. Under the strict rule 124 of 132 rows - 94% of the
    masked population - would read as drift for a prose key neither tool disagrees about.

That is the flood shape this corpus keeps refusing, so the armed rule is the recorded keys.
Keys the current tools produce and the row does not are reported as `unrecorded_fields` and
are not a difference: an incomplete record is a different defect from a wrong one, with a
different repair, and §8 counts causes rather than symptoms. The opposite direction IS a
difference - a key the row records that the tools no longer produce reads as absent and
fails, which is what stops a field being deleted out of a comparison.

THE SCHEMA FORK IS THE CASE THAT RULE WAS NOT MEASURED AGAINST
---------------------------------------------------------------
What was measured was "a note field holding a constant string". What exists is **two
schemas**, and they are not the same thing: two rows in the same condition are now compared
over different key sets, and nothing said so. `RECORDED_SECRET_KEYS` closes the writer half -
`remeasure-gates.py` now writes the same named subset `mask-samples.py` does, and
`--inject` reads that subset out of `mask-samples.py`'s own AST rather than restating it, so
they cannot drift apart again. The extra key is an artefact of one writer emitting whatever
the gate returned, not a second legitimate schema: `note` carries no measurement, it is
byte-identical on all 8 rows, and no reader anywhere distinguishes the two shapes.

**Why the eight rows are not rewritten, priced rather than asserted.** Dropping `note` from
them moves `clearance.finding_digest` for `secret_gate`, and one of the eight -
`34bba99dae63` - carries a live human clearance keyed to exactly that digest. Rewriting the
record would inert an authorisation entered a round ago, over a constant string that carries
no measurement, and re-signing it is the operator's act and not a tool's. So the schema is
reconciled at the writer and converges by attrition: no new row can fork, and each of the
eight collapses to twelve keys the next time it is legitimately re-measured.

**And the divergence is inert today for a reason that is now checked rather than assumed.**
The two schemas can only be compared differently if the note's TEXT moves, and that string
is a literal inside `verify-content-mask.py`, which is one of the six modules in
`gate_provenance.TOOLS` - so editing it moves the `tools` digest and every stamped row reads
stale in the same instant. The fork cannot go live quietly. That coupling is exactly what
`fp-note.txt` deliberately broke for the OTHER prose key in this block's sibling finding, so
it is a property to check and not to trust: `digest-controls.py` asserts both halves - the
note inside the AST moves the digest, the note outside it does not.

WHAT IT DOES NOT ANSWER
-----------------------
Whether the bytes are the ones the row stands behind. `restage-masked.py` answers that by
hash and refuses where it cannot; a comparison run over the wrong bytes is worse than none,
because it looks like one. And it says nothing about `detection_survived`, whose evidence is
`rules_before`/`rules_after` and whose provenance is `measured_with`: no module in `TOOLS`
produces it and no stamp here claims it.
"""
import ast, json, os

import clearance

__all__ = ["STAMPED_GATES", "RECORDED_SECRET_KEYS", "evidence_for", "compare_gate",
           "compare", "same_finding", "mask_samples_secret_keys"]

HERE = os.path.dirname(os.path.abspath(__file__))

# The `secret_literals` block as it is RECORDED - the twelve measured fields, and no prose.
#
# It lives here rather than in `mask-samples.py` because that file is one of the six in
# `gate_provenance.TOOLS`: a module-level constant added there would change its AST, move
# the `tools` digest, and put all 142 stamped rows into re-measurement to install a name.
# This module decides no verdict and is deliberately outside TOOLS for the same reason
# `shard-gate.py` is.
#
# So it is a copy, and a copy is only safe if something asserts it. `mask_samples_secret_keys`
# reads the tuple out of `mask-samples.py`'s own syntax tree and `--inject` asserts the two
# are equal, which is the same tie `evidence_for is clearance.evidence_for` makes one level
# along: a stamp must certify exactly what a clearance keys to, and a re-measurement must
# record exactly what a masking pass records.
RECORDED_SECRET_KEYS = ("secret_literals_before", "secret_literals_after",
                        "secret_literals_carried_over", "secret_literals_added",
                        "secret_literals_added_by_the_masker",
                        "secret_literals_added_unattributed",
                        "shapes_carried_over", "shapes_added_unattributed",
                        "shapes_remaining",
                        "decoded_layers_before", "decoded_layers_after",
                        "literal_population_comparable")


def mask_samples_secret_keys(path=None):
    """The key tuple `mask-samples.py` records for `secret_literals`, read from its AST.

    Parsed rather than imported: importing that module executes a masking driver. Parsed
    rather than grepped, because the question is which names are in THAT tuple and a text
    search cannot tell one tuple from another. Returns None where the shape it looks for is
    not there any more, which the control reports as a failure rather than as agreement -
    an extractor that silently finds nothing would make the tie pass by being blind.
    """
    p = path or os.path.join(HERE, "mask-samples.py")
    with open(p, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if not (isinstance(k, ast.Constant) and k.value == "secret_literals"):
                continue
            if not isinstance(v, ast.DictComp) or not v.generators:
                continue
            it = v.generators[0].iter
            if not isinstance(it, (ast.Tuple, ast.List)):
                continue
            names = [e.value for e in it.elts
                     if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if len(names) == len(it.elts):
                return tuple(names)
    return None

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
    print("=== the schema fork, stated rather than depended on ===")
    # THE RULE WAS MEASURED AGAINST "a note field holding a constant string" AND WHAT EXISTS
    # IS TWO SCHEMAS. 124 rows record 12 keys and 8 record 13. These cases assert what that
    # actually costs today, in both directions, rather than leaving it to the fact that
    # nothing has gone wrong yet.
    NOTE = ("counts and shapes only; a credential-shaped literal remaining after masking is "
            "a synthetic one by construction")
    twelve = {"secret_gate": "FAIL", "secret_literals": dict(secret),
              "provenance": dict(m["provenance"])}
    thirteen = {"secret_gate": "FAIL", "secret_literals": dict(secret, note=NOTE),
                "provenance": dict(m["provenance"])}
    today = dict(secret, note=NOTE)
    # The property that matters: same condition, same answer, whichever schema the row holds.
    case("a 12-key row and a 13-key row in the same condition AGREE alike",
         (compare_gate(twelve, "secret_gate", "FAIL", dict(today), gr)[0],
          compare_gate(thirteen, "secret_gate", "FAIL", dict(today), gr)[0]),
         ("agrees", "agrees"))
    case("and both see the SAME measured field move",
         (compare_gate(twelve, "secret_gate", "FAIL",
                       dict(today, secret_literals_after=2), gr)[0],
          compare_gate(thirteen, "secret_gate", "FAIL",
                       dict(today, secret_literals_after=2), gr)[0]),
         ("evidence-moved", "evidence-moved"))
    # And the direction the rule was never measured against, asserted so that it is a known
    # cost rather than a surprise: if the note's TEXT moves, the two schemas answer
    # differently. That is the whole fork, in one case.
    case("if the note text moved, the 12-key row would still agree",
         compare_gate(twelve, "secret_gate", "FAIL",
                      dict(today, note="reworded"), gr)[0], "agrees")
    case("...and the 13-key row would NOT - which is the fork, priced",
         compare_gate(thirteen, "secret_gate", "FAIL",
                      dict(today, note="reworded"), gr)[0], "evidence-moved")
    # Why that cannot happen quietly: the note is a literal inside a TOOLS module, so the
    # text and the `tools` digest move together. `digest-controls.py` asserts that half.
    case("the divergence is inert only while the note is inside the tools AST",
         NOTE.split(";")[0] in open(os.path.join(HERE, "verify-content-mask.py"),
                                    encoding="utf-8").read(), True)
    # The writer half of the reconciliation.
    case("the recorded subset carries no prose key",
         [k for k in RECORDED_SECRET_KEYS if k.endswith("note")], [])
    case("and it is exactly twelve fields", len(RECORDED_SECRET_KEYS), 12)
    ms = mask_samples_secret_keys()
    case("mask-samples.py's own tuple was found in its AST", ms is not None, True)
    case("and the copy here equals it", set(ms or ()), set(RECORDED_SECRET_KEYS))
    # The extractor must be able to say "not found", or the tie above passes by being blind.
    import tempfile
    _fd, _p = tempfile.mkstemp(suffix=".py")
    with os.fdopen(_fd, "w") as fh:
        fh.write('BLOCK = {"secret_literals": {"a": 1}}\n')
    case("the extractor reports absence rather than agreement",
         mask_samples_secret_keys(_p), None)
    os.unlink(_p)

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
