#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A human overriding a gate finding, recorded as a thing in the index rather than a gap in it.

WHY AN ESCAPE HATCH AT ALL
--------------------------
Some gate findings are collisions. The encoded-layer predicate produces 127 false positives
over 8,000 stock CMS files, and the case that killed its confidence grade was real: a
six-character account label sitting at the start of a token in a decoded PHP function table,
between two neighbouring entries of the same table. No predicate that can see that hit can
also decide it. A person has to read the bytes and say.

Today there is no way to record that decision. The three ways it gets made instead are all
worse than an escape hatch:

  * edit `publishable` to `true` by hand - which §4.4 forbids, because a stored derived value
    that disagrees with what derives it is the defect `staleness()` exists to catch;
  * edit the tag so the gate stops asking - which is the exact move this round is repairing,
    a claim about the bytes silencing a measurement of them;
  * loosen the predicate for everybody - which trades one row's collision for a hole under
    the whole corpus.

So the decision gets recorded. `publishable` stays computed: a cleared row is publishable
because `evaluate()` now says so given a recorded human input, never because someone wrote
`true` over a `false`.

WHAT A CLEARANCE IS KEYED TO, AND WHY EACH KEY
----------------------------------------------
An escape hatch is the most dangerous thing in a publish gate, so every one of these is a
constraint with a control in `inject()` proving it holds.

  * **the specific finding, by digest.** The digest covers the gate, the verdict recorded for
    it, and the evidence recorded beside it. A judgement about a 3-character identifier
    contained in a 97-character base64 segment is not a judgement about whatever the next
    re-measurement finds, so it must not carry to it. Everything in the evidence block is in
    the digest, `note` and `false_positive_note` included: a false-positive rate the human
    weighed is part of what they weighed, and a digest that ignored prose would be a digest
    that could be edited around.

  * **the gate provenance at the time of judgement.** A clearance is a judgement about what a
    particular gate said. §7.2's provenance stamp exists because a recorded `PASS` is a claim
    about some version of the gate and nothing recorded which; a recorded *clearance* is a
    claim about some version of a FAIL and has exactly the same problem one level up. When
    the tools or the map move, the finding has not been judged by anyone. It is not enough
    that the digest still matches - a predicate can change its reasoning and return the same
    profile.

  * **not `pii` and not `content`.** §7.2 says those are never publishable by any route, and
    "any route" has to include this one. Structurally they cannot be cleared anyway - they
    produce no gate finding, so there is nothing to key a digest to - but a structural
    property nobody asserts is the kind of thing that survives one refactor. So it is also
    checked outright: on a row carrying either tag, no clearance applies to anything.

  * **not the provenance blocker itself.** Clearing it would be circular: the clearance is
    pinned to a provenance that the blocker says cannot be trusted. Falls out of the same
    rule - a clearance clears a *finding*, and only a recorded gate result is a finding.
    Nothing else on a row is clearable, which is why there is no list of exclusions here for
    `verdict is unreviewed`, `local_only` or `no masking has been applied`. None of those is
    a measurement, and the repair for each is to do the work rather than to judge it.

TWO WAYS A CLEARANCE CAN FAIL, AND THEY ARE NOT THE SAME
---------------------------------------------------------
  * **malformed** - a missing author, an empty reason, a gate that is not clearable. This is
    a hard failure of the index, reported and exited on, never quietly skipped. A clearance
    that cannot be read is a human decision the record has lost.
  * **inert** - well formed, and does not apply: the digest matches no finding on the row, or
    the provenance has moved since. This is the mechanism working, not breaking, so it is not
    a failure - but it is printed with a count on every run, because a clearance that has
    stopped applying looks from a distance exactly like one that still does.

Nothing here writes. `clear-finding.py` is the only writer, and `shard-gate.py --fix` is
asserted never to manufacture one: a --fix that can invent a human decision is not a --fix.
"""
import hashlib, json

import finding_notes

__all__ = ["CLEARABLE_GATES", "NEVER_CLEARABLE_TAGS", "REASONED_BY", "finding_digest",
           "evidence_for", "malformed", "applies", "applicable", "row_clearances",
           "unreasoned"]

# Only a recorded gate result is a finding, and only a finding is clearable.
CLEARABLE_GATES = ("plaintext_gate", "encoded_layer_gate", "secret_gate", "detection_survived")

# §7.2. Mirrors shard-gate.NEVER; duplicated here rather than imported so this module stays
# importable on its own, and asserted equal to it by shard-gate's control suite.
NEVER_CLEARABLE_TAGS = frozenset({"pii", "content"})

# What counts as the evidence for each gate. Looked up in the masking block and then in
# `gate_categories`, which is where the same findings are also recorded.
EVIDENCE_KEYS = {
    "plaintext_gate": ("plaintext_finding",),
    "encoded_layer_gate": ("encoded_layer_finding",),
    "secret_gate": ("secret_literals",),
    "detection_survived": ("rules_before", "rules_after"),
}

REQUIRED = ("gate", "finding_digest", "by", "at", "reason", "gate_provenance")

# WHO AUTHORISED IT AND WHAT PRODUCED THE ARGUMENT ARE TWO QUESTIONS
# ------------------------------------------------------------------
# `by` is the authorising human, and it stays that. Accountability for a publication
# decision belongs with a person: a corpus that lets a tool sign its own escape hatch has an
# escape hatch and no accountability.
#
# But `by` was carrying a second claim it was never entitled to. All three live clearances
# read `by: cl` while the argument in each - the segment analysis, the null model, the
# collision ruling - was drafted by an assistant, presented, and authorised. That is a
# perfectly ordinary way for a decision to be made and a bad thing to leave unrecorded,
# because the record then reads as though a person did the reading, and the whole value of
# a clearance is that someone can go back and ask what was read.
#
# So `reasoned_by` records what produced the argument, beside rather than instead of `by`.
# Rewriting `by` would have been the laundering this mechanism exists to prevent, in the
# other direction.
#
# It is deliberately NOT in `REQUIRED`. `malformed()` is the hard-failure path - a clearance
# it rejects is "a human decision the record has lost" and exits the gate non-zero - and two
# superseded clearances on `34bba99dae63` were written before this field existed. Making
# them unreadable would destroy the history the `supersedes` chain exists to keep, to record
# a fact about how they were drafted. `clear-finding.py` refuses to WRITE one without it,
# which is where the rule belongs, and `shard-gate` prints the count of clearances that
# carry none so the gap is visible rather than silent.
REASONED_BY = "reasoned_by"


def evidence_for(masking, gate):
    """The evidence recorded beside one gate verdict. Absent keys are absent, not empty.

    A finding with no evidence block still gets a digest - over the verdict alone - because a
    gate can fail without recording a profile, and a clearance for that failure still has to
    be keyed to something. What it must not do is silently collapse two different findings
    onto one digest, which is why the gate name is in the payload as well.
    """
    cats = masking.get("gate_categories") or {}
    out = {}
    for k in EVIDENCE_KEYS.get(gate, ()):
        if k in masking:
            out[k] = masking[k]
        elif k in cats:
            out[k] = cats[k]
    return out


def finding_digest(masking, gate):
    """12 hex characters over the gate, its recorded verdict and its evidence.

    Deliberately not over the whole masking block: `provenance.at` is a timestamp and
    `measured_with` is a scanner build, and a digest that moved when either did would
    invalidate every clearance on every re-stamp. Provenance is pinned separately, by value,
    which is the part that is about the gate rather than about when it ran.
    """
    payload = {"gate": gate,
               "result": masking.get(gate),
               "evidence": evidence_for(masking, gate)}
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:12]


def _prov_key(prov):
    """The half of a provenance stamp that is about the gate rather than about the clock."""
    if not isinstance(prov, dict):
        return None
    return {"tools": prov.get("tools"), "map": prov.get("map")}


def malformed(c):
    """Why this clearance cannot be read at all, or None. Never a judgement about whether
    it applies - that is `applies`, and the two are separate because one is an index defect
    and the other is the mechanism doing its job."""
    if not isinstance(c, dict):
        return "not an object"
    missing = [k for k in REQUIRED if not c.get(k)]
    if missing:
        return "missing %s" % "/".join(missing)
    if c["gate"] not in CLEARABLE_GATES:
        return ("gate %r is not a recorded gate result and so is not a finding; only %s "
                "can be cleared" % (c["gate"], "/".join(CLEARABLE_GATES)))
    for k in ("by", "reason", "at", "finding_digest"):
        if not isinstance(c[k], str) or not c[k].strip():
            return "%s is not a non-empty string" % k
    if _prov_key(c["gate_provenance"]) is None or not c["gate_provenance"].get("tools"):
        return "gate_provenance records no tools digest"
    return None


def applies(c, row, gate):
    """(bool, why_not) - does this clearance clear `gate` on this row, right now?

    `why_not` is populated for every negative answer, including the uninteresting one where
    the clearance is simply about a different gate, so a caller reporting inert clearances
    can say which kind of inert.
    """
    bad = malformed(c)
    if bad:
        return False, "malformed: %s" % bad
    if c["gate"] != gate:
        return False, "is about %s, not %s" % (c["gate"], gate)
    tags = set(row.get("sensitivity") or [])
    blocked = tags & NEVER_CLEARABLE_TAGS
    if blocked:
        return False, ("row carries %s, which §7.2 says is never publishable by any route"
                       % "/".join(sorted(blocked)))
    m = row.get("masking") or {}
    if gate not in m:
        return False, "row records no %s result to clear" % gate
    want = finding_digest(m, gate)
    if c["finding_digest"] != want:
        return False, ("keyed to finding %s; the finding on this row is now %s"
                       % (c["finding_digest"], want))
    if _prov_key(c["gate_provenance"]) != _prov_key(m.get("provenance")):
        return False, ("judged against gate provenance %s; the row now records %s"
                       % (json.dumps(_prov_key(c["gate_provenance"]), sort_keys=True),
                          json.dumps(_prov_key(m.get("provenance")), sort_keys=True)))
    return True, None


def row_clearances(row):
    """The clearance list on a row, as a list, whatever the row actually holds."""
    c = row.get("clearances")
    return c if isinstance(c, list) else []


def unreasoned(row):
    """Clearances on this row recording no `reasoned_by`, as (gate, at) pairs.

    Not a failure and not a malformation - see `REASONED_BY`. It is counted so that the
    absence of the field is something a report says rather than something a reader has to
    notice, which is the difference between the two superseded records here and the next
    clearance somebody writes by hand.
    """
    def recorded(c):
        v = c.get(REASONED_BY)
        # Whitespace is not a record. `by` is checked the same way in `malformed`, and the
        # two must agree about what counts as saying something.
        return isinstance(v, str) and bool(v.strip())

    return [(c.get("gate"), c.get("at")) for c in row_clearances(row)
            if isinstance(c, dict) and not recorded(c)]


def applicable(row, gate):
    """The first clearance that clears `gate` on `row`, or None."""
    for c in row_clearances(row):
        ok, _why = applies(c, row, gate)
        if ok:
            return c
    return None


# ---------------------------------------------------------------------------------------
# The module's own control. `shard-gate.py --inject` exercises the rule end to end; this
# exercises the digest, which is the part everything else rests on and the part with no
# visible symptom when it is wrong. A digest too sensitive invalidates every clearance on
# every re-stamp and gets removed within a round; a digest too coarse lets a judgement about
# one finding carry to another. Both halves are asserted.
# ---------------------------------------------------------------------------------------

def _selftest():
    """`python3 corpus/clearance.py --selftest`"""
    fails = []

    ran = []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-64s %-9s %s" % (label, got, "ok" if ok else "WRONG (wanted %s)" % want))
        if not ok:
            fails.append(label)

    find = {"distinct_identifiers": 1, "occurrences": 1, "identifier_lengths": [6],
            "positions": ["begins"], "segment_lengths": [25],
            "note": finding_notes.IDENTIFIER_NOTE}
    m = {"applied": True, "plaintext_gate": "PASS", "encoded_layer_gate": "FAIL",
         "encoded_layer_finding": dict(find), "detection_survived": True,
         "secret_gate": "FAIL", "secret_literals": {"secret_literals_carried_over": 1},
         "provenance": {"tools": "aaaaaaaaaaaa", "map": "bbbbbbbbbbbb",
                        "at": "2026-09-06T02:00:00"},
         "measured_with": {"path": "build-release/lyxbosa", "sha256_12": "cccccccccccc"}}
    d = finding_digest(m, "encoded_layer_gate")

    print("=== the digest must MOVE for each of these ===")
    case("the recorded verdict changes",
         finding_digest(dict(m, encoded_layer_gate="PASS"), "encoded_layer_gate") != d,
         True)
    case("the verdict changes shape (string -> dict)",
         finding_digest(dict(m, encoded_layer_gate={"result": "FAIL"}),
                        "encoded_layer_gate") != d, True)
    case("an identifier length in the evidence changes",
         finding_digest(dict(m, encoded_layer_finding=dict(find, identifier_lengths=[12])),
                        "encoded_layer_gate") != d, True)
    case("the number of occurrences changes",
         finding_digest(dict(m, encoded_layer_finding=dict(find, occurrences=4)),
                        "encoded_layer_gate") != d, True)
    case("the segment the identifier sits in gets bigger",
         finding_digest(dict(m, encoded_layer_finding=dict(find, segment_lengths=[473603])),
                        "encoded_layer_gate") != d, True)
    case("the evidence disappears entirely",
         finding_digest({k: v for k, v in m.items() if k != "encoded_layer_finding"},
                        "encoded_layer_gate") != d, True)
    case("the same FAIL, asked about a different gate",
         finding_digest(m, "secret_gate") != d, True)
    # The prose keys are IN the digest on purpose. `false_positive_note` carries the measured
    # collision rate a person weighed when they ruled the hit a coincidence; if that figure
    # is re-measured the judgement rests on a number that has moved.
    case("the measured false-positive rate cited in the finding changes",
         finding_digest(dict(m, encoded_layer_finding=dict(find, false_positive_note="1.3%")),
                        "encoded_layer_gate") != d, True)

    print()
    print("=== and must HOLD for each of these ===")
    case("the provenance timestamp moves on a re-stamp",
         finding_digest(dict(m, provenance=dict(m["provenance"],
                                                at="2026-09-07T09:00:00")),
                        "encoded_layer_gate") == d, True)
    case("the scanner build recorded in measured_with moves",
         finding_digest(dict(m, measured_with={"path": "build/lyxbosa",
                                               "sha256_12": "dddddddddddd"}),
                        "encoded_layer_gate") == d, True)
    case("an unrelated gate's verdict moves",
         finding_digest(dict(m, plaintext_gate="FAIL"), "encoded_layer_gate") == d, True)
    # Provenance is pinned by value in the clearance, not folded into the digest, precisely
    # so that these two questions stay separate: "is this the same finding" and "did the
    # gate that produced it move". A digest that answered both could not tell you which.
    case("the tools digest moves (pinned separately, not in the finding digest)",
         finding_digest(dict(m, provenance=dict(m["provenance"], tools="0" * 12)),
                        "encoded_layer_gate") == d, True)
    # The same evidence recorded in the other place it is recorded must read the same.
    cats = {k: v for k, v in m.items() if k != "encoded_layer_finding"}
    cats["gate_categories"] = {"encoded_layer_finding": dict(find)}
    case("evidence found under gate_categories reads identically",
         finding_digest(cats, "encoded_layer_gate") == d, True)

    print()
    print("=== malformed() must name every way a clearance cannot be read ===")
    good = {"gate": "encoded_layer_gate", "finding_digest": d, "by": "cl",
            "at": "2026-09-06T12:00:00", "reason": "a collision, by shape",
            "gate_provenance": {"tools": "aaaaaaaaaaaa", "map": "bbbbbbbbbbbb"}}
    case("a complete clearance", malformed(good) is None, True)
    for k in REQUIRED:
        bad = dict(good)
        bad.pop(k)
        case("missing %s" % k, malformed(bad) is not None, True)
    case("a gate that is not a finding",
         malformed(dict(good, gate="verdict")) is not None, True)
    case("an author of whitespace",
         malformed(dict(good, by="   ")) is not None, True)
    case("not an object at all", malformed("cleared") is not None, True)

    print()
    print("=== applies() ===")
    row = {"sha256": "0" * 64, "sensitivity": ["c2", "identity"], "masking": m,
           "clearances": [good]}
    case("clears the finding it names", applies(good, row, "encoded_layer_gate")[0], True)
    case("does not clear a different gate", applies(good, row, "secret_gate")[0], False)
    case("does not clear on a pii row",
         applies(good, dict(row, sensitivity=["pii"]), "encoded_layer_gate")[0], False)
    case("does not clear on a content row",
         applies(good, dict(row, sensitivity=["content"]), "encoded_layer_gate")[0], False)
    case("every negative answer says why",
         all(applies(good, row, g)[1] for g in CLEARABLE_GATES if g != "encoded_layer_gate"),
         True)
    case("applicable() finds it", applicable(row, "encoded_layer_gate") is good, True)
    case("applicable() returns None where nothing applies",
         applicable(row, "plaintext_gate"), None)
    case("a row with no clearances key reads as none",
         row_clearances({"sha256": "0" * 64}), [])

    print()
    print("=== reasoned_by: recorded and counted, never a hard failure ===")
    # Both directions. A rule that made a missing `reasoned_by` malformed would delete the
    # two superseded records this repository keeps on purpose; a rule that never noticed it
    # would leave the field optional in practice, which is the same as absent.
    reasoned = dict(good, **{REASONED_BY: "an assistant, presented and authorised"})
    case("a clearance without it is still READABLE",
         malformed(good) is None, True)
    case("and still APPLIES", applies(good, row, "encoded_layer_gate")[0], True)
    case("a clearance with it is readable too", malformed(reasoned) is None, True)
    case("adding it does not change what the clearance clears",
         applies(reasoned, dict(row, clearances=[reasoned]), "encoded_layer_gate")[0], True)
    case("unreasoned() counts the one that has none",
         unreasoned(row), [("encoded_layer_gate", "2026-09-06T12:00:00")])
    case("and counts nothing where every clearance carries one",
         unreasoned(dict(row, clearances=[reasoned])), [])
    case("an empty string is not a record",
         unreasoned(dict(row, clearances=[dict(good, **{REASONED_BY: "  "})])) != [], True)
    case("REASONED_BY is deliberately outside REQUIRED",
         REASONED_BY in REQUIRED, False)

    print()
    # Counted, not quoted: a hardcoded total cannot report a case being dropped.
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    sys.exit("usage: clearance.py --selftest   (this module is a library; see the docstring)")
