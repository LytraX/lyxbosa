#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Record a human's decision to clear one gate finding. The only writer of `clearances`.

`clearance.py` holds the rule; this holds the writing, and the two are separate for the
reason `shard-gate.py` and `mask-samples.py` are separate: the thing that decides whether a
record is valid must be readable by someone who is not running the tool that made it.

WHAT THIS REFUSES, AND WHY EACH REFUSAL
---------------------------------------
An escape hatch in a publish gate is the highest-leverage thing in the corpus, so this tool
is written as a list of refusals with a default of no.

  * **a gate that recorded a pass.** Nothing to clear. A clearance written against a passing
    gate would sit dormant until the gate changed its mind, and then silently pre-approve
    whatever it said next - a clearance for a finding that did not exist when it was signed.
  * **a gate whose provenance is not `ok`.** A clearance is pinned to the provenance, so
    writing one against absent or stale provenance produces a record that is inert the
    instant it is written. Refuse at the door rather than let someone believe they decided
    something.
  * **a row carrying `pii` or `content`.** §7.2, and it is checked here as well as in
    `clearance.applies` because a refusal a person can read at the moment they try is worth
    more than one they discover from a gate report later.
  * **a reason that names a customer.** The reason is free text a human types, it lands in
    the index, and the published half of the index is a tracked file. AGENTS.md records five
    separate occasions in one day where a client name went into git through prose - including
    the docstring of the script written to catch it. So the reason is run through the same
    identifier set the masking gate uses, and refused if it matches. This needs the maps, so
    this tool requires them; `shard-gate.py` deliberately does not.
  * **an empty reason, or no author.** The whole point is that the decision has an owner.
  * **a duplicate.** Re-signing the same finding twice is either a mistake or an attempt to
    paper over an inert one, and both want a human to look.

The digest is computed here from the row and never accepted from the command line. A caller
who could supply one could sign a finding they never read.

Additive, and asserted to be: nothing but `clearances` may differ between the row before and
the row after. In particular `publishable` is not written. It is recomputed by
`shard-gate.py --fix`, which is the only thing allowed to compute it (§4.4), and this tool
prints that as the next step rather than doing it.

    corpus/clear-finding.py --index corpus/local/index-local.jsonl \\
        --sha 34bba99dae63 --gate encoded_layer_gate --by cl \\
        --reason "..." --apply
    corpus/clear-finding.py --inject          # the controls
"""
import argparse, copy, datetime, importlib.util, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy   # noqa: E402
import gate_provenance                                                      # noqa: E402
import clearance                                                            # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "vcm_clear", os.path.join(HERE, "verify-content-mask.py"))
VCM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(VCM)

MAPS = [p for p in (VCM.INCIDENT_MAP, VCM.LEGACY_MAP) if os.path.exists(p)]


def _load_shard_gate():
    spec = importlib.util.spec_from_file_location(
        "shard_gate_clear", os.path.join(HERE, "shard-gate.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SG = _load_shard_gate()


def reason_names_a_customer(reason, ids):
    """Which identifier shapes the reason matches. Returns SHAPES, never the names.

    Same discipline as everywhere else in this tree: the finding is reported as "a
    six-character label", because a tool that prints the collision to explain the refusal
    has put the name in a terminal, a log and, if anyone pastes it, a commit message.
    """
    low = reason.lower()
    hits = []
    for ident in ids:
        at = low.find(ident)
        if at < 0:
            continue
        if not VCM.V._is_a_leak(low, ident, at):
            continue
        hits.append(len(ident))
    return sorted(set(hits))


def build(row, gate, by, reason, ids, prov_maps=MAPS):
    """(clearance, refusal). Exactly one is None."""
    if gate not in clearance.CLEARABLE_GATES:
        return None, ("%r is not a recorded gate result. Only a finding can be cleared, and "
                      "only %s are findings. A verdict, a local_only hold or an unapplied "
                      "masking pass is work to do, not evidence to judge."
                      % (gate, "/".join(clearance.CLEARABLE_GATES)))
    if not by or not by.strip():
        return None, "an author is required: a clearance without one has no owner"
    if not reason or not reason.strip():
        return None, "a reason is required: the record has to say what was read"
    tags = set(row.get("sensitivity") or [])
    blocked = tags & clearance.NEVER_CLEARABLE_TAGS
    if blocked:
        return None, ("row carries %s. §7.2 says those are never publishable by any route, "
                      "and this is a route." % "/".join(sorted(blocked)))
    m = row.get("masking") or {}
    if gate not in m:
        return None, "row records no %s result, so there is no finding to clear" % gate
    verdict, _detail = SG.gate_result(m[gate], boolean=(gate == "detection_survived"))
    if verdict == "pass":
        return None, ("%s recorded a pass; there is nothing to clear, and a clearance signed "
                      "against a pass would pre-approve whatever the gate says next" % gate)
    state, detail = gate_provenance.verify(m.get("provenance"), prov_maps)
    if state != "ok":
        return None, ("gate provenance is %s (%s). A clearance is a judgement about what a "
                      "particular gate said; re-measure first, then judge what it says."
                      % (state, detail))
    shapes = reason_names_a_customer(reason, ids)
    if shapes:
        return None, ("the reason matches %d identifier(s) from the maps, of length %s. "
                      "Describe a collision by shape, never by spelling it out - the index "
                      "is a tracked file." % (len(shapes), shapes))
    digest = clearance.finding_digest(m, gate)
    pin = {"tools": m["provenance"].get("tools"), "map": m["provenance"].get("map")}
    # THE DUPLICATE TEST USED TO REFUSE THE ONE ACT THE MECHANISM REQUIRES.
    #
    # It compared the gate and the digest and stopped there, so a clearance that had gone
    # INERT because the tools digest moved - the state this design deliberately produces,
    # and the state both clearances on `34bba99dae63` were in - could never be re-signed.
    # The refusal even named the case ("an inert one being papered over") while being unable
    # to tell it from a genuine duplicate: the finding is the same, and what has changed is
    # the pin, which the test did not read. A check blind to the thing it names.
    #
    # So the comparison is (gate, finding, PIN). Same finding under the same pin is a
    # duplicate and refused. Same finding under a pin that has since moved is the re-signing
    # this mechanism is built to demand, and it is appended - never edited over the old one,
    # because the record of who judged what under which gate is a history and not a slot.
    superseded = None
    for existing in clearance.row_clearances(row):
        if not (isinstance(existing, dict) and existing.get("gate") == gate
                and existing.get("finding_digest") == digest):
            continue
        if clearance._prov_key(existing.get("gate_provenance")) == pin:
            return None, ("this exact finding already carries a clearance by %r, judged "
                          "against the provenance the row records now; re-signing it would "
                          "be a duplicate rather than a re-judgement"
                          % existing.get("by"))
        superseded = existing
    out = {"gate": gate,
           "finding_digest": digest,
           "by": by.strip(),
           "at": datetime.datetime.now().replace(microsecond=0).isoformat(),
           "reason": reason.strip(),
           "gate_provenance": pin}
    if superseded is not None:
        # Which record this one re-signs, so two clearances over one finding read as a
        # history rather than as a pair of independent judgements.
        out["supersedes"] = {"at": superseded.get("at"), "by": superseded.get("by"),
                             "gate_provenance": superseded.get("gate_provenance")}
    return out, None


def assert_additive(before, after):
    """None, or what changed that should not have."""
    b, a = copy.deepcopy(before), copy.deepcopy(after)
    b.pop("clearances", None)
    a.pop("clearances", None)
    if b != a:
        moved = sorted({k for k in set(b) | set(a) if b.get(k) != a.get(k)})
        return "changed %s outside `clearances`" % "/".join(moved)
    n_before = len(clearance.row_clearances(before))
    n_after = len(clearance.row_clearances(after))
    if n_after != n_before + 1:
        return "clearances went %d -> %d, expected exactly one added" % (n_before, n_after)
    if clearance.row_clearances(after)[:n_before] != clearance.row_clearances(before):
        return "an existing clearance was rewritten"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=os.path.join(HERE, "local", "index-local.jsonl"))
    ap.add_argument("--sha", help="full sha256 or a unique prefix")
    ap.add_argument("--gate", help="/".join(clearance.CLEARABLE_GATES))
    ap.add_argument("--by", help="who is deciding")
    ap.add_argument("--reason", help="what they read, by shape and never by name")
    ap.add_argument("--apply", action="store_true", help="write it; default is a dry run")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()

    if a.inject:
        return inject()
    for req in ("sha", "gate", "by", "reason"):
        if not getattr(a, req):
            return ap.error("--%s is required" % req)
    if not MAPS:
        return ap.error("the pseudonym maps are not present. This tool refuses to write a "
                        "free-text reason it cannot scan for customer identifiers.")
    ids, _keep = VCM.load_ids(MAPS)
    print("maps                    : %s" % ", ".join(os.path.basename(m) for m in MAPS))
    print("identifiers to refuse   : %d" % len(ids))

    def one(rows):
        hits = [r for r in rows if r["sha256"].startswith(a.sha)]
        if len(hits) != 1:
            sys.exit("--sha %r matched %d rows in %s" % (a.sha, len(hits), a.index))
        return hits[0]

    rows = read_jsonl(a.index)
    row = one(rows)
    c, refusal = build(row, a.gate, a.by, a.reason, ids)
    print("row                     : %s" % row["sha256"][:12])
    print("gate                    : %s" % a.gate)
    if refusal:
        print()
        sys.exit("REFUSED: %s" % refusal)
    print("finding digest          : %s" % c["finding_digest"])
    print("pinned to provenance    : %s" % json.dumps(c["gate_provenance"], sort_keys=True))
    print("by / at                 : %s / %s" % (c["by"], c["at"]))

    if not a.apply:
        print()
        print("dry run: nothing written. Re-run with --apply.")
        return 0

    with index_lock(a.index):
        # Re-read inside the lock. The row may have moved between the dry run and now, and a
        # digest computed against a stale copy would pin a finding that no longer exists.
        rows = read_jsonl(a.index)
        row = one(rows)
        c, refusal = build(row, a.gate, a.by, a.reason, ids)
        if refusal:
            sys.exit("REFUSED on re-read under the lock: %s" % refusal)
        before = copy.deepcopy(row)
        row.setdefault("clearances", []).append(c)
        bad = assert_additive(before, row)
        if bad:
            sys.exit("refusing to write: %s" % bad)
        write_jsonl_atomic(a.index, rows)
    print()
    print("written. `publishable` is NOT touched here - run")
    print("  corpus/shard-gate.py --fix %s" % os.path.relpath(a.index, os.getcwd()))
    print("which is the only thing allowed to compute it.")
    return 0


# ---------------------------------------------------------------------------------------
# Controls. One per constraint the design claims, and the negative half for each: a refusal
# that refuses everything proves nothing.
# ---------------------------------------------------------------------------------------

def inject():
    fails, ran = [], []

    def case(label, got, want):
        """Counted, not tallied by hand. The total was the literal 19 while the suite ran
        more than 19 cases, so a case added or dropped could not be seen from the report -
        which is the shape of every other defect in this tree."""
        ok = got == want
        ran.append(label)
        print("  %-62s %-9s %s" % (label, got, "ok" if ok else "WRONG (wanted %s)" % want))
        if not ok:
            fails.append(label)

    NOW = gate_provenance.stamp(MAPS)
    PROV = {"tools": NOW["tools"], "map": NOW["map"]}

    def row(**kw):
        m = {"applied": True, "plaintext_gate": "PASS", "detection_survived": True,
             "encoded_layer_gate": "FAIL",
             "encoded_layer_finding": {"distinct_identifiers": 1, "occurrences": 1,
                                       "identifier_lengths": [6], "positions": ["begins"]},
             "provenance": dict(NOW)}
        m.update(kw.pop("masking", {}))
        r = {"sha256": "0" * 64, "verdict": "malicious", "sensitivity": ["c2", "identity"],
             "masking": m}
        r.update(kw)
        return r

    ids = set()
    print("=== the writer must REFUSE these ===")
    case("a gate that is not a recorded gate result",
         "refused" if build(row(), "pii", "cl", "x", ids)[1] else "written", "refused")
    case("a gate the row records as a pass",
         "refused" if build(row(masking={"encoded_layer_gate": "PASS"}),
                            "encoded_layer_gate", "cl", "x", ids)[1] else "written", "refused")
    case("a gate the row does not record at all",
         "refused" if build(row(), "secret_gate", "cl", "x", ids)[1] else "written", "refused")
    case("a row carrying pii",
         "refused" if build(row(sensitivity=["pii", "identity"]),
                            "encoded_layer_gate", "cl", "x", ids)[1] else "written", "refused")
    case("a row carrying content",
         "refused" if build(row(sensitivity=["content"]),
                            "encoded_layer_gate", "cl", "x", ids)[1] else "written", "refused")
    case("provenance absent",
         "refused" if build(row(masking={"provenance": None}),
                            "encoded_layer_gate", "cl", "x", ids)[1] else "written", "refused")
    case("provenance stale",
         "refused" if build(row(masking={"provenance": {"tools": "0" * 12, "map": None}}),
                            "encoded_layer_gate", "cl", "x", ids)[1] else "written", "refused")
    case("no author", "refused" if build(row(), "encoded_layer_gate", "  ", "x", ids)[1]
         else "written", "refused")
    case("no reason", "refused" if build(row(), "encoded_layer_gate", "cl", "   ", ids)[1]
         else "written", "refused")
    # The reason scan, against a synthetic identifier rather than a real one - the whole
    # point of the check is that a real one must never be typed into a tracked file, and
    # that includes this control.
    case("a reason that names an identifier",
         "refused" if build(row(), "encoded_layer_gate", "cl",
                            "collides with zzqqvv in a function table",
                            {"zzqqvv"})[1] else "written", "refused")
    c_first, _ = build(row(), "encoded_layer_gate", "cl", "read it, a collision", ids)
    dup = row(clearances=[c_first])
    case("the same finding signed twice",
         "refused" if build(dup, "encoded_layer_gate", "cl", "again", ids)[1]
         else "written", "refused")

    print()
    print("=== and WRITE this one ===")
    c, refusal = build(row(), "encoded_layer_gate", "cl",
                       "a 6-character label at the start of a token in a function table", ids)
    case("a real finding, current provenance, a named author",
         "written" if c else "refused: %s" % refusal, "written")
    if c:
        case("it pins the finding digest", "yes" if c["finding_digest"] else "no", "yes")
        case("it pins the gate provenance",
             "yes" if c["gate_provenance"] == PROV else "no", "yes")
        case("it carries who and when", "yes" if c["by"] and c["at"] else "no", "yes")
        case("clearance.malformed reads it",
             "yes" if clearance.malformed(c) is None else clearance.malformed(c), "yes")

    print()
    print("=== an INERT clearance must be re-signable, and a live one must not ===")
    # The duplicate test compared the gate and the digest and not the pin, so the one act
    # this design demands - re-judging a finding whose gate provenance has moved - was
    # refused by the tool that exists to record it. Both clearances on `34bba99dae63` were
    # in exactly that state, and the refusal it produced named the case it could not see.
    #
    # Both directions, because a rule that refuses everything and one that refuses nothing
    # are indistinguishable from a green run.
    old_pin = {"tools": "0" * 12, "map": NOW["map"]}
    stale_c = dict(c_first, gate_provenance=old_pin, at="2026-01-01T00:00:00", by="cl")
    inert_row = row(clearances=[stale_c])
    resigned, why = build(inert_row, "encoded_layer_gate", "cl",
                          "re-read against the current gate, same collision", ids)
    case("the same finding under a pin that has since moved",
         "written" if resigned else "refused: %s" % why, "written")
    if resigned:
        case("it pins the provenance the row records NOW",
             "yes" if resigned["gate_provenance"] == PROV else "no", "yes")
        case("and it names the record it re-signs",
             "yes" if resigned.get("supersedes", {}).get("gate_provenance") == old_pin
             else "no", "yes")
        # The property that matters is not the write, it is that the row is cleared again.
        after_row = row(clearances=[stale_c, resigned])
        case("the re-signed clearance actually applies",
             "yes" if clearance.applies(resigned, after_row, "encoded_layer_gate")[0]
             else "no", "yes")
        case("and the superseded one is still inert, not edited away",
             "yes" if (not clearance.applies(stale_c, after_row, "encoded_layer_gate")[0]
                       and after_row["clearances"][0] == stale_c) else "no", "yes")
    # The negative half, restated where it can be seen next to its opposite: a live
    # clearance for the same finding under the SAME pin is a duplicate and stays refused.
    live_row = row(clearances=[c_first])
    case("the same finding under the pin the row already records",
         "refused" if build(live_row, "encoded_layer_gate", "cl", "again", ids)[1]
         else "written", "refused")
    case("and the refusal says it is a duplicate rather than a re-judgement",
         "yes" if "duplicate" in (build(live_row, "encoded_layer_gate", "cl", "again",
                                        ids)[1] or "") else "no", "yes")
    # A first clearance carries no `supersedes` at all: the key must mean something.
    case("a first clearance names nothing it supersedes",
         "supersedes" in (c or {}), False)

    print()
    print("=== the write must be additive, and must not compute publishability ===")
    base = row()
    after = copy.deepcopy(base)
    after.setdefault("clearances", []).append(c)
    case("nothing outside `clearances` moves",
         assert_additive(base, after) or "clean", "clean")
    after2 = copy.deepcopy(after)
    after2["publishable"] = True
    after2["clearances"] = list(after["clearances"]) + [dict(c)]
    case("writing publishable alongside is caught",
         "caught" if assert_additive(after, after2) else "MISSED", "caught")

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
