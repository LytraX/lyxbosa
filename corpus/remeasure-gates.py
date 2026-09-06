#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Write the verdict a re-measurement produces onto a row whose record disagrees with it.

`verify-and-stamp.py` deliberately cannot do this. Its whole contract is that it stamps
provenance **only where the current gate returns what the row records**, and refuses the row
where it does not - so a row whose predicate has since moved gets no stamp and blocks on
`gate results have no usable provenance` rather than on the finding. That is the right
default and it left one thing undone: the finding itself is never written, so the row records
a `PASS` that nothing believes and there is no finding for anyone to judge.

That is not a gap to paper over inside the stamper. It is a different act with a different
owner, so it is a different tool:

  * stamping says *these tools produced this verdict*. Additive, safe, and run in batches.
  * re-measuring says *the verdict has changed and here is the new one*. It rewrites a
    recorded measurement in an index a stranger reads, and on the published half it can flip
    a `publishable`. It takes one `--sha` at a time and an author, and it refuses to run
    where nothing moved.

WHY THE ORDER MATTERS, AND WHY IT IS FIXED
------------------------------------------
A human clearance is keyed to a recorded finding. `clear-finding.py` refuses a gate that
records a pass - "a clearance signed against a pass would pre-approve whatever the gate says
next" - so a row like `3529f0f6b2cd`, which stores `encoded_layer_gate: PASS` while the
current gate returns `FAIL`, cannot be cleared at all until the FAIL is on the row. Judging a
finding the record does not hold is the same defect as trusting a `PASS` nothing measured,
one level up. So: re-measure, and only then judge what it says.

WHAT IT WRITES, AND WHAT IT REFUSES
-----------------------------------
Writes the gate verdicts and finding profiles **that moved**, `provenance`, and a
`remeasured` record naming the author, the moment, the sha256 of the bytes it read and what
each moved key was before. Nothing else moves and the tool proves it rather than trusting
itself. It refuses:

  * bytes that do not hash to what was expected. A re-measurement against the wrong bytes is
    worse than none, because it looks like one;
  * a row where every recorded verdict AND every recorded finding already agrees -
    `verify-and-stamp.py` is the tool for that, and running this instead would rewrite a
    record that did not change;
  * a finding block carrying a human `decision`, which is not a gate measurement and not
    this tool's to rewrite or remove;
  * `--apply` without an author.

"THAT MOVED", AND WHY IT IS NOT "ALL OF THEM"
---------------------------------------------
It used to write every verdict and every finding it measured, which was harmless while it
only ran on rows whose verdict had moved. Now that a moved FINDING is also a reason to run,
writing the lot would rewrite records nothing re-decided - and two of those rewrites are not
harmless. Normalising a recorded `{"result": "FAIL"}` into the string `"FAIL"` moves
`clearance.finding_digest` and takes a human clearance with it, for a verdict whose class
never changed; and the finding-removal branch, which correctly drops a profile when its gate
goes back to PASS, would delete a human decision record sitting under `encoded_layer_finding`
on a row whose gate already passes. So the write is scoped to the keys `moved()` reports.

It does NOT compute `publishable`. `shard-gate.py --fix` is the only thing allowed to
(§4.4), and it is printed as the next step.

    corpus/remeasure-gates.py --index corpus/index.jsonl --sha 3529f0f6b2cd \\
        --bytes <path to the bytes the row stands behind> --expect-sha256 <hex>
    corpus/remeasure-gates.py --inject
"""
import argparse, copy, datetime, hashlib, importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy   # noqa: E402
import gate_provenance                                                     # noqa: E402
import gate_evidence                                                       # noqa: E402
import finding_notes                                                       # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "vcm_remeasure", os.path.join(HERE, "verify-content-mask.py"))
VCM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(VCM)

_sgspec = importlib.util.spec_from_file_location(
    "sg_remeasure", os.path.join(HERE, "shard-gate.py"))
SG = importlib.util.module_from_spec(_sgspec)
_sgspec.loader.exec_module(SG)

MAPS = [p for p in (VCM.INCIDENT_MAP, VCM.LEGACY_MAP) if os.path.exists(p)]

GATES = ("plaintext_gate", "encoded_layer_gate")
FINDINGS = {"plaintext_gate": "plaintext_finding",
            "encoded_layer_gate": "encoded_layer_finding"}
SECRET = "secret_gate"
RECORD_KEY = "remeasured"
# `masking` keys this may write. Detection parity stays out: it is the scanner's
# measurement, provenanced by `measured_with` rather than by the tools digest, and this tool
# runs no scanner. The SECRET gate is now in, because it is produced by a module inside
# `gate_provenance.TOOLS` and was therefore always covered by the stamp this tool writes -
# it was left out only because the tool was given one file and the gate is a differential
# over two. `--before` supplies the other one; without it a row that records a secret gate
# is REFUSED rather than re-measured on two thirds of its record.
WRITABLE = set(GATES) | set(FINDINGS.values()) | {SECRET, "secret_literals",
                                                  "provenance", RECORD_KEY}
# The evidence keys, and the second place the index records them. A finding lives under
# `masking` on some rows and under `masking.gate_categories` on others - `plaintext_finding`
# is in `gate_categories` alone on all five rows that record one - and a re-measurement that
# wrote only the first would leave the second holding a superseded copy of the same finding.
# `gate_categories` is therefore writable, but only for these keys: `assert_scoped` checks
# inside it rather than waving the whole block through.
EVIDENCE = dict(FINDINGS, **{SECRET: "secret_literals"})
CATEGORIES = "gate_categories"
WRITABLE |= {CATEGORIES}
# A gate finding block that carries this key is not a gate finding. Two published rows
# record a human decision under `encoded_layer_finding` - an adjudication of one address,
# with evidence that exists nowhere else in the corpus - on rows whose gate now reads PASS.
# The finding-removal branch below would have deleted both the moment anything else on the
# row moved. See `shard-gate.py`'s decision-without-resolution invariant.
HUMAN_DECISION = "decision"


def recorded_form(key, finding):
    """The finding as it is RECORDED, which is not always the whole thing measured.

    THE TWO WRITERS HAD FORKED THE SCHEMA AND NOTHING SAID SO
    ----------------------------------------------------------
    `mask-samples.py` records a named subset of `secret_gate`'s twelve measured fields.
    `build()` wrote `findings[key]` whole - everything the gate returned bar the verdict -
    which is thirteen, the extra being `note`, a constant string of prose. Measured today
    over both halves: 124 rows at twelve keys, 8 at thirteen, and all 8 of the thirteens
    are rows this tool rewrote. Every one of them was created here.

    That matters because `gate_evidence.compare_gate` compares the keys the ROW records, a
    choice measured as safe against "a note field holding a constant string" and not against
    two schemas. Two rows in the same condition were being compared over different key sets,
    and the only thing keeping the two answers identical is that the note happens to be a
    literal inside a `gate_provenance.TOOLS` module, so its text cannot move without every
    stamp going stale in the same instant. That is a coupling to check, not to rely on.

    So the recorded form is narrowed here to the same tuple `mask-samples.py` writes, taken
    from `gate_evidence.RECORDED_SECRET_KEYS` rather than restated, and asserted equal to
    that module's own AST by `gate_evidence --inject`. Consequence, stated rather than
    hidden: a row that currently records thirteen keys drops to twelve the next time this
    tool legitimately rewrites its secret finding, which moves `clearance.finding_digest`
    for that gate. That can only happen on a row whose evidence moved - `build()` writes
    nothing where nothing moved - and a moved evidence field moves the digest anyway.

    Other findings are recorded whole. `plaintext_finding` and `encoded_layer_finding` carry
    `false_positive_note`, which is NOT the same kind of prose: it states a measured rate a
    human weighed, `clearance.finding_digest` covers it deliberately, and dropping it would
    remove the qualifier from every judgement keyed to it.
    """
    if key != "secret_literals" or not isinstance(finding, dict):
        return finding
    return {k: finding[k] for k in gate_evidence.RECORDED_SECRET_KEYS if k in finding}


def measure(data, before=None):
    """(verdicts, findings) from the current gate over these bytes.

    `before` is the pre-masking bytes. Where it is given the differential secret gate is
    re-measured too and lands in `verdicts[SECRET]` with its evidence under
    `findings["secret_literals"]`; where it is not, neither key appears at all - absent and
    `PASS` must not be the same answer.
    """
    _ok, g = VCM.gate(data, *VCM.load_ids(MAPS))
    verdicts = {k: g[k] for k in GATES}
    findings = {FINDINGS[k]: g[FINDINGS[k]] for k in GATES
                if FINDINGS[k] in g and g[k] != "PASS"}
    if before is not None:
        _sok, sres = VCM.secret_gate(before, data)
        verdicts[SECRET] = sres[SECRET]
        findings["secret_literals"] = {k: v for k, v in sres.items() if k != SECRET}
    return verdicts, findings


def moved(row, verdicts, findings=None):
    """Which recorded findings the re-measurement disagrees with, and how.

    THE VERDICT WAS ONLY HALF THE QUESTION
    ---------------------------------------
    This compared verdict CLASSES and nothing else, so a row whose payload had gone stale
    beneath an unmoved verdict read as "nothing moved" and was refused - correctly by its own
    rule, and wrongly about the row. `verify-and-stamp.py` stamped the same row for the
    mirror-image reason. Both now compare through `gate_evidence.py`, so the two tools cannot
    disagree about what "the row records this" means.

    The verdict is still compared by class rather than by bytes: a dict-form record and the
    string form of the same verdict are not a change, and six local rows carry the older
    dict schema that a byte comparison would rewrite while reporting a movement that did not
    happen.

    Each entry carries `cause` - `verdict-moved` or `evidence-moved` - because the repairs
    differ and §8 counts causes rather than symptoms.

    A gate the row does not record is not a movement and is not reported, where the old
    comparison read the absent value as `unreadable` and called it one. That narrowing is
    stated rather than incidental: it means this tool no longer ADDS a gate result a row
    never had, which is `mask-samples.py`'s job and not a re-measurement's. It changes
    nothing today - all 142 masked rows record both identifier gates, and 132 of them
    record the secret gate.
    """
    m = row.get("masking") or {}
    findings = findings or {}
    today = {}
    for k in list(GATES) + ([SECRET] if SECRET in verdicts else []):
        today[k] = (verdicts[k], findings.get(EVIDENCE[k]))
    _state, per = gate_evidence.compare(m, today, SG.gate_result)
    out = {}
    for k, (state, det) in per.items():
        if state not in ("verdict-moved", "evidence-moved"):
            continue
        out[k] = {"cause": state,
                  "was": m.get(k), "was_class": det["verdict"]["recorded"],
                  "now": verdicts[k], "now_class": det["verdict"]["today"],
                  "evidence_fields": sorted(det.get("evidence") or {})}
    return out


def _where_recorded(masking, key):
    """The blocks on this row that hold this finding. Both, where both do.

    A row records `plaintext_finding` under `gate_categories` and `encoded_layer_finding`
    under `masking`, and three rows record the encoded one in both places. Writing only one
    of two copies leaves the other holding a superseded finding that reads exactly like a
    current one, which is the defect this whole tool is about, one level down.
    """
    out = []
    if key in masking:
        out.append(masking)
    cats = masking.get(CATEGORIES)
    if isinstance(cats, dict) and key in cats:
        out.append(cats)
    return out


def build(row, data, by, at=None, before=None):
    """(after_row, refusal). Exactly one is None."""
    if not by or not by.strip():
        return None, "an author is required: a rewritten measurement has an owner"
    m0 = row.get("masking") or {}
    if SECRET in m0 and before is None:
        return None, ("the row records a secret_gate and no --before bytes were given. That "
                      "gate is a differential and cannot be re-measured from one file; "
                      "stamping the other two while leaving it is the two-file question "
                      "asked about one file, which is the shape AGENTS.md opens with")
    verdicts, findings = measure(data, before)
    delta = moved(row, verdicts, findings)
    if not delta:
        return None, ("every recorded verdict and every recorded finding already agrees "
                      "with the current gate; verify-and-stamp.py is the tool for that, and "
                      "rewriting the record here would move a measurement that did not "
                      "change")
    # A block carrying a human decision is not a gate finding, and this tool rewrites gate
    # findings. Refused whole rather than skipped, because a partial re-measurement that
    # silently steps around one key is the thing every other refusal here exists to stop.
    for gate in sorted(delta):
        rec = gate_evidence.evidence_for(m0, gate).get(EVIDENCE[gate])
        if isinstance(rec, dict) and HUMAN_DECISION in rec:
            return None, ("masking.%s carries a human %r and is a recorded adjudication "
                          "rather than a gate finding; a re-measurement may not rewrite or "
                          "remove one" % (EVIDENCE[gate], HUMAN_DECISION))
    after = copy.deepcopy(row)
    m = after.setdefault("masking", {})
    keys = sorted(delta)
    was = {k: m.get(k) for k in keys}
    was_evidence = {EVIDENCE[k]: gate_evidence.evidence_for(m, k).get(EVIDENCE[k])
                    for k in keys}
    for k in keys:
        # Only a verdict whose CLASS moved is rewritten. Restating an agreeing verdict in
        # the canonical shape would move `clearance.finding_digest` on a dict-form record
        # for a decision nobody took.
        if delta[k]["cause"] == "verdict-moved":
            m[k] = verdicts[k]
        key = EVIDENCE[k]
        if key in findings:
            for block in (_where_recorded(m, key) or [m]):
                block[key] = recorded_form(key, findings[key])
        else:
            # A finding belongs to a failing verdict. When a gate goes back to PASS its
            # finding has to GO, or the row keeps evidence for a verdict it no longer
            # records - the stale-record defect this tool repairs, in the other direction.
            for block in _where_recorded(m, key):
                block.pop(key, None)
    m["provenance"] = gate_provenance.stamp(MAPS)
    m[RECORD_KEY] = {
        "by": by.strip(),
        "at": (at or datetime.datetime.now().replace(microsecond=0)).isoformat(),
        "bytes_sha256": hashlib.sha256(data).hexdigest(),
        "before_bytes_sha256": (hashlib.sha256(before).hexdigest()
                                if before is not None else None),
        "was": was,
        "now": {k: m.get(k) for k in keys},
        # What moved, per key, so a reader can tell a re-decided verdict from a re-measured
        # payload without diffing two index revisions.
        "cause": {k: delta[k]["cause"] for k in keys},
        "evidence_fields_moved": {k: delta[k]["evidence_fields"] for k in keys
                                  if delta[k]["evidence_fields"]},
        "was_evidence": was_evidence,
        "why": ("the record and the current gate disagreed about the verdict, the finding "
                "beneath it, or both; the sample did not change, the predicate did, and a "
                "clearance cannot be keyed to a finding the record does not hold"),
    }
    return after, None


def assert_scoped(before, after):
    """None, or what changed that should not have."""
    for k in set(before) | set(after):
        if k == "masking":
            continue
        if before.get(k) != after.get(k):
            return "%s changed, which is outside masking" % k
    b, a = before.get("masking") or {}, after.get("masking") or {}
    for k in set(b) | set(a):
        if b.get(k) == a.get(k):
            continue
        if k not in WRITABLE:
            return "masking.%s changed, which is not this tool's to write" % k
    # `gate_categories` is writable only for the findings it holds. Waving the whole block
    # through because one key inside it may move is how a scope assertion stops asserting
    # anything: it also carries whatever a future pass records there.
    bc, ac = b.get(CATEGORIES) or {}, a.get(CATEGORIES) or {}
    for k in set(bc) | set(ac):
        if bc.get(k) != ac.get(k) and k not in set(EVIDENCE.values()):
            return ("masking.%s.%s changed, which is not this tool's to write"
                    % (CATEGORIES, k))
    if "publishable" in set(before) | set(after) and before.get("publishable") != after.get("publishable"):
        return "wrote publishable, which only shard-gate.py may compute"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=os.path.join(HERE, "index.jsonl"))
    ap.add_argument("--sha", help="full sha256 or a unique prefix")
    ap.add_argument("--bytes", dest="bytes_path",
                    help="the bytes the row stands behind - for a published row, the file "
                         "inside the shard, not the source blob")
    ap.add_argument("--expect-sha256", default=None,
                    help="what those bytes must hash to. Required unless the row records a "
                         "masked_sha256 of its own")
    ap.add_argument("--before", dest="before_path", default=None,
                    help="the PRE-masking bytes. Required where the row records a "
                         "secret_gate: that gate is a differential and one file cannot "
                         "answer it")
    ap.add_argument("--expect-before-sha256", default=None,
                    help="what the --before bytes must hash to. Defaults to the row's own "
                         "sha256, which is what the pre-masking bytes are")
    ap.add_argument("--by", help="who is re-measuring")
    ap.add_argument("--apply", action="store_true", help="write; default is a dry run")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    for req in ("sha", "bytes_path"):
        if not getattr(a, req):
            return ap.error("--%s is required unless --inject" % req.replace("_path", ""))

    def one(rows):
        hits = [r for r in rows if r["sha256"].startswith(a.sha)]
        if len(hits) != 1:
            sys.exit("--sha %r matched %d rows in %s" % (a.sha, len(hits), a.index))
        return hits[0]

    rows = read_jsonl(a.index)
    row = one(rows)
    with open(a.bytes_path, "rb") as fh:
        data = fh.read()
    got = hashlib.sha256(data).hexdigest()
    want = a.expect_sha256 or (row.get("masking") or {}).get("masked_sha256")
    if not want:
        sys.exit("the row records no masked_sha256, so --expect-sha256 is required: a "
                 "re-measurement against unidentified bytes looks exactly like one against "
                 "the right bytes")
    if not got.startswith(want):
        sys.exit("the bytes hash to %s and were expected to hash to %s; refusing"
                 % (got[:16], want[:16]))

    print("index                   : %s" % a.index)
    print("row                     : %s" % row["sha256"][:12])
    print("bytes                   : %s (%d bytes, sha %s)"
          % (os.path.basename(a.bytes_path), len(data), got[:12]))
    pre = None
    if a.before_path:
        with open(a.before_path, "rb") as fh:
            pre = fh.read()
        gotb = hashlib.sha256(pre).hexdigest()
        wantb = a.expect_before_sha256 or row["sha256"]
        if not gotb.startswith(wantb):
            sys.exit("the --before bytes hash to %s and were expected to hash to %s; "
                     "refusing" % (gotb[:16], wantb[:16]))
        print("before bytes            : %s (%d bytes, sha %s)"
              % (os.path.basename(a.before_path), len(pre), gotb[:12]))
    verdicts, fnds = measure(data, pre)
    delta = moved(row, verdicts, fnds)
    m = row.get("masking") or {}
    for k in list(GATES) + ([SECRET] if SECRET in verdicts else []):
        # The cause, not just MOVED: a re-decided verdict and a re-measured payload need
        # different reading, and the row printed `agrees` for the second one until now.
        print("  %-20s recorded=%-8s today=%-8s %s"
              % (k, json.dumps(m.get(k))[:20], verdicts[k],
                 delta[k]["cause"].upper() if k in delta else "agrees"))
        if k in delta and delta[k]["evidence_fields"]:
            for f in delta[k]["evidence_fields"]:
                was = gate_evidence.evidence_for(m, k).get(EVIDENCE[k], {}).get(f)
                now = (fnds.get(EVIDENCE[k]) or {}).get(f)
                print("      %-40s %s -> %s"
                      % (f, json.dumps(was)[:48], json.dumps(now)[:48]))
    after, refusal = build(row, data, a.by or "-", before=pre)
    if refusal and not a.by:
        # Distinguish "nothing to do" from "you forgot the author", so a dry run without
        # --by still reports the measurement rather than an argument error.
        if "author is required" not in refusal:
            print()
            print("REFUSED: %s" % refusal)
            return 1
    elif refusal:
        print()
        print("REFUSED: %s" % refusal)
        return 1
    if after is not None:
        for k in FINDINGS.values():
            if k in (after.get("masking") or {}):
                f = {kk: vv for kk, vv in after["masking"][k].items()
                     if kk not in ("note", "false_positive_note")}
                print("  finding %-12s %s" % (k, json.dumps(f, sort_keys=True)))

    if not a.apply:
        print()
        print("dry run: nothing written. Re-run with --by <who> --apply.")
        return 0
    if not a.by:
        return ap.error("--by is required to write")

    at = datetime.datetime.now().replace(microsecond=0)
    with index_lock(a.index):
        rows = read_jsonl(a.index)
        n_before = len(rows)
        row = one(rows)
        after, refusal = build(row, data, a.by, at, before=pre)
        if refusal:
            sys.exit("REFUSED on re-read under the lock: %s" % refusal)
        bad = assert_scoped(row, after)
        if bad:
            sys.exit("refusing to write: %s" % bad)
        rows[rows.index(row)] = after
        if len(rows) != n_before:
            sys.exit("row count moved %d -> %d" % (n_before, len(rows)))
        write_jsonl_atomic(a.index, rows)
    print()
    print("written. `publishable` is NOT touched here - run")
    print("  corpus/shard-gate.py --fix %s" % os.path.relpath(a.index, os.getcwd()))
    print("which is the only thing allowed to compute it.")
    return 0


# ---------------------------------------------------------------------------------------
# Controls. Real bytes through the real gate, because the thing under test is what happens
# when a recorded verdict and a live measurement disagree.
# ---------------------------------------------------------------------------------------

def inject():
    fails = []
    ran = []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-64s %-22s %s" % (label, str(got)[:22],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    ids, keep = VCM.load_ids(MAPS)
    longest = max((i for i in ids if len(i) >= 6), key=len, default=None)
    clean = b"<?php\n$a = 'wp-content/plugins/akismet/index.php';\n$b = 1;\n"
    import base64 as _b64
    leaky = clean + b"$e = '" + _b64.b64encode(
        ("/home/%s/public_html/index.php" % (longest or "acct01")).encode()) + b"';\n"

    def row(**kw):
        m = {"applied": True, "plaintext_gate": "PASS", "encoded_layer_gate": "PASS",
             "detection_survived": True, "rules_before": ["X1"], "rules_after": ["X1"]}
        m.update(kw.pop("masking", {}))
        r = {"sha256": "0" * 64, "verdict": "malicious", "sensitivity": ["c2"], "masking": m}
        r.update(kw)
        return r

    print("=== it must REFUSE these ===")
    case("a row every verdict already agrees with",
         "refused" if build(row(), clean, "cl")[1] else "written", "refused")
    case("no author",
         "refused" if build(row(), leaky, "  ")[1] else "written", "refused")

    print()
    print("=== and WRITE the moved verdict, with the finding beside it ===")
    r0 = row()
    after, refusal = build(r0, leaky, "cl")
    case("a recorded PASS the current gate calls FAIL",
         "written" if after else "refused: %s" % refusal, "written")
    if after:
        m = after["masking"]
        case("the verdict is rewritten", m["encoded_layer_gate"], "FAIL")
        case("the finding is written beside it",
             "encoded_layer_finding" in m, True)
        case("the finding names no identifier",
             (longest or "").lower() not in json.dumps(m["encoded_layer_finding"]).lower(),
             True)
        case("provenance is stamped with it", bool(m["provenance"].get("tools")), True)
        case("the record says what it was", m[RECORD_KEY]["was"]["encoded_layer_gate"],
             "PASS")
        case("the record identifies the bytes it read",
             m[RECORD_KEY]["bytes_sha256"] == hashlib.sha256(leaky).hexdigest(), True)
        case("nothing outside masking's own keys moves",
             assert_scoped(r0, after) or "clean", "clean")
        case("the scanner's own fields are untouched",
             m["detection_survived"] is True and m["rules_after"] == ["X1"], True)

    print()
    print("=== the secret gate is a differential, so one file cannot answer it ===")
    # The defect this closes: the tool re-measured two of the four recorded gates and
    # stamped provenance as though it had measured all of them. `secret_gate` is produced by
    # a module inside gate_provenance.TOOLS, so the stamp always claimed it.
    pw_before = b"<?php $user_password = 'abcd1234';\n"
    pw_after = b"<?php $user_password = 'abcd1234';\n"      # masking did not touch it
    sgrow = row(masking={"secret_gate": "PASS",
                         "secret_literals": {"secret_literals_before": 0,
                                             "secret_literals_after": 0}})
    case("a row recording a secret_gate, with no --before bytes",
         "refused" if build(sgrow, pw_after, "cl")[1] else "written", "refused")
    a3, r3 = build(sgrow, pw_after, "cl", before=pw_before)
    case("the same row WITH them", "written" if a3 else "refused: %s" % r3, "written")
    if a3:
        case("the moved secret verdict is written", a3["masking"]["secret_gate"], "FAIL")
        case("its evidence is written beside it",
             a3["masking"]["secret_literals"]["secret_literals_carried_over"], 1)
        case("and the record identifies the BEFORE bytes too",
             a3["masking"][RECORD_KEY]["before_bytes_sha256"]
             == hashlib.sha256(pw_before).hexdigest(), True)
        case("nothing outside masking's own keys moves",
             assert_scoped(sgrow, a3) or "clean", "clean")
    # The negative half: a row that records NO secret gate is not forced to supply bytes it
    # has no reason to have, and no secret key appears out of nowhere.
    a4, _r4 = build(row(), leaky, "cl")
    case("a row with no secret_gate needs no --before", "written" if a4 else "refused",
         "written")
    case("and gains no secret_gate from a re-measurement that could not take one",
         "secret_gate" in (a4 or {}).get("masking", {}), False)

    print()
    print("=== a verdict going back to PASS must take its finding with it ===")
    stale = row(masking={"encoded_layer_gate": "FAIL",
                         "encoded_layer_finding": {"occurrences": 9}})
    after2, refusal2 = build(stale, clean, "cl")
    case("a recorded FAIL the current gate calls PASS",
         "written" if after2 else "refused: %s" % refusal2, "written")
    if after2:
        case("the superseded finding is removed",
             "encoded_layer_finding" not in after2["masking"], True)

    print()
    print("=== the dict-form schema must not read as a movement ===")
    # Six local rows record the encoded verdict as {"result": "FAIL", ...}. A byte
    # comparison would rewrite every one of them and report a change that did not happen.
    dictrow = row(masking={"encoded_layer_gate": {"result": "FAIL", "occurrences": 3}})
    case("a dict FAIL against a live FAIL is not a movement",
         "encoded_layer_gate" not in moved(dictrow, {"plaintext_gate": "PASS",
                                                     "encoded_layer_gate": "FAIL"}), True)
    case("a dict FAIL against a live PASS IS a movement",
         "encoded_layer_gate" in moved(dictrow, {"plaintext_gate": "PASS",
                                                 "encoded_layer_gate": "PASS"}), True)

    print()
    print("=== a payload that moved beneath a verdict that did NOT ===")
    # The defect this round arms. `34bba99dae63` records `secret_literals` 1/1/1 where the
    # current gate returns 2/2/2 with FAIL unchanged, so `moved()` saw nothing and this tool
    # refused the one row that needed exactly this repair - while `verify-and-stamp.py`
    # stamped it, for the mirror-image reason.
    _s5, sres5 = VCM.secret_gate(pw_before, pw_after)
    ev5 = {k: v for k, v in sres5.items() if k != SECRET}
    stale_payload = dict(ev5, secret_literals_carried_over=ev5["secret_literals_carried_over"] + 1)
    driftrow = row(masking={"secret_gate": sres5[SECRET], "secret_literals": stale_payload})
    a5, r5 = build(driftrow, pw_after, "cl", before=pw_before)
    case("a recorded payload the current gate would not produce",
         "written" if a5 else "refused: %s" % r5, "written")
    if a5:
        case("the cause is recorded as the payload, not the verdict",
             a5["masking"][RECORD_KEY]["cause"][SECRET], "evidence-moved")
        case("the fresh payload is written",
             a5["masking"]["secret_literals"]["secret_literals_carried_over"],
             ev5["secret_literals_carried_over"])
        case("and the record says which field moved",
             a5["masking"][RECORD_KEY]["evidence_fields_moved"][SECRET],
             ["secret_literals_carried_over"])
        case("nothing outside masking's own keys moves",
             assert_scoped(driftrow, a5) or "clean", "clean")
    # The other direction, which a tool that always rewrites would fail: the same payload
    # re-measured is not a movement and must still be refused.
    samerow = row(masking={"secret_gate": sres5[SECRET], "secret_literals": dict(ev5)})
    case("the same payload, re-measured, is still refused",
         "refused" if build(samerow, pw_after, "cl", before=pw_before)[1] else "written",
         "refused")

    print()
    print("=== a verdict nobody re-decided must not be rewritten in passing ===")
    # Writing every measured verdict was harmless while only a moved verdict could start a
    # run. It is not harmless now: normalising a dict-form record into the canonical string
    # moves `clearance.finding_digest` and takes a human clearance with it.
    import clearance as _clr
    leaky_pw = leaky + pw_before
    _ok6, g6 = VCM.gate(leaky_pw, ids, keep)
    _s6, sres6 = VCM.secret_gate(pw_before, leaky_pw)
    ev6 = {k: v for k, v in sres6.items() if k != SECRET}
    dictverdict = {"result": g6["encoded_layer_gate"], "occurrences": 3}
    mixed = row(masking={"encoded_layer_gate": dictverdict,
                         "encoded_layer_finding": dict(g6["encoded_layer_finding"]),
                         "secret_gate": sres6[SECRET],
                         "secret_literals": dict(
                             ev6, secret_literals_before=ev6["secret_literals_before"] + 1)})
    a6, r6 = build(mixed, leaky_pw, "cl", before=pw_before)
    case("the secret payload moved and the encoded verdict agreed",
         "written" if a6 else "refused: %s" % r6, "written")
    if a6:
        case("the agreeing dict-form verdict is left exactly as recorded",
             a6["masking"]["encoded_layer_gate"], dictverdict)
        case("so the finding digest of the gate nobody re-measured is unmoved",
             _clr.finding_digest(a6["masking"], "encoded_layer_gate")
             == _clr.finding_digest(mixed["masking"], "encoded_layer_gate"), True)
        case("and the digest of the gate that DID move has moved",
             _clr.finding_digest(a6["masking"], SECRET)
             != _clr.finding_digest(mixed["masking"], SECRET), True)

    print()
    print("=== a finding recorded under gate_categories is written THERE ===")
    # `plaintext_finding` lives under `gate_categories` alone on all five rows that record
    # one. Writing only the top-level copy would leave the row holding two findings for one
    # gate, one of them superseded and indistinguishable from a current one.
    # A PLAINTEXT hit, which `leaky` deliberately does not carry - its identifier sits
    # inside a base64 literal - so the finding this case needs has to be produced by bytes
    # that name one in the clear.
    plain_leaky = clean + b"$p = '/home/" + (longest or "acct01").encode() + b"/x.php';\n"
    _ok7, g7 = VCM.gate(plain_leaky, ids, keep)
    cats = row(masking={"plaintext_gate": g7["plaintext_gate"],
                        CATEGORIES: {"plaintext_finding":
                                     dict(g7["plaintext_finding"], occurrences=99)}})
    a7, r7 = build(cats, plain_leaky, "cl")
    case("a stale finding recorded only under gate_categories",
         "written" if a7 else "refused: %s" % r7, "written")
    if a7:
        case("it is refreshed in the block that holds it",
             a7["masking"][CATEGORIES]["plaintext_finding"]["occurrences"],
             g7["plaintext_finding"]["occurrences"])
        case("and no duplicate is created at the top level",
             "plaintext_finding" in a7["masking"], False)
        case("nothing outside masking's own keys moves",
             assert_scoped(cats, a7) or "clean", "clean")
    tamper_cats = copy.deepcopy(a7 or cats)
    tamper_cats["masking"].setdefault(CATEGORIES, {})["something_else"] = 1
    case("but any OTHER key under gate_categories is still caught",
         "caught" if assert_scoped(cats, tamper_cats) else "MISSED", "caught")

    print()
    print("=== a human decision is not a gate finding and is not this tool's to delete ===")
    # Two published rows record an adjudication of one address under
    # `encoded_layer_finding`, with evidence that exists nowhere else in the corpus, on rows
    # whose gate reads PASS. The removal branch below - correct for a real finding - would
    # have deleted both the moment anything else on the row moved.
    held = row(masking={"encoded_layer_finding": {
                            "decision": "held for human confirmation; not published "
                                        "until resolved",
                            "resolution": {"resolution": "attacker-owned; kept as an IOC"}},
                        "secret_gate": sres5[SECRET],
                        "secret_literals": stale_payload})
    a8, r8 = build(held, pw_after, "cl", before=pw_before)
    case("a row whose finding key holds a human decision",
         "refused" if r8 else "written", "refused")
    case("and the refusal says which key and why",
         bool(r8 and "encoded_layer_finding" in r8 and "decision" in r8), True)
    # The negative half: an ordinary finding with no decision on it is still removed when
    # its gate goes back to PASS. Without this the guard could be "refuse everything".
    ordinary = row(masking={"encoded_layer_gate": "FAIL",
                            "encoded_layer_finding": {"occurrences": 9},
                            "secret_gate": sres5[SECRET],
                            "secret_literals": stale_payload})
    a9, _r9 = build(ordinary, pw_after, "cl", before=pw_before)
    case("an ordinary superseded finding is still removed",
         "encoded_layer_finding" not in (a9 or {}).get("masking", {}), True)

    print()
    print("=== the recorded form of a finding is not always the whole measurement ===")
    # The schema fork this tool created: it wrote everything `secret_gate` returned, where
    # `mask-samples.py` writes a named subset, and the difference is one prose key. Both
    # directions, because a narrowing that dropped everything and one that dropped nothing
    # look identical on a row whose measurement happens to match.
    FULL = {k: 1 for k in gate_evidence.RECORDED_SECRET_KEYS}
    FULL["note"] = "counts and shapes only"
    case("the prose key is not recorded",
         "note" in recorded_form("secret_literals", FULL), False)
    case("and every measured field still is",
         sorted(recorded_form("secret_literals", FULL)),
         sorted(gate_evidence.RECORDED_SECRET_KEYS))
    case("the values are the measured ones, not defaults",
         set(recorded_form("secret_literals", dict(FULL, secret_literals_after=7)).values()),
         {1, 7})
    case("a field the gate did not return is not invented",
         "shapes_remaining" in recorded_form(
             "secret_literals", {k: 1 for k in gate_evidence.RECORDED_SECRET_KEYS
                                 if k != "shapes_remaining"}), False)
    # The other findings are recorded WHOLE, and `false_positive_note` is the reason: it
    # carries a measured rate a human weighed, and the digest covers it on purpose.
    prof = {"occurrences": 3, "false_positive_note": "127 across 104 of 8,000",
            "note": finding_notes.IDENTIFIER_NOTE}
    case("an identifier finding keeps its false-positive figure",
         recorded_form("encoded_layer_finding", dict(prof)), prof)
    case("and keeps its own note too", recorded_form("plaintext_finding", dict(prof)), prof)
    case("a finding that is not a dict is passed through untouched",
         recorded_form("secret_literals", "FAIL"), "FAIL")
    # The tie: this tool and the masking driver must record the same twelve.
    case("the recorded subset is mask-samples.py's own",
         set(gate_evidence.RECORDED_SECRET_KEYS)
         == set(gate_evidence.mask_samples_secret_keys() or ()), True)
    # And end to end through build(), which is where it actually matters.
    forked = row(masking={"secret_gate": sres5[SECRET],
                          "secret_literals": dict(stale_payload, note="a constant")})
    a10, _r10 = build(forked, pw_after, "cl", before=pw_before)
    case("a row rewritten through build() comes out at twelve keys",
         sorted((a10 or {}).get("masking", {}).get("secret_literals", {})),
         sorted(gate_evidence.RECORDED_SECRET_KEYS))

    print()
    print("=== the scope assertion must be able to fail ===")
    if after:
        t1 = copy.deepcopy(after)
        t1["verdict"] = "benign"
        case("a change outside masking is caught",
             "caught" if assert_scoped(r0, t1) else "MISSED", "caught")
        t2 = copy.deepcopy(after)
        t2["masking"]["detection_survived"] = False
        case("a change to a field this tool does not own is caught",
             "caught" if assert_scoped(r0, t2) else "MISSED", "caught")
        t3 = copy.deepcopy(after)
        t3["publishable"] = True
        case("writing publishable is caught",
             "caught" if assert_scoped(r0, t3) else "MISSED", "caught")

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
