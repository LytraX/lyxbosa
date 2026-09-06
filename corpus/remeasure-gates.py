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
Writes the two identifier gate verdicts, their finding profiles, `provenance`, and a
`remeasured` record naming the author, the moment, the sha256 of the bytes it read and what
each verdict was before. Nothing else moves and the tool proves it rather than trusting
itself. It refuses:

  * bytes that do not hash to what was expected. A re-measurement against the wrong bytes is
    worse than none, because it looks like one;
  * a row where every verdict already agrees - `verify-and-stamp.py` is the tool for that,
    and running this instead would rewrite a record that did not change;
  * `--apply` without an author.

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
RECORD_KEY = "remeasured"
# `masking` keys this may write. Everything else in the block is somebody else's
# measurement - detection parity is the scanner's, the secret gate is a differential over
# bytes this tool is not given - and rewriting one from here would be inventing it.
WRITABLE = set(GATES) | set(FINDINGS.values()) | {"provenance", RECORD_KEY}


def measure(data):
    """(verdicts, findings) from the current gate over these bytes."""
    _ok, g = VCM.gate(data, *VCM.load_ids(MAPS))
    verdicts = {k: g[k] for k in GATES}
    findings = {FINDINGS[k]: g[FINDINGS[k]] for k in GATES
                if FINDINGS[k] in g and g[k] != "PASS"}
    return verdicts, findings


def moved(row, verdicts):
    """Which recorded verdicts the re-measurement disagrees with, by CLASS.

    Compared through `shard-gate.gate_result` rather than by string, so a dict-form record
    and the string form of the same verdict are not reported as a change. Six local rows
    carry the older dict schema and a byte comparison would rewrite every one of them while
    reporting a movement that did not happen.
    """
    m = row.get("masking") or {}
    out = {}
    for k in GATES:
        was, now = SG.gate_result(m.get(k))[0], SG.gate_result(verdicts[k])[0]
        if was != now:
            out[k] = {"was": m.get(k), "was_class": was, "now": verdicts[k], "now_class": now}
    return out


def build(row, data, by, at=None):
    """(after_row, refusal). Exactly one is None."""
    if not by or not by.strip():
        return None, "an author is required: a rewritten measurement has an owner"
    verdicts, findings = measure(data)
    delta = moved(row, verdicts)
    if not delta:
        return None, ("every recorded verdict already agrees with the current gate; "
                      "verify-and-stamp.py is the tool for that, and rewriting the record "
                      "here would move a measurement that did not change")
    after = copy.deepcopy(row)
    m = after.setdefault("masking", {})
    before = {k: m.get(k) for k in GATES}
    for k in GATES:
        m[k] = verdicts[k]
    for k in FINDINGS.values():
        # A finding belongs to a failing verdict. When a gate goes back to PASS its finding
        # has to GO, or the row keeps evidence for a verdict it no longer records - which is
        # the stale-record defect this tool exists to repair, in the other direction.
        if k in findings:
            m[k] = findings[k]
        else:
            m.pop(k, None)
    m["provenance"] = gate_provenance.stamp(MAPS)
    m[RECORD_KEY] = {
        "by": by.strip(),
        "at": (at or datetime.datetime.now().replace(microsecond=0)).isoformat(),
        "bytes_sha256": hashlib.sha256(data).hexdigest(),
        "was": before,
        "now": {k: verdicts[k] for k in GATES},
        "why": ("the recorded verdict and the current gate disagreed; the sample did not "
                "change, the predicate did, and a clearance cannot be keyed to a finding "
                "the record does not hold"),
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
    verdicts, _f = measure(data)
    delta = moved(row, verdicts)
    m = row.get("masking") or {}
    for k in GATES:
        print("  %-20s recorded=%-8s today=%-8s %s"
              % (k, json.dumps(m.get(k))[:20], verdicts[k],
                 "MOVED" if k in delta else "agrees"))
    after, refusal = build(row, data, a.by or "-")
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
        after, refusal = build(row, data, a.by, at)
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
