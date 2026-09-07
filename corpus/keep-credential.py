#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run the secret gate on a row that records none, and record the keep as a decision.

WHAT THIS IS FOR
----------------
A row whose masking pass changed nothing still carries whatever credential-shaped literals
its bytes contain, and `verify-content-mask.secret_gate()` is a differential - it fails on a
literal that is byte-identical before and after. So `changes: 0` plus one credential literal
is a guaranteed FAIL, and that is the correct answer rather than a defect: the gate is saying
"this credential survived masking", which is exactly true.

What was wrong is that nobody asked. `shard-gate.evaluate()` demands a `secret_gate` result
only from a `secret`-tagged row, so two published rows tagged `c2`/`path` carried a
credential literal each with no gate result, no finding, and no decision - and passed. This
runs the gate, records what it says, and writes the human's keep as a
`masking.credential_dispositions` entry beside it.

IT DOES NOT MAKE ANYTHING PUBLISHABLE
--------------------------------------
Recording a FAIL BLOCKS the row - that is `shard-gate.evaluate()` Question Three doing its
job. Clearing it is a separate act by a separate tool (`clear-finding.py`), signed by a
person, keyed to the finding digest and to the gate provenance. That separation is the whole
safety property: this tool can only ever make a row LESS publishable, so it cannot be the
route by which something ships. A disposition is the argument; the clearance is the
authorisation; and the two are written by different tools on purpose.

WHY THE GATE IS RE-RUN RATHER THAN THE RESULT ASSERTED
-------------------------------------------------------
§7.2: a gate's finding is evidence about the bytes. A tool that took the verdict from an
argument would be recording a claim, and the claim is what is already in doubt. So the bytes
are supplied, hashed against what the row records, and gated; the verdict written is the one
the gate returned, whatever it is.

    corpus/keep-credential.py --index corpus/index.jsonl --sha 9437f7423b83 \\
        --bytes <the file inside the shard> --keyword password \\
        --classification "attacker infrastructure kept as an indicator (CORPUS_PLAN 4.1)" \\
        --ground "<why, by shape and never by value>" --by cl --reasoned-by "..." --apply
    corpus/keep-credential.py --inject
"""
import argparse, copy, hashlib, importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock          # noqa: E402
import gate_provenance                                                  # noqa: E402
import credential_disposition as CD                                     # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "vcm_keepcred", os.path.join(HERE, "verify-content-mask.py"))
VCM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(VCM)

MAPS = [p for p in (VCM.INCIDENT_MAP, VCM.LEGACY_MAP) if os.path.exists(p)]

# §7.2 by both of its routes: a tag no clearance may cover is a tag no keep may cover
# either, and the refusal is here as well as in `clearance.py` so that neither file is the
# only thing standing between a `pii` row and a recorded decision to publish it.
NEVER = {"pii", "content"}


def measure(after, before):
    """(verdict, evidence, literals) from the gate itself, never from an argument."""
    _ok, res = VCM.secret_gate(before, after)
    verdict = res["secret_gate"]
    evidence = {k: v for k, v in res.items() if k != "secret_gate"}
    return verdict, evidence, VCM.secret_literals(after)


def build(row, after, before, keyword, classification, ground, about="secret_gate"):
    """(additions, refusal). Additions are the three keys this may write, and no others."""
    tags = set(row.get("sensitivity") or [])
    blocked = tags & NEVER
    if blocked:
        return None, ("row carries %s, which is never publishable by any route; a keep "
                      "would be a decision §7.2 does not permit" % "/".join(sorted(blocked)))
    m = row.get("masking") or {}
    if CD.FIELD in m:
        return None, ("row already records %s; rewriting a recorded decision is not "
                      "something this tool does" % CD.FIELD)
    verdict, evidence, literals = measure(after, before)
    if not literals:
        return None, ("the gate finds no credential-shaped literal in these bytes, so there "
                      "is nothing to keep and nothing to record")
    dispositions = []
    for shape, value in sorted(literals):
        dispositions.append({
            "shape": shape,
            "keyword": keyword,
            "value_length": len(value),
            "value_character_classes": CD.classes(value),
            "disposition": CD.DISPOSITIONS[0],
            "classification": classification,
            "ground": ground,
            "about": about,
        })
    for d in dispositions:
        bad = CD.malformed(d, recorded_gates=set(m) | {about})
        if bad:
            return None, "the disposition this would write is malformed: %s" % bad
    st = gate_provenance.stamp(MAPS)
    st["bytes_sha256"] = hashlib.sha256(after).hexdigest()
    return {"secret_gate": verdict, "secret_literals": evidence,
            CD.FIELD: dispositions, "provenance": st}, None


ALLOWED = {"secret_gate", "secret_literals", CD.FIELD, "provenance"}


def assert_additive(before, after):
    """Nothing outside `ALLOWED` moves, and nothing outside `masking` moves at all.

    `provenance` is the one key here that may be REPLACED, for the same reason
    `verify-and-stamp.py --restamp` exists: writing a gate result and leaving the stamp
    describing the run before it would date the new verdict to the old measurement.
    """
    b, a = before.get("masking") or {}, after.get("masking") or {}
    for k, v in b.items():
        if k == "provenance":
            continue
        if a.get(k) != v:
            return "masking.%s changed" % k
    extra = set(a) - set(b) - ALLOWED
    if extra:
        return "masking gained %s, which is not on the allow-list" % ", ".join(sorted(extra))
    for k in set(before) | set(after):
        if k == "masking":
            continue
        if before.get(k) != after.get(k):
            return "%s changed" % k
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=os.path.join(HERE, "index.jsonl"))
    ap.add_argument("--sha", help="full sha256 or a unique prefix")
    ap.add_argument("--bytes", dest="bytes_path",
                    help="the bytes the row stands behind - for a published row, the file "
                         "inside the shard")
    ap.add_argument("--expect-sha256", default=None,
                    help="what those bytes must hash to; defaults to the row's masked hash "
                         "where it records one, otherwise its sha256")
    ap.add_argument("--before", dest="before_path", default=None,
                    help="the PRE-masking bytes. Defaults to --bytes, which is correct ONLY "
                         "for a row recording changes:0 and is refused otherwise")
    ap.add_argument("--keyword", help="the alternation member that fired; %s"
                    % "/".join(CD.KEYWORDS))
    ap.add_argument("--classification", help="what the literal IS")
    ap.add_argument("--ground", help="why it is kept, by shape and never by value")
    ap.add_argument("--by", help="who is AUTHORISING the keep; a person")
    ap.add_argument("--reasoned-by", dest="reasoned_by",
                    help="what produced the argument they authorised")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    for req in ("sha", "bytes_path", "keyword", "classification", "ground", "by",
                "reasoned_by"):
        if not getattr(a, req):
            return ap.error("--%s is required unless --inject" % req.replace("_", "-"))

    rows = read_jsonl(a.index)
    hits = [r for r in rows if r["sha256"].startswith(a.sha)]
    if len(hits) != 1:
        sys.exit("--sha %r matched %d rows in %s" % (a.sha, len(hits), a.index))
    row = hits[0]
    m = row.get("masking") or {}
    with open(a.bytes_path, "rb") as fh:
        after = fh.read()
    got = hashlib.sha256(after).hexdigest()
    want = a.expect_sha256 or m.get("masked_sha256") or row["sha256"]
    if not got.startswith(want):
        sys.exit("the bytes hash to %s and were expected to hash to %s; refusing"
                 % (got[:16], want[:16]))
    if a.before_path:
        with open(a.before_path, "rb") as fh:
            before = fh.read()
    else:
        if m.get("changes") not in (0, None) or m.get("applied") and m.get("changes"):
            sys.exit("the row records changes:%s, so the pre-masking bytes are a DIFFERENT "
                     "file and --before is required: a differential asked of one file "
                     "answers a question nobody put" % m.get("changes"))
        before = after

    print("index                   : %s" % a.index)
    print("row                     : %s  %s" % (row["sha256"][:12], row.get("family")))
    print("bytes                   : %s (%d bytes, sha %s)"
          % (os.path.basename(a.bytes_path), len(after), got[:12]))
    print("pre-masking bytes       : %s"
          % (os.path.basename(a.before_path) if a.before_path
             else "the same file, because the row records changes:0"))
    add, refusal = build(row, after, before, a.keyword, a.classification, a.ground)
    if refusal:
        print()
        print("REFUSED: %s" % refusal)
        return 1
    print("secret_gate             : %s   (measured, not asserted)" % add["secret_gate"])
    sl = add["secret_literals"]
    print("  literals before/after/carried : %s / %s / %s"
          % (sl.get("secret_literals_before"), sl.get("secret_literals_after"),
             sl.get("secret_literals_carried_over")))
    for d in add[CD.FIELD]:
        print("  disposition           : %s  shape=%s keyword=%s len=%d classes=%s"
              % (d["disposition"], d["shape"], d["keyword"], d["value_length"],
                 d["value_character_classes"]))
    after_row = copy.deepcopy(row)
    after_row.setdefault("masking", {}).update(add)
    bad = assert_additive(row, after_row)
    if bad:
        sys.exit("refusing to write: %s" % bad)
    if add["secret_gate"] != "PASS":
        print()
        print("This BLOCKS the row. `publishable` is computed, and a recorded non-pass is a")
        print("blocker until a human clears it:")
        print("  corpus/clear-finding.py --sha %s --gate secret_gate --by %s \\"
              % (row["sha256"][:12], a.by))
        print("      --reasoned-by %r --reason <what was read, by shape> --apply"
              % a.reasoned_by)
    if not a.apply:
        print()
        print("dry run: nothing written. Pass --apply.")
        return 0

    with index_lock(a.index):
        rows = read_jsonl(a.index)
        n = 0
        for r in rows:
            if r["sha256"] != row["sha256"]:
                continue
            snapshot = copy.deepcopy(r)
            r.setdefault("masking", {}).update(add)
            bad = assert_additive(snapshot, r)
            if bad:
                sys.exit("refusing to write: %s on %s" % (bad, r["sha256"][:12]))
            n += 1
        if n != 1:
            sys.exit("expected to write exactly one row, wrote %d" % n)
        write_jsonl_atomic(a.index, rows)
    print()
    print("written: 1 row. `publishable` is NOT touched here - run")
    print("  corpus/shard-gate.py --fix %s" % a.index)
    return 0


def inject():
    """Every refusal, and the one direction that must still work."""
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-58s %-14s %s" % (label, str(got)[:14],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    creds = b"<?php $u='http://h/x.php?pass=\"abcd\"'; $q=1;\n"
    plain = b"<?php $q = 1;\n"
    row = {"sha256": "0" * 64, "sensitivity": ["c2"],
           "masking": {"applied": True, "changes": 0, "plaintext_gate": "PASS"}}

    print("=== the vocabulary is taken from the gate, not restated beside it ===")
    live = set()
    for shape, rx in VCM.SECRET_SHAPES:
        if shape == "quoted-credential":
            import re as _re
            live = set(_re.findall(r"[a-z_]+", rx.pattern.decode("latin-1").split("(?![")[0]
                                   .split("(?:")[-1]))
    case("every recorded keyword is one the gate can report",
         all(k in live for k in CD.KEYWORDS), True)

    print()
    print("=== it measures the gate rather than being told the answer ===")
    add, refusal = build(row, creds, creds, "pass", "attacker infrastructure", "because")
    case("a carried-over literal is recorded as FAIL", add and add["secret_gate"], "FAIL")
    case("one disposition per literal", add and len(add[CD.FIELD]), 1)
    case("the disposition carries no value, only its shape",
         add and add[CD.FIELD][0]["value_character_classes"], "aaaa")
    case("the stamp names the bytes it gated",
         add and add["provenance"]["bytes_sha256"] == hashlib.sha256(creds).hexdigest(),
         True)
    # The other direction: masking that really did replace the literal passes, and then
    # there is nothing to keep.
    masked = creds.replace(b"abcd", b"mask")
    add2, ref2 = build(row, masked, creds, "pass", "x", "y")
    case("a literal that masking replaced gates PASS", add2 and add2["secret_gate"], "PASS")

    print()
    print("=== the refusals ===")
    _a, r1 = build(row, plain, plain, "pass", "x", "y")
    case("no credential in the bytes -> nothing to record", bool(r1), True)
    _a, r2 = build(dict(row, sensitivity=["pii"]), creds, creds, "pass", "x", "y")
    case("a pii row may not record a keep", bool(r2), True)
    _a, r3 = build(dict(row, sensitivity=["content"]), creds, creds, "pass", "x", "y")
    case("a content row may not record a keep", bool(r3), True)
    already = copy.deepcopy(row)
    already["masking"][CD.FIELD] = []
    _a, r4 = build(already, creds, creds, "pass", "x", "y")
    case("a row already recording a decision is not rewritten", bool(r4), True)
    _a, r5 = build(row, creds, creds, "not-a-keyword", "x", "y")
    case("a keyword the gate cannot report is refused", bool(r5), True)
    _a, r6 = build(row, creds, creds, "pass", "x", "   ")
    case("a blank ground is refused", bool(r6), True)

    print()
    print("=== the write is additive, and the assertion can fail ===")
    good = copy.deepcopy(row)
    good["masking"].update(add)
    case("the three keys plus the stamp are additive",
         assert_additive(row, good) or "clean", "clean")
    tampered = copy.deepcopy(good)
    tampered["masking"]["plaintext_gate"] = "FAIL"
    case("an existing gate verdict changed", bool(assert_additive(row, tampered)), True)
    outside = copy.deepcopy(good)
    outside["verdict"] = "benign"
    case("a key outside masking changed", bool(assert_additive(row, outside)), True)
    smuggled = copy.deepcopy(good)
    smuggled["masking"]["publishable_override"] = True
    case("a key off the allow-list", bool(assert_additive(row, smuggled)), True)

    print()
    print("=== the matcher, in both directions ===")
    lits = VCM.secret_literals(creds)
    unrec, unmatched = CD.matches(good["masking"], lits)
    case("a recorded disposition covers the literal", (unrec, unmatched), ([], []))
    bare = {"masking": {}}
    unrec2, _u = CD.matches(bare["masking"], lits)
    case("a literal with no disposition is reported", len(unrec2), 1)
    stale = copy.deepcopy(good)
    stale["masking"][CD.FIELD][0]["value_length"] = 9
    stale["masking"][CD.FIELD][0]["value_character_classes"] = "aaaaaaaaa"
    u3, u4 = CD.matches(stale["masking"], lits)
    case("a disposition matching no literal is reported", (len(u3), len(u4)), (1, 1))

    print()
    print("=== malformed dispositions ===")
    d = dict(add[CD.FIELD][0])
    case("a well-formed one reads", CD.malformed(d, {"secret_gate"}), None)
    case("about naming a gate the row does not record",
         bool(CD.malformed(d, {"plaintext_gate"})), True)
    case("a disposition outside the closed vocabulary",
         bool(CD.malformed(dict(d, disposition="ignored"), {"secret_gate"})), True)
    case("value_length disagreeing with the class form",
         bool(CD.malformed(dict(d, value_length=99), {"secret_gate"})), True)
    case("a boolean value_length",
         bool(CD.malformed(dict(d, value_length=True), {"secret_gate"})), True)
    for k in CD.REQUIRED:
        missing = {kk: vv for kk, vv in d.items() if kk != k}
        if CD.malformed(missing, {"secret_gate"}) is None:
            case("missing %s is refused" % k, False, True)
    case("every required key is load-bearing",
         all(CD.malformed({kk: vv for kk, vv in d.items() if kk != k},
                          {"secret_gate"}) for k in CD.REQUIRED), True)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
