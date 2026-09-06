#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stamp provenance onto a row whose recorded gate verdicts are re-verified, and only then.

`mask-samples.py` produces provenance as a side effect of masking. That is the right route
for a row whose bytes can be re-masked, and the wrong one for a row whose bytes are already
built: the eight rows in the published half were masked before `mask-samples.py` existed,
six of them ship as generated fixtures rather than as the masked source, and re-masking would
rewrite records that are correct.

So this does the smaller thing. It re-runs the current gate over the bytes a row actually
stands behind, compares the result to what the row records, and writes provenance **only
where they agree**. Where they disagree it refuses that row and says so, because a stamp is a
statement that these tools produced these verdicts - writing one over a verdict they would
not produce is the exact lie the provenance field exists to prevent.

ADDITIVE, AND ASSERTED TO BE
---------------------------
The only keys this may create are `provenance` and, where a row records no hash of its own
masked bytes at all, `masked_sha256`. No existing value is changed, and the tool compares the
row before and after to prove it rather than trusting itself. Two published rows carry no
hash of what they ship: for those the only identification lives in the shard `MANIFEST.json`,
which is a build artefact that can be regenerated, so the identification sits in the more
perishable of the two places.

REPLACING A STAMP IS A DIFFERENT ACT FROM ADDING ONE, AND NEEDS `--restamp`
--------------------------------------------------------------------------
The additive assertion above refused every row that already carried a `provenance` - which
is every row this tool had ever stamped. So the tool written to keep provenance current
could not update it: after the tools digest moved, the seven published rows read `stale` and
the only route back was to hand-edit them. That is the gap this closes.

`provenance` is now the one key that may be REPLACED, and only under `--restamp`, so
overwriting a human-readable record of what measured a row is something someone typed rather
than something that happened. Every other key stays add-only and the assertion still proves
it. The safety property is unchanged and is not the assertion: a stamp is written only where
`reverify()` says the current gate returns what the row records, so a replacement can never
launder a verdict that moved - it can only restate one that did not.
"""
import argparse, copy, hashlib, importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock          # noqa: E402
import gate_provenance                                                  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "vcm_stamp", os.path.join(HERE, "verify-content-mask.py"))
VCM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(VCM)

_sgspec = importlib.util.spec_from_file_location(
    "shard_gate_stamp", os.path.join(HERE, "shard-gate.py"))
SG = importlib.util.module_from_spec(_sgspec)
_sgspec.loader.exec_module(SG)

MAPS = [p for p in (VCM.INCIDENT_MAP, VCM.LEGACY_MAP) if os.path.exists(p)]


def _norm(v):
    """A recorded verdict as its CLASS, so two records can be compared.

    Delegated to `shard-gate.gate_result` so there is one parser for a gate value in the
    tree rather than two that disagree. This used to be `v if isinstance(v, str) else
    ("FAIL" if v else v)`, which reads any truthy non-string as a failure. That is the safe
    direction and it is safe by accident: it cannot tell a dict recording `result: FAIL`
    from one recording `result: PASS`, and it would have read the second as a failure and
    refused to stamp a row that agreed with the gate. Six rows in the local half store the
    encoded verdict in exactly that older dict schema.
    """
    return SG.gate_result(v)[0]


def reverify(row, data):
    """(agrees, detail) - does the current gate still return what the row records?"""
    ids, keep = VCM.load_ids(MAPS)
    _ok, g = VCM.gate(data, ids, keep)
    m = row.get("masking") or {}
    out = {}
    for k in ("plaintext_gate", "encoded_layer_gate"):
        out[k] = {"recorded": _norm(m.get(k)), "today": _norm(g.get(k))}
    agrees = all(v["recorded"] == v["today"] for v in out.values())
    return agrees, {"gates": out, "finding": g.get("encoded_layer_finding")
                    or g.get("plaintext_finding")}


def additions(row, data):
    """The keys this would add. Never a key the row already has."""
    m = row.get("masking") or {}
    add = {"provenance": gate_provenance.stamp(MAPS)}
    if "masked_sha256" not in m and not row.get("fixture"):
        add["masked_sha256"] = hashlib.sha256(data).hexdigest()
    return add


ALLOWED_ADDITIONS = {"provenance", "masked_sha256"}
# The one key a re-stamp may overwrite, and only when `restamp` is passed. Kept as its own
# name rather than folded into the loop so that widening it is a visible edit.
REPLACEABLE = {"provenance"}


def assert_additive(before, after, restamp=False):
    """Every key the row already had must be untouched, and no key may appear that is not
    on the allow-list.

    The first version iterated only the keys `before` already had, so it could see an
    overwrite and could not see an ADDITION - a new top-level key sailed past it. Its own
    control caught that, which is the whole reason the control asserts both directions:
    a check that looks one way is the shape AGENTS.md opens with.

    `restamp` permits exactly one overwrite, `masking.provenance`, and nothing else moves
    with it. Without it this function refused every row that had ever been stamped, which
    made the tool unable to do the job it exists for the moment the tools digest moved.
    """
    b, a = before.get("masking") or {}, after.get("masking") or {}
    replaceable = REPLACEABLE if restamp else set()
    for k, v in b.items():
        if k in replaceable:
            continue
        if a.get(k) != v:
            return "masking.%s changed" % k
    extra = set(a) - set(b) - ALLOWED_ADDITIONS
    if extra:
        return "masking gained %s, which is not additive" % ", ".join(sorted(extra))
    for k in set(before) | set(after):
        if k == "masking":
            continue
        if before.get(k) != after.get(k):
            return "%s changed" % k
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", required=False)
    ap.add_argument("--bytes-map", required=False,
                    help="json of sha256 -> path holding the bytes the row stands behind")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--restamp", action="store_true",
                    help="replace an existing masking.provenance where the current gate "
                         "still returns what the row records. Off by default: overwriting "
                         "the record of what measured a row is a deliberate act")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    if not (a.index and a.bytes_map):
        return ap.error("--index and --bytes-map are required unless --inject")

    paths = json.load(open(a.bytes_map))
    rows = read_jsonl(a.index)
    todo, refused, restamped = {}, [], []
    for r in rows:
        if r["sha256"] not in paths:
            continue
        m = r.get("masking") or {}
        if not m.get("applied"):
            continue
        with open(paths[r["sha256"]], "rb") as fh:
            data = fh.read()
        agrees, detail = reverify(r, data)
        if not agrees:
            refused.append((r["sha256"], detail))
            continue
        add = additions(r, data)
        after = copy.deepcopy(r)
        after["masking"].update(add)
        bad = assert_additive(r, after, restamp=a.restamp)
        if bad:
            refused.append((r["sha256"], {"refused": "not additive: %s" % bad}))
            continue
        if "provenance" in m:
            restamped.append(r["sha256"])
        todo[r["sha256"]] = add

    print("rows offered            : %d" % len(paths))
    print("rows re-verified and stampable : %d" % len(todo))
    # Always printed, never only when non-zero: replacing a stamp and adding one are
    # different acts and a report that showed only the total could not tell them apart.
    print("of which a stamp is REPLACED   : %d%s"
          % (len(restamped), "" if a.restamp else "   (--restamp not given)"))
    for sha, add in sorted(todo.items()):
        print("    %s  adds %s" % (sha[:12], ", ".join(sorted(add))))
    print("rows refused            : %d" % len(refused))
    for sha, d in refused:
        g = d.get("gates") or {}
        print("    %s  %s" % (sha[:12], json.dumps(g)))
        if d.get("finding"):
            print("        finding: %s" % json.dumps(d["finding"])[:220])
    if not a.apply:
        print()
        print("dry run: nothing written. Pass --apply.")
        return 1 if refused else 0

    with index_lock(a.index):
        rows = read_jsonl(a.index)
        before = len(rows)
        n = 0
        for r in rows:
            add = todo.get(r["sha256"])
            if not add:
                continue
            snapshot = copy.deepcopy(r)
            r["masking"].update(add)
            bad = assert_additive(snapshot, r, restamp=a.restamp)
            if bad:
                sys.exit("refusing to write: %s on %s" % (bad, r["sha256"][:12]))
            n += 1
        if len(rows) != before:
            sys.exit("row count moved %d -> %d" % (before, len(rows)))
        write_jsonl_atomic(a.index, rows)
    print()
    print("rows stamped            : %d" % n)
    return 1 if refused else 0


def inject():
    """It must stamp an agreeing row, refuse a disagreeing one, and never overwrite."""
    fails = []
    ids, keep = VCM.load_ids(MAPS)
    clean = b"<?php\n$a = 'wp-content/plugins/akismet/index.php';\n$b = 1;\n"
    _ok, g = VCM.gate(clean, ids, keep)

    row_ok = {"sha256": "0" * 64,
              "masking": {"applied": True, "plaintext_gate": g["plaintext_gate"],
                          "encoded_layer_gate": g["encoded_layer_gate"],
                          "detection_survived": True, "note": "kept"}}
    agrees, _d = reverify(row_ok, clean)
    print("=== a row the gate still agrees with ===")
    print("  %-52s %s" % ("re-verification agrees", "yes" if agrees else "WRONG"))
    if not agrees:
        fails.append("agreeing row not recognised")
    add = additions(row_ok, clean)
    after = copy.deepcopy(row_ok)
    after["masking"].update(add)
    bad = assert_additive(row_ok, after)
    print("  %-52s %s" % ("the write is additive", "yes" if bad is None else "WRONG: " + bad))
    if bad:
        fails.append("write was not additive")
    print("  %-52s %s" % ("it adds provenance", "yes" if "provenance" in add else "WRONG"))
    if "provenance" not in add:
        fails.append("no provenance added")

    print()
    print("=== a row the gate no longer agrees with must be REFUSED ===")
    row_bad = copy.deepcopy(row_ok)
    row_bad["masking"]["plaintext_gate"] = "FAIL"      # records FAIL; the gate says PASS
    agrees, _d = reverify(row_bad, clean)
    print("  %-52s %s" % ("recorded FAIL, gate says PASS", "refused" if not agrees
                          else "WRONG: stamped anyway"))
    if agrees:
        fails.append("a disagreeing row was accepted")

    row_bad2 = copy.deepcopy(row_ok)
    row_bad2["masking"]["encoded_layer_gate"] = "FAIL"
    agrees, _d = reverify(row_bad2, clean)
    print("  %-52s %s" % ("recorded encoded FAIL, gate says PASS",
                          "refused" if not agrees else "WRONG: stamped anyway"))
    if agrees:
        fails.append("a disagreeing encoded verdict was accepted")

    # The older schema, in both directions. `_norm` used to read any truthy non-string as
    # FAIL, which refuses a dict-form PASS that agrees with the gate and accepts nothing it
    # should not - safe, and unable to tell the two apart. Six local rows carry this form.
    row_dict_pass = copy.deepcopy(row_ok)
    row_dict_pass["masking"]["encoded_layer_gate"] = {"result": "PASS", "occurrences": 0}
    agrees, _d = reverify(row_dict_pass, clean)
    print("  %-52s %s" % ("recorded dict PASS, gate says PASS",
                          "stamped" if agrees else "WRONG: refused an agreeing row"))
    if not agrees:
        fails.append("a dict-form PASS was read as a disagreement")
    row_dict_fail = copy.deepcopy(row_ok)
    row_dict_fail["masking"]["encoded_layer_gate"] = {"result": "FAIL",
                                                      "distinct_identifiers": 2}
    agrees, _d = reverify(row_dict_fail, clean)
    print("  %-52s %s" % ("recorded dict FAIL, gate says PASS",
                          "refused" if not agrees else "WRONG: stamped anyway"))
    if agrees:
        fails.append("a dict-form FAIL was stamped over a passing gate")
    row_skip = copy.deepcopy(row_ok)
    row_skip["masking"]["encoded_layer_gate"] = "SKIPPED-oversize (>1MB)"
    agrees, _d = reverify(row_skip, clean)
    print("  %-52s %s" % ("recorded SKIPPED, gate says PASS",
                          "refused" if not agrees else "WRONG: stamped anyway"))
    if agrees:
        fails.append("a SKIPPED verdict was stamped as if it had been measured")

    print()
    print("=== a stamp may be REPLACED only under --restamp, and nothing else with it ===")
    # The gap this closes: every row this tool had ever stamped carried a `provenance`, and
    # the additive assertion refused every one of them. So the tool that exists to keep
    # provenance current could not update it the moment the tools digest moved.
    stamped = copy.deepcopy(row_ok)
    stamped["masking"]["provenance"] = {"tools": "0" * 12, "map": None, "at": "2026-01-01"}
    restamped = copy.deepcopy(stamped)
    restamped["masking"].update(additions(stamped, clean))
    bad_off = assert_additive(stamped, restamped, restamp=False)
    bad_on = assert_additive(stamped, restamped, restamp=True)
    print("  %-52s %s" % ("a stale stamp, without --restamp",
                          "refused" if bad_off else "WRONG: overwrote it silently"))
    if not bad_off:
        fails.append("a stamp was replaced without --restamp")
    print("  %-52s %s" % ("a stale stamp, with --restamp",
                          "replaced" if bad_on is None else "WRONG: " + str(bad_on)))
    if bad_on is not None:
        fails.append("--restamp could not replace a stale stamp")
    smuggled = copy.deepcopy(restamped)
    smuggled["masking"]["plaintext_gate"] = "PASS-ish"
    bad = assert_additive(stamped, smuggled, restamp=True)
    print("  %-52s %s" % ("--restamp does not license any other overwrite",
                          "caught" if bad else "WRONG: missed"))
    if not bad:
        fails.append("--restamp allowed a second key to move")
    # And the property that makes the overwrite safe is not the assertion at all: a stamp is
    # written only where the current gate returns what the row records, so a replacement can
    # restate a verdict and never launder one.
    moved = copy.deepcopy(stamped)
    moved["masking"]["plaintext_gate"] = "FAIL"
    agrees, _d = reverify(moved, clean)
    print("  %-52s %s" % ("a stale stamp on a verdict that MOVED",
                          "refused" if not agrees else "WRONG: would be restamped"))
    if agrees:
        fails.append("a re-stamp was offered on a row whose verdict moved")

    print()
    print("=== the additive assertion must be able to fail ===")
    tampered = copy.deepcopy(row_ok)
    tampered["masking"]["note"] = "changed"
    bad = assert_additive(row_ok, tampered)
    print("  %-52s %s" % ("an existing key changed", "caught" if bad else "WRONG: missed"))
    if not bad:
        fails.append("the additive assertion cannot see an overwrite")
    tampered2 = copy.deepcopy(row_ok)
    tampered2["verdict"] = "benign"
    bad = assert_additive(row_ok, tampered2)
    print("  %-52s %s" % ("a key outside masking changed",
                          "caught" if bad else "WRONG: missed"))
    if not bad:
        fails.append("the additive assertion only looks inside masking")

    print()
    print("cases: 14 · passed: %d · failed: %d" % (14 - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
