#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Give a field whose author is unknown an author, a date, and a re-checked claim.

Two fields in the local index are written by nothing in this tree:

  * `masking.not_applicable_reason`, on 29 rows. `mask-samples.py` READS it - it refuses a
    row that carries one - and never writes it. So the current driver honours a claim it
    cannot produce.
  * `masking.encoded_layer_gate_uncapped`, on 3 rows. It records a re-run after a 1 MB cap
    was removed from the gate. No cap exists in the tree now, and nothing writes the field.

Both are in the 2026-09-04 16:33 index snapshot at the same counts, which dates them to an
uncommitted state of `mask-samples.py` before it was first committed on 2026-09-05. That is
the same condition as an unprovenanced gate result one level down: a value the index carries
and cannot account for.

The 3 `uncapped` rows need nothing from this script - they carry `applied: true`, so this
round's re-measurement replaces their whole masking block and the field goes with it. The 29
do not: they carry `applied: false`, which is exactly why no re-measurement touches them.

WHY THIS STAMPS A CHECK AND NOT A LABEL
---------------------------------------
Recording "legacy, author unknown" would tidy the accounting and assert nothing. The claim
those 29 rows actually make is that each is an archive container, and that is testable
without the original tool: `tar` writes `ustar` at offset 257 and gzip starts `1f 8b`. So the
stamp carries a re-verification rather than a provenance note alone, and refuses to write if
a row's claim does not hold. A legacy marker on an unverified claim would launder it.
"""
import argparse, collections, datetime, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock          # noqa: E402

FIELD = "not_applicable_reason"
SNAPSHOT = os.path.join("trail-data", "incoming", "2026-09-04", "index-backup",
                        "index-local.jsonl.pre")


def container_kind(data):
    """What kind of container these bytes are, or None. Magic only; nothing is unpacked."""
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[257:262] == b"ustar":
        return "tar (ustar at offset 257)"
    if data[:2] == b"PK\x03\x04":
        return "zip"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    return None


def stamp_for(kind, first_seen):
    return {
        "field": FIELD,
        "written_by": "an uncommitted state of mask-samples.py, before its first commit",
        "first_seen_in_index": first_seen,
        "recorded_as_legacy": datetime.date.today().isoformat(),
        "claim_reverified": "container magic re-read from the source bytes: %s" % kind,
        "why_not_regenerated": ("the row carries applied:false, so no masking pass writes "
                                "it; the current driver reads this field and never emits "
                                "it. Re-verified rather than relabelled"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=os.path.join(HERE, "local", "index-local.jsonl"))
    ap.add_argument("--resolved", required=False,
                    help="json map of sha256 -> source path, for the re-verification")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()

    if a.inject:
        return inject()

    first_seen = "unknown"
    if os.path.exists(SNAPSHOT):
        n = sum(1 for l in open(SNAPSHOT, encoding="utf-8")
                if l.strip() and FIELD in json.loads(l).get("masking", {}))
        first_seen = "2026-09-04 snapshot, %d row(s)" % n

    rows = read_jsonl(a.index)
    targets = [r for r in rows if FIELD in (r.get("masking") or {})]
    print("rows carrying %s : %d" % (FIELD, len(targets)))
    print("first seen                       : %s" % first_seen)
    already = [r for r in targets if "legacy" in r["masking"]]
    print("already stamped                  : %d" % len(already))

    resolved = json.load(open(a.resolved)) if a.resolved else {}
    kinds = collections.Counter()
    unverified = []
    for r in targets:
        p = resolved.get(r["sha256"])
        if not p or not os.path.exists(p):
            unverified.append(r["sha256"])
            continue
        with open(p, "rb") as fh:
            k = container_kind(fh.read(1024))
        if k is None:
            unverified.append(r["sha256"])
        else:
            kinds[k] += 1
    print("claims re-verified               : %s" % dict(kinds))
    print("claims NOT re-verified           : %d" % len(unverified))
    if unverified:
        for s in unverified[:5]:
            print("    %s" % s[:12])
        print("  refusing to stamp: a legacy marker on an unverified claim launders it")
        return 1

    if not a.apply:
        print()
        print("dry run: nothing written. Pass --apply to stamp.")
        return 0

    with index_lock(a.index):
        rows = read_jsonl(a.index)
        before = len(rows)
        touched = 0
        for r in rows:
            m = r.get("masking") or {}
            if FIELD not in m or "legacy" in m:
                continue
            p = resolved.get(r["sha256"])
            with open(p, "rb") as fh:
                k = container_kind(fh.read(1024))
            m["legacy"] = stamp_for(k, first_seen)
            touched += 1
        if len(rows) != before:
            sys.exit("row count moved %d -> %d" % (before, len(rows)))
        write_jsonl_atomic(a.index, rows)
    print()
    print("rows stamped                     : %d" % touched)
    return 0


def inject():
    """The magic reader must be able to say the other thing."""
    import io, tarfile, gzip, tempfile, shutil
    fails = []
    tmp = tempfile.mkdtemp(prefix="stamp-legacy-inject.")
    try:
        cases = []
        p = os.path.join(tmp, "a.tar")
        with tarfile.open(p, "w") as tf:
            f = os.path.join(tmp, "x.txt")
            open(f, "w").write("hello" * 40)
            tf.add(f, arcname="x.txt")
        cases.append(("a real tar", p, True))
        p = os.path.join(tmp, "b.gz")
        with gzip.open(p, "wb") as fh:
            fh.write(b"hello" * 40)
        cases.append(("a real gzip", p, True))
        p = os.path.join(tmp, "c.php")
        open(p, "wb").write(b"<?php eval($_POST['x']); // " + b"A" * 400)
        cases.append(("a PHP file that is not a container", p, False))
        p = os.path.join(tmp, "d.txt")
        open(p, "wb").write(b"ustar" + b"B" * 400)
        cases.append(("'ustar' present but not at offset 257", p, False))

        print("=== container magic must say both things ===")
        for label, path, want in cases:
            with open(path, "rb") as fh:
                k = container_kind(fh.read(1024))
            got = k is not None
            ok = got == want
            print("  %-46s %-28s %s" % (label, k or "not a container",
                                        "ok" if ok else "WRONG"))
            if not ok:
                fails.append(label)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("cases: 4 · passed: %d · failed: %d" % (4 - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
