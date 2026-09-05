#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Close corpus rows that are byte-identical to a file in a pinned benign source.

WHY THIS IS A TOOL AND NOT A SCRIPT SOMEBODY RAN ONCE
-----------------------------------------------------
92% of everything ever closed in this corpus was closed by exact hash against a pinned
source and 8% by human review, and until now the 92% had no committed implementation - it
was done by an ad-hoc script in a collection directory, so the reason code
`pinned-benign-hash` appeared in 9,168 published rows and nowhere in the repository. A
mechanism that decides tens of thousands of rows has to be readable by the person auditing
those rows.

WHAT IT ASSERTS, AND WHAT THAT ARGUMENT RESTS ON
------------------------------------------------
A blob whose sha256 equals a file inside a hash-pinned upstream release is that upstream
file. So:

  * `verdict: benign`     - the bytes are upstream's, not the attacker's;
  * `sensitivity: clean`  - and they are not the CUSTOMER'S either, which is the property
                            sensitivity exists to protect. Anyone can download the same
                            bytes from the same URL, so publishing the row exposes nothing.

The second point is the one that decides the awkward cases, and there are two kinds:

  * rows the automated sensitivity pass tagged `content` because they are images. A JPEG
    bundled inside a plugin release is the plugin author's, and hash-identity says which;
  * rows it tagged `c2`, `identity`, `secret` or `pii` because upstream vendor code
    contains API hostnames and key material - the Freemius SDK is most of them. The tag is
    a true statement about the bytes and a false statement about whose bytes they are.

Both are recorded on the row as `sensitivity_superseded` rather than silently overwritten,
because a tag that turned out to be wrong is evidence about the tagger. Neither is closed
unless the row is `unreviewed`: a human verdict is never overridden by a hash.

A row that resolves and whose scan already flagged it is NOT quietly closed either - it is
a false positive on upstream code, and the tool prints those separately so they can be
pinned in `expect/benign-false-positives.json` as §8 requires.

Usage:
  corpus/resolve-benign.py --dry-run        say what would change, write nothing
  corpus/resolve-benign.py --apply          close them, and promote to the published half
  corpus/resolve-benign.py --apply --no-promote    close in place, publish nothing
  corpus/resolve-benign.py --inject         positive control
"""
import argparse, collections, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy   # noqa: E402

PUB = os.path.join(HERE, "index.jsonl")
LOC = os.path.join(HERE, "local", "index-local.jsonl")
LOCK = os.path.join(HERE, "benign", "sources.jsonl")
DEST = os.path.join(ROOT, "trail-data", "CMS-ext")

CLEAN_ENOUGH = {"unreviewed", "clean"}

# The published row is BUILT, never copied-and-pruned. shard-gate.py fails a published row
# that carries `origin`, and four rows once carried one because a promotion took the whole
# local row and removed what it remembered to remove. A whitelist cannot forget.
CARRY = ("sha256", "size", "count", "bucket", "account_hash",
         "discovered_by", "placements")


def sources():
    """(kind, name, version) -> unpacked directory, for every lockfile entry."""
    out = {}
    for line in open(LOCK):
        line = line.strip()
        if not line:
            continue
        s = json.loads(line)
        out[(s["kind"], s["name"], s["version"])] = os.path.join(
            DEST, s["kind"], "%s-%s" % (s["name"], s["version"]))
    return out


def hash_sources(srcs):
    """sha256 -> "name version" of the first pinned source that contains it."""
    by_hash, missing, files = {}, [], 0
    for (kind, name, version), d in sorted(srcs.items()):
        if not os.path.isdir(d):
            missing.append("%s %s" % (name, version))
            continue
        label = "%s %s" % (name, version)
        for dirpath, _, filenames in os.walk(d):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    h = hashlib.sha256()
                    with open(p, "rb") as fh:
                        for chunk in iter(lambda: fh.read(1 << 20), b""):
                            h.update(chunk)
                except OSError:
                    continue
                files += 1
                by_hash.setdefault(h.hexdigest(), label)
    return by_hash, missing, files


def plan(rows, by_hash):
    """Decide, without writing. Returns (closable, flagged, per-source counts)."""
    closable, flagged = [], []
    per_source = collections.Counter()
    per_bucket = collections.Counter()
    superseded = collections.Counter()
    for r in rows:
        if r.get("verdict") != "unreviewed":
            continue
        label = by_hash.get(r["sha256"])
        if label is None:
            continue
        tags = set(r.get("sensitivity") or [])
        extra = tags - CLEAN_ENOUGH
        entry = (r, label, sorted(extra))
        if r.get("observed_detection"):
            flagged.append(entry)
        closable.append(entry)
        per_source[label] += 1
        per_bucket[r.get("bucket")] += 1
        for t in extra:
            superseded[t] += 1
    return closable, flagged, per_source, per_bucket, superseded


def close_row(r, label, extra):
    """Mutate a local row into a closed benign one. Single writer of these fields."""
    if extra:
        r["sensitivity_superseded"] = {
            "was": sorted(set(r.get("sensitivity") or [])),
            "why": ("byte-identical to a file in a pinned upstream release, so the bytes "
                    "are the vendor's and are downloadable by anyone; the tag described "
                    "the content correctly and its owner incorrectly"),
            "resolved_by": label,
        }
    r["verdict"] = "benign"
    r["reason"] = "pinned-benign-hash"
    r["sensitivity"] = ["clean"]
    r["auto_classified_by"] = "pinned-benign-source"
    r["resolved_by_source"] = label
    return r


def published_row(r):
    out = {k: r[k] for k in CARRY if k in r}
    out.update(verdict="benign", reason="pinned-benign-hash",
               sensitivity=["clean"], auto_classified_by="pinned-benign-source",
               publishable=True, resolved_by_source=r["resolved_by_source"])
    if "sensitivity_superseded" in r:
        out["sensitivity_superseded"] = r["sensitivity_superseded"]
    return out


def report(closable, flagged, per_source, per_bucket, superseded, files, missing):
    print("pinned benign files hashed : %d" % files)
    if missing:
        print("sources NOT on disk        : %d  (run corpus/fetch-benign.sh)" % len(missing))
        for m in missing[:10]:
            print("    missing  %s" % m)
    print("rows closable              : %d" % len(closable))
    print()
    print("by bucket:")
    for b, n in per_bucket.most_common():
        print("    %-24s %6d" % (b, n))
    print()
    print("by source (top 25 of %d):" % len(per_source))
    for s, n in per_source.most_common(25):
        print("    %-42s %6d" % (s, n))
    if superseded:
        print()
        print("sensitivity tags superseded by hash identity:")
        for t, n in superseded.most_common():
            print("    %-24s %6d" % (t, n))
    if flagged:
        print()
        print("=== %d of these are FALSE POSITIVES on upstream code ===" % len(flagged))
        print("    the scan that collected them recorded a finding, and the file is a "
              "pinned release's own bytes.")
        print("    Pin each in corpus/expect/benign-false-positives.json as known_fp (§8).")
        for r, label, _ in flagged:
            rules = (r.get("observed_detection") or {}).get("rules")
            print("    %s  %-40s %s" % (r["sha256"][:12], label, rules))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--no-promote", action="store_true",
                    help="close rows in the local half and publish nothing")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args(argv)
    if a.inject:
        return inject()
    if not (a.dry_run or a.apply):
        ap.error("one of --dry-run or --apply is required")

    srcs = sources()
    by_hash, missing, files = hash_sources(srcs)
    rows = read_jsonl(LOC)
    closable, flagged, per_source, per_bucket, superseded = plan(rows, by_hash)
    report(closable, flagged, per_source, per_bucket, superseded, files, missing)
    if a.dry_run:
        print("\ndry run: nothing written")
        return 0
    if not closable:
        print("\nnothing to do")
        return 0

    want = {r["sha256"] for r, _, _ in closable}
    labels = {r["sha256"]: (lab, extra) for r, lab, extra in closable}

    # Published half first. An interruption between the two halves then leaves a row in
    # BOTH, which is visible as a total_blobs that grew and is repairable; the other order
    # loses it. round8/apply.py records the same reasoning.
    promoted = 0
    if not a.no_promote:
        try:
            with index_lock(PUB):
                pub = read_jsonl(PUB)                      # re-read INSIDE the lock
                have = {r["sha256"] for r in pub}
                loc_now = read_jsonl(LOC)
                add = []
                for r in loc_now:
                    if r["sha256"] in want and r["sha256"] not in have:
                        lab, extra = labels[r["sha256"]]
                        add.append(published_row(close_row(dict(r), lab, extra)))
                write_jsonl_atomic(PUB, pub + add)
                promoted = len(add)
        except LockBusy as e:
            print("index busy: %s" % e, file=sys.stderr)
            return 2

    closed = 0
    try:
        with index_lock(LOC):
            loc = read_jsonl(LOC)                          # re-read INSIDE the lock
            keep = []
            for r in loc:
                if r["sha256"] in want and r.get("verdict") == "unreviewed":
                    lab, extra = labels[r["sha256"]]
                    close_row(r, lab, extra)
                    closed += 1
                    if not a.no_promote:
                        continue                           # it now lives in the published half
                keep.append(r)
            write_jsonl_atomic(LOC, keep)
    except LockBusy as e:
        print("index busy: %s" % e, file=sys.stderr)
        return 2

    print("\nclosed %d local rows; promoted %d to the published half" % (closed, promoted))
    print("now run: corpus/shard-gate.py corpus/index.jsonl --fix")
    print("         corpus/shard-gate.py corpus/local/index-local.jsonl --fix")
    print("         corpus/make-summary.py")
    return 0


# ---------------------------------------------------------------------------------------
# Positive control.
#
# The failure this guards against is the one AGENTS.md keeps recording: a resolver that
# reports a large, plausible number while being blind in one direction. Every case below
# asserts the tool says the OTHER thing - that it declines a row it must decline, and that
# it does not decline one it must close.
# ---------------------------------------------------------------------------------------
def inject():
    import tempfile, shutil
    tmp = tempfile.mkdtemp()
    try:
        d = os.path.join(tmp, "src")
        os.makedirs(d)
        payload = b"<?php // an upstream file\n"
        with open(os.path.join(d, "up.php"), "wb") as fh:
            fh.write(payload)
        h = hashlib.sha256(payload).hexdigest()
        other = hashlib.sha256(b"not in any source").hexdigest()
        by_hash = {h: "control-source 1.0"}

        def row(**kw):
            base = dict(sha256=h, size=len(payload), verdict="unreviewed",
                        sensitivity=["unreviewed"], bucket="recovery/stock", count=1,
                        discovered_by=["manual-sweep"])
            base.update(kw)
            return base

        cases = [
            ("a hash-matching unreviewed row is closed",
             row(), True, None),
            ("a row whose hash is in no pinned source is left alone",
             row(sha256=other), False, None),
            ("a row a human already ruled on is never overridden",
             row(verdict="malicious"), False, None),
            ("a `content` tag is superseded, and recorded",
             row(sensitivity=["content"]), True, ["content"]),
            ("a `c2`/`secret` tag is superseded, and recorded",
             row(sensitivity=["c2", "secret"]), True, ["c2", "secret"]),
            ("an already-clean row still closes",
             row(sensitivity=["clean"]), True, []),
        ]
        ok = 0
        fail = 0
        print("resolve-benign.py positive control")
        for label, r, want_closable, want_extra in cases:
            closable, flagged, _, _, _ = plan([r], by_hash)
            got = bool(closable)
            good = got == want_closable
            if good and want_extra is not None:
                good = closable[0][2] == want_extra
            print("  %s  %s" % ("PASS " if good else "FAIL ", label))
            ok, fail = (ok + 1, fail) if good else (ok, fail + 1)

        # A flagged row must be reported as a false positive, not swallowed.
        r = row(observed_detection={"rules": ["OBF025"]})
        closable, flagged, _, _, _ = plan([r], by_hash)
        good = len(flagged) == 1 and len(closable) == 1
        print("  %s  a row the scan already flagged is surfaced as a false positive"
              % ("PASS " if good else "FAIL "))
        ok, fail = (ok + 1, fail) if good else (ok, fail + 1)

        # The published row must never carry origin: that is shard-gate's hard failure.
        r = close_row(row(origin={"path": "/home/acct01/public_html/x.php"}),
                      "control-source 1.0", [])
        p = published_row(r)
        good = "origin" not in p and p["verdict"] == "benign" and p["publishable"] is True
        print("  %s  the published row is built from a whitelist and carries no origin"
              % ("PASS " if good else "FAIL "))
        ok, fail = (ok + 1, fail) if good else (ok, fail + 1)

        # And the hasher must actually find a file, or every zero above means nothing.
        got, missing, files = hash_sources({("control", "control-source", "1.0"): d})
        good = files == 1 and got.get(h) == "control-source 1.0"
        print("  %s  the source hasher reads files and is not silently empty (%d hashed)"
              % ("PASS " if good else "FAIL ", files))
        ok, fail = (ok + 1, fail) if good else (ok, fail + 1)

        print("\ncontrol: %d passed, %d failed" % (ok, fail))
        return 0 if fail == 0 else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
