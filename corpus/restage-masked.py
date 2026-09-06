#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rebuild the masked bytes a row stands behind, and prove they are the ones it stands behind.

WHY THIS EXISTS
---------------
`verify-and-stamp.py` re-runs the current gate over the bytes a masked row records and
re-stamps where the two agree. It needs those bytes, and for most rows they are not on this
machine: the masking pass staged them under `trail-data`, the stage was cleared, and what
survives is the ORIGINAL sample plus a recorded `masked_sha256`.

When the tools digest moves, every row whose bytes cannot be produced reads `stale` and
blocks on `gate results have no usable provenance`. Repairing the gate's credential shapes
moved the digest for 140 stamped rows; 73 had reachable bytes and 69 did not, and 32 of
those 69 were publishable. That is a real regression caused by a real repair, and the fix is
not to soften the provenance rule - it is that the bytes are recoverable.

THE THREE FIGURES, AND WHICH ONE IS CURRENT
--------------------------------------------
That 73/69 split is the state BEFORE this tool existed, and it is quoted elsewhere as "69 of
140" - `shard-gate.findingShapeViolations` is where that phrasing lives. It is also
internally inconsistent: 73 + 69 is 142, the number of MASKED rows, while 140 was the number
STAMPED at that moment. It is a motivating figure, not a measurement of today.

Regeneration answered 132 of 142, which is what `remeasure-gates.py` and the changelog
quote, and re-running this tool on 2026-09-07 reproduced it exactly - 132 regenerated, 3
mismatch, 7 unrecorded. Neither figure is the reachable set, though, because regeneration is
only one of three ways a row's masked bytes can be PROVED, and this tool used to implement
one. The other two are below, and with them the answer is 142 of 142.

`content_mask.mask_sample` is deterministic in (bytes, map, vocabulary, flags). So the
masked form can be REGENERATED and then CHECKED against the hash the row already records.
That check is the whole point: a regenerated file that hashes to `masked_sha256` is not a
plausible reconstruction, it is the same file, and one that does not is refused rather than
staged. Nothing here decides a verdict, and nothing here writes an index row.

WHAT A MISMATCH MEANS, AND WHY IT IS NOT RETRIED
------------------------------------------------
`mask_ipv4` and `mask_hex_digests` change the output, and so does a map or a vocabulary that
has moved since. A tool that tried each combination until one hashed correctly would be
searching for the answer it wanted; the first match would then "prove" a flag combination
nobody recorded. So the flags are arguments with the driver's own defaults, one attempt is
made, and a mismatch is reported as a mismatch - which is a finding about the row (its bytes
were produced by something this tree can no longer reproduce) rather than an obstacle.

    corpus/restage-masked.py --index corpus/local/index-local.jsonl \
        --originals <out-of-repo json: sha256 -> path> --vocabulary trail-data/CMS-ext \
        --stage <out-of-repo dir> --out <out-of-repo bytes-map.json>
    corpus/restage-masked.py --inject
"""
import argparse, collections, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import incident_mask                                                      # noqa: E402
import content_mask                                                       # noqa: E402
from indexio import read_jsonl                                            # noqa: E402


def build_vocabulary(roots):
    """The collision reference, and a hard failure where it is absent.

    Copied in spirit from `mask-samples.build_vocabulary` and for its reason: the vocabulary
    is what demotes an identifier that is also an ordinary stock-CMS token, so regenerating
    without it silently produces DIFFERENT bytes - which here would show up as a mismatch on
    every row and read as "the masking cannot be reproduced".
    """
    vocab = set()
    for r in roots:
        if not os.path.isdir(r):
            sys.exit("vocabulary root %s is not a directory; refusing to regenerate against "
                     "an empty collision reference" % r)
        before = len(vocab)
        vocab |= incident_mask.vocabulary(r)
        if len(vocab) == before:
            sys.exit("vocabulary root %s contributed no tokens" % r)
    return vocab


def target_hash(row):
    """(hash, where) - the hash of the masked bytes this row records, and under which key.

    `masked_sha256` is the field for it. Where a row has none, a `remeasured` record written
    by `remeasure-gates.py` carries `bytes_sha256`: the hash of the bytes that measurement
    actually read. That is the same kind of evidence under a different name - a hash the row
    itself records for its own masked form - and naming the source keeps the two apart in
    the report rather than letting a fallback read as the field.
    """
    m = row.get("masking") or {}
    if m.get("masked_sha256"):
        return m["masked_sha256"], "masked_sha256"
    rec = m.get("remeasured")
    if isinstance(rec, dict) and rec.get("bytes_sha256"):
        return rec["bytes_sha256"], "remeasured.bytes_sha256"
    return None, None


def regenerate(row, raw, m, vocab, mask_ipv4=False, mask_hex=False):
    """(state, bytes|None, detail). Four states, never two.

    'regenerated'           - the rebuilt bytes hash to the hash the row already records, so
                              they are that file rather than a reconstruction of it
    'regenerated-unchanged' - the row records no hash and `changes: 0`, which is the row
                              saying its masked form IS its input; the rebuild reproduced
                              the input byte for byte, and the input's hash is `sha256`,
                              which the row does record. Same proof, different field.
    'mismatch'              - the rebuild does not hash to what the row records. Reported,
                              never staged
    'unrecorded'            - the row records no hash and does not say it changed nothing,
                              so there is nothing this can prove and it declines rather than
                              staging an unidentified file

    THE THIRD STATE IS A PROOF AND NOT A RELAXATION
    ------------------------------------------------
    Six published rows record `changes: 0` and no `masked_sha256`, and read as `unrecorded`
    for a schema reason rather than an evidential one: a pass that changed nothing had no
    second hash to write, because there was no second file. The row still says exactly what
    its masked bytes are - the ones it came in with, whose hash is `sha256` and is recorded.

    It can still fail, which is the part that makes it a check. If today's masker touches
    one byte of those bytes, the rebuild is not the input, the identity the row asserts does
    not hold, and this returns `mismatch` like any other. Measured on 2026-09-07: all six
    rebuilt to byte-identical output, and the two rows recording `changes: 4` that also lack
    a hash produce 8 changes today and are refused here exactly as they should be.
    """
    want, _where = target_hash(row)
    mk = row.get("masking") or {}
    unchanged_claim = want is None and mk.get("changes") == 0
    if want is None and not unchanged_claim:
        return "unrecorded", None, "row records no masked_sha256 and no changes:0 claim"
    if hashlib.sha256(raw).hexdigest() != row["sha256"]:
        return "mismatch", None, "the source bytes do not hash to the row"
    masked, _detail = content_mask.mask_sample(raw, m, mask_ipv4=mask_ipv4,
                                               vocabulary=vocab, mask_hex_digests=mask_hex)
    if len(masked) != len(raw):                                      # pragma: no cover
        return "mismatch", None, "regeneration changed the length"
    if unchanged_claim:
        if masked != raw:
            return "mismatch", None, ("the row records changes:0 and the masker changes "
                                      "these bytes today")
        return ("regenerated-unchanged", masked,
                "the row records changes:0 and the rebuild is the input, whose sha256 the "
                "row records")
    got = hashlib.sha256(masked).hexdigest()
    if got != want:
        return "mismatch", None, "regenerated %s, row records %s" % (got[:12], want[:12])
    return "regenerated", masked, "hashes to the recorded masked_sha256"


def find_on_disk(wanted, roots):
    """{hash: path} for every wanted hash whose bytes are already on disk under `roots`.

    THIS IS A LOOKUP, NOT A SEARCH FOR A MATCH
    -------------------------------------------
    The hazard the whole module is written against is a tool that tries possibilities until
    one "proves" what it wanted. This cannot do that: the hash is fixed by the row before
    anything is read, and a file is accepted only when its bytes hash to exactly that. No
    candidate is preferred, none is retried under other parameters, and a root holding
    nothing simply returns nothing.

    Size-filtered first because masking is length-preserving - `length_preserved` is on every
    one of these rows - so a masked file has the size the row records, and a file of another
    size cannot be it. The filter is exact equality, so it cannot exclude a file that would
    have matched, and hashing every file under a tree this size is 500,000 reads to answer a
    question about ten.
    """
    sizes = {size for _h, size in wanted}
    want = {h for h, _size in wanted}
    out = {}
    for root in roots:
        for base, _dirs, names in os.walk(root):
            for n in names:
                path = os.path.join(base, n)
                try:
                    if os.path.getsize(path) not in sizes:
                        continue
                    with open(path, "rb") as fh:
                        blob = fh.read()
                except OSError:
                    continue
                h = hashlib.sha256(blob).hexdigest()
                if h in want:
                    out.setdefault(h, path)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", action="append", default=[])
    ap.add_argument("--originals", help="json of sha256 -> path to the ORIGINAL bytes")
    ap.add_argument("--vocabulary", action="append", default=[])
    ap.add_argument("--map", default=incident_mask.MAP_PATH)
    ap.add_argument("--stage", help="directory to write the regenerated bytes into")
    ap.add_argument("--out", help="write the two-sided bytes map here")
    ap.add_argument("--found", action="append", default=[],
                    help="root to look in for masked bytes that are ALREADY on disk. A file "
                         "is taken only where it hashes to the hash the row records, which "
                         "is the same proof regeneration has to pass")
    ap.add_argument("--mask-ipv4", action="store_true")
    ap.add_argument("--mask-hex-digests", action="store_true")
    ap.add_argument("--inject", action="store_true")
    a = ap.parse_args()
    if a.inject:
        return inject()
    for req in ("originals", "vocabulary", "stage"):
        if not getattr(a, req):
            return ap.error("--%s is required unless --inject" % req)

    m = incident_mask.load_map(a.map)
    vocab = build_vocabulary(a.vocabulary)
    print("stock vocabulary tokens : %d" % len(vocab))
    originals = json.load(open(a.originals))
    rows = []
    for p in (a.index or [os.path.join(HERE, "index.jsonl"),
                          os.path.join(HERE, "local", "index-local.jsonl")]):
        rows += read_jsonl(p)

    os.makedirs(os.path.join(a.stage, "after"), exist_ok=True)
    tally = collections.Counter()
    out, mismatches, unbuilt = {}, [], []
    for r in rows:
        if not (r.get("masking") or {}).get("applied"):
            continue
        src = originals.get(r["sha256"])
        if not src or not os.path.exists(src):
            tally["no original bytes"] += 1
            continue
        with open(src, "rb") as fh:
            raw = fh.read()
        state, masked, detail = regenerate(r, raw, m, vocab, a.mask_ipv4,
                                           a.mask_hex_digests)
        tally[state] += 1
        if state not in ("regenerated", "regenerated-unchanged"):
            if state == "mismatch":
                mismatches.append((r["sha256"], detail))
            # The bytes could not be REBUILT. They may still be on disk, and a file that
            # hashes to what the row records is that file whoever wrote it - so the row is
            # held for the lookup below rather than written off here.
            h, where = target_hash(r)
            if h and a.found:
                unbuilt.append((r, src, h, where))
            continue
        dest = os.path.join(a.stage, "after", r["sha256"][:12] + ".bin")
        with open(dest, "wb") as fh:
            fh.write(masked)
        out[r["sha256"]] = {"after": dest, "before": src}

    # A SECOND TALLY, BECAUSE THESE ROWS ARE ALREADY COUNTED ONCE.
    #
    # Every row here has a rebuild state above - `mismatch` or `unrecorded` - and adding the
    # recovery into the same counter made the states sum to 146 over 142 rows. A total that
    # does not add up is the first thing a reader stops trusting, so recovery is counted
    # apart and the rebuild tally still describes every row exactly once.
    recovered = collections.Counter()
    if unbuilt:
        located = find_on_disk({(h, r["size"]) for r, _s, h, _w in unbuilt}, a.found)
        for r, src, h, where in unbuilt:
            if h not in located:
                recovered["not rebuilt and not on disk"] += 1
                continue
            recovered["found on disk (%s)" % where] += 1
            out[r["sha256"]] = {"after": located[h], "before": src}

    print("masked rows                : %d" % sum(tally.values()))
    for k in sorted(tally):
        print("  %-40s %d" % (k, tally[k]))
    if unbuilt:
        print("of those, offered to the disk lookup : %d  (roots: %s)"
              % (len(unbuilt), ", ".join(a.found)))
        for k in sorted(recovered):
            print("  %-40s %d" % (k, recovered[k]))
    print("rows with bytes this tool can prove  : %d of %d"
          % (len(out), sum(tally.values())))
    if mismatches:
        print()
        print("=== regenerated bytes that do NOT hash to the recorded masked_sha256 ===")
        print("  These are not staged. The row's masked form was produced by something this")
        print("  tree no longer reproduces - a different flag, map or vocabulary - and that")
        print("  is a finding about the row, not a reason to search for a match.")
        for sha, why in mismatches[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(mismatches) > 10:
            print("  ... and %d more" % (len(mismatches) - 10))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1)
        print()
        print("bytes map written          : %s (%d rows)" % (a.out, len(out)))
    return 0


def inject():
    """The regeneration must be able to say all three things, and must not search."""
    import shutil, tempfile
    fails, ran = [], []

    def case(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-64s %-22s %s" % (label, str(got)[:22],
                                    "ok" if ok else "WRONG (wanted %s)" % (want,)))
        if not ok:
            fails.append(label)

    if not os.path.exists(incident_mask.MAP_PATH):
        print("  ~ the map is not on this machine; the regeneration half cannot run.")
        print("    Reported rather than passed - see gate_provenance.verify().")
        return 0
    m = incident_mask.load_map(incident_mask.MAP_PATH)
    vocab = {"admin", "index", "upload", "cache"}
    ident = next(iter(sorted(m["mapping"], key=len, reverse=True)))
    # An IPv4 is in the probe deliberately: `--mask-ipv4` is one of the flags whose
    # setting changes the output, and a probe with nothing for it to act on would make the
    # flag case degenerate into the default one and pass while measuring nothing.
    raw = ("<?php $p = '/home/%s/public_html/index.php'; $ip = '198.51.100.7';\n"
           % ident).encode()
    masked, _d = content_mask.mask_sample(raw, m, vocabulary=vocab)

    def row(**kw):
        r = {"sha256": hashlib.sha256(raw).hexdigest(),
             "masking": {"applied": True,
                         "masked_sha256": hashlib.sha256(masked).hexdigest()}}
        r["masking"].update(kw)
        return r

    print("=== the three states ===")
    case("bytes that regenerate to the recorded hash",
         regenerate(row(), raw, m, vocab)[0], "regenerated")
    bad = row(masked_sha256="0" * 64)
    case("bytes that do not", regenerate(bad, raw, m, vocab)[0], "mismatch")
    none = row()
    none["masking"].pop("masked_sha256")
    case("a row recording no masked_sha256", regenerate(none, raw, m, vocab)[0],
         "unrecorded")
    other = row()
    case("source bytes that do not hash to the row",
         regenerate(other, raw + b"x", m, vocab)[0], "mismatch")

    print()
    print("=== a mismatch must not be staged, and must not be retried under other flags ===")
    # The masker is deterministic in its flags, so a different flag is a different output.
    # A tool that retried until something matched would manufacture a provenance claim.
    alt, _d = content_mask.mask_sample(raw, m, vocabulary=vocab, mask_ipv4=True,
                                       mask_hex_digests=True)
    # The premise, asserted rather than assumed: without it the two cases below are the
    # default case twice over.
    case("the flags actually change the output on this probe", alt != masked, True)
    flagged = row(masked_sha256=hashlib.sha256(alt).hexdigest())
    state, data, _why = regenerate(flagged, raw, m, vocab)          # default flags
    case("a row masked under other flags is a mismatch, not a search", state, "mismatch")
    case("and nothing is returned to stage", data is None, True)

    print()
    print("=== the regeneration is deterministic ===")
    a1 = regenerate(row(), raw, m, vocab)[1]
    a2 = regenerate(row(), raw, m, vocab)[1]
    case("two runs produce identical bytes", a1 == a2, True)
    case("and the length is preserved", len(a1) == len(raw), True)

    print()
    print("=== a row recording changes:0 is proved by the rebuild, and can still fail ===")
    # The six published rows this state exists for record no `masked_sha256` because the
    # pass changed nothing, so there was no second file to hash. The row still says what its
    # masked bytes are, and `sha256` is the hash of them.
    plain = b"<?php echo 1; // nothing here to mask\n"
    unchanged = {"sha256": hashlib.sha256(plain).hexdigest(),
                 "masking": {"applied": True, "changes": 0}}
    st, data, why = regenerate(unchanged, plain, m, vocab)
    case("a changes:0 row whose rebuild is its input", st, "regenerated-unchanged")
    case("and the bytes it yields are those bytes", data == plain, True)
    case("the reason names the field it was proved against",
         "sha256" in (why or ""), True)
    # The positive half, and the reason this is a proof rather than a relaxation: a row that
    # CLAIMS changes:0 over bytes the masker does touch must be refused, not accepted.
    leaky = ("<?php $p = '/home/%s/public_html/index.php';\n" % ident).encode()
    lying = {"sha256": hashlib.sha256(leaky).hexdigest(),
             "masking": {"applied": True, "changes": 0}}
    case("a changes:0 row whose rebuild is NOT its input",
         regenerate(lying, leaky, m, vocab)[0], "mismatch")
    # And a row with neither a hash nor the claim is still declined rather than guessed at.
    case("a row with no hash and no changes:0 claim",
         regenerate({"sha256": hashlib.sha256(plain).hexdigest(),
                     "masking": {"applied": True, "changes": 4}}, plain, m, vocab)[0],
         "unrecorded")

    print()
    print("=== the hash a row records for its masked bytes, and where it is read from ===")
    case("masked_sha256 is the field",
         target_hash({"masking": {"masked_sha256": "a" * 64}}), ("a" * 64, "masked_sha256"))
    case("a remeasured record is the named fallback",
         target_hash({"masking": {"remeasured": {"bytes_sha256": "b" * 64}}}),
         ("b" * 64, "remeasured.bytes_sha256"))
    case("the field wins where a row has both",
         target_hash({"masking": {"masked_sha256": "a" * 64,
                                  "remeasured": {"bytes_sha256": "b" * 64}}})[1],
         "masked_sha256")
    case("and a row with neither says so",
         target_hash({"masking": {"applied": True}}), (None, None))

    print()
    print("=== the disk lookup takes a file only where it hashes to what was asked for ===")
    tmpd = tempfile.mkdtemp(prefix="restage-found.")
    try:
        blob = b"masked bytes that are already on disk"
        want = hashlib.sha256(blob).hexdigest()
        with open(os.path.join(tmpd, "a.bin"), "wb") as fh:
            fh.write(blob)
        # A decoy of the SAME SIZE, so the size filter cannot be what makes this pass.
        with open(os.path.join(tmpd, "decoy.bin"), "wb") as fh:
            fh.write(b"masked bytes that are already ON DISK")
        got = find_on_disk({(want, len(blob))}, [tmpd])
        case("the file whose bytes hash to the wanted hash is found",
             os.path.basename(got.get(want, "")), "a.bin")
        case("and a same-size file that does not hash to it is not returned",
             len(got), 1)
        case("a hash nothing on disk holds returns nothing",
             find_on_disk({("c" * 64, len(blob))}, [tmpd]), {})
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)

    print()
    print("=== the vocabulary is load-bearing, and its absence is a hard failure ===")
    tmp = tempfile.mkdtemp(prefix="restage-inject.")
    try:
        empty = os.path.join(tmp, "not-a-dir")
        try:
            build_vocabulary([empty])
            got = "returned"
        except SystemExit:
            got = "refused"
        case("a vocabulary root that is not a directory", got, "refused")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
