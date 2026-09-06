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


def regenerate(row, raw, m, vocab, mask_ipv4=False, mask_hex=False):
    """(state, bytes|None, detail). Three states, never two.

    'regenerated' - the rebuilt bytes hash to the `masked_sha256` the row already records,
                    so they are that file rather than a reconstruction of it
    'mismatch'    - they do not. Reported, never staged
    'unrecorded'  - the row records no hash to check against, so there is nothing this can
                    prove and it declines rather than staging an unidentified file
    """
    want = (row.get("masking") or {}).get("masked_sha256")
    if not want:
        return "unrecorded", None, "row records no masked_sha256"
    if hashlib.sha256(raw).hexdigest() != row["sha256"]:
        return "mismatch", None, "the source bytes do not hash to the row"
    masked, _detail = content_mask.mask_sample(raw, m, mask_ipv4=mask_ipv4,
                                               vocabulary=vocab, mask_hex_digests=mask_hex)
    got = hashlib.sha256(masked).hexdigest()
    if got != want:
        return "mismatch", None, "regenerated %s, row records %s" % (got[:12], want[:12])
    if len(masked) != len(raw):                                      # pragma: no cover
        return "mismatch", None, "regeneration changed the length"
    return "regenerated", masked, "hashes to the recorded masked_sha256"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", action="append", default=[])
    ap.add_argument("--originals", help="json of sha256 -> path to the ORIGINAL bytes")
    ap.add_argument("--vocabulary", action="append", default=[])
    ap.add_argument("--map", default=incident_mask.MAP_PATH)
    ap.add_argument("--stage", help="directory to write the regenerated bytes into")
    ap.add_argument("--out", help="write the two-sided bytes map here")
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
    out, mismatches = {}, []
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
        if state != "regenerated":
            if state == "mismatch":
                mismatches.append((r["sha256"], detail))
            continue
        dest = os.path.join(a.stage, "after", r["sha256"][:12] + ".bin")
        with open(dest, "wb") as fh:
            fh.write(masked)
        out[r["sha256"]] = {"after": dest, "before": src}

    print("masked rows                : %d" % sum(tally.values()))
    for k in sorted(tally):
        print("  %-24s %d" % (k, tally[k]))
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
