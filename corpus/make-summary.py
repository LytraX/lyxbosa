#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate index-summary.json from the two halves of the index.

This file is the denominator: it is what lets a suite run report "N verified, M held, of
which ..." instead of quoting a percentage of a population it chose. It was previously
written by hand, which is how it came to claim `shipped-sample: 2353` while also claiming
`published_shipped_as_bytes: 6` - two statements that cannot both be true. Generating it
removes the opportunity.

  corpus/make-summary.py            write index-summary.json
  corpus/make-summary.py --check    fail non-zero if the file on disk disagrees
"""
import collections, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Reason codes whose samples ship as BYTES in a shard. Everything else is an index row plus
# a lockfile entry, reproducible with fetch-benign.sh rather than shipped (SOURCES.md 6).
SHIPPED = {"media-polyglot", "staging-directory-review"}

def build():
    pub = [json.loads(l) for l in open(os.path.join(HERE, "index.jsonl"))]
    locp = os.path.join(HERE, "local", "index-local.jsonl")
    loc = [json.loads(l) for l in open(locp)] if os.path.exists(locp) else []
    allr = pub + loc
    shipped = sum(1 for r in pub if r.get("reason") in SHIPPED)
    s = {
        "total_blobs": len(allr),
        "published": len(pub),
        "local_only": len(loc),
        "published_shipped_as_bytes": shipped,
        "published_fetched_not_shipped": len(pub) - shipped,
        "published_reason_codes": dict(collections.Counter(
            r.get("reason", "<no basis recorded>") for r in pub)),
        "verdicts": dict(collections.Counter(r["verdict"] for r in allr)),
        "sensitivity_tags": dict(collections.Counter(
            t for r in allr for t in (r.get("sensitivity") or []))),
        "local_only_blockers": dict(collections.Counter(
            b for r in loc for b in (r.get("publish_blockers") or []))),
        "known_miss": sum(1 for r in allr if (r.get("expect") or {}).get("known_miss")),
        "discovered_by_blobs": dict(collections.Counter(
            d for r in allr for d in (r.get("discovered_by") or []))),
        "families_published": dict(collections.Counter(
            r["family"] for r in pub if r.get("family"))),
        # The milestone is technique COVERAGE, not sample count: the malicious set should
        # cover every distinct technique the corpus knows about. Counted over reviewed
        # malicious rows in both halves, so a technique held local-only still counts as known
        # and still shows up as a gap until something covering it can be published.
        "techniques_known": dict(collections.Counter(
            t for r in allr if r.get("verdict") == "malicious"
            for t in (r.get("technique") or []))),
        "techniques_published": dict(collections.Counter(
            t for r in pub if r.get("verdict") == "malicious"
            for t in (r.get("technique") or []))),
        "note": ("index.jsonl carries published samples only; the rest live in the gitignored "
                 "local/index-local.jsonl. This file is the denominator, so the suite can say "
                 "how much it is NOT testing. A suite that cannot say that overstates itself."),
        "local_only_blockers_note": ("a row may carry several blockers and is counted under "
                                     "each, so these sum to more than local_only. Reported this "
                                     "way deliberately: collapsing to one reason per row hides "
                                     "the specific, actionable blocker behind the generic one"),
        "generated_from": "corpus/make-summary.py over index.jsonl + local/index-local.jsonl",
    }
    return s

if __name__ == "__main__":
    s = build()
    p = os.path.join(HERE, "index-summary.json")
    if "--check" in sys.argv:
        cur = json.load(open(p))
        drift = {k: (cur.get(k), s[k]) for k in s if k != "generated_from" and cur.get(k) != s[k]}
        if drift:
            print("index-summary.json disagrees with the index:")
            for k, (a, b) in drift.items():
                print("  %-28s on disk=%s  computed=%s" % (k, a, b))
            sys.exit(1)
        print("index-summary.json agrees with the index")
        sys.exit(0)
    json.dump(s, open(p, "w"), indent=1, sort_keys=True)
    print("wrote %s" % p)
    for k in ("total_blobs", "published", "local_only", "published_shipped_as_bytes", "known_miss"):
        print("  %-30s %s" % (k, s[k]))
    print("  verdicts                       %s" % s["verdicts"])
