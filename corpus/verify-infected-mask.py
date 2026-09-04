#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent check that no client identifier survives in the rows this round writes.

CORPUS_PLAN 5.3: "Verification must not share the masker's regexes. A self-check built from
the same patterns passes while being wrong." So this shares nothing with `infected_mask.py` -
no compiled pattern, no alternation, no import of it. It uses `str.startswith` over an
enumerated vocabulary.

It is also NOT a substring sweep, and that is the second half of the same lesson. A substring
sweep over this corpus reported `wp` in 52,103 rows (all `wp-content`) and `global` in 227
(all Elementor). A sweep whose output is thousands of hits that must each be explained away
is a sweep nobody finishes.

What it does instead is POSITIVE and finite:

  1. enumerate every distinct path segment the rows actually store, from every string value
     in every row - not just the field someone remembered to mask (5.3 failure 2);
  2. for each segment, ask whether it BEGINS with a known client identifier at a separator
     boundary. That is a bounded question with a small answer set, and each hit is a real
     finding rather than a coincidence to be triaged away.

`--show-vocabulary` prints the segment vocabulary itself, which is the artefact worth reading:
it is the complete list of what these rows say, and it is short enough to read.
"""
import json, os, sys, collections, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
MAP = os.path.join("trail-data", "incoming", "2026-09-03", "private",
                   "infected-tree-mapping.json")
SEPARATORS = "/.-_@!:, \\'\"()[]{}=?&+"


# Words that are somebody's subdomain somewhere and nobody's identity anywhere. Without
# this the check drowns in exactly the noise it exists to avoid: run against the
# current-incident map, whose `domains` include several `server.*` and `test.*` subdomains,
# a first version reported `server`, `test` and `new` as leaks.
GENERIC = {"server", "test", "new", "www", "mail", "web", "dev", "staging", "demo", "old",
           "cdn", "api", "blog", "shop", "admin", "app", "static", "preview", "live"}


# Public suffixes that are TWO labels, so the owner's name is the third from the right.
# Not the full PSL - just the forms this collection actually contains. Without it
# a `<name>.com.gr` domain yields the label `com`, which is generic, matches everywhere and
# turns the check back into the substring sweep it exists to replace.
MULTI_SUFFIX = {"com.gr", "co.uk", "org.uk", "com.au", "co.nz", "com.br", "com.tr",
                "edu.gr", "gov.gr", "net.gr", "org.gr", "ac.uk", "co.il", "com.cy"}


def registrable_label(domain):
    """`example.gr` -> example, `a.b.example.com` -> example,
    `example.com.gr` -> example.

    The label that names the owner is the one before the public suffix, and the public
    suffix is not always one label. Getting this wrong does not produce a miss, it produces
    a generic token that matches everything - which is worse, because the output stops being
    readable and the check stops being run.
    """
    parts = [p for p in domain.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def identifiers(m):
    """Every real-world name this tree contains, as plain strings. Includes each domain's
    registrable label, because the bare label identifies the customer as surely as the
    full domain does."""
    out = set()
    for d in list(m["sites"]) + list(m["servers"]) + list(m["dirs_masked"]):
        out.add(d)
        out.add(registrable_label(d))
    out |= set(m["accounts"])
    out |= set(m["people"])
    return {x.lower() for x in out if len(x) >= 3 and x.lower() not in GENERIC}


def strings_in(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            for s in strings_in(v):
                yield s
    elif isinstance(obj, list):
        for v in obj:
            for s in strings_in(v):
                yield s


def segments_of(text):
    """Split on every separator. No regex: the point is not to reuse the masker's idea of
    what a boundary is."""
    cur, out = [], []
    for ch in text:
        if ch in SEPARATORS:
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rows", help="jsonl of the rows to check")
    ap.add_argument("--show-vocabulary", action="store_true")
    a = ap.parse_args()

    with open(MAP, encoding="utf-8") as fh:
        m = json.load(fh)
    ids = identifiers(m)
    keep = {x.lower() for x in m["keep_c2"]} | {x.lower() for x in m["impersonated_brands_kept"]}
    keep_segments = set()
    for k in keep:
        keep_segments |= {s.lower() for s in segments_of(k)}

    rows = [json.loads(l) for l in open(a.rows, encoding="utf-8") if l.strip()]
    vocab = collections.Counter()
    where = {}
    for r in rows:
        for s in strings_in(r):
            for seg in segments_of(s):
                vocab[seg] += 1
                where.setdefault(seg, r["sha256"])

    print("rows checked                 : %d" % len(rows))
    print("distinct path segments stored: %d" % len(vocab))
    print("client identifiers to look for: %d" % len(ids))

    # Two positions, because "begins with" alone has a blind spot that a control found:
    # a `%2F<client>.gr` reference in a cached URL splits to the segment `2f<client>`, which
    # does not BEGIN with the label. The masker handles that form; this check could not see
    # it, and a check that cannot see a form the masker handles cannot certify the masker.
    #
    # So containment, not prefix - which is affordable ONLY because these identifiers are
    # client names rather than words. That is the difference from the sweep that reported
    # `wp` in 52,103 rows: `wp` is a CMS prefix, a client label is a company. The 3-char floor
    # and the c2 keep-list are what hold the noise at zero, and the assertion below is that
    # it IS zero - if this ever starts reporting coincidences, it needs a longer floor, not
    # a looser test.
    hits = []
    for seg in sorted(vocab):
        low = seg.lower()
        if low in keep_segments:
            continue                       # attacker infrastructure, kept deliberately (4.1)
        for ident in ids:
            at = low.find(ident)
            if at < 0:
                continue
            rest = low[at + len(ident):]
            if rest and rest[0].isalnum():
                continue                   # a longer word that merely starts the same way
            hits.append((seg, ident, vocab[seg], where[seg], "begins" if at == 0 else "contains"))
            break

    print()
    if hits:
        print("=== SEGMENTS BEGINNING WITH A CLIENT NAME: %d ===" % len(hits))
        for seg, ident, n, sha, pos in hits:
            print("   %-40s %-8s %-22s n=%-5d %s" % (seg[:40], pos, ident, n, sha[:12]))
        print()
        print("FAIL: a client identifier survives in the stored rows.")
        return 1
    print("=== no stored segment begins with a client identifier ===")
    print("PASS")
    if a.show_vocabulary:
        print()
        print("=== the segment vocabulary these rows store (%d) ===" % len(vocab))
        for seg, n in vocab.most_common():
            print("   %-52s %d" % (seg[:52], n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
