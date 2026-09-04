#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The check that runs when a row moves from the local half to the published half.

WHY THIS IS A SEPARATE TOOL AND NOT A RULE IN `shard-gate.py`
------------------------------------------------------------
`shard-gate.py` is the gate on the published half, and its defining property is that it
needs **no map**: it asserts the FORM of what is allowed (`acctNN`, `siteNN`, `srvNN`, and
no `origin` field at all), so a stranger who clones this repository can run it and get the
same answer we do. The map is gitignored and out of repo, deliberately. That property is
worth more than any single rule, and nothing below may be moved into it.

The consequence is a real hole, and this file is the shape of the repair.

Incident-response directories are named `<token>-<what was done>-<8 digits>-<6 digits>`, and
the leading token is sometimes an account name and usually an operation verb. A published
row carrying `<clientname>-backup-component-validation-20260828-234000` in any field leaks a
customer into a public git repository, and neither of the gate's two invariants sees it: the
string is not an `origin` field and it contains no `/home<digits>/` at all.

**A form-based rule cannot close it.** Measured on the 80,536 rows of the local half as they
stood before this round's masking: requiring the leading token of every
`<token>-...-<8 digits>-<6 digits>` segment to be a pseudonym flags **16,656 rows** in order
to reach the **2,425** that actually carried a client name - 14,231 false positives, 85.4%.
The tokens it trips over are `live`, `ir`, `cross`, `renamed`, `post`, `orphaned`, `active`,
`core`: operation verbs, which is what that slot usually holds. A gate that fails 16,656
rows to catch 2,425 is a gate that gets switched off, and 5.3 already records what happens
to a check nobody finishes.

So the discriminator between "operation verb" and "customer" is **the map, and only the
map** - and the map is exactly what the published gate must not need. The check therefore
has to run at the moment the map is in the room, which is promotion. That is not a
workaround; it is where the information exists.

Promotion is also the right moment for a second reason. A published row is built OUT OF a
local row - 5.3 records four rows that carried an `origin` because a promotion copied the
whole local row - so the last point at which a leak is cheap to stop is the point at which
the new row is being constructed, not the commit after.

WHAT IT CHECKS
--------------
  1. every identifier the map knows, in both directions, over the exact text that will be
     written - delegated to `verify-infected-mask.py`, which shares no regex with either
     masker. This is what sees the incident-response directory shape;
  2. account names too short for that check to see safely, reported as a HOLD rather than a
     pass. `wp` is two characters and is also the name of half the paths in a WordPress
     tree; 5.3's rule is to mask it only where it can be the account and to gate exactly
     that. That leaves a real residue - the name in free prose, e.g. a `note` listing six
     accounts of which five are already pseudonyms - which no mechanical rule can resolve
     and which a human can resolve in seconds. It is surfaced here rather than tolerated
     silently, because the alternative is that nobody ever sees it;
  3. the map-free invariants themselves, borrowed from `shard-gate.py`, so a row cannot pass
     the map-aware check here and fail the public gate afterwards.

WHAT IT RECORDS
---------------
Category and count. Never the identifier. 5.3's seventh failure was a gate result stored in
the index, whose contents are by construction the names of the identifiers the gate had just
found - storing the finding stored the leak.
"""
import argparse, collections, importlib.util, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
INCIDENT_MAP = os.path.join("trail-data", "incoming", "2026-09-03", "private",
                            "account-mapping.json")


def _load(stem):
    """Import a sibling script whose filename has a hyphen in it."""
    spec = importlib.util.spec_from_file_location(
        stem.replace("-", "_"), os.path.join(HERE, stem + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VERIFY = _load("verify-infected-mask")
GATE = _load("shard-gate")

# Slots in which a short name really is the account, and is therefore already masked. Used
# only to subtract: anything left over is the same name somewhere it cannot be judged
# mechanically, which is the thing a human is being asked to look at.
POSITIONAL = [re.compile(r"/home\d*/[A-Za-z0-9._-]+"),
              re.compile(r"_home\d*_[A-Za-z0-9.-]+_"),
              re.compile(r"[A-Za-z0-9.-]+_public_html"),
              re.compile(r"php\d+-[A-Za-z0-9.-]+\.conf")]


def short_name_residue(rows, m):
    """Account names below the identifier check's floor, outside any positional slot.

    Not a failure of the masker and not a bug in the check: both are behaving exactly as 5.3
    requires. It is the gap between them, and promotion is the only place with both the map
    and a human.
    """
    # Below three characters is precisely what `identifiers()` drops, so this is the
    # complement of the check above rather than a second opinion about the same names.
    short = [a.lower() for a in m.get("mapping", {}) if len(a) < 3]
    if not short:
        return []
    out = []
    for r in rows:
        for s in VERIFY.strings_in(r):
            stripped = s
            for rx in POSITIONAL:
                stripped = rx.sub(" ", stripped)
            for seg in VERIFY.segments_of(stripped):
                if seg.lower() in short:
                    out.append((r.get("sha256", "?"), len(seg)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rows", help="jsonl of the rows about to be promoted, in published shape")
    ap.add_argument("--map", default=INCIDENT_MAP)
    ap.add_argument("--allow-short-residue", action="store_true",
                    help="a human has looked at the short-name occurrences and they are not "
                         "the account. Recorded as a decision, not a default.")
    a = ap.parse_args()

    with open(a.map, encoding="utf-8") as fh:
        m = json.load(fh)
    rows = [json.loads(l) for l in open(a.rows, encoding="utf-8") if l.strip()]

    # The exact text that will be written, not the objects in memory. `promote-index.py`
    # already gates the serialised bytes for the same reason: a field that survives
    # json.dumps is a field that reaches git.
    written = [json.loads(json.dumps(r, sort_keys=True)) for r in rows]

    ids = VERIFY.identifiers(m)
    keep = VERIFY.keep_tokens(m)
    contained, truncated, vocab = VERIFY.check(written, ids, keep)
    residue = short_name_residue(written, m)
    leaks = GATE.publishedLeaks(written)
    forms = GATE.formViolations(written)

    print("rows about to be promoted    : %d" % len(rows))
    print("map                          : %s" % a.map)
    print("client identifiers to look for: %d" % len(ids))
    print("distinct path segments stored: %d" % len(vocab))
    print()

    # Category and count only - never the identifier itself (5.3 failure 7).
    summary = collections.Counter()
    for _, _, _, _, pos in contained:
        summary["identifier-in-segment:" + pos] += 1
    for _, slot, _, _ in truncated:
        summary["truncated-identifier-in-slot"] += 1
    if residue:
        summary["short-account-name-outside-a-positional-slot"] += len(residue)
    for _, why in leaks:
        summary["published-invariant:" + why.split(":")[0]] += 1
    for _, why in forms:
        summary["masked-component-malformed"] += 1

    blocking = bool(contained or truncated or leaks or forms) or \
        (bool(residue) and not a.allow_short_residue)

    if summary:
        print("=== findings, by category ===")
        for cat, n in summary.most_common():
            print("  %-56s %5d" % (cat, n))
        print()
        print("  (categories and counts only: the identifiers are the thing being "
              "withheld)")
        print()

    if contained or truncated:
        print("An identifier the map knows survives in these rows. This is the check the "
              "published")
        print("gate cannot make, because the discriminator is the map. Re-mask, do not "
              "re-word.")
    if residue and not a.allow_short_residue:
        print("%d occurrence(s) of an account name too short to judge mechanically sit "
              "outside" % len(residue))
        print("any positional slot. Read them. If they are the account, mask them by hand "
              "and say so;")
        print("if they are CMS vocabulary, re-run with --allow-short-residue to record "
              "that decision.")
    elif residue:
        print("%d short-name occurrence(s) waived by --allow-short-residue: a human read "
              "them and" % len(residue))
        print("says they are CMS vocabulary, not the account. Recorded as a decision.")
    if leaks or forms:
        print("A map-free invariant from shard-gate.py fails too; the public gate would "
              "have caught")
        print("this one, but only after the row had already been written.")

    if blocking:
        print()
        print("REFUSING TO PROMOTE.")
        return 1
    print("=== PASS: nothing in these rows names a customer ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
