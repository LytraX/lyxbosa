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
  corpus/make-summary.py --inject   controls for the argument dispatch

AN UNRECOGNISED ARGUMENT IS AN ERROR, NEVER THE DEFAULT
--------------------------------------------------------
The dispatch was `if "--check" in sys.argv: ... else: write`, so `--help`, a typo, or any
flag added later fell through to the WRITE path: asking this file a question overwrote it.
It is small and it is the wrong shape - the one irreversible thing this tool does was the
thing it did when it did not understand you, and this file is the denominator every suite
run quotes. `dispatch()` now returns an error for anything it does not recognise and
`--inject` asserts that it can.
"""
import collections, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import clearance                                                        # noqa: E402

# Every gate a human can clear a finding on. Imported rather than restated, so a gate added
# to the clearance rule cannot become an override this file does not count.
CLEARABLE = clearance.CLEARABLE_GATES

# Reason codes whose samples ship as BYTES in a shard. Everything else is an index row plus
# a lockfile entry, reproducible with fetch-benign.sh rather than shipped (SOURCES.md 6).
SHIPPED = {"media-polyglot", "staging-directory-review", "outside-webroot-sweep",
           "doorway-kit-review", "undetected-pool-review"}
# Adding a reason code without adding it here silently reclassifies its samples as
# "reproducible from a pinned source", which is the opposite of the truth. --check catches a
# stale summary; nothing catches a stale set, so keep this beside the shard that uses it.
#
# NOTHING CAUGHT IT, AND THE COMMENT ABOVE PREDICTED EXACTLY HOW.
# ---------------------------------------------------------------
# `undetected-pool-review` was added as a reason code and not added here, so its 58 rows -
# every one of them shipping as bytes in `malicious-uploaders-001`, `malicious-db-dropin-001`
# and `benign-attacker-artefacts-001` - were counted under `published_fetched_not_shipped`,
# which asserts they are reproducible from a pinned source. They are not; nothing outside
# the shard has them. `published_shipped_as_bytes` read 84 against 142 members actually
# shipped, and both `--check` and both `shard-gate` runs passed throughout, because the
# summary agreed with the index and the index was never asked about the archives.
#
# The control this comment asked for now exists and is not in this file: `shard-census.py`
# opens the shards, resolves every member to its row, and asserts this set equals the set of
# reason codes it actually observed. A stale set is now a failure with a name rather than a
# silent reclassification. It cannot live here - this file must run without the shards,
# which are gitignored release assets - so it lives with the tool that has them open.

def ships_as_bytes(r):
    """Does this row's sample ship as BYTES in a public shard?

    Two conditions, and the second one was missing.

    The reason code says the sample's bytes are the artefact rather than a fetch recipe. It
    does not say the bytes are IN a shard, and the two came apart the moment a round dropped
    a member: two rows were adjudicated unpublishable and their files removed from
    `malicious-staging-001` and `malicious-outside-webroot-001`, while their rows kept the
    reason code that records how they were FOUND - which is right, because a discovery route
    is not a publication decision, and rewriting it to fix the arithmetic would destroy the
    provenance instead.

    So the count gains the condition the archives already enforce. `shard-census.py` fails
    the build on "shipped row is not publishable today", so a row that is not publishable is
    not in a public shard, and counting it as shipped bytes asserts a file a stranger cannot
    fetch. 142 -> 140, and the two are exactly the two that were dropped.
    """
    return r.get("reason") in SHIPPED and r.get("publishable") is True


def build():
    pub = [json.loads(l) for l in open(os.path.join(HERE, "index.jsonl"))]
    locp = os.path.join(HERE, "local", "index-local.jsonl")
    loc = [json.loads(l) for l in open(locp)] if os.path.exists(locp) else []
    allr = pub + loc
    # PUBLISHABLE IS PART OF THE PREDICATE, AND IT WAS NOT.
    # --------------------------------------------------------
    # The reason code says a sample's bytes are the artefact rather than a fetch recipe. It
    # does not say the bytes are IN a shard, and the two came apart the moment a round
    # dropped a member: two rows were adjudicated unpublishable and their files removed from
    # `malicious-staging-001` and `malicious-outside-webroot-001`, while their rows kept the
    # reason code that records how they were FOUND - which is right, because a discovery
    # route is not a publication decision and rewriting it would destroy the provenance to
    # fix the arithmetic.
    #
    # So the count gains the condition the archives already enforce: `shard-census.py` fails
    # the build on "shipped row is not publishable today", so a row that is not publishable
    # is not in a public shard, and counting it as shipped bytes asserts a file a stranger
    # cannot fetch. 142 -> 140, and the two are the two that were dropped.
    shipped = sum(1 for r in pub if ships_as_bytes(r))

    # The one mechanism that can turn a recorded gate FAIL into a publishable row. It is
    # counted here so it is never invisible: a human override that only shows up when
    # someone runs the gate is an override nobody is watching, and this file is what the
    # suite quotes. Counted three ways because they answer different questions - how many
    # rows are standing on a human decision, how many decisions that is, and which gates
    # are being overridden, which is the one that would show a predicate being routed
    # around row by row instead of fixed.
    def cleared(rows):
        by_gate, n_rows, n_findings = collections.Counter(), 0, 0
        for r in rows:
            hit = 0
            for g in CLEARABLE:
                if clearance.applicable(r, g) is not None:
                    by_gate[g] += 1
                    hit += 1
            if hit:
                n_rows += 1
                n_findings += hit
        return n_rows, n_findings, dict(sorted(by_gate.items()))

    cl_rows, cl_findings, cl_by_gate = cleared(allr)
    pub_cl_rows, _pf, _pg = cleared(pub)

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
        # The residue the blocker table cannot show: rows in the local half that nothing
        # blocks. They are held because no shard carries their bytes or because they are
        # not classified far enough to ship, and neither of those is a `publish_blockers`
        # entry - so without this key they are a count with no attributed cause, which is
        # exactly what section 8 forbids. It read 0 for as long as the publishability gate
        # was one-directional, because a row that became publishable was never recorded as
        # having done so.
        "local_only_publishable_no_blocker": sum(
            1 for r in loc if r.get("publishable") is True),
        "cleared_by_human_rows": cl_rows,
        "cleared_by_human_findings": cl_findings,
        "cleared_by_human_by_gate": cl_by_gate,
        "published_cleared_by_human_rows": pub_cl_rows,
        "known_miss": sum(1 for r in allr if (r.get("expect") or {}).get("known_miss")),
        # The detection denominator, over BOTH halves. It has to be every reviewed malicious
        # sample, not just the ones carrying must_detect: must_detect is populated FROM the
        # rescan, so a denominator built from it contains only samples that were detected and
        # is 100% by construction. See CORPUS_PLAN section 11.
        "malicious_reviewed": sum(1 for r in allr if r.get("verdict") == "malicious"),
        "malicious_detected": sum(1 for r in allr if r.get("verdict") == "malicious"
                                  and (r.get("expect") or {}).get("must_detect")),
        "malicious_known_miss": sum(1 for r in allr if r.get("verdict") == "malicious"
                                    and (r.get("expect") or {}).get("known_miss")),
        # Of the detected ones, how many SHIP and can therefore actually be re-run - and
        # "ship" is `ships_as_bytes`, not "is in the published index". The two were the same
        # number until a round dropped two members out of two shards, and then this counted
        # 98 while `verify.py` executed 97 and reported the detection figure as NOT
        # RECONCILED. The comment on this line already said "ship"; the predicate did not.
        "malicious_detected_runnable": sum(1 for r in pub if ships_as_bytes(r)
                                           and r.get("verdict") == "malicious"
                                           and (r.get("expect") or {}).get("must_detect")),
        "malicious_no_expectation": sum(1 for r in allr if r.get("verdict") == "malicious"
                                        and not (r.get("expect") or {}).get("must_detect")
                                        and not (r.get("expect") or {}).get("known_miss")),
        # Provenance split, section 11 in its newest place. `trail-data/Infected` is the tree
        # the FIRST version of these rules was written against, so detection measured over it
        # is partly a test of the rules against their own source material. The rows record
        # that at import; these keys are what make the record usable, so the figure can be
        # reported BOTH ways instead of only the flattering one.
        "predates_ruleset_blobs": sum(1 for r in allr if r.get("predates_ruleset")),
        "malicious_reviewed_excl_predates_ruleset": sum(
            1 for r in allr if r.get("verdict") == "malicious" and not r.get("predates_ruleset")),
        "malicious_detected_excl_predates_ruleset": sum(
            1 for r in allr if r.get("verdict") == "malicious" and not r.get("predates_ruleset")
            and (r.get("expect") or {}).get("must_detect")),
        "malicious_known_miss_excl_predates_ruleset": sum(
            1 for r in allr if r.get("verdict") == "malicious" and not r.get("predates_ruleset")
            and (r.get("expect") or {}).get("known_miss")),
        # Known misses by family, because one campaign can dominate the count and a bare
        # total cannot show that. 495 of them are a single 2017 doorway campaign; without
        # this key a reader has no way to see that from the summary alone.
        "malicious_known_miss_by_family": dict(collections.Counter(
            r.get("family", "<unfamilied>") for r in allr
            if r.get("verdict") == "malicious" and (r.get("expect") or {}).get("known_miss"))),
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
        "local_only_publishable_no_blocker_note": (
            "rows held local-only that the section 7.2 gate does not block. Held for a "
            "reason outside the gate's remit - no shard carries their bytes, or they lack "
            "the family/technique classification a published row needs - so they appear "
            "under no blocker and would otherwise be an unattributed count"),
        "cleared_by_human_note": (
            "a gate finding a person read and ruled a collision, recorded on the row with "
            "who, when, why, the digest of the finding it is about and the gate provenance "
            "it was judged against. `publishable` is still computed: a cleared row is "
            "publishable because the gate says so given a recorded human input, never "
            "because the field was written over. A clearance stops applying by itself when "
            "either the finding or the gate that produced it moves, and shard-gate.py "
            "reports the ones that have. Counted here so the number can be watched: it is "
            "the only route by which a recorded FAIL becomes a publishable row"),
        "local_only_blockers_note": ("a row may carry several blockers and is counted under "
                                     "each, so these sum to more than local_only. Reported this "
                                     "way deliberately: collapsing to one reason per row hides "
                                     "the specific, actionable blocker behind the generic one"),
        "generated_from": "corpus/make-summary.py over index.jsonl + local/index-local.jsonl",
    }
    return s

KNOWN_FLAGS = ("--check", "--inject")
USAGE = ("usage: make-summary.py            write index-summary.json\n"
         "       make-summary.py --check    exit non-zero if the file on disk disagrees\n"
         "       make-summary.py --inject   controls for the argument dispatch")


def dispatch(argv):
    """('write'|'check'|'inject', None) or (None, error). Exactly one is None.

    The default action WRITES, so it must be reachable only by asking for nothing at all.
    Every other input is either a flag this tool knows or an error.
    """
    unknown = [a for a in argv if a not in KNOWN_FLAGS]
    if unknown:
        return None, "unrecognised argument(s): %s" % " ".join(unknown)
    if "--check" in argv and "--inject" in argv:
        return None, "--check and --inject are different questions; pass one"
    if "--inject" in argv:
        return "inject", None
    if "--check" in argv:
        return "check", None
    return "write", None


def inject():
    """The dispatch must refuse what it does not understand, and must still do its job.

    Both halves. A dispatch that errored on everything would satisfy the negative cases and
    make the tool useless, so `[]` mapping to `write` is asserted beside them.
    """
    fails = []
    cases = [([], "write", None),
             (["--check"], "check", None),
             (["--inject"], "inject", None),
             # The bug: each of these used to reach the write path.
             (["--help"], None, "error"),
             (["-h"], None, "error"),
             (["--chekc"], None, "error"),
             (["--check", "--force"], None, "error"),
             (["index.jsonl"], None, "error"),
             (["--check", "--inject"], None, "error")]
    print("%-28s %-10s %s" % ("argv", "action", "verdict"))
    print("-" * 56)
    for argv, want_action, want_err in cases:
        action, err = dispatch(argv)
        ok = (action == want_action) and (bool(err) == (want_err is not None))
        print("%-28s %-10s %s" % (" ".join(argv) or "(none)", action or "error",
                                  "ok" if ok else "WRONG (wanted %s)"
                                  % (want_action or "error")))
        if not ok:
            fails.append(" ".join(argv) or "(none)")
    print()
    print("=== what counts as shipping as bytes ===")
    # Both directions. The predicate was the reason code alone and could not tell a row
    # whose file is in the tar from one whose file was dropped out of it.
    pcases = [("a publishable row with a shipping reason code",
               {"reason": "media-polyglot", "publishable": True}, True),
              ("the same row, adjudicated unpublishable",
               {"reason": "media-polyglot", "publishable": False}, False),
              ("a publishable row whose reason is a fetch recipe",
               {"reason": "benign-upstream", "publishable": True}, False),
              ("publishable absent entirely",
               {"reason": "media-polyglot"}, False)]
    for label, row, want in pcases:
        got = ships_as_bytes(row)
        ok = got == want
        cases.append((label, None, None))
        print("  %-52s %-6s %s" % (label, got, "ok" if ok else "WRONG (wanted %s)" % want))
        if not ok:
            fails.append(label)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(cases), len(cases) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


if __name__ == "__main__":
    action, error = dispatch(sys.argv[1:])
    if error:
        sys.exit("%s\n\n%s" % (USAGE, error))
    if action == "inject":
        sys.exit(inject())
    s = build()
    p = os.path.join(HERE, "index-summary.json")
    if action == "check":
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
