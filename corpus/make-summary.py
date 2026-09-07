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

# ------------------------------------------------------------- family-weighted detection
#
# A sample-weighted detection figure is a statement about the collection as much as about the
# scanner: it moves when one campaign is collected heavily. This corpus has that in an extreme
# form. A single 2017 doorway campaign supplies 495 of the 1,299 reviewed malicious rows, so
# the headline can fall by a third because one family was swept thoroughly and would rise the
# same way if one rule landed. Family-weighted detection asks the other question - how many
# distinct campaigns does the scanner catch at all - and the two answers differ by design.
# Neither is the true one, which is why they are generated side by side rather than one being
# chosen: sample weighting says the scanner misses a great deal, family weighting says it
# misses one thing prolifically, and a reader needs both to know which.
#
# THE DENOMINATOR IS THE WEAK PART, AND IT IS SECTION 11 IN A NEW PLACE
# ---------------------------------------------------------------------
# A family figure is computed over families that exist, and a family exists because somebody
# assigned one, so the metric is bounded by the labelling effort rather than by the corpus.
# 531 of the 1,299 reviewed malicious rows carry no family at all - and they are not a random
# 531: 530 of them are detected, so they hold 530 of the 696 recorded detections. Drop them
# silently and sample-weighted detection over what remains reads 21.6% instead of 53.6%. A
# family metric that quietly excluded them would be reporting who did the labelling.
#
# So the three populations are counted and published beside the rates, and they PARTITION the
# reviewed malicious set: `malicious_family_population` sums to `malicious_reviewed`, and
# `--inject` asserts that it does. The unfamilied rows cannot vanish out of a total; they can
# only be reported as what they are.
#
# A LABEL WHOSE MEMBERSHIP IS CONDITIONED ON DETECTION IS NOT A FAMILY
# --------------------------------------------------------------------
# `import-infected-tree.py` assigns one label under `if hit`: a sample is in it BECAUSE the
# scanner flagged it, and the row records that as `reason: detected-and-read`. Counting it as
# a family makes it fully detected by construction and moves family coverage in the flattering
# direction - section 11 again, this time in the numerator's own selection rule rather than in
# a denominator.
#
# Three independent properties agree that it is a provenance bucket rather than a campaign,
# and the sweep that established it was a census over all 39 labelled families, not a sample:
#
#   * its 61 members carry 39 distinct expected rule-sets with NO rule shared by all of them,
#     spanning eight unrelated rule prefixes; every other multi-member family either shares a
#     rule across all its detected members or fires one rule-set
#   * its single technique is the most generic one in the vocabulary and no other family
#     carries it, so excluding the bucket costs technique coverage exactly one technique
#   * its verdict_reason is a five-way disjunction of unrelated malware classes, which is the
#     shape of a label written for a pile rather than for a campaign
#
# Its rows are NOT dropped. They move into their own population, counted and named, because a
# sample that was reviewed does not stop having been reviewed.
DETECTION_CONDITIONED_REASONS = {"detected-and-read"}
# Adding a review pass whose selection rule reads the scanner's own output, and not adding its
# reason code here, silently readmits the defect - the way `SHIPPED` above went stale and
# reclassified 58 rows. `family_bucket_suspects` is the control that does not depend on this
# set being maintained: it recomputes rule-set dispersion from the rows every run and names any
# family carrying the shape, whatever reason code it arrived under.


def family_population(r):
    """Which of the three reviewed-malicious populations a row is in.

    Exhaustive by construction, and that is the whole point: every reviewed malicious row is in
    exactly one, so the three counts sum to `malicious_reviewed` and the unfamilied half cannot
    be lost by a metric that simply does not mention it.
    """
    if r.get("reason") in DETECTION_CONDITIONED_REASONS:
        return "provenance_bucketed"
    if r.get("family"):
        return "campaign_familied"
    return "unfamilied"


def is_detected(r):
    """The one detection predicate, shared with `malicious_detected` above.

    A row is detected when it carries an expected rule; a known miss and a row with no
    expectation recorded at all are both not-detected. Written once and called from both the
    sample-weighted and the family-weighted counts, because two predicates that are meant to be
    the same predicate are exactly how a family figure comes to disagree with the headline it is
    printed beside.
    """
    return bool((r.get("expect") or {}).get("must_detect"))


def family_state(rows):
    """'fully_detected' | 'partially_detected' | 'completely_missed'. Three states, never two.

    Collapsing partial into either neighbour discards the same information as collapsing a
    row's several publish blockers into one reason. Five of the 38 campaign families are
    partial; a reader told only "9 detected, 29 not" cannot see that four of those 29 are
    families the scanner catches most of.
    """
    d = sum(1 for r in rows if is_detected(r))
    if d == len(rows):
        return "fully_detected"
    if d == 0:
        return "completely_missed"
    return "partially_detected"


def family_metrics(rows):
    """The family block over an arbitrary row set, so the excl-predates variant is the same code.

    `macro_rate` weights every family equally; `micro_rate` weights every sample equally over
    the same rows. Both are reported because they answer different questions, and because a
    macro average that tracked the micro average on every input would not be measuring what it
    claims: over the same 707 rows these read 29.9% and 14.9%.
    """
    fams = collections.defaultdict(list)
    for r in rows:
        if family_population(r) == "campaign_familied":
            fams[r["family"]].append(r)
    by_state = collections.Counter(), collections.Counter()
    for g in fams.values():
        st = family_state(g)
        by_state[0][st] += 1
        by_state[1][st] += len(g)
    n_rows = sum(len(g) for g in fams.values())
    n_det = sum(1 for g in fams.values() for r in g if is_detected(r))
    rates = [sum(1 for r in g if is_detected(r)) / float(len(g)) for g in fams.values()]
    return {
        "families": len(fams),
        "rows": n_rows,
        "detected_rows": n_det,
        "fully_detected": by_state[0]["fully_detected"],
        "partially_detected": by_state[0]["partially_detected"],
        "completely_missed": by_state[0]["completely_missed"],
        "rows_fully_detected": by_state[1]["fully_detected"],
        "rows_partially_detected": by_state[1]["partially_detected"],
        "rows_completely_missed": by_state[1]["completely_missed"],
        # SIX DECIMAL PLACES, NOT FOUR, AND THE REASON IS A FIGURE THAT WAS ALREADY WRONG.
        # `micro_rate` was stored rounded to 4dp and `doc-figures.py` rendered it as a
        # percentage by rounding again: 105/707 is 14.8515%, which reads 14.9% from the pair
        # and 14.8% from the pre-rounded 0.1485. The published table said 14.8% while the
        # prose beside it said 14.9% and both were derived from this one key. Double rounding
        # is a silent one-digit lie, so the stored rate keeps enough precision that a second
        # rounding cannot move it - and `doc-figures.py` renders micro from the published
        # integer pair anyway, with a control asserting the two agree.
        "macro_rate": round(sum(rates) / len(rates), 6) if rates else None,
        "micro_rate": round(n_det / float(n_rows), 6) if n_rows else None,
    }


def family_bucket_suspects(rows):
    """Labelled families whose detected members share no expected rule: the shape of a pile.

    Deliberately independent of `DETECTION_CONDITIONED_REASONS`. That set is maintained by
    hand and will go stale; this recomputes from the rows every run, so a bucket arriving under
    a new reason code is named rather than silently counted as a campaign. It reports and does
    not exclude - "these members share no rule" is evidence for a person to rule on, not a
    verdict a summary generator should reach by itself.

    Three detected members is the floor. Two members firing two rule-sets is an ordinary
    campaign whose payloads differ, and flagging that would make this fire on real families and
    stop being read.
    """
    out, fams = {}, collections.defaultdict(list)
    for r in rows:
        if r.get("family"):
            fams[r["family"]].append(r)
    for f, g in sorted(fams.items()):
        sets = [set((r.get("expect") or {}).get("must_detect") or []) for r in g]
        sets = [s for s in sets if s]
        if len(sets) < 3 or set.intersection(*sets):
            continue
        out[f] = {"members": len(g), "detected": len(sets),
                  "distinct_rule_sets": len({frozenset(s) for s in sets}),
                  "rules_shared_by_all": 0}
    return out


def family_rerun_power(pub_rows, campaign_rows):
    """How much of each family verdict a stranger can actually re-execute.

    A family's three-state verdict is read off `expect.must_detect`, which is a RECORDED result
    from an earlier rescan. `verify.py` re-runs only the rows whose bytes ship in a public
    shard, and the largest families are not among them. Publishing the family split without
    this is publishing a census whose biggest cells nothing re-executed - and §11's habit is
    that the cell nobody checked is the one that is wrong.
    """
    runnable = {r["sha256"] for r in pub_rows if ships_as_bytes(r)}
    fams = collections.defaultdict(list)
    for r in campaign_rows:
        fams[r["family"]].append(r)
    # Rows as well as families, for each of the three states. The family counts alone read
    # "23 of 38 fully re-runnable" and invite the conclusion that most of the census is
    # reproducible; the row counts say 77 of 707, because the re-runnable families are the
    # small ones. A results document quoting either should be able to derive both from here
    # rather than recomputing - the first draft of this round's write-up recomputed it by
    # hand and reported 146.
    st, rows = collections.Counter(), collections.Counter()
    for g in fams.values():
        c = sum(1 for r in g if r["sha256"] in runnable)
        k = ("every_member_rerun" if c == len(g)
             else "no_member_rerun" if c == 0 else "some_members_rerun")
        st[k] += 1
        rows[k] += len(g)
    return {"families": len(fams),
            "every_member_rerun": st["every_member_rerun"],
            "some_members_rerun": st["some_members_rerun"],
            "no_member_rerun": st["no_member_rerun"],
            "rows_every_member_rerun": rows["every_member_rerun"],
            "rows_some_members_rerun": rows["some_members_rerun"],
            "rows_in_families_with_no_member_rerun": rows["no_member_rerun"]}



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
    # The same predicate, kept by reason code. `published_reason_codes` cannot answer this:
    # it counts every published row under its reason, so its shipping codes sum to 142 and
    # include the two rows whose files were dropped out of the archives. A document that
    # wants to say WHICH samples ship - and `SOURCES.md` does - was left computing the
    # breakdown by hand, and did: it named four reason codes at their pre-drop counts and
    # omitted `undetected-pool-review` entirely, which is the stale-set defect above
    # reproduced one level out, in prose, where no --check could see it. It can see it now.
    shipped_by_reason = dict(sorted(collections.Counter(
        r["reason"] for r in pub if ships_as_bytes(r)).items()))

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

    # The reviewed malicious set, split into the three populations a family figure has to
    # keep apart. Built once and passed around, so the family block and the population
    # counts cannot be computed over two different row sets.
    mal = [r for r in allr if r.get("verdict") == "malicious"]
    fam_pop = {k: 0 for k in ("campaign_familied", "provenance_bucketed", "unfamilied")}
    fam_pop_det = dict.fromkeys(fam_pop, 0)
    for r in mal:
        fam_pop[family_population(r)] += 1
        if is_detected(r):
            fam_pop_det[family_population(r)] += 1
    campaign = [r for r in mal if family_population(r) == "campaign_familied"]
    det_conditioned = dict(sorted(collections.Counter(
        r.get("family") or "<unfamilied>" for r in mal
        if family_population(r) == "provenance_bucketed").items()))

    s = {
        "total_blobs": len(allr),
        "published": len(pub),
        "local_only": len(loc),
        "published_shipped_as_bytes": shipped,
        "published_shipped_by_reason": shipped_by_reason,
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
        # ---- family-weighted detection, generated beside the sample-weighted figure ----
        # Why both, why the populations are counted rather than the unfamilied rows quietly
        # dropped, and why one labelled group is not allowed to be a family: see the long
        # block above `family_population`.
        "malicious_family_population": fam_pop,
        "malicious_family_population_detected": fam_pop_det,
        "families_detection_conditioned": det_conditioned,
        "family_detection": family_metrics(mal),
        "family_detection_excl_predates_ruleset": family_metrics(
            [r for r in mal if not r.get("predates_ruleset")]),
        "family_bucket_suspects": family_bucket_suspects(mal),
        "family_rerun_power": family_rerun_power(pub, campaign),
        # Technique coverage is the same question asked a third way, and it is silent about
        # EXACTLY the same rows: the set carrying no technique and the set carrying no family
        # are the same 531 rows, not merely the same size. Counted here so a reader can see
        # that the two coverage figures share one blind spot rather than corroborating each
        # other.
        "malicious_rows_without_technique": sum(1 for r in mal if not r.get("technique")),
        "malicious_family_population_note": (
            "the three populations partition the reviewed malicious set and sum to "
            "malicious_reviewed. campaign_familied carries an attacker-campaign label; "
            "provenance_bucketed carries a label whose membership is conditioned on the "
            "scanner having flagged the sample, so it is fully detected by construction and "
            "is kept out of every family rate; unfamilied carries no label at all. The "
            "unfamilied rows hold most of the recorded detections, so a family figure is "
            "silent about the part of the corpus that is doing best - which is why this key "
            "is published beside the rates and never folded into them"),
        "family_detection_note": (
            "macro_rate weights every family equally, micro_rate weights every sample "
            "equally, over the identical rows; they differ by a factor of two here and that "
            "gap is the result, not a discrepancy. A family is fully_detected only if every "
            "member carries an expected rule, completely_missed only if none does, and "
            "partially_detected otherwise - three states, because collapsing partial into "
            "either neighbour loses which families the scanner catches most of. Detection "
            "uses the same predicate as malicious_detected, so the family figures and the "
            "headline cannot drift apart"),
        "family_bucket_suspects_note": (
            "labelled families whose three or more detected members share no expected rule. "
            "Evidence that a label groups a pile rather than a campaign, recomputed from the "
            "rows every run so a bucket arriving under a new reason code is named rather "
            "than counted as a family. Reported, never auto-excluded: reclassifying a label "
            "is a human judgement"),
        "family_rerun_power_note": (
            "a family's three-state verdict is read from a recorded rescan; verify.py "
            "re-executes only the members whose bytes ship in a public shard. These counts "
            "say how much of the family census a stranger can reproduce, and the families "
            "nothing re-runs are the largest ones"),
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
    print("=== the family verdict, on constructed rows ===")

    def case(label, ok):
        cases.append((label, None, None))
        print("  %-64s %s" % (label, "ok" if ok else "WRONG"))
        if not ok:
            fails.append(label)

    def row(fam, detected, reason=None, predates=False, n=[0]):
        n[0] += 1
        r = {"verdict": "malicious", "sha256": "%040d" % n[0],
             "expect": ({"must_detect": ["RULE001"]} if detected else {"known_miss": True})}
        if fam:
            r["family"] = fam
        if reason:
            r["reason"] = reason
        if predates:
            r["predates_ruleset"] = True
        return r

    # The three states, each asserted to be reachable AND asserted not to be one of the
    # others. "reads fully_detected" alone would pass on an implementation that always says
    # fully_detected, which is the shape of every check this project has caught being blind.
    case("a family whose every sample is detected    reads fully_detected",
         family_state([row("a", True), row("a", True), row("a", True)]) == "fully_detected")
    st = family_state([row("b", True), row("b", True), row("b", False)])
    case("a family with a single miss                reads partially_detected",
         st == "partially_detected")
    case("  ...and specifically NOT fully_detected", st != "fully_detected")
    case("a family with no detections                reads completely_missed",
         family_state([row("c", False), row("c", False)]) == "completely_missed")
    case("one detected member out of many            reads partially_detected, not missed",
         family_state([row("d", True)] + [row("d", False) for _ in range(9)])
         == "partially_detected")

    # A MACRO AVERAGE THAT TRACKS THE MICRO AVERAGE ON EVERY INPUT IS NOT MEASURING WHAT IT
    # CLAIMS. Both directions: it must diverge when family sizes are lopsided, and it must
    # agree when they are not. Only the pair proves the divergence is the data rather than
    # the arithmetic.
    lopsided = ([row("big", False) for _ in range(100)]
                + [row("s1", True), row("s2", True), row("s3", True)])
    fm = family_metrics(lopsided)
    case("lopsided families: macro and micro disagree",
         fm["macro_rate"] != fm["micro_rate"])
    case("  ...macro 0.75 (3 of 4 families) vs micro 0.029126 (3 of 103 rows)",
         fm["macro_rate"] == 0.75 and fm["micro_rate"] == round(3 / 103.0, 6))
    even = [row("e1", True), row("e1", False), row("e2", True), row("e2", False)]
    fe = family_metrics(even)
    case("equal-sized families at equal rates: macro == micro",
         fe["macro_rate"] == fe["micro_rate"] == 0.5)

    # THE POPULATION THE METRIC IS SILENT ABOUT CANNOT VANISH FROM A TOTAL.
    # This is the one the credibility of the whole figure rests on: the unfamilied rows are
    # where most of the detections are, so a partition that leaked them would flatter or
    # damn the scanner depending only on which way the leak went.
    mixed = ([row("f", True), row("f", False)]
             + [row(None, True) for _ in range(7)]
             + [row("bucketlabel", True, reason="detected-and-read") for _ in range(4)])
    pop = {k: 0 for k in ("campaign_familied", "provenance_bucketed", "unfamilied")}
    for r in mixed:
        pop[family_population(r)] += 1
    case("the three populations partition the constructed set",
         sum(pop.values()) == len(mixed) == 13)
    case("  ...7 unfamilied rows are counted, not dropped", pop["unfamilied"] == 7)
    fmx = family_metrics(mixed)
    case("  ...and none of them reach the family rate", fmx["rows"] == 2)
    case("  ...so rows outside the family metric are 11, and named",
         len(mixed) - fmx["rows"] == 11)

    # A label whose membership is conditioned on detection leaves the family census and stays
    # in the total. Both halves asserted: excluding it without counting it elsewhere is the
    # same defect wearing the opposite sign.
    case("a detection-conditioned label is not a family",
         "bucketlabel" not in {r["family"] for r in mixed
                               if family_population(r) == "campaign_familied"})
    case("  ...its rows are still in the partition total", pop["provenance_bucketed"] == 4)
    case("  ...and it cannot inflate the family counts",
         fmx["families"] == 1 and fmx["fully_detected"] == 0)

    # The dispersion detector, which must not depend on the reason-code set being maintained.
    pile = [row("pile", True) for _ in range(3)]
    for i, r in enumerate(pile):
        r["expect"] = {"must_detect": ["RULE%03d" % i]}
    camp = [row("camp", True) for _ in range(3)]
    for i, r in enumerate(camp):
        r["expect"] = {"must_detect": ["SHARED1", "RULE%03d" % i]}
    two = [row("two", True) for _ in range(2)]
    for i, r in enumerate(two):
        r["expect"] = {"must_detect": ["RULE%03d" % i]}
    case("members sharing no expected rule            flagged as a bucket suspect",
         "pile" in family_bucket_suspects(pile))
    case("members sharing one expected rule           NOT flagged",
         "camp" not in family_bucket_suspects(camp))
    case("two members, two rule-sets                  NOT flagged (below the floor)",
         "two" not in family_bucket_suspects(two))
    case("the detector needs no reason code to fire",
         family_bucket_suspects(pile)["pile"]["distinct_rule_sets"] == 3)

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
