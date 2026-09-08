#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Write the corpus figures that tracked documents quote, from index-summary.json.

  corpus/doc-figures.py            rewrite every generated region in place
  corpus/doc-figures.py --check    exit non-zero if a document disagrees, naming the figure
  corpus/doc-figures.py --inject   controls, both directions

WHY THIS EXISTS
---------------
`README.md` said **detection is 22.2%, 172 of 774, with 602 recorded misses** and **the
corpus holds 91,669 blobs, of which 12,249 are classified and 79,420 unreviewed**. The index
said 53.6% (696 of 1,299), 603, and 92,800 blobs of which 46,016 are classified and 46,784
unreviewed. Both README claims were stale by several rounds; an outside reviewer reading the
published release found them, and they are the first thing a stranger reads. `SOURCES.md`
was two rounds stale in the other direction, still quoting `published_shipped_as_bytes: 84`
and `44,460` after `make-summary.py` itself had recorded the move to 142/44,402 and then to
140/44,404.

Nothing was wrong with the corpus in any of those cases. The documents had been corrected by
hand once and then not corrected again, which is what hand-correction always decays into. So
the repair is not a fresh set of hand-written numbers - that is the same defect with a newer
date on it - but a delimited region that a tool writes and a `--check` defends.

IT READS THE SUMMARY, NEVER THE INDEX, AND THAT IS THE POINT
------------------------------------------------------------
This tool could open `index.jsonl` and count. It deliberately does not. If it counted, a
document could agree with the index while disagreeing with `index-summary.json`, and the
project would have two denominators that nothing compares - which is the failure
`make-summary.py` was written to end, one level out. Reading only the summary makes the chain
single-file and transitive:

    index.jsonl + local/index-local.jsonl
        --(make-summary.py --check)-->  index-summary.json
        --(doc-figures.py --check)   -->  README.md, SOURCES.md

Both links are enforced, both run in `pre-push-check.py`, and neither can be satisfied by a
number nobody derived. A figure this tool cannot get from the summary is a figure that does
not belong in a generated region: see `MISSING_IS_AN_ERROR` below, and see the false-positive
rate in `README.md`, which is a measurement over a binary, is not in the summary, and is
therefore carried as a dated measurement rather than as a current fact.

WHAT GOES IN A REGION AND WHAT DOES NOT
---------------------------------------
A number that comes from the summary is generated. Prose that interprets it is written by a
person and must survive regeneration untouched. So the regions here are tables and nothing
else: the interpretation - why two detection figures are quoted, why precision is not
reported, why a coverage number going down is healthy - lives outside the markers and is
never rewritten. A renderer that emitted a sentence would eventually eat an argument.

MISSING_IS_AN_ERROR
-------------------
A region that is not in the file is a failure, in every mode. The tempting behaviour is to
skip it - regenerate what is there, check what is there - and that is precisely how a
generated block gets deleted in a merge and nobody learns. `--check` on a document with no
region must say so, not pass. Likewise a figure the summary does not carry raises rather than
rendering `None` into a published table.
"""
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

BEGIN = "<!-- BEGIN GENERATED %s — corpus/doc-figures.py writes this block; edit the tool, not the block -->"
END = "<!-- END GENERATED %s -->"
_BEGIN_RE = "<!-- BEGIN GENERATED %s[^\n]*-->"
_END_RE = "<!-- END GENERATED %s[^\n]*-->"


class Missing(Exception):
    """A figure the summary does not carry, or a region a document does not have."""


def _n(v):
    """1299 -> '1,299'. Every figure in a region is formatted once, here."""
    return "{:,}".format(v)


def _pct(num, den):
    """One decimal, and the division is never done twice in two places."""
    if not den:
        raise Missing("denominator is zero")
    return "%.1f%%" % round(100.0 * num / den, 1)


def _rate(v):
    """0.2992 -> '29.9%'. A rate the summary already computed, not a division done twice.

    `_pct` exists for figures whose numerator and denominator are both published; the family
    macro average has no such pair - it is a mean of per-family rates - so re-deriving it here
    would mean this file owning a second definition of it. It does not. It formats the one
    `make-summary.py` computed.
    """
    if v is None:
        raise Missing("rate is null")
    return "%.1f%%" % round(100.0 * v, 1)


# A rate over an empty population. NOT the same thing as a figure the summary does not carry:
# the key is there, the population is genuinely zero, and rendering `0.0%` would assert a
# measured rate over nothing. MISSING_IS_AN_ERROR still applies to the key itself - `_sub`
# below raises exactly as `_get` does - and this only covers the arithmetic.
DASH = "\u2014"


def _opt_rate(v):
    return DASH if v is None else _rate(v)


def _opt_pct(num, den):
    return DASH if not den else _pct(num, den)


def _sub(block, key, where):
    """A nested figure, with the same refusal `_get` makes one level up."""
    if not isinstance(block, dict) or key not in block:
        raise Missing("index-summary.json has no %s.%s - regenerate it with make-summary.py, "
                      "or stop quoting the figure" % (where, key))
    return block[key]


def _get(s, key):
    if key not in s:
        raise Missing("index-summary.json has no key %r - regenerate it with "
                      "make-summary.py, or stop quoting the figure" % key)
    return s[key]


# The three states `expect.known_miss` can be in, named here so the renderer cannot invent a
# fourth and a missing one cannot read as zero.
KNOWN_MISS_KINDS = ("rule-gap", "detected-not-shippable", "unverified")


def _kinds(block, where):
    """{kind: count} over KNOWN_MISS_KINDS, refusing anything unclassified.

    A `.get(kind, 0)` here would render a document in which an unmeasured row is silently a
    zero. The rows exist either way; what a default would hide is that nobody has measured
    them, which is exactly the failure the split was added to end.
    """
    if not isinstance(block, dict):
        raise Missing("%s is not a mapping of kind to count" % where)
    unknown = sorted(k for k in block if k not in KNOWN_MISS_KINDS)
    if unknown:
        raise Missing("%s carries %s, which is not a known_miss kind. `<unclassified>` means "
                      "classify-known-miss.py has not visited those rows; run it with --apply "
                      "before publishing a split that leaves them out"
                      % (where, ", ".join(repr(u) for u in unknown)))
    return {k: block.get(k, 0) for k in KNOWN_MISS_KINDS}


def figures(s):
    """Every figure any region may quote: name -> preformatted string.

    Named because `--check` reports the name. "detection disagrees" is actionable;
    "line 267 differs" sends the reader to count digits.
    """
    v = _get(s, "verdicts")
    det, rev = _get(s, "malicious_detected"), _get(s, "malicious_reviewed")
    dex = _get(s, "malicious_detected_excl_predates_ruleset")
    rex = _get(s, "malicious_reviewed_excl_predates_ruleset")
    km_by_fam = _get(s, "malicious_known_miss_by_family")
    top_fam, top_n = max(km_by_fam.items(), key=lambda kv: (kv[1], kv[0]))
    km_kind = _kinds(_get(s, "malicious_known_miss_by_kind"), "malicious_known_miss_by_kind")
    km_kind_scope = _kinds(_get(s, "malicious_known_miss_by_kind_excl_predates_ruleset"),
                           "malicious_known_miss_by_kind_excl_predates_ruleset")
    # The split has to add up to the union, or one of the three lines the README publishes is
    # over a population that is not the one the heading names. Checked here rather than in the
    # renderer so a document is never written from a partition that does not close.
    if sum(km_kind.values()) != _get(s, "known_miss"):
        raise Missing("malicious_known_miss_by_kind sums to %d but known_miss is %d - the "
                      "split does not partition the marker; rerun classify-known-miss.py"
                      % (sum(km_kind.values()), _get(s, "known_miss")))
    tech_pub, tech_known = len(_get(s, "techniques_published")), len(_get(s, "techniques_known"))
    classified = v["benign"] + v["malicious"]
    fam = _get(s, "family_detection")
    pop = _get(s, "malicious_family_population")
    popd = _get(s, "malicious_family_population_detected")
    rerun = _get(s, "family_rerun_power")
    cond = _get(s, "families_detection_conditioned")
    # The frame split. `family_detection` itself is deliberately NOT rendered as a rate
    # anywhere: it is the union across both sampling frames, which is a population nobody
    # drew. It is still read here, because the guard below has to know what that number is in
    # order to refuse a document that quotes it.
    bf = _get(s, "family_detection_by_frame")
    cond_b = _sub(bf, "sampling_frame_detection_conditioned", "family_detection_by_frame")
    unrec_b = _sub(bf, "sampling_frame_not_recorded", "family_detection_by_frame")
    cond_m = _sub(cond_b, "metrics", "family_detection_by_frame.sampling_frame_detection_conditioned")
    unrec_m = _sub(unrec_b, "metrics", "family_detection_by_frame.sampling_frame_not_recorded")

    def frame_label(block, metrics):
        """What the column header has to carry for the rate under it to mean anything."""
        if not metrics["families"]:
            return "no families carry this frame yet"
        fr = block.get("frame")
        if not isinstance(fr, dict):
            return "the rows under this frame do not record one shared pool"
        return ("detection-conditioned — %s of %s rows in the pool carry an expected rule"
                % (_n(fr["pool_detected"]), _n(fr["pool_rows"])))

    # The bucket is named in the table because "61 rows under a provenance label" with no
    # label is a figure a reader cannot check. If a second one is ever ruled a bucket, this
    # renders both rather than silently naming the first: a table that quietly stopped
    # mentioning one is the stale-set failure this file exists to prevent.
    bucket_label = "`, `".join(sorted(cond)) if cond else "none"
    return {
        "detection_pct": _pct(det, rev),
        "detection_ratio": "%s of %s" % (_n(det), _n(rev)),
        "detection_in_scope_pct": _pct(dex, rex),
        "detection_in_scope_ratio": "%s of %s" % (_n(dex), _n(rex)),
        "predates_ruleset": _n(_get(s, "predates_ruleset_blobs")),
        # --- the known_miss split ----------------------------------------------------------
        # `known_miss_mixed_total` and `known_miss_mixed_in_scope` are computed and rendered
        # NOWHERE. They are the two numbers this round exists to stop publishing: the union of
        # rows the scanner misses and rows the scanner detects but nothing ships, quoted under
        # a heading that says the first. `miss_violations` refuses a document that puts either
        # beside the words "known miss", the same way COMBINED_RATES refuses a family rate
        # over a population nobody drew.
        "known_miss_mixed_total": _n(_get(s, "known_miss")),
        "known_miss_mixed_in_scope": _n(_get(s, "malicious_known_miss_excl_predates_ruleset")),
        "known_miss_rule_gap": _n(km_kind["rule-gap"]),
        "known_miss_rule_gap_in_scope": _n(km_kind_scope["rule-gap"]),
        "known_miss_detected": _n(km_kind["detected-not-shippable"]),
        "known_miss_detected_in_scope": _n(km_kind_scope["detected-not-shippable"]),
        "known_miss_unverified": _n(km_kind["unverified"]),
        "known_miss_unverified_in_scope": _n(km_kind_scope["unverified"]),
        "largest_known_miss_family": "`%s`" % top_fam,
        "largest_known_miss_count": _n(top_n),
        "re_runnable": _n(_get(s, "malicious_detected_runnable")),
        "techniques": "%s of %s" % (_n(tech_pub), _n(tech_known)),
        "total_blobs": _n(_get(s, "total_blobs")),
        "classified": _n(classified),
        "unreviewed": _n(v["unreviewed"]),
        "published_rows": _n(_get(s, "published")),
        "local_rows": _n(_get(s, "local_only")),
        "shipped_as_bytes": _n(_get(s, "published_shipped_as_bytes")),
        "fetched_not_shipped": _n(_get(s, "published_fetched_not_shipped")),
        # --- family-weighted detection ---------------------------------------------------
        # Every one of these is read from the summary and none is recomputed here, for the
        # reason in IT READS THE SUMMARY, NEVER THE INDEX above: a family figure this file
        # derived itself could agree with the index while disagreeing with the denominator,
        # which is the two-denominators defect one level further out.
        "family_count": _n(fam["families"]),
        # --- one column per sampling frame, and no rate across the two -------------------
        # Every rate below is over ONE frame and is rendered beside that frame's label and its
        # own integer pair. `rate_violations` refuses a document that separates them.
        "frame_conditioned_label": frame_label(cond_b, cond_m),
        "frame_conditioned_families": _n(cond_m["families"]),
        "frame_conditioned_rows": _n(cond_m["rows"]),
        "frame_conditioned_fully": _n(cond_m["fully_detected"]),
        "frame_conditioned_partially": _n(cond_m["partially_detected"]),
        "frame_conditioned_missed": _n(cond_m["completely_missed"]),
        "frame_conditioned_macro_pct": _opt_rate(cond_m["macro_rate"]),
        # From the integer pair, never from the stored rate: both are published, so there is
        # no reason to round a rounded number. The stored `micro_rate` is kept for anything
        # reading the summary directly, and `--inject` asserts the two agree to a decimal.
        "frame_conditioned_micro_pct": _opt_pct(cond_m["detected_rows"], cond_m["rows"]),
        "frame_conditioned_micro_ratio": "%s of %s" % (_n(cond_m["detected_rows"]),
                                                       _n(cond_m["rows"])),
        "frame_unrecorded_label": "sampling frame not recorded",
        "frame_unrecorded_families": _n(unrec_m["families"]),
        "frame_unrecorded_rows": _n(unrec_m["rows"]),
        "frame_unrecorded_fully": _n(unrec_m["fully_detected"]),
        "frame_unrecorded_partially": _n(unrec_m["partially_detected"]),
        "frame_unrecorded_missed": _n(unrec_m["completely_missed"]),
        "frame_unrecorded_macro_pct": _opt_rate(unrec_m["macro_rate"]),
        "frame_unrecorded_micro_pct": _opt_pct(unrec_m["detected_rows"], unrec_m["rows"]),
        "frame_unrecorded_micro_ratio": "%s of %s" % (_n(unrec_m["detected_rows"]),
                                                      _n(unrec_m["rows"])),
        # Computed and NEVER rendered. These exist so the guard can name them in a document
        # that quotes one; see COMBINED_RATES.
        "family_combined_macro_pct": _opt_rate(fam["macro_rate"]),
        "family_combined_micro_pct": _opt_pct(fam["detected_rows"], fam["rows"]),
        "unfamilied_rows": _n(pop["unfamilied"]),
        "unfamilied_detected": _n(popd["unfamilied"]),
        "bucketed_rows": _n(pop["provenance_bucketed"]),
        "bucketed_label": "`%s`" % bucket_label,
        "rows_without_technique": _n(_get(s, "malicious_rows_without_technique")),
        "family_rerun_full": _n(rerun["every_member_rerun"]),
        "family_rerun_none": _n(rerun["no_member_rerun"]),
        "family_rerun_none_rows": _n(rerun["rows_in_families_with_no_member_rerun"]),
        "shipped_by_reason": ", ".join(
            "%s %s" % (_n(c), r) for r, c in sorted(
                _get(s, "published_shipped_by_reason").items(),
                key=lambda kv: (-kv[1], kv[0]))),
    }


# --------------------------------------------------------------------------- renderers
# Each returns [(figure_name_or_None, line)]. The name is what --check reports; None marks
# a line that carries no figure (a table rule, a header) and can only differ structurally.

def render_readme_figures(f):
    return [
        (None, "| figure | value | denominator |"),
        (None, "|---|---|---|"),
        ("detection_pct",
         "| **Detection** | **%s** | %s reviewed malicious samples |"
         % (f["detection_pct"], f["detection_ratio"])),
        ("detection_in_scope_pct",
         "| **Detection, excluding the rules' own source material** | **%s** | %s samples |"
         % (f["detection_in_scope_pct"], f["detection_in_scope_ratio"])),
        # Three lines, not one. The single line these replace read "Recorded known misses |
        # 598 | 67 of them outside that source material", and 32 of that 598 - 29 of the 67 -
        # are files the scanner detects and no shard carries, which the prose below the table
        # glossed as "malware this version does not catch". The states are rendered apart so
        # no reader has to be told which one a number means.
        ("known_miss_rule_gap",
         "| Recorded known misses | %s | %s of them outside that source material |"
         % (f["known_miss_rule_gap"], f["known_miss_rule_gap_in_scope"])),
        ("known_miss_detected",
         "| Recorded, but detected: no shard carries the bytes | %s | %s outside it; the "
         "suite has nothing to run the assertion against |"
         % (f["known_miss_detected"], f["known_miss_detected_in_scope"])),
        ("known_miss_unverified",
         "| Recorded, and not re-measurable here | %s | %s outside it; the bytes are not on "
         "this machine |"
         % (f["known_miss_unverified"], f["known_miss_unverified_in_scope"])),
        ("largest_known_miss_count",
         "| Largest single known-miss family | %s | %s |"
         % (f["largest_known_miss_count"], f["largest_known_miss_family"])),
        ("re_runnable",
         "| Samples a stranger can re-run | %s | ship as bytes carrying a recorded "
         "expected rule |" % f["re_runnable"]),
        ("techniques",
         "| Technique coverage | %s | distinct techniques in the reviewed set |"
         % f["techniques"]),
        ("total_blobs",
         "| Corpus | %s blobs | %s classified, %s unreviewed |"
         % (f["total_blobs"], f["classified"], f["unreviewed"])),
        ("predates_ruleset",
         "| Of those, the tree the rules were written against | %s blobs | excluded from "
         "the second detection figure |" % f["predates_ruleset"]),
    ]


def render_readme_family(f):
    """One column per sampling frame, and no rate across the two.

    The previous version of this table published a single family rate. That rate was 14.9%, and
    applying 180 byte-defined labels would have taken it to 32.1% without a single verdict
    changing - because all 180 came out of a pool that is 530-of-531 detected. A reader would
    have seen the scanner improve by 17 points overnight, and the only thing that changed was
    who had got around to labelling what.

    NEITHER COLUMN IS THE HEADLINE, and that is a decision rather than a hedge. The obvious
    repair - exclude the contaminated families and keep 14.9% - promotes a figure whose own
    frame is contaminated the other way: 597 of those 707 rows carry `expect.known_miss` and 565
    of those are samples no rule fires on, because a mass miss is what gets investigated and
    labelled, and one 2017 doorway campaign supplies 495 of them. Drop that single family and
    the same rate reads 49.5%. This project
    has already shipped a metric that could not deliver bad news; one that cannot deliver good
    news is the same defect with the sign flipped. So both, each under its own frame.

    The sample-weighted figure below the split is the whole reviewed set with its denominator
    stated, and it does not move when a label is assigned - assigning a family changes no
    verdict and no expectation.
    """
    return [
        (None, "| figure | families labelled before this writer | families labelled from the "
               "unfamilied pool |"),
        (None, "|---|---|---|"),
        ("frame_unrecorded_label",
         "| **Sampling frame** | **%s** | **%s** |"
         % (f["frame_unrecorded_label"], f["frame_conditioned_label"])),
        ("frame_unrecorded_families",
         "| Campaign families | %s | %s |"
         % (f["frame_unrecorded_families"], f["frame_conditioned_families"])),
        ("frame_unrecorded_rows",
         "| Rows carrying the label | %s | %s |"
         % (f["frame_unrecorded_rows"], f["frame_conditioned_rows"])),
        ("frame_unrecorded_fully",
         "| Families fully detected | %s | %s |"
         % (f["frame_unrecorded_fully"], f["frame_conditioned_fully"])),
        ("frame_unrecorded_partially",
         "| Families partially detected | %s | %s |"
         % (f["frame_unrecorded_partially"], f["frame_conditioned_partially"])),
        ("frame_unrecorded_missed",
         "| Families completely missed | %s | %s |"
         % (f["frame_unrecorded_missed"], f["frame_conditioned_missed"])),
        ("frame_unrecorded_macro_pct",
         "| Macro average — every family weighted equally | %s | %s |"
         % (f["frame_unrecorded_macro_pct"], f["frame_conditioned_macro_pct"])),
        ("frame_unrecorded_micro_pct",
         "| Micro average — every sample weighted equally | %s (%s) | %s (%s) |"
         % (f["frame_unrecorded_micro_pct"], f["frame_unrecorded_micro_ratio"],
            f["frame_conditioned_micro_pct"], f["frame_conditioned_micro_ratio"])),
        (None, ""),
        (None, "| figure | value | denominator |"),
        (None, "|---|---|---|"),
        ("detection_pct",
         "| **Sample-weighted detection, whole reviewed set** | **%s** | %s reviewed malicious "
         "samples — unchanged by any labelling |"
         % (f["detection_pct"], f["detection_ratio"])),
        ("unfamilied_rows",
         "| Reviewed malicious rows carrying no family | %s | %s of them detected — outside "
         "both columns above |" % (f["unfamilied_rows"], f["unfamilied_detected"])),
        ("bucketed_rows",
         "| Rows under a provenance label rather than a campaign | %s | %s — membership "
         "conditioned on detection, so excluded |"
         % (f["bucketed_rows"], f["bucketed_label"])),
        ("techniques",
         "| Technique coverage | %s | distinct techniques; %s reviewed malicious rows carry "
         "none |" % (f["techniques"], f["rows_without_technique"])),
        ("family_rerun_full",
         "| Families a stranger can re-run in full | %s | of %s; %s have no re-runnable "
         "member, holding %s rows |"
         % (f["family_rerun_full"], f["family_count"], f["family_rerun_none"],
            f["family_rerun_none_rows"])),
    ]


def render_sources_index_halves(f):
    return [
        (None, "| file | rows | tracked? | what it is |"),
        (None, "|---|---|---|---|"),
        ("published_rows",
         "| `index.jsonl` | %s | yes | published samples — the ones a public suite can "
         "verify |" % f["published_rows"]),
        ("local_rows",
         "| `local/index-local.jsonl` | %s | no | everything held back, with each row's "
         "blockers |" % f["local_rows"]),
        (None,
         "| `index-summary.json` | — | yes | the counts, so the denominator survives "
         "without the rows |"),
    ]


def render_sources_shipped(f):
    return [
        ("fetched_not_shipped",
         "Of the %s published rows, **%s are reproducible from a pinned source or from the"
         % (f["published_rows"], f["fetched_not_shipped"])),
        (None,
         "stock CMS tree** and are therefore *not* shipped as blobs — they are an index row"),
        ("shipped_as_bytes",
         "plus a lockfile entry. **%s** ship as bytes in a public shard:"
         % f["shipped_as_bytes"]),
        ("shipped_by_reason", "%s." % f["shipped_by_reason"]),
    ]


REGIONS = [
    ("README.md", "corpus-figures", render_readme_figures),
    ("README.md", "family-detection", render_readme_family),
    ("corpus/SOURCES.md", "index-halves", render_sources_index_halves),
    ("corpus/SOURCES.md", "shipped-vs-fetched", render_sources_shipped),
]


# --------------------------------------------------------------------------- region I/O

def locate(text, name):
    """(start_of_body, end_of_body) character offsets, or raise Missing.

    Every way this can go wrong is an error with a name. A silent skip here is the whole
    defect this file exists to prevent, so absence, duplication and inversion each say so.
    """
    begins = list(re.finditer(_BEGIN_RE % re.escape(name), text))
    ends = list(re.finditer(_END_RE % re.escape(name), text))
    if not begins:
        raise Missing("no BEGIN marker for region %r" % name)
    if not ends:
        raise Missing("region %r has a BEGIN marker and no END marker" % name)
    if len(begins) > 1:
        raise Missing("region %r has %d BEGIN markers; exactly one is allowed"
                      % (name, len(begins)))
    if len(ends) > 1:
        raise Missing("region %r has %d END markers; exactly one is allowed"
                      % (name, len(ends)))
    if ends[0].start() < begins[0].end():
        raise Missing("region %r has its END marker before its BEGIN marker" % name)
    return begins[0].end(), ends[0].start()


def body_of(text, name):
    a, b = locate(text, name)
    return text[a:b].strip("\n").split("\n")


def replace_body(text, name, lines):
    a, b = locate(text, name)
    return text[:a] + "\n" + "\n".join(lines) + "\n" + text[b:]


# ------------------------------------------------------- the guard on a family rate
#
# THE REGION CHECK ABOVE CANNOT SEE THIS, AND THAT IS WHY THIS EXISTS.
# `drift()` compares a generated block against what the generator would write. It says nothing
# about the prose around the block, which is by design - prose is a person's and survives
# regeneration. But a family rate quoted in that prose is a published figure with no denominator
# beside it, and the region check will report `agrees` over a document that carries one.
#
# Two rules, and they are different failures:
#
#   companions   a rate rendered for ONE sampling frame must appear with that frame's integer
#                pair and that frame's label. `14.9%` alone is not a claim anybody can check;
#                `14.9% (105 of 707), sampling frame not recorded` is.
#   combined     a rate computed across BOTH frames must not appear at all. It is not merely
#                unaccompanied - there is no population to accompany it with. 32.1% is over the
#                union of a pool that is 530-of-531 detected and a pool that is 602-of-707
#                missed; no denominator makes that number mean anything, so the repair is not
#                to caption it but to refuse it.
#
# The combined rule stands down when the union rate EQUALS a rendered per-frame rate, which is
# exactly the state before any frame-conditioned family exists: the union is then one frame's
# population and carries that frame's denominator. Without that exemption this guard would
# refuse the correct document it was committed alongside.
#
# SCOPE: the documents in `REGIONS`, and deliberately not every tracked file. `CHANGELOG.md`,
# `CORPUS_PLAN.md` and everything under `docs/results/` are history - the corpus changelog says
# so in its own header - and a round is entitled to record "this figure would have read 32.1%
# and here is why we did not publish it". Sweeping those would forbid the sentence that
# explains the rule. What is defended is the set of documents that carry a generated region,
# which is the set a stranger reads as current.
RATE_COMPANIONS = {
    "frame_conditioned_macro_pct": ("frame_conditioned_micro_ratio", "frame_conditioned_label"),
    "frame_conditioned_micro_pct": ("frame_conditioned_micro_ratio", "frame_conditioned_label"),
    "frame_unrecorded_macro_pct": ("frame_unrecorded_micro_ratio", "frame_unrecorded_label"),
    "frame_unrecorded_micro_pct": ("frame_unrecorded_micro_ratio", "frame_unrecorded_label"),
}

COMBINED_RATES = ("family_combined_macro_pct", "family_combined_micro_pct")

# ------------------------------------------------- the guard on a mixed known-miss total
#
# Same argument as COMBINED_RATES, one field over. `expect.known_miss` marks a row the
# published suite asserts no rule for, and two unrelated facts put a row there: no rule fires
# (a miss), or rules fire and no shard carries the bytes (a shipping gap). The union is a real
# count of a real marker and a fine thing to state as such; what it is not is a count of what
# the scanner fails to catch, which is how the README published it.
#
# So these two are computed, rendered nowhere, and refused when they appear in a paragraph
# that is talking about known misses. Paragraph-scoped rather than whole-document because
# these are small integers: `598` and `67` occur in this repository as byte counts and line
# numbers, and a guard that reported those is a guard nobody finishes. Scoped to the
# documents in REGIONS, for the reason the family guard gives - CHANGELOG.md and the files
# under docs/ are history, and a round is entitled to record what a figure used to read.
MIXED_MISS_TOTALS = ("known_miss_mixed_total", "known_miss_mixed_in_scope")

# The words that turn a bare integer into a claim about detection. Hyphen or space, because
# the table writes "known-miss family" and the prose writes "known misses".
#
# `known_miss` with the underscore is deliberately NOT matched, and that is the line between a
# true statement and a false one rather than an oversight. `expect.known_miss` is a field, 598
# rows carry it, and "598 rows are `known_miss`" is correct - the marker really does cover all
# three states. What is wrong is "598 known misses", which says the scanner fails on 598 files.
# So the guard fires on the English claim and leaves the field name alone. It is what keeps
# SOURCES.md's "Twenty-three of the 67 are `known_miss`" - where 67 is a shard's sample count
# and nothing to do with this figure - from being reported: measured, that paragraph is clean.
MISS_PHRASE = re.compile(r"known[- ]miss", re.I)


def miss_violations(text, f):
    """[(figure, why)] for every paragraph that quotes a mixed total as a miss count.

    The split figures are exempt from being *called* mixed, and so is a mixed total that
    happens to equal one of them: when nothing is detected-but-unshippable the union IS the
    miss count, and a guard that refused the correct document in that state would be turned
    off rather than fixed. That is the same stand-down COMBINED_RATES has.
    """
    split = {f[k] for k in ("known_miss_rule_gap", "known_miss_rule_gap_in_scope",
                            "known_miss_detected", "known_miss_detected_in_scope",
                            "known_miss_unverified", "known_miss_unverified_in_scope")}
    out = []
    for para in re.split(r"\n\s*\n", text):
        if not MISS_PHRASE.search(para):
            continue
        for name in MIXED_MISS_TOTALS:
            value = f[name]
            if value in split:
                continue
            # Not a substring match: `67` must not fire on `1,678` or `5.67%`.
            if re.search(r"(?<![\d,.])%s(?![\d,.%%])" % re.escape(value), para):
                out.append((name, "appears in a paragraph about known misses, but it counts "
                                  "the rows the scanner misses TOGETHER with the rows it "
                                  "detects and no shard ships; quote the split instead"))
    return out


def rate_violations(text, f):
    """[(figure, what is missing)] for every family rate `text` publishes without its population.

    Whole-document rather than per-region on purpose: the region is already defended line by
    line, and the failure this catches is a number that escaped INTO the prose, where nothing
    was looking.
    """
    out = []
    per_frame = {f[k] for k in RATE_COMPANIONS if f.get(k) not in (None, DASH)}
    for rate in sorted(RATE_COMPANIONS):
        if f[rate] == DASH or f[rate] not in text:
            continue
        for c in RATE_COMPANIONS[rate]:
            if f[c] not in text:
                out.append((rate, "its %s is not stated beside it (%r)" % (c, f[c])))
    for name in COMBINED_RATES:
        v = f[name]
        if v == DASH or v in per_frame:
            continue
        if v in text:
            out.append((name, "a rate across BOTH sampling frames, over a population nobody "
                              "drew; quote the two frames separately"))
    return out


def drift(on_disk, rendered):
    """(named_figures_that_differ, structural_lines_that_differ).

    A figure is reported by name when its rendered line is not present on disk. Whole-line
    matching rather than substring: `140` occurs in this repository as a megabyte count and
    as a character offset, and a check that reported those would be a check nobody finishes.
    """
    have = set(l.strip() for l in on_disk)
    named, structural = [], []
    for fig, line in rendered:
        if line.strip() in have:
            continue
        (named if fig else structural).append(fig or line)
    return named, structural


# --------------------------------------------------------------------------- modes

def run(root, mode, out=sys.stdout, guard=True):
    """mode is 'write' or 'check'. Returns the number of problems.

    `guard=False` exists for one control and for nothing else: it turns off `rate_violations`
    so the suite can assert that the region check ALONE passes a document the guard refuses.
    A guard whose positive case is also caught by the check it was added beside has not been
    shown to do anything.
    """
    try:
        s = json.load(open(os.path.join(root, "corpus", "index-summary.json"),
                          encoding="utf-8"))
    except OSError as e:
        print("cannot read index-summary.json: %s" % e, file=out)
        return 1
    try:
        f = figures(s)
    except Missing as e:
        print("cannot build the figures: %s" % e, file=out)
        return 1

    bad = 0
    for rel, name, render in REGIONS:
        path = os.path.join(root, rel)
        try:
            text = open(path, encoding="utf-8").read()
        except OSError as e:
            print("  %-44s CANNOT READ (%s)" % ("%s [%s]" % (rel, name), e), file=out)
            bad += 1
            continue
        rendered = render(f)
        try:
            current = body_of(text, name)
        except Missing as e:
            print("  %-44s MISSING REGION: %s" % ("%s [%s]" % (rel, name), e), file=out)
            bad += 1
            continue

        named, structural = drift(current, rendered)
        want = [l for _, l in rendered]
        same = [l.strip() for l in current] == [l.strip() for l in want]
        if mode == "check":
            if same:
                print("  %-44s agrees" % ("%s [%s]" % (rel, name)), file=out)
            else:
                bad += 1
                print("  %-44s DISAGREES" % ("%s [%s]" % (rel, name)), file=out)
                for fig in named:
                    print("      figure %-28s on disk does not carry the generated value "
                          "%r" % (fig, f.get(fig, "?")), file=out)
                for line in structural:
                    print("      structure: missing %r" % line[:70], file=out)
                if not named and not structural:
                    print("      the region carries lines the generator did not write",
                          file=out)
        else:
            if same:
                print("  %-44s unchanged" % ("%s [%s]" % (rel, name)), file=out)
            else:
                open(path, "w", encoding="utf-8").write(replace_body(text, name, want))
                print("  %-44s rewritten (%s)"
                      % ("%s [%s]" % (rel, name),
                         ", ".join(named + ["structure"] * bool(structural)) or "reflowed"),
                      file=out)

    # The guard, over each tracked document once and AFTER any rewrite: writing a region can
    # only add the companions, never remove them, so sweeping the pre-write text would report a
    # violation the file on disk no longer has.
    if guard:
        for rel in sorted({r for r, _n_, _r_ in REGIONS}):
            path = os.path.join(root, rel)
            try:
                text = open(path, encoding="utf-8").read()
            except OSError:
                continue                      # already reported as CANNOT READ by the loop above
            bad_rates = rate_violations(text, f)
            label = "%s [family-rate guard]" % rel
            if not bad_rates:
                print("  %-44s no unaccompanied family rate" % label, file=out)
            else:
                bad += len(bad_rates)
                print("  %-44s PUBLISHES A FAMILY RATE WITHOUT ITS POPULATION" % label,
                      file=out)
                for fig, why in bad_rates:
                    print("      %s (%s): %s" % (fig, f[fig], why), file=out)

            bad_miss = miss_violations(text, f)
            label = "%s [known-miss guard]" % rel
            if not bad_miss:
                print("  %-44s no mixed known-miss total" % label, file=out)
                continue
            bad += len(bad_miss)
            print("  %-44s PUBLISHES A MIXED KNOWN-MISS TOTAL" % label, file=out)
            for fig, why in bad_miss:
                print("      %s (%s): %s" % (fig, f[fig], why), file=out)
    return bad


# --------------------------------------------------------------------------- controls

def inject():
    """Both directions, over a temp copy of the tree. Nothing in the repository is written.

    A checker that only ever runs against the currently-passing file is a checker nobody has
    seen say no. The cases below are the ones this project has actually been bitten by: a
    figure stale by one (README, twice, for rounds), and a generated block that is simply not
    there (the failure mode a merge produces, where skipping silently would report green over
    a document with no generated content at all).
    """
    import shutil, tempfile, io
    fails, cases = [], []

    def case(label, ok):
        cases.append(label)
        print("  %-58s %s" % (label, "ok" if ok else "WRONG"))
        if not ok:
            fails.append(label)

    tmp = tempfile.mkdtemp(prefix="doc-figures-inject-")
    try:
        os.makedirs(os.path.join(tmp, "corpus"))
        for rel, _n_, _r in REGIONS:
            dst = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.exists(dst):
                shutil.copy2(os.path.join(ROOT, rel), dst)
        shutil.copy2(os.path.join(HERE, "index-summary.json"),
                     os.path.join(tmp, "corpus", "index-summary.json"))

        def check(root=tmp):
            buf = io.StringIO()
            n = run(root, "check", out=buf)
            return n, buf.getvalue()

        n, _out = check()
        case("documents that agree with the summary            accepted", n == 0)

        # 1. A figure stale by one. Not a malformed file - that would prove only that broken
        #    markup is caught. A table that is valid, plausible and wrong by one is the
        #    actual failure mode, and it must be named.
        sp = os.path.join(tmp, "corpus", "index-summary.json")
        original = open(sp, encoding="utf-8").read()
        s = json.loads(original)
        s["malicious_detected"] = s["malicious_detected"] + 1
        json.dump(s, open(sp, "w", encoding="utf-8"), indent=1, sort_keys=True)
        n, out = check()
        case("a summary figure drifted by one                  refused", n > 0)
        case("  ...and the refusal names detection_ratio/pct",
             "detection_pct" in out or "detection_ratio" in out)
        case("  ...and it names the file that carries it", "README.md" in out)

        # The mirror: regenerating against the drifted summary makes the documents agree
        # again. Without this, a check that refused everything would pass the case above.
        run(tmp, "write", out=io.StringIO())
        n, _out = check()
        case("regenerating against that summary                accepted", n == 0)
        open(sp, "w", encoding="utf-8").write(original)
        run(tmp, "write", out=io.StringIO())
        n, _out = check()
        case("restoring the real summary and regenerating      accepted", n == 0)

        # 2. A missing region must fail, not silently generate nothing. This is the merge
        #    failure mode: the markers go, the numbers stay, and a skip reports green over a
        #    document nothing is defending any more.
        rel, name, _r = REGIONS[0]
        p = os.path.join(tmp, rel)
        whole = open(p, encoding="utf-8").read()
        no_begin = re.sub(_BEGIN_RE % re.escape(name), "", whole)
        open(p, "w", encoding="utf-8").write(no_begin)
        n, out = check()
        case("a region with no BEGIN marker                    refused",
             n > 0 and "MISSING REGION" in out)

        no_markers = re.sub(_END_RE % re.escape(name), "", no_begin)
        open(p, "w", encoding="utf-8").write(no_markers)
        n, out = check()
        case("a region absent entirely                         refused",
             n > 0 and "MISSING REGION" in out)

        open(p, "w", encoding="utf-8").write(
            re.sub(_END_RE % re.escape(name), "", whole))
        n, out = check()
        case("a BEGIN with no END                              refused",
             n > 0 and "MISSING REGION" in out)

        b = re.search(_BEGIN_RE % re.escape(name), whole).group(0)
        open(p, "w", encoding="utf-8").write(whole.replace(b, b + "\n" + b, 1))
        n, out = check()
        case("a region with two BEGIN markers                  refused",
             n > 0 and "MISSING REGION" in out)

        # 3. Writing must not police prose. A region is a fence around numbers; an edit
        #    outside it is a person doing their job and must survive regeneration untouched.
        open(p, "w", encoding="utf-8").write(whole)
        marker = "\nPROSE-OUTSIDE-THE-REGION-SENTINEL\n"
        open(p, "w", encoding="utf-8").write(whole.rstrip("\n") + marker)
        run(tmp, "write", out=io.StringIO())
        after = open(p, encoding="utf-8").read()
        case("prose outside a region survives regeneration",
             "PROSE-OUTSIDE-THE-REGION-SENTINEL" in after)
        n, _out = check()
        case("  ...and the document still agrees", n == 0)

        # 4. Prose written INSIDE a region is not protected, and must be reported.
        a0, b0 = locate(after, name)
        open(p, "w", encoding="utf-8").write(
            after[:a0] + "\n| a hand-written row | 1 | 2 |\n" + after[a0:])
        n, out = check()
        case("a hand-written line inside a region              refused", n > 0)
        open(p, "w", encoding="utf-8").write(whole)

        # 5. A figure the summary does not carry must raise, not render None into a
        #    published table. `make-summary.py` dropping a key is a real event: this round
        #    added one.
        s = json.loads(original)
        del s["malicious_detected_runnable"]
        json.dump(s, open(sp, "w", encoding="utf-8"), indent=1, sort_keys=True)
        n, out = check()
        case("a summary missing a key the docs quote           refused",
             n > 0 and "malicious_detected_runnable" in out)
        case("  ...and no region was rendered with None", "None" not in out)
        open(sp, "w", encoding="utf-8").write(original)

        # 6. A FAMILY FIGURE THAT DRIFTS MUST FAIL THE SAME WAY A DETECTION FIGURE DOES.
        #    This round added a second table to README.md, and a generated region nobody has
        #    seen refuse is not yet defended. Each of the three family states is drifted
        #    separately, because a check that only ever watched "fully detected" would let a
        #    partial silently become a miss - which is the collapse the three-state split
        #    exists to prevent.
        for key, figname in (("fully_detected", "frame_unrecorded_fully"),
                             ("partially_detected", "frame_unrecorded_partially"),
                             ("completely_missed", "frame_unrecorded_missed")):
            s2 = json.loads(original)
            s2["family_detection_by_frame"]["sampling_frame_not_recorded"]["metrics"][key] += 1
            json.dump(s2, open(sp, "w", encoding="utf-8"), indent=1, sort_keys=True)
            n, out = check()
            case("family %-22s drifted by one       refused and named" % key,
                 n > 0 and figname in out)
        open(sp, "w", encoding="utf-8").write(original)

        # 7. THE UNFAMILIED POPULATION CANNOT SILENTLY LEAVE THE TABLE.
        #    The whole credibility of a family figure rests on the 531 rows it is silent
        #    about being stated beside it. If that count moves and the document does not, the
        #    table is asserting a gap that is no longer the gap.
        s2 = json.loads(original)
        s2["malicious_family_population"]["unfamilied"] += 1
        json.dump(s2, open(sp, "w", encoding="utf-8"), indent=1, sort_keys=True)
        n, out = check()
        case("the unfamilied population drifted                refused",
             n > 0 and "unfamilied_rows" in out)
        open(sp, "w", encoding="utf-8").write(original)

        #    ...and the same for the provenance bucket, which is the other row a reader needs
        #    in order to add the table back up to the reviewed total.
        s2 = json.loads(original)
        s2["malicious_family_population"]["provenance_bucketed"] += 1
        json.dump(s2, open(sp, "w", encoding="utf-8"), indent=1, sort_keys=True)
        n, out = check()
        case("the provenance bucket count drifted              refused",
             n > 0 and "bucketed_rows" in out)
        open(sp, "w", encoding="utf-8").write(original)

        # 8. NO FIGURE IS ROUNDED TWICE. The rendered micro average is taken from the
        #    published integer pair; the summary also stores the rate. They must agree to the
        #    printed decimal. They did not: 105/707 rendered as 14.8% from a 4dp stored rate
        #    and 14.9% from the pair, and the prose beside the table said 14.9%.
        s3 = json.loads(original)
        fam3 = s3["family_detection"]
        case("micro average agrees with the stored rate to 1dp",
             _pct(fam3["detected_rows"], fam3["rows"]) == _rate(fam3["micro_rate"]))
        case("  ...and the macro rate survives being rendered",
             _rate(fam3["macro_rate"]) == "%.1f%%" % round(100.0 * fam3["macro_rate"], 1))
        # The same property on the block that is actually RENDERED. The pair above is over
        # `family_detection`, which no document quotes any more; a double-rounding defect could
        # be reintroduced in the frame blocks with that case still green.
        r3 = s3["family_detection_by_frame"]["sampling_frame_not_recorded"]["metrics"]
        case("  ...and on the frame block the documents actually render",
             _pct(r3["detected_rows"], r3["rows"]) == _rate(r3["micro_rate"]))

        # 9. The family region must be defended by the same MISSING_IS_AN_ERROR rule as the
        #    first one. It is a different entry in REGIONS and could have been added without
        #    ever being asserted absent.
        famrel, famname = "README.md", "family-detection"
        pf = os.path.join(tmp, famrel)
        wholef = open(pf, encoding="utf-8").read()
        open(pf, "w", encoding="utf-8").write(
            re.sub(_BEGIN_RE % re.escape(famname), "", wholef))
        n, out = check()
        case("the family region with no BEGIN marker           refused",
             n > 0 and "MISSING REGION" in out)
        open(pf, "w", encoding="utf-8").write(wholef)

        # 10. THE GUARD ON A FAMILY RATE, in both directions and shown not to be redundant.
        #     Every case below runs against a summary this function BUILDS, carrying both
        #     sampling frames populated, so the controls behave identically whether or not any
        #     frame-conditioned family exists in the real index yet. A control that only worked
        #     after a particular write would be a control nobody could run first.
        s10 = json.loads(original)
        s10["family_detection_by_frame"]["sampling_frame_detection_conditioned"] = {
            "frame": {"pool_rows": 531, "pool_detected": 530},
            "metrics": {"families": 7, "rows": 180, "detected_rows": 180,
                        "fully_detected": 7, "partially_detected": 0, "completely_missed": 0,
                        "rows_fully_detected": 180, "rows_partially_detected": 0,
                        "rows_completely_missed": 0, "macro_rate": 1.0, "micro_rate": 1.0}}
        s10["family_detection"] = dict(s10["family_detection"],
                                       families=45, rows=887, detected_rows=285,
                                       macro_rate=0.408205, micro_rate=0.321308)
        json.dump(s10, open(sp, "w", encoding="utf-8"), indent=1, sort_keys=True)
        run(tmp, "write", out=io.StringIO())
        f10 = figures(s10)
        case("the two frames render different rates",
             (f10["frame_unrecorded_micro_pct"], f10["frame_conditioned_micro_pct"])
             == ("14.9%", "100.0%"))
        case("  ...and the union of them is a third number nobody drew",
             f10["family_combined_micro_pct"] == "32.1%")

        #     (a) the companion rule, on text, both ways.
        case("a frame rate quoted with nothing beside it          refused",
             [v for v in rate_violations("detection by family is 14.9%.", f10)
              if v[0] == "frame_unrecorded_micro_pct"] != [])
        with_pop = ("detection by family is 14.9% (105 of 707), sampling frame not recorded.")
        case("  ...the same rate with its pair and its frame      accepted",
             rate_violations(with_pop, f10) == [])
        case("  ...the rate with the pair but NO frame            refused",
             any("frame_unrecorded_label" in why
                 for _fig, why in rate_violations("14.9% (105 of 707)", f10)))
        case("  ...and text quoting no rate at all                accepted",
             rate_violations("this document quotes no family rate.", f10) == [])

        #     (b) the combined rule: a number over the union of two frames, which no
        #         denominator can rescue.
        case("the union rate quoted anywhere                      refused",
             [v for v in rate_violations("family detection is 32.1%", f10)
              if v[0] == "family_combined_micro_pct"] != [])
        case("  ...even with a denominator written beside it",
             [v for v in rate_violations("family detection is 32.1% of 285 of 887 rows", f10)
              if v[0] == "family_combined_micro_pct"] != [])
        case("  ...and the macro union too, not only the micro",
             [v for v in rate_violations("the macro figure is 40.8%", f10)
              if v[0] == "family_combined_macro_pct"] != [])

        #     (c) the exemption, which is the state this guard was committed in: with no
        #         frame-conditioned family the union IS the unmarked frame's population, and
        #         refusing it would refuse the correct document.
        #
        #         BUILT rather than read off the live summary. The first version of this case
        #         asked `if the real index has no conditioned family yet`, and the moment 180
        #         rows were applied it stopped running - the suite went from 39 cases to 38
        #         with nothing failing. A control that disappears when the data changes is a
        #         control that was never defending the code.
        s10c = json.loads(original)
        s10c["family_detection_by_frame"]["sampling_frame_detection_conditioned"] = {
            "frame": None,
            "metrics": {"families": 0, "rows": 0, "detected_rows": 0, "fully_detected": 0,
                        "partially_detected": 0, "completely_missed": 0,
                        "rows_fully_detected": 0, "rows_partially_detected": 0,
                        "rows_completely_missed": 0, "macro_rate": None, "micro_rate": None}}
        unrec = s10c["family_detection_by_frame"]["sampling_frame_not_recorded"]["metrics"]
        s10c["family_detection"] = dict(s10c["family_detection"], **{
            k: unrec[k] for k in ("families", "rows", "detected_rows", "macro_rate",
                                  "micro_rate")})
        f_none = figures(s10c)
        case("  ...an empty frame renders as a dash, not as 0.0%",
             (f_none["frame_conditioned_macro_pct"], f_none["frame_conditioned_micro_pct"])
             == (DASH, DASH))
        case("  ...and the union is NOT refused while it equals one frame's own rate",
             [v for v in rate_violations("family detection is %s"
                                         % f_none["family_combined_micro_pct"], f_none)
              if v[0] == "family_combined_micro_pct"] == [])
        case("  ...while that same text IS refused once both frames are populated",
             [v for v in rate_violations("family detection is %s"
                                         % f10["family_combined_micro_pct"], f10)
              if v[0] == "family_combined_micro_pct"] != [])

        #     (d) END TO END, and NOT REDUNDANT. A rate in prose is invisible to the region
        #         check by design - prose is a person's and survives regeneration - so the
        #         guard is asserted to catch what the region check passes.
        pr = os.path.join(tmp, "README.md")
        clean_readme = open(pr, encoding="utf-8").read()
        open(pr, "w", encoding="utf-8").write(
            clean_readme.rstrip("\n") + "\n\nFamily-weighted detection is 32.1%.\n")
        n, out = check()
        case("a union rate loose in the prose                     refused",
             n > 0 and "family_combined_micro_pct" in out)
        buf = io.StringIO()
        n_noguard = run(tmp, "check", out=buf, guard=False)
        case("  ...and the region check ALONE passes that file (so the guard is not redundant)",
             n_noguard == 0)
        open(pr, "w", encoding="utf-8").write(clean_readme)

        #     ...and the companion rule end to end, in the document that carries no family
        #     table at all, so nothing else in the file can satisfy it by accident.
        ps = os.path.join(tmp, "corpus", "SOURCES.md")
        clean_sources = open(ps, encoding="utf-8").read()
        open(ps, "w", encoding="utf-8").write(
            clean_sources.rstrip("\n") + "\n\nFamilies are detected at 14.9%.\n")
        n, out = check()
        case("a frame rate in a document with no population       refused",
             n > 0 and "SOURCES.md [family-rate guard]" in out)
        buf = io.StringIO()
        case("  ...which the region check alone also passes",
             run(tmp, "check", out=buf, guard=False) == 0)
        open(ps, "w", encoding="utf-8").write(clean_sources)

        # 11. THE KNOWN-MISS SPLIT. Three states share one marker and only one is a miss, so
        #     each is drifted separately: a check watching only the miss count would let a
        #     detected row silently become one, which is the direction that FLATTERS the
        #     scanner and is therefore the one to nail down.
        for kind, figname in (("rule-gap", "known_miss_rule_gap"),
                              ("detected-not-shippable", "known_miss_detected"),
                              ("unverified", "known_miss_unverified")):
            s11 = json.loads(original)
            s11["malicious_known_miss_by_kind"][kind] = \
                s11["malicious_known_miss_by_kind"].get(kind, 0) + 1
            s11["known_miss"] += 1
            s11["malicious_known_miss"] += 1
            json.dump(s11, open(sp, "w", encoding="utf-8"), indent=1, sort_keys=True)
            n, out = check()
            case("known_miss %-24s drifted by one   refused and named" % kind,
                 n > 0 and figname in out)
        open(sp, "w", encoding="utf-8").write(original)

        #     The split must PARTITION the marker. A kind count that no longer adds up to
        #     `known_miss` means one of the three published lines is over a population that is
        #     not the one its heading names, and rendering it would be worse than refusing.
        s11 = json.loads(original)
        s11["known_miss"] += 5
        json.dump(s11, open(sp, "w", encoding="utf-8"), indent=1, sort_keys=True)
        n, out = check()
        case("a split that does not add up to the marker       refused",
             n > 0 and "does not partition" in out)
        open(sp, "w", encoding="utf-8").write(original)

        #     An unmeasured row must not render as a zero. `<unclassified>` is what
        #     make-summary emits for a row classify-known-miss.py has not visited, and the
        #     figures must refuse rather than quietly leave it out of all three lines.
        s11 = json.loads(original)
        s11["malicious_known_miss_by_kind"]["<unclassified>"] = 3
        s11["known_miss"] += 3
        s11["malicious_known_miss"] += 3
        json.dump(s11, open(sp, "w", encoding="utf-8"), indent=1, sort_keys=True)
        n, out = check()
        case("an unclassified known_miss row                   refused",
             n > 0 and "<unclassified>" in out)
        case("  ...and nothing was rendered from the partial split", "None" not in out)
        open(sp, "w", encoding="utf-8").write(original)

        # 12. THE GUARD ON A MIXED KNOWN-MISS TOTAL, both directions, on text.
        f12 = figures(json.loads(original))
        case("the mixed total quoted as a miss count              refused",
             [v for v in miss_violations(
                 "There are %s recorded known misses." % f12["known_miss_mixed_total"], f12)
              if v[0] == "known_miss_mixed_total"] != [])
        case("  ...and the mixed in-scope total likewise",
             [v for v in miss_violations(
                 "%s known misses fall outside the source material."
                 % f12["known_miss_mixed_in_scope"], f12)
              if v[0] == "known_miss_mixed_in_scope"] != [])
        case("  ...the split figures in the same sentence          accepted",
             miss_violations("%s known misses, %s outside that source material."
                             % (f12["known_miss_rule_gap"],
                                f12["known_miss_rule_gap_in_scope"]), f12) == [])
        case("  ...the same integers away from the phrase          accepted",
             miss_violations("The archive is %s bytes and %s files."
                             % (f12["known_miss_mixed_total"],
                                f12["known_miss_mixed_in_scope"]), f12) == [])
        # A small integer must not fire on a longer number that contains it. `67` inside
        # `1,678` or `5.67%` would make this guard noise, and a noisy guard gets removed.
        case("  ...and it does not fire on a number containing it",
             miss_violations("known misses: 1,%s8 files at 5.%s%% of the tree."
                             % (f12["known_miss_mixed_in_scope"],
                                f12["known_miss_mixed_in_scope"]), f12) == [])
        # The stand-down, which is the state this guard would otherwise refuse the day the
        # detected-and-unverified counts reach zero: the union then IS the miss count.
        s12 = json.loads(original)
        s12["malicious_known_miss_by_kind"] = {
            "rule-gap": s12["known_miss"], "detected-not-shippable": 0, "unverified": 0}
        s12["malicious_known_miss_by_kind_excl_predates_ruleset"] = {
            "rule-gap": s12["malicious_known_miss_excl_predates_ruleset"],
            "detected-not-shippable": 0, "unverified": 0}
        f_eq = figures(s12)
        case("  ...and it stands down when the union IS the miss count",
             miss_violations("There are %s recorded known misses."
                             % f_eq["known_miss_mixed_total"], f_eq) == [])
        case("  ...while the same text IS refused when the two differ",
             miss_violations("There are %s recorded known misses."
                             % f12["known_miss_mixed_total"], f12) != [])

        #     End to end, and not redundant: a mixed total loose in the prose is invisible to
        #     the region check, exactly as a family rate is.
        open(pr, "w", encoding="utf-8").write(
            clean_readme.rstrip("\n")
            + "\n\nThe corpus records %s known misses in total.\n"
              % f12["known_miss_mixed_total"])
        n, out = check()
        case("a mixed known-miss total loose in the prose         refused",
             n > 0 and "known_miss_mixed_total" in out)
        buf = io.StringIO()
        case("  ...which the region check alone passes",
             run(tmp, "check", out=buf, guard=False) == 0)
        open(pr, "w", encoding="utf-8").write(clean_readme)

        open(sp, "w", encoding="utf-8").write(original)
        run(tmp, "write", out=io.StringIO())

        n, _out = check()
        case("the tree restored                                accepted", n == 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(cases), len(cases) - len(fails), len(fails)))
    for f_ in fails:
        print("FAIL:", f_)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(
        description="write the generated figure regions in tracked documents")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if a document disagrees with index-summary.json")
    ap.add_argument("--inject", action="store_true",
                    help="prove the check can fail, in both directions, then exit")
    a = ap.parse_args()
    if a.check and a.inject:
        sys.exit("--check and --inject are different questions; pass one")
    if a.inject:
        return inject()

    mode = "check" if a.check else "write"
    print("=== generated figure regions, from corpus/index-summary.json ===")
    bad = run(ROOT, mode)
    print()
    if bad:
        # Two failures reach this line and they have opposite repairs, so it must not name
        # only one. A drifted region is fixed by regenerating; a family rate published without
        # its population is in PROSE, which this tool never rewrites, and telling its reader to
        # regenerate would send them to run a command that cannot touch the problem.
        print("%d problem(s).\n"
              "  a region that DISAGREES is fixed by running corpus/doc-figures.py\n"
              "  a region that is MISSING is fixed by restoring its markers\n"
              "  a family rate PUBLISHED WITHOUT ITS POPULATION is in prose this tool does "
              "not write:\n    state the frame and the denominator beside it, or take the "
              "number out\n"
              "Read WHY THIS EXISTS and the guard's comment in this file before hand-editing "
              "anything." % bad)
        return 1
    print("every generated region agrees with corpus/index-summary.json"
          if mode == "check" else "every generated region is up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
