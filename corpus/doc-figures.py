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


def _get(s, key):
    if key not in s:
        raise Missing("index-summary.json has no key %r - regenerate it with "
                      "make-summary.py, or stop quoting the figure" % key)
    return s[key]


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
    tech_pub, tech_known = len(_get(s, "techniques_published")), len(_get(s, "techniques_known"))
    classified = v["benign"] + v["malicious"]
    fam = _get(s, "family_detection")
    pop = _get(s, "malicious_family_population")
    popd = _get(s, "malicious_family_population_detected")
    rerun = _get(s, "family_rerun_power")
    cond = _get(s, "families_detection_conditioned")
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
        "known_miss": _n(_get(s, "known_miss")),
        "known_miss_in_scope": _n(_get(s, "malicious_known_miss_excl_predates_ruleset")),
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
        "family_fully_detected": _n(fam["fully_detected"]),
        "family_partially_detected": _n(fam["partially_detected"]),
        "family_completely_missed": _n(fam["completely_missed"]),
        "family_macro_pct": _rate(fam["macro_rate"]),
        # From the integer pair, never from the stored rate: both are published, so there is
        # no reason to round a rounded number. The stored `micro_rate` is kept for anything
        # reading the summary directly, and `--inject` asserts the two agree to a decimal.
        "family_micro_pct": _pct(fam["detected_rows"], fam["rows"]),
        "family_micro_ratio": "%s of %s" % (_n(fam["detected_rows"]), _n(fam["rows"])),
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
        ("known_miss",
         "| Recorded known misses | %s | %s of them outside that source material |"
         % (f["known_miss"], f["known_miss_in_scope"])),
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
    """The family split, the macro/micro gap, and the populations the gap is silent about.

    The last three rows are not decoration. A reader who sees only the first six learns that
    the scanner catches 9 campaigns of 38 and misses 24, and would reasonably conclude the
    corpus says so about the whole reviewed set. It does not: 531 reviewed malicious rows
    carry no family, 530 of them are detected, and no figure above them counts one. The rows
    naming that, the provenance bucket and the re-run power are what stop the table being a
    more precise version of the same overstatement.
    """
    return [
        (None, "| figure | value | denominator |"),
        (None, "|---|---|---|"),
        ("family_fully_detected",
         "| **Families fully detected** | **%s** | of %s campaign families |"
         % (f["family_fully_detected"], f["family_count"])),
        ("family_partially_detected",
         "| **Families partially detected** | **%s** | of %s campaign families |"
         % (f["family_partially_detected"], f["family_count"])),
        ("family_completely_missed",
         "| **Families completely missed** | **%s** | of %s campaign families |"
         % (f["family_completely_missed"], f["family_count"])),
        ("family_macro_pct",
         "| Macro average — every family weighted equally | %s | mean per-family detection "
         "over %s families |" % (f["family_macro_pct"], f["family_count"])),
        ("family_micro_pct",
         "| Micro average — every sample weighted equally | %s | %s samples carrying a "
         "campaign family |" % (f["family_micro_pct"], f["family_micro_ratio"])),
        ("detection_pct",
         "| Sample-weighted detection, whole reviewed set | %s | %s reviewed malicious "
         "samples |" % (f["detection_pct"], f["detection_ratio"])),
        ("unfamilied_rows",
         "| Reviewed malicious rows carrying no family | %s | %s of them detected — outside "
         "every family figure above |" % (f["unfamilied_rows"], f["unfamilied_detected"])),
        ("bucketed_rows",
         "| Rows under a provenance label rather than a campaign | %s | %s — membership "
         "conditioned on detection, so excluded |"
         % (f["bucketed_rows"], f["bucketed_label"])),
        ("techniques",
         "| Technique coverage | %s | distinct techniques; the same %s rows carry none |"
         % (f["techniques"], f["rows_without_technique"])),
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

def run(root, mode, out=sys.stdout):
    """mode is 'write' or 'check'. Returns the number of problems."""
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
        for key, figname in (("fully_detected", "family_fully_detected"),
                             ("partially_detected", "family_partially_detected"),
                             ("completely_missed", "family_completely_missed")):
            s2 = json.loads(original)
            s2["family_detection"][key] += 1
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
        print("%d region(s) disagree with the index summary. Run corpus/doc-figures.py to "
              "regenerate,\nand read WHY THIS EXISTS in this file before hand-editing one."
              % bad)
        return 1
    print("every generated region agrees with corpus/index-summary.json"
          if mode == "check" else "every generated region is up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
