#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Record a family label on reviewed rows, with the evidence, or refuse and say why.

USAGE
  corpus/assign-family.py --propose FILE           validate and report; writes nothing
  corpus/assign-family.py --propose FILE --apply   write, then audit what was written
  corpus/assign-family.py --audit [--session ID]   audit the families already recorded
  corpus/assign-family.py --inject                 the controls, in both directions

WHY A NEW WRITER RATHER THAN A FLAG ON THE EXISTING ONE
--------------------------------------------------------
`import-infected-tree.py` is the only module that assigns `family` today, and it is where the
detection-conditioned bucket came from: `if hit and not container_scoped: d["family"] = ...`.
Extending it would put the refusal that exists to prevent that shape inside the file that
produced it, sharing its helpers and its habits. A separate writer can refuse on rules the
importer would fail, and the fact that the importer WOULD fail them is information worth
keeping visible rather than migrating away.

WHAT IT REFUSES, AND WHY EACH REFUSAL IS SEPARATE FROM THE OTHERS
------------------------------------------------------------------
  name and prose      `family_evidence.detection_references()` - a rule code or a word naming
                      the scanner's output, in the family name, the basis, or any marker.
                      Lexical, immediate, and the one that will eventually miss something.
  membership          every sha256 must be a reviewed, malicious, currently-unfamilied row in
                      the reviewed bucket. A writer that could relabel an already-familied row
                      is a writer that can quietly rewrite the census.
  byte evidence       every marker is re-read from the sample bytes IN THIS PROCESS. The
                      reviewer's tool computed them; taking its word for it would be checking
                      the app's arithmetic against the app's arithmetic.
  determinism         a session in which EVERY family's membership is a function of the
                      recorded rule-set is refused outright. That session has renamed the
                      scanner's output and added nothing; see `family_evidence` for why the
                      dispersion test cannot see it.
  dispersion          how far a family's expected rules spread, as a SHARE. Refused below
                      `family_evidence.DISPERSION_FLOOR`. The boolean `family_bucket_suspects`
                      from `make-summary.py` is still computed and still reported, because the
                      census applies it - but it is not the refusal, and the first pilot session
                      is why: it named two families of seven, on one outlier member each, where
                      16 of 17 and 24 of 26 members share a rule. See `family_evidence`.
  leak                the recorded name, basis and markers are swept with the same predicate
                      `pre-push-check.py` uses. Markers are literals lifted out of malware, and
                      malware hardcodes its victim: a family named after a string that turns
                      out to be a customer's own host would write that host into the index.

WHAT IT RECORDS THAT NOTHING REFUSES
-------------------------------------
The sampling frame. Every refusal above interrogates the DEFINITION - is this family a renamed
rule-set, does it group a pile, are its markers really in the bytes. None of them can see the
pool the family was selected out of, because that is not a property of the family at all. This
writer draws from one pool and that pool is 530-of-531 detected, so every family it produces is
fully detected before anybody opens a file. That is not a reason to refuse - the labels are
correct and the rows deserve them - so `family_evidence.frame_detail()` measures it and
`apply_to_row` writes it onto every row beside the label. See `family_evidence.FRAME_MARGIN`
for why it is recorded rather than refused, and why it is a different key in the summary from
the detection-conditioned MEMBERSHIP bucket the importer produced.

WHAT IT WILL NOT TOUCH
-----------------------
`publishable`, which is computed by the gates and is nobody's to set by hand, and every other
field. The write asserts, per row, that the keys it changed are exactly `family` and
`family_evidence` - not as a comment, as an assertion in the path that does the writing.

It also sets no verdict and reviews nothing. These rows are already `review.human_confirmed`;
a family is a classification of material already ruled on, and if that ever stops being true
this tool is the wrong one to be reaching for.

THE WRITE ITSELF
-----------------
`indexio.index_lock` is held across the whole read-modify-write and the index is re-read inside
the lock immediately before the write, so a proposal validated against a stale read cannot land
on rows that moved underneath it. `write_jsonl_atomic` replaces the file. Both are the house
rule and both exist because this tree has lost a write to each failure already.
"""
import argparse, collections, copy, datetime, importlib.util, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import family_evidence as fe                                            # noqa: E402
from indexio import index_lock, write_jsonl_atomic, read_jsonl          # noqa: E402

WRITER = "corpus/assign-family.py"

# The other half. The sampling frame compares the pool against the whole reviewed malicious set
# and 140 of those 1,299 rows are published, so measuring against the index being written would
# compare the pool against a reference that moves every time a row is published.
PUBLISHED_INDEX = os.path.join(HERE, "index.jsonl")

# The leak predicate, loaded the way pre-push-check.py loads it: from the module that owns the
# question rather than restated here. A second opinion about what a leak is would be a second
# leak predicate, and this repository has already paid for a sweep that had its own idea.
_MAPS = [os.path.join(REPO, "trail-data/incoming/2026-09-03/private/account-mapping.json"),
         os.path.join(REPO, "trail-data/incoming/2026-09-03/private/infected-tree-mapping.json")]


def _load_mask_module():
    spec = importlib.util.spec_from_file_location(
        "vim_", os.path.join(HERE, "verify-infected-mask.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def leak_refusals(texts, maps=None):
    """Refusals for any text carrying a customer identifier. Empty means none does.

    Returns a note rather than a pass when no pseudonym map is on this machine: a public clone
    has neither map, and reporting "no leak" from a sweep with an empty identifier list is the
    inverted-status-check failure this repository records - a check that answered "all present"
    when every object was gone.
    """
    maps = [m for m in (maps if maps is not None else _MAPS) if os.path.isfile(m)]
    if not maps:
        return ["no pseudonym map on this machine, so the leak sweep could not run "
                "(this is not a pass)"]
    vim = _load_mask_module()
    out = []
    for path in maps:
        m = vim.load_map(path) if hasattr(vim, "load_map") else json.load(open(path))
        ids, keep = vim.identifiers(m), vim.keep_tokens(m)
        for text in texts:
            for seg in set(vim.segments_of(text or "")):
                low = seg.lower()
                if low in keep:
                    continue
                for ident in ids:
                    at = low.find(ident)
                    if at >= 0 and vim._is_a_leak(low, ident, at):
                        out.append("recorded evidence carries a customer identifier "
                                   "(a %d-character segment); pick a marker the attacker "
                                   "wrote, not one naming the victim" % len(seg))
                        break
    return sorted(set(out))


# ------------------------------------------------------------------------------- proposals

REQUIRED = ("family", "sha256", "basis", "markers", "decided_by", "decided_at", "session")


def read_proposals(path):
    """Proposals from a JSONL file, with shape errors raised rather than skipped."""
    props = read_jsonl(path)
    for i, p in enumerate(props, 1):
        if not isinstance(p, dict):
            raise ValueError("proposal %d is not an object" % i)
        missing = [k for k in REQUIRED if k not in p]
        if missing:
            raise ValueError("proposal %d is missing %s" % (i, ", ".join(missing)))
        if not isinstance(p["sha256"], list) or not p["sha256"]:
            raise ValueError("proposal %d has no members" % i)
        if not isinstance(p["markers"], list):
            raise ValueError("proposal %d: markers must be a list" % i)
    sessions = {p["session"] for p in props}
    if len(sessions) != 1:
        raise ValueError("a proposal file is one session; found %d" % len(sessions))
    return props, sessions.pop()


def reviewed_rows(rows, index_path):
    """`rows` plus the half it is not, so the frame's reference is the whole reviewed set.

    Which half to add is decided from the path rather than assumed, because `--index` can point
    this writer at either one and adding `index.jsonl` to itself would count 140 rows twice - a
    reference set that disagrees with `index-summary.json` by construction.
    """
    other_path = (fe.LOCAL_INDEX
                  if os.path.abspath(index_path) == os.path.abspath(PUBLISHED_INDEX)
                  else PUBLISHED_INDEX)
    other = read_jsonl(other_path) if os.path.isfile(other_path) else []
    return rows + other


def apply_to_row(row, prop, cluster_key, now):
    """A copy of `row` carrying the family and its evidence. Nothing else may differ.

    The assertion at the bottom is the guarantee, and it is here rather than in a test because
    a test proves the path was clean on the day it ran. `publishable` is the field this is
    protecting: it is computed by the gates from the publication blockers, and a classification
    pass that adjusted it would be deciding publication on the strength of a label.
    """
    out = copy.deepcopy(row)
    out["family"] = prop["family"]
    out[fe.EVIDENCE_FIELD] = {
        "assigned_by": WRITER,
        "session": prop["session"],
        "decided_by": prop["decided_by"],
        "decided_at": prop["decided_at"],
        "recorded_at": now,
        "basis": prop["basis"],
        "markers": sorted(prop["markers"]),
        "review_unit": {"kind": "expect.must_detect", "key": cluster_key},
        # Written on the row rather than left to the audit: a reader of this row a year from
        # now needs to know whether the label carried information the rule-set did not, and
        # the audit is a command nobody will re-run against the state that produced it.
        "ruleset_determined": prop["_ruleset_determined"],
        # Recorded rather than left to the audit for the same reason as the line above: a
        # family this round's pilot found the census WILL name needs its number on the row, so
        # the next reader of that census output can see 94% instead of re-deriving it.
        "dispersion": prop["_dispersion"],
        # The pool this family was selected out of, and how far its detection share sits from
        # the reviewed set. Indexed here rather than derived later because the pool SHRINKS as
        # rows are labelled: re-deriving this in a year would measure a different population and
        # quietly answer a different question. Subscripted, not `.get`, so a proposal that
        # reached this function without a measured frame is a crash and not a null field.
        "sampling_frame": prop["_sampling_frame"],
        "review_seconds": prop.get("review_seconds"),
    }
    changed = {k for k in set(out) | set(row) if out.get(k, KeyError) != row.get(k, KeyError)}
    assert changed == {"family", fe.EVIDENCE_FIELD}, \
        "assign-family would have changed %s; it may only change family and %s" % (
            sorted(changed - {"family", fe.EVIDENCE_FIELD}), fe.EVIDENCE_FIELD)
    assert out.get("publishable", KeyError) == row.get("publishable", KeyError)
    return out


def validate(props, rows, store, ms, maps=None, reviewed=None):
    """(refusals, post_state_rows, report). `refusals` empty means the write may proceed.

    Everything is decided against the POST state, computed in memory, before anything is
    written. The determinism and dispersion questions are properties of the result rather than
    of any one proposal, so a validator that ruled proposal-by-proposal could pass every one
    and still produce a session that says nothing.
    """
    refusals = []
    by_sha = {}
    for r in rows:
        by_sha.setdefault(r.get("sha256"), []).append(r)
    pop = fe.population(rows, ms=ms)
    pop_sha = {r["sha256"] for r in pop}
    # Measured against the pre-write pool, which is the pool these proposals were actually
    # drawn from. Computing it after the write would measure the pool the NEXT session will
    # draw from and record it on this one's rows.
    frame = fe.frame_detail(pop, reviewed if reviewed is not None else rows, ms=ms)

    seen, per_prop = set(), []
    for i, p in enumerate(props, 1):
        tag = "proposal %d (%s)" % (i, p.get("family", "?")[:40])
        bad = ["%s: %s" % (tag, m) for m in fe.check_family_name(p.get("family"))]
        for m in fe.detection_references(p.get("basis")):
            bad.append("%s: basis %s" % (tag, m))
        for mk in p.get("markers") or []:
            for m in fe.detection_references(mk):
                bad.append("%s: marker %s" % (tag, m))
        if not (p.get("basis") or "").strip():
            bad.append("%s: basis is empty; a label with no stated reason is a label nobody "
                       "can check" % tag)

        members = []
        for sha in p["sha256"]:
            if sha in seen:
                bad.append("%s: %s... appears in more than one proposal" % (tag, sha[:12]))
                continue
            seen.add(sha)
            hits = by_sha.get(sha) or []
            if not hits:
                bad.append("%s: %s... is not a row in the local index" % (tag, sha[:12]))
            elif len(hits) > 1:
                bad.append("%s: %s... matches %d rows; ambiguous" % (tag, sha[:12], len(hits)))
            elif sha not in pop_sha:
                r = hits[0]
                why = ("already carries family %r" % r["family"] if r.get("family")
                       else "verdict is %r" % r.get("verdict") if r.get("verdict") != "malicious"
                       else "bucket is %r" % r.get("bucket") if r.get("bucket") != fe.POPULATION_BUCKET
                       else "is not in the unfamilied population")
                bad.append("%s: %s... %s" % (tag, sha[:12], why))
            else:
                members.append(hits[0])

        if members:
            bad.extend("%s: %s" % (tag, m)
                       for m in fe.verify_markers(members, p.get("markers") or [], store))
        bad.extend("%s: %s" % (tag, m)
                   for m in leak_refusals([p.get("family"), p.get("basis")]
                                          + list(p.get("markers") or []), maps=maps))
        per_prop.append((p, members))
        refusals.extend(bad)

    # Determinism, computed against the reviewable population as it stands. Done here rather
    # than after the write because a session that has renamed the rule-set must not reach the
    # index and then be reported on.
    #
    # Grouped BY FAMILY and not by proposal, because merging across clusters is the main way a
    # family escapes being a function of the rule-set and it arrives as two proposals carrying
    # one name. Per-proposal, each half would look like a whole cluster and be refused; per
    # family, the union is judged, which is also what `audit()` measures after the write. Two
    # groupings would have been two answers to one question.
    fam_members = collections.defaultdict(list)
    for p, members in per_prop:
        fam_members[p.get("family")].extend(members)
    det = {}
    for f, members in fam_members.items():
        if not members:
            continue
        det[f] = fe.ruleset_determined(members, pop)
    for p, members in per_prop:
        is_det, keys = det.get(p.get("family"), (False, []))
        p["_ruleset_determined"] = is_det
        p["_cluster_keys"] = keys
        p["_dispersion"] = fe.dispersion_detail(fam_members.get(p.get("family")) or [])
        p["_sampling_frame"] = frame
    det = {f: v[0] for f, v in det.items()}
    if det and all(det.values()):
        refusals.append(
            "REFUSED: every family in this session is a function of the recorded rule-set "
            "(%d of %d). The labels restate expect.must_detect and carry nothing it did not. "
            "Split a cluster on a marker its members do not share, or take part of one - see "
            "family_evidence.ruleset_determined." % (len(det), len(det)))

    # The post state, and the census's own dispersion test over it.
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    replace = {}
    for p, members in per_prop:
        for r in members:
            # The row's OWN cluster, not the family's first one: `review_unit` records which
            # screen this row was decided on, and a family that merged two clusters would
            # otherwise stamp both halves with one of them.
            replace[r["sha256"]] = apply_to_row(r, p, fe.ruleset_key(r), now)
    post = [replace.get(r.get("sha256"), r) for r in rows]

    report = fe.audit(post, session=(props[0]["session"] if props else None), ms=ms)
    for f in report["dispersion_below_floor"]:
        d = report["determined"][f]["dispersion"]
        refusals.append(
            "REFUSED: %s is dispersed like a pile rather than a campaign - its most common "
            "expected rule reaches only %.0f%% of its %d detected members, across %d distinct "
            "rule-sets. The floor is %.0f%%; see family_evidence.dispersion_detail for what it "
            "is calibrated on and how thin that is."
            % (f, 100 * d["top_rule_share"], d["detected"], d["distinct_rule_sets"],
               100 * fe.DISPERSION_FLOOR))
    return refusals, post, report


# ----------------------------------------------------------------------------------- apply

def do_apply(props, path, store, ms):
    """Validate against the rows inside the lock, then write. Returns (rc, report).

    The re-read inside the lock is the whole reason the lock is taken around both halves of the
    operation: a proposal validated a minute ago against rows another writer has since merged is
    a proposal about rows that no longer exist in that state, and the resulting index would be
    internally consistent and wrong.
    """
    with index_lock(path):
        rows = read_jsonl(path)
        refusals, post, report = validate(props, rows, store, ms,
                                          reviewed=reviewed_rows(rows, path))
        if refusals:
            return 1, report, refusals
        write_jsonl_atomic(path, post)
    return 0, report, []


def rebuild_db():
    """Rebuild the derived read index after a write. Returns a one-line note.

    The database is a cache over exactly these bytes and the write just moved them, so leaving
    it stale would leave the next reader with an error to fix by hand - and a tool that makes a
    person fix something by hand is a tool that gets bypassed.
    """
    try:
        import derived_db
        stats = derived_db.build()
        return "derived index rebuilt: %s rows" % stats.get("rows", "?")
    except Exception as exc:                                # noqa: BLE001 - reported, not raised
        return "derived index NOT rebuilt (%s: %s); run corpus/derive-index-db.py" % (
            type(exc).__name__, str(exc)[:120])


def print_report(report):
    print("  rows assigned            %d" % report["rows_assigned"])
    print("  families                 %d" % len(report["families"]))
    print("  reviewable rows in scope %d" % report["scope_rows"])
    print("  dispersion test names    %s"
          % (", ".join(report["dispersion_names"]) or "none of the new families"))
    print("  ...below the %.0f%% floor    %s"
          % (100 * fe.DISPERSION_FLOOR,
             ", ".join(report["dispersion_below_floor"]) or "none"))
    print("  ruleset-determined       %d of %d families"
          % (report["ruleset_determined_families"], len(report["determined"])))
    fr = report.get("sampling_frame") or {}
    if fr:
        print("  sampling frame           %s - the pool is %d of %d detected (%.1f%%) against "
              "%d of %d (%.1f%%) over the reviewed set"
              % ("DETECTION-CONDITIONED" if fr["detection_conditioned"] else "not conditioned",
                 fr["pool_detected"], fr["pool_rows"], 100 * (fr["pool_detected_share"] or 0),
                 fr["reviewed_detected"], fr["reviewed_rows"],
                 100 * (fr["reviewed_detected_share"] or 0)))
    if report["determined"]:
        print("  recorded as detected     %d of %d assigned rows  (a property of the "
              "population: 530 of the 531 carry an expected rule)"
              % (report["detected_rows"], report["rows_assigned"]))
    for f, d in sorted(report["determined"].items()):
        sh = d["dispersion"]["top_rule_share"]
        print("    %-38s %3d rows  %2d cluster(s)  top rule %s  %s%s"
              % (f[:38], d["rows"], d["clusters_touched"],
                 "%3.0f%%" % (100 * sh) if sh is not None else "   -",
                 "RULESET-DETERMINED" if d["ruleset_determined"] else "carries own information",
                 "  (named by family_bucket_suspects)" if d["dispersion_named"] else ""))


# -------------------------------------------------------------------------------- controls

class _FakeStore:
    """A SampleStore with the bytes supplied, for controls that must not depend on trail-data."""

    def __init__(self, blobs):
        self.blobs = blobs
        self.truncated = {}
        self.available = True

    def get(self, sha256, size=None):
        b = self.blobs.get(sha256)
        return (b, "ok") if b is not None else (None, "not in the fake store")


def _row(sha, rules, **kw):
    r = {"sha256": sha, "verdict": "malicious", "bucket": fe.POPULATION_BUCKET,
         "size": 100, "publishable": True,
         "expect": {"must_detect": list(rules), "must_not_detect": []},
         "review": {"human_confirmed": True, "date": "2026-09-05"}}
    r.update(kw)
    return r


def inject():
    """Every refusal shown saying no, and shown saying yes on the neighbouring input.

    A refusal that has only ever been observed to pass is not yet a refusal - AGENTS.md, and
    five checks during the 2026-09-05 incident that passed while blind. So each case below is a
    pair: the input that must be refused, and the smallest change to it that must be accepted.
    Nine of these would pass trivially if `validate()` returned no refusals at all, which is why
    the accepted half of every pair is asserted too.
    """
    ms = fe.load_make_summary()
    fails = []

    def case(label, got, want):
        ok = (got == want)
        print("  %-64s %s" % (label, "ok" if ok else "FAIL (got %r)" % (got,)))
        if not ok:
            fails.append(label)

    # A real map in the current-incident schema, holding one identifier that appears in none of
    # the synthetic evidence below. Every case runs the leak sweep against it, so the sweep is
    # exercised in the ACCEPTING direction by all eighteen of them rather than only in the two
    # that are about leaks - and the controls do not silently become "no map, so no opinion" on
    # a machine without the collection tree, which is how the first draft of this function
    # reported eight failures that were all one missing file.
    import tempfile
    fd, fakemap = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(fakemap, "w", encoding="utf-8") as fh:
        json.dump({"mapping": {"zzfakeclientname": "acct99"}}, fh)

    def refused(props, rows, store, maps=(fakemap,), reviewed=None):
        r, _post, _rep = validate([dict(p) for p in props], rows, store, ms, maps=list(maps),
                                  reviewed=reviewed if reviewed is not None else rows)
        return r

    # Two rule-set clusters, so a family can be built that is NOT a function of the rule-set.
    # Three clusters. `g` shares OBF001 with `a` and is the neighbour a family can legitimately
    # be merged across; `b` shares nothing, so merging into it is refused by DISPERSION rather
    # than by determinism. Both refusals exist and they answer different questions, so the
    # controls need an input that reaches each of them alone.
    rows = ([_row("a%063d" % i, ["OBF001", "OBF002"]) for i in range(4)]
            + [_row("b%063d" % i, ["RCE009"]) for i in range(3)]
            + [_row("g%063d" % i, ["OBF001", "OBF003"]) for i in range(3)])
    blobs = {}
    for i in range(4):
        blobs["a%063d" % i] = b"<?php $k='ZZmarkerAlpha'; $s='ZZsharedKit'; eval($x); //padding"
    for i in range(3):
        blobs["b%063d" % i] = b"<?php $k='ZZmarkerBeta'; system($y); //padding padding"
    for i in range(3):
        blobs["g%063d" % i] = b"<?php $k='ZZmarkerGamma'; $s='ZZsharedKit'; assert($x); //pad"
    store = _FakeStore(blobs)

    def base(**kw):
        p = {"family": "doorway-kit-alpha", "sha256": ["a%063d" % i for i in range(3)],
             "basis": "the same hardcoded key literal in every member",
             "markers": ["ZZmarkerAlpha"], "decided_by": "control",
             "decided_at": "2026-09-07T00:00:00Z", "session": "control"}
        p.update(kw)
        return p

    print("family name and prose")
    case("a rule code in the family name is refused",
         any("rule code" in m for m in refused([base(family="obf001-cluster")], rows, store)), True)
    case("  ...the same name without it is accepted",
         refused([base(family="alpha-cluster")], rows, store), [])
    case("a detection word in the family name is refused",
         any("scanner's output" in m for m in refused([base(family="detected-payloads")], rows, store)), True)
    case("a detection word in the basis is refused",
         any("basis names" in m for m in refused([base(basis="the scanner flagged all three")],
                                                 rows, store)), True)
    case("  ...a basis about the bytes is accepted", refused([base()], rows, store), [])
    case("an empty basis is refused",
         any("basis is empty" in m for m in refused([base(basis="  ")], rows, store)), True)
    case("a name that is not kebab-case is refused",
         any("kebab-case" in m for m in refused([base(family="Doorway Kit")], rows, store)), True)

    print("membership")
    case("a sha256 that is not in the index is refused",
         any("not a row" in m for m in refused([base(sha256=["c" * 64] + ["a%063d" % i for i in range(3)])],
                                               rows, store)), True)
    already = [dict(r) for r in rows]
    already[0]["family"] = "something-else"
    case("a row that already carries a family is refused",
         any("already carries" in m for m in refused([base()], already, store)), True)
    notmal = [dict(r) for r in rows]
    notmal[0]["verdict"] = "benign"
    case("a row that is not reviewed-malicious is refused",
         any("verdict is" in m for m in refused([base()], notmal, store)), True)
    case("the same rows in the population are accepted", refused([base()], rows, store), [])
    case("one sha256 in two proposals is refused",
         any("more than one proposal" in m for m in refused(
             [base(), base(family="doorway-kit-beta")], rows, store)), True)

    print("byte evidence")
    case("a marker that is in no member's bytes is refused",
         any("at least 2" in m for m in refused([base(markers=["ZZnotpresent"])], rows, store)), True)
    case("a marker in only one member is refused",
         any("at least 2" in m for m in refused(
             [base(markers=["ZZmarkerAlpha", "padding padding"], sha256=["a%063d" % i for i in range(3)])],
             rows, _FakeStore(dict(blobs, **{"a%063d" % 0: b"<?php $k='ZZmarkerAlpha'; solo",
                                             "a%063d" % 1: b"<?php $k='ZZmarkerAlpha'; x",
                                             "a%063d" % 2: b"<?php $k='ZZmarkerAlpha'; y"})))), True)
    onemissing = dict(blobs); onemissing["a%063d" % 2] = b"<?php nothing shared here at all;;"
    case("a member carrying none of the markers is refused",
         any("carry none of the markers" in m
             for m in refused([base()], rows, _FakeStore(onemissing))), True)
    case("no markers at all is refused",
         any("no byte evidence" in m for m in refused([base(markers=[])], rows, store)), True)
    case("  ...markers present in every member are accepted", refused([base()], rows, store), [])

    print("determinism - the refusal family_bucket_suspects cannot make")
    whole = base(sha256=["a%063d" % i for i in range(4)])          # the entire OBF001,OBF002 cluster
    case("a session whose only family IS a whole rule-set cluster is refused",
         any("function of the recorded rule-set" in m for m in refused([whole], rows, store)), True)
    case("  ...taking part of that cluster instead is accepted",
         refused([base()], rows, store), [])
    both = [base(sha256=["a%063d" % i for i in range(4)]),
            base(family="doorway-kit-beta", sha256=["b%063d" % i for i in range(3)],
                 markers=["ZZmarkerBeta"], basis="a different hardcoded key literal")]
    case("two families that are both whole clusters are refused together",
         any("function of the recorded rule-set" in m for m in refused(both, rows, store)), True)
    mixed = [base(sha256=["a%063d" % i for i in range(4)]),
             base(family="doorway-kit-beta", sha256=["b%063d" % i for i in range(2)],
                  markers=["ZZmarkerBeta"], basis="a different hardcoded key literal")]
    case("  ...one whole and one partial is accepted, and the whole one is flagged on its row",
         refused(mixed, rows, store), [])
    # A family that merges two whole clusters is still a function of the rule-set, and it
    # arrives as two proposals carrying one name. Judged per proposal each half is a whole
    # cluster and refused for the wrong reason; judged per family the union is what is ruled on.
    # Merged across the neighbour that SHARES a rule, so this reaches the determinism refusal
    # rather than the dispersion one - the first draft merged into the unrelated cluster and
    # passed on the wrong message.
    def merge(n_g):
        return [base(sha256=["a%063d" % i for i in range(4)], markers=["ZZsharedKit"],
                     basis="the same hardcoded key literal across both variants"),
                base(sha256=["g%063d" % i for i in range(n_g)], markers=["ZZsharedKit"],
                     basis="the same hardcoded key literal across both variants")]
    case("a family merging two WHOLE clusters is still refused",
         any("function of the recorded rule-set" in m for m in refused(merge(3), rows, store)), True)
    case("  ...the same family leaving one row of the second cluster out is accepted",
         refused(merge(2), rows, store), [])

    print("dispersion - as a share, because the boolean refused two real families")
    # The pile: eight members, eight disjoint rule-sets, top rule reaching one in eight. This is
    # `legacy-infected-tree-sample`'s shape (39 rule-sets over 61 members, top rule 15%).
    pile_rows = [_row("d%063d" % i, ["AAA%03d" % i]) for i in range(8)] + \
                [_row("e%063d" % i, ["BBB001"]) for i in range(2)]
    pile_blobs = {"d%063d" % i: b"<?php $z='ZZpileMarker'; padding padding" for i in range(8)}
    pile_blobs.update({"e%063d" % i: b"<?php $z='ZZotherMarker'; padding" for i in range(2)})
    pile = base(family="looks-like-a-campaign", sha256=["d%063d" % i for i in range(8)],
                markers=["ZZpileMarker"], basis="a shared key literal in all eight")
    case("a family dispersed across every rule-set it touches is refused",
         any("dispersed like a pile" in m
             for m in refused([pile], pile_rows, _FakeStore(pile_blobs))), True)
    # The outlier: this round's real shape. Seven of eight share AAA001, one does not, so the
    # INTERSECTION IS EMPTY and family_bucket_suspects names it - and it must still be accepted.
    # One row is left outside a touched cluster so the determinism refusal does not fire and let
    # this case pass for the wrong reason; that happened on the first run of these controls.
    out_rows = [_row("d%063d" % i, ["AAA001", "AAA10%d" % i]) for i in range(7)] + \
               [_row("d%063d" % 7, ["ZZZ009"])] + \
               [_row("d%063d" % 9, ["AAA001", "AAA100"])] + \
               [_row("e%063d" % i, ["BBB001"]) for i in range(2)]
    out_blobs = dict(pile_blobs)
    out_blobs["d%063d" % 7] = b"<?php $z='ZZpileMarker'; a different wrapper entirely"
    outlier = base(family="one-outlier-campaign", sha256=["d%063d" % i for i in range(8)],
                   markers=["ZZpileMarker"], basis="a shared key literal in all eight")
    r_out, _post, rep_out = validate([dict(outlier)], out_rows, _FakeStore(out_blobs), ms,
                                     maps=[fakemap])
    case("  ...one outlier emptying the intersection is ACCEPTED", r_out, [])
    case("  ...and family_bucket_suspects still names it, reported not refused",
         rep_out["dispersion_names"], ["one-outlier-campaign"])
    case("  ...its top-rule share is recorded on the row",
         rep_out["determined"]["one-outlier-campaign"]["dispersion"]["top_rule_share"], 0.875)
    case("  ...the pile's share is below the floor and the outlier's is not",
         (fe.dispersion_detail([r for r in pile_rows if r["sha256"].startswith("d")][:8]
                               )["top_rule_share"] < fe.DISPERSION_FLOOR,
          rep_out["determined"]["one-outlier-campaign"]["dispersion"]["top_rule_share"]
          >= fe.DISPERSION_FLOOR), (True, True))
    # And the refusal that actually stops a pile, which does not consult the scanner at all.
    scattered = dict(pile_blobs)
    for i in range(8):
        scattered["d%063d" % i] = b"<?php unrelated malware class number %d here;;" % i
    case("a pile with no shared literal is refused by the byte evidence, not by dispersion",
         [m for m in refused([pile], pile_rows, _FakeStore(scattered))
          if "carry none of the markers" in m or "at least 2" in m] != [], True)

    print("the sampling frame - recorded, never refused, and separate from membership")
    # A pool every one of whose rows is detected, against a reviewed set that is half detected.
    # This is the real shape: 530 of 531 against 696 of 1,299.
    hot_pool = [_row("h%063d" % i, ["OBF001"]) for i in range(10)]
    cold = ([_row("k%063d" % i, ["OBF001"]) for i in range(5)]
            + [_row("m%063d" % i, []) for i in range(5)])
    f_hot = fe.frame_detail(hot_pool, hot_pool + cold, ms=ms)
    case("a pool detected far above the set it came from is CONDITIONED",
         f_hot["detection_conditioned"], True)
    case("  ...and the figures it was judged from are on the record",
         (f_hot["pool_detected"], f_hot["pool_rows"], f_hot["reviewed_detected"],
          f_hot["reviewed_rows"]), (10, 10, 15, 20))
    # The accepting direction, and it is the one that matters: a check that calls every frame
    # contaminated is not measuring the frame, it is a constant.
    fair = [_row("p%063d" % i, ["OBF001"]) for i in range(5)] + \
           [_row("q%063d" % i, []) for i in range(5)]
    f_fair = fe.frame_detail(fair, fair + fair, ms=ms)
    case("  ...a pool detected at the same rate as its set is NOT conditioned",
         f_fair["detection_conditioned"], False)
    case("  ...and a pool detected far BELOW its set is conditioned too, not only above",
         fe.frame_detail([_row("r%063d" % i, []) for i in range(10)],
                         [_row("r%063d" % i, []) for i in range(10)]
                         + [_row("s%063d" % i, ["OBF001"]) for i in range(30)],
                         ms=ms)["detection_conditioned"], True)
    case("  ...the frame says membership is NOT what is conditioned",
         f_hot["membership_conditioned_on_detection"], False)
    # And it reaches the row, which is the whole point of measuring it.
    props_f = [base()]
    _r, post_f, rep_f = validate([dict(p) for p in props_f], rows, store, ms, maps=[fakemap],
                                 reviewed=rows)
    written = [r for r in post_f if isinstance(r.get(fe.EVIDENCE_FIELD), dict)]
    case("every written row carries a sampling frame",
         (len(written), all(isinstance(r[fe.EVIDENCE_FIELD].get("sampling_frame"), dict)
                            for r in written)), (3, True))
    case("  ...and the audit reads it back off the rows rather than recomputing",
         rep_f["sampling_frame"] is not None and rep_f["sampling_frame"]["kind"], "sampling-frame")
    case("  ...one frame across the session is reported as one, not as a list of three",
         len(rep_f["sampling_frames"]), 1)
    # A proposal that reached the writer without a measured frame must crash, not write a null.
    try:
        apply_to_row(rows[0], dict(base(), _ruleset_determined=False,
                                   _dispersion=fe.dispersion_detail(rows[:3])),
                     "OBF001,OBF002", "T")
        got = "wrote a row with no frame"
    except KeyError:
        got = "KeyError"
    case("a proposal with no measured frame is a crash, not a null field", got, "KeyError")
    # The reference set is the OTHER half, chosen from the path rather than assumed.
    case("the reviewed reference for the local half adds the published half",
         os.path.basename(PUBLISHED_INDEX), "index.jsonl")

    print("the row the writer produces")
    r0 = rows[0]
    frame0 = fe.frame_detail(rows[:3], rows, ms=ms)
    out = apply_to_row(r0, dict(base(), _ruleset_determined=False,
                            _dispersion=fe.dispersion_detail(rows[:3]),
                            _sampling_frame=frame0),
                   "OBF001,OBF002", "T")
    case("only family and family_evidence differ",
         sorted(k for k in set(out) | set(r0) if out.get(k) != r0.get(k)),
         ["family", fe.EVIDENCE_FIELD])
    case("publishable is byte-identical", out["publishable"] == r0["publishable"], True)
    case("the source row is not mutated", "family" in r0, False)
    mutated = copy.deepcopy(out)
    mutated["publishable"] = False
    case("  ...and a version that DID touch publishable is caught by the same comparison",
         sorted(k for k in set(mutated) | set(r0) if mutated.get(k) != r0.get(k)),
         ["family", fe.EVIDENCE_FIELD, "publishable"])

    print("the leak sweep on recorded evidence")
    vim = _load_mask_module()
    m = vim.load_map(fakemap) if hasattr(vim, "load_map") else json.load(open(fakemap))
    ids = vim.identifiers(m)
    case("the control map yields an identifier to probe with", bool(ids), True)
    if ids:
        probe = list(ids)[0]
        case("a marker carrying a mapped identifier is refused",
             any("customer identifier" in x for x in leak_refusals([probe], maps=[fakemap])), True)
        case("  ...an unrelated marker is not",
             leak_refusals(["ZZmarkerAlpha"], maps=[fakemap]), [])
        case("  ...and the identifier inside a longer marker is still refused",
             any("customer identifier" in x
                 for x in leak_refusals(["wp-content-%s-backup" % probe], maps=[fakemap])), True)
    case("no map on this machine is reported, not passed",
         any("not a pass" in m for m in leak_refusals(["anything"], maps=[])), True)
    if os.path.exists(fakemap):
        os.unlink(fakemap)

    print("the real sample store")
    real = fe.SampleStore()
    if not real.available:
        print("  %-64s %s" % ("collection tree absent", "SKIPPED - stated, not passed"))
    else:
        rows_local = read_jsonl(fe.LOCAL_INDEX) if os.path.exists(fe.LOCAL_INDEX) else []
        pop = fe.population(rows_local, ms=ms)
        if pop:
            data, note = real.get(pop[0]["sha256"], pop[0].get("size"))
            case("a population row resolves to bytes that hash to its sha256",
                 note in ("ok",) or note.startswith("truncated"), True)
            case("  ...and an unknown sha256 resolves to nothing",
                 real.get("f" * 64)[0], None)

    print()
    print("%d control(s) FAILED" % len(fails) if fails else "all controls passed")
    return 1 if fails else 0


# -------------------------------------------------------------------------------------- cli

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Record a family label and its byte evidence, or refuse and say why.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--propose", metavar="FILE",
                   help="a session's proposals, JSONL. Validated and reported; nothing is "
                        "written without --apply.")
    g.add_argument("--audit", action="store_true",
                   help="audit the families this writer has already recorded")
    g.add_argument("--inject", action="store_true", help="the controls, in both directions")
    ap.add_argument("--apply", action="store_true",
                    help="write the validated proposals to the local index")
    ap.add_argument("--session", default=None, help="restrict --audit to one session id")
    ap.add_argument("--index", default=fe.LOCAL_INDEX,
                    help="the index to read and write (default: the local half)")
    args = ap.parse_args(argv)

    if args.inject:
        return inject()

    ms = fe.load_make_summary()

    if args.audit:
        rows = read_jsonl(args.index)
        report = fe.audit(rows, session=args.session, ms=ms)
        print("audit of %s" % os.path.relpath(args.index, REPO))
        print_report(report)
        bad = bool(report["dispersion_below_floor"]) or report["all_ruleset_determined"]
        if report["all_ruleset_determined"]:
            print("\nEVERY recorded family is a function of the recorded rule-set. The labels "
                  "restate expect.must_detect.")
        print("\n%s" % ("AUDIT FAILED" if bad else "audit clean"))
        return 1 if bad else 0

    props, session = read_proposals(args.propose)
    store = fe.SampleStore()
    if not store.available:
        print("REFUSE TO WRITE: the collection tree is not on this machine, so no marker can "
              "be verified against the bytes it claims to come from.")
        return 2
    print("session %s: %d proposal(s), %d row(s)"
          % (session, len(props), sum(len(p["sha256"]) for p in props)))

    if not args.apply:
        rows = read_jsonl(args.index)
        refusals, _post, report = validate(props, rows, store, ms,
                                           reviewed=reviewed_rows(rows, args.index))
        print_report(report)
        for m in refusals:
            print("  REFUSE: %s" % m)
        print("\n%s" % ("REFUSED (%d)" % len(refusals) if refusals
                        else "would write %d row(s); re-run with --apply" % report["rows_assigned"]))
        return 1 if refusals else 0

    rc, report, refusals = do_apply(props, args.index, store, ms)
    print_report(report)
    for m in refusals:
        print("  REFUSE: %s" % m)
    if rc:
        print("\nREFUSED (%d); nothing was written" % len(refusals))
        return 1
    print("\nwrote %d row(s) to %s" % (report["rows_assigned"],
                                       os.path.relpath(args.index, REPO)))
    if os.path.abspath(args.index) == os.path.abspath(fe.LOCAL_INDEX):
        print(rebuild_db())
    # Re-read and re-audit: the report above was computed on the in-memory post state, and a
    # writer that reported on what it MEANT to write would be the only witness to its own write.
    again = fe.audit(read_jsonl(args.index), session=session, ms=ms)
    if (again["rows_assigned"] != report["rows_assigned"]
            or again["dispersion_below_floor"] != report["dispersion_below_floor"]):
        print("MISMATCH: the index does not hold what was validated. Investigate before "
              "trusting either figure.")
        return 3
    print("re-read from disk: %d row(s), audit agrees" % again["rows_assigned"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
