#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""What a family label may be justified by, and what it may never be justified by.

Shared by `assign-family.py` (the writer, which is the authority) and `review-app.py` (the
local reviewer, which only proposes). Neither owns this file: the rule that a family is
defined by bytes has to be one rule, because two copies of it drift and the drift is
invisible - `make-summary.py` records that exact failure for the detection predicate and
solved it by writing `is_detected()` once.

THE DEFECT THIS FILE EXISTS TO MAKE UNREPEATABLE
-------------------------------------------------
Round 16 found `legacy-infected-tree-sample`: 61 rows, 61 detected, a label assigned by
`import-infected-tree.py` under `if hit and not container_scoped`. A sample joined the family
*because the scanner flagged it*, so the family's detection rate was 100% definitionally and no
rule change in either direction could move it. Twelfth recorded instance of CORPUS_PLAN section
11, and the first one sitting in a numerator's selection rule rather than in a denominator.

The 531 rows this tool reviews are one step away from repeating it, and the step is short.

**The review unit is the rule-set cluster, and the rule-set is the scanner's output.** The 531
carry no family and no technique; what they do carry is `expect.must_detect`, a recorded rescan
result, and grouping by it collapses them into 95 clusters of which six cover 212 rows. That
grouping is the only thing that makes 531 rows reviewable in an afternoon - the 525 quarantine
rows were ruled in 88 clusters for the same reason - and it is also, taken literally as a
membership rule, exactly the defect above with a different label on it.

**`family_bucket_suspects` cannot see this shape.** That test names a family whose detected
members share NO expected rule: dispersion, the shape a pile has. A family lifted from one
rule-set cluster is the *opposite* extreme - its members share ALL their rules - so it passes
the dispersion test trivially, by construction, every time. The control that caught the bucket
is blind to the bucket's mirror image, and running it over a rule-set-clustered session and
reporting a clean result would be reporting nothing. That is why `ruleset_determined()` below
exists and why the writer refuses on it.

And the consequence is not subtle. Every one of the 531 except one carries a non-empty
`expect.must_detect`, so `is_detected()` is true for 530 of them. Any family drawn from these
rows is therefore *fully detected*, whatever it is called. Labelling all 95 clusters would add
95 fully-detected families to a census that currently holds 9 of 38, and move the macro rate
from 29.9% to roughly 80% without a single rule changing. A figure that moves that far on a
labelling pass is not a measurement of the scanner.

SO WHAT MAY A FAMILY BE JUSTIFIED BY
-------------------------------------
Bytes, and only bytes. `markers_for()` extracts printable literals shared across members and
ranks them by how *rare* they are across the whole population, so the strings that rise are the
ones that pick this cluster out rather than the ones every PHP file carries. A hardcoded key
literal present in 26 members and in 26 rows corpus-wide is a family marker; `function`,
present in 252, is not.

The writer then re-reads the bytes and **verifies** that every marker it is asked to record
actually occurs in them (`verify_markers`). Evidence that is asserted rather than checked is
the same class of claim as a figure nobody regenerated.

Two independent refusals, because one of them is a vocabulary and vocabularies go stale:

  `detection_references()`  a lexical refusal on the words and the rule codes. Cheap, obvious,
                            and it is the one that will miss something.
  `ruleset_determined()`    a structural refusal computed from the rows every run. It does not
                            read the family's name or its prose at all, so a family that talks
                            its way past the vocabulary is still caught if its membership is a
                            function of the rule-set.

The second is the real one. The first is there because a reviewer typing a rule code into a
family name should be told immediately rather than after the write.

WHAT THE FIRST PILOT SESSION CHANGED HERE, AND WHY
----------------------------------------------------
The round that built this file specified a third refusal: run `family_bucket_suspects` over the
result and refuse a session it names. The first real session refused two families of seven on
it, and both refusals were wrong.

`family_bucket_suspects` asks whether the intersection of a family's rule-sets is empty. **One
outlier member empties an intersection.** The two it named were a file-manager shell where 16 of
17 members share `BD012`, and a doorway-page set where 24 of 26 share `PHI008`; the odd members
are the same malware caught by a different route. The thing the test was built to catch sits at
15% - `legacy-infected-tree-sample`, 39 distinct rule-sets over 61 members - and every other
labelled family in the index today sits at 100%. A boolean cannot tell 15% from 94%.

There is a second reason, and it is the structural one. **Both dispersion and determinism are
computed from `expect.must_detect`, which is the scanner's output.** Determinism uses it to say
*this label carries nothing the detection record did not*, which is a statement about
informativeness and is a fair thing to refuse on. Dispersion would use it to say *this family is
not real*, which is the scanner deciding family membership - the exact defect this file exists
to prevent, wearing the coat of the check that found it.

So dispersion is now **quantified and recorded, and refuses only below `DISPERSION_FLOOR`**; the
boolean result is still reported, because the census will apply it and whoever reads that output
needs to know why these families are named. What actually stops a pile from being recorded here
is `verify_markers`: every member must carry a literal read from its own bytes, and the 61 rows
of `legacy-infected-tree-sample` - five unrelated malware classes - have no such literal to
share. That refusal is stricter than dispersion and it does not consult the scanner at all.
"""
import collections, importlib.util, json, math, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

__all__ = ["LOCAL_INDEX", "POPULATION_BUCKET", "population", "ruleset_key",
           "ruleset_clusters", "SampleStore", "markers_for", "detection_references",
           "ruleset_determined", "verify_markers", "audit", "FAMILY_NAME_RE",
           "check_family_name", "MARKER_MIN", "MARKER_MAX", "READ_CAP",
           "EVIDENCE_FIELD", "load_make_summary"]

LOCAL_INDEX = os.path.join(HERE, "local", "index-local.jsonl")

# Where the reviewed-but-unfamilied rows live. All 531 are local-half rows in this one bucket;
# stated as a constant rather than hardcoded at three call sites so that pointing this tool at
# a different bucket is one edit and is visible in a diff.
POPULATION_BUCKET = "quarantine/evidence"

# The field the writer adds beside `family`. Named once here: `assign-family.py --audit` finds
# its own writes by it, and a rename that missed one site would make the audit silently
# measure an empty set - which is the shape of a check that cannot fail.
EVIDENCE_FIELD = "family_evidence"

# Bytes read per sample for previews and markers. The population's median is 6,991 bytes and
# its p90 is 173,409, but its max is a 279 MB archive: an uncapped read makes one member of one
# cluster stall the reviewer for as long as it takes to read a quarter-gigabyte, and no family
# judgement has ever needed the tail of a tarball. Markers found past this point do not exist
# as far as this tool is concerned, and `SampleStore.truncated` reports when that happened so a
# reviewer is told rather than quietly shown a prefix.
READ_CAP = 256 * 1024

MARKER_MIN = 8          # shorter runs are language boilerplate, not campaign markers
MARKER_MAX = 64         # longer runs are usually one encoded blob and identify one file

FAMILY_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")


def load_make_summary():
    """`make-summary.py` as a module, for its population and detection predicates.

    Imported rather than reimplemented. `family_population()` decides which rows this tool may
    touch and `is_detected()` decides what a family's rate means; a second copy of either here
    would be two predicates meant to be one predicate, which is the drift `make-summary.py`
    already documents having paid for once.
    """
    spec = importlib.util.spec_from_file_location(
        "make_summary_", os.path.join(HERE, "make-summary.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------ population and clusters

def population(rows, bucket=POPULATION_BUCKET, ms=None):
    """The rows this tool may assign a family to: reviewed, malicious, unfamilied, in `bucket`.

    `family_population(r) == "unfamilied"` is the same predicate `index-summary.json` counts
    531 with, imported rather than restated. The bucket condition is an additional narrowing,
    not a redefinition: it is what makes the first version of this tool one screen per cluster
    over one queue instead of a general-purpose index editor.
    """
    ms = ms or load_make_summary()
    return [r for r in rows
            if r.get("verdict") == "malicious"
            and r.get("bucket") == bucket
            and ms.family_population(r) == "unfamilied"]


def ruleset_key(row):
    """The cluster key: the recorded rule-set, sorted, as a stable string.

    THIS IS THE SCANNER'S OUTPUT AND IT IS A PRESENTATION ORDER, NOT A MEMBERSHIP RULE. It puts
    like bytes on one screen so a person can decide quickly. The moment it decides who is in a
    family, the family is conditioned on detection - see the module docstring, and see
    `ruleset_determined()`, which is the check that says whether that happened.
    """
    return ",".join(sorted((row.get("expect") or {}).get("must_detect") or [])) or "<none>"


def ruleset_clusters(rows):
    """{key: [rows]}, largest first. Ordering is the queue: the six largest cover 212 of 531."""
    out = collections.defaultdict(list)
    for r in rows:
        out[ruleset_key(r)].append(r)
    return collections.OrderedDict(
        sorted(out.items(), key=lambda kv: (-len(kv[1]), kv[0])))


# ------------------------------------------------------------------------------- the bytes

class SampleStore:
    """Sample bytes by sha256, resolved through the collection's blobmap.

    `origin.path` on these rows is the absolute path the file had on the customer's machine and
    resolves to nothing here - all 531 of them. The bytes are in the collection tree and the
    blobmap is the only index onto them, so this is the resolver rather than a convenience.

    Every read is verified against the row's `sha256` and capped at `READ_CAP`. A cap makes the
    hash of a truncated read disagree, so verification is done on the FIRST `READ_CAP` bytes of
    the file only when the file is that short, and skipped-with-a-flag when it is not: claiming
    a hash match over a prefix would be a check that cannot fail.
    """

    def __init__(self, repo=REPO, cap=READ_CAP):
        self.base = os.path.join(repo, "trail-data", "incoming", "2026-09-03")
        self.cap = cap
        self.truncated = {}
        self._map = None
        self._cache = {}

    @property
    def available(self):
        return os.path.isfile(os.path.join(self.base, "derived", "blobmap-all.jsonl"))

    def _blobmap(self):
        if self._map is None:
            self._map = {}
            p = os.path.join(self.base, "derived", "blobmap-all.jsonl")
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        d = json.loads(line)
                        self._map[d["sha256"]] = d["paths"]
        return self._map

    def get(self, sha256, size=None):
        """(data, note). `data` is None when the bytes are not on this machine.

        `note` is 'ok', 'truncated at N', or a reason. A caller that renders `data` without
        looking at `note` shows a prefix as if it were the file, which is how a reviewer comes
        to rule on a cluster whose members differ only past byte 262,144.
        """
        if sha256 in self._cache:
            return self._cache[sha256]
        result = (None, "no blobmap at %s" % self.base)
        if self.available:
            result = (None, "sha256 not in the blobmap")
            for rel in self._blobmap().get(sha256, []):
                cand = os.path.join(self.base, rel)
                if not os.path.isfile(cand):
                    continue
                with open(cand, "rb") as fh:
                    data = fh.read(self.cap + 1)
                if len(data) > self.cap:
                    data = data[:self.cap]
                    self.truncated[sha256] = True
                    result = (data, "truncated at %d of %s bytes"
                              % (self.cap, size if size is not None else "?"))
                else:
                    import hashlib
                    ok = hashlib.sha256(data).hexdigest() == sha256
                    result = (data, "ok" if ok else "SHA256 MISMATCH - not the recorded bytes")
                break
        self._cache[sha256] = result
        return result


_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % MARKER_MIN)
_SPLIT = re.compile(rb"[\s,;()\[\]{}<>|]+")


def literals(data):
    """Printable literals in `data`, as a set of bytes objects.

    Runs of printable ASCII split on the punctuation that separates tokens in every language
    in this corpus. Deliberately not a language parser: the population holds PHP, HTML,
    JavaScript, shell, and files whose extension says one and whose bytes say another, and a
    parser that understood one of them would silently see less of the others.
    """
    out = set()
    for m in _RUN.finditer(data or b""):
        for tok in _SPLIT.split(m.group()):
            if MARKER_MIN <= len(tok) <= MARKER_MAX:
                out.add(tok)
    return out


def document_frequency(rows, store):
    """{literal: how many rows of the population carry it}. The denominator for rarity.

    Over the whole population rather than over the cluster, which is the entire point: a
    literal in 56 of 56 members means nothing if it is also in 189 of 531 rows. Ranking without
    this returns `function` and `__FILE__` at the top of every cluster.
    """
    df = collections.Counter()
    per_row = {}
    for r in rows:
        data, _ = store.get(r["sha256"], r.get("size"))
        toks = literals(data)
        per_row[r["sha256"]] = toks
        for t in toks:
            df[t] += 1
    return df, per_row


def markers_for(cluster_rows, df, per_row, population_size, limit=25):
    """Candidate byte markers for one cluster, most distinctive first.

    Ranked by coverage times rarity - the share of the cluster's members carrying the literal,
    times `log(population / document frequency)`. Coverage alone promotes boilerplate that
    every member has because every PHP file has it; rarity alone promotes a literal unique to
    one member, which identifies a file and not a family.

    Returned with both counts attached, because the reviewer is the one ruling and a bare
    ranked list hides the thing they need: a literal in 26 of 32 members and 26 rows corpus-wide
    is a family that SPLITS this cluster, and that is visible only from the pair.
    """
    n = len(cluster_rows)
    seen = collections.Counter()
    for r in cluster_rows:
        for t in per_row.get(r["sha256"], ()):
            seen[t] += 1
    out = []
    for tok, k in seen.items():
        if k < 2:
            continue                    # a literal one member carries is not shared evidence
        d = max(df.get(tok, k), 1)
        score = (k / float(n)) * math.log(max(population_size, 2) / float(d))
        out.append({"marker": tok.decode("ascii", "replace"),
                    "members": k, "of": n, "corpus_wide": d,
                    "score": round(score, 4)})
    out.sort(key=lambda d: (-d["score"], -d["members"], d["marker"]))
    return out[:limit]


# ---------------------------------------------------------------------- the two refusals

# A rule code as this corpus writes them: ARC002, BD016, DEFC001, PHI008, OBF037, WS006.
_RULE_CODE = re.compile(r"[A-Za-z]{2,5}[0-9]{3}")

# Whole alphabetic words that name the scanner's output rather than the sample's bytes. Matched
# case-insensitively against alphabetic runs, so `Detected`, `detection` and `undetected` are
# all caught and `detectable-by-eye` inside a longer token still is.
#
# `hit` and `quarantine` are in this list on purpose and both will occasionally refuse a
# sentence that meant something else. `if hit and not container_scoped` is the literal predicate
# that produced the bucket, and the prior-corpus labels these very rows carry include several
# named after a containment batch and three named after the scanner's own confidence tier -
# which is the same defect already sitting in the data, waiting to be copied forward by a
# reviewer who sees a plausible-looking label and reuses it. Over-refusal costs a rephrase.
# Under-refusal costs a round, and this round exists because of one.
DETECTION_WORDS = frozenset("""
    detect detects detected detecting detection detections undetected detectable
    flag flags flagged flagging
    scan scans scanned scanning scanner scanners
    quarantine quarantined quarantining
    hit hits
    alert alerts alerted
    signature signatures
    rule rules ruleset rulesets
    confidence
    lyxbosa clamav yara
    must_detect expect
""".split())

_ALPHA_RUN = re.compile(r"[A-Za-z_]+")


def detection_references(text):
    """Every reason `text` names the scanner's output. Empty list means it does not.

    Lexical, and therefore the weaker of the two refusals - a vocabulary is a list somebody
    maintains, and this repository's standing lesson is that a hand-maintained set goes stale
    and nothing notices. It is here to fail fast and legibly at the moment a reviewer types a
    rule code into a family name. `ruleset_determined()` is the one that does not depend on
    anybody keeping a list current.
    """
    if not text:
        return []
    out = []
    for m in _RULE_CODE.finditer(text):
        out.append("names a rule code: %s" % m.group())
    for m in _ALPHA_RUN.finditer(text):
        w = m.group().lower()
        if w in DETECTION_WORDS:
            out.append("names the scanner's output: %s" % m.group())
    return sorted(set(out))


# A family is refused when its most common expected rule is carried by fewer than this share of
# its detected members. See `dispersion_detail` for where the number comes from and for the
# statement of how thin the calibration is.
DISPERSION_FLOOR = 0.5


def dispersion_detail(family_rows):
    """How dispersed a family's expected rules are, as a share rather than as a boolean.

    `make-summary.family_bucket_suspects` asks whether the intersection of the members' rule-sets
    is empty. That is the right question for the census and the wrong one for this writer,
    because ONE outlier member empties an intersection. Run over this round's pilot session it
    named two families of seven: one where 16 of 17 members share `BD012` and one where 24 of 26
    share `PHI008`. Neither is a pile. Both would have been refused by a boolean.

    The share separates them from the thing the boolean was built to catch:

        legacy-infected-tree-sample   61 members, 39 distinct rule-sets, top rule in  15%
        every other labelled family    3-52 members, 1 distinct rule-set, top rule in 100%
        this round's two named        17 and 26 members, top rule in 94% and 92%

    **The calibration is one positive and six negatives, and that is not a calibration.** It is a
    floor at 15% and a ceiling at 92% with nothing observed between them. `DISPERSION_FLOOR` is
    set at 50% because it is the middle of an empty range, not because anything was measured
    there. A family landing between 20% and 90% is a case this repository has never seen; the
    tool refuses it, and the right response is for a person to look rather than to move the
    number.
    """
    sets = [set((r.get("expect") or {}).get("must_detect") or []) for r in family_rows]
    sets = [s for s in sets if s]
    if not sets:
        return {"members": len(family_rows), "detected": 0, "distinct_rule_sets": 0,
                "top_rule_count": 0, "top_rule_share": None, "intersection_empty": True}
    counts = collections.Counter()
    for s in sets:
        for x in s:
            counts[x] += 1
    top = counts.most_common(1)[0][1]
    return {"members": len(family_rows), "detected": len(sets),
            "distinct_rule_sets": len({frozenset(s) for s in sets}),
            "top_rule_count": top, "top_rule_share": round(top / float(len(sets)), 4),
            "intersection_empty": not set.intersection(*sets)}


def ruleset_determined(family_rows, population_rows):
    """Is this family's membership a function of the recorded rule-set?

    True when every rule-set cluster the family touches lies ENTIRELY inside it. If it does,
    then knowing a row's `expect.must_detect` tells you its family, the label carries nothing
    the detection record did not already carry, and a family-weighted figure computed over it
    restates the scanner's own output back to itself.

    This is the check `family_bucket_suspects` structurally cannot make. That one names a
    family whose members share no rule; this one names a family whose members share every rule
    and nothing else. The bucket found in round 16 was the first shape. A cluster-first review
    tool produces the second by default, which is why this is computed rather than trusted.

    A family escapes by carrying information the rule-set does not: it splits a cluster (two
    rows with identical rule-sets landing in different families, because their bytes differ), or
    it takes part of one. Both are ordinary outcomes of reading the bytes, and both are what the
    marker ranking in `markers_for()` is for.
    """
    fam = {r["sha256"] for r in family_rows}
    by_key = collections.defaultdict(set)
    for r in population_rows:
        by_key[ruleset_key(r)].add(r["sha256"])
    touched = {ruleset_key(r) for r in family_rows}
    for k in touched:
        if not by_key[k] <= fam:
            return False, sorted(touched)
    return True, sorted(touched)


def verify_markers(family_rows, markers, store):
    """Refusals for markers that are not in the bytes. Empty list means every one is.

    Two conditions, and they are different questions:

      every marker must occur in at least two members   - a literal one file carries identifies
                                                          that file, not a family
      every member must carry at least one marker       - otherwise a row is in the family on
                                                          the reviewer's say-so alone, which is
                                                          the assertion this whole file exists
                                                          to stop being accepted

    Read from the bytes here, in the writer's own process, rather than trusted from the
    proposal. The reviewer's tool computed these; a writer that took its word for it would be
    checking the app's arithmetic against the app's arithmetic.
    """
    if not markers:
        return ["no markers: a family with no byte evidence cannot be recorded"]
    encoded = []
    for m in markers:
        try:
            encoded.append((m, m.encode("ascii")))
        except UnicodeEncodeError:
            return ["marker is not ASCII, so it cannot be a literal read from these bytes: %r"
                    % m[:40]]
    problems, carried = [], {}
    per_marker = collections.Counter()
    for r in family_rows:
        data, note = store.get(r["sha256"], r.get("size"))
        if data is None:
            problems.append("bytes for a member are not on this machine (%s)" % note)
            continue
        n = 0
        for m, b in encoded:
            if b in data:
                per_marker[m] += 1
                n += 1
        carried[r["sha256"]] = n
    for m, _ in encoded:
        if per_marker[m] < 2:
            problems.append("marker occurs in %d member(s), needs at least 2: %r"
                            % (per_marker[m], m[:40]))
    bare = [s for s, n in carried.items() if n == 0]
    if bare:
        problems.append("%d member(s) carry none of the markers, so their membership rests on "
                        "no byte evidence (first: %s...)" % (len(bare), bare[0][:12]))
    return problems


# ------------------------------------------------------------------------------- the audit

def audit(all_rows, session=None, ms=None):
    """What the assignment did, measured from the rows rather than from the session file.

    Three questions, and the round's rule is that a session which fails any of them is wrong
    now rather than at the next census:

      dispersion    `family_bucket_suspects` over every reviewed malicious row. It must name
                    none of the newly assigned families. Imported from `make-summary.py` so
                    that the test the census will apply is the test applied here.
      determinism   `ruleset_determined()` over each newly assigned family. The dispersion test
                    is blind to this shape; see that function.
      detection     the recorded rate for the new families. Reported because it is expected to
                    be 100% and a reader needs to see that stated rather than discover it - the
                    530 detected rows of the 531 are why, and it is a property of the
                    population and not of the labelling.
    """
    ms = ms or load_make_summary()
    mal = [r for r in all_rows if r.get("verdict") == "malicious"]
    mine = [r for r in mal
            if isinstance(r.get(EVIDENCE_FIELD), dict)
            and (session is None or r[EVIDENCE_FIELD].get("session") == session)]
    new_families = sorted({r["family"] for r in mine if r.get("family")})

    suspects = ms.family_bucket_suspects(mal)
    named = sorted(set(suspects) & set(new_families))

    # The determinism population is every row that was reviewable in this scope, whether or not
    # it was assigned: a family that took a whole cluster is only visible as such against the
    # rows it left behind.
    scope = [r for r in mal if r.get("bucket") == POPULATION_BUCKET
             and (ms.family_population(r) == "unfamilied"
                  or isinstance(r.get(EVIDENCE_FIELD), dict))]
    by_family = collections.defaultdict(list)
    for r in mine:
        if r.get("family"):
            by_family[r["family"]].append(r)

    determined = {}
    for f, g in sorted(by_family.items()):
        is_det, keys = ruleset_determined(g, scope)
        d = dispersion_detail(g)
        determined[f] = {"ruleset_determined": is_det, "rows": len(g),
                         "clusters_touched": len(keys),
                         "detected": sum(1 for r in g if ms.is_detected(r)),
                         "dispersion": d,
                         "dispersion_named": f in suspects,
                         "below_floor": (d["top_rule_share"] is not None
                                         and d["top_rule_share"] < DISPERSION_FLOOR)}
    n_det = sum(1 for v in determined.values() if v["ruleset_determined"])
    return {
        "families": new_families,
        "rows_assigned": len(mine),
        "dispersion_names": named,
        "dispersion_below_floor": sorted(f for f, v in determined.items() if v["below_floor"]),
        "determined": determined,
        "ruleset_determined_families": n_det,
        "all_ruleset_determined": bool(determined) and n_det == len(determined),
        "detected_rows": sum(v["detected"] for v in determined.values()),
        "scope_rows": len(scope),
    }


def check_family_name(name):
    """Refusals for a family name. Empty list means it is usable."""
    out = []
    if not isinstance(name, str) or not name:
        return ["family name is missing"]
    if not FAMILY_NAME_RE.match(name):
        out.append("family name must be lowercase kebab-case ([a-z0-9-], starting with a "
                   "letter): %r" % name[:60])
    if not 3 <= len(name) <= 60:
        out.append("family name must be 3-60 characters, is %d" % len(name))
    out.extend(detection_references(name))
    return out


if __name__ == "__main__":
    sys.exit("family_evidence.py is a library. The writer, its controls and its audit are "
             "corpus/assign-family.py; the reviewer is corpus/review-app.py.")
