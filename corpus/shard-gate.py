#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§7.2 - the gate that runs before any shard is built. Fails the build, never warns.

`publishable` is a COMPUTED field, not a human assertion (§4.4). This script is the only
thing allowed to compute it, so the rule lives in exactly one place.

The rule (§4.1): a sample is publishable when its verdict is not `unreviewed` AND every
sensitivity tag is `clean`, `c2`, or has been masked and re-verified. `pii` and `content`
are never publishable, because there is no substitution that makes them safe.

A `secret`-tagged row carries one more requirement, added once `verify-content-mask.py`
had a gate able to answer it: masking applied is not enough, the row must also carry
`masking.secret_gate == "PASS"`. §5.1 requires a masked credential to keep its shape, so an
absolute scan of the output must report credential-shaped literals and cannot be the test;
the differential one - no credential-shaped literal in the output byte-identical to one in
the input - is what `secret_gate()` measures. The other three masking gates ask about
identifiers and detection, so all three can pass on a row whose attacker password came
through untouched.

THE GATE USED TO BE HALF A GATE
-------------------------------
It failed when a row CLAIMED publishable and was not, and it was silent when a row was
publishable and did not claim it. Both are the same defect - a stored copy of a derived
value that no longer matches what derives it - and only one of them had ever been
observed to fail. AGENTS.md: a check that has never been observed to fail is not yet a
check. This is the same shape as the regex that matched `/home/` and not `/home2/`, and
as the status check that read a 404 body as success: a check narrower than the thing it
guards, silent in exactly the direction its subject drifted.

The drift was not hypothetical. Two operator review passes - six samples in one, eight in
another - set `verdict: malicious` and `sensitivity: ["c2"]` and did not re-run this
script, so fourteen rows kept `publishable: false` and kept recording "verdict is
unreviewed" and "sensitivity not yet assessed" as their blockers after both statements
had stopped being true. The gate recomputed all fourteen, printed "publishable flags
corrected: 14", and exited 0. Nothing downstream could see them: `promote-pending.py`
defers on the recorded blocker, and `index-summary.json` counts the recorded blocker, so
a stale blocker is a stale denominator.

`staleness()` therefore reports THREE classes and fails on any of them:

  * over-claimed - stored true, computed false. The original rule.
  * under-claimed - stored false, computed true. The fourteen.
  * blocker drift - the boolean agrees and the recorded REASONS do not. Narrower than the
    boolean and worth its own class, because §8's accounting is built out of the reasons:
    a row can be unpublishable for a different reason than the one it records, and the
    boolean cannot see that at all.

WHY THE FIELD IS STILL STORED
-----------------------------
A derived value that is stored can drift; one computed on read cannot. That argues for
dropping it, and the argument loses to a property of the published half: `index.jsonl` is
tracked, and a stranger who clones this repository reads it as a document. A row that
says `publishable: true` states its own status; a row that omits it requires the reader
to run this script to learn anything, and the whole point of the map-free invariants
below is that this file is runnable by a stranger, not that it is mandatory reading.
`publish_blockers` has to be materialised for the same reason and a stronger one - it is
where §8's denominator comes from, and it carries EVERY blocker rather than the boolean's
one bit.

So the repair is not to stop storing it. It is that a stored derived value is a cache,
and a cache with nothing asserting it equals its source is just a copy. `staleness()` is
that assertion, and `--inject` is the proof it can fail.
"""
import json, os, re, sys, collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from indexio import read_jsonl, write_jsonl_atomic, index_lock, LockBusy

import gate_provenance
import clearance
import finding_notes

ALWAYS_OK = {"clean", "c2"}
NEVER = {"pii", "content"}

# The gates that read bytes, and the word each one goes by in a blocker. Detection parity is
# not here: it is a boolean, and it is the one field whose meaning depends on whether a
# masking pass ran at all, so it is asked separately at the end of `evaluate()`.
BYTE_GATES = (("plaintext_gate", "plaintext"),
              ("encoded_layer_gate", "encoded-layer"),
              ("secret_gate", "secret"))

# The maps are gitignored and out of repo. `gate_provenance.verify` checks the `tools` half
# always - those five modules are tracked, so a stranger who clones this repository can
# recompute it - and the `map` half only where the maps exist, saying which it managed. That
# ordering is what keeps this gate runnable by someone who has the index and nothing else,
# which §7.2's map-free invariants exist to guarantee.
PROV_MAPS = [p for p in (os.path.join("trail-data", "incoming", "2026-09-03", "private",
                                      "account-mapping.json"),
                         os.path.join("trail-data", "incoming", "2026-09-03", "private",
                                      "infected-tree-mapping.json"))
             if os.path.exists(p)]


def provenance_state(m):
    """'ok', 'absent' or 'stale' for one masking block. Three answers, never two."""
    return gate_provenance.verify(m.get("provenance"), PROV_MAPS)[0]


# ---------------------------------------------------------------------------
# Reading a recorded gate verdict.
#
# The rule underneath this function is one line: an unrecognised or absent gate value is a
# FAILURE, never a pass. It is written out as a classifier rather than as `!= "PASS"`
# scattered four times because `!= "PASS"` is right by accident. It fails closed on every
# value that is not the string, which is the correct direction - but it cannot tell a FAIL
# from a value it does not understand, and it cannot say so. Six rows record this field as a
# DICT carrying `result: FAIL` plus a profile, an older schema that predates every tool now
# in the tree; twelve more record the string `SKIPPED-oversize (>1MB)`, which is not a
# verdict at all but a gate that never ran. Both are blockers, and they are different
# blockers: the repair for a FAIL is a human decision, and the repair for a SKIP is to run
# the gate.
#
# Four classes, and the fourth exists so that a form nobody anticipated cannot be silent:
#   pass       - the exact string PASS, or a dict whose `result` is
#   fail       - the exact string FAIL, or a dict whose `result` is
#   skipped    - a string that says the gate did not run
#   unreadable - everything else, including a bool, a number, a list, and a dict with no
#                recognised `result`. Fails closed and says what it saw.
# ---------------------------------------------------------------------------

def gate_result(value, boolean=False):
    """(verdict, detail) for one recorded gate value. Never returns 'pass' by default."""
    if boolean:
        # Strictly `is True`. A truthiness test here would read the string "no" as a pass.
        if value is True:
            return "pass", None
        if value is False:
            return "fail", None
        return "unreadable", "a %s, not a boolean" % type(value).__name__
    if isinstance(value, dict):
        result = value.get("result")
        if result == "PASS":
            return "pass", None
        if result == "FAIL":
            return "fail", None
        return "unreadable", "a finding dict whose result is %r" % (result,)
    if isinstance(value, str):
        if value == "PASS":
            return "pass", None
        if value == "FAIL":
            return "fail", None
        if value.upper().startswith("SKIP"):
            return "skipped", value
        return "unreadable", "the string %r" % (value[:60],)
    return "unreadable", "a %s" % type(value).__name__


def _gate_blocker(label, verdict, detail):
    """One reason per cause, and the cause is which of the three ways it is not a pass."""
    if verdict == "fail":
        return "%s gate did not pass" % label
    if verdict == "skipped":
        return "%s gate was not run: %s" % (label, detail)
    return ("%s gate result is not a recognised verdict and is not read as a pass: %s"
            % (label, detail))


DECISION = "decision"
RESOLUTION = "resolution"


def _decision_blocks(masking):
    """(name, block) for every dict under `masking` that records a `decision`.

    One level down, and one level down inside `gate_categories`, which is the second place
    this index records a finding. Deliberately not keyed to a fixed list of finding names:
    the field is a human's, the two rows that carry one put it inside
    `encoded_layer_finding`, and a rule that only looked there would be a rule about where
    somebody happened to write it.
    """
    out = []
    for k, v in sorted((masking or {}).items()):
        if isinstance(v, dict) and DECISION in v:
            out.append((k, v))
        if k == "gate_categories" and isinstance(v, dict):
            for k2, v2 in sorted(v.items()):
                if isinstance(v2, dict) and DECISION in v2:
                    out.append(("gate_categories." + k2, v2))
    return out


def evaluate(r):
    why = []
    if r.get("verdict") == "unreviewed":
        why.append("verdict is unreviewed: nothing leaves that state without a human")
    tags = set(r.get("sensitivity") or [])
    bad = tags & NEVER
    if bad:
        why.append("carries %s, which is not maskable and is never published"
                   % "/".join(sorted(bad)))
    if "unreviewed" in tags:
        why.append("sensitivity not yet assessed")
    if "undecidable" in tags:
        why.append("obfuscated and did not decode: held local-only permanently")
    unmasked = tags - ALWAYS_OK - NEVER - {"unreviewed", "undecidable"}
    m = r.get("masking") or {}
    applied = bool(m.get("applied"))

    # QUESTION ONE, and it is about the TAGS: does this row need a masking pass it has not
    # had? Unchanged, and it stays tag-driven because that is what it is asking.
    if unmasked and not applied:
        why.append("carries %s but no masking has been applied" % "/".join(sorted(unmasked)))

    # QUESTION TWO, and it is about the TAGS as well: where a masking pass was required and
    # ran, is the record complete enough to read? Absent is demanded only where the tags say
    # the gate was owed, because a row that owes no gate owes no result either - and absent
    # is a separate blocker from FAIL on purpose. FAIL is a measurement that did not pass;
    # absent is a row nothing measured, and the repair differs. Collapsing them would let a
    # --fix manufacture the field.
    if unmasked and applied:
        # Asked FIRST, because it decides whether the verdicts below mean anything. A
        # recorded `PASS` is a claim about what some version of the gate said, and until
        # last round nothing recorded which version. Re-gating by hand found 5 of 95 local
        # rows and 1 of 8 rows in the published half sitting at `PASS` under a predicate
        # that had since been tightened; the samples had not changed, and no field in the
        # index could have shown it.
        #
        # Absent and stale are one blocker rather than two: §8 counts reasons and the
        # repair is identical for both - re-measure with `mask-samples.py`. The distinction
        # is diagnostic, so it goes in the gate's report and not in the row's blocker list.
        if provenance_state(m) != "ok":
            why.append("gate results have no usable provenance: cannot tell whether "
                       "the tools that produced them still agree")
        for gate, label in BYTE_GATES:
            if gate in m:
                continue
            if gate == "secret_gate":
                # §7.2's secret bullet. The other gates ask about identifiers and detection;
                # none looks at credentials, so a row could clear all of them with an
                # attacker password still byte-identical to the one in the input.
                if "secret" in tags:
                    why.append("carries secret with masking applied but no secret_gate "
                               "result was recorded")
            else:
                why.append("%s gate has no recorded result" % label)
        if "detection_survived" not in m:
            why.append("detection parity has no recorded result")

    # QUESTION THREE, and it is about the BYTES: what did the gates that ran actually say?
    #
    # Asked of EVERY row that records a result, whatever its tags are. That is the whole
    # repair. The gate's finding is evidence about the bytes and the tag is a claim about
    # them, so conditioning whether to read the evidence on the claim it might contradict is
    # backwards - and it was not hypothetical. Five rows recorded `secret_gate: FAIL` and
    # none carried the `secret` tag, so the armed rule never looked; four of them were
    # `publishable: true` with zero blockers, three tagged `clean` alone, which put them
    # outside `unmasked` and skipped the masking branch entirely. A recorded FAIL nobody
    # reads is worse than no gate, because the index looks like it was checked.
    #
    # `unreadFailures()` asserts the property this is here to produce - publishable with a
    # recorded non-pass and no clearance is impossible - independently of this loop, so the
    # rule and the invariant cannot fail silently together.
    for gate, label in BYTE_GATES:
        if gate not in m:
            continue
        verdict, detail = gate_result(m[gate])
        if verdict == "pass":
            continue
        if clearance.applicable(r, gate) is not None:
            continue
        why.append(_gate_blocker(label, verdict, detail))

    # QUESTION FOUR, and it is about the BYTES as well: did masking ADD a credential-shaped
    # literal that nothing can attribute?
    #
    # `secret_gate()` was differential in one direction only - no literal in the output
    # byte-identical to one in the input - and said nothing about the count going up. One row
    # recorded 23 credential-shaped literals after masking where it had 22 before, and
    # nothing in the tree asked. A gate that can only fail one way is the defect this corpus
    # keeps finding.
    #
    # The gate itself now owns the comparable half: an unattributed addition over an
    # UNCHANGED decoded-layer population is masking making a credential, and it returns FAIL,
    # which the loop above already reads. This is the other half, and it is here rather than
    # there because it is a different cause with a different repair. `secret_literals()`
    # counts over the plaintext and every decoded layer, and that layer population is not
    # stable under masking: on the observed row four masked bytes inside one base64 region
    # re-encoded, the `base64+inflate` layers below it decoded differently, and 23 layers
    # became 16. `before` and `after` were then censuses of two different populations, which
    # §11 says bounds the result and not reality.
    #
    # It still blocks, because a "cannot tell" must not read as "fine" - that is exactly the
    # three-answer rule `gate_provenance.verify()` exists for. It is ONE reason, never two:
    # where the population is comparable the gate has already failed and this stays silent,
    # because §8 counts reasons and two reasons for one cause is the double-counted
    # denominator that left the blocker tally 14 out for two rounds.
    #
    # Read of every row that records the evidence, whatever its tags - the Question Three
    # discipline. Not clearable: `CLEARABLE_GATES` is the four recorded gate results, and
    # this is a statement that a measurement cannot be made rather than a finding to judge.
    sl = m.get("secret_literals")
    if isinstance(sl, dict):
        b4, aft = (sl.get("secret_literals_before"), sl.get("secret_literals_after"))
        comparable = sl.get("literal_population_comparable")
        if isinstance(b4, int) and isinstance(aft, int) and aft > b4 and comparable is False:
            why.append("masking left more credential-shaped literals than it found (%d -> "
                       "%d) over a decoded-layer population that moved (%s layers before, "
                       "%s after): the two counts are censuses of different populations"
                       % (b4, aft, sl.get("decoded_layers_before"),
                          sl.get("decoded_layers_after")))

    # QUESTION FIVE: is there a recorded decision that says it is holding this row, with
    # nothing recorded to say it was ever resolved?
    #
    # THE POPULATION IS ZERO AND THAT IS WHY THE CONTROLS ARE THE WHOLE OF THE CHECK.
    # Two rows in the corpus carry a `decision` - both published, both `publishable: true`,
    # both adjudicating one address inside an encoded layer - and both carry a `resolution`.
    # Nothing in this repository reads either field. So this rule has never fired, cannot
    # be validated against real data, and is exactly what AGENTS.md means by "a check that
    # has never been observed to fail is not yet a check". It is written for its controls,
    # which assert it in both directions; the live run is a census that says the population
    # is zero, never evidence that the rule works.
    #
    # The hazard is precise. A block reading `decision: held for human confirmation; not
    # published until resolved` with no `resolution` beside it is, to every tracked
    # consumer of this index, identical to a row with nothing wrong: `publishable` is
    # computed from the gate verdicts and the tags, none of which the decision touches. The
    # sentence says the row is held and nothing holds it.
    #
    # Read one level down through `masking` and through `gate_categories`, because that is
    # where a finding is recorded and a decision has so far been written inside one. Not
    # clearable: `CLEARABLE_GATES` is the four recorded gate results, and a decision awaiting
    # its own resolution is work to finish rather than evidence to judge.
    for block_name, block in _decision_blocks(m):
        if not block.get("resolution"):
            why.append("masking.%s records a decision with no resolution" % block_name)

    # Detection parity is the one field whose meaning depends on whether a masking pass
    # happened at all. `applied: false` has two forms and they are told apart by which key
    # is set: `reason` ("no identifier to mask") is a pass that ran, and its
    # `detection_survived: true` is honest. `not_applicable_reason` is a recorded decision
    # that masking is impossible - 29 archive containers - and its `detection_survived:
    # false` is a placeholder for a measurement nobody took, not a report that masking
    # destroyed detection. Reading it as the latter would attach 29 rows to a cause that
    # never happened, which §8 forbids more specifically than it forbids missing one.
    if "detection_survived" in m and not m.get("not_applicable_reason"):
        verdict, detail = gate_result(m["detection_survived"], boolean=True)
        if verdict != "pass" and clearance.applicable(r, "detection_survived") is None:
            why.append("masking changed the detection set" if verdict == "fail"
                       else _gate_blocker("detection-parity", verdict, detail))
    if r.get("local_only"):
        why.append("marked local_only: %s" % r["local_only"])
    return (not why), why

# An assertion nobody sanctioned. `expect.must_detect` says a reviewed sample MUST be
# detected and fails the suite when it is not; a row with verdict `unreviewed` has no
# review behind it, so the field is asserting a judgement no human ever made.
#
# 943 rows were in this state, written by the scan that discovered them - the same
# mechanism §11 records for the recall figure, where `must_detect` was populated from a
# rescan so a sample carried it BECAUSE it was detected. That reporting was repaired and
# these rows were not. What the scan saw belongs in `observed_detection`, which asserts
# nothing; `expect` stays absent until a human sets a verdict.
#
# This is a hard failure rather than a publish blocker, because an unreviewed row is
# already unpublishable for a different reason and the blocker would hide it.
# Two invariants for the published half, both checkable WITHOUT the account map - which
# matters, because the map is gitignored and out of repo, so a gate that needed it could
# never run for anyone else.
#
#   * a published row carries no `origin`. That field is the collection's record of a path
#     on a customer host. It is not verifiable by a stranger and not ours to publish. Four
#     rows had one, because a promotion built the new row out of the whole local row.
#   * every `/home/<x>/` in a published row has <x> in `acctNN` form. A real account name
#     surviving there is the failure this catches, and it does not need to know which names
#     are real: anything that is not a pseudonym is wrong.
#
# Masking missed three client names for a year of collection because it keyed on full
# account names while the incident-response directories used abbreviations - a repair
# directory named `<abbrev>-safe-repair-...` for an account mapped under its full name. Name
# matching is the wrong shape of check; a positive assertion about the form of what is
# allowed is the right one. (The example here used to name the real account: the commit that
# scrubbed three client names left a fourth in the comment explaining the scrub.)
# `/home\d*/`, not `/home/`. The largest account in the legacy Infected tree lives at
# `/home2/<acct>/` - 13,982 occurrences in one error_log - and a `/home/`-only pattern does
# not see it. The gate was narrower than the thing it was guarding, which is the failure mode
# 5.3 records as "a gate that is stricter than the masker can be is a gate that can never
# pass", in its mirror form: a gate looser in the wrong axis never fires at all.
HOME_RE = re.compile(r'/home\d*/([^/"]+)/')
ACCT_RE = re.compile(r'acct\d+$')

# The same positive-form discipline, extended to the two components the legacy-tree import
# introduces. Both state what is ALLOWED rather than hunting for what is not, and neither
# needs the account map - which is the property that makes them runnable by a stranger.
#
#   * `site`   identifies the customer whose server a sample came from -> siteNN
#   * `server` identifies the hosting provider's machine               -> srvNN
#
# Added WITH the fields, not after them: 5.3 says every new field that can carry an
# identifier gets gate coverage before it is populated, and records two separate occasions
# where a field nobody expected to carry identifiers carried them.
SITE_RE = re.compile(r'^site\d+$')
SERVER_RE = re.compile(r'^srv\d+$')
FORM = (("site", SITE_RE, "siteNN"), ("server", SERVER_RE, "srvNN"))

def formViolations(rows):
    """Form of the masked components, over BOTH halves.

    Cheap, map-free, and it runs on the local half too - a local row is not published, but it
    is where the next promotion reads from, and a leak that is only caught at promotion time
    has already been copied into whatever built the new row.
    """
    out = []
    for r in rows:
        for field, rx, want in FORM:
            v = r.get(field)
            if v is not None and not (isinstance(v, str) and rx.match(v)):
                out.append((r["sha256"], "%s=%r is not in %s form" % (field, v, want)))
    return out

def publishedLeaks(rows):
    out = []
    for r in rows:
        if r.get("origin") is not None:
            out.append((r["sha256"], "carries origin"))
            continue
        for m in HOME_RE.finditer(json.dumps(r)):
            if not ACCT_RE.match(m.group(1)):
                out.append((r["sha256"], "unmasked home component: %s" % m.group(1)))
                break
    return out

def integrityViolations(rows):
    out = []
    for r in rows:
        exp = r.get("expect") or {}
        if exp.get("must_detect") and r.get("verdict") == "unreviewed":
            out.append(r["sha256"])
    return out


def mustDetectViolations(rows):
    """`expect.must_detect` may not assert a rule the row's own post-masking scan did not see.

    WHY THIS FIELD GETS A READER RATHER THAN A DELETION
    ----------------------------------------------------
    `masking.detection_after_masking` was an orphan: 6 published rows carry it and no
    tracked module in `corpus/` mentioned it. It looks redundant beside `rules_after`, and
    it is not - **no published row carries `rules_after` at all**, so on those six rows this
    is the published half's only record of what the scanner matched after masking, and it is
    the measurement `expect.must_detect` was taken from. Deleting it would delete the
    evidence for six `must_detect` assertions and leave the assertions.

    So it gets the relationship it stands in:

        set(expect.must_detect) <= set(masking.detection_after_masking)

    A subset and not equality, because `must_detect` is a floor - a suite assertion that
    these rules must fire - while the recorded scan may legitimately have seen more. What it
    may not be is a rule the row's own record says was not matched: that is an assertion
    contradicting the measurement beside it, and it is exactly the shape §11 records for
    `must_detect` populated from a rescan. It holds on 6 of 6 today, with equality on all
    six.

    Map-free and scanner-free, like every other invariant here: it compares two fields the
    row already carries, so a stranger with the published half can run it.
    """
    out = []
    for r in rows:
        after = (r.get("masking") or {}).get("detection_after_masking")
        if after is None:
            continue
        if not isinstance(after, list):
            out.append((r["sha256"], "detection_after_masking is %s, not a list"
                        % type(after).__name__))
            continue
        want = (r.get("expect") or {}).get("must_detect") or []
        missing = sorted(set(want) - set(after))
        if missing:
            out.append((r["sha256"],
                        "expect.must_detect asserts %s, which the row's own recorded "
                        "post-masking scan did not match" % "/".join(missing)))
    return out


# `staging_dir` is a directory NAME, and the positive form of that is what is asserted.
# Same discipline as `HOME_RE`/`ACCT_RE` above and for the same reason: 67 of the 75 rows
# that carry it are PUBLISHED, no tracked module read it, and a field on a published row
# that nothing looks at cannot go wrong in a way anything notices. Stating what is allowed -
# one path component, from a conservative character set - is checkable without the account
# map, which is the property that lets a stranger run it.
#
# Measured before it was armed: 13 distinct values over 75 rows, 7 to 32 characters, every
# one a single component drawn from [A-Za-z0-9._-], and NONE of them matching an identifier
# in either pseudonym map. They are attacker-created directory names. The value of the rule
# is not today's population, it is that `staging_dir` can never come to hold `/home/<x>/…`
# without something saying so.
STAGING_DIR_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')


def stagingDirViolations(rows):
    """`staging_dir` must be one path component, never a path."""
    out = []
    for r in rows:
        v = r.get("staging_dir")
        if v is None:
            continue
        if not isinstance(v, str):
            out.append((r["sha256"], "staging_dir is %s, not a string" % type(v).__name__))
        elif v in (".", ".."):
            out.append((r["sha256"], "staging_dir is a relative path element"))
        elif not STAGING_DIR_RE.match(v):
            out.append((r["sha256"], "staging_dir is not a single path component from "
                                     "[A-Za-z0-9._-]"))
    return out


# The placement vocabulary, closed. Eleven labels are carried by 33,555 rows and every one
# of them was written by an untracked pass; listing them here is what turns "whatever that
# pass emitted" into something a reader can be wrong about. A twelfth label is not a
# failure of the corpus, it is a signal that a writer nobody tracks has changed its
# categories - which is exactly how `sensitivity` and the decoded-form tags were found, one
# round apart, by somebody noticing rather than by anything asking.
PLACEMENT_LABELS = {
    "live webroot: plugin or theme directory",
    "live webroot: other",
    "live account .trash (deleted site remnant)",
    "live account home (outside the webroot)",
    "inside the webroot",
    "IR quarantine copy",
    "account home ~/tmp",
    "account home ~/.cache",
    "shared system temp (/var/tmp)",
    "cron-triggered copy",
    "other",
}


def placementViolations(rows):
    """`placements` must account for exactly as many copies as the row claims to have.

    WHY THIS FIELD GETS A READER RATHER THAN A DELETION
    ----------------------------------------------------
    `placements` was an orphan: 33,555 rows carry it, 15,674 of them PUBLISHED, and no
    tracked module in `corpus/` mentioned it. It is not dead, though - it is a histogram of
    where on a real server the copies of a blob were found, which is corpus content a
    consumer of the published half can actually use, and it stands in a checkable
    relationship to a field that is tracked:

        sum(placements.values()) == count

    That held on 33,553 of 33,555 rows when this was written. The other two carry
    `copies_on_disk` instead of `count` - an older name for the same quantity, itself an
    orphan on exactly those two rows - and it agrees there too, so the invariant is
    33,555 of 33,555 with both names allowed and neither assumed.

    A field with no reader cannot go wrong in a way anything notices. This is the reader:
    the untracked pass that writes `placements` also writes `count` from the same list, so
    the two drifting apart means that pass changed on one side only, and nothing else in
    the tree would see it.
    """
    out = []
    for r in rows:
        p = r.get("placements")
        if p is None:
            continue
        if not isinstance(p, dict):
            out.append((r["sha256"], "placements is %s, not a mapping" % type(p).__name__))
            continue
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in p.values()):
            out.append((r["sha256"], "placements holds a non-integer count"))
            continue
        unknown = sorted(set(p) - PLACEMENT_LABELS)
        if unknown:
            out.append((r["sha256"], "placement label not in the closed vocabulary: %r"
                        % unknown[0][:48]))
            continue
        # `count` is the tracked name; `copies_on_disk` is the older one two published rows
        # still use. Absent BOTH is a finding, not a skip - a histogram whose total nothing
        # records is a histogram nothing can check.
        total = r.get("count", r.get("copies_on_disk"))
        if total is None:
            out.append((r["sha256"], "placements with neither count nor copies_on_disk"))
        elif sum(p.values()) != total:
            out.append((r["sha256"], "placements sum to %d, row claims %d"
                        % (sum(p.values()), total)))
    return out


# ---------------------------------------------------------------------------
# Three blocks that carry published content and had no tracked reader at all.
#
# `field-provenance.py` reports 64 orphan fields; the three groups below are 10 of them,
# and they are the 10 that sit on PUBLISHED rows and describe either an identifier that is
# deliberately KEPT or the identity of a shipped fixture. A field with no reader cannot go
# wrong in a way anything notices, and these are the fields where "goes wrong" means either
# a customer address recorded as attacker infrastructure or a shard whose manifest does not
# describe what it ships.
#
# All three are map-free. §7.2's floor is that a stranger with the index and nothing else
# can run this file, so a rule that needed the pseudonym maps would be a rule that only the
# incident host can check - which is the half that matters least.
# ---------------------------------------------------------------------------

# The shape of a human adjudication, and the complete list of what one must say. Mirrors
# `lift-adjudication.ADJUDICATION_KEYS` plus the gate it is about; duplicated rather than
# imported because that module reads and writes an index and this one must stay importable
# by anything, and asserted equal to it in `inject()`.
ADJUDICATION = "human_adjudication"
ADJUDICATION_REQUIRED = ("about", "classification", "decision", "resolution", "value",
                         "why_it_matters")


def adjudicationViolations(rows):
    """A recorded human adjudication must be one somebody else could audit.

    WHY THIS FIELD EXISTS AND WHY IT NEEDS A READER
    ------------------------------------------------
    Two published rows recorded an adjudication of one embedded address under
    `masking.encoded_layer_finding` - the key `clearance.finding_digest` hashes as the
    encoded-layer gate's evidence. `lift-adjudication.py` moved it to a field of its own;
    this is the reader that stops the field becoming the next place a claim hides.

    Four rules, and the third is the one that earns the check:

      * every key in `ADJUDICATION_REQUIRED` present and non-empty. An adjudication that
        does not say what was classified, what the value was, why it mattered and how it
        was resolved is not a record, it is an assertion.
      * `about` names a gate the row actually RECORDS. An adjudication about a measurement
        the row does not carry is about nothing.
      * **an address recorded in the resolution must be one the row declares as a kept
        indicator.** This is the c2-versus-customer distinction made structural rather than
        assumed. The whole reason this block is allowed to name an identifier at all is
        that the identifier is attacker infrastructure kept on purpose (§4.1: c2 is never
        masked); an adjudication that resolved to an address the row does NOT list in
        `ioc.campaign_hosts` would be a decision to publish an address on no declared
        ground, which is exactly the direction that cannot be undone.
      * the block must not be a gate finding. `decision` is what makes it a human's, and
        `shard-gate`'s question five already requires a `resolution` beside it; what is
        added here is that nothing under this key may carry a profile key the gate emits,
        so the two can never merge back into one block.

    Each required key is read BY NAME below rather than through a loop over
    `ADJUDICATION_REQUIRED`. That is not style: `field-provenance.key_positions` counts a
    field as read when its name appears as a `.get("k")` argument or a subscript, and a
    tuple of string constants iterated with `a.get(k)` is invisible to it. A reader the
    census cannot see leaves the field reported as an orphan, which is the state this whole
    section exists to end - and writing the names into a dict literal instead would classify
    them as WRITTEN by this file, which is worse: false in the direction that hides them.
    """
    out = []
    for r in rows:
        a = (r.get("masking") or {}).get(ADJUDICATION)
        if a is None:
            continue
        if not isinstance(a, dict):
            out.append((r["sha256"], "%s is %s, not an object" % (ADJUDICATION,
                                                                  type(a).__name__)))
            continue

        def said(key, value):
            return bool(value) if not isinstance(value, str) else bool(value.strip())

        missing = [k for k, v in (("about", a.get("about")),
                                  ("classification", a.get("classification")),
                                  ("decision", a.get("decision")),
                                  ("resolution", a.get("resolution")),
                                  ("value", a.get("value")),
                                  ("why_it_matters", a.get("why_it_matters")))
                   if not said(k, v)]
        if missing:
            out.append((r["sha256"], "records no %s" % "/".join(missing)))
            continue
        extra = sorted(set(a) - set(ADJUDICATION_REQUIRED))
        if extra:
            out.append((r["sha256"], "carries %s, which is not adjudication shape"
                        % "/".join(extra)))
            continue
        if a.get("about") not in (r.get("masking") or {}):
            out.append((r["sha256"], "is about %s, which this row does not record"
                        % a.get("about")))
            continue
        res = a.get("resolution")
        addr = res.get("address") if isinstance(res, dict) else None
        if addr is not None and addr not in iocValues(r):
            # By shape. The address on these rows is attacker infrastructure and is
            # published on purpose, but this refusal has to be printable on a row where
            # it is NOT, and there it would be a customer identifier in a terminal.
            out.append((r["sha256"], "resolves to a %d-character address the row does "
                                     "not declare in ioc.campaign_hosts" % len(str(addr))))
    return out


# What a gate finding may contain, and nothing else. Taken from `verify-content-mask._profile`
# - counts, lengths, positions, the segment size and the layer that carried it - plus the two
# prose keys the gate attaches. Measured over both halves before arming: 12 finding blocks,
# two key sets differing only by `methods`, and every value the type below.
#
# `kinds` and `positions` are closed because their producers are closed: `_kind` returns
# `domain` or `acct`, and `verify-infected-mask` labels a containment hit `exact`, `begins`
# or `contains`, with `truncation` added for the other direction. A twelfth position label
# means a predicate changed its vocabulary, which is how `sensitivity` and the decoded-form
# tags were both found - by somebody noticing rather than by anything asking.
FINDING_SHAPE = {
    "distinct_identifiers": "int",
    "occurrences": "int",
    "identifier_lengths": "ints",
    "segment_lengths": "ints",
    "kinds": {"domain", "acct"},
    "positions": {"exact", "begins", "contains", "truncation"},
    "methods": "strs",
    "note": "str",
    "false_positive_note": "str",
}


def findingShapeViolations(rows):
    """A gate finding records shapes and counts. It must not be able to record anything else.

    THE NOTE INSIDE EVERY FINDING MAKES A CLAIM AND NOTHING CHECKED IT
    -------------------------------------------------------------------
    `verify-content-mask.gate` attaches to each finding: *"identifier names deliberately not
    recorded here; they are the thing being masked"*. That sentence is generated onto seven
    blocks and published in the tracked index, and it is a claim about the FIELD rather than
    about the row it sits on - which is why two other published rows could use
    `encoded_layer_finding` to record an address while the index simultaneously asserted
    that identifiers are never recorded there. The claim was true of every block that
    carried it and false of the field, and nothing in the tree could tell the difference.

    Moving the adjudication out made the claim true again. This makes it CHECKED, which is
    the part that lasts: a finding may carry only the keys `_profile` emits, with the types
    it emits them at, so there is no key left in which a name could sit. It would have fired
    on both published rows before the move.

    The note itself was not corrected here for two rounds, and the price is recorded above
    rather than the omission being quiet: its second clause - *"they are the thing being
    masked"* - presumed the outcome these two rows exist to record, because an identifier
    this gate finds may equally be attacker infrastructure that is deliberately KEPT, which
    is what the adjudication concluded.

    **Paid on 2026-09-07.** The prose is in `corpus/finding-note.txt`, loaded by
    `corpus/finding_notes.py`, which is outside `TOOLS`; the five modules that hard-coded
    the note in their own fixtures now read it from there, and `finding_notes.py --inject`
    reports any that goes back to a literal. The estimate quoted here was 44,543 to 44,536
    published and 365 to 294 local. What happened: the published half did not move at all -
    all seven rows that estimate wrote off were reachable after all, six of them because a
    row recording `changes: 0` says its masked form IS its input - and the local half
    settled at 364, one row short, because `34bba99dae63`'s five clearances are keyed to
    finding digests and gate provenance that both moved. Re-signing those is a person's act
    and no tool's, so the row is `publishable: false` with its blockers recorded.
    """
    def wrong(key, value):
        want = FINDING_SHAPE[key]
        if want == "int":
            return not (isinstance(value, int) and not isinstance(value, bool))
        if want == "str":
            return not isinstance(value, str)
        if want == "ints":
            return not (isinstance(value, list)
                        and all(isinstance(v, int) and not isinstance(v, bool)
                                for v in value))
        if want == "strs":
            return not (isinstance(value, list)
                        and all(isinstance(v, str) for v in value))
        return not (isinstance(value, list) and all(v in want for v in value))

    out = []
    for r in rows:
        m = r.get("masking") or {}
        for container, prefix in ((m, ""), (m.get("gate_categories"), "gate_categories.")):
            if not isinstance(container, dict):
                continue
            for key in ("plaintext_finding", "encoded_layer_finding"):
                b = container.get(key)
                if b is None:
                    continue
                if not isinstance(b, dict):
                    out.append((r["sha256"], "masking.%s%s is %s, not an object"
                                % (prefix, key, type(b).__name__)))
                    continue
                extra = sorted(set(b) - set(FINDING_SHAPE))
                if extra:
                    # Named, not printed with its value: the whole reason a key outside the
                    # profile is a finding is that it might hold an identifier.
                    out.append((r["sha256"], "masking.%s%s carries %s, which no gate emits"
                                % (prefix, key, "/".join(extra))))
                    continue
                bad = sorted(k for k in b if wrong(k, b[k]))
                if bad:
                    out.append((r["sha256"], "masking.%s%s records %s at the wrong shape"
                                % (prefix, key, "/".join(bad))))
    return out


def iocValues(row):
    """The hosts a row declares it is keeping, as a list. Never None."""
    i = row.get("ioc")
    if not isinstance(i, dict):
        return []
    v = i.get("campaign_hosts")
    return v if isinstance(v, list) else []


# A host, and nothing else. No scheme, no path, no query, no whitespace, no uppercase: a
# domain or a bare IPv4. The point of the closed shape is not tidiness - it is that this is
# the one published field whose entire purpose is to carry identifiers verbatim, so the way
# it goes wrong is that something other than a host gets written into it.
IOC_HOST_RE = re.compile(r"^(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}"
                         r"|(?:\d{1,3}\.){3}\d{1,3})$")


def iocViolations(rows):
    """The kept-indicator block must say what it is keeping, and keep saying only that.

    `ioc`, `ioc.c2_fallback_ip` and `ioc.campaign_hosts` were orphans on two PUBLISHED
    rows. The block records the one class of identifier this corpus publishes on purpose,
    so the questions are: is it consistent with itself, is it consistent with the masker's
    own record, and is it still a list of hosts.

      * `c2_fallback_ip` must appear in `campaign_hosts`. A fallback the host list does not
        contain is a record disagreeing with itself.
      * every entry is host-shaped. A path, a URL or a sentence in this field would be an
        unmasked string published under a name that says it was meant to be.
      * a row with an `ioc` block must record `masking.c2_kept: true` and carry the `c2`
        tag. The block is the human-readable half of a decision the masker records as a
        boolean and the tagger as a tag; three records of one decision that can disagree
        is the shape §8 counts causes to avoid.
    """
    out = []
    for r in rows:
        i = r.get("ioc")
        if i is None:
            continue
        if not isinstance(i, dict):
            out.append((r["sha256"], "ioc is %s, not an object" % type(i).__name__))
            continue
        hosts = i.get("campaign_hosts")
        if not isinstance(hosts, list) or not hosts:
            out.append((r["sha256"], "ioc records no campaign_hosts list"))
            continue
        bad = [h for h in hosts
               if not isinstance(h, str) or not IOC_HOST_RE.match(h)]
        if bad:
            out.append((r["sha256"], "campaign_hosts holds a %d-character entry that is "
                                     "not host-shaped" % len(str(bad[0]))))
            continue
        fb = i.get("c2_fallback_ip")
        if fb is not None and fb not in hosts:
            out.append((r["sha256"], "c2_fallback_ip is not one of the campaign_hosts"))
            continue
        if (r.get("masking") or {}).get("c2_kept") is not True:
            out.append((r["sha256"], "declares kept indicators while masking.c2_kept is "
                                     "%r" % ((r.get("masking") or {}).get("c2_kept"),)))
            continue
        if "c2" not in set(r.get("sensitivity") or []):
            out.append((r["sha256"], "declares kept indicators and carries no c2 tag"))
    return out


HEX64 = re.compile(r"^[0-9a-f]{64}$")


def fixtureViolations(rows):
    """A generated fixture must describe the bytes it actually ships.

    Seven published rows carry a `fixture` block and eight of its keys were orphans. The
    block is the only record of what a shard ships where the shipped bytes are NOT the
    original sample, so an error in it is a published claim about bytes nobody can check.

      * `payload_size` < `fixture_size`. The payload is carried INSIDE the fixture.
      * `fixture_sha256` and `payload_sha256` are 64 hex and are different from each other.
        Equal would mean the carrier contributed nothing, which contradicts the block.
      * `sha256 == fixture_sha256` **iff** `size == fixture_size`. Three of the seven rows
        are their own fixture and four are not, and both are legitimate - but a row that is
        its own fixture by hash and not by size, or the reverse, is a half-updated record.
        Measured before arming: 7 of 7 agree in both directions.
      * `fixture.name == family`, on all 7.
    """
    out = []
    for r in rows:
        f = r.get("fixture")
        if f is None:
            continue
        if not isinstance(f, dict):
            out.append((r["sha256"], "fixture is %s, not an object" % type(f).__name__))
            continue
        fs, ps = f.get("fixture_size"), f.get("payload_size")
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (fs, ps)):
            out.append((r["sha256"], "fixture_size/payload_size are not both integers"))
            continue
        if ps >= fs:
            out.append((r["sha256"], "payload_size %d is not smaller than fixture_size %d"
                        % (ps, fs)))
            continue
        fh, ph = f.get("fixture_sha256"), f.get("payload_sha256")
        if not all(isinstance(x, str) and HEX64.match(x) for x in (fh, ph)):
            out.append((r["sha256"], "fixture_sha256/payload_sha256 are not both 64 hex"))
            continue
        if fh == ph:
            out.append((r["sha256"], "fixture and payload record the same hash"))
            continue
        if (fh == r.get("sha256")) != (fs == r.get("size")):
            out.append((r["sha256"], "the row is its own fixture by %s and not by %s"
                        % (("hash", "size") if fh == r.get("sha256") else ("size", "hash"))))
            continue
        if f.get("name") != r.get("family"):
            out.append((r["sha256"], "fixture.name does not match family"))
    return out


# ---------------------------------------------------------------------------
# The property this round exists to produce, asserted separately from the rule that
# produces it.
#
# `evaluate()` is supposed to make "publishable with zero blockers while holding a recorded
# FAIL" impossible. If that were the only statement of it, the rule and its guarantee would
# be the same code, and the guarantee would fail exactly when the rule did - which is what
# happened: `secret_gate: FAIL` on four publishable rows, recorded in the index for a round,
# with `--inject` green throughout because every one of its cases carried the `secret` tag
# the rule needed to look.
#
# So the invariant is re-derived here from the raw record and does not call `evaluate()`. It
# reads the gate fields, allows exactly what a valid clearance allows, and fails otherwise.
# A future edit that reintroduces a tag condition breaks this check without touching it.
# ---------------------------------------------------------------------------

def unreadFailures(rows):
    """Rows publishable - stored OR computed - holding a recorded non-pass nothing clears.

    Both directions, because they fail for different reasons and only one of them is about
    the rule. Computed-true is `evaluate()` having a blind spot. Stored-true is the FIELD
    being wrong while the rule is right, which is what a hand-edited `publishable` looks
    like and what `staleness()` catches from the other side. A downstream reader reads the
    field, so an invariant that only asked the rule would be an invariant about the wrong
    value.
    """
    out = []
    for r in rows:
        if not (evaluate(r)[0] or r.get("publishable") is True):
            continue
        m = r.get("masking") or {}
        for gate, _label in BYTE_GATES + (("detection_survived", "detection-parity"),):
            if gate not in m:
                continue
            if gate == "detection_survived":
                if m.get("not_applicable_reason"):
                    continue
                verdict, detail = gate_result(m[gate], boolean=True)
            else:
                verdict, detail = gate_result(m[gate])
            if verdict == "pass":
                continue
            c = clearance.applicable(r, gate)
            if c is None:
                out.append((r["sha256"], gate, verdict, detail))
    return out


def clearanceHygiene(rows):
    """(malformed, inert) - the two ways a recorded human decision stops being one.

    Malformed is an index defect and exits non-zero: a clearance nobody can read is a
    decision the record has lost. Inert is the mechanism working - the finding moved, or the
    provenance did - so it is reported with a count rather than failed on, because from a
    distance a clearance that has stopped applying looks exactly like one that still does.
    """
    bad, inert = [], []
    for r in rows:
        for c in clearance.row_clearances(r):
            why = clearance.malformed(c)
            if why:
                bad.append((r["sha256"], why))
                continue
            applies, why = clearance.applies(c, r, c["gate"])
            if not applies:
                inert.append((r["sha256"], c["gate"], why))
    return bad, inert

# ---------------------------------------------------------------------------
# The stored-vs-computed assertion. Everything above decides what a row IS; this
# decides whether the row's own copy of that answer still agrees.
# ---------------------------------------------------------------------------

def recompute(r):
    """Write the computed answer onto a row. The ONLY writer of these three fields."""
    ok, why = evaluate(r)
    r["publishable"] = ok
    if ok:
        r.pop("publish_blocker", None)
        r.pop("publish_blockers", None)
    else:
        # Keep every reason. Storing only the first overwrites the specific, actionable
        # blocker ("identifier inside an encoded layer") with the generic one ("verdict
        # is unreviewed"), and the accounting then cannot see it.
        r["publish_blockers"] = why
        r["publish_blocker"] = why[0]
    return ok, why


def staleness(rows):
    """Stored publishability against computed, in BOTH directions, plus blocker drift.

    Returns (over_claimed, under_claimed, blocker_drift). See the module docstring for
    why the second and third exist: the gate had only the first, and the first is the
    direction these rows did not drift in.

    Symmetry is the whole point, so neither branch may be written as the negation of the
    other's condition - each is stated positively and a row lands in exactly one.
    """
    over, under, drift = [], [], []
    for r in rows:
        ok, why = evaluate(r)
        stored = r.get("publishable") is True
        recorded = list(r.get("publish_blockers") or [])
        if stored and not ok:
            over.append((r["sha256"], why))
        elif ok and not stored:
            under.append((r["sha256"], recorded))
        elif not ok and recorded != why:
            drift.append((r["sha256"], recorded, why))
        elif ok and (recorded or r.get("publish_blocker") is not None):
            # Publishable and still carrying the blocker it was cleared of. Same class:
            # the boolean was updated and the reasons were not.
            drift.append((r["sha256"], recorded or [r["publish_blocker"]], []))
    return over, under, drift


def _report_staleness(over, under, drift, examples=2):
    """One printer, so no direction can be reported more quietly than another."""
    if over:
        print()
        print("=== STALE: %d row(s) claim publishable and are not ===" % len(over))
        byreason = collections.Counter()
        eg = collections.defaultdict(list)
        for sha, why in over:
            for w in why:
                byreason[w] += 1
                if len(eg[w]) < examples:
                    eg[w].append(sha[:12])
        for w, n in byreason.most_common():
            print("  %-70s %5d  e.g. %s" % (w[:70], n, ", ".join(eg[w])))
    if under:
        print()
        print("=== STALE: %d row(s) are publishable and do not say so ===" % len(under))
        print("  A review that changed a verdict or a sensitivity tag did not re-run this")
        print("  gate. The rows below still record blockers that have stopped being true,")
        print("  and everything downstream reads the record rather than the row.")
        byreason = collections.Counter()
        eg = collections.defaultdict(list)
        for sha, recorded in under:
            for w in (recorded or ["<no blocker recorded>"]):
                byreason[w] += 1
                if len(eg[w]) < examples:
                    eg[w].append(sha[:12])
        for w, n in byreason.most_common():
            print("  stale blocker: %-55s %5d  e.g. %s" % (w[:55], n, ", ".join(eg[w])))
    if drift:
        print()
        print("=== STALE: %d row(s) record the wrong blockers ===" % len(drift))
        print("  The boolean agrees and the reasons do not. §8's accounting is built out")
        print("  of the reasons, so this is a stale denominator even though nothing about")
        print("  publishability changed.")
        for sha, recorded, want in drift[:10]:
            print("  %s  recorded=%s" % (sha[:12], recorded))
            print("  %-12s  computed=%s" % ("", want))
        if len(drift) > 10:
            print("  ... and %d more" % (len(drift) - 10))


def main(path, apply_fix=False):
    rows = read_jsonl(path)
    over, under, drift = staleness(rows)
    stale = len(over) + len(under) + len(drift)

    print("rows                        :", len(rows))
    print("publishable, stored         :", sum(1 for r in rows if r.get("publishable") is True))
    print("publishable, computed       :", sum(1 for r in rows if evaluate(r)[0]))
    # Both counts, always, and never only the difference. A single "corrected: N" line is
    # what let fourteen rows be recomputed on every run and reported as routine.
    print("stale: over-claimed         :", len(over))
    print("stale: under-claimed        :", len(under))
    print("stale: blocker drift        :", len(drift))
    _report_staleness(over, under, drift)

    if apply_fix:
        for r in rows:
            recompute(r)
        left = staleness(rows)
        if any(left):
            # Recompute is idempotent by construction; if it is not, say so rather than
            # writing a file that still disagrees with the rule that produced it.
            sys.exit("refusing to write: %d row(s) still stale after recompute"
                     % sum(len(x) for x in left))

    # Always printed, never only when it is non-zero. "absent" and "stale" are one blocker
    # because the repair is the same, and they are two lines here because the diagnosis is
    # not: absent means nothing ever recorded what measured the row, stale means the tools
    # have moved since. A gate that reports only the blocker cannot tell you which.
    prov = collections.Counter()
    for r in rows:
        m = r.get("masking") or {}
        if m.get("applied"):
            prov[provenance_state(m)] += 1
    print("masked rows by gate provenance       :", dict(sorted(prov.items())))

    # Always printed. A count of human overrides that only appears when it is non-zero is a
    # count nobody is watching, and this is the one mechanism in the gate that can turn a
    # FAIL into a publishable row.
    cleared = collections.Counter()
    for r in rows:
        for g, _l in BYTE_GATES + (("detection_survived", "detection-parity"),):
            if clearance.applicable(r, g) is not None:
                cleared[g] += 1
    print("findings cleared by a human          :",
          dict(sorted(cleared.items())) if cleared else "none")
    badc, inert = clearanceHygiene(rows)
    print("clearances recorded but inert        :", len(inert))
    if inert:
        print()
        print("=== CLEARANCE: recorded, well formed, and clearing nothing ===")
        print("  Not a failure - a clearance is pinned to one finding measured by one set of")
        print("  tools, and both are allowed to move. It is printed because a clearance that")
        print("  has stopped applying reads, from a distance, exactly like one that has not.")
        for sha, gate, why in inert[:10]:
            print("  %s  %-20s %s" % (sha[:12], gate, why))
        if len(inert) > 10:
            print("  ... and %d more" % (len(inert) - 10))
    # Always printed, like the two above it. `reasoned_by` is not required to READ a
    # clearance - see clearance.REASONED_BY - so the only thing that can report its absence
    # is a count, and a count that appears only when it is non-zero is a count nobody
    # watches.
    unreasoned = [(r["sha256"], g, at) for r in rows for g, at in clearance.unreasoned(r)]
    print("clearances recording no reasoned_by  :", len(unreasoned))
    if unreasoned:
        print()
        print("=== CLEARANCE: no record of what produced the argument ===")
        print("  `by` is the authorising human and stays that. This is the second question -")
        print("  what drafted the reasoning they authorised - and the two superseded records")
        print("  here predate the field. A clearance written by hand would look the same.")
        for sha, gate, at in unreasoned[:10]:
            print("  %s  %-20s %s" % (sha[:12], gate, at))
        if len(unreasoned) > 10:
            print("  ... and %d more" % (len(unreasoned) - 10))
    print("clearances that cannot be read       :", len(badc))
    if badc:
        print()
        print("=== CLEARANCE: malformed, so a human decision has been lost ===")
        for sha, why in badc[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(badc) > 10:
            print("  ... and %d more" % (len(badc) - 10))

    unread = unreadFailures(rows)
    print("publishable rows holding an unread FAIL :", len(unread))
    if unread:
        print()
        print("=== INVARIANT: publishable while holding a recorded non-pass ===")
        print("  Re-derived from the record without calling evaluate(), so this fires even")
        print("  when the rule that is meant to prevent it does not. Five rows were in this")
        print("  state for a round: secret_gate FAIL, no secret tag, nothing looked.")
        for sha, gate, verdict, detail in unread[:10]:
            print("  %s  %-20s %-10s %s" % (sha[:12], gate, verdict, detail or ""))
        if len(unread) > 10:
            print("  ... and %d more" % (len(unread) - 10))

    bad = integrityViolations(rows)
    print("unreviewed rows asserting must_detect :", len(bad))
    if bad:
        print()
        print("=== INTEGRITY: expect.must_detect on a row with no review ===")
        for sha in bad[:10]:
            print("  %s" % sha[:12])
        if len(bad) > 10:
            print("  ... and %d more" % (len(bad) - 10))
        print("  move these to observed_detection; expect stays absent until a verdict is set")

    places = placementViolations(rows)
    print("rows whose placements disagree with count :", len(places))
    if places:
        print()
        print("=== INVARIANT: placements must account for every copy the row claims ===")
        print("  `placements` is written by a pass this repository does not track, and so is")
        print("  `count`, from the same list. Drift between them means that pass changed on")
        print("  one side only, and until this check existed nothing in the tree read either.")
        for sha, why in places[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(places) > 10:
            print("  ... and %d more" % (len(places) - 10))

    musts = mustDetectViolations(rows)
    print("rows asserting a rule their own scan did not match :", len(musts))
    if musts:
        print()
        print("=== INVARIANT: must_detect may not contradict detection_after_masking ===")
        print("  `detection_after_masking` is the published half's only record of what the")
        print("  scanner matched after masking - no published row carries `rules_after` - and")
        print("  it is what `expect.must_detect` was taken from. An assertion the row's own")
        print("  measurement contradicts is §11's must_detect-from-a-rescan, facing the other")
        print("  way.")
        for sha, why in musts[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(musts) > 10:
            print("  ... and %d more" % (len(musts) - 10))

    stages = stagingDirViolations(rows)
    print("rows whose staging_dir is not a single component :", len(stages))
    if stages:
        print()
        print("=== INVARIANT: staging_dir is a directory NAME, not a path ===")
        print("  67 of the 75 rows carrying it are published and nothing read it. The positive")
        print("  form is asserted rather than a hunt for host paths, so it needs no map.")
        for sha, why in stages[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(stages) > 10:
            print("  ... and %d more" % (len(stages) - 10))

    adjs = adjudicationViolations(rows)
    print("adjudications that are not auditable :", len(adjs))
    if adjs:
        print()
        print("=== INVARIANT: a human adjudication must be one somebody else could audit ===")
        print("  The block was living inside `encoded_layer_finding`, the key a clearance")
        print("  digest is taken over, so rewording the argument moved the digest. Moved to")
        print("  a field of its own; this is the reader that stops it drifting there again.")
        print("  An address it resolves to must be one the row DECLARES as a kept indicator -")
        print("  which is the c2-versus-customer distinction made structural, not assumed.")
        for sha, why in adjs[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(adjs) > 10:
            print("  ... and %d more" % (len(adjs) - 10))

    shapes = findingShapeViolations(rows)
    print("gate findings recording something no gate emits : %d" % len(shapes))
    if shapes:
        print()
        print("=== INVARIANT: a gate finding records shapes and counts, and nothing else ===")
        print("  Every finding carries a note saying identifier names are deliberately not")
        print("  recorded there. That was a claim about the field with nothing checking it,")
        print("  and two published rows were using the same field to record an address.")
        for sha, why in shapes[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(shapes) > 10:
            print("  ... and %d more" % (len(shapes) - 10))

    iocs = iocViolations(rows)
    print("rows whose kept indicators disagree with the row : %d" % len(iocs))
    if iocs:
        print()
        print("=== INVARIANT: the kept-indicator block is the one field that publishes an ===")
        print("=== identifier on purpose, so it must keep saying only that                ===")
        print("  `ioc`, `c2_fallback_ip` and `campaign_hosts` were orphans on two published")
        print("  rows. Three records of one decision - the block, `masking.c2_kept` and the")
        print("  `c2` tag - could disagree and nothing asked.")
        for sha, why in iocs[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(iocs) > 10:
            print("  ... and %d more" % (len(iocs) - 10))

    fixes = fixtureViolations(rows)
    print("fixtures that do not describe what they ship :", len(fixes))
    if fixes:
        print()
        print("=== INVARIANT: a generated fixture must describe the bytes it ships ===")
        print("  Eight of this block's keys were orphans on seven published rows, and where")
        print("  the shipped bytes are not the original sample this block is the only record")
        print("  of what a shard actually contains.")
        for sha, why in fixes[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(fixes) > 10:
            print("  ... and %d more" % (len(fixes) - 10))

    forms = formViolations(rows)
    print("rows whose masked component is malformed :", len(forms))
    if forms:
        print()
        print("=== FORM: site/server must be siteNN / srvNN ===")
        for sha, why in forms[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(forms) > 10:
            print("  ... and %d more" % (len(forms) - 10))

    leaks = publishedLeaks(rows) if os.path.basename(path) == "index.jsonl" else []
    if os.path.basename(path) == "index.jsonl":
        print("published rows leaking a host path   :", len(leaks))
    if leaks:
        print()
        print("=== PRIVACY: published rows must carry no host path ===")
        for sha, why in leaks[:10]:
            print("  %s  %s" % (sha[:12], why))
        if len(leaks) > 10:
            print("  ... and %d more" % (len(leaks) - 10))

    if apply_fix:
        # Atomic, and under the lock. This used to be open(path, "w"), which
        # truncates a 62 MB index before the first row lands - see indexio.
        write_jsonl_atomic(path, rows)
        print()
        print("wrote %s: %d row(s) recomputed" % (path, stale))

    # A --fix run that corrected something exits NON-ZERO, and that is deliberate. The
    # correction is not the result; the result is that the index was stale, which means
    # something upstream changed a verdict or a tag without re-running this gate. Exiting
    # zero there is how "publishable flags corrected: 14" became a line nobody read.
    # The green result is the plain run afterwards.
    return 1 if (stale or bad or leaks or forms or unread or badc or places
                 or musts or stages or adjs or iocs or fixes or shapes) else 0


# ---------------------------------------------------------------------------

def inject(path):
    """Positive control: prove each direction can actually say the other thing.

    The over-claimed direction had fired in anger (103 rows on this gate's first run) and
    the other two never had, which is the whole reason they were added blind. So every
    case below is constructed, run through the real `staleness()`, and asserted - and the
    negative half is as load-bearing as the positive one, because a checker that flags
    everything proves nothing about a corpus of 92,800 rows.

    A real row from `path` is used as the base wherever one is needed, so the control
    exercises the join against real data rather than a fixture of itself.
    """
    rows = read_jsonl(path)
    real = next((r for r in rows if r.get("publishable") is True), None) or rows[0]
    fails = []

    ran = []

    def case(label, row, want):
        over, under, drift = staleness([row])
        got = ("over" if over else "under" if under else "drift" if drift else "clean")
        ok = got == want
        ran.append(label)
        print("  %-56s %-6s %s" % (label, got, "ok" if ok else "WRONG (wanted %s)" % want))
        if not ok:
            fails.append(label)

    base = {"sha256": "0" * 64, "verdict": "malicious", "sensitivity": ["c2"]}

    print("=== positive controls: each must be reported, in the RIGHT class ===")
    # 1. over-claimed: the direction the gate already had.
    case("stored true, verdict still unreviewed",
         dict(base, verdict="unreviewed", publishable=True), "over")
    case("stored true, carries pii",
         dict(base, sensitivity=["pii"], publishable=True), "over")
    # 2. under-claimed: the fourteen. This is the direction that was invisible.
    case("reviewed c2 row still stored false (the fourteen)",
         dict(base, publishable=False,
              publish_blocker="verdict is unreviewed: nothing leaves that state without a human",
              publish_blockers=["verdict is unreviewed: nothing leaves that state without a human",
                                "sensitivity not yet assessed"]), "under")
    case("stored false with no blocker recorded at all",
         dict(base, publishable=False), "under")
    case("field absent entirely: the gate has never run on this row",
         dict(base), "under")
    # 3. blocker drift: boolean right, reasons wrong.
    case("unpublishable for a reason other than the one recorded",
         dict(base, verdict="unreviewed", publishable=False,
              publish_blocker="carries pii, which is not maskable and is never published",
              publish_blockers=["carries pii, which is not maskable and is never published"]),
         "drift")
    case("second blocker appeared and was never recorded",
         dict(base, verdict="unreviewed", sensitivity=["unreviewed"], publishable=False,
              publish_blocker="verdict is unreviewed: nothing leaves that state without a human",
              publish_blockers=["verdict is unreviewed: nothing leaves that state without a human"]),
         "drift")
    case("publishable but still carrying a cleared blocker",
         dict(base, publishable=True, publish_blocker="sensitivity not yet assessed",
              publish_blockers=["sensitivity not yet assessed"]), "drift")
    # 4. the secret gate. The other three masking gates pass on both rows below, so each
    # case isolates the secret rule and nothing else: if the rule is absent, both are
    # reported "clean" and this suite fails, which is what it is for.
    NOW = gate_provenance.stamp(PROV_MAPS)
    # Every masked fixture carries current provenance, so a case about the secret rule
    # fails for the secret rule and not for the provenance one. Without this the two
    # positive secret cases would still read "over" - for the wrong reason - which is a
    # control that passes while measuring something else.
    MASKED = {"applied": True, "plaintext_gate": "PASS", "encoded_layer_gate": "PASS",
              "detection_survived": True, "provenance": NOW}
    case("secret row, masking applied, no secret_gate recorded",
         dict(base, sensitivity=["c2", "secret"], publishable=True, masking=dict(MASKED)),
         "over")
    case("secret row, masking applied, secret_gate FAIL",
         dict(base, sensitivity=["c2", "secret"], publishable=True,
              masking=dict(MASKED, secret_gate="FAIL")), "over")
    # 4b. The same FAIL on a row that does NOT carry the tag. This is the case the armed
    # rule could not see: five rows recorded `secret_gate: FAIL` and none was tagged
    # `secret`, so the rule never looked, and four were publishable with zero blockers.
    # Three of them were tagged `clean` alone, which is in ALWAYS_OK, so `unmasked` was
    # empty and the whole masking branch was skipped as well - two independent tag
    # conditions between a recorded credential failure and a shard.
    case("secret_gate FAIL on a row tagged clean alone (the four)",
         dict(base, sensitivity=["clean"], publishable=True,
              masking=dict(MASKED, secret_gate="FAIL")), "over")
    case("secret_gate FAIL on a c2/identity row that never claimed secret",
         dict(base, sensitivity=["c2", "identity"], publishable=True,
              masking=dict(MASKED, secret_gate="FAIL")), "over")
    case("plaintext FAIL on a row tagged c2 alone",
         dict(base, sensitivity=["c2"], publishable=True,
              masking=dict(MASKED, plaintext_gate="FAIL")), "over")

    # 4c. The four ways a gate value can fail to be a pass. Every one must block, and each
    # must block for its OWN reason: the repair for a FAIL is a human decision, for a SKIP
    # it is to run the gate, and for a value nobody recognises it is to find out what wrote
    # it. Six rows store the encoded verdict as a DICT carrying `result: FAIL` - a schema
    # older than every tool in the tree - and twelve store the string `SKIPPED-oversize`.
    DICTFAIL = {"result": "FAIL", "distinct_identifiers": 2, "occurrences": 26,
                "kinds": ["acct", "dom"]}
    for label, value, want_word in (
            ("string FAIL", "FAIL", "did not pass"),
            ("dict FAIL, the older schema", DICTFAIL, "did not pass"),
            ("SKIPPED: a gate that never ran", "SKIPPED-oversize (>1MB)", "was not run"),
            ("a bare boolean nobody wrote on purpose", True, "not a recognised verdict"),
            ("a dict with no recognised result", {"occurrences": 3}, "not a recognised verdict"),
            ("a list", ["FAIL"], "not a recognised verdict")):
        row = dict(base, sensitivity=["clean"], publishable=True,
                   masking=dict(MASKED, encoded_layer_gate=value))
        _ok, why = evaluate(row)
        got = "blocks (%s)" % want_word if any(want_word in w for w in why) else \
              ("blocks, wrong reason: %s" % why if why else "CLEARS")
        ran.append("encoded gate value: " + label)
        print("  %-56s %-6s %s" % ("encoded gate value: " + label, "",
                                   "ok" if got.startswith("blocks (") else "WRONG: " + got))
        if not got.startswith("blocks ("):
            fails.append("encoded gate value: " + label)
    # Detection parity, strictly. A truthiness test reads the string "no" as a pass.
    case("detection_survived recorded as a non-boolean",
         dict(base, sensitivity=["clean"], publishable=True,
              masking=dict(MASKED, detection_survived="no")), "over")
    case("detection_survived false where masking DID run",
         dict(base, sensitivity=["clean"], publishable=True,
              masking=dict(MASKED, detection_survived=False)), "over")
    # The other half of the not-applicable rule: its BYTE gates are still read, so a SKIPPED
    # encoded layer on an archive container blocks. Two such rows are held today by nothing
    # but a `local_only` marker, which is the "blocked by coincidence" shape exactly.
    case("not-applicable row: a SKIPPED encoded layer still blocks",
         dict(base, sensitivity=["clean"], publishable=True,
              masking={"applied": False,
                       "not_applicable_reason": "a genuine tar container (5.5)",
                       "plaintext_gate": "PASS", "detection_survived": False,
                       "encoded_layer_gate": "SKIPPED-oversize (>1MB)"}), "over")

    # 5. gate provenance. A recorded verdict is a claim about what some version of the
    # gate said; until this round nothing recorded which version, and 5 of 95 local rows
    # and 1 of 8 published rows were sitting at PASS under a predicate since tightened.
    PASSING = {"applied": True, "plaintext_gate": "PASS", "encoded_layer_gate": "PASS",
               "detection_survived": True}
    case("every gate passes but nothing records what measured them",
         dict(base, sensitivity=["c2", "identity"], publishable=True,
              masking=dict(PASSING)), "over")
    case("every gate passes, provenance is from superseded tools",
         dict(base, sensitivity=["c2", "identity"], publishable=True,
              masking=dict(PASSING, provenance={"tools": "0" * 12, "map": None})), "over")

    # 5b. The credential-literal count going UP. The gate was differential in one direction
    # only and one row sat at 23-against-22 for a round with nothing asking. Both halves of
    # the split are exercised, and so is the double-count: where the population is
    # comparable the gate has already returned FAIL and this reason must stay silent, or one
    # cause acquires two reasons and §8's denominator goes out again.
    def sl(**kw):
        d = {"secret_literals_before": 22, "secret_literals_after": 23,
             "secret_literals_carried_over": 0, "secret_literals_added": 1,
             "secret_literals_added_by_the_masker": 0,
             "secret_literals_added_unattributed": 1,
             "decoded_layers_before": 23, "decoded_layers_after": 16,
             "literal_population_comparable": False}
        d.update(kw)
        return d

    row = dict(base, sensitivity=["clean"], publishable=True,
               masking=dict(MASKED, secret_gate="PASS", secret_literals=sl()))
    _ok, why = evaluate(row)
    hit = [w for w in why if "more credential-shaped literals" in w]
    ran.append("more literals out than in, over a population that moved")
    print("  %-56s %-6s %s" % ("more literals out than in, over a moved population", "",
                               "ok" if len(hit) == 1 else "WRONG: %s" % why))
    if len(hit) != 1:
        fails.append("more literals out than in, over a population that moved")

    for label, block, want in (
            ("the count went DOWN over a moved population",
             sl(secret_literals_after=21), 0),
            ("the count held over a moved population - 11 masked in, 11 out",
             sl(secret_literals_before=11, secret_literals_after=11,
                secret_literals_added=11, secret_literals_added_by_the_masker=11,
                secret_literals_added_unattributed=0), 0),
            ("an increase over a COMPARABLE population: the gate owns it, one reason only",
             sl(literal_population_comparable=True), 0),
            ("a row that records no secret_literals block at all", None, 0)):
        m2 = dict(MASKED, secret_gate="PASS")
        if block is not None:
            m2["secret_literals"] = block
        _ok, why = evaluate(dict(base, sensitivity=["clean"], publishable=True, masking=m2))
        n = len([w for w in why if "more credential-shaped literals" in w])
        ran.append("silent: " + label)
        print("  %-56s %-6s %s" % ("silent: " + label[:54], "",
                                   "ok" if n == want else "WRONG: fired %d time(s)" % n))
        if n != want:
            fails.append("silent: " + label)

    print()
    print("=== negative controls: each must be SILENT ===")
    case("a consistent publishable row", dict(base, publishable=True), "clean")
    case("a consistent blocked row, every reason recorded",
         dict(base, verdict="unreviewed", sensitivity=["unreviewed"], publishable=False,
              publish_blocker="verdict is unreviewed: nothing leaves that state without a human",
              publish_blockers=["verdict is unreviewed: nothing leaves that state without a human",
                                "sensitivity not yet assessed"]), "clean")
    case("secret row, masking applied, secret_gate PASS",
         dict(base, sensitivity=["c2", "secret"], publishable=True,
              masking=dict(MASKED, secret_gate="PASS")), "clean")
    # The double-counting control, and the reason the rule sits inside the `applied`
    # branch. This row is blocked for exactly ONE cause and records exactly one reason. A
    # secret rule written outside that branch would add a second reason for the same cause,
    # the recorded list would no longer equal the computed one, and this case would report
    # "drift" instead of "clean" - which is the 14-row tally drift, reproduced in a fixture.
    case("secret row, no masking applied: ONE blocker for one cause",
         dict(base, sensitivity=["c2", "secret"], publishable=False,
              masking={"applied": False,
                       "not_applicable_reason": "a genuine tar container (5.5)"},
              publish_blocker="carries secret but no masking has been applied",
              publish_blockers=["carries secret but no masking has been applied"]), "clean")
    case("every gate passes and the current tools measured them",
         dict(base, sensitivity=["c2", "identity"], publishable=True,
              masking=dict(PASSING, provenance=NOW)), "clean")
    # Provenance is asked only where the gate verdicts are read. A row with no masking
    # applied is blocked once, for one cause, and must not collect a second reason - the
    # 14-row tally drift, in its third possible form.
    case("no masking applied: provenance is not a second blocker",
         dict(base, sensitivity=["c2", "identity"], publishable=False,
              masking={"applied": False, "not_applicable_reason": "a container"},
              publish_blocker="carries identity but no masking has been applied",
              publish_blockers=["carries identity but no masking has been applied"]),
         "clean")
    # `not_applicable_reason` is the one thing that says a masking block records a DECISION
    # rather than measurements, and the only field it disqualifies is detection parity. All
    # 29 archive-container rows store `detection_survived: false` as a placeholder for a
    # measurement nobody took; reading it as "masking destroyed detection" would attribute 29
    # rows to a cause that never happened, which §8 forbids more specifically than it forbids
    # missing one. The BYTE gates on the same row are still read - a SKIPPED encoded layer
    # there is a real "nothing gated these bytes", and two such rows are held today by
    # nothing but a `local_only` marker.
    NA = {"applied": False, "not_applicable_reason": "a genuine tar container (5.5)",
          "plaintext_gate": "PASS", "detection_survived": False}
    case("not-applicable row: detection_survived false is not a blocker",
         dict(base, sensitivity=["clean"], publishable=True,
              masking=dict(NA, encoded_layer_gate="PASS")), "clean")

    r = json.loads(json.dumps(real))
    case("a real row from %s, untouched" % os.path.basename(path), r, "clean")

    # ---------------------------------------------------------------------------------
    # The clearance mechanism. It is an escape hatch in a publish gate, so it gets a
    # control per constraint and the negative half of each: a hatch that never opens is as
    # useless as one that never shuts, and only the pair proves which this is.
    # ---------------------------------------------------------------------------------
    print()
    print("=== the human clearance: each constraint, and that it can still open ===")
    FIND = {"distinct_identifiers": 1, "occurrences": 1, "identifier_lengths": [6],
            "positions": ["begins"], "segment_lengths": [25]}
    FAILED = dict(MASKED, encoded_layer_gate="FAIL", encoded_layer_finding=dict(FIND))

    def signed(masking, gate="encoded_layer_gate", **over):
        """What `clear-finding.py` would write for this row, at this moment.

        The provenance is taken FROM the masking block rather than from `NOW`, because that
        is what the writer does. An earlier version of this helper hardcoded the current
        stamp, which quietly turned "re-judged after the tools moved" into "judged against
        tools the row does not carry" - a control that passed for the wrong reason, caught
        by pairing it with the positive it is supposed to contrast with.
        """
        prov = masking.get("provenance") or {}
        c = {"gate": gate,
             "finding_digest": clearance.finding_digest(masking, gate),
             "by": "cl", "at": "2026-09-06T12:00:00",
             "reason": "read in context; a collision, described by shape",
             "gate_provenance": {"tools": prov.get("tools"), "map": prov.get("map")}}
        c.update(over)
        return c

    def blocks_on(row, needle="encoded-layer gate did not pass"):
        return any(needle in w for w in evaluate(row)[1])

    def ccase(label, got, want):
        ok = got == want
        ran.append(label)
        print("  %-62s %-9s %s" % (label, got, "ok" if ok else "WRONG (wanted %s)" % want))
        if not ok:
            fails.append(label)

    row_uncleared = dict(base, sensitivity=["c2", "identity"], masking=dict(FAILED))
    ccase("without a clearance the finding blocks",
          "blocks" if blocks_on(row_uncleared) else "clears", "blocks")

    row_cleared = dict(row_uncleared, clearances=[signed(FAILED)])
    ccase("a signed clearance clears exactly that finding",
          "blocks" if blocks_on(row_cleared) else "clears", "clears")
    ccase("and publishable is COMPUTED, not written",
          "computed true" if evaluate(row_cleared)[0] else "still blocked", "computed true")

    # Keyed to the finding. Re-measurement that changes the evidence must not inherit the
    # judgement: what was read was a 6-character label in a 25-character segment, and a
    # different profile is a different question.
    #
    # Each negative below is PAIRED with the positive that re-signs the same judgement
    # against the new state. Without the pair, "blocks" proves only that something blocked,
    # and a clearance mechanism that never clears anything would pass every one of them.
    moved = dict(FAILED, encoded_layer_finding=dict(FIND, identifier_lengths=[12],
                                                    positions=["exact"]))
    ccase("the same clearance against a CHANGED finding",
          "blocks" if blocks_on(dict(row_uncleared, masking=moved,
                                     clearances=[signed(FAILED)])) else "clears", "blocks")
    ccase("  ... and re-signed against the changed finding it clears",
          "blocks" if blocks_on(dict(row_uncleared, masking=moved,
                                     clearances=[signed(moved)])) else "clears", "clears")
    # And it must not carry to a different gate on the same row, which is the same
    # constraint in the axis a digest-per-row would have missed.
    two_bad = dict(FAILED, plaintext_gate="FAIL")
    ccase("a clearance for the encoded gate does not clear the plaintext one",
          "blocks" if any("plaintext gate did not pass" in w for w in
                          evaluate(dict(row_uncleared, masking=two_bad,
                                        clearances=[signed(two_bad)]))[1])
          else "clears", "blocks")
    ccase("  ... and a clearance for the plaintext gate does",
          "blocks" if any("plaintext gate did not pass" in w for w in
                          evaluate(dict(row_uncleared, masking=two_bad,
                                        clearances=[signed(two_bad),
                                                    signed(two_bad, gate="plaintext_gate")]))[1])
          else "clears", "clears")

    # Invalidated when the provenance moves. A clearance is a judgement about what a
    # particular gate said, and a changed gate has not been judged - even when the recorded
    # profile happens to come out the same, which is why this is pinned by value and not
    # inferred from the digest.
    stale_prov = dict(FAILED, provenance={"tools": "0" * 12, "map": NOW["map"]})
    ccase("the tools digest moved since the judgement",
          "blocks" if blocks_on(dict(row_uncleared, masking=stale_prov,
                                     clearances=[signed(FAILED)])) else "clears", "blocks")
    ccase("the map digest moved since the judgement",
          "blocks" if blocks_on(dict(row_uncleared, masking=dict(FAILED),
                                     clearances=[signed(FAILED,
                                                        gate_provenance={"tools": NOW["tools"],
                                                                         "map": "0" * 12})]))
          else "clears", "blocks")
    ccase("  ... and re-judged against the moved tools it clears again",
          "blocks" if blocks_on(dict(row_uncleared, masking=stale_prov,
                                     clearances=[signed(stale_prov)])) else "clears",
          "clears")

    # §7.2: pii and content are never publishable by any route, and this is a route.
    for tag in ("pii", "content"):
        ccase("a clearance on a row carrying %s clears nothing" % tag,
              "blocks" if blocks_on(dict(row_uncleared, sensitivity=["c2", tag],
                                         clearances=[signed(FAILED)])) else "clears",
              "blocks")
    ccase("clearance.NEVER_CLEARABLE_TAGS still equals the gate's NEVER",
          "equal" if set(clearance.NEVER_CLEARABLE_TAGS) == NEVER else "DIVERGED", "equal")

    # A cleared finding must not clear the row. This is the difference between an escape
    # hatch and an override.
    ccase("a second, uncleared blocker survives the clearance",
          "blocked" if not evaluate(dict(row_cleared, verdict="unreviewed"))[0]
          else "PUBLISHABLE", "blocked")

    # Malformed is an index defect, not a quiet skip.
    for label, over in (("no author", {"by": ""}),
                        ("no reason", {"reason": "  "}),
                        ("no provenance", {"gate_provenance": {}}),
                        ("a gate that is not a finding", {"gate": "pii"})):
        bad, _inert = clearanceHygiene([dict(row_uncleared, clearances=[signed(FAILED, **over)])])
        ccase("malformed clearance reported: %s" % label,
              "reported" if bad else "SILENT", "reported")
    bad, inert = clearanceHygiene([dict(row_uncleared, masking=stale_prov,
                                        clearances=[signed(FAILED)])])
    ccase("a clearance that has gone inert is reported as inert",
          "inert" if (inert and not bad) else "WRONG", "inert")

    # The invariant, separately from the rule. This is the check that would have caught the
    # five rows while `evaluate()` was still blind, so it must fire on a row `evaluate()`
    # is happy with - which means constructing one where the rule is wrong on purpose.
    ccase("unreadFailures sees a stored-true row with a recorded FAIL",
          "sees" if unreadFailures([dict(base, sensitivity=["clean"], publishable=True,
                                         masking=dict(MASKED, secret_gate="FAIL"))])
          else "BLIND", "sees")
    ccase("unreadFailures is silent on a properly cleared row",
          "silent" if not unreadFailures([row_cleared]) else "FIRES", "silent")
    ccase("unreadFailures is silent on a row whose gates all pass",
          "silent" if not unreadFailures([dict(base, sensitivity=["clean"], publishable=True,
                                               masking=dict(MASKED, secret_gate="PASS"))])
          else "FIRES", "silent")

    # A --fix that can invent a human decision is not a --fix. `recompute()` writes three
    # fields and this asserts it writes no fourth.
    r_nofix = dict(row_uncleared)
    recompute(r_nofix)
    ccase("recompute() cannot manufacture a clearance",
          "none" if not clearance.row_clearances(r_nofix) else "MANUFACTURED", "none")

    print()
    print("=== recompute() is what --fix writes: it must clear every class ===")
    made = [dict(base, verdict="unreviewed", publishable=True),
            dict(base, publishable=False,
                 publish_blockers=["verdict is unreviewed: nothing leaves that state "
                                   "without a human"]),
            dict(base, verdict="unreviewed", publishable=False,
                 publish_blocker="carries pii, which is not maskable and is never published",
                 publish_blockers=["carries pii, which is not maskable and is never published"])]
    before = sum(len(x) for x in staleness(made))
    for r in made:
        recompute(r)
    after = sum(len(x) for x in staleness(made))
    ok = before == 3 and after == 0
    ran.append("recompute clears every class")
    print("  %-56s %s" % ("3 stale rows in, 0 out",
                          "ok" if ok else "WRONG: before=%d after=%d" % (before, after)))
    if not ok:
        fails.append("recompute does not clear staleness")

    # And the control on the control: the whole file, unmodified, must be clean or the
    # cases above are being read against a corpus that is already failing.
    over, under, drift = staleness(rows)
    print()
    print("index examined                : %s" % path)
    print("rows examined                 : %d" % len(rows))
    print("stale rows found in it        : over=%d under=%d drift=%d"
          % (len(over), len(under), len(drift)))
    print()
    # 6. placements against count. Both directions: this invariant has never fired in
    # anger - it was written over a population that already satisfies it on all 33,555 rows
    # - which is precisely the condition AGENTS.md names as "not yet a check".
    print("=== placements: the histogram must account for every copy claimed ===")

    def pcase(label, row, want_hit):
        got = placementViolations([row])
        ok = bool(got) == want_hit
        ran.append(label)
        print("  %-56s %-6s %s" % (label, "hit" if got else "clean",
                                   "ok" if ok else "WRONG (wanted %s)"
                                   % ("hit" if want_hit else "clean")))
        if not ok:
            fails.append(label)

    GOOD = {"live webroot: plugin or theme directory": 3, "IR quarantine copy": 1}
    pcase("placements summing to count", dict(base, placements=dict(GOOD), count=4), False)
    pcase("the same total under the older copies_on_disk name",
          dict(base, placements=dict(GOOD), copies_on_disk=4), False)
    pcase("no placements at all: not this check's business",
          dict(base, count=9), False)
    pcase("placements summing to one less than count",
          dict(base, placements=dict(GOOD), count=5), True)
    pcase("placements summing to one more than count",
          dict(base, placements=dict(GOOD), count=3), True)
    pcase("a histogram with no total recorded anywhere",
          dict(base, placements=dict(GOOD)), True)
    pcase("a label outside the closed vocabulary",
          dict(base, placements={"somewhere new nobody declared": 4}, count=4), True)
    pcase("placements recorded as a list",
          dict(base, placements=["live webroot: other"], count=1), True)
    pcase("a count that is a bool rather than an int",
          dict(base, placements={"other": True}, count=1), True)

    print()
    # 7. two orphan fields given a reader. Neither invariant has ever fired: both were
    # written over populations that already satisfy them (6 of 6, and 75 of 75), which is
    # the condition AGENTS.md names as "not yet a check", so both directions are asserted
    # here rather than inferred from a green run.
    print("=== must_detect may not contradict the row's own post-masking scan ===")

    def mcase(label, row, want_hit):
        got = mustDetectViolations([row])
        ok = bool(got) == want_hit
        ran.append(label)
        print("  %-56s %-6s %s" % (label, "hit" if got else "clean",
                                   "ok" if ok else "WRONG (wanted %s)"
                                   % ("hit" if want_hit else "clean")))
        if not ok:
            fails.append(label)

    mcase("must_detect exactly what the scan recorded",
          dict(base, expect={"must_detect": ["BD012"]},
               masking={"detection_after_masking": ["BD012"]}), False)
    mcase("a scan that matched MORE than must_detect asserts",
          dict(base, expect={"must_detect": ["BD012"]},
               masking={"detection_after_masking": ["BD012", "EXP006"]}), False)
    mcase("a known miss: nothing asserted, nothing matched",
          dict(base, expect={"must_detect": []},
               masking={"detection_after_masking": []}), False)
    mcase("no detection_after_masking at all: not this check's business",
          dict(base, expect={"must_detect": ["BD012"]}, masking={}), False)
    mcase("must_detect asserts a rule the scan did not match",
          dict(base, expect={"must_detect": ["BD012"]},
               masking={"detection_after_masking": ["EXP006"]}), True)
    mcase("must_detect asserts a rule against an empty scan",
          dict(base, expect={"must_detect": ["BD012"]},
               masking={"detection_after_masking": []}), True)
    mcase("detection_after_masking recorded as a string",
          dict(base, expect={"must_detect": []},
               masking={"detection_after_masking": "BD012"}), True)

    print()
    print("=== staging_dir is a directory NAME, and the positive form says so ===")

    def scase(label, value, want_hit):
        got = stagingDirViolations([dict(base, staging_dir=value)])
        ok = bool(got) == want_hit
        ran.append(label)
        print("  %-56s %-6s %s" % (label, "hit" if got else "clean",
                                   "ok" if ok else "WRONG (wanted %s)"
                                   % ("hit" if want_hit else "clean")))
        if not ok:
            fails.append(label)

    scase("an ordinary attacker directory name", "woo-paypal-stripe-gateway-wtC8pc", False)
    scase("a short lowercase name", "acajapa", False)
    scase("a name with a dot in it", "wp-admin.bak", False)
    ran.append("no staging_dir at all: not this check's business")
    none_hit = bool(stagingDirViolations([dict(base)]))
    print("  %-56s %-6s %s" % ("no staging_dir at all: not this check's business",
                               "hit" if none_hit else "clean", "ok" if not none_hit else "WRONG"))
    if none_hit:
        fails.append("no staging_dir at all: not this check's business")
    scase("a host path", "/home/acct01/public_html", True)
    scase("a home path with a digit suffix on /home", "/home2/acct01", True)
    scase("a bare traversal element", "..", True)
    scase("a windows-style path", "C:\\wwwroot\\site", True)
    scase("a name with a slash anywhere in it", "wp-content/uploads", True)
    scase("an empty string", "", True)
    scase("a value that is not a string at all", ["dir"], True)

    print()
    # 8. a recorded decision must carry its resolution. The population is TWO rows, both
    # resolved, so this rule has never fired and cannot fire on today's corpus. These cases
    # are not a supplement to a live result - they are the whole of it.
    print("=== a decision that says it holds the row must say it was resolved ===")

    def dcase(label, masking, want_hit):
        row = dict(base, masking=masking)
        _ok, why = evaluate(row)
        hit = [w for w in why if "records a decision with no resolution" in w]
        got = bool(hit)
        ok = got == want_hit
        ran.append(label)
        print("  %-56s %-6s %s" % (label, "blocks" if got else "clean",
                                   "ok" if ok else "WRONG (wanted %s)"
                                   % ("blocks" if want_hit else "clean")))
        if not ok:
            fails.append(label)
        return why

    HELD = "held for human confirmation; not published until resolved"
    RESOLVED = {"resolution": "attacker-owned; kept as an IOC", "method": "read locally"}
    masked_ok = dict(MASKED)
    dcase("a decision with a resolution beside it",
          dict(masked_ok, encoded_layer_finding={"decision": HELD,
                                                 "resolution": dict(RESOLVED)}), False)
    dcase("the same decision with no resolution",
          dict(masked_ok, encoded_layer_finding={"decision": HELD}), True)
    dcase("a resolution recorded as empty",
          dict(masked_ok, encoded_layer_finding={"decision": HELD, "resolution": {}}), True)
    dcase("a resolution and no decision: not this check's business",
          dict(masked_ok, encoded_layer_finding={"resolution": dict(RESOLVED)}), False)
    dcase("an ordinary finding with neither",
          dict(masked_ok, encoded_layer_finding={"occurrences": 3}), False)
    dcase("a decision recorded under gate_categories, the other place findings live",
          dict(masked_ok, gate_categories={"plaintext_finding": {"decision": HELD}}), True)
    dcase("and there with its resolution",
          dict(masked_ok, gate_categories={"plaintext_finding": {"decision": HELD,
                                                                 "resolution": "done"}}),
          False)
    # §8: one cause, one reason. A row already blocked for something else must gain exactly
    # one more, not two, and the existing blockers must be untouched.
    both = dcase("a row already blocked elsewhere gains exactly one reason",
                 dict(masked_ok, encoded_layer_gate="FAIL",
                      encoded_layer_finding={"decision": HELD}), True)
    n = len([w for w in both if "records a decision with no resolution" in w])
    ran.append("exactly one decision reason")
    print("  %-56s %-6s %s" % ("and exactly one, not one per place it looked", n,
                               "ok" if n == 1 else "WRONG (wanted 1)"))
    if n != 1:
        fails.append("exactly one decision reason")
    # Not clearable, asserted rather than assumed: only a recorded gate result is a finding.
    ran.append("a decision blocker is not a clearable finding")
    not_clearable = DECISION not in clearance.CLEARABLE_GATES
    print("  %-56s %-6s %s" % ("a decision is not in CLEARABLE_GATES",
                               "yes" if not_clearable else "no",
                               "ok" if not_clearable else "WRONG"))
    if not not_clearable:
        fails.append("a decision blocker is not a clearable finding")
    # And the live census, which is a statement about the population and not a pass: the
    # rule fires on nothing today, and two rows carry a decision for it to fire on.
    carriers = [r for r in rows if _decision_blocks(r.get("masking") or {})]
    unresolved = [r for r in carriers
                  if any(not b.get("resolution")
                         for _n, b in _decision_blocks(r.get("masking") or {}))]
    print("  rows carrying a recorded decision : %d" % len(carriers))
    print("  of those, unresolved              : %d   (the population this rule has ever "
          "had to act on)" % len(unresolved))

    print()
    # 9. the adjudication, now that it has a field of its own. Population TWO, both valid,
    # so this rule has never fired either - every case below is constructed.
    print("=== a human adjudication must be one somebody else could audit ===")

    ADJ = {"about": "encoded_layer_gate",
           "classification": "ambiguous between c2 and identity",
           "decision": HELD,
           "resolution": {"resolution": "attacker-owned; kept as an IOC",
                          "address": "203.0.113.7"},
           "value": "an address inside an encoded layer",
           "why_it_matters": "masking cannot reach inside an encoded layer"}
    # The address in the fixture is a documentation-range literal, never a real one: this
    # suite is a tracked file, and the rule about not spelling identifiers into git does not
    # stop being true because the identifier in the live row happens to be attacker-owned.
    IOC = {"c2_fallback_ip": "203.0.113.7",
           "campaign_hosts": ["203.0.113.7", "c.example-campaign.xyz"]}

    def acase(label, row, want_hit):
        got = adjudicationViolations([row])
        ok = bool(got) == want_hit
        ran.append(label)
        print("  %-60s %-6s %s" % (label, "hit" if got else "clean",
                                   "ok" if ok else "WRONG (wanted %s)"
                                   % ("hit" if want_hit else "clean")))
        if not ok:
            fails.append(label)

    def arow(adj=None, **kw):
        m = dict(MASKED)
        if adj is not None:
            m[ADJUDICATION] = adj
        r = dict(base, masking=m, ioc=dict(IOC))
        r.update(kw)
        return r

    acase("a complete adjudication whose address the row declares", arow(dict(ADJ)), False)
    acase("no adjudication at all: not this check's business", arow(), False)
    acase("a resolution that records no address", arow(
        dict(ADJ, resolution={"resolution": "attacker-owned"})), False)
    for k in ADJUDICATION_REQUIRED:
        acase("missing %s" % k, arow({kk: vv for kk, vv in ADJ.items() if kk != k}), True)
    acase("a key that is not adjudication shape",
          arow(dict(ADJ, occurrences=3)), True)
    acase("about names a gate the row does not record",
          arow(dict(ADJ, about="secret_gate")), True)
    # THE ONE THAT MATTERS: an address adjudicated as attacker infrastructure that the row
    # never declared it was keeping. Both directions, because a rule that fired on every
    # address would make the field unusable and one that fired on none is not a rule.
    acase("resolves to an address the row does NOT declare as kept",
          arow(dict(ADJ, resolution={"resolution": "attacker-owned",
                                     "address": "198.51.100.9"})), True)
    acase("the same row with that address declared",
          dict(arow(dict(ADJ, resolution={"resolution": "attacker-owned",
                                          "address": "198.51.100.9"})),
               ioc={"c2_fallback_ip": "198.51.100.9",
                    "campaign_hosts": ["198.51.100.9"]}), False)
    acase("an adjudication on a row with no ioc block at all",
          dict(arow(dict(ADJ)), ioc=None), True)
    acase("recorded as a string rather than a block",
          arow("attacker-owned, kept"), True)
    # The tie to the mover, asserted rather than restated in two places.
    ran.append("the adjudication shape matches lift-adjudication's")
    import importlib.util
    _lspec = importlib.util.spec_from_file_location(
        "lift_adj_probe", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "lift-adjudication.py"))
    _lift = importlib.util.module_from_spec(_lspec)
    _lspec.loader.exec_module(_lift)
    tied = (set(ADJUDICATION_REQUIRED) == _lift.ADJUDICATION_KEYS | {_lift.ABOUT}
            and _lift.TARGET == ADJUDICATION)
    print("  %-60s %-6s %s" % ("the mover writes exactly the shape this gate demands",
                               "yes" if tied else "no", "ok" if tied else "WRONG"))
    if not tied:
        fails.append("the adjudication shape matches lift-adjudication's")
    # And the live census: a population statement, never a pass.
    carr = [r for r in rows if isinstance((r.get("masking") or {}).get(ADJUDICATION), dict)]
    print("  rows carrying a lifted adjudication : %d" % len(carr))

    print()
    print("=== a gate finding records shapes and counts, and nothing else ===")

    def scase(label, block, want_hit, key="encoded_layer_finding", under=None):
        m = dict(MASKED)
        if under:
            m[under] = {key: block}
        else:
            m[key] = block
        got = findingShapeViolations([dict(base, masking=m)])
        ok = bool(got) == want_hit
        ran.append("shape: " + label)
        print("  %-60s %-6s %s" % (label, "hit" if got else "clean",
                                   "ok" if ok else "WRONG (wanted %s)"
                                   % ("hit" if want_hit else "clean")))
        if not ok:
            fails.append("shape: " + label)

    PROFILE = {"distinct_identifiers": 1, "occurrences": 3, "identifier_lengths": [6, 11],
               "segment_lengths": [25, 473603], "kinds": ["acct", "domain"],
               "positions": ["begins", "contains", "exact", "truncation"],
               "methods": ["base64", "base64+inflate"],
               "note": finding_notes.IDENTIFIER_NOTE,
               "false_positive_note": "127 across 104 of 8,000 stock files"}
    scase("the profile the gate actually emits", dict(PROFILE), False)
    scase("a plaintext finding, which carries no methods",
          {k: v for k, v in PROFILE.items() if k != "methods"}, False,
          key="plaintext_finding")
    scase("the same profile under gate_categories", dict(PROFILE), False,
          under="gate_categories")
    scase("no finding at all: not this check's business", None, False)
    # THE CASE THIS EXISTS FOR: the adjudication that was living in this key. It would have
    # fired on both published rows before the move, and it says so by name.
    scase("the adjudication that used to live here",
          {"classification": "ambiguous", "decision": "held", "resolution": {},
           "value": "an address", "why_it_matters": "encoded layers"}, True)
    scase("one adjudication key smuggled into a real profile",
          dict(PROFILE, value="an address inside the layer"), True)
    scase("a free-text key nobody declared", dict(PROFILE, seen_at="a path"), True)
    scase("a count recorded as a string", dict(PROFILE, occurrences="3"), True)
    scase("a count recorded as a bool", dict(PROFILE, distinct_identifiers=True), True)
    scase("lengths recorded as strings", dict(PROFILE, identifier_lengths=["6"]), True)
    scase("a position label outside the closed vocabulary",
          dict(PROFILE, positions=["begins", "somewhere-else"]), True)
    scase("a kind outside the closed vocabulary", dict(PROFILE, kinds=["ipv4"]), True)
    scase("the note recorded as a list", dict(PROFILE, note=["a", "b"]), True)
    scase("the finding recorded as a string", "FAIL", True)
    # The live census: a population statement, never a pass.
    fb = sum(1 for r in rows
             for c_ in (r.get("masking") or {},
                        (r.get("masking") or {}).get("gate_categories") or {})
             if isinstance(c_, dict)
             for k_ in ("plaintext_finding", "encoded_layer_finding")
             if isinstance(c_.get(k_), dict))
    print("  gate finding blocks in this half : %d" % fb)

    print()
    print("=== the kept-indicator block must keep saying only what it is for ===")

    def icase(label, row, want_hit):
        got = iocViolations([row])
        ok = bool(got) == want_hit
        ran.append(label)
        print("  %-60s %-6s %s" % (label, "hit" if got else "clean",
                                   "ok" if ok else "WRONG (wanted %s)"
                                   % ("hit" if want_hit else "clean")))
        if not ok:
            fails.append(label)

    def irow(ioc, **kw):
        r = dict(base, sensitivity=["c2"], masking=dict(MASKED, c2_kept=True), ioc=ioc)
        r.update(kw)
        return r

    icase("a fallback address listed among the hosts", irow(dict(IOC)), False)
    icase("hosts with no fallback recorded",
          irow({"campaign_hosts": ["c.example-campaign.xyz"]}), False)
    icase("no ioc block at all: not this check's business",
          dict(base, sensitivity=["c2"]), False)
    icase("a fallback that is not among the hosts",
          irow(dict(IOC, c2_fallback_ip="198.51.100.9")), True)
    icase("a host that is a URL rather than a host",
          irow({"campaign_hosts": ["http://c.example-campaign.xyz/x.php"]}), True)
    icase("a host that is a path",
          irow({"campaign_hosts": ["/home2/acct01/public_html"]}), True)
    icase("a host that is a sentence",
          irow({"campaign_hosts": ["kept deliberately, see the note"]}), True)
    icase("an empty host list", irow({"campaign_hosts": []}), True)
    icase("campaign_hosts recorded as a string",
          irow({"campaign_hosts": "c.example-campaign.xyz"}), True)
    icase("kept indicators while the masker says c2 was not kept",
          dict(irow(dict(IOC)), masking=dict(MASKED, c2_kept=False)), True)
    icase("kept indicators on a row carrying no c2 tag",
          dict(irow(dict(IOC)), sensitivity=["identity"]), True)

    print()
    print("=== a generated fixture must describe the bytes it ships ===")

    def fcase(label, row, want_hit):
        got = fixtureViolations([row])
        ok = bool(got) == want_hit
        ran.append(label)
        print("  %-60s %-6s %s" % (label, "hit" if got else "clean",
                                   "ok" if ok else "WRONG (wanted %s)"
                                   % ("hit" if want_hit else "clean")))
        if not ok:
            fails.append(label)

    A, B = "a" * 64, "b" * 64
    SELFFX = {"name": "fam-x", "fixture_sha256": A, "fixture_size": 5355,
              "payload_sha256": B, "payload_size": 5343}

    def frow(fx, sha=A, size=5355, family="fam-x"):
        return dict(base, sha256=sha, size=size, family=family, fixture=fx)

    fcase("a row that IS its own fixture, by hash and by size", frow(dict(SELFFX)), False)
    fcase("a row that is NOT its own fixture, by neither",
          frow(dict(SELFFX), sha="c" * 64, size=99999), False)
    fcase("no fixture block at all: not this check's business",
          dict(base, sha256=A), False)
    fcase("its own fixture by hash but not by size",
          frow(dict(SELFFX), sha=A, size=99999), True)
    fcase("its own fixture by size but not by hash",
          frow(dict(SELFFX), sha="c" * 64, size=5355), True)
    fcase("a payload no smaller than the fixture that carries it",
          frow(dict(SELFFX, payload_size=5355)), True)
    fcase("a payload larger than the fixture", frow(dict(SELFFX, payload_size=6000)), True)
    fcase("fixture and payload recording the same hash",
          frow(dict(SELFFX, payload_sha256=A)), True)
    fcase("a hash that is not 64 hex", frow(dict(SELFFX, payload_sha256="deadbeef")), True)
    fcase("a size recorded as a string", frow(dict(SELFFX, payload_size="5343")), True)
    fcase("a size recorded as a bool", frow(dict(SELFFX, payload_size=True)), True)
    fcase("a fixture name that is not the row's family",
          frow(dict(SELFFX), family="fam-y"), True)
    fcase("a fixture recorded as a string", frow("generated"), True)

    print()
    # Counted, never quoted, and printed LAST. It was hardcoded at 20 while the suite grew;
    # then it was correct but emitted before the nine `pcase` checks ran, so the headline read
    # "61 · 61 · 0" over a suite of 70 and would have read "failed: 0" while returning 1. A
    # total is only a total when nothing can be added after it is printed.
    print()
    print("cases: %d · passed: %d · failed: %d"
          % (len(ran), len(ran) - len(fails), len(fails)))
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0


USAGE = "usage: shard-gate.py <index.jsonl> [--fix] | shard-gate.py --inject <index.jsonl>"

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        sys.exit(USAGE)
    if "--inject" in sys.argv:
        sys.exit(inject(args[0]))
    fix = "--fix" in sys.argv
    try:
        if fix:
            # Read under the same lock we write under: re-reading rows that
            # another writer is mid-merge on and then rewriting the whole file
            # is how the other session's appends would disappear.
            with index_lock(args[0]):
                sys.exit(main(args[0], True))
        else:
            sys.exit(main(args[0], False))
    except LockBusy as exc:
        sys.exit(str(exc))
