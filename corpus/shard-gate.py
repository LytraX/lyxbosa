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
    return 1 if (stale or bad or leaks or forms or unread or badc) else 0


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
    # Counted, never quoted. The number was hardcoded at 20 while the suite grew, which is
    # a case count that cannot report a case being dropped.
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
