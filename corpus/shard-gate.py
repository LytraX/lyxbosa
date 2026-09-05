#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§7.2 - the gate that runs before any shard is built. Fails the build, never warns.

`publishable` is a COMPUTED field, not a human assertion (§4.4). This script is the only
thing allowed to compute it, so the rule lives in exactly one place.

The rule (§4.1): a sample is publishable when its verdict is not `unreviewed` AND every
sensitivity tag is `clean`, `c2`, or has been masked and re-verified. `pii` and `content`
are never publishable, because there is no substitution that makes them safe.

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

ALWAYS_OK = {"clean", "c2"}
NEVER = {"pii", "content"}

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
    if unmasked:
        if not m.get("applied"):
            why.append("carries %s but no masking has been applied" % "/".join(sorted(unmasked)))
        else:
            if m.get("plaintext_gate") != "PASS":
                why.append("plaintext gate did not pass")
            if m.get("encoded_layer_gate") != "PASS":
                why.append("encoded-layer gate did not pass")
            if not m.get("detection_survived"):
                why.append("masking changed the detection set")
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
    return 1 if (stale or bad or leaks or forms) else 0


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

    def case(label, row, want):
        over, under, drift = staleness([row])
        got = ("over" if over else "under" if under else "drift" if drift else "clean")
        ok = got == want
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

    print()
    print("=== negative controls: each must be SILENT ===")
    case("a consistent publishable row", dict(base, publishable=True), "clean")
    case("a consistent blocked row, every reason recorded",
         dict(base, verdict="unreviewed", sensitivity=["unreviewed"], publishable=False,
              publish_blocker="verdict is unreviewed: nothing leaves that state without a human",
              publish_blockers=["verdict is unreviewed: nothing leaves that state without a human",
                                "sensitivity not yet assessed"]), "clean")
    r = json.loads(json.dumps(real))
    case("a real row from %s, untouched" % os.path.basename(path), r, "clean")

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
    print("cases: 12 · passed: %d · failed: %d" % (12 - len(fails), len(fails)))
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
