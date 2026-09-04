#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""§7.2 - the gate that runs before any shard is built. Fails the build, never warns.

`publishable` is a COMPUTED field, not a human assertion (§4.4). This script is the only
thing allowed to compute it, so the rule lives in exactly one place.

The rule (§4.1): a sample is publishable when its verdict is not `unreviewed` AND every
sensitivity tag is `clean`, `c2`, or has been masked and re-verified. `pii` and `content`
are never publishable, because there is no substitution that makes them safe.
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
# account names while the incident-response directories used abbreviations -
# `acct42-safe-repair-...` for the account mapped as `acct42`. Name matching is the wrong
# shape of check; a positive assertion about the form of what is allowed is the right one.
HOME_RE = re.compile(r'/home/([^/"]+)/')
ACCT_RE = re.compile(r'acct\d+$')

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

def main(path, apply_fix=False):
    rows = read_jsonl(path)
    changed = 0
    viol = collections.Counter()
    examples = collections.defaultdict(list)
    for r in rows:
        ok, why = evaluate(r)
        if r.get("publishable") != ok:
            changed += 1
            if r.get("publishable") and not ok:
                for w in why:
                    viol[w] += 1
                    if len(examples[w]) < 2:
                        examples[w].append(r["sha256"][:12])
        if apply_fix:
            r["publishable"] = ok
            if ok:
                r.pop("publish_blocker", None)
                r.pop("publish_blockers", None)
            elif why:
                # Keep every reason. Storing only the first overwrites the specific,
                # actionable blocker ("identifier inside an encoded layer") with the generic
                # one ("verdict is unreviewed"), and the accounting then cannot see it.
                r["publish_blockers"] = why
                r["publish_blocker"] = why[0]
    print("rows                        :", len(rows))
    print("publishable flags corrected :", changed)
    print("now publishable             :", sum(1 for r in rows if evaluate(r)[0]))
    if viol:
        print()
        print("=== rows that claimed publishable but are not ===")
        for w, n in viol.most_common():
            print("  %-70s %5d  e.g. %s" % (w[:70], n, ", ".join(examples[w])))
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
    return 1 if (viol or bad or leaks) else 0

USAGE = "usage: shard-gate.py <index.jsonl> [--fix]"

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        sys.exit(USAGE)
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
